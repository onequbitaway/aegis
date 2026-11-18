//! The impossible speed detector.

use std::net::IpAddr;
use std::sync::Mutex;

use aegis_contracts::common::{EntityKind, EventId, Severity};
use aegis_contracts::event::{Event, Outcome, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Finding, Tracked, at_least, seconds, tenant_key};
use crate::attack::technique_in;
use crate::common::{canonical_ip, ip_entity, lock, push_entity, time_after};
use crate::error::DetectError;

/// The rule identifier of an impossible speed detection.
pub const IMPOSSIBLE_SPEED_RULE_ID: &str = "aegis.velocity.impossible_speed";

/// The mean radius of the Earth in kilometers.
const EARTH_RADIUS_KM: f64 = 6_371.008_8;

/// The settings of [`ImpossibleSpeed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImpossibleSpeedConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// The largest speed in kilometers per hour that is possible for a principal.
    pub max_speed_kmh: f64,
    /// The smallest distance in kilometers that the detector examines. A smaller distance
    /// is in the error of the location data.
    pub min_distance_km: f64,
    /// For events with no coordinates: the largest time in seconds between activity in two
    /// countries that is a detection.
    pub country_window_seconds: u64,
    /// The largest time in seconds between activity in two resource tenants, from two
    /// places, that is a `malicious` detection.
    pub cross_tenant_window_seconds: u64,
    /// The time in seconds after a detection in which the detector reports no more
    /// detections for the same principal.
    pub cooldown_seconds: u64,
    /// The largest number of principals for which the detector keeps state.
    pub max_tracked_principals: usize,
}

impl Default for ImpossibleSpeedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_speed_kmh: 1_000.0,
            min_distance_km: 500.0,
            country_window_seconds: 1_800,
            cross_tenant_window_seconds: 60,
            cooldown_seconds: 900,
            max_tracked_principals: 100_000,
        }
    }
}

/// Returns the great-circle distance in kilometers between two points.
///
/// Each point is a latitude and a longitude in degrees.
#[must_use]
pub fn haversine_km(from: (f64, f64), to: (f64, f64)) -> f64 {
    let (from_latitude, from_longitude) = (from.0.to_radians(), from.1.to_radians());
    let (to_latitude, to_longitude) = (to.0.to_radians(), to.1.to_radians());
    let latitude = ((to_latitude - from_latitude) / 2.0).sin();
    let longitude = ((to_longitude - from_longitude) / 2.0).sin();
    let a = latitude * latitude + from_latitude.cos() * to_latitude.cos() * longitude * longitude;
    2.0 * EARTH_RADIUS_KM * a.sqrt().min(1.0).asin()
}

/// The place and the time of one event of a principal.
#[derive(Clone)]
struct Observation {
    time: DateTime<Utc>,
    event_id: EventId,
    ip: Option<IpAddr>,
    /// The latitude and the longitude in degrees.
    point: Option<(f64, f64)>,
    /// The ISO 3166-1 alpha-2 country code in upper case.
    country: Option<[u8; 2]>,
    resource_tenant: Option<String>,
}

fn coordinate(event: &Event, key: &str, limit: f64) -> Option<f64> {
    event
        .attributes
        .get(key)
        .and_then(Value::as_f64)
        .filter(|degrees| degrees.is_finite() && degrees.abs() <= limit)
}

fn country_code(event: &Event) -> Option<[u8; 2]> {
    match event.attribute_str(attr::COUNTRY)?.trim().as_bytes() {
        [first, second] if first.is_ascii_alphabetic() && second.is_ascii_alphabetic() => {
            Some([first.to_ascii_uppercase(), second.to_ascii_uppercase()])
        }
        _ => None,
    }
}

fn country_text(code: Option<[u8; 2]>) -> Value {
    code.and_then(|code| std::str::from_utf8(&code).ok().map(str::to_owned))
        .map_or(Value::Null, Value::String)
}

impl Observation {
    /// Returns the observation of an event, if the event has a place.
    fn of(event: &Event) -> Option<Self> {
        let point =
            coordinate(event, attr::LATITUDE, 90.0).zip(coordinate(event, attr::LONGITUDE, 180.0));
        let country = country_code(event);
        if point.is_none() && country.is_none() {
            return None;
        }
        Some(Self {
            time: event.time,
            event_id: event.id,
            ip: event.actor.ip.map(canonical_ip),
            point,
            country,
            resource_tenant: event
                .attribute_str(attr::RESOURCE_TENANT)
                .map(str::to_owned),
        })
    }
}

struct PrincipalState {
    /// The newest observation.
    last: Observation,
    /// The end of the cooldown, and `true` if the detection was `malicious`.
    alert: Option<(DateTime<Utc>, bool)>,
}

/// What the comparison of two observations found.
struct Violation {
    /// The distance in kilometers, if both observations have coordinates.
    distance_km: Option<f64>,
    seconds: f64,
    /// `true` if the two observations are in two resource tenants.
    cross_tenant: bool,
}

/// Finds one principal that acts from two places at a speed that is not possible.
///
/// The detector keeps the last place of each user, service principal, and application. It
/// uses the events that did not fail and that have the attributes `latitude` and
/// `longitude`, or `country`. It compares each event with the last place:
///
/// - With coordinates on the two events, the distance (haversine) and the time give a
///   speed. A speed above `max_speed_kmh` over more than `min_distance_km` is a detection.
/// - With no coordinates, activity in two countries in `country_window_seconds` is a
///   detection.
/// - If the two events are also in two resource tenants in `cross_tenant_window_seconds`,
///   the detection is `malicious`. All other detections are `suspicious`, because a VPN
///   gives the same pattern.
///
/// The technique is `T1078.004`. After a detection, the detector reports the same
/// principal again only after the cooldown, or when a `malicious` pattern follows a
/// `suspicious` detection.
pub struct ImpossibleSpeed {
    config: ImpossibleSpeedConfig,
    country_window: TimeDelta,
    cross_tenant_window: TimeDelta,
    cooldown: TimeDelta,
    state: Mutex<Tracked<(u64, EntityKind, String), PrincipalState>>,
}

impl ImpossibleSpeed {
    /// Makes the detector.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if a speed or a distance is not a positive number,
    /// or `max_tracked_principals` is zero.
    pub fn new(config: ImpossibleSpeedConfig) -> std::result::Result<Self, DetectError> {
        let prefix = "impossible_speed";
        for (name, value) in [
            ("max_speed_kmh", config.max_speed_kmh),
            ("min_distance_km", config.min_distance_km),
        ] {
            if !(value.is_finite() && value > 0.0) {
                return Err(DetectError::Config(format!(
                    "{prefix}.{name} must be a number above 0, but it is {value}"
                )));
            }
        }
        at_least(
            &format!("{prefix}.max_tracked_principals"),
            config.max_tracked_principals,
            1,
        )?;
        Ok(Self {
            country_window: seconds(
                &format!("{prefix}.country_window_seconds"),
                config.country_window_seconds,
            )?,
            cross_tenant_window: seconds(
                &format!("{prefix}.cross_tenant_window_seconds"),
                config.cross_tenant_window_seconds,
            )?,
            cooldown: seconds(
                &format!("{prefix}.cooldown_seconds"),
                config.cooldown_seconds,
            )?,
            state: Mutex::new(Tracked::new(config.max_tracked_principals)),
            config,
        })
    }

    /// Compares two observations of one principal.
    fn compare(&self, earlier: &Observation, later: &Observation) -> Option<Violation> {
        let gap = (later.time - earlier.time).abs();
        let seconds = gap.as_seconds_f64();
        let distance_km = earlier
            .point
            .zip(later.point)
            .map(|(from, to)| haversine_km(from, to));
        let other_country = earlier
            .country
            .zip(later.country)
            .is_some_and(|(from, to)| from != to);
        let other_place = match distance_km {
            Some(distance) => {
                distance >= self.config.min_distance_km
                    && distance > self.config.max_speed_kmh * (seconds / 3_600.0)
            }
            None => other_country && gap <= self.country_window,
        };
        if !other_place {
            return None;
        }
        let cross_tenant = gap <= self.cross_tenant_window
            && earlier
                .resource_tenant
                .as_deref()
                .zip(later.resource_tenant.as_deref())
                .is_some_and(|(from, to)| from != to);
        Some(Violation {
            distance_km,
            seconds,
            cross_tenant,
        })
    }

    /// Examines one event. Returns a detection if the event completes the pattern.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        let is_principal = matches!(
            event.actor.kind,
            EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application
        );
        if !self.config.enabled || !is_principal || event.outcome == Outcome::Failure {
            return None;
        }
        let current = Observation::of(event)?;

        let mut tracked = lock(&self.state);
        let key = (tenant_key(event), event.actor.kind, event.actor.id.clone());
        let mut is_new = false;
        let state = tracked.upsert(key, event.time, || {
            is_new = true;
            PrincipalState {
                last: current.clone(),
                alert: None,
            }
        });
        if is_new {
            return None;
        }
        let previous = if current.time >= state.last.time {
            std::mem::replace(&mut state.last, current.clone())
        } else {
            state.last.clone()
        };
        let violation = self.compare(&previous, &current)?;
        let in_cooldown = state.alert.is_some_and(|(until, was_malicious)| {
            current.time < until && (was_malicious || !violation.cross_tenant)
        });
        if in_cooldown {
            return None;
        }
        state.alert = Some((
            time_after(current.time, self.cooldown),
            violation.cross_tenant,
        ));
        drop(tracked);

        Some(self.detection(event, &previous, &current, &violation))
    }

    fn detection(
        &self,
        event: &Event,
        previous: &Observation,
        current: &Observation,
        violation: &Violation,
    ) -> Detection {
        let (earlier, later) = if previous.time <= current.time {
            (previous, current)
        } else {
            (current, previous)
        };
        let (verdict, severity) = if violation.cross_tenant {
            (Verdict::Malicious, Severity::High)
        } else {
            (Verdict::Suspicious, Severity::Medium)
        };
        let movement = match violation.distance_km {
            Some(distance) => format!("{distance:.0} kilometers apart"),
            None => "in two countries".to_owned(),
        };
        let tenants = if violation.cross_tenant {
            " and in two resource tenants"
        } else {
            ""
        };
        let mut entities = vec![event.actor.entity()];
        for ip in [earlier.ip, later.ip].into_iter().flatten() {
            push_entity(&mut entities, ip_entity(ip));
        }
        let mut attributes = vec![
            ("seconds", json!(violation.seconds)),
            ("cross_tenant", json!(violation.cross_tenant)),
            ("from_country", country_text(earlier.country)),
            ("to_country", country_text(later.country)),
            ("max_speed_kmh", json!(self.config.max_speed_kmh)),
        ];
        if let Some(distance) = violation.distance_km {
            attributes.push(("distance_km", json!(distance.round())));
        }
        if violation.cross_tenant {
            attributes.push(("from_resource_tenant", json!(earlier.resource_tenant)));
            attributes.push(("to_resource_tenant", json!(later.resource_tenant)));
        }
        Finding {
            rule_id: IMPOSSIBLE_SPEED_RULE_ID,
            title: "Principal acts from two places at an impossible speed",
            description: format!(
                "The principal {} acted from two places {movement}{tenants} in {:.0} seconds.",
                event.actor.id, violation.seconds
            ),
            severity,
            verdict,
            attack: vec![technique_in("initial-access", "T1078.004")],
            time: later.time,
            event_ids: vec![earlier.event_id, later.event_id],
            entities,
            attributes,
        }
        .into_detection(event)
    }
}

#[async_trait]
impl Detector for ImpossibleSpeed {
    fn id(&self) -> &str {
        IMPOSSIBLE_SPEED_RULE_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        Ok(self.evaluate(event).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::AttackTechnique;
    use aegis_contracts::common::EntityRef;
    use aegis_contracts::event::{EventClass, action};

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    const BUCHAREST: (&str, f64, f64) = ("RO", 44.43, 26.10);
    const SINGAPORE: (&str, f64, f64) = ("SG", 1.35, 103.82);
    const SEATTLE: (&str, f64, f64) = ("US", 47.61, -122.33);
    const PORTLAND: (&str, f64, f64) = ("US", 45.52, -122.68);
    const VANCOUVER: (&str, f64, f64) = ("CA", 49.28, -123.12);

    fn detector() -> ImpossibleSpeed {
        ImpossibleSpeed::new(ImpossibleSpeedConfig::default()).unwrap()
    }

    /// An API call of a service principal from a place, in a resource tenant.
    fn call(
        sequence: u32,
        milliseconds: i64,
        ip: &str,
        place: (&str, f64, f64),
        tenant: &str,
    ) -> Event {
        event(
            sequence,
            at(milliseconds),
            EventClass::ApiActivity,
            action::API_CALL,
            actor(EntityKind::ServicePrincipal, "sp-sync-helper", ip),
        )
        .with_attribute(attr::COUNTRY, place.0)
        .with_attribute(attr::LATITUDE, place.1)
        .with_attribute(attr::LONGITUDE, place.2)
        .with_attribute(attr::RESOURCE_TENANT, tenant)
    }

    fn without_coordinates(mut event: Event) -> Event {
        event.attributes.remove(attr::LATITUDE);
        event.attributes.remove(attr::LONGITUDE);
        event
    }

    #[test]
    fn haversine_gives_known_distances() {
        // London to New York is about 5 570 kilometers.
        let london_new_york = haversine_km((51.5074, -0.1278), (40.7128, -74.0060));
        assert!(
            (london_new_york - 5_570.0).abs() < 20.0,
            "{london_new_york}"
        );
        // Paris to Tokyo is about 9 710 kilometers.
        let paris_tokyo = haversine_km((48.8566, 2.3522), (35.6762, 139.6503));
        assert!((paris_tokyo - 9_710.0).abs() < 30.0, "{paris_tokyo}");
        assert!((haversine_km((35.6762, 139.6503), (48.8566, 2.3522)) - paris_tokyo).abs() < 1e-6);
        let seattle_portland = haversine_km((47.61, -122.33), (45.52, -122.68));
        assert!((seattle_portland - 234.0).abs() < 5.0, "{seattle_portland}");
        assert!(haversine_km((10.0, 20.0), (10.0, 20.0)).abs() < 1e-9);
        let poles = haversine_km((90.0, 0.0), (-90.0, 0.0));
        assert!((poles - 20_015.0).abs() < 5.0, "{poles}");
        let across_the_date_line = haversine_km((0.0, 179.5), (0.0, -179.5));
        assert!(
            (across_the_date_line - 111.2).abs() < 1.0,
            "{across_the_date_line}"
        );
    }

    #[test]
    fn two_tenants_from_two_continents_in_two_seconds_is_malicious() {
        let detector = detector();
        let first = call(1, 0, "203.0.113.51", BUCHAREST, "tenant-contoso");
        let second = call(2, 2_000, "192.0.2.77", SINGAPORE, "tenant-fabrikam");
        assert_eq!(detector.evaluate(&first), None);
        let found = detector.evaluate(&second).unwrap();
        assert_eq!(found.rule_id, IMPOSSIBLE_SPEED_RULE_ID);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "initial-access",
                "T1078.004",
                "Cloud Accounts"
            )]
        );
        assert_eq!(found.time, second.time);
        assert_eq!(found.event_ids, [first.id, second.id]);
        assert_eq!(found.tenant.as_deref(), Some(TENANT));
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
                EntityRef::new(EntityKind::IpAddress, "192.0.2.77"),
            ]
        );
        assert_eq!(found.attributes["cross_tenant"], json!(true));
        assert_eq!(found.attributes["from_country"], json!("RO"));
        assert_eq!(found.attributes["to_country"], json!("SG"));
        assert_eq!(
            found.attributes["from_resource_tenant"],
            json!("tenant-contoso")
        );
        assert_eq!(
            found.attributes["to_resource_tenant"],
            json!("tenant-fabrikam")
        );
        assert_eq!(found.attributes["seconds"], json!(2.0));
        // Bucharest to Singapore is about 8 930 kilometers.
        assert_eq!(found.attributes["distance_km"], json!(8_930.0));
        assert_eq!(
            found.description,
            "The principal sp-sync-helper acted from two places 8930 kilometers apart and in two \
             resource tenants in 2 seconds."
        );
    }

    #[test]
    fn an_impossible_speed_in_one_tenant_is_suspicious() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "t")),
            None
        );
        let found = detector
            .evaluate(&call(2, 60_000, "192.0.2.77", SINGAPORE, "t"))
            .unwrap();
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.severity, Severity::Medium);
        assert_eq!(found.attributes["cross_tenant"], json!(false));
        assert_eq!(found.attributes.get("from_resource_tenant"), None);
    }

    #[test]
    fn a_speed_that_is_possible_is_not_detected() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "t")),
            None
        );
        // About 8 930 kilometers in 9 hours is 992 kilometers per hour.
        let nine_hours = 9 * 3_600 * 1_000;
        assert_eq!(
            detector.evaluate(&call(2, nine_hours, "192.0.2.77", SINGAPORE, "t")),
            None
        );
        // The return in 8 hours and 50 minutes is 1 011 kilometers per hour.
        let back = nine_hours + (8 * 3_600 + 50 * 60) * 1_000;
        assert!(
            detector
                .evaluate(&call(3, back, "203.0.113.51", BUCHAREST, "t"))
                .is_some()
        );
    }

    #[test]
    fn a_short_distance_is_not_detected_at_any_speed() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "198.51.100.10", SEATTLE, "a")),
            None
        );
        assert_eq!(
            detector.evaluate(&call(2, 1_000, "198.51.100.11", PORTLAND, "b")),
            None
        );
        // Two countries, but the coordinates show a short distance.
        assert_eq!(
            detector.evaluate(&call(3, 2_000, "198.51.100.12", VANCOUVER, "c")),
            None
        );
    }

    #[test]
    fn the_same_place_in_two_tenants_is_not_detected() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "tenant-a")),
            None
        );
        assert_eq!(
            detector.evaluate(&call(2, 1_000, "203.0.113.51", BUCHAREST, "tenant-b")),
            None
        );
    }

    #[test]
    fn two_countries_with_no_coordinates_use_the_country_window() {
        let detector = detector();
        let first = without_coordinates(call(1, 0, "203.0.113.51", BUCHAREST, "t"));
        let second = without_coordinates(call(2, 1_800_000, "192.0.2.77", SINGAPORE, "t"));
        assert_eq!(detector.evaluate(&first), None);
        let found = detector.evaluate(&second).unwrap();
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.attributes.get("distance_km"), None);
        assert_eq!(
            found.description,
            "The principal sp-sync-helper acted from two places in two countries in 1800 seconds."
        );

        let detector = self::detector();
        assert_eq!(detector.evaluate(&first), None);
        let late = without_coordinates(call(3, 1_800_001, "192.0.2.77", SINGAPORE, "t"));
        assert_eq!(detector.evaluate(&late), None);
    }

    #[test]
    fn two_countries_and_two_tenants_with_no_coordinates_is_malicious() {
        let detector = detector();
        let first = without_coordinates(call(1, 0, "203.0.113.51", BUCHAREST, "tenant-a"));
        let second = without_coordinates(call(2, 60_000, "192.0.2.77", SINGAPORE, "tenant-b"));
        assert_eq!(detector.evaluate(&first), None);
        assert_eq!(
            detector.evaluate(&second).unwrap().verdict,
            Verdict::Malicious
        );

        // One millisecond after the cross-tenant window, the detection is suspicious.
        let detector = self::detector();
        let late = without_coordinates(call(3, 60_001, "192.0.2.77", SINGAPORE, "tenant-b"));
        assert_eq!(detector.evaluate(&first), None);
        assert_eq!(
            detector.evaluate(&late).unwrap().verdict,
            Verdict::Suspicious
        );
    }

    #[test]
    fn one_country_with_no_coordinates_is_not_detected() {
        let detector = detector();
        let first = without_coordinates(call(1, 0, "198.51.100.10", SEATTLE, "a"));
        let second = without_coordinates(call(2, 1_000, "198.51.100.99", PORTLAND, "b"));
        assert_eq!(detector.evaluate(&first), None);
        assert_eq!(detector.evaluate(&second), None);
    }

    #[test]
    fn an_event_with_no_place_is_ignored_and_does_not_replace_the_last_place() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "a")),
            None
        );
        let mut no_place = call(2, 500, "192.0.2.1", SINGAPORE, "b");
        for key in [attr::COUNTRY, attr::LATITUDE, attr::LONGITUDE] {
            no_place.attributes.remove(key);
        }
        assert_eq!(detector.evaluate(&no_place), None);
        let found = detector
            .evaluate(&call(3, 1_000, "192.0.2.77", SINGAPORE, "b"))
            .unwrap();
        assert_eq!(found.event_ids.len(), 2);
        assert_eq!(found.attributes["from_country"], json!("RO"));
    }

    #[test]
    fn coordinates_that_are_not_valid_are_ignored() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "a")),
            None
        );
        let mut bad = call(2, 1_000, "192.0.2.77", ("RO", 144.0, 26.10), "b");
        assert_eq!(detector.evaluate(&bad), None);
        bad.attributes
            .insert(attr::LATITUDE.to_owned(), json!("1.35"));
        bad.attributes
            .insert(attr::COUNTRY.to_owned(), json!("Romania"));
        assert_eq!(detector.evaluate(&bad), None);
    }

    #[test]
    fn a_failed_event_is_not_activity_of_the_principal() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "a")),
            None
        );
        let mut failed = call(2, 1_000, "192.0.2.77", SINGAPORE, "b");
        failed.outcome = Outcome::Failure;
        assert_eq!(detector.evaluate(&failed), None);
        // The failed event did not replace the last place.
        assert_eq!(
            detector.evaluate(&call(3, 2_000, "203.0.113.51", BUCHAREST, "a")),
            None
        );
    }

    #[test]
    fn each_principal_and_each_kind_has_its_own_last_place() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "a")),
            None
        );
        let mut other = call(2, 1_000, "192.0.2.77", SINGAPORE, "b");
        other.actor.id = "sp-other".to_owned();
        assert_eq!(detector.evaluate(&other), None);
        let mut user = call(3, 2_000, "192.0.2.77", SINGAPORE, "b");
        user.actor.kind = EntityKind::User;
        assert_eq!(detector.evaluate(&user), None);
        let mut device = call(4, 3_000, "192.0.2.77", SINGAPORE, "b");
        device.actor.kind = EntityKind::Device;
        assert_eq!(detector.evaluate(&device), None);
        let mut other_tenant = call(5, 4_000, "192.0.2.77", SINGAPORE, "b");
        other_tenant.source.tenant = Some("tenant-2".to_owned());
        assert_eq!(detector.evaluate(&other_tenant), None);
    }

    #[test]
    fn a_principal_that_alternates_between_two_places_gives_one_detection_in_the_cooldown() {
        let detector = detector();
        let mut detections = Vec::new();
        for index in 0..6_u32 {
            let event = if index % 2 == 0 {
                call(
                    index,
                    i64::from(index) * 2_000,
                    "203.0.113.51",
                    BUCHAREST,
                    "tenant-a",
                )
            } else {
                call(
                    index,
                    i64::from(index) * 2_000,
                    "192.0.2.77",
                    SINGAPORE,
                    "tenant-b",
                )
            };
            detections.extend(detector.evaluate(&event));
        }
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].time, at(2_000));

        // After the cooldown of 900 seconds, the pattern gives a new detection.
        let after = call(10, 2_000 + 900_000, "192.0.2.77", SINGAPORE, "tenant-b");
        assert_eq!(detector.evaluate(&after), None);
        let back = call(11, 2_000 + 901_000, "203.0.113.51", BUCHAREST, "tenant-a");
        assert_eq!(
            detector.evaluate(&back).unwrap().verdict,
            Verdict::Malicious
        );
    }

    #[test]
    fn a_malicious_pattern_in_the_cooldown_of_a_suspicious_detection_is_reported() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "tenant-a")),
            None
        );
        let suspicious = detector
            .evaluate(&call(2, 1_000, "192.0.2.77", SINGAPORE, "tenant-a"))
            .unwrap();
        assert_eq!(suspicious.verdict, Verdict::Suspicious);
        // A second suspicious pattern is in the cooldown.
        assert_eq!(
            detector.evaluate(&call(3, 2_000, "203.0.113.51", BUCHAREST, "tenant-a")),
            None
        );
        let malicious = detector
            .evaluate(&call(4, 3_000, "192.0.2.77", SINGAPORE, "tenant-b"))
            .unwrap();
        assert_eq!(malicious.verdict, Verdict::Malicious);
        // After a malicious detection, the cooldown stops all patterns.
        assert_eq!(
            detector.evaluate(&call(5, 4_000, "203.0.113.51", BUCHAREST, "tenant-a")),
            None
        );
    }

    #[test]
    fn an_event_that_arrives_late_is_compared_but_does_not_replace_the_last_place() {
        let detector = detector();
        assert_eq!(
            detector.evaluate(&call(1, 10_000, "203.0.113.51", BUCHAREST, "tenant-a")),
            None
        );
        let late = call(2, 8_000, "192.0.2.77", SINGAPORE, "tenant-b");
        let found = detector.evaluate(&late).unwrap();
        // The events are in time order in the detection.
        assert_eq!(found.event_ids[0], late.id);
        assert_eq!(found.time, at(10_000));
        assert_eq!(found.attributes["from_country"], json!("SG"));
        assert_eq!(found.attributes["to_country"], json!("RO"));
        let state = lock(&detector.state);
        assert_eq!(
            state.slots.values().next().unwrap().value.last.time,
            at(10_000)
        );
    }

    #[test]
    fn events_at_the_ends_of_the_time_range_do_not_panic() {
        let detector = detector();
        let mut first = call(1, 0, "203.0.113.51", BUCHAREST, "tenant-a");
        first.time = DateTime::<Utc>::MIN_UTC;
        let mut second = call(2, 0, "192.0.2.77", SINGAPORE, "tenant-b");
        second.time = DateTime::<Utc>::MAX_UTC;
        assert_eq!(detector.evaluate(&first), None);
        // The two events are too far apart in time for a detection. The speed is possible.
        assert_eq!(detector.evaluate(&second), None);
        // A third event at the same last instant, in a different place, is a detection.
        // Its cooldown ends after the end of the range.
        let mut third = call(3, 0, "203.0.113.51", BUCHAREST, "tenant-a");
        third.time = DateTime::<Utc>::MAX_UTC;
        let found = detector.evaluate(&third).unwrap();
        assert_eq!(found.time, DateTime::<Utc>::MAX_UTC);
        assert_eq!(found.verdict, Verdict::Malicious);
    }

    #[test]
    fn the_state_is_limited() {
        let detector = ImpossibleSpeed::new(ImpossibleSpeedConfig {
            max_tracked_principals: 4,
            ..ImpossibleSpeedConfig::default()
        })
        .unwrap();
        for index in 0..100_u32 {
            let mut event = call(index, i64::from(index), "203.0.113.51", BUCHAREST, "a");
            event.actor.id = format!("sp-{index}");
            assert_eq!(detector.evaluate(&event), None);
        }
        assert!(lock(&detector.state).len() <= 4);
    }

    #[test]
    fn a_detector_that_is_not_enabled_gives_no_detection() {
        let detector = ImpossibleSpeed::new(ImpossibleSpeedConfig {
            enabled: false,
            ..ImpossibleSpeedConfig::default()
        })
        .unwrap();
        assert_eq!(
            detector.evaluate(&call(1, 0, "203.0.113.51", BUCHAREST, "a")),
            None
        );
        assert_eq!(
            detector.evaluate(&call(2, 2_000, "192.0.2.77", SINGAPORE, "b")),
            None
        );
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        for (config, expected) in [
            (
                ImpossibleSpeedConfig {
                    max_speed_kmh: 0.0,
                    ..ImpossibleSpeedConfig::default()
                },
                "impossible_speed.max_speed_kmh must be a number above 0, but it is 0",
            ),
            (
                ImpossibleSpeedConfig {
                    min_distance_km: f64::NAN,
                    ..ImpossibleSpeedConfig::default()
                },
                "impossible_speed.min_distance_km must be a number above 0, but it is NaN",
            ),
            (
                ImpossibleSpeedConfig {
                    max_tracked_principals: 0,
                    ..ImpossibleSpeedConfig::default()
                },
                "impossible_speed.max_tracked_principals must be 1 or more, but it is 0",
            ),
        ] {
            let error = ImpossibleSpeed::new(config).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
    }

    #[tokio::test]
    async fn the_detector_contract_returns_the_detection() {
        let detector = detector();
        assert_eq!(detector.id(), "aegis.velocity.impossible_speed");
        assert_eq!(detector.tier(), DetectionTier::Deterministic);
        let first = call(1, 0, "203.0.113.51", BUCHAREST, "tenant-a");
        let second = call(2, 2_000, "192.0.2.77", SINGAPORE, "tenant-b");
        assert_eq!(detector.inspect(&first).await.unwrap(), []);
        assert_eq!(detector.inspect(&second).await.unwrap().len(), 1);
    }
}
