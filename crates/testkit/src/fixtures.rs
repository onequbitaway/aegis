//! Shared test data.
//!
//! [`artex_style_attack`] is a recorded log of an agent attack on an identity tenant, mixed
//! with normal activity. The detection tests and the demonstration replay it. The same log
//! is in the repository as `fixtures/artex_style_attack.jsonl`, one event in each line.
//!
//! All addresses are in the documentation ranges of RFC 5737. All names are examples.
//!
//! # Attack sequence
//!
//! Times are minutes and seconds after [`base_time`].
//!
//! | Time | Activity | Expected technique |
//! | --- | --- | --- |
//! | 10:00 to 10:30 | [`SPRAY_ATTEMPTS`] failed sign-ins from [`SPRAY_IP`] | [`expected::PASSWORD_SPRAY`] |
//! | 10:31 | A sign-in for [`VICTIM_USER_ID`] from [`SPRAY_IP`] succeeds | |
//! | 10:37 | The user consents to privileged scopes for [`ROGUE_APP_ID`] | [`expected::CONSENT_GRANT`] |
//! | 10:40 | A new credential on [`ROGUE_PRINCIPAL_ID`], 3 seconds after the grant | [`expected::CREDENTIAL_ADD`] |
//! | 10:43 | [`ROGUE_PRINCIPAL_ID`] signs in from [`WORKLOAD_IP`] | |
//! | 10:46 | [`ROGUE_PRINCIPAL_ID`] assigns a privileged role to itself | [`expected::ROLE_ASSIGN`] |
//! | 10:50 to 11:00 | API calls in two tenants from two continents, 2 seconds apart | [`expected::CLOUD_ACCOUNT`] |
//! | 11:15 | [`ROGUE_PRINCIPAL_ID`] reads the honeytoken [`HONEYTOKEN_ID`] | |

use std::net::{IpAddr, Ipv4Addr};

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use uuid::Uuid;

/// The tenant that the attack log comes from.
pub const TENANT: &str = "tenant-contoso";
/// A second tenant that the attacker reaches.
pub const OTHER_TENANT: &str = "tenant-fabrikam";
/// An office address. Normal sign-ins come from this address and the two after it.
pub const OFFICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
/// The address that the password spray comes from.
pub const SPRAY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
/// The address that the rogue service principal operates from.
pub const WORKLOAD_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));
/// A second address of the rogue service principal, on a different continent.
pub const DISTANT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
/// The user whose password the spray finds.
pub const VICTIM_USER_ID: &str = "user-dana";
/// The application that the attacker gets consent for.
pub const ROGUE_APP_ID: &str = "app-sync-helper";
/// The service principal of [`ROGUE_APP_ID`].
pub const ROGUE_PRINCIPAL_ID: &str = "sp-sync-helper";
/// The honeytoken that the rogue service principal reads.
pub const HONEYTOKEN_ID: &str = "honeytoken-legacy-admin";
/// The number of failed sign-ins in the password spray.
pub const SPRAY_ATTEMPTS: usize = 600;
/// The duration of the password spray in seconds.
pub const SPRAY_SECONDS: i64 = 30;
/// The number of events in [`artex_style_attack`].
pub const ATTACK_LOG_EVENTS: usize = 648;
/// The text of `fixtures/artex_style_attack.jsonl`.
pub const ARTEX_STYLE_ATTACK_JSONL: &str =
    include_str!("../../../fixtures/artex_style_attack.jsonl");

/// The MITRE ATT&CK technique identifiers that detection must find in the attack log.
pub mod expected {
    /// Password spraying: the sign-in burst.
    pub const PASSWORD_SPRAY: &str = "T1110.003";
    /// Steal application access token: the consent to privileged scopes.
    pub const CONSENT_GRANT: &str = "T1528";
    /// Additional cloud credentials: the new credential immediately after the grant.
    pub const CREDENTIAL_ADD: &str = "T1098.001";
    /// Additional cloud roles: the privileged role that the principal assigns to itself.
    pub const ROLE_ASSIGN: &str = "T1098.003";
    /// Cloud accounts: activity across tenants at a speed that is not possible for a person.
    pub const CLOUD_ACCOUNT: &str = "T1078.004";
}

const BASE_EPOCH_SECONDS: i64 = 1793696400;
const EVENT_ID_BASE: u128 = 0x0193_0000_0000_7000_8000_0000_0000_0000;
const GLOBAL_ADMINISTRATOR_ROLE_ID: &str = "62e90394-69f5-4237-9190-012177145e10";
const SCRIPT_USER_AGENT: &str = "python-httpx/0.27.0";
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

/// Returns the time at which the attack log starts: 2026-11-03T09:00:00Z.
#[must_use]
pub fn base_time() -> DateTime<Utc> {
    DateTime::from_timestamp(BASE_EPOCH_SECONDS, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

/// Returns the event source of the fixture events.
#[must_use]
pub fn source() -> EventSource {
    EventSource::new("fixture", "microsoft", "entra_id").with_tenant(TENANT)
}

fn user(id: &str, ip: IpAddr, user_agent: &str) -> Actor {
    let name = id.strip_prefix("user-").unwrap_or(id);
    Actor::new(EntityKind::User, id)
        .with_name(format!("{name}@contoso.example"))
        .with_tenant(TENANT)
        .with_ip(ip)
        .with_user_agent(user_agent)
}

fn rogue_principal(ip: IpAddr) -> Actor {
    Actor::new(EntityKind::ServicePrincipal, ROGUE_PRINCIPAL_ID)
        .with_name("Sync Helper")
        .with_tenant(TENANT)
        .with_ip(ip)
        .with_user_agent(SCRIPT_USER_AGENT)
}

fn rogue_principal_entity() -> EntityRef {
    EntityRef::new(EntityKind::ServicePrincipal, ROGUE_PRINCIPAL_ID)
        .with_name("Sync Helper")
        .with_tenant(TENANT)
}

/// Makes one sign-in event for a user in [`TENANT`].
///
/// With `success` set to `false`, the event has the error data of a wrong password.
#[must_use]
pub fn sign_in(time: DateTime<Utc>, user_id: &str, ip: IpAddr, success: bool) -> Event {
    let event = Event::new(
        time,
        source(),
        EventClass::Authentication,
        action::SIGN_IN,
        user(user_id, ip, BROWSER_USER_AGENT),
    )
    .with_target(EntityRef::new(EntityKind::Application, "app-portal").with_name("Portal"))
    .with_attribute(attr::MFA_SATISFIED, success);
    if success {
        event.with_outcome(Outcome::Success)
    } else {
        event
            .with_outcome(Outcome::Failure)
            .with_attribute(attr::ERROR_CODE, "50126")
            .with_attribute(attr::FAILURE_REASON, "Invalid username or password.")
    }
}

fn api_call(time: DateTime<Utc>, actor: Actor, operation: &str, resource_tenant: &str) -> Event {
    Event::new(
        time,
        source(),
        EventClass::ApiActivity,
        action::API_CALL,
        actor,
    )
    .with_outcome(Outcome::Success)
    .with_attribute(attr::OPERATION, operation)
    .with_attribute(attr::HOME_TENANT, TENANT)
    .with_attribute(attr::RESOURCE_TENANT, resource_tenant)
}

fn located(event: Event, country: &str, city: &str, latitude: f64, longitude: f64) -> Event {
    event
        .with_attribute(attr::COUNTRY, country)
        .with_attribute(attr::CITY, city)
        .with_attribute(attr::LATITUDE, latitude)
        .with_attribute(attr::LONGITUDE, longitude)
}

fn in_office(event: Event) -> Event {
    located(event, "US", "Seattle", 47.61, -122.33)
}

fn in_bucharest(event: Event) -> Event {
    located(event, "RO", "Bucharest", 44.43, 26.10)
}

fn in_singapore(event: Event) -> Event {
    located(event, "SG", "Singapore", 1.35, 103.82)
}

/// Returns the recorded attack log, in time order. The log is the same in each call.
///
/// Refer to the [module documentation](self) for the attack sequence.
#[must_use]
pub fn artex_style_attack() -> Vec<Event> {
    let start = base_time();
    let at = |milliseconds: i64| start + Duration::milliseconds(milliseconds);
    let mut events = Vec::with_capacity(ATTACK_LOG_EVENTS);

    // Normal activity: eight users sign in from three office addresses.
    for minute in 0..30_u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10 + minute % 3));
        let user_id = format!("user-{:03}", minute % 8);
        events.push(in_office(sign_in(
            at(i64::from(minute) * 60_000),
            &user_id,
            ip,
            true,
        )));
    }

    // Normal activity: a backup service principal calls the API each five minutes.
    for call in 0..6_i64 {
        let actor = Actor::new(EntityKind::ServicePrincipal, "sp-backup")
            .with_name("Backup")
            .with_tenant(TENANT)
            .with_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        events.push(in_office(api_call(
            at(call * 300_000 + 15_000),
            actor,
            "GET /users",
            TENANT,
        )));
    }

    // 10:00 to 10:30. Password spray: many users, one address, one script.
    let spray_start = 600_000_i64;
    let interval = SPRAY_SECONDS * 1_000 / i64::try_from(SPRAY_ATTEMPTS).unwrap_or(1);
    for attempt in 0..SPRAY_ATTEMPTS {
        let offset = i64::try_from(attempt).unwrap_or(0) * interval;
        let user_id = format!("user-{:03}", attempt % 150);
        let mut event = sign_in(at(spray_start + offset), &user_id, SPRAY_IP, false);
        event.actor.user_agent = Some(SCRIPT_USER_AGENT.to_owned());
        events.push(in_bucharest(
            event.with_attribute(attr::AUTH_PROTOCOL, "ropc"),
        ));
    }

    // 10:31. The spray finds one password. The sign-in has no second factor.
    let mut foothold = sign_in(at(spray_start + 31_000), VICTIM_USER_ID, SPRAY_IP, true)
        .with_attribute(attr::MFA_SATISFIED, false)
        .with_attribute(attr::AUTH_PROTOCOL, "ropc");
    foothold.actor.user_agent = Some(SCRIPT_USER_AGENT.to_owned());
    events.push(in_bucharest(foothold));

    // 10:37. The user consents to privileged scopes for the application of the attacker.
    let victim = || user(VICTIM_USER_ID, SPRAY_IP, SCRIPT_USER_AGENT);
    events.push(in_bucharest(
        Event::new(
            at(spray_start + 37_000),
            source(),
            EventClass::UserAccessManagement,
            action::OAUTH_CONSENT_GRANT,
            victim(),
        )
        .with_outcome(Outcome::Success)
        .with_target(EntityRef::new(EntityKind::Application, ROGUE_APP_ID).with_name("Sync Helper"))
        .with_attribute(attr::APP_ID, ROGUE_APP_ID)
        .with_attribute(attr::APP_NAME, "Sync Helper")
        .with_attribute(attr::PRIVILEGED, true)
        .with_attribute(
            attr::SCOPES,
            json!([
                "Directory.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
                "offline_access"
            ]),
        ),
    ));

    // 10:40. A new credential on the service principal, three seconds after the grant.
    events.push(in_bucharest(
        Event::new(
            at(spray_start + 40_000),
            source(),
            EventClass::AccountChange,
            action::APP_CREDENTIAL_ADD,
            victim(),
        )
        .with_outcome(Outcome::Success)
        .with_target(rogue_principal_entity())
        .with_attribute(attr::APP_ID, ROGUE_APP_ID)
        .with_attribute(attr::CREDENTIAL_TYPE, "password")
        .with_attribute(attr::CREDENTIAL_ID, "credential-1"),
    ));

    // 10:43. The service principal signs in with the new credential.
    events.push(in_bucharest(
        Event::new(
            at(spray_start + 43_000),
            source(),
            EventClass::Authentication,
            action::SIGN_IN,
            rogue_principal(WORKLOAD_IP),
        )
        .with_outcome(Outcome::Success)
        .with_attribute(attr::APP_ID, ROGUE_APP_ID)
        .with_attribute(attr::AUTH_PROTOCOL, "client_credentials")
        .with_attribute(attr::MFA_SATISFIED, false),
    ));

    // 10:46. The service principal assigns a privileged role to itself.
    events.push(in_bucharest(
        Event::new(
            at(spray_start + 46_000),
            source(),
            EventClass::UserAccessManagement,
            action::ROLE_ASSIGN,
            rogue_principal(WORKLOAD_IP),
        )
        .with_outcome(Outcome::Success)
        .with_target(rogue_principal_entity())
        .with_attribute(attr::APP_ID, ROGUE_APP_ID)
        .with_attribute(attr::ROLE_ID, GLOBAL_ADMINISTRATOR_ROLE_ID)
        .with_attribute(attr::ROLE_NAME, "Global Administrator")
        .with_attribute(attr::PRIVILEGED, true),
    ));

    // 10:50 to 11:00. API calls in two tenants from two continents, two seconds apart.
    for call in 0..6_i64 {
        let time = at(spray_start + 50_000 + call * 2_000);
        let event = if call % 2 == 0 {
            in_bucharest(api_call(
                time,
                rogue_principal(WORKLOAD_IP),
                "GET /users",
                TENANT,
            ))
        } else {
            in_singapore(api_call(
                time,
                rogue_principal(DISTANT_IP),
                "GET /servicePrincipals",
                OTHER_TENANT,
            ))
        };
        events.push(event);
    }

    // 11:15. The service principal reads a honeytoken secret.
    events.push(in_bucharest(
        Event::new(
            at(spray_start + 75_000),
            source(),
            EventClass::ApiActivity,
            action::HONEYTOKEN_TRIP,
            rogue_principal(WORKLOAD_IP),
        )
        .with_outcome(Outcome::Success)
        .with_severity(Severity::High)
        .with_target(
            EntityRef::new(EntityKind::Secret, "kv-prod/legacy-admin-password").with_tenant(TENANT),
        )
        .with_attribute(attr::HONEYTOKEN_ID, HONEYTOKEN_ID)
        .with_attribute(attr::OPERATION, "SecretGet"),
    ));

    events.sort_by_key(|event| event.time);
    for (index, event) in events.iter_mut().enumerate() {
        let offset = u128::try_from(index).unwrap_or_default();
        event.id = EventId(Uuid::from_u128(EVENT_ID_BASE + offset));
    }
    events
}

/// Encodes events as JSON Lines: one event in each line.
pub fn to_jsonl(events: &[Event]) -> Result<String> {
    let mut text = String::new();
    for event in events {
        text.push_str(&serde_json::to_string(event)?);
        text.push('\n');
    }
    Ok(text)
}

/// Decodes events from JSON Lines. Empty lines are ignored.
pub fn from_jsonl(text: &str) -> Result<Vec<Event>> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| Error::Serialization(format!("line {}: {error}", index + 1)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn with_action<'a>(events: &'a [Event], name: &str) -> Vec<&'a Event> {
        events.iter().filter(|event| event.action == name).collect()
    }

    #[test]
    fn the_log_starts_at_the_documented_time() {
        assert_eq!(base_time().to_rfc3339(), "2026-11-03T09:00:00+00:00");
        assert_eq!(artex_style_attack()[0].time, base_time());
    }

    #[test]
    fn the_log_is_the_same_in_each_call_and_is_in_time_order() {
        let first = artex_style_attack();
        assert_eq!(first, artex_style_attack());
        assert_eq!(first.len(), ATTACK_LOG_EVENTS);
        assert!(first.is_sorted_by_key(|event| event.time));
        let ids: BTreeSet<EventId> = first.iter().map(|event| event.id).collect();
        assert_eq!(ids.len(), ATTACK_LOG_EVENTS);
        assert!(
            first
                .iter()
                .all(|event| event.source.tenant.as_deref() == Some(TENANT))
        );
    }

    #[test]
    fn the_repository_file_holds_the_same_log() {
        let from_file = from_jsonl(ARTEX_STYLE_ATTACK_JSONL).unwrap();
        assert_eq!(from_file.len(), ATTACK_LOG_EVENTS);
        assert_eq!(from_file, artex_style_attack());
    }

    #[test]
    fn jsonl_round_trips_and_reports_the_line_of_an_error() {
        let events = artex_style_attack();
        let text = to_jsonl(&events[..3]).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert_eq!(from_jsonl(&format!("\n{text}\n")).unwrap(), events[..3]);
        let error = from_jsonl(&format!("{text}{{broken\n")).unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(message) if message.starts_with("line 4:")),
            "{error}"
        );
    }

    #[test]
    fn the_spray_is_one_burst_of_failures_from_one_address() {
        let events = artex_style_attack();
        let spray: Vec<&Event> = events
            .iter()
            .filter(|event| event.action == action::SIGN_IN && event.outcome == Outcome::Failure)
            .collect();
        assert_eq!(spray.len(), SPRAY_ATTEMPTS);
        assert!(spray.iter().all(|event| event.actor.ip == Some(SPRAY_IP)));
        let users: BTreeSet<&str> = spray.iter().map(|event| event.actor.id.as_str()).collect();
        assert_eq!(users.len(), 150);
        let duration = spray[SPRAY_ATTEMPTS - 1].time - spray[0].time;
        assert!(duration < Duration::seconds(SPRAY_SECONDS), "{duration}");
        assert!(
            duration > Duration::seconds(SPRAY_SECONDS - 1),
            "{duration}"
        );

        let office_failures = events
            .iter()
            .filter(|event| event.outcome == Outcome::Failure && event.actor.ip != Some(SPRAY_IP))
            .count();
        assert_eq!(office_failures, 0);
    }

    #[test]
    fn the_victim_signs_in_from_the_spray_address_after_the_spray() {
        let events = artex_style_attack();
        let footholds: Vec<&Event> = events
            .iter()
            .filter(|event| {
                event.action == action::SIGN_IN
                    && event.outcome == Outcome::Success
                    && event.actor.ip == Some(SPRAY_IP)
            })
            .collect();
        assert_eq!(footholds.len(), 1);
        assert_eq!(footholds[0].actor.id, VICTIM_USER_ID);
        assert_eq!(
            footholds[0].attribute_bool(attr::MFA_SATISFIED),
            Some(false)
        );
    }

    #[test]
    fn the_credential_change_follows_the_grant_by_three_seconds() {
        let events = artex_style_attack();
        let grants = with_action(&events, action::OAUTH_CONSENT_GRANT);
        let credentials = with_action(&events, action::APP_CREDENTIAL_ADD);
        assert_eq!(grants.len(), 1);
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].time - grants[0].time, Duration::seconds(3));
        assert_eq!(grants[0].attribute_str(attr::APP_ID), Some(ROGUE_APP_ID));
        assert_eq!(
            credentials[0].attribute_str(attr::APP_ID),
            Some(ROGUE_APP_ID)
        );
        assert_eq!(grants[0].attribute_bool(attr::PRIVILEGED), Some(true));
        assert_eq!(
            credentials[0]
                .target
                .as_ref()
                .map(|target| target.id.as_str()),
            Some(ROGUE_PRINCIPAL_ID)
        );
    }

    #[test]
    fn the_service_principal_assigns_a_privileged_role_to_itself() {
        let events = artex_style_attack();
        let assignments = with_action(&events, action::ROLE_ASSIGN);
        assert_eq!(assignments.len(), 1);
        let assignment = assignments[0];
        assert_eq!(assignment.actor.kind, EntityKind::ServicePrincipal);
        assert_eq!(assignment.actor.id, ROGUE_PRINCIPAL_ID);
        assert_eq!(assignment.target, Some(assignment.actor.entity()));
        assert_eq!(assignment.attribute_bool(attr::PRIVILEGED), Some(true));
        assert_eq!(
            assignment.attribute_str(attr::ROLE_NAME),
            Some("Global Administrator")
        );
    }

    #[test]
    fn the_rogue_principal_acts_in_two_tenants_from_two_places_within_seconds() {
        let events = artex_style_attack();
        let calls: Vec<&Event> = with_action(&events, action::API_CALL)
            .into_iter()
            .filter(|event| event.actor.id == ROGUE_PRINCIPAL_ID)
            .collect();
        assert_eq!(calls.len(), 6);
        for pair in calls.windows(2) {
            assert_eq!(pair[1].time - pair[0].time, Duration::seconds(2));
            assert_ne!(pair[0].actor.ip, pair[1].actor.ip);
            assert_ne!(
                pair[0].attribute_str(attr::RESOURCE_TENANT),
                pair[1].attribute_str(attr::RESOURCE_TENANT)
            );
            assert_ne!(
                pair[0].attribute_str(attr::COUNTRY),
                pair[1].attribute_str(attr::COUNTRY)
            );
        }
        let tenants: BTreeSet<Option<&str>> = calls
            .iter()
            .map(|event| event.attribute_str(attr::RESOURCE_TENANT))
            .collect();
        assert_eq!(tenants, BTreeSet::from([Some(OTHER_TENANT), Some(TENANT)]));
    }

    #[test]
    fn the_last_attack_event_is_a_honeytoken_trip() {
        let events = artex_style_attack();
        let trips = with_action(&events, action::HONEYTOKEN_TRIP);
        assert_eq!(trips.len(), 1);
        assert_eq!(
            trips[0].attribute_str(attr::HONEYTOKEN_ID),
            Some(HONEYTOKEN_ID)
        );
        assert_eq!(trips[0].actor.id, ROGUE_PRINCIPAL_ID);
        let last_from_rogue_principal = events
            .iter()
            .rfind(|event| event.actor.id == ROGUE_PRINCIPAL_ID)
            .map(|event| event.id);
        assert_eq!(last_from_rogue_principal, Some(trips[0].id));
    }

    #[test]
    fn normal_activity_comes_only_from_office_addresses() {
        let events = artex_style_attack();
        let attack_addresses = [Some(SPRAY_IP), Some(WORKLOAD_IP), Some(DISTANT_IP)];
        let normal: Vec<&Event> = events
            .iter()
            .filter(|event| !attack_addresses.contains(&event.actor.ip))
            .collect();
        assert_eq!(normal.len(), 36);
        assert!(normal.iter().all(|event| event.outcome == Outcome::Success));
        assert!(
            normal
                .iter()
                .all(|event| event.attribute_str(attr::COUNTRY) == Some("US"))
        );
    }
}
