//! The sign-in burst detector.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use aegis_contracts::common::{EventId, Severity};
use aegis_contracts::event::{Event, Outcome, action};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Finding, Tracked, at_least, seconds, tenant_key, text_key};
use crate::attack::technique_in;
use crate::common::{canonical_ip, ip_entity, lock, time_after, time_before};
use crate::error::DetectError;

/// The rule identifier of a sign-in burst detection.
pub const SIGN_IN_BURST_RULE_ID: &str = "aegis.velocity.sign_in_burst";

/// The rule identifier of a detection for a sign-in that succeeds after a burst.
pub const SIGN_IN_AFTER_BURST_RULE_ID: &str = "aegis.velocity.sign_in_after_burst";

/// The largest number of users for which one burst reports a later successful sign-in.
const MAX_REPORTED_USERS: usize = 64;

/// The settings of [`SignInBurst`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignInBurstConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// The length of the sliding window in seconds.
    pub window_seconds: u64,
    /// The number of failed sign-ins from one address in the window that is a burst.
    pub failure_threshold: usize,
    /// The number of different users with a failed sign-in from one address in the window
    /// that is a password spray.
    pub distinct_user_threshold: usize,
    /// The time in seconds after a detection in which the detector reports no more bursts
    /// for the same address.
    pub cooldown_seconds: u64,
    /// Set to `false` to stop the detection for a sign-in that succeeds after a burst.
    pub report_success_after_burst: bool,
    /// The largest number of addresses for which the detector keeps state.
    pub max_tracked_addresses: usize,
}

impl Default for SignInBurstConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 60,
            failure_threshold: 20,
            distinct_user_threshold: 10,
            cooldown_seconds: 900,
            report_success_after_burst: true,
            max_tracked_addresses: 100_000,
        }
    }
}

struct Failure {
    time: DateTime<Utc>,
    user: u64,
    event_id: EventId,
}

/// A burst that the detector reported for one address.
struct Alert {
    /// The first instant after the cooldown.
    until: DateTime<Utc>,
    /// `true` if the burst was a password spray.
    spray: bool,
    /// The users for which the detector reported a successful sign-in after the burst.
    reported_users: Vec<u64>,
}

#[derive(Default)]
struct AddressState {
    /// The failed sign-ins in the window, oldest first. Empty during a cooldown.
    failures: VecDeque<Failure>,
    /// The number of failures in the window for each user.
    users: HashMap<u64, u32>,
    alert: Option<Alert>,
}

impl AddressState {
    fn forget_oldest(&mut self) {
        let Some(oldest) = self.failures.pop_front() else {
            return;
        };
        if let Some(count) = self.users.get_mut(&oldest.user) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.users.remove(&oldest.user);
            }
        }
    }
}

/// Finds many failed sign-ins from one address in a short time.
///
/// The detector counts the failed `sign_in` events of each address in a sliding window.
/// It makes ONE detection when a count reaches its threshold. It then makes no more burst
/// detections for that address until the cooldown ends.
///
/// - Failures for many different users are a password spray: `T1110.003`, `malicious`.
/// - Many failures for few users are a brute force attempt: `T1110`, `suspicious`.
///
/// A sign-in that succeeds from the address during the cooldown gives a second detection
/// (`T1078`). That account is possibly compromised.
pub struct SignInBurst {
    config: SignInBurstConfig,
    window: TimeDelta,
    cooldown: TimeDelta,
    state: Mutex<Tracked<(u64, IpAddr), AddressState>>,
}

impl SignInBurst {
    /// Makes the detector.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the window is zero, a threshold is less than 2,
    /// or `max_tracked_addresses` is zero.
    pub fn new(config: SignInBurstConfig) -> std::result::Result<Self, DetectError> {
        let prefix = "sign_in_burst";
        at_least(
            &format!("{prefix}.window_seconds"),
            usize::try_from(config.window_seconds).unwrap_or(usize::MAX),
            1,
        )?;
        at_least(
            &format!("{prefix}.failure_threshold"),
            config.failure_threshold,
            2,
        )?;
        at_least(
            &format!("{prefix}.distinct_user_threshold"),
            config.distinct_user_threshold,
            2,
        )?;
        at_least(
            &format!("{prefix}.max_tracked_addresses"),
            config.max_tracked_addresses,
            1,
        )?;
        Ok(Self {
            window: seconds(&format!("{prefix}.window_seconds"), config.window_seconds)?,
            cooldown: seconds(
                &format!("{prefix}.cooldown_seconds"),
                config.cooldown_seconds,
            )?,
            state: Mutex::new(Tracked::new(config.max_tracked_addresses)),
            config,
        })
    }

    /// Examines one event. Returns a detection if the event completes a burst, or if it is
    /// a sign-in that succeeds after a burst.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        if !self.config.enabled || event.action != action::SIGN_IN {
            return None;
        }
        let ip = event.actor.ip.map(canonical_ip)?;
        match event.outcome {
            Outcome::Failure => self.failure(event, ip),
            Outcome::Success => self.success(event, ip),
            Outcome::Unknown => None,
        }
    }

    fn failure(&self, event: &Event, ip: IpAddr) -> Option<Detection> {
        let mut tracked = lock(&self.state);
        let state = tracked.upsert((tenant_key(event), ip), event.time, AddressState::default);
        if let Some(alert) = &state.alert {
            if event.time < alert.until {
                return None;
            }
            state.alert = None;
        }

        let newest = state
            .failures
            .back()
            .map_or(event.time, |last| last.time.max(event.time));
        let horizon = time_before(newest, self.window);
        while state
            .failures
            .front()
            .is_some_and(|oldest| oldest.time <= horizon)
        {
            state.forget_oldest();
        }
        if event.time <= horizon {
            return None;
        }
        let user = text_key(&event.actor.id);
        state.failures.push_back(Failure {
            time: event.time,
            user,
            event_id: event.id,
        });
        *state.users.entry(user).or_default() += 1;

        let failures = state.failures.len();
        let users = state.users.len();
        let spray = users >= self.config.distinct_user_threshold;
        if !spray && failures < self.config.failure_threshold {
            return None;
        }

        let event_ids: Vec<EventId> = state
            .failures
            .iter()
            .map(|failure| failure.event_id)
            .collect();
        state.failures.clear();
        state.users.clear();
        state.alert = Some(Alert {
            until: time_after(event.time, self.cooldown),
            spray,
            reported_users: Vec::new(),
        });
        drop(tracked);

        let (technique, verdict, severity, kind) = if spray {
            (
                "T1110.003",
                Verdict::Malicious,
                Severity::High,
                "A password spray",
            )
        } else {
            (
                "T1110",
                Verdict::Suspicious,
                Severity::Medium,
                "A brute force attempt",
            )
        };
        Some(
            Finding {
                rule_id: SIGN_IN_BURST_RULE_ID,
                title: "Sign-in burst from one address",
                description: format!(
                    "{kind}: {failures} failed sign-ins for {users} users came from the address \
                     {ip} in {} seconds.",
                    self.config.window_seconds
                ),
                severity,
                verdict,
                attack: vec![technique_in("credential-access", technique)],
                time: event.time,
                event_ids,
                entities: vec![ip_entity(ip)],
                attributes: vec![
                    ("address", json!(ip.to_string())),
                    ("failures", json!(failures)),
                    ("distinct_users", json!(users)),
                    ("window_seconds", json!(self.config.window_seconds)),
                    ("password_spray", json!(spray)),
                ],
            }
            .into_detection(event),
        )
    }

    fn success(&self, event: &Event, ip: IpAddr) -> Option<Detection> {
        if !self.config.report_success_after_burst {
            return None;
        }
        let mut tracked = lock(&self.state);
        let alert = tracked.get_mut(&(tenant_key(event), ip))?.alert.as_mut()?;
        let user = text_key(&event.actor.id);
        if event.time >= alert.until
            || alert.reported_users.contains(&user)
            || alert.reported_users.len() >= MAX_REPORTED_USERS
        {
            return None;
        }
        alert.reported_users.push(user);
        let spray = alert.spray;
        drop(tracked);

        let (verdict, severity) = if spray {
            (Verdict::Malicious, Severity::High)
        } else {
            (Verdict::Suspicious, Severity::Medium)
        };
        Some(
            Finding {
                rule_id: SIGN_IN_AFTER_BURST_RULE_ID,
                title: "Successful sign-in after a sign-in burst",
                description: format!(
                    "The account {} signed in from the address {ip} after a burst of failed \
                     sign-ins from that address. The account is possibly compromised.",
                    event.actor.id
                ),
                severity,
                verdict,
                attack: vec![technique_in("initial-access", "T1078")],
                time: event.time,
                event_ids: vec![event.id],
                entities: vec![event.actor.entity(), ip_entity(ip)],
                attributes: vec![
                    ("address", json!(ip.to_string())),
                    ("password_spray", json!(spray)),
                ],
            }
            .into_detection(event),
        )
    }
}

#[async_trait]
impl Detector for SignInBurst {
    fn id(&self) -> &str {
        SIGN_IN_BURST_RULE_ID
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
    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::event::EventClass;

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    const SPRAY_IP: &str = "203.0.113.50";

    fn config() -> SignInBurstConfig {
        SignInBurstConfig {
            window_seconds: 10,
            failure_threshold: 6,
            distinct_user_threshold: 4,
            cooldown_seconds: 60,
            ..SignInBurstConfig::default()
        }
    }

    fn sign_in(sequence: u32, milliseconds: i64, user: &str, ip: &str, success: bool) -> Event {
        let mut event = event(
            sequence,
            at(milliseconds),
            EventClass::Authentication,
            action::SIGN_IN,
            actor(EntityKind::User, user, ip),
        );
        if !success {
            event.outcome = Outcome::Failure;
        }
        event
    }

    async fn feed(detector: &SignInBurst, events: &[Event]) -> Vec<Detection> {
        let mut detections = Vec::new();
        for event in events {
            detections.extend(detector.inspect(event).await.unwrap());
        }
        detections
    }

    /// Failed sign-ins from one address, one each 100 milliseconds, for `users` users.
    fn failures(first_sequence: u32, start: i64, count: u32, users: u32, ip: &str) -> Vec<Event> {
        (0..count)
            .map(|index| {
                sign_in(
                    first_sequence + index,
                    start + i64::from(index) * 100,
                    &format!("user-{}", index % users),
                    ip,
                    false,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn failures_for_many_users_give_one_spray_detection() {
        let detector = SignInBurst::new(config()).unwrap();
        let events = failures(0, 0, 200, 50, SPRAY_IP);
        let detections = feed(&detector, &events).await;
        assert_eq!(detections.len(), 1);
        let found = &detections[0];
        assert_eq!(found.rule_id, SIGN_IN_BURST_RULE_ID);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "credential-access",
                "T1110.003",
                "Password Spraying"
            )]
        );
        // The fourth user crosses the threshold.
        assert_eq!(found.time, at(300));
        assert_eq!(
            found.event_ids,
            events[..4].iter().map(|event| event.id).collect::<Vec<_>>()
        );
        assert_eq!(
            found.entities,
            [EntityRef::new(EntityKind::IpAddress, SPRAY_IP)]
        );
        assert_eq!(found.tenant.as_deref(), Some(TENANT));
        assert_eq!(found.attributes["failures"], json!(4));
        assert_eq!(found.attributes["distinct_users"], json!(4));
        assert_eq!(found.attributes["password_spray"], json!(true));
        assert_eq!(found.attributes["detector"], json!("aegis.velocity"));
        assert_eq!(
            found.description,
            "A password spray: 4 failed sign-ins for 4 users came from the address 203.0.113.50 in 10 seconds."
        );
    }

    #[tokio::test]
    async fn failures_for_one_user_give_one_suspicious_brute_force_detection() {
        let detector = SignInBurst::new(config()).unwrap();
        let detections = feed(&detector, &failures(0, 0, 50, 1, SPRAY_IP)).await;
        assert_eq!(detections.len(), 1);
        let found = &detections[0];
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.severity, Severity::Medium);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "credential-access",
                "T1110",
                "Brute Force"
            )]
        );
        assert_eq!(found.event_ids.len(), 6);
        assert_eq!(found.attributes["failures"], json!(6));
        assert_eq!(found.attributes["distinct_users"], json!(1));
        assert_eq!(found.attributes["password_spray"], json!(false));
    }

    #[tokio::test]
    async fn counts_below_the_thresholds_give_no_detection() {
        let detector = SignInBurst::new(config()).unwrap();
        // Five failures for three users: one below each threshold.
        let detections = feed(&detector, &failures(0, 0, 5, 3, SPRAY_IP)).await;
        assert_eq!(detections, []);
    }

    #[tokio::test]
    async fn failures_that_are_not_in_one_window_give_no_detection() {
        let detector = SignInBurst::new(config()).unwrap();
        // One failure each 4 seconds: at most three in a window of 10 seconds.
        let events: Vec<Event> = (0..40_u32)
            .map(|index| {
                sign_in(
                    index,
                    i64::from(index) * 4_000,
                    &format!("user-{index}"),
                    SPRAY_IP,
                    false,
                )
            })
            .collect();
        assert_eq!(feed(&detector, &events).await, []);
    }

    #[tokio::test]
    async fn the_window_is_exclusive_at_its_old_end() {
        let detector = SignInBurst::new(config()).unwrap();
        let mut events = failures(0, 0, 3, 3, SPRAY_IP);
        // Exactly 10 seconds after the first failure, the first failure is out of the window.
        events.push(sign_in(3, 10_000, "user-3", SPRAY_IP, false));
        assert_eq!(feed(&detector, &events).await, []);
        // The next failure completes four users in the window: 100, 200, 10 000, 10 050.
        let detections = feed(&detector, &[sign_in(4, 10_050, "user-4", SPRAY_IP, false)]).await;
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].event_ids.len(), 4);
    }

    #[tokio::test]
    async fn each_address_and_each_tenant_has_its_own_count() {
        let detector = SignInBurst::new(config()).unwrap();
        let mut events = Vec::new();
        for index in 0..12_u32 {
            let ip = format!("203.0.113.{}", index % 4);
            events.push(sign_in(
                index,
                i64::from(index) * 10,
                &format!("user-{index}"),
                &ip,
                false,
            ));
        }
        assert_eq!(feed(&detector, &events).await, []);

        let mut split = failures(100, 1_000, 6, 6, "198.51.100.7");
        for (index, event) in split.iter_mut().enumerate() {
            event.source.tenant = Some(format!("tenant-{}", index % 2));
        }
        assert_eq!(feed(&detector, &split).await, []);
    }

    #[tokio::test]
    async fn a_burst_after_the_cooldown_gives_a_new_detection() {
        let detector = SignInBurst::new(config()).unwrap();
        let first = feed(&detector, &failures(0, 0, 100, 50, SPRAY_IP)).await;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].time, at(300));
        // The cooldown of 60 seconds ends at 60 300. A failure before that is not counted.
        let during = feed(&detector, &failures(200, 50_000, 100, 50, SPRAY_IP)).await;
        assert_eq!(during, []);
        let after = feed(&detector, &failures(400, 60_300, 100, 50, SPRAY_IP)).await;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].time, at(60_600));
        assert_ne!(after[0].id, first[0].id);
    }

    #[tokio::test]
    async fn a_success_after_a_spray_gives_one_detection_for_each_account() {
        let detector = SignInBurst::new(config()).unwrap();
        assert_eq!(
            feed(&detector, &failures(0, 0, 20, 20, SPRAY_IP))
                .await
                .len(),
            1
        );

        let foothold = sign_in(100, 5_000, "user-dana", SPRAY_IP, true);
        let detections = feed(&detector, std::slice::from_ref(&foothold)).await;
        assert_eq!(detections.len(), 1);
        let found = &detections[0];
        assert_eq!(found.rule_id, SIGN_IN_AFTER_BURST_RULE_ID);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "initial-access",
                "T1078",
                "Valid Accounts"
            )]
        );
        assert_eq!(found.event_ids, [foothold.id]);
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::User, "user-dana"),
                EntityRef::new(EntityKind::IpAddress, SPRAY_IP),
            ]
        );

        // The same account again: no second detection. A different account: one more.
        let again = sign_in(101, 6_000, "user-dana", SPRAY_IP, true);
        assert_eq!(feed(&detector, &[again]).await, []);
        let other = sign_in(102, 7_000, "user-eve", SPRAY_IP, true);
        assert_eq!(feed(&detector, &[other]).await.len(), 1);
    }

    #[tokio::test]
    async fn a_success_gives_no_detection_without_a_burst_or_after_the_cooldown() {
        let detector = SignInBurst::new(config()).unwrap();
        // No burst.
        assert_eq!(
            feed(&detector, &[sign_in(0, 0, "user-1", SPRAY_IP, true)]).await,
            []
        );
        // Failures below the threshold, then a success.
        feed(&detector, &failures(1, 100, 3, 3, SPRAY_IP)).await;
        assert_eq!(
            feed(&detector, &[sign_in(9, 500, "user-1", SPRAY_IP, true)]).await,
            []
        );
        // A burst, then a success from a different address, and one after the cooldown.
        assert_eq!(
            feed(&detector, &failures(10, 1_000, 20, 20, SPRAY_IP))
                .await
                .len(),
            1
        );
        let elsewhere = sign_in(50, 2_000, "user-1", "198.51.100.10", true);
        assert_eq!(feed(&detector, &[elsewhere]).await, []);
        let late = sign_in(51, 70_000, "user-1", SPRAY_IP, true);
        assert_eq!(feed(&detector, &[late]).await, []);
    }

    #[tokio::test]
    async fn a_success_after_a_brute_force_burst_is_suspicious() {
        let detector = SignInBurst::new(config()).unwrap();
        assert_eq!(
            feed(&detector, &failures(0, 0, 6, 1, SPRAY_IP)).await.len(),
            1
        );
        let detections = feed(&detector, &[sign_in(10, 1_000, "user-0", SPRAY_IP, true)]).await;
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].verdict, Verdict::Suspicious);
        assert_eq!(detections[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn the_success_detection_can_be_set_to_off() {
        let detector = SignInBurst::new(SignInBurstConfig {
            report_success_after_burst: false,
            ..config()
        })
        .unwrap();
        assert_eq!(
            feed(&detector, &failures(0, 0, 20, 20, SPRAY_IP))
                .await
                .len(),
            1
        );
        assert_eq!(
            feed(&detector, &[sign_in(100, 5_000, "user-1", SPRAY_IP, true)]).await,
            []
        );
    }

    #[tokio::test]
    async fn events_that_are_not_sign_ins_with_an_address_are_ignored() {
        let detector = SignInBurst::new(config()).unwrap();
        let mut events = failures(0, 0, 20, 20, SPRAY_IP);
        for event in &mut events {
            event.action = action::API_CALL.to_owned();
        }
        assert_eq!(feed(&detector, &events).await, []);

        let mut no_address = failures(100, 0, 20, 20, SPRAY_IP);
        for event in &mut no_address {
            event.actor.ip = None;
        }
        assert_eq!(feed(&detector, &no_address).await, []);

        let mut unknown = failures(200, 0, 20, 20, SPRAY_IP);
        for event in &mut unknown {
            event.outcome = Outcome::Unknown;
        }
        assert_eq!(feed(&detector, &unknown).await, []);
    }

    #[tokio::test]
    async fn a_detector_that_is_not_enabled_gives_no_detection() {
        let detector = SignInBurst::new(SignInBurstConfig {
            enabled: false,
            ..config()
        })
        .unwrap();
        assert_eq!(
            feed(&detector, &failures(0, 0, 100, 50, SPRAY_IP)).await,
            []
        );
    }

    #[tokio::test]
    async fn the_state_for_one_address_and_for_all_addresses_is_limited() {
        let detector = SignInBurst::new(SignInBurstConfig {
            max_tracked_addresses: 8,
            ..config()
        })
        .unwrap();
        // One failure from each of 1 000 addresses.
        let events: Vec<Event> = (0..1_000_u32)
            .map(|index| {
                let ip = format!("198.51.{}.{}", index / 250, index % 250);
                sign_in(index, i64::from(index), "user-1", &ip, false)
            })
            .collect();
        assert_eq!(feed(&detector, &events).await, []);
        assert!(lock(&detector.state).len() <= 8);

        // A long burst from one address keeps no failures after its detection.
        let burst = failures(2_000, 5_000, 500, 100, SPRAY_IP);
        assert_eq!(feed(&detector, &burst).await.len(), 1);
        let mut tracked = lock(&detector.state);
        let key = (text_key(TENANT), SPRAY_IP.parse::<IpAddr>().unwrap());
        let state = tracked.get_mut(&key).unwrap();
        assert_eq!(state.failures.len(), 0);
        assert_eq!(state.users.len(), 0);
    }

    #[tokio::test]
    async fn an_event_that_is_older_than_the_window_is_not_counted() {
        let detector = SignInBurst::new(config()).unwrap();
        let mut events = failures(0, 20_000, 3, 3, SPRAY_IP);
        // This failure arrives late. It is 15 seconds older than the newest failure.
        events.push(sign_in(3, 5_200, "user-9", SPRAY_IP, false));
        assert_eq!(feed(&detector, &events).await, []);
        let mut tracked = lock(&detector.state);
        let key = (text_key(TENANT), SPRAY_IP.parse::<IpAddr>().unwrap());
        assert_eq!(tracked.get_mut(&key).unwrap().failures.len(), 3);
    }

    #[tokio::test]
    async fn events_at_the_ends_of_the_time_range_do_not_panic() {
        use chrono::{DateTime, Utc};

        let at_instant = |time: DateTime<Utc>| {
            let mut events = failures(0, 0, 4, 4, SPRAY_IP);
            let mut success = sign_in(9, 0, "user-0", SPRAY_IP, true);
            for event in events.iter_mut().chain(std::iter::once(&mut success)) {
                event.time = time;
            }
            (events, success)
        };

        // Four users at the last instant of the range are a spray. The cooldown cannot end
        // after the range, so a sign-in at the same instant is not in the cooldown.
        let detector = SignInBurst::new(config()).unwrap();
        let (events, success) = at_instant(DateTime::<Utc>::MAX_UTC);
        let detections = feed(&detector, &events).await;
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].time, DateTime::<Utc>::MAX_UTC);
        assert_eq!(feed(&detector, &[success]).await, []);

        // The window cannot start before the range. Events at the first instant of the
        // range are thus at the old end of the window, which the window excludes.
        let detector = SignInBurst::new(config()).unwrap();
        let (events, success) = at_instant(DateTime::<Utc>::MIN_UTC);
        assert_eq!(feed(&detector, &events).await, []);
        assert_eq!(feed(&detector, &[success]).await, []);
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        let cases = [
            (
                SignInBurstConfig {
                    window_seconds: 0,
                    ..config()
                },
                "sign_in_burst.window_seconds must be 1 or more, but it is 0",
            ),
            (
                SignInBurstConfig {
                    failure_threshold: 1,
                    ..config()
                },
                "sign_in_burst.failure_threshold must be 2 or more, but it is 1",
            ),
            (
                SignInBurstConfig {
                    distinct_user_threshold: 0,
                    ..config()
                },
                "sign_in_burst.distinct_user_threshold must be 2 or more, but it is 0",
            ),
            (
                SignInBurstConfig {
                    max_tracked_addresses: 0,
                    ..config()
                },
                "sign_in_burst.max_tracked_addresses must be 1 or more, but it is 0",
            ),
        ];
        for (config, expected) in cases {
            let error = SignInBurst::new(config).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
    }

    #[test]
    fn the_settings_read_from_a_partial_map_and_reject_unknown_keys() {
        let config: SignInBurstConfig =
            serde_json::from_value(json!({ "failure_threshold": 50 })).unwrap();
        assert_eq!(config.failure_threshold, 50);
        assert_eq!(config.window_seconds, 60);
        assert!(config.enabled);
        let error =
            serde_json::from_value::<SignInBurstConfig>(json!({ "treshold": 5 })).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `treshold`"),
            "{error}"
        );
    }
}
