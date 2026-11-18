//! The velocity and behavior detectors of tier 1.
//!
//! Each detector finds one pattern of a machine-speed attack on identity:
//!
//! | Detector | Pattern | Technique |
//! | --- | --- | --- |
//! | [`SignInBurst`] | Many failed sign-ins from one address | T1110.003 |
//! | [`PrivilegedSelfAssignment`] | A workload identity gives itself a privileged role | T1098.003 |
//! | [`CredentialAfterGrant`] | A new application credential immediately after a grant | T1098.001 |
//! | [`ImpossibleSpeed`] | One principal in two distant places, or two tenants, in seconds | T1078.004 |
//! | [`MachineCadence`] | A chain of different sensitive actions at the speed of a machine | T1059.009 |
//! | [`EndpointProbe`] | One client that asks for many paths that do not exist, or for a decoy path | T1595.003 |
//!
//! # Time
//!
//! Each detector uses the time of the events and not the clock of the host. A replay of a
//! recorded log thus gives the same detections as the live stream did.
//!
//! # Memory
//!
//! Each detector keeps state for a limited number of keys. When the limit is reached, the
//! detector drops the keys that it saw least recently. The state for one key is also
//! limited.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use aegis_contracts::common::{EntityRef, EventId, Severity};
use aegis_contracts::event::Event;
use aegis_contracts::{AttackTechnique, Detection, DetectionTier, Verdict};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::common::{detection_id, event_tenant};
use crate::error::DetectError;

mod burst;
mod cadence;
mod credential;
mod probe;
mod self_assign;
mod speed;

pub use burst::{
    SIGN_IN_AFTER_BURST_RULE_ID, SIGN_IN_BURST_RULE_ID, SignInBurst, SignInBurstConfig,
};
pub use cadence::{
    MACHINE_CADENCE_RULE_ID, MAX_CHAIN_ACTIONS, MachineCadence, MachineCadenceConfig,
    REGULARITY_MIN_ACTIONS,
};
pub use credential::{
    CREDENTIAL_AFTER_GRANT_RULE_ID, CredentialAfterGrant, CredentialAfterGrantConfig,
};
pub use probe::{
    DECOY_PATH_RULE_ID, ENDPOINT_PROBE_RULE_ID, EndpointProbe, EndpointProbeConfig,
    MAX_DISTINCT_PATH_THRESHOLD,
};
pub use self_assign::{
    PRIVILEGED_SELF_ASSIGNMENT_RULE_ID, PrivilegedSelfAssignment, PrivilegedSelfAssignmentConfig,
};
pub use speed::{IMPOSSIBLE_SPEED_RULE_ID, ImpossibleSpeed, ImpossibleSpeedConfig, haversine_km};

/// The value of the `detector` attribute of each velocity detection.
pub const VELOCITY_DETECTOR: &str = "aegis.velocity";

/// The settings of all velocity detectors.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VelocityConfig {
    /// The settings of [`SignInBurst`].
    pub sign_in_burst: SignInBurstConfig,
    /// The settings of [`PrivilegedSelfAssignment`].
    pub privileged_self_assignment: PrivilegedSelfAssignmentConfig,
    /// The settings of [`CredentialAfterGrant`].
    pub credential_after_grant: CredentialAfterGrantConfig,
    /// The settings of [`ImpossibleSpeed`].
    pub impossible_speed: ImpossibleSpeedConfig,
    /// The settings of [`MachineCadence`].
    pub machine_cadence: MachineCadenceConfig,
    /// The settings of [`EndpointProbe`].
    pub endpoint_probe: EndpointProbeConfig,
}

/// Converts a number of seconds from a configuration to a time difference.
pub(crate) fn seconds(name: &str, value: u64) -> Result<TimeDelta, DetectError> {
    i64::try_from(value)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(|| DetectError::Config(format!("{name} is too large: {value}")))
}

/// Returns an error if a setting that must be at least `least` is smaller.
pub(crate) fn at_least(name: &str, value: usize, least: usize) -> Result<(), DetectError> {
    if value < least {
        return Err(DetectError::Config(format!(
            "{name} must be {least} or more, but it is {value}"
        )));
    }
    Ok(())
}

/// Returns a number that identifies the tenant of an event inside one detector.
///
/// The state keys hold this number and not the tenant text, so that a lookup does not
/// allocate.
pub(crate) fn tenant_key(event: &Event) -> u64 {
    text_key(event_tenant(event).unwrap_or_default())
}

/// Returns a number that identifies a text inside one detector.
pub(crate) fn text_key(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

struct Slot<V> {
    last_seen: DateTime<Utc>,
    value: V,
}

/// State for a limited number of keys. A full map drops the keys with the oldest events.
pub(crate) struct Tracked<K, V> {
    slots: BTreeMap<K, Slot<V>>,
    capacity: usize,
}

impl<K: Ord, V> Tracked<K, V> {
    /// Makes a map that holds at most `capacity` keys.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            slots: BTreeMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Returns the number of keys.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// Returns the state of a key, if the map has it.
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.slots.get_mut(key).map(|slot| &mut slot.value)
    }

    /// Returns the state of each key, in key order.
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.slots.values().map(|slot| &slot.value)
    }

    /// Returns the state of a key, and records that an event at `now` used it. Makes the
    /// state with `make` if the map does not have the key.
    pub(crate) fn upsert(
        &mut self,
        key: K,
        now: DateTime<Utc>,
        make: impl FnOnce() -> V,
    ) -> &mut V {
        if self.slots.len() >= self.capacity && !self.slots.contains_key(&key) {
            self.evict();
        }
        let slot = self.slots.entry(key).or_insert_with(|| Slot {
            last_seen: now,
            value: make(),
        });
        slot.last_seen = slot.last_seen.max(now);
        &mut slot.value
    }

    /// Drops one eighth of the keys: those with the oldest events. Keys with equal times go
    /// in key order, so that the result is the same in each run.
    fn evict(&mut self) {
        let batch = (self.capacity / 8).max(1).min(self.slots.len());
        let mut times: Vec<DateTime<Utc>> =
            self.slots.values().map(|slot| slot.last_seen).collect();
        let Some(index) = batch.checked_sub(1) else {
            return;
        };
        let (_, cutoff, _) = times.select_nth_unstable(index);
        let cutoff = *cutoff;
        let older = self
            .slots
            .values()
            .filter(|slot| slot.last_seen < cutoff)
            .count();
        let mut at_cutoff = batch.saturating_sub(older);
        self.slots.retain(|_, slot| {
            if slot.last_seen < cutoff {
                false
            } else if slot.last_seen == cutoff && at_cutoff > 0 {
                at_cutoff -= 1;
                false
            } else {
                true
            }
        });
    }
}

/// The data of one velocity detection.
pub(crate) struct Finding {
    pub(crate) rule_id: &'static str,
    pub(crate) title: &'static str,
    pub(crate) description: String,
    pub(crate) severity: Severity,
    pub(crate) verdict: Verdict,
    pub(crate) attack: Vec<AttackTechnique>,
    pub(crate) time: DateTime<Utc>,
    pub(crate) event_ids: Vec<EventId>,
    pub(crate) entities: Vec<EntityRef>,
    pub(crate) attributes: Vec<(&'static str, Value)>,
}

impl Finding {
    /// Makes the detection. `event` is the event that completed the pattern.
    pub(crate) fn into_detection(self, event: &Event) -> Detection {
        let mut attributes: BTreeMap<String, Value> = self
            .attributes
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect();
        attributes.insert("detector".to_owned(), json!(VELOCITY_DETECTOR));
        Detection {
            id: detection_id(self.rule_id, &self.event_ids),
            rule_id: self.rule_id.to_owned(),
            title: self.title.to_owned(),
            description: self.description,
            severity: self.severity,
            verdict: self.verdict,
            tier: DetectionTier::Deterministic,
            time: self.time,
            attack: self.attack,
            event_ids: self.event_ids,
            entities: self.entities,
            tenant: event_tenant(event).map(str::to_owned),
            attributes,
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Event builders for the tests of the velocity detectors.

    use std::net::IpAddr;

    use aegis_contracts::common::{EntityKind, EventId};
    use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome};
    use chrono::{DateTime, TimeDelta, Utc};
    use uuid::Uuid;

    /// The tenant of the test events.
    pub(crate) const TENANT: &str = "tenant-1";

    /// Returns the time `milliseconds` after the start of the test log.
    pub(crate) fn at(milliseconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_793_696_400, 0).unwrap() + TimeDelta::milliseconds(milliseconds)
    }

    /// Makes an event with an identifier that depends on `sequence`.
    pub(crate) fn event(
        sequence: u32,
        time: DateTime<Utc>,
        class: EventClass,
        action: &str,
        actor: Actor,
    ) -> Event {
        Event::new(
            time,
            EventSource::new("test", "vendor", "product").with_tenant(TENANT),
            class,
            action,
            actor,
        )
        .with_id(EventId(Uuid::from_u128(u128::from(sequence))))
        .with_outcome(Outcome::Success)
    }

    /// Makes an actor with an address.
    pub(crate) fn actor(kind: EntityKind, id: &str, ip: &str) -> Actor {
        Actor::new(kind, id).with_ip(ip.parse::<IpAddr>().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::at;
    use super::*;

    #[test]
    fn tracked_keeps_at_most_its_capacity_and_drops_the_oldest_keys() {
        let mut tracked: Tracked<u32, &str> = Tracked::new(16);
        for key in 0..16_u32 {
            tracked.upsert(key, at(i64::from(key)), || "state");
        }
        assert_eq!(tracked.len(), 16);
        // Key 0 gets a new event, so it is no longer the oldest key.
        tracked.upsert(0, at(100), || "other");
        assert_eq!(tracked.len(), 16);

        tracked.upsert(16, at(101), || "state");
        // One eighth of 16 keys go: keys 1 and 2.
        assert_eq!(tracked.len(), 15);
        assert!(tracked.get_mut(&0).is_some());
        assert!(tracked.get_mut(&1).is_none());
        assert!(tracked.get_mut(&2).is_none());
        assert!(tracked.get_mut(&3).is_some());
        assert!(tracked.get_mut(&16).is_some());
    }

    #[test]
    fn tracked_drops_keys_with_equal_times_in_key_order() {
        let mut tracked: Tracked<u32, ()> = Tracked::new(8);
        for key in (0..8_u32).rev() {
            tracked.upsert(key, at(0), || ());
        }
        tracked.upsert(8, at(0), || ());
        assert_eq!(tracked.len(), 8);
        assert!(tracked.get_mut(&0).is_none());
        assert!(tracked.get_mut(&1).is_some());
        assert!(tracked.get_mut(&8).is_some());
    }

    #[test]
    fn tracked_keeps_the_state_of_a_key_and_never_grows_past_its_capacity() {
        let mut tracked: Tracked<u32, u32> = Tracked::new(4);
        *tracked.upsert(7, at(0), || 1) += 1;
        assert_eq!(*tracked.upsert(7, at(1), || 100), 2);
        for key in 0..1_000_u32 {
            tracked.upsert(key, at(i64::from(key) + 2), || 0);
            assert!(tracked.len() <= 4);
        }
        assert_eq!(Tracked::<u32, u32>::new(0).capacity, 1);
    }

    #[test]
    fn an_old_event_does_not_make_a_key_older() {
        let mut tracked: Tracked<u32, ()> = Tracked::new(2);
        tracked.upsert(1, at(10), || ());
        tracked.upsert(2, at(5), || ());
        tracked.upsert(1, at(0), || ());
        tracked.upsert(3, at(20), || ());
        assert!(tracked.get_mut(&1).is_some());
        assert!(tracked.get_mut(&2).is_none());
    }

    #[test]
    fn seconds_rejects_a_value_that_does_not_fit() {
        assert_eq!(
            seconds("window_seconds", 60).unwrap(),
            TimeDelta::seconds(60)
        );
        let error = seconds("window_seconds", u64::MAX).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "detector configuration: window_seconds is too large: {}",
                u64::MAX
            )
        );
    }

    #[test]
    fn at_least_names_the_setting_and_the_limit() {
        assert!(at_least("failure_threshold", 2, 2).is_ok());
        let error = at_least("failure_threshold", 1, 2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "detector configuration: failure_threshold must be 2 or more, but it is 1"
        );
    }

    #[test]
    fn text_keys_are_stable_and_differ_for_different_text() {
        assert_eq!(text_key("tenant-a"), text_key("tenant-a"));
        assert_ne!(text_key("tenant-a"), text_key("tenant-b"));
    }
}
