//! Flood protection for the engine itself.
//!
//! An attacker can send events only to make AEGIS work: to use the model budget, and to
//! fill the queue of incidents. Three limits stop this. Each limit uses the time of the
//! events and keeps a limited amount of state.
//!
//! | Limit | Setting | Effect |
//! | --- | --- | --- |
//! | Suppression | `aegis.suppress` of a rule, `suppress_seconds` of an indicator | One rule and one key give one detection in a window. The engine counts the other matches in a [`SuppressionSummary`]. |
//! | Tier 2 quota | [`LlmTriageConfig`](crate::llm::LlmTriageConfig) | A limited number of model requests for each source and each tenant in a window. |
//! | Incident coalescing | [`BusRunnerConfig`](crate::engine::BusRunnerConfig) | A limited number of published states for one incident in a window. |
//!
//! [`DetectionEngine::flood_counters`](crate::engine::DetectionEngine::flood_counters)
//! returns the count of each limit.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_contracts::common::{DetectionId, EventId, IncidentId, Severity};
use aegis_contracts::{Detection, Incident, IncidentStatus};
use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;

use crate::common::{clean_text, digest128, kind_name, time_after};
use crate::error::DetectError;
use crate::velocity::Tracked;

/// The largest number of rule keys for which the engine keeps a suppression window.
pub const MAX_SUPPRESSION_KEYS: usize = 100_000;

/// The largest number of sources, and of tenants, for which the engine keeps a quota.
pub const MAX_QUOTA_KEYS: usize = 10_000;

/// The largest number of incidents for which a coalescer keeps a window.
pub const MAX_COALESCED_INCIDENTS: usize = 10_000;

/// The number of characters of a suppression key that a summary keeps.
const MAX_KEY_CHARS: usize = 200;

/// The counts of the flood protection of one engine, from its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct FloodCounters {
    /// The number of rule matches that gave no detection, because the rule had a
    /// detection for the same key in the window.
    pub suppressed_matches: u64,
    /// The number of detections for a rule that matched many times for one key.
    pub repeat_detections: u64,
    /// The number of `suspicious` detections that got no model request, because a quota
    /// had no request left.
    pub triage_quota_denials: u64,
    /// The number of incident states that the bus runner did not publish, because a newer
    /// state of the same incident replaced them.
    pub coalesced_incident_updates: u64,
}

/// The counters behind [`FloodCounters`]. Each task can add to them.
#[derive(Debug, Default)]
pub(crate) struct FloodMeter {
    suppressed_matches: AtomicU64,
    repeat_detections: AtomicU64,
    triage_quota_denials: AtomicU64,
    coalesced_incident_updates: AtomicU64,
}

impl FloodMeter {
    pub(crate) fn suppressed(&self) {
        self.suppressed_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn repeated(&self) {
        self.repeat_detections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn quota_denied(&self) {
        self.triage_quota_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn coalesced(&self, count: u64) {
        self.coalesced_incident_updates
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn read(&self) -> FloodCounters {
        FloodCounters {
            suppressed_matches: self.suppressed_matches.load(Ordering::Relaxed),
            repeat_detections: self.repeat_detections.load(Ordering::Relaxed),
            triage_quota_denials: self.triage_quota_denials.load(Ordering::Relaxed),
            coalesced_incident_updates: self.coalesced_incident_updates.load(Ordering::Relaxed),
        }
    }
}

/// The matches of one rule for one key in one window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressionSummary {
    /// The identifier of the rule or the indicator.
    pub rule_id: String,
    /// The key: the values of the key fields, with no control characters and with a
    /// limited length.
    pub key: String,
    /// The tenant of the matches.
    pub tenant: Option<String>,
    /// The time of the first match of the window.
    pub window_start: DateTime<Utc>,
    /// The time of the newest match of the window.
    pub last_seen: DateTime<Utc>,
    /// The number of matches in the window. The first match is included.
    pub matches: u64,
    /// The identifier of the detection that the first match gave.
    pub detection_id: DetectionId,
}

struct SuppressionEntry {
    summary: SuppressionSummary,
    /// The first event of the first match, if the detection names an event.
    first_event: Option<EventId>,
    repeat_reported: bool,
}

/// What the engine does with one rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The match is the first of a window. It gives its detection. `previous_matches` is
    /// the count of the window before, if that window had more than one match.
    Emit {
        /// The number of matches in the window before this one.
        previous_matches: u64,
    },
    /// The match is counted and gives no detection.
    Suppress,
    /// The match is counted, and the count reached the `repeat` setting of the rule.
    Repeat {
        /// The number of matches in the window.
        matches: u64,
        /// The first event of the window, if its detection names an event.
        first_event: Option<EventId>,
        /// The detection of the first event of the window.
        first_detection: DetectionId,
    },
}

/// Returns the default key of a detection: its entities, in order.
pub(crate) fn entity_key(detection: &Detection) -> Vec<String> {
    let mut parts: Vec<String> = detection
        .entities
        .iter()
        .map(|entity| format!("{}:{}", kind_name(entity.kind), entity.id))
        .collect();
    parts.sort_unstable();
    parts.dedup();
    parts
}

/// The suppression windows of all rules.
pub(crate) struct Suppressor {
    entries: Tracked<u128, SuppressionEntry>,
}

impl Suppressor {
    pub(crate) fn new() -> Self {
        Self {
            entries: Tracked::new(MAX_SUPPRESSION_KEYS),
        }
    }

    /// Counts one match of a rule. `detection` is the detection that the match gives if
    /// it is the first of a window. `repeat_count` is the `repeat` setting of the rule.
    pub(crate) fn admit(
        &mut self,
        detection: &Detection,
        key: &[String],
        window: TimeDelta,
        repeat_count: Option<u64>,
    ) -> Admission {
        let tenant = detection.tenant.as_deref().unwrap_or_default();
        let mut material: Vec<&[u8]> = Vec::with_capacity(key.len() + 3);
        material.push(b"aegis-detect/suppress");
        material.push(detection.rule_id.as_bytes());
        material.push(tenant.as_bytes());
        material.extend(key.iter().map(String::as_bytes));
        let digest = digest128(&material);

        let time = detection.time;
        let fresh = || SuppressionEntry {
            summary: SuppressionSummary {
                rule_id: detection.rule_id.clone(),
                key: clean_text(&key.join(", "), MAX_KEY_CHARS),
                tenant: detection.tenant.clone(),
                window_start: time,
                last_seen: time,
                matches: 1,
                detection_id: detection.id,
            },
            first_event: detection.event_ids.first().copied(),
            repeat_reported: false,
        };
        let mut is_new = false;
        let entry = self.entries.upsert(digest, time, || {
            is_new = true;
            fresh()
        });
        if is_new {
            return Admission::Emit {
                previous_matches: 0,
            };
        }
        if time >= time_after(entry.summary.window_start, window) {
            let previous = entry.summary.matches;
            *entry = fresh();
            return Admission::Emit {
                previous_matches: if previous > 1 { previous } else { 0 },
            };
        }
        let summary = &mut entry.summary;
        summary.matches = summary.matches.saturating_add(1);
        summary.last_seen = summary.last_seen.max(time);
        if !entry.repeat_reported && repeat_count.is_some_and(|count| summary.matches >= count) {
            entry.repeat_reported = true;
            return Admission::Repeat {
                matches: summary.matches,
                first_event: entry.first_event,
                first_detection: summary.detection_id,
            };
        }
        Admission::Suppress
    }

    /// Returns the windows that counted more than one match, in order of rule and time.
    pub(crate) fn summaries(&self) -> Vec<SuppressionSummary> {
        let mut summaries: Vec<SuppressionSummary> = self
            .entries
            .values()
            .filter(|entry| entry.summary.matches > 1)
            .map(|entry| entry.summary.clone())
            .collect();
        summaries.sort_by(|left, right| {
            (&left.rule_id, left.window_start, &left.key).cmp(&(
                &right.rule_id,
                right.window_start,
                &right.key,
            ))
        });
        summaries
    }
}

/// The scope of a tier 2 quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaScope {
    /// The quota of one source connector.
    Source,
    /// The quota of one tenant.
    Tenant,
}

impl QuotaScope {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Tenant => "tenant",
        }
    }
}

struct QuotaWindow {
    start: DateTime<Utc>,
    used: u32,
}

/// The tier 2 quota: a limited number of model requests for each source connector and
/// each tenant in a window.
///
/// A window starts with the first request of a source or a tenant, in event time.
pub(crate) struct TriageQuota {
    window: TimeDelta,
    per_source: u32,
    per_tenant: u32,
    sources: Tracked<u128, QuotaWindow>,
    tenants: Tracked<u128, QuotaWindow>,
}

impl TriageQuota {
    pub(crate) fn new(window: TimeDelta, per_source: u32, per_tenant: u32) -> Self {
        Self {
            window,
            per_source,
            per_tenant,
            sources: Tracked::new(MAX_QUOTA_KEYS),
            tenants: Tracked::new(MAX_QUOTA_KEYS),
        }
    }

    /// Returns the limit of a scope.
    pub(crate) fn limit(&self, scope: QuotaScope) -> u32 {
        match scope {
            QuotaScope::Source => self.per_source,
            QuotaScope::Tenant => self.per_tenant,
        }
    }

    /// Takes one request from the quota of the source and from the quota of the tenant.
    ///
    /// Returns the scope that has no request left. The function then takes nothing.
    pub(crate) fn take(
        &mut self,
        source: &str,
        tenant: Option<&str>,
        time: DateTime<Utc>,
    ) -> Result<(), QuotaScope> {
        let window = self.window;
        let open = |table: &mut Tracked<u128, QuotaWindow>, key: u128| -> u32 {
            let slot = table.upsert(key, time, || QuotaWindow {
                start: time,
                used: 0,
            });
            if time >= time_after(slot.start, window) {
                slot.start = time;
                slot.used = 0;
            }
            slot.used
        };
        let source_key = digest128(&[b"source", source.as_bytes()]);
        let tenant_key = digest128(&[b"tenant", tenant.unwrap_or_default().as_bytes()]);
        if open(&mut self.sources, source_key) >= self.per_source {
            return Err(QuotaScope::Source);
        }
        if open(&mut self.tenants, tenant_key) >= self.per_tenant {
            return Err(QuotaScope::Tenant);
        }
        for (table, key) in [
            (&mut self.sources, source_key),
            (&mut self.tenants, tenant_key),
        ] {
            if let Some(slot) = table.get_mut(&key) {
                slot.used = slot.used.saturating_add(1);
            }
        }
        Ok(())
    }
}

struct CoalescerEntry {
    window_start: DateTime<Utc>,
    /// The number of states that left in the window.
    released: u32,
    /// The severity of the newest state that left.
    severity: Severity,
    /// The newest state that did not leave.
    held: Option<Incident>,
}

/// Limits how many states of one incident leave in a window.
///
/// Each change of an incident gives a new state of the full incident. A flood of
/// detections for one incident thus gives a flood of states. The coalescer lets
/// `max_updates` states of one incident through in each window. It holds the newest state
/// that is over the limit, and drops the states that the held state replaces. The held
/// state leaves when the window ends.
///
/// These states always leave immediately:
///
/// - The first state of an incident.
/// - A state with a higher severity than the last state that left.
/// - A state with a status that is not `open`, for example the last state of an incident
///   that a merge replaced.
///
/// The windows use the time of the events. Call [`IncidentCoalescer::release_due`] with
/// the time of each event, and [`IncidentCoalescer::flush`] when the stream of events
/// stops, so that no held state is lost.
pub struct IncidentCoalescer {
    max_updates: u32,
    window: TimeDelta,
    entries: BTreeMap<IncidentId, CoalescerEntry>,
    /// The end of the window of each incident that has a held state.
    due: BTreeSet<(DateTime<Utc>, IncidentId)>,
    coalesced: u64,
}

impl IncidentCoalescer {
    /// Makes a coalescer that lets `max_updates` states of one incident through in each
    /// window of `window_seconds`.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if `max_updates` or `window_seconds` is zero, or if
    /// the window does not fit a time difference.
    pub fn new(max_updates: u32, window_seconds: u64) -> Result<Self, DetectError> {
        if max_updates == 0 {
            return Err(DetectError::Config(
                "max_incident_updates must be 1 or more, but it is 0".to_owned(),
            ));
        }
        let window = i64::try_from(window_seconds)
            .ok()
            .filter(|seconds| *seconds > 0)
            .and_then(TimeDelta::try_seconds)
            .ok_or_else(|| {
                DetectError::Config(format!(
                    "incident_update_window_seconds must be 1 or more and must fit a time \
                     difference, but it is {window_seconds}"
                ))
            })?;
        Ok(Self {
            max_updates,
            window,
            entries: BTreeMap::new(),
            due: BTreeSet::new(),
            coalesced: 0,
        })
    }

    /// Returns `true` if the coalescer holds one or more states.
    #[must_use]
    pub fn has_held(&self) -> bool {
        !self.due.is_empty()
    }

    /// Returns the number of states that the coalescer dropped, because a newer state of
    /// the same incident replaced them.
    #[must_use]
    pub fn coalesced(&self) -> u64 {
        self.coalesced
    }

    /// Removes the held state of an entry, and counts it as dropped.
    fn drop_held(&mut self, id: IncidentId) {
        if let Some(entry) = self.entries.get_mut(&id)
            && entry.held.take().is_some()
        {
            self.due
                .remove(&(time_after(entry.window_start, self.window), id));
            self.coalesced = self.coalesced.saturating_add(1);
        }
    }

    /// Makes room for one more incident. Returns the held state of an incident that the
    /// coalescer forgets, so that the state is not lost.
    fn make_room(&mut self, now: DateTime<Utc>) -> Option<Incident> {
        if self.entries.len() < MAX_COALESCED_INCIDENTS {
            return None;
        }
        // Windows that are over and hold nothing have no more use.
        let window = self.window;
        self.entries.retain(|_, entry| {
            entry.held.is_some() || now < time_after(entry.window_start, window)
        });
        if self.entries.len() < MAX_COALESCED_INCIDENTS {
            return None;
        }
        let oldest = self
            .entries
            .iter()
            .map(|(id, entry)| (entry.window_start, *id))
            .min()?;
        let entry = self.entries.remove(&oldest.1)?;
        self.due
            .remove(&(time_after(entry.window_start, self.window), oldest.1));
        entry.held
    }

    /// Gives one new state of an incident to the coalescer. `now` is the time of the
    /// event that caused the state.
    ///
    /// Returns the states that leave now, oldest first. The list is empty if the
    /// coalescer holds the state.
    pub fn offer(&mut self, incident: Incident, now: DateTime<Utc>) -> Vec<Incident> {
        let id = incident.id;
        if incident.status != IncidentStatus::Open {
            // The incident gets no more states. A held state is older than this state.
            self.drop_held(id);
            self.entries.remove(&id);
            return vec![incident];
        }
        let window_is_over = self
            .entries
            .get(&id)
            .is_none_or(|entry| now >= time_after(entry.window_start, self.window));
        if window_is_over {
            self.drop_held(id);
            let mut leaving = Vec::with_capacity(2);
            if !self.entries.contains_key(&id) {
                leaving.extend(self.make_room(now));
            }
            self.entries.insert(
                id,
                CoalescerEntry {
                    window_start: now,
                    released: 1,
                    severity: incident.severity,
                    held: None,
                },
            );
            leaving.push(incident);
            return leaving;
        }
        let Some(entry) = self.entries.get(&id) else {
            return vec![incident];
        };
        if entry.released < self.max_updates || incident.severity > entry.severity {
            self.drop_held(id);
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.released = entry.released.saturating_add(1);
                entry.severity = incident.severity;
            }
            return vec![incident];
        }
        // The state is over the limit. It replaces the state that the coalescer holds.
        self.drop_held(id);
        if let Some(entry) = self.entries.get_mut(&id) {
            self.due
                .insert((time_after(entry.window_start, self.window), id));
            entry.held = Some(incident);
        }
        Vec::new()
    }

    /// Returns the held states whose window ended at or before `now`, in order of the end
    /// of their windows. Each of them starts a new window for its incident.
    pub fn release_due(&mut self, now: DateTime<Utc>) -> Vec<Incident> {
        let mut leaving = Vec::new();
        while let Some((end, id)) = self.due.first().copied() {
            if end > now {
                break;
            }
            self.due.remove(&(end, id));
            if let Some(entry) = self.entries.get_mut(&id)
                && let Some(incident) = entry.held.take()
            {
                entry.window_start = now;
                entry.released = 1;
                entry.severity = incident.severity;
                leaving.push(incident);
            }
        }
        leaving
    }

    /// Returns all held states, in order of the end of their windows.
    ///
    /// The windows stay as they are: a later state of the same incident in the same
    /// window is held again. Call this function when the stream of events stops.
    pub fn flush(&mut self) -> Vec<Incident> {
        let due = std::mem::take(&mut self.due);
        let mut leaving = Vec::with_capacity(due.len());
        for (_, id) in due {
            if let Some(entry) = self.entries.get_mut(&id)
                && let Some(incident) = entry.held.take()
            {
                entry.severity = incident.severity;
                leaving.push(incident);
            }
        }
        leaving
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::{DetectionTier, Verdict};
    use uuid::Uuid;

    use super::*;
    use crate::common::detection_id;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_793_696_400 + seconds, 0).unwrap()
    }

    fn detection(rule_id: &str, sequence: u32, seconds: i64) -> Detection {
        let event_ids = vec![EventId(Uuid::from_u128(u128::from(sequence)))];
        Detection {
            id: detection_id(rule_id, &event_ids),
            rule_id: rule_id.to_owned(),
            title: "Detection".to_owned(),
            description: "A detection.".to_owned(),
            severity: Severity::Low,
            verdict: Verdict::Suspicious,
            tier: DetectionTier::Deterministic,
            time: at(seconds),
            attack: Vec::new(),
            event_ids,
            entities: vec![
                EntityRef::new(EntityKind::User, "user-1"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.9"),
            ],
            tenant: Some("tenant-1".to_owned()),
            attributes: BTreeMap::new(),
        }
    }

    fn key(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    const WINDOW: TimeDelta = TimeDelta::seconds(60);

    #[test]
    fn the_first_match_of_a_window_gives_its_detection_and_the_others_are_counted() {
        let mut suppressor = Suppressor::new();
        let first = detection("rule-a", 1, 0);
        assert_eq!(
            suppressor.admit(&first, &key(&["k"]), WINDOW, None),
            Admission::Emit {
                previous_matches: 0
            }
        );
        // One match has no summary: the summaries list only the keys with more matches.
        assert_eq!(suppressor.summaries(), []);
        for sequence in 2..=10 {
            let again = detection("rule-a", sequence, i64::from(sequence));
            assert_eq!(
                suppressor.admit(&again, &key(&["k"]), WINDOW, None),
                Admission::Suppress
            );
        }
        assert_eq!(
            suppressor.summaries(),
            [SuppressionSummary {
                rule_id: "rule-a".to_owned(),
                key: "k".to_owned(),
                tenant: Some("tenant-1".to_owned()),
                window_start: at(0),
                last_seen: at(10),
                matches: 10,
                detection_id: first.id,
            }]
        );
    }

    #[test]
    fn a_different_rule_a_different_key_and_a_different_tenant_have_their_own_windows() {
        let mut suppressor = Suppressor::new();
        let emit = Admission::Emit {
            previous_matches: 0,
        };
        assert_eq!(
            suppressor.admit(&detection("rule-a", 1, 0), &key(&["k"]), WINDOW, None),
            emit
        );
        assert_eq!(
            suppressor.admit(&detection("rule-b", 2, 1), &key(&["k"]), WINDOW, None),
            emit
        );
        assert_eq!(
            suppressor.admit(&detection("rule-a", 3, 2), &key(&["other"]), WINDOW, None),
            emit
        );
        let mut other_tenant = detection("rule-a", 4, 3);
        other_tenant.tenant = Some("tenant-2".to_owned());
        assert_eq!(
            suppressor.admit(&other_tenant, &key(&["k"]), WINDOW, None),
            emit
        );
        // The parts of a key do not run together: ["a", "bc"] is not ["ab", "c"].
        assert_eq!(
            suppressor.admit(&detection("rule-c", 5, 4), &key(&["a", "bc"]), WINDOW, None),
            emit
        );
        assert_eq!(
            suppressor.admit(&detection("rule-c", 6, 5), &key(&["ab", "c"]), WINDOW, None),
            emit
        );
        assert_eq!(
            suppressor.admit(&detection("rule-a", 7, 6), &key(&["k"]), WINDOW, None),
            Admission::Suppress
        );
    }

    #[test]
    fn a_match_after_the_window_starts_a_new_window_and_reports_the_count_before() {
        let mut suppressor = Suppressor::new();
        for (sequence, seconds) in [(1, 0), (2, 10), (3, 59)] {
            let _ = suppressor.admit(
                &detection("rule-a", sequence, seconds),
                &key(&["k"]),
                WINDOW,
                None,
            );
        }
        let next = detection("rule-a", 4, 60);
        assert_eq!(
            suppressor.admit(&next, &key(&["k"]), WINDOW, None),
            Admission::Emit {
                previous_matches: 3
            }
        );
        // The new window has one match. A window with one match reports no count.
        let later = detection("rule-a", 5, 120);
        assert_eq!(
            suppressor.admit(&later, &key(&["k"]), WINDOW, None),
            Admission::Emit {
                previous_matches: 0
            }
        );
        // An event that arrives late is in the current window.
        let late = detection("rule-a", 6, 5);
        assert_eq!(
            suppressor.admit(&late, &key(&["k"]), WINDOW, None),
            Admission::Suppress
        );
        let summaries = suppressor.summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].window_start, at(120));
        assert_eq!(summaries[0].last_seen, at(120));
        assert_eq!(summaries[0].matches, 2);
        assert_eq!(summaries[0].detection_id, later.id);
    }

    #[test]
    fn the_repeat_count_gives_one_more_admission_in_each_window() {
        let mut suppressor = Suppressor::new();
        let first = detection("rule-a", 1, 0);
        let mut admissions = Vec::new();
        for sequence in 1..=6_u32 {
            admissions.push(suppressor.admit(
                &detection("rule-a", sequence, i64::from(sequence) - 1),
                &key(&["k"]),
                WINDOW,
                Some(3),
            ));
        }
        assert_eq!(
            admissions,
            [
                Admission::Emit {
                    previous_matches: 0
                },
                Admission::Suppress,
                Admission::Repeat {
                    matches: 3,
                    first_event: Some(first.event_ids[0]),
                    first_detection: first.id,
                },
                Admission::Suppress,
                Admission::Suppress,
                Admission::Suppress,
            ]
        );
        // The next window can give the repeat admission again.
        let mut next = Vec::new();
        for sequence in 10..13_u32 {
            next.push(suppressor.admit(
                &detection("rule-a", sequence, 60 + i64::from(sequence)),
                &key(&["k"]),
                WINDOW,
                Some(3),
            ));
        }
        assert!(matches!(
            next[0],
            Admission::Emit {
                previous_matches: 6
            }
        ));
        assert!(matches!(next[2], Admission::Repeat { matches: 3, .. }));
    }

    #[test]
    fn the_key_text_of_a_summary_is_cleaned_and_limited() {
        let mut suppressor = Suppressor::new();
        let long = format!("line\n{}", "x".repeat(500));
        let parts = key(&[&long, "second"]);
        let _ = suppressor.admit(&detection("rule-a", 1, 0), &parts, WINDOW, None);
        let _ = suppressor.admit(&detection("rule-a", 2, 1), &parts, WINDOW, None);
        let summaries = suppressor.summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].key.chars().count(), 200);
        assert!(!summaries[0].key.contains('\n'));
    }

    #[test]
    fn the_entity_key_is_the_entities_in_order_with_no_duplicates() {
        let mut found = detection("rule-a", 1, 0);
        found
            .entities
            .push(EntityRef::new(EntityKind::User, "user-1").with_name("A name"));
        assert_eq!(
            entity_key(&found),
            ["ip_address:203.0.113.9", "user:user-1"]
        );
    }

    #[test]
    fn the_summaries_are_in_order_of_rule_and_time() {
        let mut suppressor = Suppressor::new();
        for (rule, key_text, start) in [("rule-b", "k", 0), ("rule-a", "z", 5), ("rule-a", "a", 9)]
        {
            for offset in 0..2 {
                let found = detection(rule, 1, start + offset);
                let _ = suppressor.admit(&found, &key(&[key_text]), WINDOW, None);
            }
        }
        let order: Vec<(String, String)> = suppressor
            .summaries()
            .into_iter()
            .map(|summary| (summary.rule_id, summary.key))
            .collect();
        assert_eq!(
            order,
            [
                ("rule-a".to_owned(), "z".to_owned()),
                ("rule-a".to_owned(), "a".to_owned()),
                ("rule-b".to_owned(), "k".to_owned()),
            ]
        );
    }

    #[test]
    fn the_quota_limits_the_requests_of_one_source_and_of_one_tenant() {
        let mut quota = TriageQuota::new(WINDOW, 3, 5);
        assert_eq!(quota.limit(QuotaScope::Source), 3);
        assert_eq!(quota.limit(QuotaScope::Tenant), 5);
        for _ in 0..3 {
            assert_eq!(quota.take("decoy", Some("tenant-1"), at(0)), Ok(()));
        }
        assert_eq!(
            quota.take("decoy", Some("tenant-1"), at(1)),
            Err(QuotaScope::Source)
        );
        // A different source has its own quota, until the tenant has no request left.
        assert_eq!(quota.take("entra", Some("tenant-1"), at(2)), Ok(()));
        assert_eq!(quota.take("entra", Some("tenant-1"), at(3)), Ok(()));
        assert_eq!(
            quota.take("entra", Some("tenant-1"), at(4)),
            Err(QuotaScope::Tenant)
        );
        // A denied request takes nothing: the source `entra` used two of its three.
        assert_eq!(quota.take("entra", Some("tenant-2"), at(5)), Ok(()));
        assert_eq!(
            quota.take("entra", Some("tenant-2"), at(6)),
            Err(QuotaScope::Source)
        );
        // Events with no tenant share one quota.
        assert_eq!(quota.take("other", None, at(7)), Ok(()));
        assert_eq!(QuotaScope::Source.name(), "source");
        assert_eq!(QuotaScope::Tenant.name(), "tenant");
    }

    #[test]
    fn a_quota_window_starts_again_after_its_length_in_event_time() {
        let mut quota = TriageQuota::new(WINDOW, 2, 100);
        assert_eq!(quota.take("decoy", Some("t"), at(0)), Ok(()));
        assert_eq!(quota.take("decoy", Some("t"), at(30)), Ok(()));
        assert_eq!(
            quota.take("decoy", Some("t"), at(59)),
            Err(QuotaScope::Source)
        );
        // An event that arrives late does not start a new window.
        assert_eq!(
            quota.take("decoy", Some("t"), at(-500)),
            Err(QuotaScope::Source)
        );
        assert_eq!(quota.take("decoy", Some("t"), at(60)), Ok(()));
        assert_eq!(quota.take("decoy", Some("t"), at(61)), Ok(()));
        assert_eq!(
            quota.take("decoy", Some("t"), at(62)),
            Err(QuotaScope::Source)
        );
    }

    fn incident(id: u128, severity: Severity, detections: usize) -> Incident {
        Incident {
            id: IncidentId(Uuid::from_u128(id)),
            title: format!("{detections} detections"),
            summary: String::new(),
            severity,
            status: IncidentStatus::Open,
            created_at: at(0),
            updated_at: at(0),
            tenant: None,
            detections: Vec::new(),
            entities: Vec::new(),
            attack: Vec::new(),
            timeline: Vec::new(),
        }
    }

    fn titles(incidents: &[Incident]) -> Vec<&str> {
        incidents
            .iter()
            .map(|incident| incident.title.as_str())
            .collect()
    }

    #[test]
    fn the_coalescer_lets_the_limit_through_and_holds_the_newest_state() {
        let mut coalescer = IncidentCoalescer::new(3, 60).unwrap();
        let mut left = Vec::new();
        for count in 1..=10 {
            left.extend(coalescer.offer(incident(1, Severity::Low, count), at(count as i64)));
        }
        assert_eq!(
            titles(&left),
            ["1 detections", "2 detections", "3 detections"]
        );
        assert!(coalescer.has_held());
        // The states 4 to 9 are dropped. The state 10 is held.
        assert_eq!(coalescer.coalesced(), 6);

        // An event before the end of the window releases nothing.
        assert_eq!(coalescer.release_due(at(60)), []);
        // The window started at second 1 and ends at second 61.
        let released = coalescer.release_due(at(61));
        assert_eq!(titles(&released), ["10 detections"]);
        assert!(!coalescer.has_held());
        assert_eq!(coalescer.coalesced(), 6);

        // The released state is the first state of a new window.
        let mut next = Vec::new();
        for count in 11..=15 {
            next.extend(coalescer.offer(incident(1, Severity::Low, count), at(62)));
        }
        assert_eq!(titles(&next), ["11 detections", "12 detections"]);
    }

    #[test]
    fn a_state_after_the_window_leaves_and_replaces_the_held_state() {
        let mut coalescer = IncidentCoalescer::new(1, 60).unwrap();
        assert_eq!(
            coalescer.offer(incident(1, Severity::Low, 1), at(0)).len(),
            1
        );
        assert_eq!(
            coalescer.offer(incident(1, Severity::Low, 2), at(1)).len(),
            0
        );
        let left = coalescer.offer(incident(1, Severity::Low, 3), at(60));
        assert_eq!(titles(&left), ["3 detections"]);
        assert!(!coalescer.has_held());
        assert_eq!(coalescer.coalesced(), 1);
        assert_eq!(coalescer.release_due(at(1_000)), []);
    }

    #[test]
    fn a_higher_severity_and_a_status_that_is_not_open_are_not_held() {
        let mut coalescer = IncidentCoalescer::new(1, 60).unwrap();
        assert_eq!(
            coalescer.offer(incident(1, Severity::Low, 1), at(0)).len(),
            1
        );
        assert_eq!(
            coalescer.offer(incident(1, Severity::Low, 2), at(1)).len(),
            0
        );
        // The severity goes up. The state leaves, and the held state is dropped.
        let raised = coalescer.offer(incident(1, Severity::Critical, 3), at(2));
        assert_eq!(titles(&raised), ["3 detections"]);
        assert!(!coalescer.has_held());
        // The same severity again is held.
        assert_eq!(
            coalescer
                .offer(incident(1, Severity::Critical, 4), at(3))
                .len(),
            0
        );
        // A lower severity is not a reason to leave.
        assert_eq!(
            coalescer.offer(incident(1, Severity::High, 5), at(4)).len(),
            0
        );

        // A merge replaced the incident. Its last state leaves, and nothing stays held.
        let mut resolved = incident(1, Severity::Critical, 6);
        resolved.status = IncidentStatus::Resolved;
        let last = coalescer.offer(resolved, at(5));
        assert_eq!(titles(&last), ["6 detections"]);
        assert!(!coalescer.has_held());
        assert_eq!(coalescer.flush(), []);
        assert_eq!(coalescer.coalesced(), 3);
    }

    #[test]
    fn each_incident_has_its_own_window_and_flush_returns_all_held_states() {
        let mut coalescer = IncidentCoalescer::new(1, 60).unwrap();
        for id in 1..=3_u128 {
            let start = i64::try_from(id).unwrap();
            assert_eq!(
                coalescer
                    .offer(incident(id, Severity::Low, 1), at(start))
                    .len(),
                1
            );
            assert_eq!(
                coalescer
                    .offer(incident(id, Severity::Low, 2), at(start))
                    .len(),
                0
            );
        }
        // The windows end at seconds 61, 62, and 63.
        let first = coalescer.release_due(at(61));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, IncidentId(Uuid::from_u128(1)));
        let rest = coalescer.flush();
        let ids: Vec<IncidentId> = rest.iter().map(|incident| incident.id).collect();
        assert_eq!(
            ids,
            [
                IncidentId(Uuid::from_u128(2)),
                IncidentId(Uuid::from_u128(3))
            ]
        );
        assert!(!coalescer.has_held());
        // After a flush the window is the same, so a new state is held again.
        assert_eq!(
            coalescer.offer(incident(2, Severity::Low, 3), at(10)).len(),
            0
        );
        assert_eq!(titles(&coalescer.flush()), ["3 detections"]);
    }

    #[test]
    fn the_coalescer_keeps_a_limited_number_of_incidents_and_loses_no_held_state() {
        let mut coalescer = IncidentCoalescer::new(1, 60).unwrap();
        // The first incident has a held state.
        assert_eq!(
            coalescer.offer(incident(0, Severity::Low, 1), at(0)).len(),
            1
        );
        assert_eq!(
            coalescer.offer(incident(0, Severity::Low, 2), at(0)).len(),
            0
        );
        let mut left = 0_usize;
        let mut saw_held = false;
        let total = u128::try_from(MAX_COALESCED_INCIDENTS).unwrap() + 10;
        for id in 1..=total {
            // All in one window, so that no window is over.
            let leaving = coalescer.offer(incident(id, Severity::Low, 1), at(1));
            saw_held |= leaving
                .iter()
                .any(|incident| incident.title == "2 detections");
            left += leaving.len();
            assert!(coalescer.entries.len() <= MAX_COALESCED_INCIDENTS);
        }
        // Each new incident left, and the held state of the oldest incident left with one.
        assert_eq!(left, usize::try_from(total).unwrap() + 1);
        assert!(saw_held);
        assert!(!coalescer.has_held());
    }

    #[test]
    fn windows_that_are_over_make_room_before_an_incident_is_forgotten() {
        let mut coalescer = IncidentCoalescer::new(1, 60).unwrap();
        let limit = u128::try_from(MAX_COALESCED_INCIDENTS).unwrap();
        for id in 0..limit {
            let _ = coalescer.offer(incident(id, Severity::Low, 1), at(0));
        }
        assert_eq!(coalescer.entries.len(), MAX_COALESCED_INCIDENTS);
        // At second 60 all windows are over. One new incident removes them all.
        let leaving = coalescer.offer(incident(limit, Severity::Low, 1), at(60));
        assert_eq!(leaving.len(), 1);
        assert_eq!(coalescer.entries.len(), 1);
    }

    #[test]
    fn coalescer_settings_that_are_not_valid_are_errors() {
        let error = IncidentCoalescer::new(0, 60).err().unwrap();
        assert_eq!(
            error.to_string(),
            "detector configuration: max_incident_updates must be 1 or more, but it is 0"
        );
        for window in [0, u64::MAX] {
            let error = IncidentCoalescer::new(5, window).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!(
                    "detector configuration: incident_update_window_seconds must be 1 or more \
                     and must fit a time difference, but it is {window}"
                )
            );
        }
    }

    #[test]
    fn the_meter_counts_each_limit() {
        let meter = FloodMeter::default();
        assert_eq!(meter.read(), FloodCounters::default());
        meter.suppressed();
        meter.suppressed();
        meter.repeated();
        meter.quota_denied();
        meter.coalesced(7);
        assert_eq!(
            meter.read(),
            FloodCounters {
                suppressed_matches: 2,
                repeat_detections: 1,
                triage_quota_denials: 1,
                coalesced_incident_updates: 7,
            }
        );
    }
}
