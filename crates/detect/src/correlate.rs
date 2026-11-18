//! The correlator: it folds detections into incidents.
//!
//! Two detections are in one incident when they are in the same tenant, they share an
//! entity, and their times are in one window. A chain of shared entities also links:
//! if A shares an entity with B, and B shares a different entity with C, then A, B, and C
//! are in one incident.
//!
//! All times are event times. The identifier of an incident comes from its first
//! detection. A replay of one log thus gives the same incidents.
//!
//! # Status
//!
//! The correlator makes each incident with the status `open`. It does not know about a
//! status change that an agent or an operator makes later. When an incident is complete,
//! call [`Correlator::forget`], so that later detections start a new incident.

use std::collections::{HashMap, HashSet};

use aegis_contracts::common::{
    DetectionId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::{Detection, Incident, IncidentStatus, TimelineEntry, Verdict};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{incident_id, kind_name, time_after, time_before};
use crate::error::DetectError;

/// The author of the timeline entries that the correlator writes.
pub const CORRELATOR_AUTHOR: &str = "correlator";

/// The largest number of event references in one timeline entry.
const MAX_EVENT_EVIDENCE: usize = 10;

/// The largest number of entities that a summary names.
const MAX_SUMMARY_ENTITIES: usize = 10;

/// The settings of the [`Correlator`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CorrelatorConfig {
    /// The largest time in seconds between a detection and an incident that it can join.
    /// The time of the detection must be at most this far from the first or the last
    /// detection of the incident.
    pub window_seconds: u64,
    /// The number of different ATT&CK techniques that makes an incident `critical`.
    pub critical_technique_count: usize,
    /// The largest number of incidents that the correlator keeps. When the limit is
    /// reached, the correlator drops the incident with the oldest last detection.
    pub max_incidents: usize,
    /// The largest number of detections that one incident holds. A later detection still
    /// raises the severity and adds its techniques, but the incident does not store it,
    /// and its entities do not link more detections.
    ///
    /// Each change of an incident sends the full incident to the bus. This limit thus
    /// also limits the size of that message.
    pub max_detections_per_incident: usize,
    /// The entity kinds that do not link detections. Many principals share one tenant or
    /// one role, so these kinds would join incidents that are not related.
    pub unlinked_kinds: Vec<EntityKind>,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            window_seconds: 3_600,
            critical_technique_count: 3,
            max_incidents: 10_000,
            max_detections_per_incident: 200,
            unlinked_kinds: vec![EntityKind::Tenant, EntityKind::Role],
        }
    }
}

/// The key that links detections: the tenant of the detection and one entity.
type LinkKey = (Option<String>, EntityKind, String);

struct Tracked {
    incident: Incident,
    /// The time of the first detection.
    first: DateTime<Utc>,
    /// The time of the last detection.
    last: DateTime<Utc>,
    /// The detections that the incident stores.
    stored: HashSet<DetectionId>,
    /// The number of detections of the incident, including those that it does not store.
    total: usize,
    keys: Vec<LinkKey>,
}

/// Folds detections into incidents.
///
/// The correlator keeps the incidents in memory. Send each incident that
/// [`Correlator::add`] returns to the incident store and to the bus.
pub struct Correlator {
    config: CorrelatorConfig,
    window: TimeDelta,
    incidents: HashMap<IncidentId, Tracked>,
    index: HashMap<LinkKey, Vec<IncidentId>>,
}

impl Correlator {
    /// Makes an empty correlator.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the window does not fit a time difference, or if
    /// `critical_technique_count`, `max_incidents`, or `max_detections_per_incident` is zero.
    pub fn new(config: CorrelatorConfig) -> Result<Self, DetectError> {
        for (name, value) in [
            ("critical_technique_count", config.critical_technique_count),
            ("max_incidents", config.max_incidents),
            (
                "max_detections_per_incident",
                config.max_detections_per_incident,
            ),
        ] {
            if value == 0 {
                return Err(DetectError::Config(format!(
                    "correlator.{name} must be 1 or more, but it is 0"
                )));
            }
        }
        let window = i64::try_from(config.window_seconds)
            .ok()
            .and_then(TimeDelta::try_seconds)
            .ok_or_else(|| {
                DetectError::Config(format!(
                    "correlator.window_seconds is too large: {}",
                    config.window_seconds
                ))
            })?;
        Ok(Self {
            config,
            window,
            incidents: HashMap::new(),
            index: HashMap::new(),
        })
    }

    /// Returns the number of incidents that the correlator keeps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.incidents.len()
    }

    /// Returns `true` if the correlator keeps no incident.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.incidents.is_empty()
    }

    /// Returns one incident, if the correlator keeps it.
    #[must_use]
    pub fn incident(&self, id: IncidentId) -> Option<&Incident> {
        self.incidents.get(&id).map(|tracked| &tracked.incident)
    }

    /// Returns all incidents that the correlator keeps, oldest first.
    #[must_use]
    pub fn incidents(&self) -> Vec<Incident> {
        let mut incidents: Vec<Incident> = self
            .incidents
            .values()
            .map(|tracked| tracked.incident.clone())
            .collect();
        incidents.sort_by_key(|incident| (incident.created_at, incident.id));
        incidents
    }

    /// Removes an incident from the correlator. Returns `false` if it is not there.
    ///
    /// Use this when an incident is resolved or is a false positive. A later detection for
    /// the same entities then starts a new incident.
    pub fn forget(&mut self, id: IncidentId) -> bool {
        let Some(tracked) = self.incidents.remove(&id) else {
            return false;
        };
        self.unlink(id, &tracked.keys);
        true
    }

    fn unlink(&mut self, id: IncidentId, keys: &[LinkKey]) {
        for key in keys {
            if let Some(ids) = self.index.get_mut(key) {
                ids.retain(|found| *found != id);
                if ids.is_empty() {
                    self.index.remove(key);
                }
            }
        }
    }

    fn link_keys(&self, detection: &Detection) -> Vec<LinkKey> {
        let mut keys: Vec<LinkKey> = Vec::with_capacity(detection.entities.len());
        for entity in &detection.entities {
            if self.config.unlinked_kinds.contains(&entity.kind) || entity.id.is_empty() {
                continue;
            }
            let key = (detection.tenant.clone(), entity.kind, entity.id.clone());
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    /// Adds one detection. Returns the incidents that are new or that changed.
    ///
    /// - A `benign` detection changes nothing.
    /// - A detection that an incident already stores changes nothing.
    /// - A detection that links to no incident starts a new incident.
    /// - A detection that links to one incident joins it.
    /// - A detection that links to two or more incidents merges them into the oldest one.
    ///   Each other incident gets the status `resolved` and a timeline entry that names the
    ///   incident that replaces it. The correlator then drops it.
    ///
    /// The result holds the replaced incidents first and the live incident last.
    pub fn add(&mut self, detection: &Detection) -> Vec<Incident> {
        if detection.verdict == Verdict::Benign {
            return Vec::new();
        }
        let keys = self.link_keys(detection);

        let mut linked: Vec<IncidentId> = Vec::new();
        for key in &keys {
            for id in self.index.get(key).into_iter().flatten() {
                let in_window = self.incidents.get(id).is_some_and(|tracked| {
                    detection.time >= time_before(tracked.first, self.window)
                        && detection.time <= time_after(tracked.last, self.window)
                });
                if in_window && !linked.contains(id) {
                    linked.push(*id);
                }
            }
        }
        // A detection with no entity links to no incident. If it comes a second time, the
        // incident that it started has the identifier that comes from the detection.
        let started = incident_id(detection.id);
        let is_known = linked.iter().chain(std::iter::once(&started)).any(|id| {
            self.incidents
                .get(id)
                .is_some_and(|tracked| tracked.stored.contains(&detection.id))
        });
        if is_known {
            return Vec::new();
        }
        linked.sort_by_key(|id| {
            let created = self
                .incidents
                .get(id)
                .map(|tracked| tracked.incident.created_at);
            (created, *id)
        });

        let mut changed: Vec<Incident> = Vec::new();
        let mut linked = linked.into_iter();
        let primary = match linked.next() {
            Some(primary) => primary,
            None => self.open(detection),
        };
        for other in linked {
            if let Some(replaced) = self.merge(primary, other, detection.time) {
                changed.push(replaced);
            }
        }
        self.absorb(primary, detection, &keys);
        if let Some(tracked) = self.incidents.get_mut(&primary) {
            describe(tracked, &self.config);
            changed.push(tracked.incident.clone());
        }
        changed
    }

    /// Makes an empty incident for a detection that links to no incident.
    fn open(&mut self, detection: &Detection) -> IncidentId {
        if self.incidents.len() >= self.config.max_incidents {
            let oldest = self
                .incidents
                .iter()
                .map(|(id, tracked)| (tracked.last, *id))
                .min();
            if let Some((_, id)) = oldest {
                self.forget(id);
            }
        }
        let id = incident_id(detection.id);
        let incident = Incident {
            id,
            title: String::new(),
            summary: String::new(),
            severity: detection.severity,
            status: IncidentStatus::Open,
            created_at: detection.time,
            updated_at: detection.time,
            tenant: detection.tenant.clone(),
            detections: Vec::new(),
            entities: Vec::new(),
            attack: Vec::new(),
            timeline: Vec::new(),
        };
        self.incidents.insert(
            id,
            Tracked {
                incident,
                first: detection.time,
                last: detection.time,
                stored: HashSet::new(),
                total: 0,
                keys: Vec::new(),
            },
        );
        id
    }

    /// Adds a detection to an incident.
    fn absorb(&mut self, id: IncidentId, detection: &Detection, keys: &[LinkKey]) {
        let Some(tracked) = self.incidents.get_mut(&id) else {
            return;
        };
        if tracked.stored.contains(&detection.id) {
            return;
        }
        tracked.total += 1;
        tracked.first = tracked.first.min(detection.time);
        tracked.last = tracked.last.max(detection.time);
        let incident = &mut tracked.incident;
        incident.updated_at = incident.updated_at.max(detection.time);
        incident.severity = incident.severity.max(detection.severity);
        for technique in &detection.attack {
            if !incident.attack.contains(technique) {
                incident.attack.push(technique.clone());
            }
        }
        if incident.detections.len() >= self.config.max_detections_per_incident {
            return;
        }
        tracked.stored.insert(detection.id);

        let position = incident
            .detections
            .partition_point(|known| (known.time, known.id) <= (detection.time, detection.id));
        incident.detections.insert(position, detection.clone());
        for entity in &detection.entities {
            merge_entity(&mut incident.entities, entity);
        }
        let mut evidence = vec![EvidenceRef::new(EvidenceKind::Detection, detection.id)];
        evidence.extend(
            detection
                .event_ids
                .iter()
                .take(MAX_EVENT_EVIDENCE)
                .map(|event_id| EvidenceRef::new(EvidenceKind::Event, event_id)),
        );
        insert_entry(
            &mut incident.timeline,
            TimelineEntry {
                time: detection.time,
                author: CORRELATOR_AUTHOR.to_owned(),
                description: timeline_text(detection),
                evidence,
            },
        );
        for key in keys {
            if !tracked.keys.contains(key) {
                tracked.keys.push(key.clone());
                self.index.entry(key.clone()).or_default().push(id);
            }
        }
    }

    /// Moves the detections of `other` into `primary`. Returns the last state of `other`.
    ///
    /// `time` is the time of the detection that links the two incidents. The timeline
    /// entries for the merge get the newest time that the three items have, so that they
    /// come after the detections that the incidents had before the merge.
    fn merge(
        &mut self,
        primary: IncidentId,
        other: IncidentId,
        time: DateTime<Utc>,
    ) -> Option<Incident> {
        let replaced = self.incidents.remove(&other)?;
        self.unlink(other, &replaced.keys);
        let primary_last = self
            .incidents
            .get(&primary)
            .map_or(time, |tracked| tracked.last);
        let time = time.max(primary_last).max(replaced.last);
        for detection in &replaced.incident.detections {
            let keys = self.link_keys(detection);
            self.absorb(primary, detection, &keys);
        }
        if let Some(tracked) = self.incidents.get_mut(&primary) {
            // Detections that `other` counted but did not store.
            tracked.total += replaced
                .total
                .saturating_sub(replaced.incident.detections.len());
            tracked.first = tracked.first.min(replaced.first);
            tracked.last = tracked.last.max(replaced.last);
            let incident = &mut tracked.incident;
            incident.severity = incident.severity.max(replaced.incident.severity);
            for technique in &replaced.incident.attack {
                if !incident.attack.contains(technique) {
                    incident.attack.push(technique.clone());
                }
            }
            insert_entry(
                &mut incident.timeline,
                TimelineEntry {
                    time,
                    author: CORRELATOR_AUTHOR.to_owned(),
                    description: format!(
                        "The correlator merged incident {other} into this incident."
                    ),
                    evidence: vec![EvidenceRef::new(EvidenceKind::Incident, other)],
                },
            );
        }

        let mut incident = replaced.incident;
        incident.status = IncidentStatus::Resolved;
        incident.updated_at = incident.updated_at.max(time);
        incident.summary = format!("Merged into incident {primary}. {}", incident.summary);
        insert_entry(
            &mut incident.timeline,
            TimelineEntry {
                time,
                author: CORRELATOR_AUTHOR.to_owned(),
                description: format!(
                    "The correlator merged this incident into incident {primary}."
                ),
                evidence: vec![EvidenceRef::new(EvidenceKind::Incident, primary)],
            },
        );
        Some(incident)
    }
}

/// Adds an entity, or adds the name and the tenant to an entity that the list has.
fn merge_entity(entities: &mut Vec<EntityRef>, entity: &EntityRef) {
    match entities
        .iter_mut()
        .find(|known| known.kind == entity.kind && known.id == entity.id)
    {
        Some(known) => {
            if known.name.is_none() {
                known.name.clone_from(&entity.name);
            }
            if known.tenant.is_none() {
                known.tenant.clone_from(&entity.tenant);
            }
        }
        None => entities.push(entity.clone()),
    }
}

/// Inserts an entry so that the timeline stays in time order. Entries with one time keep
/// the order in which they came.
fn insert_entry(timeline: &mut Vec<TimelineEntry>, entry: TimelineEntry) {
    let position = timeline.partition_point(|known| known.time <= entry.time);
    timeline.insert(position, entry);
}

fn timeline_text(detection: &Detection) -> String {
    let techniques: Vec<&str> = detection
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    if techniques.is_empty() {
        detection.title.clone()
    } else {
        format!("{} ({})", detection.title, techniques.join(", "))
    }
}

/// Sets the severity, the title, and the summary from the content of the incident.
fn describe(tracked: &mut Tracked, config: &CorrelatorConfig) {
    let total = tracked.total;
    let (first, last) = (tracked.first, tracked.last);
    let incident = &mut tracked.incident;

    let mut technique_ids: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    technique_ids.sort_unstable();
    technique_ids.dedup();
    let techniques = technique_ids.len();
    if techniques >= config.critical_technique_count {
        incident.severity = Severity::Critical;
    }

    let first_title = incident
        .detections
        .first()
        .map_or("Detection", |detection| detection.title.as_str());
    incident.title = if total <= 1 {
        first_title.to_owned()
    } else if techniques >= 2 {
        format!("Multi-stage attack: {techniques} ATT&CK techniques in {total} detections")
    } else {
        format!(
            "{first_title} and {} related detections",
            total.saturating_sub(1)
        )
    };

    let stored = incident.detections.len();
    let mut summary = format!(
        "{total} {} from {} to {}",
        if total == 1 {
            "detection"
        } else {
            "detections"
        },
        first.to_rfc3339(),
        last.to_rfc3339(),
    );
    if let Some(tenant) = &incident.tenant {
        summary.push_str(&format!(" in the tenant {tenant}"));
    }
    summary.push('.');
    if stored < total {
        summary.push_str(&format!(
            " The incident stores the first {stored} detections that came."
        ));
    }
    if !incident.attack.is_empty() {
        let names: Vec<String> = incident
            .attack
            .iter()
            .map(|technique| format!("{} {}", technique.technique_id, technique.name))
            .collect();
        summary.push_str(&format!(" ATT&CK techniques: {}.", names.join("; ")));
    }
    if !incident.entities.is_empty() {
        let names: Vec<String> = incident
            .entities
            .iter()
            .take(MAX_SUMMARY_ENTITIES)
            .map(|entity| format!("{} {}", kind_name(entity.kind), entity.id))
            .collect();
        let more = incident.entities.len().saturating_sub(names.len());
        summary.push_str(&format!(" Entities: {}", names.join("; ")));
        if more > 0 {
            summary.push_str(&format!("; and {more} more"));
        }
        summary.push('.');
    }
    incident.summary = summary;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegis_contracts::common::EventId;
    use aegis_contracts::{AttackTechnique, DetectionTier};
    use uuid::Uuid;

    use super::*;
    use crate::attack::technique;
    use crate::common::detection_id;

    const TENANT: &str = "tenant-1";
    const SPRAY_IP: (EntityKind, &str) = (EntityKind::IpAddress, "203.0.113.50");
    const VICTIM: (EntityKind, &str) = (EntityKind::User, "user-dana");
    const ROGUE: (EntityKind, &str) = (EntityKind::ServicePrincipal, "sp-sync-helper");

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_793_696_400 + seconds, 0).unwrap()
    }

    /// Makes a `high`, `malicious` detection at `seconds` after the start of the test log.
    fn detection(
        sequence: u32,
        seconds: i64,
        technique_id: Option<&str>,
        entities: &[(EntityKind, &str)],
    ) -> Detection {
        let event_ids = vec![EventId(Uuid::from_u128(u128::from(sequence)))];
        let rule_id = format!("rule-{sequence}");
        Detection {
            id: detection_id(&rule_id, &event_ids),
            title: format!("Detection {sequence}"),
            description: format!("The description of detection {sequence}."),
            rule_id,
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time: at(seconds),
            attack: technique_id
                .map(|id| technique(id).unwrap())
                .into_iter()
                .collect(),
            event_ids,
            entities: entities
                .iter()
                .map(|(kind, id)| EntityRef::new(*kind, *id))
                .collect(),
            tenant: Some(TENANT.to_owned()),
            attributes: BTreeMap::new(),
        }
    }

    fn correlator() -> Correlator {
        Correlator::new(CorrelatorConfig::default()).unwrap()
    }

    fn titles(incident: &Incident) -> Vec<&str> {
        incident
            .detections
            .iter()
            .map(|detection| detection.title.as_str())
            .collect()
    }

    /// Adds a detection that must change exactly one incident, and returns that incident.
    fn add_one(correlator: &mut Correlator, detection: &Detection) -> Incident {
        let mut changed = correlator.add(detection);
        assert_eq!(changed.len(), 1, "{changed:#?}");
        changed.remove(0)
    }

    #[test]
    fn a_detection_with_no_link_starts_an_incident_with_its_data() {
        let mut correlator = correlator();
        let first = detection(1, 0, Some("T1110.003"), &[SPRAY_IP]);
        let incident = add_one(&mut correlator, &first);
        assert_eq!(incident.id, incident_id(first.id));
        assert_eq!(incident.title, "Detection 1");
        assert_eq!(incident.severity, Severity::High);
        assert_eq!(incident.status, IncidentStatus::Open);
        assert_eq!(incident.created_at, at(0));
        assert_eq!(incident.updated_at, at(0));
        assert_eq!(incident.tenant.as_deref(), Some(TENANT));
        assert_eq!(incident.detections, std::slice::from_ref(&first));
        assert_eq!(
            incident.entities,
            [EntityRef::new(EntityKind::IpAddress, "203.0.113.50")]
        );
        assert_eq!(
            incident.attack,
            [AttackTechnique::new(
                "credential-access",
                "T1110.003",
                "Password Spraying"
            )]
        );
        assert_eq!(
            incident.timeline,
            [TimelineEntry {
                time: at(0),
                author: "correlator".to_owned(),
                description: "Detection 1 (T1110.003)".to_owned(),
                evidence: vec![
                    EvidenceRef::new(EvidenceKind::Detection, first.id),
                    EvidenceRef::new(EvidenceKind::Event, first.event_ids[0]),
                ],
            }]
        );
        assert_eq!(
            incident.summary,
            "1 detection from 2026-11-03T09:00:00+00:00 to 2026-11-03T09:00:00+00:00 in the \
             tenant tenant-1. ATT&CK techniques: T1110.003 Password Spraying. Entities: \
             ip_address 203.0.113.50."
        );
        assert_eq!(correlator.len(), 1);
        assert_eq!(correlator.incident(incident.id), Some(&incident));
    }

    #[test]
    fn detections_that_share_an_entity_are_in_one_incident() {
        let mut correlator = correlator();
        let first = add_one(
            &mut correlator,
            &detection(1, 0, Some("T1110.003"), &[SPRAY_IP]),
        );
        let second = add_one(
            &mut correlator,
            &detection(2, 31, Some("T1078"), &[VICTIM, SPRAY_IP]),
        );
        assert_eq!(second.id, first.id);
        assert_eq!(titles(&second), ["Detection 1", "Detection 2"]);
        assert_eq!(second.created_at, at(0));
        assert_eq!(second.updated_at, at(31));
        assert_eq!(
            second.entities,
            [
                EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
                EntityRef::new(EntityKind::User, "user-dana"),
            ]
        );
        assert_eq!(
            second.title,
            "Multi-stage attack: 2 ATT&CK techniques in 2 detections"
        );
        assert_eq!(correlator.len(), 1);
    }

    #[test]
    fn detections_with_no_shared_entity_are_in_two_incidents() {
        let mut correlator = correlator();
        let first = add_one(&mut correlator, &detection(1, 0, None, &[SPRAY_IP]));
        let second = add_one(&mut correlator, &detection(2, 1, None, &[VICTIM]));
        assert_ne!(first.id, second.id);
        // The same identifier with a different kind is a different entity.
        let third = add_one(
            &mut correlator,
            &detection(3, 2, None, &[(EntityKind::Application, "user-dana")]),
        );
        assert_ne!(third.id, second.id);
        assert_eq!(correlator.len(), 3);
        let ids: Vec<IncidentId> = correlator
            .incidents()
            .iter()
            .map(|incident| incident.id)
            .collect();
        assert_eq!(ids, [first.id, second.id, third.id]);
    }

    #[test]
    fn a_chain_of_entities_links_detections_that_share_no_entity() {
        let mut correlator = correlator();
        let first = add_one(&mut correlator, &detection(1, 0, None, &[SPRAY_IP]));
        add_one(
            &mut correlator,
            &detection(2, 10, None, &[SPRAY_IP, VICTIM]),
        );
        // This detection shares no entity with the first detection.
        let third = add_one(&mut correlator, &detection(3, 20, None, &[VICTIM, ROGUE]));
        let fourth = add_one(&mut correlator, &detection(4, 30, None, &[ROGUE]));
        assert_eq!(third.id, first.id);
        assert_eq!(fourth.id, first.id);
        assert_eq!(
            titles(&fourth),
            ["Detection 1", "Detection 2", "Detection 3", "Detection 4"]
        );
        assert_eq!(fourth.title, "Detection 1 and 3 related detections");
        assert_eq!(correlator.len(), 1);
    }

    #[test]
    fn a_detection_that_links_two_incidents_merges_them_into_the_oldest() {
        let mut correlator = correlator();
        let older = add_one(
            &mut correlator,
            &detection(1, 0, Some("T1110.003"), &[SPRAY_IP]),
        );
        let newer = add_one(
            &mut correlator,
            &detection(2, 40, Some("T1098.003"), &[ROGUE]),
        );
        assert_ne!(older.id, newer.id);

        let bridge = detection(3, 20, Some("T1528"), &[SPRAY_IP, ROGUE]);
        let changed = correlator.add(&bridge);
        assert_eq!(changed.len(), 2);
        let (replaced, live) = (&changed[0], &changed[1]);

        assert_eq!(replaced.id, newer.id);
        assert_eq!(replaced.status, IncidentStatus::Resolved);
        assert_eq!(replaced.updated_at, at(40));
        assert!(
            replaced
                .summary
                .starts_with(&format!("Merged into incident {}. ", older.id)),
            "{}",
            replaced.summary
        );
        assert_eq!(
            replaced.timeline.last().unwrap().description,
            format!(
                "The correlator merged this incident into incident {}.",
                older.id
            )
        );
        assert_eq!(
            replaced.timeline.last().unwrap().evidence,
            [EvidenceRef::new(EvidenceKind::Incident, older.id)]
        );

        assert_eq!(live.id, older.id);
        assert_eq!(live.status, IncidentStatus::Open);
        assert_eq!(titles(live), ["Detection 1", "Detection 3", "Detection 2"]);
        assert_eq!(live.created_at, at(0));
        assert_eq!(live.updated_at, at(40));
        assert_eq!(live.severity, Severity::Critical);
        let technique_ids: Vec<&str> = live
            .attack
            .iter()
            .map(|technique| technique.technique_id.as_str())
            .collect();
        assert_eq!(technique_ids, ["T1110.003", "T1098.003", "T1528"]);
        let descriptions: Vec<&str> = live
            .timeline
            .iter()
            .map(|entry| entry.description.as_str())
            .collect();
        assert_eq!(
            descriptions,
            [
                "Detection 1 (T1110.003)",
                "Detection 3 (T1528)",
                "Detection 2 (T1098.003)",
                &format!(
                    "The correlator merged incident {} into this incident.",
                    newer.id
                ),
            ]
        );

        assert_eq!(correlator.len(), 1);
        assert_eq!(correlator.incident(newer.id), None);
        // Each link now leads to the live incident only.
        assert_eq!(correlator.index.len(), 2);
        assert!(correlator.index.values().all(|ids| *ids == [older.id]));
        // A later detection for an entity of the replaced incident joins the live incident.
        let later = add_one(&mut correlator, &detection(4, 50, None, &[ROGUE]));
        assert_eq!(later.id, older.id);
        assert_eq!(later.detections.len(), 4);
    }

    #[test]
    fn detections_in_two_tenants_are_in_two_incidents() {
        let mut correlator = correlator();
        let first = add_one(&mut correlator, &detection(1, 0, None, &[SPRAY_IP]));
        let mut other_tenant = detection(2, 1, None, &[SPRAY_IP]);
        other_tenant.tenant = Some("tenant-2".to_owned());
        let second = add_one(&mut correlator, &other_tenant);
        assert_ne!(first.id, second.id);
        assert_eq!(second.tenant.as_deref(), Some("tenant-2"));
        let mut no_tenant = detection(3, 2, None, &[SPRAY_IP]);
        no_tenant.tenant = None;
        let third = add_one(&mut correlator, &no_tenant);
        assert_ne!(third.id, first.id);
        assert_ne!(third.id, second.id);
        assert_eq!(correlator.len(), 3);
    }

    #[test]
    fn the_window_includes_its_ends_and_excludes_later_and_earlier_detections() {
        let config = CorrelatorConfig {
            window_seconds: 600,
            ..CorrelatorConfig::default()
        };
        let mut correlator = Correlator::new(config).unwrap();
        let first = add_one(&mut correlator, &detection(1, 1_000, None, &[SPRAY_IP]));
        // Exactly one window after the last detection.
        let joined = add_one(&mut correlator, &detection(2, 1_600, None, &[SPRAY_IP]));
        assert_eq!(joined.id, first.id);
        // The window now ends at 2 200. One second later is a new incident.
        let after = add_one(&mut correlator, &detection(3, 2_201, None, &[SPRAY_IP]));
        assert_ne!(after.id, first.id);
        // Exactly one window before the first detection.
        let early = add_one(&mut correlator, &detection(4, 400, None, &[SPRAY_IP]));
        assert_eq!(early.id, first.id);
        assert_eq!(
            titles(&early),
            ["Detection 4", "Detection 1", "Detection 2"]
        );
        // The first detection is now at 400. One second before its window is a new incident.
        let before = add_one(&mut correlator, &detection(5, -201, None, &[SPRAY_IP]));
        assert_ne!(before.id, first.id);
        assert_ne!(before.id, after.id);
        assert_eq!(correlator.len(), 3);
    }

    #[test]
    fn the_severity_is_the_largest_detection_severity() {
        let mut correlator = correlator();
        let mut low = detection(1, 0, None, &[VICTIM]);
        low.severity = Severity::Low;
        assert_eq!(add_one(&mut correlator, &low).severity, Severity::Low);
        let mut medium = detection(2, 1, None, &[VICTIM]);
        medium.severity = Severity::Medium;
        assert_eq!(add_one(&mut correlator, &medium).severity, Severity::Medium);
        let mut informational = detection(3, 2, None, &[VICTIM]);
        informational.severity = Severity::Informational;
        assert_eq!(
            add_one(&mut correlator, &informational).severity,
            Severity::Medium
        );
    }

    #[test]
    fn several_different_techniques_make_the_incident_critical() {
        let mut correlator = correlator();
        let mut low = |sequence: u32, technique_id: &str| {
            let mut detection =
                detection(sequence, i64::from(sequence), Some(technique_id), &[VICTIM]);
            detection.severity = Severity::Low;
            add_one(&mut correlator, &detection)
        };
        assert_eq!(low(1, "T1110.003").severity, Severity::Low);
        assert_eq!(low(2, "T1528").severity, Severity::Low);
        // The same technique again is not a third technique.
        assert_eq!(low(3, "T1528").severity, Severity::Low);
        let third = low(4, "T1098.001");
        assert_eq!(third.severity, Severity::Critical);
        assert_eq!(third.attack.len(), 3);
        assert_eq!(
            third.title,
            "Multi-stage attack: 3 ATT&CK techniques in 4 detections"
        );
    }

    #[test]
    fn the_number_of_techniques_for_critical_is_a_setting() {
        let config = CorrelatorConfig {
            critical_technique_count: 2,
            ..CorrelatorConfig::default()
        };
        let mut correlator = Correlator::new(config).unwrap();
        let first = add_one(
            &mut correlator,
            &detection(1, 0, Some("T1110.003"), &[VICTIM]),
        );
        assert_eq!(first.severity, Severity::High);
        let second = add_one(&mut correlator, &detection(2, 1, Some("T1528"), &[VICTIM]));
        assert_eq!(second.severity, Severity::Critical);
    }

    #[test]
    fn one_technique_with_two_tactics_is_one_technique_for_the_severity() {
        let mut correlator = correlator();
        let mut first = detection(1, 0, None, &[VICTIM]);
        first.attack = vec![AttackTechnique::new(
            "initial-access",
            "T1078",
            "Valid Accounts",
        )];
        let mut second = detection(2, 1, None, &[VICTIM]);
        second.attack = vec![AttackTechnique::new(
            "persistence",
            "T1078",
            "Valid Accounts",
        )];
        let mut third = detection(3, 2, None, &[VICTIM]);
        third.attack = vec![AttackTechnique::new(
            "defense-evasion",
            "T1078",
            "Valid Accounts",
        )];
        add_one(&mut correlator, &first);
        add_one(&mut correlator, &second);
        let incident = add_one(&mut correlator, &third);
        assert_eq!(incident.attack.len(), 3);
        assert_eq!(incident.severity, Severity::High);
    }

    #[test]
    fn entities_and_techniques_have_no_duplicates_and_keep_names() {
        let mut correlator = correlator();
        let mut first = detection(1, 0, Some("T1528"), &[VICTIM, SPRAY_IP]);
        first.entities[0].name = None;
        let mut second = detection(2, 1, Some("T1528"), &[SPRAY_IP, VICTIM]);
        second.entities[1].name = Some("dana@contoso.example".to_owned());
        second.entities[1].tenant = Some(TENANT.to_owned());
        add_one(&mut correlator, &first);
        let incident = add_one(&mut correlator, &second);
        assert_eq!(
            incident.entities,
            [
                EntityRef::new(EntityKind::User, "user-dana")
                    .with_name("dana@contoso.example")
                    .with_tenant(TENANT),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            ]
        );
        assert_eq!(incident.attack, [technique("T1528").unwrap()]);
    }

    #[test]
    fn detections_and_the_timeline_are_in_time_order_for_any_arrival_order() {
        let mut correlator = correlator();
        for (sequence, seconds) in [(1, 30), (2, 10), (3, 20), (4, 10)] {
            add_one(
                &mut correlator,
                &detection(sequence, seconds, None, &[VICTIM]),
            );
        }
        let incidents = correlator.incidents();
        assert_eq!(incidents.len(), 1);
        let incident = &incidents[0];
        let times: Vec<DateTime<Utc>> = incident
            .detections
            .iter()
            .map(|detection| detection.time)
            .collect();
        assert_eq!(times, [at(10), at(10), at(20), at(30)]);
        let entries: Vec<(DateTime<Utc>, &str)> = incident
            .timeline
            .iter()
            .map(|entry| (entry.time, entry.description.as_str()))
            .collect();
        assert_eq!(
            entries,
            [
                (at(10), "Detection 2"),
                (at(10), "Detection 4"),
                (at(20), "Detection 3"),
                (at(30), "Detection 1"),
            ]
        );
        // The incident starts with the detection that came first.
        assert_eq!(incident.created_at, at(30));
        assert_eq!(incident.updated_at, at(30));
        assert!(
            incident.summary.starts_with(
                "4 detections from 2026-11-03T09:00:10+00:00 to 2026-11-03T09:00:30+00:00"
            ),
            "{}",
            incident.summary
        );
    }

    #[test]
    fn a_benign_detection_changes_nothing() {
        let mut correlator = correlator();
        let mut benign = detection(1, 0, None, &[VICTIM]);
        benign.verdict = Verdict::Benign;
        assert_eq!(correlator.add(&benign), []);
        assert!(correlator.is_empty());

        add_one(&mut correlator, &detection(2, 1, None, &[VICTIM]));
        assert_eq!(correlator.add(&benign), []);
        assert_eq!(correlator.incidents()[0].detections.len(), 1);
    }

    #[test]
    fn a_suspicious_detection_joins_an_incident() {
        let mut correlator = correlator();
        let mut suspicious = detection(1, 0, None, &[VICTIM]);
        suspicious.verdict = Verdict::Suspicious;
        suspicious.severity = Severity::Medium;
        let incident = add_one(&mut correlator, &suspicious);
        assert_eq!(incident.severity, Severity::Medium);
        assert_eq!(incident.detections, [suspicious]);
    }

    #[test]
    fn a_detection_that_comes_two_times_changes_nothing_the_second_time() {
        let mut correlator = correlator();
        let first = detection(1, 0, None, &[VICTIM]);
        let second = detection(2, 1, None, &[VICTIM]);
        add_one(&mut correlator, &first);
        add_one(&mut correlator, &second);
        assert_eq!(correlator.add(&first), []);
        assert_eq!(correlator.add(&second), []);
        assert_eq!(correlator.incidents()[0].detections.len(), 2);
        assert_eq!(correlator.incidents()[0].timeline.len(), 2);
    }

    #[test]
    fn a_detection_with_no_entity_is_its_own_incident_and_is_added_one_time() {
        let mut correlator = correlator();
        let first = detection(1, 0, None, &[]);
        let second = detection(2, 1, None, &[]);
        let one = add_one(&mut correlator, &first);
        let two = add_one(&mut correlator, &second);
        assert_ne!(one.id, two.id);
        assert_eq!(correlator.add(&first), []);
        assert_eq!(correlator.len(), 2);
        assert_eq!(correlator.incident(one.id), Some(&one));
    }

    #[test]
    fn tenant_and_role_entities_do_not_link_by_default() {
        let mut correlator = correlator();
        let role = (EntityKind::Role, "global-administrator");
        let tenant = (EntityKind::Tenant, TENANT);
        let first = add_one(
            &mut correlator,
            &detection(1, 0, None, &[VICTIM, role, tenant]),
        );
        let second = add_one(
            &mut correlator,
            &detection(2, 1, None, &[ROGUE, role, tenant]),
        );
        assert_ne!(first.id, second.id);
        // The incident still names the entities.
        assert_eq!(first.entities.len(), 3);

        let config = CorrelatorConfig {
            unlinked_kinds: Vec::new(),
            ..CorrelatorConfig::default()
        };
        let mut linking = Correlator::new(config).unwrap();
        let first = add_one(&mut linking, &detection(1, 0, None, &[VICTIM, role]));
        let second = add_one(&mut linking, &detection(2, 1, None, &[ROGUE, role]));
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn an_incident_stores_a_limited_number_of_detections_and_counts_the_others() {
        let config = CorrelatorConfig {
            max_detections_per_incident: 2,
            ..CorrelatorConfig::default()
        };
        let mut correlator = Correlator::new(config).unwrap();
        let mut low = detection(1, 0, Some("T1110.003"), &[VICTIM]);
        low.severity = Severity::Low;
        add_one(&mut correlator, &low);
        let mut second = detection(2, 1, Some("T1528"), &[VICTIM]);
        second.severity = Severity::Low;
        add_one(&mut correlator, &second);

        // The third detection is not stored, but it changes the severity and the techniques.
        let third = detection(3, 2, Some("T1098.001"), &[VICTIM, ROGUE]);
        let incident = add_one(&mut correlator, &third);
        assert_eq!(titles(&incident), ["Detection 1", "Detection 2"]);
        assert_eq!(incident.timeline.len(), 2);
        assert_eq!(incident.entities.len(), 1);
        assert_eq!(incident.attack.len(), 3);
        assert_eq!(incident.severity, Severity::Critical);
        assert_eq!(incident.updated_at, at(2));
        assert_eq!(
            incident.title,
            "Multi-stage attack: 3 ATT&CK techniques in 3 detections"
        );
        assert!(
            incident
                .summary
                .contains(" The incident stores the first 2 detections that came."),
            "{}",
            incident.summary
        );
        // An entity of a detection that is not stored does not link.
        let other = add_one(&mut correlator, &detection(4, 3, None, &[ROGUE]));
        assert_ne!(other.id, incident.id);
    }

    #[test]
    fn a_full_correlator_drops_the_incident_with_the_oldest_last_detection() {
        let config = CorrelatorConfig {
            max_incidents: 2,
            ..CorrelatorConfig::default()
        };
        let mut correlator = Correlator::new(config).unwrap();
        let first = add_one(&mut correlator, &detection(1, 0, None, &[SPRAY_IP]));
        let second = add_one(&mut correlator, &detection(2, 10, None, &[VICTIM]));
        // The first incident gets a newer detection, so the second incident is the oldest.
        add_one(&mut correlator, &detection(3, 20, None, &[SPRAY_IP]));
        let third = add_one(&mut correlator, &detection(4, 30, None, &[ROGUE]));
        assert_eq!(correlator.len(), 2);
        assert!(correlator.incident(first.id).is_some());
        assert_eq!(correlator.incident(second.id), None);
        assert!(correlator.incident(third.id).is_some());
        // The link data of the dropped incident is gone.
        assert_eq!(correlator.index.len(), 2);
        // The entity of the dropped incident no longer links.
        let again = add_one(&mut correlator, &detection(5, 40, None, &[VICTIM]));
        assert_eq!(again.detections.len(), 1);
    }

    #[test]
    fn a_forgotten_incident_gets_no_more_detections() {
        let mut correlator = correlator();
        let first = add_one(&mut correlator, &detection(1, 0, None, &[VICTIM, SPRAY_IP]));
        assert_eq!(correlator.index.len(), 2);
        assert!(correlator.forget(first.id));
        assert!(!correlator.forget(first.id));
        assert!(correlator.is_empty());
        // The correlator keeps no link data for an incident that it does not have.
        assert!(correlator.index.is_empty());
        let second = add_one(&mut correlator, &detection(2, 1, None, &[VICTIM]));
        assert_ne!(second.id, first.id);
        assert_eq!(titles(&second), ["Detection 2"]);
    }

    #[test]
    fn the_same_detections_give_the_same_incidents_in_each_run() {
        let run = || {
            let mut correlator = correlator();
            let mut changed = Vec::new();
            for detection in [
                detection(1, 0, Some("T1110.003"), &[SPRAY_IP]),
                detection(2, 40, Some("T1098.003"), &[ROGUE]),
                detection(3, 5, None, &[(EntityKind::User, "user-other")]),
                detection(4, 20, Some("T1528"), &[SPRAY_IP, VICTIM, ROGUE]),
                detection(5, 60, Some("T1078.004"), &[ROGUE]),
            ] {
                changed.extend(correlator.add(&detection));
            }
            (changed, correlator.incidents())
        };
        let (first_changed, first_incidents) = run();
        let (second_changed, second_incidents) = run();
        assert_eq!(first_incidents.len(), 2);
        assert_eq!(first_changed.len(), 6);
        assert_eq!(first_changed, second_changed);
        assert_eq!(first_incidents, second_incidents);
    }

    #[test]
    fn a_timeline_entry_names_a_limited_number_of_events() {
        let mut correlator = correlator();
        let mut burst = detection(1, 0, None, &[SPRAY_IP]);
        burst.event_ids = (0..25_u128)
            .map(|index| EventId(Uuid::from_u128(index)))
            .collect();
        let incident = add_one(&mut correlator, &burst);
        let evidence = &incident.timeline[0].evidence;
        assert_eq!(evidence.len(), 11);
        assert_eq!(evidence[0].kind, EvidenceKind::Detection);
        assert!(
            evidence[1..]
                .iter()
                .all(|item| item.kind == EvidenceKind::Event)
        );
        // The detection keeps all events.
        assert_eq!(incident.detections[0].event_ids.len(), 25);
    }

    #[test]
    fn times_at_the_ends_of_the_range_do_not_panic() {
        // The window is longer than the full range of the time type.
        let config = CorrelatorConfig {
            window_seconds: 9_000_000_000_000_000,
            ..CorrelatorConfig::default()
        };
        let mut correlator = Correlator::new(config).unwrap();
        let mut last = detection(1, 0, None, &[VICTIM]);
        last.time = DateTime::<Utc>::MAX_UTC;
        let mut first = detection(2, 0, None, &[VICTIM]);
        first.time = DateTime::<Utc>::MIN_UTC;
        let one = add_one(&mut correlator, &last);
        let two = add_one(&mut correlator, &first);
        assert_eq!(one.id, two.id);
        assert_eq!(two.detections.len(), 2);
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        let cases = [
            (
                CorrelatorConfig {
                    critical_technique_count: 0,
                    ..CorrelatorConfig::default()
                },
                "correlator.critical_technique_count must be 1 or more, but it is 0",
            ),
            (
                CorrelatorConfig {
                    max_incidents: 0,
                    ..CorrelatorConfig::default()
                },
                "correlator.max_incidents must be 1 or more, but it is 0",
            ),
            (
                CorrelatorConfig {
                    max_detections_per_incident: 0,
                    ..CorrelatorConfig::default()
                },
                "correlator.max_detections_per_incident must be 1 or more, but it is 0",
            ),
            (
                CorrelatorConfig {
                    window_seconds: u64::MAX,
                    ..CorrelatorConfig::default()
                },
                "correlator.window_seconds is too large: 18446744073709551615",
            ),
        ];
        for (config, expected) in cases {
            let error = Correlator::new(config).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
    }

    #[test]
    fn the_settings_read_from_a_partial_map_and_reject_unknown_keys() {
        let config: CorrelatorConfig =
            serde_json::from_value(serde_json::json!({ "window_seconds": 120 })).unwrap();
        assert_eq!(config.window_seconds, 120);
        assert_eq!(config.critical_technique_count, 3);
        assert_eq!(
            config.unlinked_kinds,
            [EntityKind::Tenant, EntityKind::Role]
        );
        let error = serde_json::from_value::<CorrelatorConfig>(serde_json::json!({ "window": 1 }))
            .unwrap_err();
        assert!(
            error.to_string().contains("unknown field `window`"),
            "{error}"
        );
    }
}
