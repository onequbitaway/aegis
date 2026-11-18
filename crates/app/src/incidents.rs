//! The incident store that all components of one process share.
//!
//! Two components write incidents. The detection engine sends a full state of an incident
//! each time a detection joins it. The agents change the state, the summary, and the
//! timeline. [`SharedIncidents`] puts the two writers on one store with these rules:
//!
//! - The engine output never moves an incident back to an earlier state, and never removes
//!   the work of an agent. Refer to [`SharedIncidents::merge_engine`].
//! - A save of an agent never removes a detection, an entity, a technique, or a timeline
//!   entry that the store has. Refer to the [`IncidentStore`] implementation.
//! - Writes run one at a time.
//! - When an incident closes, the store tells the detection engine. A later detection
//!   then starts a new incident.

use std::collections::HashMap;
use std::sync::Arc;

use aegis_contracts::Result;
use aegis_contracts::common::{EntityRef, IncidentId};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use async_trait::async_trait;

use crate::activity::Activity;

/// The largest number of engine summaries that the store remembers.
const MAX_REMEMBERED_SUMMARIES: usize = 20_000;

type ClosedHook = Box<dyn Fn(IncidentId) + Send + Sync>;
type WrittenHook = Box<dyn Fn(&Incident) + Send + Sync>;

/// Returns `true` if no more work is necessary on an incident in this state.
#[must_use]
pub fn is_closed(status: IncidentStatus) -> bool {
    matches!(
        status,
        IncidentStatus::Resolved | IncidentStatus::FalsePositive
    )
}

/// The result of [`SharedIncidents::merge_engine`].
#[derive(Debug, Clone, PartialEq)]
pub struct EngineMerge {
    /// The state of the incident in the store after the merge.
    pub incident: Incident,
    /// `true` if the store did not have the incident before.
    pub is_new: bool,
    /// The number of detections that the store did not have before.
    pub new_detections: usize,
    /// `true` if the merge changed the store.
    pub changed: bool,
    /// The state that the store had before the merge.
    pub previous_status: Option<IncidentStatus>,
}

fn same_entity(left: &EntityRef, right: &EntityRef) -> bool {
    left.kind == right.kind && left.id == right.id
}

/// Adds to `target` the data of `stored` that `target` does not have.
///
/// The detections stay in the order of time and identifier, and the timeline stays in time
/// order. The severity and the time of the last change do not go down.
fn add_missing(target: &mut Incident, stored: &Incident) {
    let before = target.detections.len();
    for detection in &stored.detections {
        if !target
            .detections
            .iter()
            .any(|known| known.id == detection.id)
        {
            target.detections.push(detection.clone());
        }
    }
    if target.detections.len() != before {
        target
            .detections
            .sort_by_key(|detection| (detection.time, detection.id));
    }
    for entity in &stored.entities {
        if !target
            .entities
            .iter()
            .any(|known| same_entity(known, entity))
        {
            target.entities.push(entity.clone());
        }
    }
    for technique in &stored.attack {
        if !target.attack.contains(technique) {
            target.attack.push(technique.clone());
        }
    }
    let before = target.timeline.len();
    for entry in &stored.timeline {
        if !target.timeline.contains(entry) {
            target.timeline.push(entry.clone());
        }
    }
    if target.timeline.len() != before {
        // The sort is stable: entries with one time keep their order.
        target.timeline.sort_by_key(|entry| entry.time);
    }
    target.severity = target.severity.max(stored.severity);
    target.updated_at = target.updated_at.max(stored.updated_at);
}

/// Merges one state of the detection engine with the incident in the store.
///
/// `last_engine_summary` is the summary of the engine state that this process merged
/// before, if there is one.
pub(crate) fn merge_engine_output(
    stored: Option<&Incident>,
    engine: &Incident,
    last_engine_summary: Option<&str>,
) -> EngineMerge {
    let Some(stored) = stored else {
        return EngineMerge {
            incident: engine.clone(),
            is_new: true,
            new_detections: engine.detections.len(),
            changed: true,
            previous_status: None,
        };
    };
    let new_detections = engine
        .detections
        .iter()
        .filter(|detection| {
            !stored
                .detections
                .iter()
                .any(|known| known.id == detection.id)
        })
        .count();

    // The detections, the entities, the techniques, the severity, and the times come
    // from the engine. Data that only the store has stays.
    let mut merged = engine.clone();
    add_missing(&mut merged, stored);
    merged.created_at = merged.created_at.min(stored.created_at);
    if merged.tenant.is_none() {
        merged.tenant.clone_from(&stored.tenant);
    }
    if merged.title.is_empty() {
        merged.title.clone_from(&stored.title);
    }

    // The correlator makes each incident with the state `open`. The state in the store is
    // the result of the work of the agents, so it stays. One exception: the correlator
    // sets `resolved` when it merges this incident into a different one.
    merged.status = if engine.status == IncidentStatus::Resolved && !is_closed(stored.status) {
        IncidentStatus::Resolved
    } else {
        stored.status
    };

    // The summary of the store stays if an agent wrote it. If this process does not know
    // the last summary of the engine, it cannot tell, and it keeps the stored summary.
    let engine_wrote_stored_summary = match last_engine_summary {
        Some(last) => stored.summary == last,
        None => stored.summary == engine.summary,
    };
    if !engine_wrote_stored_summary && !stored.summary.is_empty() {
        merged.summary.clone_from(&stored.summary);
    }

    let changed = merged != *stored;
    EngineMerge {
        incident: merged,
        is_new: false,
        new_detections,
        changed,
        previous_status: Some(stored.status),
    }
}

/// Returns `incoming` with the data of `stored` that `incoming` does not have.
///
/// An agent reads an incident, works on it, and saves it. The detection engine can add a
/// detection between the read and the save. This function keeps that detection.
pub(crate) fn keep_stored_data(stored: &Incident, incoming: &Incident) -> Incident {
    let mut merged = incoming.clone();
    add_missing(&mut merged, stored);
    merged
}

#[derive(Default)]
struct EngineSummaries {
    by_incident: HashMap<IncidentId, String>,
}

impl EngineSummaries {
    fn remember(&mut self, incident: &Incident, engine_summary: &str) {
        if is_closed(incident.status) {
            self.by_incident.remove(&incident.id);
            return;
        }
        if self.by_incident.len() >= MAX_REMEMBERED_SUMMARIES
            && !self.by_incident.contains_key(&incident.id)
        {
            // The merge keeps a stored summary that it cannot explain, so an empty map
            // loses no work of an agent.
            self.by_incident.clear();
        }
        self.by_incident
            .insert(incident.id, engine_summary.to_owned());
    }
}

/// An incident store for many writers in one process.
///
/// Refer to the [module documentation](self) for the rules.
pub struct SharedIncidents {
    inner: Arc<dyn IncidentStore>,
    activity: Arc<Activity>,
    /// The gate for writes, and the last summary of the engine for each open incident.
    writes: tokio::sync::Mutex<EngineSummaries>,
    closed_hooks: Vec<ClosedHook>,
    written_hooks: Vec<WrittenHook>,
}

impl SharedIncidents {
    /// Makes the shared store around `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn IncidentStore>, activity: Arc<Activity>) -> Self {
        Self {
            inner,
            activity,
            writes: tokio::sync::Mutex::default(),
            closed_hooks: Vec::new(),
            written_hooks: Vec::new(),
        }
    }

    /// Adds a function that the store calls after each write, with the incident as the
    /// store has it.
    #[must_use]
    pub fn on_written(mut self, hook: impl Fn(&Incident) + Send + Sync + 'static) -> Self {
        self.written_hooks.push(Box::new(hook));
        self
    }

    /// Adds a function that the store calls after it writes an incident with the state
    /// `resolved` or `false_positive`.
    #[must_use]
    pub fn on_closed(mut self, hook: impl Fn(IncidentId) + Send + Sync + 'static) -> Self {
        self.closed_hooks.push(Box::new(hook));
        self
    }

    fn written(&self, incident: &Incident) {
        for hook in &self.written_hooks {
            hook(incident);
        }
        if is_closed(incident.status) {
            for hook in &self.closed_hooks {
                hook(incident.id);
            }
        }
        self.activity.bump();
    }

    /// Writes one state of an incident that the detection engine made.
    ///
    /// If the store has the incident, the result keeps:
    ///
    /// - The stored state. The engine makes each incident with the state `open`. If the
    ///   engine state is `resolved`, the correlator merged the incident into a different
    ///   one, and an incident that is not closed becomes `resolved`.
    /// - The stored summary, if an agent wrote it.
    /// - The timeline entries, the detections, the entities, and the techniques that the
    ///   engine state does not have.
    /// - The larger severity.
    ///
    /// The detections, the entities, the techniques, the title, and the times come from
    /// the engine state.
    ///
    /// # Errors
    ///
    /// Returns the error of the store. The store is then not changed.
    pub async fn merge_engine(&self, engine: &Incident) -> Result<EngineMerge> {
        let mut summaries = self.writes.lock().await;
        let stored = self.inner.get(engine.id).await?;
        let last = summaries.by_incident.get(&engine.id).map(String::as_str);
        let merge = merge_engine_output(stored.as_ref(), engine, last);
        if merge.changed {
            self.inner.save(&merge.incident).await?;
        }
        summaries.remember(&merge.incident, &engine.summary);
        drop(summaries);
        if merge.changed {
            self.written(&merge.incident);
        }
        Ok(merge)
    }
}

#[async_trait]
impl IncidentStore for SharedIncidents {
    /// Writes an incident. The state, the summary, and the title come from `incident`.
    ///
    /// The write keeps each detection, entity, technique, and timeline entry that the
    /// store has and that `incident` does not have. It also keeps the larger severity.
    async fn save(&self, incident: &Incident) -> Result<()> {
        let mut summaries = self.writes.lock().await;
        let merged = match self.inner.get(incident.id).await? {
            Some(stored) => keep_stored_data(&stored, incident),
            None => incident.clone(),
        };
        self.inner.save(&merged).await?;
        if is_closed(merged.status) {
            summaries.by_incident.remove(&merged.id);
        }
        drop(summaries);
        self.written(&merged);
        Ok(())
    }

    async fn get(&self, id: IncidentId) -> Result<Option<Incident>> {
        self.inner.get(id).await
    }

    async fn list(&self, status: Option<IncidentStatus>, limit: usize) -> Result<Vec<Incident>> {
        self.inner.list(status, limit).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use aegis_contracts::Error;
    use aegis_contracts::common::{DetectionId, EntityKind, EvidenceKind, EvidenceRef, Severity};
    use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
    use aegis_contracts::incident::TimelineEntry;
    use aegis_memory::MemoryIncidents;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_793_696_400 + seconds, 0).unwrap()
    }

    fn detection(number: u128, technique: &str, entity: &EntityRef) -> Detection {
        Detection {
            id: DetectionId(uuid_from(number)),
            rule_id: format!("rule-{number}"),
            title: format!("Detection {number}"),
            description: String::new(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time: at(i64::try_from(number).unwrap()),
            attack: vec![AttackTechnique::new("tactic", technique, technique)],
            event_ids: Vec::new(),
            entities: vec![entity.clone()],
            tenant: Some("tenant-contoso".to_owned()),
            attributes: BTreeMap::new(),
        }
    }

    fn uuid_from(number: u128) -> Uuid {
        Uuid::from_u128(number)
    }

    fn correlator_entry(detection: &Detection) -> TimelineEntry {
        TimelineEntry {
            time: detection.time,
            author: "correlator".to_owned(),
            description: detection.title.clone(),
            evidence: vec![EvidenceRef::new(EvidenceKind::Detection, detection.id)],
        }
    }

    fn agent_entry(seconds: i64, author: &str, description: &str) -> TimelineEntry {
        TimelineEntry {
            time: at(seconds),
            author: author.to_owned(),
            description: description.to_owned(),
            evidence: Vec::new(),
        }
    }

    fn ip() -> EntityRef {
        EntityRef::new(EntityKind::IpAddress, "203.0.113.50")
    }

    fn user() -> EntityRef {
        EntityRef::new(EntityKind::User, "user-dana")
    }

    /// Makes the state that the correlator gives for `detections`.
    fn engine_state(detections: &[Detection]) -> Incident {
        let mut entities: Vec<EntityRef> = Vec::new();
        let mut attack: Vec<AttackTechnique> = Vec::new();
        for detection in detections {
            for entity in &detection.entities {
                if !entities.contains(entity) {
                    entities.push(entity.clone());
                }
            }
            for technique in &detection.attack {
                if !attack.contains(technique) {
                    attack.push(technique.clone());
                }
            }
        }
        Incident {
            id: IncidentId(uuid_from(900)),
            title: format!("{} detections", detections.len()),
            summary: format!("{} detections from the engine.", detections.len()),
            severity: if detections.len() >= 3 {
                Severity::Critical
            } else {
                Severity::High
            },
            status: IncidentStatus::Open,
            created_at: detections.first().map_or(at(0), |first| first.time),
            updated_at: detections.last().map_or(at(0), |last| last.time),
            tenant: Some("tenant-contoso".to_owned()),
            detections: detections.to_vec(),
            entities,
            attack,
            timeline: detections.iter().map(correlator_entry).collect(),
        }
    }

    fn store() -> (Arc<MemoryIncidents>, SharedIncidents, Arc<Activity>) {
        let inner = Arc::new(MemoryIncidents::default());
        let activity = Arc::new(Activity::new());
        let shared = SharedIncidents::new(inner.clone(), activity.clone());
        (inner, shared, activity)
    }

    #[tokio::test]
    async fn the_first_engine_state_is_written_as_it_is() {
        let (inner, shared, activity) = store();
        let first = engine_state(&[detection(1, "T1110.003", &ip())]);

        let merge = shared.merge_engine(&first).await.unwrap();

        assert_eq!(
            merge,
            EngineMerge {
                incident: first.clone(),
                is_new: true,
                new_detections: 1,
                changed: true,
                previous_status: None,
            }
        );
        assert_eq!(inner.get(first.id).await.unwrap(), Some(first));
        assert_eq!(activity.count(), 1);
    }

    #[tokio::test]
    async fn a_later_engine_state_keeps_the_state_the_summary_and_the_timeline_of_the_agents() {
        let (inner, shared, _) = store();
        let one = detection(1, "T1110.003", &ip());
        let two = detection(2, "T1078", &user());
        let first = engine_state(std::slice::from_ref(&one));
        shared.merge_engine(&first).await.unwrap();

        // An agent takes the incident: a new state, a new summary, and two entries.
        let mut worked = first.clone();
        worked.status = IncidentStatus::Investigating;
        worked.summary = "The analyst confirmed a password spray.".to_owned();
        let triage = agent_entry(1, "analyst", "The analyst assessed a true positive.");
        let proposal = agent_entry(3, "responder", "Proposed block_ip on 203.0.113.50.");
        worked.timeline.push(triage.clone());
        worked.timeline.push(proposal.clone());
        worked.updated_at = at(600);
        shared.save(&worked).await.unwrap();

        // A later event adds a detection. The engine state is `open` again.
        let second = engine_state(&[one.clone(), two.clone()]);
        assert_eq!(second.status, IncidentStatus::Open);
        let merge = shared.merge_engine(&second).await.unwrap();

        assert!(!merge.is_new);
        assert!(merge.changed);
        assert_eq!(merge.new_detections, 1);
        assert_eq!(merge.previous_status, Some(IncidentStatus::Investigating));
        let merged = &merge.incident;
        assert_eq!(merged.status, IncidentStatus::Investigating);
        assert_eq!(merged.summary, "The analyst confirmed a password spray.");
        // The detections, the entities, the techniques, and the title come from the engine.
        assert_eq!(merged.detections, [one.clone(), two.clone()]);
        assert_eq!(merged.entities, [ip(), user()]);
        assert_eq!(merged.attack, second.attack);
        assert_eq!(merged.title, "2 detections");
        assert_eq!(merged.created_at, first.created_at);
        // The time of the agent work is later than the time of the last detection.
        assert_eq!(merged.updated_at, at(600));
        // The timeline has the entries of the engine and of the agents, in time order.
        assert_eq!(
            merged.timeline,
            [
                correlator_entry(&one),
                triage,
                correlator_entry(&two),
                proposal
            ]
        );
        assert_eq!(inner.get(first.id).await.unwrap().as_ref(), Some(merged));
    }

    #[tokio::test]
    async fn the_engine_summary_replaces_only_a_summary_that_the_engine_wrote() {
        let (_, shared, _) = store();
        let one = detection(1, "T1110.003", &ip());
        let two = detection(2, "T1078", &user());
        let three = detection(3, "T1528", &user());
        let first = engine_state(std::slice::from_ref(&one));
        shared.merge_engine(&first).await.unwrap();

        // No agent changed the summary: the next engine summary replaces it.
        let second = engine_state(&[one.clone(), two.clone()]);
        let merge = shared.merge_engine(&second).await.unwrap();
        assert_eq!(merge.incident.summary, "2 detections from the engine.");

        // An agent writes a summary: the next engine summary does not replace it.
        let mut worked = merge.incident.clone();
        worked.summary = "The analyst wrote this.".to_owned();
        shared.save(&worked).await.unwrap();
        let third = engine_state(&[one, two, three]);
        let merge = shared.merge_engine(&third).await.unwrap();
        assert_eq!(merge.incident.summary, "The analyst wrote this.");
        assert_eq!(merge.incident.severity, Severity::Critical);
    }

    #[test]
    fn a_process_that_does_not_know_the_last_engine_summary_keeps_the_stored_summary() {
        let one = detection(1, "T1110.003", &ip());
        let two = detection(2, "T1078", &user());
        let mut stored = engine_state(std::slice::from_ref(&one));
        stored.summary = "A summary from before the restart.".to_owned();
        let engine = engine_state(&[one, two]);

        let unknown = merge_engine_output(Some(&stored), &engine, None);
        assert_eq!(
            unknown.incident.summary,
            "A summary from before the restart."
        );

        let known = merge_engine_output(
            Some(&stored),
            &engine,
            Some("A summary from before the restart."),
        );
        assert_eq!(known.incident.summary, "2 detections from the engine.");
    }

    #[test]
    fn an_engine_state_with_fewer_detections_removes_nothing() {
        // After a restart, the correlator starts the same incident again with one
        // detection. The store has more.
        let one = detection(1, "T1110.003", &ip());
        let two = detection(2, "T1078", &user());
        let three = detection(3, "T1528", &user());
        let mut stored = engine_state(&[one.clone(), two.clone()]);
        stored.status = IncidentStatus::Contained;
        stored.severity = Severity::Critical;
        let engine = engine_state(std::slice::from_ref(&three));

        let merge = merge_engine_output(Some(&stored), &engine, None);

        assert_eq!(merge.new_detections, 1);
        assert_eq!(
            merge.incident.detections,
            [one.clone(), two.clone(), three.clone()]
        );
        assert_eq!(merge.incident.entities, [user(), ip()]);
        assert_eq!(merge.incident.attack.len(), 3);
        assert_eq!(merge.incident.severity, Severity::Critical);
        assert_eq!(merge.incident.status, IncidentStatus::Contained);
        assert_eq!(merge.incident.created_at, one.time);
        assert_eq!(merge.incident.updated_at, three.time);
        assert_eq!(
            merge.incident.timeline,
            [
                correlator_entry(&one),
                correlator_entry(&two),
                correlator_entry(&three)
            ]
        );
    }

    #[tokio::test]
    async fn the_same_engine_state_a_second_time_changes_nothing() {
        let (_, shared, activity) = store();
        let state = engine_state(&[detection(1, "T1110.003", &ip())]);
        shared.merge_engine(&state).await.unwrap();
        let count = activity.count();

        let again = shared.merge_engine(&state).await.unwrap();

        assert!(!again.changed);
        assert!(!again.is_new);
        assert_eq!(again.new_detections, 0);
        assert_eq!(again.incident, state);
        assert_eq!(activity.count(), count);
    }

    #[tokio::test]
    async fn an_incident_that_the_correlator_merged_away_becomes_resolved() {
        let closed: Arc<Mutex<Vec<IncidentId>>> = Arc::default();
        let inner = Arc::new(MemoryIncidents::default());
        let shared = SharedIncidents::new(inner.clone(), Arc::new(Activity::new())).on_closed({
            let closed = closed.clone();
            move |id| closed.lock().unwrap().push(id)
        });
        let one = detection(1, "T1110.003", &ip());
        let first = engine_state(std::slice::from_ref(&one));
        shared.merge_engine(&first).await.unwrap();
        let mut worked = first.clone();
        worked.status = IncidentStatus::Investigating;
        shared.save(&worked).await.unwrap();
        assert_eq!(*closed.lock().unwrap(), []);

        let mut replaced = first.clone();
        replaced.status = IncidentStatus::Resolved;
        replaced.timeline.push(agent_entry(
            5,
            "correlator",
            "The correlator merged this incident into incident X.",
        ));
        let merge = shared.merge_engine(&replaced).await.unwrap();

        assert_eq!(merge.incident.status, IncidentStatus::Resolved);
        assert_eq!(merge.previous_status, Some(IncidentStatus::Investigating));
        assert_eq!(*closed.lock().unwrap(), [first.id]);

        // A closed incident keeps its state when the engine sends an `open` state.
        let mut closed_by_agent = first.clone();
        closed_by_agent.id = IncidentId(uuid_from(901));
        shared.merge_engine(&closed_by_agent).await.unwrap();
        let mut false_positive = closed_by_agent.clone();
        false_positive.status = IncidentStatus::FalsePositive;
        shared.save(&false_positive).await.unwrap();
        let two = detection(2, "T1078", &user());
        let mut later = engine_state(&[one, two]);
        later.id = closed_by_agent.id;
        let merge = shared.merge_engine(&later).await.unwrap();
        assert_eq!(merge.incident.status, IncidentStatus::FalsePositive);
        assert_eq!(merge.new_detections, 1);
        assert_eq!(
            *closed.lock().unwrap(),
            [first.id, closed_by_agent.id, closed_by_agent.id]
        );
    }

    #[tokio::test]
    async fn a_save_with_an_old_copy_does_not_remove_a_newer_detection() {
        let (inner, shared, _) = store();
        let one = detection(1, "T1110.003", &ip());
        let two = detection(2, "T1078", &user());
        let first = engine_state(std::slice::from_ref(&one));
        shared.merge_engine(&first).await.unwrap();

        // An agent reads the incident. Then the engine adds a detection. Then the agent
        // saves its copy, which does not have the new detection.
        let mut copy = shared.get(first.id).await.unwrap().unwrap();
        shared
            .merge_engine(&engine_state(&[one.clone(), two.clone()]))
            .await
            .unwrap();
        copy.status = IncidentStatus::Investigating;
        copy.summary = "The analyst confirmed the incident.".to_owned();
        copy.severity = Severity::Medium;
        let entry = agent_entry(1, "analyst", "The analyst assessed a true positive.");
        copy.timeline.push(entry.clone());
        shared.save(&copy).await.unwrap();

        let stored = inner.get(first.id).await.unwrap().unwrap();
        assert_eq!(stored.status, IncidentStatus::Investigating);
        assert_eq!(stored.summary, "The analyst confirmed the incident.");
        assert_eq!(stored.detections, [one.clone(), two.clone()]);
        assert_eq!(stored.entities, [ip(), user()]);
        assert_eq!(stored.attack.len(), 2);
        assert_eq!(
            stored.timeline,
            [correlator_entry(&one), entry, correlator_entry(&two)]
        );
        // The severity does not go down.
        assert_eq!(stored.severity, Severity::High);
        assert_eq!(stored.updated_at, two.time);
    }

    #[tokio::test]
    async fn a_save_of_a_new_incident_and_the_read_functions_use_the_inner_store() {
        let (inner, shared, activity) = store();
        let mut incident = engine_state(&[detection(1, "T1110.003", &ip())]);
        incident.status = IncidentStatus::Contained;

        shared.save(&incident).await.unwrap();

        assert_eq!(
            inner.get(incident.id).await.unwrap(),
            Some(incident.clone())
        );
        assert_eq!(
            shared.get(incident.id).await.unwrap(),
            Some(incident.clone())
        );
        assert_eq!(
            shared
                .list(Some(IncidentStatus::Contained), 10)
                .await
                .unwrap(),
            [incident.clone()]
        );
        assert_eq!(
            shared.list(Some(IncidentStatus::Open), 10).await.unwrap(),
            []
        );
        assert_eq!(activity.count(), 1);
    }

    struct DownStore;

    #[async_trait]
    impl IncidentStore for DownStore {
        async fn save(&self, _: &Incident) -> Result<()> {
            Err(Error::Unavailable("the store is down".to_owned()))
        }

        async fn get(&self, _: IncidentId) -> Result<Option<Incident>> {
            Err(Error::Unavailable("the store is down".to_owned()))
        }

        async fn list(&self, _: Option<IncidentStatus>, _: usize) -> Result<Vec<Incident>> {
            Err(Error::Unavailable("the store is down".to_owned()))
        }
    }

    #[tokio::test]
    async fn a_store_error_goes_to_the_caller_and_calls_no_hook() {
        let closed: Arc<Mutex<Vec<IncidentId>>> = Arc::default();
        let activity = Arc::new(Activity::new());
        let shared = SharedIncidents::new(Arc::new(DownStore), activity.clone()).on_closed({
            let closed = closed.clone();
            move |id| closed.lock().unwrap().push(id)
        });
        let mut incident = engine_state(&[detection(1, "T1110.003", &ip())]);
        incident.status = IncidentStatus::Resolved;

        let merge = shared.merge_engine(&incident).await.unwrap_err();
        assert!(matches!(merge, Error::Unavailable(_)), "{merge:?}");
        let save = shared.save(&incident).await.unwrap_err();
        assert!(matches!(save, Error::Unavailable(_)), "{save:?}");
        assert_eq!(*closed.lock().unwrap(), []);
        assert_eq!(activity.count(), 0);
    }

    #[test]
    fn the_summary_memory_has_a_limit_and_forgets_closed_incidents() {
        let mut summaries = EngineSummaries::default();
        let mut incident = engine_state(&[detection(1, "T1110.003", &ip())]);
        summaries.remember(&incident, "first");
        assert_eq!(summaries.by_incident.get(&incident.id).unwrap(), "first");
        incident.status = IncidentStatus::Resolved;
        summaries.remember(&incident, "second");
        assert_eq!(summaries.by_incident.len(), 0);

        incident.status = IncidentStatus::Open;
        for number in 0..MAX_REMEMBERED_SUMMARIES {
            incident.id = IncidentId(uuid_from(10_000 + number as u128));
            summaries.remember(&incident, "summary");
        }
        assert_eq!(summaries.by_incident.len(), MAX_REMEMBERED_SUMMARIES);
        incident.id = IncidentId(uuid_from(1));
        summaries.remember(&incident, "summary");
        assert_eq!(summaries.by_incident.len(), 1);
    }
}
