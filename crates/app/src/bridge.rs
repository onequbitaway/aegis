//! The bridges between the detection engine, the incident store, the agents, and the
//! playbooks.
//!
//! The detection engine knows only events, detections, and incidents. The bridge takes
//! each output of the engine and does the work that connects the subsystems:
//!
//! 1. It writes an audit record for each detection and for each change of an incident.
//! 2. It writes each incident state to the shared incident store. The store keeps the
//!    work of the agents. Refer to [`SharedIncidents`].
//! 3. It publishes the stored state of the incident on `aegis.incidents`. Thus a
//!    subscriber never sees a state that moves an incident back to `open`.
//! 4. It gives the incident to the agents, and it gives the events that caused a
//!    detection to the Monitor agent.
//! 5. It selects the incidents for which the playbooks of the operator run.
//! 6. It gives each new detection, with the events that caused it, to the evidence
//!    archive, if the archive is on.
//!
//! [`App::replay`](crate::App::replay) calls the bridge directly. In service mode, the
//! bus runner of the detection engine publishes on a [`DetectionBus`], which calls the
//! same functions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use aegis_agents::AgentRuntime;
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, publish_json, subject};
use aegis_contracts::common::{DetectionId, EventId, EvidenceKind, EvidenceRef, IncidentId};
use aegis_contracts::event::Event;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::{AgentInput, AgentRole, AgentTask, Detection, Result};
use aegis_respond::PlaybookRun;
use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;

use crate::activity::Activity;
use crate::evidence::EvidenceArchive;
use crate::incidents::{EngineMerge, SharedIncidents, is_closed};
use crate::playbooks::Playbooks;
use crate::settings::MonitorEvents;

/// The audit actor of the detection records.
pub const DETECTION_ACTOR: &str = "detection";
/// The audit actor of the incident records.
pub const CORRELATOR_ACTOR: &str = "correlator";
/// The audit actor of the playbook run records.
pub const PLAYBOOK_ACTOR: &str = "playbook-engine";

/// The number of recent events that the bridge keeps for the Monitor agent and for the
/// evidence archive.
const RECENT_EVENTS: usize = 1024;
/// The number of event identifiers that the bridge remembers as sent to the Monitor.
const REMEMBERED_EVENTS: usize = 4096;
/// The number of detection identifiers that the bridge remembers as recorded.
const REMEMBERED_DETECTIONS: usize = 4096;
/// The largest number of events that one detection sends to the Monitor.
const MAX_EVENTS_PER_DETECTION: usize = 16;
/// The largest number of events that one detection gives to the evidence archive.
const MAX_ARCHIVED_EVENTS_PER_DETECTION: usize = 256;
/// The largest number of evidence links in one audit record of the bridge.
const MAX_EVIDENCE: usize = 32;

/// The roles that can take an incident, in the order of the agent runtime.
const INTAKE_ROLES: [AgentRole; 3] = [
    AgentRole::Supervisor,
    AgentRole::Monitor,
    AgentRole::Analyst,
];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Returns the wire name of a value that serializes as one string, for example a severity.
fn token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// Counts of the work of the bridges since the process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Progress {
    /// The events that the ingestion runners of this process published.
    pub events_published: u64,
    /// The events that the detection engine completed.
    pub events_processed: u64,
    /// The detections that the bridge recorded.
    pub detections: u64,
    /// The incident states that changed the incident store.
    pub incident_updates: u64,
    /// The events that the Monitor agent got.
    pub monitor_events: u64,
    /// The events that the agent runtime did not take, for example because its queue was
    /// full.
    pub monitor_events_dropped: u64,
    /// The playbook runs.
    pub playbook_runs: u64,
}

#[derive(Default)]
struct Counters {
    events_published: AtomicU64,
    events_processed: AtomicU64,
    detections: AtomicU64,
    incident_updates: AtomicU64,
    monitor_events: AtomicU64,
    monitor_events_dropped: AtomicU64,
    playbook_runs: AtomicU64,
}

/// One recent event: the bus payload, or the decoded event.
enum Recent {
    Raw(Arc<Vec<u8>>),
    Event(Box<Event>),
}

/// A set of identifiers that forgets the oldest identifier when it is full.
struct Remembered<T> {
    limit: usize,
    order: VecDeque<T>,
    members: HashSet<T>,
}

impl<T: Copy + Eq + std::hash::Hash> Remembered<T> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            order: VecDeque::new(),
            members: HashSet::new(),
        }
    }

    fn contains(&self, item: &T) -> bool {
        self.members.contains(item)
    }

    /// Adds an identifier. Returns `false` if the set has it.
    fn insert(&mut self, item: T) -> bool {
        if !self.members.insert(item) {
            return false;
        }
        self.order.push_back(item);
        if self.order.len() > self.limit
            && let Some(oldest) = self.order.pop_front()
        {
            self.members.remove(&oldest);
        }
        true
    }

    fn remove(&mut self, item: &T) {
        if self.members.remove(item) {
            self.order.retain(|known| known != item);
        }
    }
}

struct Memory {
    recent: VecDeque<Recent>,
    sent_to_monitor: Remembered<EventId>,
    recorded_detections: Remembered<DetectionId>,
    /// The incident changes that are in the store and not yet on the bus.
    unpublished: HashMap<IncidentId, Unpublished>,
}

#[derive(Clone, Copy)]
struct Unpublished {
    is_new: bool,
    new_detections: usize,
    previous_status: Option<IncidentStatus>,
}

#[derive(Default)]
struct Tap {
    last_published: Option<Vec<u8>>,
    caught_up: bool,
}

/// How an incident gets to the agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentFeed {
    /// The bridge puts the incident in the queue of the agent runtime.
    Direct,
    /// The agent runtime reads the incident from the bus.
    Bus,
}

/// What the bridge did with one incident state of the detection engine.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IncidentUpdate {
    /// The result of the merge with the incident store.
    pub merge: EngineMerge,
    /// `true` if the Analyst must get the incident directly. Refer to
    /// [`Bridge::nudge_analyst`].
    pub analyst_nudge: bool,
    /// `true` if the matching playbooks must run for the incident.
    pub playbooks: bool,
}

/// The connections between the detection engine and the other subsystems.
pub(crate) struct Bridge {
    bus: Arc<dyn MessageBus>,
    audit: Arc<dyn AuditLog>,
    incidents: Arc<SharedIncidents>,
    agents: Option<Arc<AgentRuntime>>,
    playbooks: Arc<Playbooks>,
    playbooks_enabled: bool,
    monitor_events: MonitorEvents,
    activity: Arc<Activity>,
    /// The evidence archive. `None` if the archive is off.
    evidence: Option<Arc<EvidenceArchive>>,
    memory: Mutex<Memory>,
    tap: Mutex<Tap>,
    counters: Counters,
}

impl Bridge {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bus: Arc<dyn MessageBus>,
        audit: Arc<dyn AuditLog>,
        incidents: Arc<SharedIncidents>,
        agents: Option<Arc<AgentRuntime>>,
        playbooks: Arc<Playbooks>,
        playbooks_enabled: bool,
        monitor_events: MonitorEvents,
        activity: Arc<Activity>,
    ) -> Self {
        Self {
            bus,
            audit,
            incidents,
            agents,
            playbooks,
            playbooks_enabled,
            monitor_events,
            activity,
            evidence: None,
            memory: Mutex::new(Memory {
                recent: VecDeque::new(),
                sent_to_monitor: Remembered::new(REMEMBERED_EVENTS),
                recorded_detections: Remembered::new(REMEMBERED_DETECTIONS),
                unpublished: HashMap::new(),
            }),
            tap: Mutex::default(),
            counters: Counters::default(),
        }
    }

    /// Sets the evidence archive. The bridge then gives it each new detection with the
    /// events that caused the detection.
    pub(crate) fn with_evidence(mut self, evidence: Option<Arc<EvidenceArchive>>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Returns `true` if the bridge keeps the recent events: the Monitor agent or the
    /// evidence archive gets the events of a detection.
    fn keeps_recent(&self) -> bool {
        self.evidence.is_some()
            || (self.monitor_events == MonitorEvents::Detected && self.monitor().is_some())
    }

    /// Returns the counts of the work of the bridges.
    pub(crate) fn progress(&self) -> Progress {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Progress {
            events_published: read(&self.counters.events_published),
            events_processed: read(&self.counters.events_processed),
            detections: read(&self.counters.detections),
            incident_updates: read(&self.counters.incident_updates),
            monitor_events: read(&self.counters.monitor_events),
            monitor_events_dropped: read(&self.counters.monitor_events_dropped),
            playbook_runs: read(&self.counters.playbook_runs),
        }
    }

    /// Returns the agent runtime if the Monitor agent can take events.
    fn monitor(&self) -> Option<&Arc<AgentRuntime>> {
        if self.monitor_events == MonitorEvents::None {
            return None;
        }
        self.agents
            .as_ref()
            .filter(|runtime| runtime.roster().has(&AgentRole::Monitor))
    }

    /// Gives one event to the Monitor agent.
    fn send_to_monitor(&self, runtime: &AgentRuntime, event: Event) {
        let id = event.id;
        let task = AgentTask::new(AgentRole::Monitor, AgentInput::Event(Box::new(event)));
        match runtime.submit(task) {
            Ok(()) => {
                self.counters.monitor_events.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                // The event is in the detection path already. Only the graph misses it.
                lock(&self.memory).sent_to_monitor.remove(&id);
                self.counters
                    .monitor_events_dropped
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(event = %id, %error, "the monitor agent did not get an event");
            }
        }
    }

    /// Takes one event before the detection engine examines it.
    pub(crate) fn observe_event(&self, event: &Event) {
        if self.monitor_events == MonitorEvents::All
            && let Some(runtime) = self.monitor()
            && lock(&self.memory).sent_to_monitor.insert(event.id)
        {
            self.send_to_monitor(runtime, event.clone());
        }
        if self.keeps_recent() {
            self.remember(Recent::Event(Box::new(event.clone())));
        }
    }

    /// Takes one event message from the bus before the detection engine examines it.
    fn observe_message(&self, payload: &Arc<Vec<u8>>) {
        if self.monitor_events == MonitorEvents::All
            && let Some(runtime) = self.monitor()
            // The detection runner records a message that is not an event.
            && let Ok(event) = serde_json::from_slice::<Event>(payload)
            && lock(&self.memory).sent_to_monitor.insert(event.id)
        {
            self.send_to_monitor(runtime, event);
        }
        if self.keeps_recent() {
            self.remember(Recent::Raw(payload.clone()));
        }
    }

    fn remember(&self, recent: Recent) {
        let mut memory = lock(&self.memory);
        if memory.recent.len() >= RECENT_EVENTS {
            memory.recent.pop_front();
        }
        memory.recent.push_back(recent);
    }

    /// Returns the recent events that caused `detection` and that the Monitor does not
    /// have, oldest first.
    fn events_for_monitor(&self, detection: &Detection) -> Vec<Event> {
        let mut memory = lock(&self.memory);
        let skip = detection
            .event_ids
            .len()
            .saturating_sub(MAX_EVENTS_PER_DETECTION);
        let mut wanted: HashSet<EventId> = detection.event_ids[skip..]
            .iter()
            .copied()
            .filter(|id| !memory.sent_to_monitor.contains(id))
            .collect();
        let mut found = Vec::new();
        let mut position = memory.recent.len();
        while position > 0 && !wanted.is_empty() {
            position -= 1;
            // Decode a bus payload one time, when a detection first needs it.
            if let Some(Recent::Raw(payload)) = memory.recent.get(position) {
                match serde_json::from_slice::<Event>(payload) {
                    Ok(event) => memory.recent[position] = Recent::Event(Box::new(event)),
                    Err(_) => {
                        memory.recent.remove(position);
                        continue;
                    }
                }
            }
            if let Some(Recent::Event(event)) = memory.recent.get(position)
                && wanted.remove(&event.id)
            {
                found.push(event.as_ref().clone());
            }
        }
        for event in &found {
            memory.sent_to_monitor.insert(event.id);
        }
        found.reverse();
        found
    }

    /// Returns the recent events that caused `detection`, oldest first, for the evidence
    /// archive. The list has the newest events of the detection if the detection has more
    /// events than the archive takes.
    fn events_for_archive(&self, detection: &Detection) -> Vec<Event> {
        let mut memory = lock(&self.memory);
        let skip = detection
            .event_ids
            .len()
            .saturating_sub(MAX_ARCHIVED_EVENTS_PER_DETECTION);
        let mut wanted: HashSet<EventId> = detection.event_ids[skip..].iter().copied().collect();
        let mut found = Vec::new();
        let mut position = memory.recent.len();
        while position > 0 && !wanted.is_empty() {
            position -= 1;
            // Decode a bus payload one time, when a detection first needs it.
            if let Some(Recent::Raw(payload)) = memory.recent.get(position) {
                match serde_json::from_slice::<Event>(payload) {
                    Ok(event) => memory.recent[position] = Recent::Event(Box::new(event)),
                    Err(_) => {
                        memory.recent.remove(position);
                        continue;
                    }
                }
            }
            if let Some(Recent::Event(event)) = memory.recent.get(position)
                && wanted.remove(&event.id)
            {
                found.push(event.as_ref().clone());
            }
        }
        found.reverse();
        found
    }

    /// Takes one detection of the engine: the audit record, and the events for the Monitor.
    ///
    /// A detection that arrives a second time, for example after a new delivery of its
    /// event, gets no second audit record.
    pub(crate) async fn on_detection(&self, detection: &Detection) -> Result<()> {
        let is_new = !lock(&self.memory)
            .recorded_detections
            .contains(&detection.id);
        if is_new {
            let techniques: Vec<&str> = detection
                .attack
                .iter()
                .map(|technique| technique.technique_id.as_str())
                .collect();
            let mut evidence = vec![EvidenceRef::new(EvidenceKind::Detection, detection.id)];
            evidence.extend(
                detection
                    .event_ids
                    .iter()
                    .take(MAX_EVIDENCE - 1)
                    .map(|id| EvidenceRef::new(EvidenceKind::Event, id)),
            );
            let entry = AuditEntry::new(
                AuditKind::Detection,
                DETECTION_ACTOR,
                format!(
                    "The detector {} made the detection \"{}\" ({}, {}).",
                    detection.rule_id,
                    detection.title,
                    token(&detection.severity),
                    token(&detection.verdict)
                ),
            )
            .with_payload(json!({
                "detection_id": detection.id,
                "rule_id": detection.rule_id,
                "title": detection.title,
                "severity": detection.severity,
                "verdict": detection.verdict,
                "tier": detection.tier,
                "time": detection.time,
                "techniques": techniques,
                "entities": detection.entities,
                "tenant": detection.tenant,
                "events": detection.event_ids.len(),
            }))
            .with_evidence(evidence);
            self.audit.append(entry).await?;
            lock(&self.memory).recorded_detections.insert(detection.id);
            self.counters.detections.fetch_add(1, Ordering::Relaxed);
            // The archive is not the audit log. A write that fails does not stop the
            // detection: the archive counts it.
            if let Some(archive) = &self.evidence {
                archive.record_detection(detection, &self.events_for_archive(detection));
            }
        }
        if self.monitor_events == MonitorEvents::Detected
            && let Some(runtime) = self.monitor()
        {
            for event in self.events_for_monitor(detection) {
                self.send_to_monitor(runtime, event);
            }
        }
        Ok(())
    }

    /// Publishes one detection on `aegis.detections.{tier}`.
    pub(crate) async fn publish_detection(&self, detection: &Detection) -> Result<()> {
        let subject = format!(
            "{}.{}",
            subject::DETECTIONS,
            aegis_detect::common::tier_token(detection.tier)
        );
        publish_json(self.bus.as_ref(), &subject, detection).await
    }

    /// Takes one incident state of the engine.
    ///
    /// The function writes the state to the shared store, writes the audit record, and
    /// publishes the stored state on `aegis.incidents`. With [`AgentFeed::Direct`], it also
    /// puts the incident in the queue of the agent runtime.
    ///
    /// A state that changes nothing in the store has no effect. A call that failed after
    /// the write to the store continues at the next call with the same state.
    pub(crate) async fn on_engine_incident(
        &self,
        engine: &Incident,
        feed: AgentFeed,
    ) -> Result<IncidentUpdate> {
        let mut merge = self.incidents.merge_engine(engine).await?;
        let pending = {
            let mut memory = lock(&self.memory);
            if merge.changed {
                let pending = Unpublished {
                    is_new: merge.is_new,
                    new_detections: merge.new_detections,
                    previous_status: merge.previous_status,
                };
                memory.unpublished.insert(engine.id, pending);
                Some(pending)
            } else {
                memory.unpublished.get(&engine.id).copied()
            }
        };
        let Some(pending) = pending else {
            return Ok(IncidentUpdate {
                merge,
                analyst_nudge: false,
                playbooks: false,
            });
        };
        merge.is_new = pending.is_new;
        merge.new_detections = pending.new_detections;
        merge.previous_status = pending.previous_status;
        merge.changed = true;

        self.audit.append(incident_entry(&merge)).await?;
        publish_json(self.bus.as_ref(), subject::INCIDENTS, &merge.incident).await?;
        if feed == AgentFeed::Direct {
            self.submit_incident(&merge.incident)?;
        }
        lock(&self.memory).unpublished.remove(&engine.id);
        self.counters
            .incident_updates
            .fetch_add(1, Ordering::Relaxed);
        self.activity.bump();

        let incident = &merge.incident;
        let merged_away = engine.status == IncidentStatus::Resolved;
        let has_new_detection = merge.new_detections > 0;
        // The Monitor gives an incident to the Analyst when the incident store did not
        // have the data before, or when the incident is `open`. The store has the data at
        // this time, because the bridge wrote it. Thus an incident that an agent moved past
        // `open` gets to the Analyst only from here.
        let analyst_nudge = has_new_detection
            && !merge.is_new
            && !merged_away
            && incident.status != IncidentStatus::Open
            && self.agents.as_ref().is_some_and(|runtime| {
                runtime.roster().has(&AgentRole::Monitor)
                    && runtime.roster().has(&AgentRole::Analyst)
            });
        let playbooks = self.playbooks_enabled
            && has_new_detection
            && matches!(
                incident.status,
                IncidentStatus::Open | IncidentStatus::Investigating
            );
        Ok(IncidentUpdate {
            merge,
            analyst_nudge,
            playbooks,
        })
    }

    /// Puts an incident in the queue of the agent runtime, if an agent can take it.
    fn submit_incident(&self, incident: &Incident) -> Result<()> {
        let Some(runtime) = &self.agents else {
            return Ok(());
        };
        if !INTAKE_ROLES.iter().any(|role| runtime.roster().has(role)) {
            return Ok(());
        }
        runtime.submit_incident(incident.clone()).map(|_| ())
    }

    /// Gives an incident with a new detection directly to the Analyst.
    ///
    /// Call this for an [`IncidentUpdate`] that has `analyst_nudge` set.
    pub(crate) fn nudge_analyst(&self, incident: &Incident) -> Result<()> {
        let Some(runtime) = &self.agents else {
            return Ok(());
        };
        let task = AgentTask::new(
            AgentRole::Analyst,
            AgentInput::Incident(Box::new(incident.clone())),
        )
        .for_incident(incident.id);
        runtime.submit(task)
    }

    /// Runs each matching playbook that did not run for the incident before.
    ///
    /// The function reads the incident from the store, so the playbooks see the work of
    /// the agents. An incident that is not `open` or `investigating` at that time gets no
    /// playbook.
    pub(crate) async fn run_playbooks(&self, incident_id: IncidentId) -> Result<Vec<PlaybookRun>> {
        let Some(mode) = self.playbooks.run_mode() else {
            return Ok(Vec::new());
        };
        if !self.playbooks_enabled {
            return Ok(Vec::new());
        }
        let Some(incident) = self.incidents.get(incident_id).await? else {
            return Ok(Vec::new());
        };
        if !matches!(
            incident.status,
            IncidentStatus::Open | IncidentStatus::Investigating
        ) {
            if is_closed(incident.status) {
                self.playbooks.forget(incident_id);
            }
            return Ok(Vec::new());
        }
        let engine = self.playbooks.engine();
        let mut runs = Vec::new();
        for playbook in engine.matching(&incident) {
            if !self.playbooks.claim(incident_id, playbook.name()) {
                continue;
            }
            let run = engine.run(playbook, &incident, mode).await?;
            self.counters.playbook_runs.fetch_add(1, Ordering::Relaxed);
            let entry = AuditEntry::new(
                AuditKind::Other,
                PLAYBOOK_ACTOR,
                format!(
                    "The playbook {} ran for the incident {incident_id} in the mode {}: {} \
                     requests, {} failures.",
                    run.playbook,
                    token(&run.mode),
                    run.steps
                        .iter()
                        .filter(|step| step.request_id.is_some())
                        .count(),
                    run.failures()
                ),
            )
            .with_payload(json!({
                "playbook": run.playbook,
                "incident_id": incident_id,
                "mode": run.mode,
                "completed": run.completed(),
                "failures": run.failures(),
                "actions": run
                    .steps
                    .iter()
                    .filter_map(|step| step.request_id)
                    .collect::<Vec<_>>(),
            }))
            .with_evidence(vec![EvidenceRef::new(EvidenceKind::Incident, incident_id)]);
            self.audit.append(entry).await?;
            runs.push(run);
        }
        self.activity.bump();
        Ok(runs)
    }

    /// Records that an ingestion runner of this process publishes one event.
    fn event_published(&self, payload: &[u8]) {
        let mut tap = lock(&self.tap);
        tap.last_published = Some(payload.to_vec());
        tap.caught_up = false;
        self.counters
            .events_published
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records that the detection engine completed one event message.
    fn event_completed(&self, payload: &[u8]) {
        {
            let mut tap = lock(&self.tap);
            if tap.last_published.as_deref() == Some(payload) {
                tap.caught_up = true;
            }
        }
        self.counters
            .events_processed
            .fetch_add(1, Ordering::Relaxed);
        self.activity.bump();
    }

    /// Returns `true` if the detection engine completed the last event that an ingestion
    /// runner of this process published, or if no runner published an event.
    pub(crate) fn caught_up(&self) -> bool {
        let tap = lock(&self.tap);
        tap.last_published.is_none() || tap.caught_up
    }
}

/// Makes the audit record for one change of an incident.
fn incident_entry(merge: &EngineMerge) -> AuditEntry {
    let incident = &merge.incident;
    let summary = if merge.is_new {
        format!(
            "The correlator opened the incident {}: {}.",
            incident.id, incident.title
        )
    } else if incident.status == IncidentStatus::Resolved
        && merge.previous_status != Some(IncidentStatus::Resolved)
    {
        format!(
            "The correlator closed the incident {}: a different incident replaces it.",
            incident.id
        )
    } else {
        format!(
            "The correlator changed the incident {}: {} new detections, severity {}, state {}.",
            incident.id,
            merge.new_detections,
            token(&incident.severity),
            token(&incident.status)
        )
    };
    let techniques: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    let mut evidence = vec![EvidenceRef::new(EvidenceKind::Incident, incident.id)];
    // The newest detections are the cause of the change.
    let skip = incident.detections.len().saturating_sub(MAX_EVIDENCE - 1);
    evidence.extend(
        incident.detections[skip..]
            .iter()
            .map(|detection| EvidenceRef::new(EvidenceKind::Detection, detection.id)),
    );
    AuditEntry::new(AuditKind::Incident, CORRELATOR_ACTOR, summary)
        .with_payload(json!({
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "previous_status": merge.previous_status,
            "is_new": merge.is_new,
            "detections": incident.detections.len(),
            "new_detections": merge.new_detections,
            "techniques": techniques,
            "tenant": incident.tenant,
        }))
        .with_evidence(evidence)
}

/// The bus that the bus runner of the detection engine uses in service mode.
///
/// The runner publishes each detection and each incident state. This bus gives them to
/// the [`Bridge`] first:
///
/// - A detection gets its audit record. Then it goes to the bus with no change.
/// - An incident state goes to the shared incident store. The bus then gets the stored
///   state, which keeps the work of the agents. The agent runtime reads it from the bus.
///
/// The bus also watches the event subscription of the runner. Thus the bridge knows the
/// events for the Monitor agent, and it knows when the engine completed an event.
pub(crate) struct DetectionBus {
    inner: Arc<dyn MessageBus>,
    bridge: Arc<Bridge>,
    playbook_jobs: mpsc::UnboundedSender<IncidentId>,
}

impl DetectionBus {
    pub(crate) fn new(
        inner: Arc<dyn MessageBus>,
        bridge: Arc<Bridge>,
        playbook_jobs: mpsc::UnboundedSender<IncidentId>,
    ) -> Self {
        Self {
            inner,
            bridge,
            playbook_jobs,
        }
    }
}

fn is_below(subject_text: &str, parent: &str) -> bool {
    subject_text
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('.'))
}

#[async_trait]
impl MessageBus for DetectionBus {
    async fn publish(&self, subject_text: &str, payload: Vec<u8>) -> Result<()> {
        if subject_text == subject::INCIDENTS {
            let incident: Incident = serde_json::from_slice(&payload)?;
            let update = self
                .bridge
                .on_engine_incident(&incident, AgentFeed::Bus)
                .await?;
            if update.analyst_nudge
                && let Err(error) = self.bridge.nudge_analyst(&update.merge.incident)
            {
                // The incident is in the store and on the bus. The Monitor sweep finds an
                // open incident later, and a person sees each other one.
                tracing::warn!(
                    incident = %incident.id,
                    %error,
                    "the analyst did not get an incident with a new detection"
                );
            }
            if update.playbooks && self.playbook_jobs.send(incident.id).is_err() {
                tracing::debug!(incident = %incident.id, "no playbook worker runs");
            }
            return Ok(());
        }
        if is_below(subject_text, subject::DETECTIONS) {
            let detection: Detection = serde_json::from_slice(&payload)?;
            self.bridge.on_detection(&detection).await?;
        }
        self.inner.publish(subject_text, payload).await
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        let stream = self.inner.subscribe(pattern, durable).await?;
        if pattern == subject::EVENTS || is_below(pattern, subject::EVENTS) {
            return Ok(Box::pin(TappedEvents {
                inner: stream,
                bridge: self.bridge.clone(),
                in_work: None,
            }));
        }
        Ok(stream)
    }
}

/// The event subscription of the detection runner, with a watcher.
///
/// The runner completes its work on one message before it polls the stream again. Thus a
/// poll tells the bridge that the message before is complete.
struct TappedEvents {
    inner: BusStream,
    bridge: Arc<Bridge>,
    in_work: Option<Arc<Vec<u8>>>,
}

impl Stream for TappedEvents {
    type Item = Result<BusMessage>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(payload) = self.in_work.take() {
            self.bridge.event_completed(&payload);
        }
        let item = self.inner.as_mut().poll_next(context);
        if let Poll::Ready(Some(Ok(message))) = &item {
            let payload = Arc::new(message.payload.clone());
            self.bridge.observe_message(&payload);
            self.in_work = Some(payload);
        }
        item
    }
}

/// The bus that the ingestion runners use in service mode. It counts the events.
pub(crate) struct IngestTap {
    inner: Arc<dyn MessageBus>,
    bridge: Arc<Bridge>,
}

impl IngestTap {
    pub(crate) fn new(inner: Arc<dyn MessageBus>, bridge: Arc<Bridge>) -> Self {
        Self { inner, bridge }
    }
}

#[async_trait]
impl MessageBus for IngestTap {
    async fn publish(&self, subject_text: &str, payload: Vec<u8>) -> Result<()> {
        if is_below(subject_text, subject::EVENTS) {
            // Record the event before the publish. The detection engine can complete the
            // event before the publish returns.
            self.bridge.event_published(&payload);
        }
        self.inner.publish(subject_text, payload).await
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        self.inner.subscribe(pattern, durable).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU32;

    use aegis_contracts::Error;
    use aegis_contracts::common::{EntityKind, EntityRef, Severity};
    use aegis_contracts::detection::{AttackTechnique, DetectionTier, Verdict};
    use aegis_contracts::incident::TimelineEntry;
    use aegis_memory::MemoryIncidents;
    use aegis_testkit::{DispatchMode, MemoryAuditLog, MemoryBus, RecordingDispatcher, fixtures};
    use futures::StreamExt;

    use super::*;
    use crate::settings::PlaybookMode;

    /// A bus that refuses the first publishes on one subject.
    struct FlakyBus {
        inner: MemoryBus,
        subject: &'static str,
        failures_left: AtomicU32,
    }

    #[async_trait]
    impl MessageBus for FlakyBus {
        async fn publish(&self, subject_text: &str, payload: Vec<u8>) -> Result<()> {
            if subject_text == self.subject
                && self
                    .failures_left
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                        left.checked_sub(1)
                    })
                    .is_ok()
            {
                return Err(Error::Unavailable("the bus is down".to_owned()));
            }
            self.inner.publish(subject_text, payload).await
        }

        async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
            self.inner.subscribe(pattern, durable).await
        }
    }

    struct Bench {
        bridge: Arc<Bridge>,
        bus: Arc<FlakyBus>,
        audit: Arc<MemoryAuditLog>,
        store: Arc<MemoryIncidents>,
    }

    async fn bench(failing_subject: &'static str, failures: u32) -> Bench {
        let bus = Arc::new(FlakyBus {
            inner: MemoryBus::default(),
            subject: failing_subject,
            failures_left: AtomicU32::new(failures),
        });
        let audit = Arc::new(MemoryAuditLog::default());
        let store = Arc::new(MemoryIncidents::default());
        let activity = Arc::new(Activity::new());
        let incidents = Arc::new(SharedIncidents::new(store.clone(), activity.clone()));
        let playbooks = Arc::new(
            Playbooks::load(
                Arc::new(RecordingDispatcher::new(DispatchMode::Execute)),
                None,
                PlaybookMode::Off,
            )
            .await
            .unwrap(),
        );
        let bridge = Arc::new(Bridge::new(
            bus.clone(),
            audit.clone(),
            incidents,
            None,
            playbooks,
            false,
            MonitorEvents::Detected,
            activity,
        ));
        Bench {
            bridge,
            bus,
            audit,
            store,
        }
    }

    fn detection() -> Detection {
        Detection {
            id: DetectionId::new(),
            rule_id: "rule-1".to_owned(),
            title: "Sign-in burst".to_owned(),
            description: String::new(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time: fixtures::base_time(),
            attack: vec![AttackTechnique::new(
                "credential-access",
                "T1110.003",
                "Password Spraying",
            )],
            event_ids: vec![EventId::new()],
            entities: vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")],
            tenant: Some(fixtures::TENANT.to_owned()),
            attributes: BTreeMap::new(),
        }
    }

    fn incident(detections: &[Detection]) -> Incident {
        Incident {
            id: IncidentId::new(),
            title: "Sign-in burst".to_owned(),
            summary: "One detection.".to_owned(),
            severity: Severity::High,
            status: IncidentStatus::Open,
            created_at: fixtures::base_time(),
            updated_at: fixtures::base_time(),
            tenant: Some(fixtures::TENANT.to_owned()),
            detections: detections.to_vec(),
            entities: vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")],
            attack: Vec::new(),
            timeline: Vec::<TimelineEntry>::new(),
        }
    }

    #[tokio::test]
    async fn an_incident_change_that_the_bus_refused_continues_at_the_next_call() {
        let bench = bench(subject::INCIDENTS, 1).await;
        let state = incident(&[detection()]);

        // The store takes the state, and the bus refuses it.
        let error = bench
            .bridge
            .on_engine_incident(&state, AgentFeed::Bus)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
        assert_eq!(
            bench.store.get(state.id).await.unwrap(),
            Some(state.clone())
        );
        assert_eq!(bench.bus.inner.published_to(subject::INCIDENTS), []);
        assert_eq!(bench.bridge.progress().incident_updates, 0);

        // The detection runner publishes the same state again. The store does not change,
        // but the bridge knows that the bus does not have the change.
        let update = bench
            .bridge
            .on_engine_incident(&state, AgentFeed::Bus)
            .await
            .unwrap();
        assert!(update.merge.changed);
        assert!(update.merge.is_new);
        assert_eq!(update.merge.new_detections, 1);
        let published = bench.bus.inner.published_to(subject::INCIDENTS);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].decode::<Incident>().unwrap(), state);
        assert_eq!(bench.bridge.progress().incident_updates, 1);

        // A third copy has no effect.
        let again = bench
            .bridge
            .on_engine_incident(&state, AgentFeed::Bus)
            .await
            .unwrap();
        assert!(!again.merge.changed);
        assert!(!again.analyst_nudge);
        assert!(!again.playbooks);
        assert_eq!(bench.bus.inner.published_to(subject::INCIDENTS).len(), 1);
        assert_eq!(bench.bridge.progress().incident_updates, 1);
    }

    #[tokio::test]
    async fn a_detection_that_arrives_two_times_gets_one_audit_record() {
        let bench = bench(subject::INCIDENTS, 0).await;
        let found = detection();

        bench.bridge.on_detection(&found).await.unwrap();
        bench.bridge.on_detection(&found).await.unwrap();
        bench.bridge.on_detection(&detection()).await.unwrap();

        let records = bench.audit.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::Detection);
        assert_eq!(records[0].actor, DETECTION_ACTOR);
        assert_eq!(
            records[0].summary,
            "The detector rule-1 made the detection \"Sign-in burst\" (high, malicious)."
        );
        assert_eq!(records[0].payload["detection_id"], json!(found.id));
        assert_eq!(records[0].payload["techniques"], json!(["T1110.003"]));
        assert_eq!(
            records[0].evidence,
            [
                EvidenceRef::new(EvidenceKind::Detection, found.id),
                EvidenceRef::new(EvidenceKind::Event, found.event_ids[0]),
            ]
        );
        assert_eq!(bench.bridge.progress().detections, 2);
    }

    #[tokio::test]
    async fn the_detection_bus_gives_the_engine_output_to_the_bridge_first() {
        let bench = bench(subject::INCIDENTS, 0).await;
        let (jobs, mut job_queue) = mpsc::unbounded_channel();
        let bus = DetectionBus::new(bench.bus.clone(), bench.bridge.clone(), jobs);
        let found = detection();
        let state = incident(std::slice::from_ref(&found));

        publish_json(&bus, "aegis.detections.deterministic", &found)
            .await
            .unwrap();
        publish_json(&bus, subject::INCIDENTS, &state)
            .await
            .unwrap();
        // A different subject goes to the bus with no change.
        bus.publish("aegis.other", b"payload".to_vec())
            .await
            .unwrap();

        let subjects: Vec<String> = bench
            .bus
            .inner
            .published()
            .iter()
            .map(|message| message.subject.clone())
            .collect();
        assert_eq!(
            subjects,
            [
                "aegis.detections.deterministic",
                "aegis.incidents",
                "aegis.other"
            ]
        );
        let kinds: Vec<AuditKind> = bench
            .audit
            .records()
            .iter()
            .map(|record| record.kind)
            .collect();
        assert_eq!(kinds, [AuditKind::Detection, AuditKind::Incident]);
        assert_eq!(
            bench.store.get(state.id).await.unwrap(),
            Some(state.clone())
        );
        // The playbooks are off for this bridge, so no job is in the queue.
        assert!(job_queue.try_recv().is_err());

        // A payload that is not the type of its subject is an error, and nothing changes.
        let error = bus
            .publish(subject::INCIDENTS, b"not an incident".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Serialization(_)), "{error:?}");
        assert_eq!(bench.bus.inner.published().len(), 3);
    }

    #[tokio::test]
    async fn the_taps_know_when_the_engine_completed_the_last_published_event() {
        let bench = bench(subject::INCIDENTS, 0).await;
        let (jobs, _job_queue) = mpsc::unbounded_channel();
        let detection_bus = DetectionBus::new(bench.bus.clone(), bench.bridge.clone(), jobs);
        let ingest = IngestTap::new(bench.bus.clone(), bench.bridge.clone());
        let mut events = detection_bus
            .subscribe("aegis.events.>", Some("detect"))
            .await
            .unwrap();
        // No event is published: the engine has nothing to do.
        assert!(bench.bridge.caught_up());

        ingest
            .publish("aegis.events.file", b"one".to_vec())
            .await
            .unwrap();
        ingest
            .publish("aegis.events.file", b"two".to_vec())
            .await
            .unwrap();
        // A message on a different subject is not an event.
        ingest
            .publish("aegis.audit", b"record".to_vec())
            .await
            .unwrap();
        assert_eq!(bench.bridge.progress().events_published, 2);
        assert!(!bench.bridge.caught_up());

        // The consumer takes the first event. The work on it is not complete.
        assert_eq!(events.next().await.unwrap().unwrap().payload, b"one");
        assert_eq!(bench.bridge.progress().events_processed, 0);
        // The next poll tells the bridge that the first event is complete.
        assert_eq!(events.next().await.unwrap().unwrap().payload, b"two");
        assert_eq!(bench.bridge.progress().events_processed, 1);
        assert!(!bench.bridge.caught_up());
        // The poll after the last event completes it. No more event arrives.
        let idle = tokio::time::timeout(std::time::Duration::from_millis(50), events.next()).await;
        assert!(idle.is_err());
        assert_eq!(bench.bridge.progress().events_processed, 2);
        assert!(bench.bridge.caught_up());

        // A new event makes the engine late again.
        ingest
            .publish("aegis.events.file", b"three".to_vec())
            .await
            .unwrap();
        assert!(!bench.bridge.caught_up());
    }

    #[test]
    fn the_remembered_set_forgets_the_oldest_identifier() {
        let mut set = Remembered::new(2);
        assert!(set.insert(1));
        assert!(!set.insert(1));
        assert!(set.insert(2));
        assert!(set.insert(3));
        assert!(!set.contains(&1));
        assert!(set.contains(&2) && set.contains(&3));
        set.remove(&2);
        assert!(!set.contains(&2));
        assert!(set.insert(4));
        assert!(set.contains(&3) && set.contains(&4));
    }
}
