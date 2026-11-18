//! The Responder: proposes containment actions and records their results.

use std::collections::BTreeMap;
use std::net::IpAddr;

use aegis_contracts::action::{ActionDisposition, ActionKind, ActionRequest};
use aegis_contracts::common::{ActionId, EntityKind, EntityRef, EvidenceKind, EvidenceRef};
use aegis_contracts::event::attr;
use aegis_contracts::graph::{NodeId, relation};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::model::TaskKind;
use aegis_contracts::{
    Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Error, Result,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use super::Roster;
use crate::config::ResponderConfig;
use crate::graph_ops::{link, prop, sync_incident_node, upsert_entity};
use crate::ledger::{ActionState, TrackedAction, kind_token, marker, marker_for, tracked_by};
use crate::llm::{ModelOutput, chat_json};
use crate::prompt::Prompt;
use crate::support::{
    self, active_detections, entity_label, incident_view, involved_entities, one_line, same_entity,
    token,
};

const RESPONDER: &str = "responder";
const MAX_OPTIONAL_CANDIDATES: usize = 20;
const SEARCH_LIMIT: usize = 200;

const INSTRUCTIONS: &str = "You are the responder agent of AEGIS, a defensive security system. \
    You plan the containment of one security incident in the environment of the operator. \
    The code already selected the baseline actions. You can add optional actions from the \
    list in the data section `optional_actions`. You cannot remove a baseline action, and \
    you cannot make an action that is not in the list. Add an optional action only if the \
    facts of the incident make it necessary. Each action goes through the policy of the \
    operator before it runs.";

const OUTPUT_FORMAT: &str = r#"{"add": an array of identifiers from `optional_actions`, for example ["o1"], or an empty array, "rationale": at most three sentences}"#;

/// One containment action that the code permits for an incident.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The action type.
    pub kind: ActionKind,
    /// The entity that the action changes.
    pub target: EntityRef,
    /// With `false`, the Responder always proposes the action. With `true`, the Responder
    /// proposes it only if the model selects it.
    pub optional: bool,
    /// Why the action is necessary.
    pub reason: String,
    /// The evidence for the action: the incident and the detections for the target.
    pub evidence: Vec<EvidenceRef>,
    /// Parameters for the connector.
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Draft {
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    rationale: String,
}

impl ModelOutput for Draft {}

/// Returns the baseline action types and the optional action types for an entity type.
fn rules(kind: EntityKind) -> (&'static [ActionKind], &'static [ActionKind]) {
    match kind {
        EntityKind::ServicePrincipal => (
            &[
                ActionKind::DisableServicePrincipal,
                ActionKind::RevokeCredential,
            ],
            &[ActionKind::RotateCredential],
        ),
        EntityKind::Application => (&[], &[ActionKind::RevokeCredential]),
        EntityKind::User => (&[ActionKind::KillSession], &[ActionKind::DisableUser]),
        EntityKind::Session => (&[ActionKind::KillSession], &[]),
        EntityKind::Host => (&[ActionKind::IsolateHost], &[]),
        EntityKind::Device => (&[], &[ActionKind::IsolateHost]),
        EntityKind::IpAddress => (&[ActionKind::BlockIp], &[]),
        EntityKind::Secret => (&[], &[ActionKind::RotateSecret]),
        EntityKind::Domain
        | EntityKind::Tenant
        | EntityKind::Role
        | EntityKind::Resource
        | EntityKind::Other => (&[], &[]),
    }
}

/// The order of the entity types in a containment plan. Identities come first.
fn priority(kind: EntityKind) -> u8 {
    match kind {
        EntityKind::ServicePrincipal => 0,
        EntityKind::User => 1,
        EntityKind::Session => 2,
        EntityKind::Host => 3,
        EntityKind::IpAddress => 4,
        _ => 5,
    }
}

/// Returns `true` if a block of this address is a sensible containment action.
///
/// An address inside the network of the operator is not a candidate. A block of such an
/// address can stop services of the operator. A person must decide.
fn is_blockable(address: &str) -> bool {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast())
        }
        Ok(IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
        Err(_) => false,
    }
}

fn reason(kind: &ActionKind, target: &EntityRef, rules_text: &str) -> String {
    let label = entity_label(target);
    let why = match kind {
        ActionKind::DisableServicePrincipal => {
            format!("Disable {label} to stop its access.")
        }
        ActionKind::RevokeCredential => {
            format!("Remove the credentials of {label}, so that the attacker cannot use them.")
        }
        ActionKind::RotateCredential => {
            format!("Replace the credentials of {label}.")
        }
        ActionKind::KillSession => {
            format!("Stop the sessions of {label}. The identity is possibly compromised.")
        }
        ActionKind::DisableUser => {
            format!("Disable {label} until a person examines the account.")
        }
        ActionKind::BlockIp => {
            format!(
                "Block the address {}. The attack activity comes from it.",
                target.id
            )
        }
        ActionKind::IsolateHost => {
            format!("Isolate {label} from the network to stop the activity.")
        }
        ActionKind::RotateSecret => {
            format!("Replace {label}. The attacker possibly read it.")
        }
        other => format!("Do {} on {label}.", kind_token(other)),
    };
    one_line(&format!("{why} Detections: {rules_text}."))
}

/// Returns the containment actions that the code permits for `incident`.
///
/// The function is deterministic. It reads the entities of the incident and of its
/// detections that are not benign. The entity type selects the actions:
///
/// | Entity | Baseline | Optional |
/// | --- | --- | --- |
/// | Service principal | Disable the service principal, revoke its credentials | Rotate its credentials |
/// | User | Stop the sessions | Disable the user |
/// | Session | Stop the session | |
/// | Host | Isolate the host | |
/// | IP address that is not internal | Block the address | |
/// | Application | | Revoke its credentials |
/// | Device | | Isolate the device |
/// | Secret | | Rotate the secret |
#[must_use]
pub fn containment_candidates(incident: &Incident) -> Vec<Candidate> {
    let mut entities = involved_entities(incident);
    entities.sort_by_key(|entity| priority(entity.kind));
    let mut candidates = Vec::new();
    for entity in &entities {
        let (baseline, optional) = rules(entity.kind);
        if baseline.is_empty() && optional.is_empty() {
            continue;
        }
        if entity.kind == EntityKind::IpAddress && !is_blockable(&entity.id) {
            continue;
        }
        let about: Vec<_> = active_detections(incident)
            .filter(|detection| {
                detection
                    .entities
                    .iter()
                    .any(|candidate| same_entity(candidate, entity))
            })
            .collect();
        let relevant: Vec<_> = if about.is_empty() {
            active_detections(incident).collect()
        } else {
            about
        };
        let mut evidence = vec![EvidenceRef::new(EvidenceKind::Incident, incident.id)];
        evidence.extend(
            relevant
                .iter()
                .take(support::MAX_EVIDENCE_LINKS - 1)
                .map(|detection| {
                    EvidenceRef::new(EvidenceKind::Detection, detection.id)
                        .with_note(one_line(&detection.rule_id))
                }),
        );
        let mut rule_ids: Vec<&str> = relevant
            .iter()
            .map(|detection| detection.rule_id.as_str())
            .collect();
        rule_ids.dedup();
        let rules_text = if rule_ids.is_empty() {
            "none".to_owned()
        } else {
            rule_ids.join(", ")
        };
        let credential = relevant.iter().find_map(|detection| {
            detection
                .attributes
                .get(attr::CREDENTIAL_ID)
                .and_then(Value::as_str)
        });
        let classes = [(baseline, false), (optional, true)];
        for (kinds, is_optional) in classes {
            for kind in kinds {
                let mut parameters = BTreeMap::new();
                let uses_credential = matches!(
                    kind,
                    ActionKind::RevokeCredential | ActionKind::RotateCredential
                );
                if let Some(id) = credential.filter(|_| uses_credential) {
                    parameters.insert(attr::CREDENTIAL_ID.to_owned(), json!(id));
                }
                candidates.push(Candidate {
                    kind: kind.clone(),
                    target: entity.clone(),
                    optional: is_optional,
                    reason: reason(kind, entity, &rules_text),
                    evidence: evidence.clone(),
                    parameters,
                });
            }
        }
    }
    candidates
}

/// Returns the last proposal of the Responder for each action type and target.
///
/// A new proposal replaces an earlier one for the same action and target. This occurs
/// after a failure, and after a dry run when the operator stops the dry run.
fn latest_proposals(incident: &Incident) -> Vec<TrackedAction> {
    let mut latest: Vec<TrackedAction> = Vec::new();
    for action in tracked_by(incident, RESPONDER) {
        let earlier = latest
            .iter_mut()
            .find(|known| known.kind == action.kind && known.target == action.target);
        match earlier {
            Some(known) => *known = action,
            None => latest.push(action),
        }
    }
    latest
}

/// The Responder agent.
///
/// For an incident, the Responder proposes the baseline actions of
/// [`containment_candidates`]. The model can add optional actions from the same function.
/// The model cannot remove a baseline action, and it cannot make a different action.
///
/// The Responder records each proposal and each result in the timeline of the incident.
/// It sets the state `Contained` only when each proposed action ran in the environment. A
/// dry run, a denial, a pending approval, and a failure do not contain an incident. The
/// Responder proposes a failed action again when it gets the incident again. The last
/// proposal for an action and a target sets the state.
#[derive(Debug, Clone)]
pub struct Responder {
    config: ResponderConfig,
    roster: Roster,
    dry_run: bool,
}

impl Responder {
    /// Makes the agent. With `dry_run`, each proposed action is a dry run.
    #[must_use]
    pub fn new(config: ResponderConfig, roster: Roster, dry_run: bool) -> Self {
        Self {
            config,
            roster,
            dry_run,
        }
    }

    /// Returns `true` if an action in this state must not be proposed again.
    fn blocks(&self, state: ActionState) -> bool {
        match state {
            ActionState::Proposed
            | ActionState::PendingApproval
            | ActionState::Denied
            | ActionState::Skipped
            | ActionState::Succeeded => true,
            ActionState::Failed => false,
            // After the operator stops the dry run, the action must run for real.
            ActionState::Simulated => self.dry_run,
        }
    }

    /// Asks the model which optional actions to add. Returns the selected actions and
    /// the notes for the audit log.
    async fn refine(
        &self,
        incident: &Incident,
        baseline: &[Candidate],
        optional: &[Candidate],
        context: &AgentContext,
    ) -> (Vec<Candidate>, Vec<String>) {
        let describe = |candidate: &Candidate| {
            json!({
                "action": kind_token(&candidate.kind),
                "target": NodeId::for_entity(&candidate.target).0,
                "reason": candidate.reason,
            })
        };
        let listed: Vec<(String, &Candidate)> = optional
            .iter()
            .take(MAX_OPTIONAL_CANDIDATES)
            .enumerate()
            .map(|(index, candidate)| (format!("o{}", index + 1), candidate))
            .collect();
        let options: Vec<Value> = listed
            .iter()
            .map(|(id, candidate)| {
                let mut option = describe(candidate);
                option["id"] = json!(id);
                option
            })
            .collect();
        let prompt = Prompt::new(INSTRUCTIONS)
            .task("Review the response for the incident in the data section `incident`.")
            .output_format(OUTPUT_FORMAT)
            .data("incident", &incident_view(incident))
            .data(
                "baseline_actions",
                &Value::Array(baseline.iter().map(describe).collect()),
            )
            .data("optional_actions", &Value::Array(options));
        match chat_json::<Draft>(context.models.as_ref(), TaskKind::ResponseDraft, &prompt).await {
            Ok(draft) => {
                let mut selected: Vec<Candidate> = Vec::new();
                let mut unknown = 0_usize;
                for id in &draft.add {
                    match listed.iter().find(|(known, _)| known == id.trim()) {
                        Some((_, candidate)) if !selected.contains(candidate) => {
                            selected.push((*candidate).clone());
                        }
                        Some(_) => {}
                        None => unknown += 1,
                    }
                }
                let mut notes = vec![format!(
                    "The model added {} optional actions for incident {}. {unknown} selections \
                     were not in the list and were ignored.",
                    selected.len(),
                    incident.id
                )];
                let rationale = one_line(&draft.rationale);
                if !rationale.is_empty() {
                    notes.push(format!("Response rationale of the model: {rationale}"));
                }
                (selected, notes)
            }
            Err(error) => (
                Vec::new(),
                vec![one_line(&format!(
                    "The model did not refine the response for incident {}: {error}. The \
                     deterministic actions apply.",
                    incident.id
                ))],
            ),
        }
    }

    async fn contain(&self, incoming: &Incident, context: &AgentContext) -> Result<AgentOutput> {
        let (mut incident, _) = support::current(context, incoming).await?;
        let before = incident.clone();
        let mut output = AgentOutput::default();
        if matches!(
            incident.status,
            IncidentStatus::FalsePositive | IncidentStatus::Resolved
        ) {
            output.notes.push(format!(
                "Incident {} has the state {}. The responder proposes no action.",
                incident.id,
                token(&incident.status)
            ));
            return Ok(output);
        }

        let tracked = latest_proposals(&incident);
        let (mut selected, optional): (Vec<Candidate>, Vec<Candidate>) =
            containment_candidates(&incident)
                .into_iter()
                .filter(|candidate| {
                    !tracked.iter().any(|known| {
                        known.is_for(&candidate.kind, &candidate.target) && self.blocks(known.state)
                    })
                })
                .partition(|candidate| !candidate.optional);
        if self.config.refine_with_model && !optional.is_empty() {
            let (added, notes) = self.refine(&incident, &selected, &optional, context).await;
            selected.extend(added);
            output.notes.extend(notes);
        }
        let limit = self.config.max_actions_per_incident;
        if selected.len() > limit {
            let description = format!(
                "The plan has {} actions. The limit is {limit}. The responder proposes the \
                 first {limit}. A person must review the other entities.",
                selected.len()
            );
            selected.truncate(limit);
            support::add_entry(&mut incident, &AgentRole::Responder, description.clone());
            output.notes.push(description);
        }

        if selected.is_empty() {
            if tracked.is_empty() {
                let description = "No containment action applies to the entities of the \
                                   incident. A person must decide."
                    .to_owned();
                self.add_once(&mut incident, description.clone());
                output
                    .notes
                    .push(format!("Incident {}: {description}", incident.id));
            } else if let Some(note) = self.settle(&mut incident) {
                output.notes.push(note);
            }
        } else {
            let mode = if self.dry_run { " as a dry run" } else { "" };
            let mut kinds = Vec::new();
            for candidate in selected {
                let mut request = ActionRequest::new(
                    candidate.kind.clone(),
                    candidate.target.clone(),
                    RESPONDER,
                    candidate.reason.clone(),
                );
                request.incident_id = Some(incident.id);
                request.evidence.clone_from(&candidate.evidence);
                request.parameters = candidate.parameters;
                request.dry_run = self.dry_run;
                let mut evidence = vec![marker(
                    request.id,
                    ActionState::Proposed,
                    &candidate.kind,
                    &candidate.target,
                )];
                evidence.extend(candidate.evidence);
                support::add_timeline(
                    &mut incident,
                    &AgentRole::Responder,
                    format!(
                        "Proposed {} on {}{mode}. {}",
                        kind_token(&candidate.kind),
                        entity_label(&candidate.target),
                        candidate.reason
                    ),
                    evidence,
                );
                kinds.push(kind_token(&candidate.kind));
                output.actions.push(request);
            }
            if matches!(
                incident.status,
                IncidentStatus::Open | IncidentStatus::Contained
            ) {
                incident.status = IncidentStatus::Investigating;
            }
            output.notes.push(format!(
                "Proposed {} containment actions{mode} for incident {}: {}.",
                kinds.len(),
                incident.id,
                kinds.join(", ")
            ));
        }

        self.finish(incident, &before, context, &mut output).await;
        Ok(output)
    }

    /// Adds a timeline entry, unless it is the same as the last entry of the Responder.
    fn add_once(&self, incident: &mut Incident, description: String) {
        let is_repeat = support::last_entry_by(incident, &AgentRole::Responder)
            .is_some_and(|entry| entry.description == description);
        if !is_repeat {
            support::add_entry(incident, &AgentRole::Responder, description);
        }
    }

    /// Sets the state of the incident from the results of its actions.
    ///
    /// Returns a note if each action has a result. Returns `None` while a result is
    /// missing.
    fn settle(&self, incident: &mut Incident) -> Option<String> {
        let tracked = latest_proposals(incident);
        if tracked.is_empty() || tracked.iter().any(|action| !action.state.is_settled()) {
            return None;
        }
        let count = |state: ActionState| {
            tracked
                .iter()
                .filter(|action| action.state == state)
                .count()
        };
        let done = tracked
            .iter()
            .filter(|action| action.state.is_done())
            .count();
        let description = if done == tracked.len() {
            incident.status = IncidentStatus::Contained;
            format!("Containment is complete. All {done} actions ran.")
        } else {
            if incident.status == IncidentStatus::Contained
                || incident.status == IncidentStatus::Open
            {
                incident.status = IncidentStatus::Investigating;
            }
            format!(
                "Containment is not complete. Of {} actions: {done} ran, {} were dry runs, {} \
                 wait for approval, {} were denied, {} failed. The incident stays open.",
                tracked.len(),
                count(ActionState::Simulated),
                count(ActionState::PendingApproval),
                count(ActionState::Denied),
                count(ActionState::Failed),
            )
        };
        self.add_once(incident, description.clone());
        Some(format!("Incident {}: {description}", incident.id))
    }

    /// Writes the state of the incident to the graph and puts the incident in the output.
    async fn finish(
        &self,
        incident: Incident,
        before: &Incident,
        context: &AgentContext,
        output: &mut AgentOutput,
    ) {
        if &incident == before {
            return;
        }
        if incident.status != before.status
            && let Err(error) = sync_incident_node(context.graph.as_ref(), &incident).await
        {
            output.notes.push(one_line(&format!(
                "The Defensive Graph did not take the state of incident {}: {error}.",
                incident.id
            )));
        }
        output.incidents.push(incident);
    }

    /// Finds the incident whose timeline has the action `action_id`.
    async fn incident_for_action(
        &self,
        action_id: ActionId,
        context: &AgentContext,
    ) -> Result<Incident> {
        let wanted = action_id.to_string();
        context
            .incidents
            .list(None, SEARCH_LIMIT)
            .await?
            .into_iter()
            .find(|incident| {
                tracked_by(incident, RESPONDER)
                    .iter()
                    .any(|action| action.action_id == wanted)
            })
            .ok_or_else(|| Error::NotFound(format!("an incident with the action {action_id}")))
    }

    /// Records a result for the tracked action and sets the state of the incident.
    async fn record(
        &self,
        mut incident: Incident,
        action_id: ActionId,
        state: ActionState,
        result: &str,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let before = incident.clone();
        let mut output = AgentOutput::default();
        let wanted = action_id.to_string();
        let tracked = tracked_by(&incident, RESPONDER)
            .into_iter()
            .find(|action| action.action_id == wanted);
        let Some(tracked) = tracked else {
            let description = one_line(&format!(
                "A result arrived for the action {action_id}. The responder did not propose \
                 this action for the incident. Result: {result}"
            ));
            self.add_once(&mut incident, description.clone());
            output
                .notes
                .push(format!("Incident {}: {description}", incident.id));
            self.finish(incident, &before, context, &mut output).await;
            return Ok(output);
        };

        // The bus can deliver one result two times. The second copy changes nothing.
        if tracked.state == state {
            return Ok(output);
        }

        let description = one_line(&format!("{} on {}: {result}", tracked.kind, tracked.target));
        let mut evidence = vec![marker_for(&tracked, state)];
        evidence.push(EvidenceRef::new(EvidenceKind::Incident, incident.id));
        support::add_timeline(
            &mut incident,
            &AgentRole::Responder,
            description.clone(),
            evidence,
        );
        output
            .notes
            .push(format!("Incident {}: {description}", incident.id));

        if state == ActionState::Succeeded
            && let Err(error) = self.link_containment(&incident, &tracked, context).await
        {
            output.notes.push(one_line(&format!(
                "The Defensive Graph did not take the containment of {}: {error}.",
                tracked.target
            )));
        }
        if let Some(note) = self.settle(&mut incident) {
            output.notes.push(note);
            if self.roster.has(&AgentRole::Reporter) {
                output.tasks.push(
                    AgentTask::new(
                        AgentRole::Reporter,
                        AgentInput::Incident(Box::new(incident.clone())),
                    )
                    .for_incident(incident.id),
                );
            }
        }
        self.finish(incident, &before, context, &mut output).await;
        Ok(output)
    }

    /// Writes the `contained_by` relation from the target of an action to the incident.
    async fn link_containment(
        &self,
        incident: &Incident,
        tracked: &TrackedAction,
        context: &AgentContext,
    ) -> Result<()> {
        let graph = context.graph.as_ref();
        let incident_node = sync_incident_node(graph, incident).await?;
        let target = NodeId(tracked.target.clone());
        if graph.node(&target).await?.is_none() {
            let entity = involved_entities(incident)
                .into_iter()
                .find(|entity| NodeId::for_entity(entity) == target);
            match entity {
                Some(entity) => {
                    upsert_entity(graph, &entity).await?;
                }
                None => return Err(Error::NotFound(format!("graph node {target}"))),
            }
        }
        let properties = BTreeMap::from([
            (prop::ACTION_KIND.to_owned(), json!(tracked.kind)),
            (prop::ACTION_ID.to_owned(), json!(tracked.action_id)),
        ]);
        link(
            graph,
            &target,
            relation::CONTAINED_BY,
            &incident_node,
            properties,
        )
        .await
    }

    async fn on_result(
        &self,
        task: &AgentTask,
        disposition: &ActionDisposition,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        // The runtime gives the result task the identifier of the action. A denial and a
        // pending approval carry no action identifier of their own.
        let task_action = ActionId(task.id.0);
        let (action_id, state, result) = match disposition {
            ActionDisposition::Executed(outcome) => (
                outcome.action_id,
                ActionState::from_status(outcome.status),
                format!(
                    "{} by the connector {}. {}",
                    token(&outcome.status),
                    outcome.connector,
                    outcome.message
                ),
            ),
            ActionDisposition::PendingApproval {
                approval_id,
                decision,
            } => (
                task_action,
                ActionState::PendingApproval,
                format!(
                    "waits for approval {approval_id}. {}",
                    decision.reasons.join(" ")
                ),
            ),
            ActionDisposition::Denied(decision) => (
                task_action,
                ActionState::Denied,
                format!("denied by policy. {}", decision.reasons.join(" ")),
            ),
        };
        let Some(incident_id) = task.incident_id else {
            // The runtime runs the tasks of one incident one at a time. Give the result
            // back as a task of its incident, so that it waits for the other tasks.
            let incident = self.incident_for_action(action_id, context).await?;
            let mut output = AgentOutput::default();
            output.tasks.push(AgentTask {
                incident_id: Some(incident.id),
                ..task.clone()
            });
            return Ok(output);
        };
        let incident = support::by_id(context, incident_id).await?;
        self.record(incident, action_id, state, &result, context)
            .await
    }

    /// Records a note from the runtime that the dispatcher could not take an action.
    async fn on_note(
        &self,
        task: &AgentTask,
        note: &str,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let Some(incident_id) = task.incident_id else {
            return Ok(AgentOutput::default());
        };
        let incident = support::by_id(context, incident_id).await?;
        let wanted = task.id.to_string();
        let is_open_proposal = tracked_by(&incident, RESPONDER)
            .iter()
            .any(|action| action.action_id == wanted && action.state == ActionState::Proposed);
        if !is_open_proposal {
            return Ok(AgentOutput::default());
        }
        self.record(
            incident,
            ActionId(task.id.0),
            ActionState::Failed,
            &format!("failed. {note}"),
            context,
        )
        .await
    }
}

#[async_trait]
impl Agent for Responder {
    fn role(&self) -> AgentRole {
        AgentRole::Responder
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Incident(incident) => self.contain(incident, context).await,
            AgentInput::ActionResult(disposition) => {
                self.on_result(&task, disposition, context).await
            }
            AgentInput::Note(note) => self.on_note(&task, note, context).await,
            AgentInput::Goal(_)
            | AgentInput::Tick
            | AgentInput::Event(_)
            | AgentInput::Detection(_) => Ok(AgentOutput::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::{ActionOutcome, ActionStatus};
    use aegis_contracts::common::{ApprovalId, TaskId};
    use aegis_contracts::detection::Verdict;
    use aegis_contracts::graph::DefensiveGraph;
    use aegis_contracts::incident::IncidentStore;
    use aegis_contracts::policy::{ActionTier, PolicyDecision, PolicyEffect};
    use aegis_testkit::{Harness, ScriptedModel};
    use chrono::Utc;

    use super::*;
    use crate::ledger::tracked_actions;
    use crate::prompt::{data_sections, outside_data_sections};
    use crate::support::testing::{
        attack_incident, detection, incident_task, rogue, spray_ip, victim,
    };

    fn responder(dry_run: bool) -> Responder {
        Responder::new(ResponderConfig::default(), Roster::all(), dry_run)
    }

    fn harness() -> Harness {
        Harness::new(ScriptedModel::new("fake"))
    }

    /// Does what the runtime does with the incidents of an output.
    async fn save(harness: &Harness, output: &AgentOutput) {
        for incident in &output.incidents {
            harness.incidents.save(incident).await.unwrap();
        }
    }

    /// Proposes the baseline actions for the attack incident and saves the incident.
    async fn proposed(harness: &Harness, dry_run: bool) -> (Incident, Vec<ActionRequest>) {
        let incident = attack_incident();
        let output = responder(dry_run)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        save(harness, &output).await;
        (incident, output.actions)
    }

    fn summary(actions: &[ActionRequest]) -> Vec<(ActionKind, String)> {
        actions
            .iter()
            .map(|action| (action.kind.clone(), action.target.id.clone()))
            .collect()
    }

    fn baseline() -> Vec<(ActionKind, String)> {
        vec![
            (ActionKind::DisableServicePrincipal, rogue().id),
            (ActionKind::RevokeCredential, rogue().id),
            (ActionKind::KillSession, victim().id),
            (ActionKind::BlockIp, spray_ip().id),
        ]
    }

    fn result_task(action: &ActionRequest, input: AgentInput) -> AgentTask {
        AgentTask {
            id: TaskId(action.id.0),
            to: AgentRole::Responder,
            from: None,
            incident_id: action.incident_id,
            input,
            created_at: Utc::now(),
        }
    }

    fn executed(action: &ActionRequest, status: ActionStatus) -> AgentInput {
        AgentInput::ActionResult(Box::new(ActionDisposition::Executed(ActionOutcome {
            action_id: action.id,
            status,
            connector: "test".to_owned(),
            message: "Done.".to_owned(),
            details: Value::Null,
            reversible: true,
            completed_at: Utc::now(),
        })))
    }

    fn decision(effect: PolicyEffect) -> PolicyDecision {
        PolicyDecision {
            effect,
            tier: ActionTier::Gated,
            reasons: vec!["The test policy decided.".to_owned()],
            policy: None,
            evaluated_at: Utc::now(),
        }
    }

    fn denied() -> AgentInput {
        AgentInput::ActionResult(Box::new(ActionDisposition::Denied(decision(
            PolicyEffect::Deny,
        ))))
    }

    fn pending(approval_id: ApprovalId) -> AgentInput {
        AgentInput::ActionResult(Box::new(ActionDisposition::PendingApproval {
            approval_id,
            decision: decision(PolicyEffect::RequireApproval),
        }))
    }

    /// Gives one result to the Responder and saves the changed incident.
    async fn deliver(
        harness: &Harness,
        dry_run: bool,
        action: &ActionRequest,
        input: AgentInput,
    ) -> AgentOutput {
        let output = responder(dry_run)
            .handle(result_task(action, input), &harness.context("goal"))
            .await
            .unwrap();
        save(harness, &output).await;
        output
    }

    async fn stored(harness: &Harness, incident: &Incident) -> Incident {
        harness.incidents.get(incident.id).await.unwrap().unwrap()
    }

    fn descriptions(incident: &Incident) -> Vec<&str> {
        incident
            .timeline
            .iter()
            .map(|entry| entry.description.as_str())
            .collect()
    }

    #[test]
    fn the_entity_type_selects_the_baseline_and_the_optional_actions() {
        let incident = attack_incident();
        let candidates = containment_candidates(&incident);
        let found: Vec<(ActionKind, String, bool)> = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.kind.clone(),
                    candidate.target.id.clone(),
                    candidate.optional,
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (ActionKind::DisableServicePrincipal, rogue().id, false),
                (ActionKind::RevokeCredential, rogue().id, false),
                (ActionKind::RotateCredential, rogue().id, true),
                (ActionKind::KillSession, victim().id, false),
                (ActionKind::DisableUser, victim().id, true),
                (ActionKind::BlockIp, spray_ip().id, false),
            ]
        );

        // The evidence is the incident and the detections that name the target.
        let disable = &candidates[0];
        assert_eq!(
            disable.evidence,
            [
                EvidenceRef::new(EvidenceKind::Incident, incident.id),
                EvidenceRef::new(EvidenceKind::Detection, incident.detections[1].id)
                    .with_note("velocity.credential_after_grant"),
                EvidenceRef::new(EvidenceKind::Detection, incident.detections[2].id)
                    .with_note("velocity.self_role_assignment"),
            ]
        );
        assert_eq!(
            disable.reason,
            "Disable service_principal sp-sync-helper to stop its access. Detections: \
             velocity.credential_after_grant, velocity.self_role_assignment."
        );
        let block = &candidates[5];
        assert_eq!(block.evidence.len(), 2);
        assert_eq!(
            block.reason,
            "Block the address 203.0.113.50. The attack activity comes from it. Detections: \
             velocity.sign_in_burst."
        );
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.parameters.is_empty())
        );
    }

    #[test]
    fn internal_addresses_and_benign_detections_give_no_candidates() {
        let mut incident = attack_incident();
        let address = |text: &str| EntityRef::new(EntityKind::IpAddress, text);
        incident.entities = vec![
            address("10.1.2.3"),
            address("192.168.0.9"),
            address("127.0.0.1"),
            address("169.254.10.10"),
            address("fd00::1"),
            address("::1"),
            address("not an address"),
            address("2001:db8::7"),
            EntityRef::new(EntityKind::Domain, "contoso.example"),
            EntityRef::new(EntityKind::Tenant, "tenant-contoso"),
        ];
        incident.detections = vec![
            detection(
                "noise.known_scanner",
                Verdict::Benign,
                "T0000",
                vec![EntityRef::new(EntityKind::Host, "host-benign")],
            ),
            detection(
                "velocity.sign_in_burst",
                Verdict::Malicious,
                "T1110.003",
                vec![address("198.51.100.200")],
            ),
        ];
        let found: Vec<(ActionKind, String)> = containment_candidates(&incident)
            .into_iter()
            .map(|candidate| (candidate.kind, candidate.target.id))
            .collect();
        assert_eq!(
            found,
            [
                (ActionKind::BlockIp, "2001:db8::7".to_owned()),
                (ActionKind::BlockIp, "198.51.100.200".to_owned()),
            ]
        );
    }

    #[test]
    fn the_credential_of_a_detection_goes_to_the_credential_actions() {
        let mut incident = attack_incident();
        incident.detections[1]
            .attributes
            .insert(attr::CREDENTIAL_ID.to_owned(), json!("credential-1"));
        let candidates = containment_candidates(&incident);
        let parameters: Vec<(ActionKind, Option<&Value>)> = candidates
            .iter()
            .filter(|candidate| candidate.target.kind == EntityKind::ServicePrincipal)
            .map(|candidate| {
                (
                    candidate.kind.clone(),
                    candidate.parameters.get(attr::CREDENTIAL_ID),
                )
            })
            .collect();
        let credential = json!("credential-1");
        assert_eq!(
            parameters,
            [
                (ActionKind::DisableServicePrincipal, None),
                (ActionKind::RevokeCredential, Some(&credential)),
                (ActionKind::RotateCredential, Some(&credential)),
            ]
        );
    }

    #[tokio::test]
    async fn the_baseline_actions_apply_when_the_model_is_not_available() {
        let harness = harness();
        let incident = attack_incident();
        let output = responder(true)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();

        assert_eq!(summary(&output.actions), baseline());
        for action in &output.actions {
            assert_eq!(action.incident_id, Some(incident.id));
            assert_eq!(action.requested_by, "responder");
            assert!(action.dry_run);
            assert_eq!(
                action.evidence[0],
                EvidenceRef::new(EvidenceKind::Incident, incident.id)
            );
            assert!(
                action.evidence[1..]
                    .iter()
                    .all(|link| link.kind == EvidenceKind::Detection)
            );
            assert!(action.evidence.len() >= 2);
        }
        assert_eq!(
            output.notes,
            [
                format!(
                    "The model did not refine the response for incident {}: the model call \
                     failed: unavailable: the script of model fake is empty. The deterministic \
                     actions apply.",
                    incident.id
                ),
                format!(
                    "Proposed 4 containment actions as a dry run for incident {}: \
                     disable_service_principal, revoke_credential, kill_session, block_ip.",
                    incident.id
                ),
            ]
        );
        assert!(output.tasks.is_empty());

        assert_eq!(output.incidents.len(), 1);
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert_eq!(updated.timeline.len(), 4);
        assert_eq!(
            updated.timeline[3].description,
            "Proposed block_ip on ip_address 203.0.113.50 as a dry run. Block the address \
             203.0.113.50. The attack activity comes from it. Detections: \
             velocity.sign_in_burst."
        );
        let tracked = tracked_actions(updated);
        assert_eq!(tracked.len(), 4);
        for (record, action) in tracked.iter().zip(&output.actions) {
            assert_eq!(record.action_id, action.id.to_string());
            assert_eq!(record.state, ActionState::Proposed);
            assert_eq!(record.author, "responder");
            assert!(record.is_for(&action.kind, &action.target));
        }
        let node = harness
            .graph
            .node(&NodeId::for_incident(incident.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.properties[prop::STATUS], "investigating");
    }

    #[tokio::test]
    async fn the_model_can_add_only_the_optional_actions_of_the_list() {
        let model = ScriptedModel::new("fake").reply_json(&json!({
            "add": ["o2", "o9", " o2 ", "disable_user user:user-000"],
            "rationale": "The password of the user is known\nto the attacker."
        }));
        let harness = Harness::new(model);
        let incident = attack_incident();
        let output = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();

        let mut expected = baseline();
        expected.push((ActionKind::DisableUser, victim().id));
        assert_eq!(summary(&output.actions), expected);
        assert!(output.actions.iter().all(|action| !action.dry_run));
        assert_eq!(
            output.notes,
            [
                format!(
                    "The model added 1 optional actions for incident {}. 2 selections were \
                     not in the list and were ignored.",
                    incident.id
                ),
                "Response rationale of the model: The password of the user is known to the \
                 attacker."
                    .to_owned(),
                format!(
                    "Proposed 5 containment actions for incident {}: \
                     disable_service_principal, revoke_credential, kill_session, block_ip, \
                     disable_user.",
                    incident.id
                ),
            ]
        );

        let requests = harness.model.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].task, TaskKind::ResponseDraft);
        let user = &requests[0].messages[1].content;
        assert!(!outside_data_sections(user).contains(&incident.title));
        assert!(!requests[0].messages[0].content.contains(&incident.title));
        let sections = data_sections(user);
        assert_eq!(sections.len(), 3);
        let listed_baseline: Value = serde_json::from_str(sections[1]).unwrap();
        assert_eq!(listed_baseline.as_array().unwrap().len(), 4);
        let options: Value = serde_json::from_str(sections[2]).unwrap();
        assert_eq!(
            options
                .as_array()
                .unwrap()
                .iter()
                .map(|option| (
                    option["id"].as_str().unwrap(),
                    option["action"].as_str().unwrap(),
                    option["target"].as_str().unwrap()
                ))
                .collect::<Vec<_>>(),
            [
                (
                    "o1",
                    "rotate_credential",
                    "service_principal:sp-sync-helper"
                ),
                ("o2", "disable_user", "user:user-dana"),
            ]
        );
    }

    #[tokio::test]
    async fn with_refinement_off_the_responder_uses_no_model() {
        let model = ScriptedModel::new("fake").reply_json(&json!({ "add": ["o2"] }));
        let harness = Harness::new(model);
        let config = ResponderConfig {
            refine_with_model: false,
            ..ResponderConfig::default()
        };
        let output = Responder::new(config, Roster::all(), true)
            .handle(
                incident_task(AgentRole::Responder, &attack_incident()),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(summary(&output.actions), baseline());
        assert!(harness.model.requests().is_empty());
    }

    #[tokio::test]
    async fn a_closed_incident_gets_no_action() {
        let harness = harness();
        for status in [IncidentStatus::FalsePositive, IncidentStatus::Resolved] {
            let mut incident = attack_incident();
            incident.status = status;
            let output = responder(false)
                .handle(
                    incident_task(AgentRole::Responder, &incident),
                    &harness.context("goal"),
                )
                .await
                .unwrap();
            assert!(output.actions.is_empty());
            assert!(output.incidents.is_empty());
            assert_eq!(
                output.notes,
                [format!(
                    "Incident {} has the state {}. The responder proposes no action.",
                    incident.id,
                    token(&status)
                )]
            );
        }
        assert!(harness.model.requests().is_empty());
    }

    #[tokio::test]
    async fn the_incident_is_contained_only_after_each_action_ran() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, false).await;
        assert_eq!(actions.len(), 4);

        for action in &actions[..3] {
            let output = deliver(
                &harness,
                false,
                action,
                executed(action, ActionStatus::Succeeded),
            )
            .await;
            assert!(output.tasks.is_empty());
            assert_eq!(output.incidents.len(), 1);
            assert_eq!(output.incidents[0].status, IncidentStatus::Investigating);
        }
        let last = &actions[3];
        let output = deliver(&harness, false, last, executed(last, ActionStatus::Skipped)).await;

        let contained = stored(&harness, &incident).await;
        assert_eq!(contained.status, IncidentStatus::Contained);
        assert_eq!(
            descriptions(&contained)[4..],
            [
                "disable_service_principal on service_principal:sp-sync-helper: succeeded by \
                 the connector test. Done.",
                "revoke_credential on service_principal:sp-sync-helper: succeeded by the \
                 connector test. Done.",
                "kill_session on user:user-dana: succeeded by the connector test. Done.",
                "block_ip on ip_address:203.0.113.50: skipped by the connector test. Done.",
                "Containment is complete. All 4 actions ran.",
            ]
        );
        let states: Vec<ActionState> = tracked_actions(&contained)
            .iter()
            .map(|action| action.state)
            .collect();
        assert_eq!(
            states,
            [
                ActionState::Succeeded,
                ActionState::Succeeded,
                ActionState::Succeeded,
                ActionState::Skipped
            ]
        );
        assert_eq!(
            output.notes,
            [
                format!(
                    "Incident {}: block_ip on ip_address:203.0.113.50: skipped by the \
                     connector test. Done.",
                    incident.id
                ),
                format!(
                    "Incident {}: Containment is complete. All 4 actions ran.",
                    incident.id
                ),
            ]
        );

        // The report follows the last result.
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Reporter);
        assert_eq!(output.tasks[0].incident_id, Some(incident.id));
        assert_eq!(
            output.tasks[0].input,
            AgentInput::Incident(Box::new(contained.clone()))
        );

        // Each target that an action changed has the relation to the incident. A skipped
        // action changed nothing.
        let incident_node = NodeId::for_incident(incident.id);
        let mut contained_by: Vec<(String, String)> = harness
            .graph
            .edges()
            .into_iter()
            .filter(|edge| edge.relation == relation::CONTAINED_BY)
            .map(|edge| {
                assert_eq!(edge.to, incident_node);
                (
                    edge.from.0,
                    edge.properties[prop::ACTION_KIND]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
            })
            .collect();
        contained_by.sort();
        assert_eq!(
            contained_by,
            [
                (
                    "service_principal:sp-sync-helper".to_owned(),
                    "revoke_credential".to_owned()
                ),
                ("user:user-dana".to_owned(), "kill_session".to_owned()),
            ]
        );
        let node = harness.graph.node(&incident_node).await.unwrap().unwrap();
        assert_eq!(node.properties[prop::STATUS], "contained");
    }

    #[tokio::test]
    async fn a_dry_run_a_denial_an_approval_and_a_failure_do_not_contain_the_incident() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, true).await;
        let approval = ApprovalId::new();

        deliver(
            &harness,
            true,
            &actions[0],
            executed(&actions[0], ActionStatus::Simulated),
        )
        .await;
        deliver(&harness, true, &actions[1], pending(approval)).await;
        deliver(&harness, true, &actions[2], denied()).await;
        let unsettled = stored(&harness, &incident).await;
        assert_eq!(unsettled.status, IncidentStatus::Investigating);
        assert_eq!(unsettled.timeline.len(), 7);

        let note = AgentInput::Note(
            "The dispatcher did not take the action: unavailable: the connector is down".to_owned(),
        );
        let output = deliver(&harness, true, &actions[3], note).await;

        let settled = stored(&harness, &incident).await;
        assert_eq!(settled.status, IncidentStatus::Investigating);
        assert_eq!(
            descriptions(&settled)[4..],
            [
                "disable_service_principal on service_principal:sp-sync-helper: simulated by \
                 the connector test. Done."
                    .to_owned(),
                format!(
                    "revoke_credential on service_principal:sp-sync-helper: waits for approval \
                     {approval}. The test policy decided."
                ),
                "kill_session on user:user-dana: denied by policy. The test policy decided."
                    .to_owned(),
                "block_ip on ip_address:203.0.113.50: failed. The dispatcher did not take the \
                 action: unavailable: the connector is down"
                    .to_owned(),
                "Containment is not complete. Of 4 actions: 0 ran, 1 were dry runs, 1 wait for \
                 approval, 1 were denied, 1 failed. The incident stays open."
                    .to_owned(),
            ]
        );
        let states: Vec<ActionState> = tracked_actions(&settled)
            .iter()
            .map(|action| action.state)
            .collect();
        assert_eq!(
            states,
            [
                ActionState::Simulated,
                ActionState::PendingApproval,
                ActionState::Denied,
                ActionState::Failed
            ]
        );
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Reporter);
        assert!(
            harness
                .graph
                .edges()
                .iter()
                .all(|edge| edge.relation != relation::CONTAINED_BY)
        );
    }

    #[tokio::test]
    async fn an_approved_action_that_runs_later_completes_the_containment() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, false).await;
        for action in &actions[..3] {
            deliver(
                &harness,
                false,
                action,
                executed(action, ActionStatus::Succeeded),
            )
            .await;
        }
        let gated = &actions[3];
        deliver(&harness, false, gated, pending(ApprovalId::new())).await;
        assert_eq!(
            stored(&harness, &incident).await.status,
            IncidentStatus::Investigating
        );

        // A person approved the action. The result arrives with no incident.
        let mut late = result_task(gated, executed(gated, ActionStatus::Succeeded));
        late.id = TaskId::new();
        late.incident_id = None;
        let routed = responder(false)
            .handle(late.clone(), &harness.context("goal"))
            .await
            .unwrap();
        assert!(routed.incidents.is_empty());
        assert!(routed.notes.is_empty());
        assert_eq!(
            routed.tasks,
            [AgentTask {
                incident_id: Some(incident.id),
                ..late
            }]
        );

        let output = responder(false)
            .handle(routed.tasks[0].clone(), &harness.context("goal"))
            .await
            .unwrap();
        save(&harness, &output).await;
        let contained = stored(&harness, &incident).await;
        assert_eq!(contained.status, IncidentStatus::Contained);
        assert_eq!(
            contained.timeline.last().unwrap().description,
            "Containment is complete. All 4 actions ran."
        );
    }

    #[tokio::test]
    async fn a_result_with_no_incident_and_an_unknown_action_is_an_error() {
        let harness = harness();
        let (_, actions) = proposed(&harness, false).await;
        let mut unknown = actions[0].clone();
        unknown.id = ActionId::new();
        unknown.incident_id = None;
        let error = responder(false)
            .handle(
                result_task(&unknown, executed(&unknown, ActionStatus::Succeeded)),
                &harness.context("goal"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::NotFound(what) if *what == format!("an incident with the action {}", unknown.id)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_repeated_result_changes_nothing() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, false).await;
        let action = &actions[0];
        let first = deliver(
            &harness,
            false,
            action,
            executed(action, ActionStatus::Succeeded),
        )
        .await;
        assert_eq!(first.incidents.len(), 1);
        let second = deliver(
            &harness,
            false,
            action,
            executed(action, ActionStatus::Succeeded),
        )
        .await;
        assert_eq!(second, AgentOutput::default());
        assert_eq!(stored(&harness, &incident).await.timeline.len(), 5);
    }

    #[tokio::test]
    async fn a_result_for_an_action_that_the_responder_did_not_propose_is_only_a_note() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, false).await;
        let mut foreign = actions[0].clone();
        foreign.id = ActionId::new();
        let output = deliver(
            &harness,
            false,
            &foreign,
            executed(&foreign, ActionStatus::Succeeded),
        )
        .await;
        let updated = stored(&harness, &incident).await;
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert_eq!(
            updated.timeline.last().unwrap().description,
            format!(
                "A result arrived for the action {}. The responder did not propose this \
                 action for the incident. Result: succeeded by the connector test. Done.",
                foreign.id
            )
        );
        assert!(
            tracked_actions(&updated)
                .iter()
                .all(|action| action.state == ActionState::Proposed)
        );
        assert!(output.tasks.is_empty());

        // A note for an action with a result, or with no incident, changes nothing.
        deliver(
            &harness,
            false,
            &actions[0],
            executed(&actions[0], ActionStatus::Succeeded),
        )
        .await;
        let note = AgentInput::Note("The dispatcher did not take the action: late".to_owned());
        let output = deliver(&harness, false, &actions[0], note.clone()).await;
        assert_eq!(output, AgentOutput::default());
        let mut no_incident = result_task(&actions[1], note);
        no_incident.incident_id = None;
        let output = responder(false)
            .handle(no_incident, &harness.context("goal"))
            .await
            .unwrap();
        assert_eq!(output, AgentOutput::default());
    }

    #[tokio::test]
    async fn only_failed_actions_are_proposed_again() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, true).await;
        deliver(
            &harness,
            true,
            &actions[0],
            executed(&actions[0], ActionStatus::Simulated),
        )
        .await;
        deliver(&harness, true, &actions[1], denied()).await;
        deliver(
            &harness,
            true,
            &actions[2],
            executed(&actions[2], ActionStatus::Failed),
        )
        .await;
        // The fourth action has no result.

        let again = responder(true)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(
            summary(&again.actions),
            [(ActionKind::KillSession, victim().id)]
        );
        assert_ne!(again.actions[0].id, actions[2].id);

        // After the operator stops the dry run, a simulated action must run for real.
        let live = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(
            summary(&live.actions),
            [
                (ActionKind::DisableServicePrincipal, rogue().id),
                (ActionKind::KillSession, victim().id)
            ]
        );
    }

    #[tokio::test]
    async fn a_retry_that_runs_completes_the_containment() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, false).await;
        for action in &actions[..3] {
            deliver(
                &harness,
                false,
                action,
                executed(action, ActionStatus::Succeeded),
            )
            .await;
        }
        deliver(
            &harness,
            false,
            &actions[3],
            executed(&actions[3], ActionStatus::Failed),
        )
        .await;
        let failed = stored(&harness, &incident).await;
        assert_eq!(failed.status, IncidentStatus::Investigating);
        assert_eq!(
            failed.timeline.last().unwrap().description,
            "Containment is not complete. Of 4 actions: 3 ran, 0 were dry runs, 0 wait for \
             approval, 0 were denied, 1 failed. The incident stays open."
        );

        // The next pass proposes the failed action again. Its result replaces the failure.
        let again = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        save(&harness, &again).await;
        assert_eq!(
            summary(&again.actions),
            [(ActionKind::BlockIp, spray_ip().id)]
        );
        let retry = &again.actions[0];
        let output = deliver(
            &harness,
            false,
            retry,
            executed(retry, ActionStatus::Succeeded),
        )
        .await;
        let contained = stored(&harness, &incident).await;
        assert_eq!(contained.status, IncidentStatus::Contained);
        assert_eq!(
            contained.timeline.last().unwrap().description,
            "Containment is complete. All 4 actions ran."
        );
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Reporter);
        // The record of the incident keeps the failed attempt.
        assert_eq!(tracked_actions(&contained).len(), 5);
    }

    #[tokio::test]
    async fn after_a_dry_run_the_real_actions_contain_the_incident() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, true).await;
        for action in &actions {
            deliver(
                &harness,
                true,
                action,
                executed(action, ActionStatus::Simulated),
            )
            .await;
        }
        assert_eq!(
            stored(&harness, &incident).await.status,
            IncidentStatus::Investigating
        );

        // The operator stops the dry run. The Responder proposes each action again.
        let live = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        save(&harness, &live).await;
        assert_eq!(summary(&live.actions), baseline());
        assert!(live.actions.iter().all(|action| !action.dry_run));
        for action in &live.actions {
            deliver(
                &harness,
                false,
                action,
                executed(action, ActionStatus::Succeeded),
            )
            .await;
        }
        let contained = stored(&harness, &incident).await;
        assert_eq!(contained.status, IncidentStatus::Contained);
        assert_eq!(
            contained.timeline.last().unwrap().description,
            "Containment is complete. All 4 actions ran."
        );
    }

    #[tokio::test]
    async fn a_second_pass_with_all_results_reports_the_state_and_proposes_nothing() {
        let harness = harness();
        let (incident, actions) = proposed(&harness, true).await;
        for action in &actions {
            deliver(
                &harness,
                true,
                action,
                executed(action, ActionStatus::Simulated),
            )
            .await;
        }
        let before = stored(&harness, &incident).await;
        let output = responder(true)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert!(output.actions.is_empty());
        assert!(output.incidents.is_empty());
        assert_eq!(
            output.notes[1],
            format!(
                "Incident {}: Containment is not complete. Of 4 actions: 0 ran, 4 were dry \
                 runs, 0 wait for approval, 0 were denied, 0 failed. The incident stays open.",
                incident.id
            )
        );
        assert_eq!(stored(&harness, &incident).await, before);
    }

    #[tokio::test]
    async fn the_plan_obeys_the_action_limit() {
        let harness = harness();
        let config = ResponderConfig {
            refine_with_model: false,
            max_actions_per_incident: 2,
        };
        let incident = attack_incident();
        let output = Responder::new(config, Roster::all(), true)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(
            summary(&output.actions),
            [
                (ActionKind::DisableServicePrincipal, rogue().id),
                (ActionKind::RevokeCredential, rogue().id)
            ]
        );
        assert_eq!(
            output.incidents[0].timeline[0].description,
            "The plan has 4 actions. The limit is 2. The responder proposes the first 2. A \
             person must review the other entities."
        );
    }

    #[tokio::test]
    async fn an_incident_with_no_candidate_gets_one_entry_for_a_person() {
        let harness = harness();
        let mut incident = attack_incident();
        incident.entities = vec![EntityRef::new(EntityKind::Domain, "contoso.example")];
        incident.detections.clear();
        let first = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert!(first.actions.is_empty());
        assert_eq!(first.incidents.len(), 1);
        assert_eq!(first.incidents[0].status, IncidentStatus::Open);
        assert_eq!(
            descriptions(&first.incidents[0]),
            [
                "No containment action applies to the entities of the incident. A person must decide."
            ]
        );
        save(&harness, &first).await;

        let second = responder(false)
            .handle(
                incident_task(AgentRole::Responder, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert!(second.incidents.is_empty());
        assert_eq!(second.notes.len(), 1);
        assert!(harness.model.requests().is_empty());
    }

    #[tokio::test]
    async fn inputs_that_are_not_for_the_responder_make_no_work() {
        let harness = harness();
        for input in [AgentInput::Tick, AgentInput::Goal("Contain.".to_owned())] {
            let output = responder(false)
                .handle(
                    AgentTask::new(AgentRole::Responder, input),
                    &harness.context("goal"),
                )
                .await
                .unwrap();
            assert_eq!(output, AgentOutput::default());
        }
    }
}
