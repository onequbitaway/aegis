//! The Deception agent: plans honeytokens and reacts when a honeytoken is used.

use std::collections::BTreeMap;

use aegis_contracts::action::{ActionDisposition, ActionKind, ActionRequest};
use aegis_contracts::common::{
    ActionId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, Severity,
};
use aegis_contracts::event::{Event, action, attr};
use aegis_contracts::graph::{DefensiveGraph, GraphNode, NodeId, NodeKind, relation};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};

use super::Roster;
use crate::config::DeceptionConfig;
use crate::graph_ops::{
    flag, is_entity_kind, link, link_tenant, prop, sync_incident_node, upsert_entity,
    upsert_entity_with,
};
use crate::ledger::{ActionState, kind_token, marker, marker_for, tracked_by};
use crate::support::{
    self, HONEYTOKEN_TRIP_NOTE, entity_label, involved_entities, is_active, one_line, same_entity,
    token,
};

const DECEPTION: &str = "deception";
const MAX_ESCALATED_INCIDENTS: usize = 3;
const MAX_MIMICS: usize = 3;

/// The Deception agent.
///
/// The agent is passive. It proposes `DeployHoneytoken` actions, and it reads the events
/// that a honeytoken makes when someone uses it. It never contacts an attacker and never
/// changes a system of a different party.
///
/// - For a confirmed incident with a compromised identity, the agent proposes one decoy
///   credential in each tenant of the incident that has no honeytoken.
/// - For a `Tick` or a goal, it proposes a decoy credential for each tenant in the graph
///   that has no honeytoken.
/// - For a honeytoken trip, it sets the severity of each active incident of the actor to
///   critical and gives the incident to the Analyst. A honeytoken has no legitimate use.
///   If no active incident has the actor, the agent records a finding.
/// - For the result of its action, it records the state of the honeytoken in the graph.
#[derive(Debug, Clone)]
pub struct Deception {
    config: DeceptionConfig,
    roster: Roster,
}

/// Returns the decoy credential for a tenant.
fn decoy_for(tenant: &str) -> EntityRef {
    EntityRef::new(
        EntityKind::Secret,
        format!("honeytoken-credential-{tenant}"),
    )
    .with_name("Decoy administrator credential")
    .with_tenant(tenant)
}

impl Deception {
    /// Makes the agent. `roster` holds the roles that can receive tasks.
    #[must_use]
    pub fn new(config: DeceptionConfig, roster: Roster) -> Self {
        Self { config, roster }
    }

    /// Makes the request for a decoy credential in `tenant`, unless the tenant has one.
    async fn propose(
        &self,
        graph: &dyn DefensiveGraph,
        tenant: &str,
        reason: String,
        mimics: &[NodeId],
        evidence: Vec<EvidenceRef>,
    ) -> Result<Option<ActionRequest>> {
        let decoy = decoy_for(tenant);
        let decoy_node = NodeId::for_entity(&decoy);
        if let Some(existing) = graph.node(&decoy_node).await? {
            let failed = existing
                .properties
                .get(prop::HONEYTOKEN_STATE)
                .and_then(Value::as_str)
                == Some(token(&ActionState::Failed).as_str());
            if !failed {
                return Ok(None);
            }
        }
        let mut request = ActionRequest::new(
            ActionKind::DeployHoneytoken,
            decoy.clone(),
            DECEPTION,
            reason,
        );
        request.evidence = evidence;
        request
            .parameters
            .insert("decoy_type".to_owned(), json!("credential"));
        request
            .parameters
            .insert("tenant".to_owned(), json!(tenant));
        if !mimics.is_empty() {
            request
                .parameters
                .insert("mimics".to_owned(), json!(mimics));
        }
        let properties = BTreeMap::from([
            (prop::HONEYTOKEN.to_owned(), json!(true)),
            (
                prop::HONEYTOKEN_STATE.to_owned(),
                json!(ActionState::Proposed),
            ),
            (prop::HONEYTOKEN_ACTION_ID.to_owned(), json!(request.id)),
        ]);
        upsert_entity_with(graph, &decoy, properties).await?;
        link_tenant(graph, &decoy_node, tenant).await?;
        Ok(Some(request))
    }

    async fn on_incident(
        &self,
        incoming: &Incident,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let (mut incident, _) = support::current(context, incoming).await?;
        let mut output = AgentOutput::default();
        if !matches!(
            incident.status,
            IncidentStatus::Investigating | IncidentStatus::Contained
        ) {
            return Ok(output);
        }
        let entities = involved_entities(&incident);
        let identities: Vec<&EntityRef> = entities
            .iter()
            .filter(|entity| NodeKind::from(entity.kind) == NodeKind::Identity)
            .collect();
        if identities.is_empty() {
            return Ok(output);
        }
        let mut tenants: Vec<&str> = Vec::new();
        let named = incident.tenant.iter().chain(
            identities
                .iter()
                .filter_map(|entity| entity.tenant.as_ref()),
        );
        for tenant in named {
            if !tenants.contains(&tenant.as_str()) {
                tenants.push(tenant);
            }
        }
        let mimics: Vec<NodeId> = identities
            .iter()
            .take(MAX_MIMICS)
            .map(|entity| NodeId::for_entity(entity))
            .collect();
        let tenants: Vec<String> = tenants
            .into_iter()
            .take(self.config.max_honeytokens_per_task)
            .map(str::to_owned)
            .collect();
        for tenant in tenants {
            let reason = one_line(&format!(
                "The incident {} shows misuse of an identity in the tenant {tenant}. A decoy \
                 credential shows if the attacker comes back.",
                incident.id
            ));
            let request = self
                .propose(
                    context.graph.as_ref(),
                    &tenant,
                    reason,
                    &mimics,
                    support::evidence(&incident),
                )
                .await?;
            let Some(mut request) = request else {
                continue;
            };
            request.incident_id = Some(incident.id);
            let mut evidence = vec![marker(
                request.id,
                ActionState::Proposed,
                &request.kind,
                &request.target,
            )];
            evidence.push(EvidenceRef::new(EvidenceKind::Incident, incident.id));
            support::add_timeline(
                &mut incident,
                &AgentRole::Deception,
                one_line(&format!(
                    "Proposed {} for the tenant {tenant}.",
                    kind_token(&request.kind)
                )),
                evidence,
            );
            output.notes.push(one_line(&format!(
                "Proposed a honeytoken for the tenant {tenant} because of the incident {}.",
                incident.id
            )));
            output.actions.push(request);
        }
        if !output.actions.is_empty() {
            output.incidents.push(incident);
        }
        Ok(output)
    }

    /// Proposes a decoy credential for each tenant in the graph that has no honeytoken.
    async fn review(&self, context: &AgentContext) -> Result<AgentOutput> {
        let graph = context.graph.as_ref();
        let mut output = AgentOutput::default();
        let assets = graph
            .nodes_by_kind(NodeKind::Asset, self.config.scan_limit)
            .await?;
        for tenant_node in assets
            .iter()
            .filter(|node| is_entity_kind(node, EntityKind::Tenant))
        {
            if output.actions.len() >= self.config.max_honeytokens_per_task {
                break;
            }
            let Some(tenant) = tenant_node.id.0.strip_prefix("tenant:") else {
                continue;
            };
            let reason = one_line(&format!(
                "The tenant {tenant} has no honeytoken. A decoy credential shows the theft of \
                 credentials early."
            ));
            if let Some(request) = self.propose(graph, tenant, reason, &[], Vec::new()).await? {
                output.notes.push(one_line(&format!(
                    "Proposed a honeytoken for the tenant {tenant}: the tenant has none."
                )));
                output.actions.push(request);
            }
        }
        Ok(output)
    }

    /// Finds the honeytoken node that the action `action_id` deploys.
    async fn honeytoken_for(
        &self,
        graph: &dyn DefensiveGraph,
        action_id: &str,
    ) -> Result<Option<GraphNode>> {
        let assets = graph
            .nodes_by_kind(NodeKind::Asset, self.config.scan_limit)
            .await?;
        Ok(assets.into_iter().find(|node| {
            flag(node, prop::HONEYTOKEN)
                && node
                    .properties
                    .get(prop::HONEYTOKEN_ACTION_ID)
                    .and_then(Value::as_str)
                    == Some(action_id)
        }))
    }

    /// Records the result of a `DeployHoneytoken` action in the graph and in the incident.
    async fn record(
        &self,
        task: &AgentTask,
        action_id: ActionId,
        state: ActionState,
        result: &str,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let graph = context.graph.as_ref();
        let mut output = AgentOutput::default();
        let wanted = action_id.to_string();
        let Some(mut node) = self.honeytoken_for(graph, &wanted).await? else {
            return Ok(output);
        };
        // The bus can deliver one result two times. The second copy changes nothing.
        if node.properties.get(prop::HONEYTOKEN_STATE) == Some(&json!(state)) {
            return Ok(output);
        }
        node.properties
            .insert(prop::HONEYTOKEN_STATE.to_owned(), json!(state));
        node.updated_at = Utc::now();
        let node_id = node.id.clone();
        graph.upsert_node(node).await?;
        output.notes.push(one_line(&format!(
            "The honeytoken {node_id} has the state {}: {result}",
            token(&state)
        )));

        if let Some(incident_id) = task.incident_id {
            let mut incident = support::by_id(context, incident_id).await?;
            let tracked = tracked_by(&incident, DECEPTION)
                .into_iter()
                .find(|action| action.action_id == wanted);
            if let Some(tracked) = tracked {
                let links = vec![
                    marker_for(&tracked, state),
                    EvidenceRef::new(EvidenceKind::Incident, incident.id),
                ];
                support::add_timeline(
                    &mut incident,
                    &AgentRole::Deception,
                    one_line(&format!("{} on {}: {result}", tracked.kind, tracked.target)),
                    links,
                );
                output.incidents.push(incident);
            }
        }
        Ok(output)
    }

    async fn on_result(
        &self,
        task: &AgentTask,
        disposition: &ActionDisposition,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        // The runtime gives the result task the identifier of the action.
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
            ActionDisposition::PendingApproval { approval_id, .. } => (
                task_action,
                ActionState::PendingApproval,
                format!("waits for approval {approval_id}."),
            ),
            ActionDisposition::Denied(decision) => (
                task_action,
                ActionState::Denied,
                format!("denied by policy. {}", decision.reasons.join(" ")),
            ),
        };
        self.record(task, action_id, state, &result, context).await
    }

    /// Writes the actor, the honeytoken, and their relation to the graph. Returns the
    /// node of the actor.
    async fn write_trip(
        &self,
        graph: &dyn DefensiveGraph,
        event: &Event,
        actor: &EntityRef,
    ) -> Result<NodeId> {
        let actor_node = upsert_entity(graph, actor).await?;
        if let Some(target) = &event.target {
            let properties = BTreeMap::from([
                (prop::HONEYTOKEN.to_owned(), json!(true)),
                (prop::HONEYTOKEN_TRIPPED_AT.to_owned(), json!(event.time)),
                (prop::HONEYTOKEN_TRIPPED_BY.to_owned(), json!(actor_node)),
            ]);
            let target_node = upsert_entity_with(graph, target, properties).await?;
            if target_node != actor_node {
                let properties = BTreeMap::from([
                    (prop::ACTION.to_owned(), json!(event.action)),
                    (prop::TIME.to_owned(), json!(event.time)),
                ]);
                link(
                    graph,
                    &actor_node,
                    relation::ACTED_ON,
                    &target_node,
                    properties,
                )
                .await?;
            }
        }
        Ok(actor_node)
    }

    /// Records a trip that has no active incident as a finding.
    async fn record_finding(
        &self,
        graph: &dyn DefensiveGraph,
        event: &Event,
        actor: &EntityRef,
        actor_node: &NodeId,
        honeytoken: &str,
    ) -> Result<String> {
        let id = NodeId(format!("finding:honeytoken-trip:{actor_node}:{honeytoken}"));
        let label = one_line(&format!(
            "The honeytoken {honeytoken} was used by {} and no active incident has this \
             identity",
            entity_label(actor)
        ));
        graph
            .upsert_node(GraphNode {
                id: id.clone(),
                kind: NodeKind::Finding,
                label: label.clone(),
                properties: BTreeMap::from([
                    (prop::HUNT.to_owned(), json!("honeytoken_trip")),
                    (prop::SOURCE.to_owned(), json!("deterministic")),
                    (prop::TIME.to_owned(), json!(event.time)),
                ]),
                updated_at: Utc::now(),
            })
            .await?;
        link(graph, &id, relation::INVOLVES, actor_node, BTreeMap::new()).await?;
        Ok(format!("Finding: {label}."))
    }

    /// Reacts to the use of a honeytoken.
    ///
    /// A task with no incident finds the active incidents of the actor. It makes one task
    /// for each of these incidents. A task with an incident escalates that incident. The
    /// runtime runs the tasks of one incident one at a time, so the escalation does not
    /// replace a change that a different agent makes at the same time.
    async fn on_trip(
        &self,
        task: &AgentTask,
        event: &Event,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let graph = context.graph.as_ref();
        let actor = event.actor.entity();
        let actor_node = self.write_trip(graph, event, &actor).await?;
        let honeytoken = one_line(
            event
                .attribute_str(attr::HONEYTOKEN_ID)
                .unwrap_or("unknown"),
        );
        let mut output = AgentOutput::default();

        if let Some(incident_id) = task.incident_id {
            let incident = support::by_id(context, incident_id).await?;
            if is_active(incident.status) {
                return self
                    .escalate(incident, event, &actor, &honeytoken, context)
                    .await;
            }
            let note = self
                .record_finding(graph, event, &actor, &actor_node, &honeytoken)
                .await?;
            output.notes.push(note);
            return Ok(output);
        }

        let incidents: Vec<Incident> = context
            .incidents
            .list(None, self.config.scan_limit)
            .await?
            .into_iter()
            .filter(|incident| {
                is_active(incident.status)
                    && involved_entities(incident)
                        .iter()
                        .any(|entity| same_entity(entity, &actor))
            })
            .take(MAX_ESCALATED_INCIDENTS)
            .collect();
        if incidents.is_empty() {
            let note = self
                .record_finding(graph, event, &actor, &actor_node, &honeytoken)
                .await?;
            output.notes.push(note);
            return Ok(output);
        }
        for incident in &incidents {
            output.tasks.push(
                AgentTask::new(
                    AgentRole::Deception,
                    AgentInput::Event(Box::new(event.clone())),
                )
                .for_incident(incident.id),
            );
        }
        output.notes.push(one_line(&format!(
            "The honeytoken {honeytoken} was used by {}. {} active incidents have this \
             identity.",
            entity_label(&actor),
            incidents.len()
        )));
        Ok(output)
    }

    /// Sets the severity of `incident` to critical for a honeytoken trip and gives the
    /// incident to the Analyst.
    async fn escalate(
        &self,
        mut incident: Incident,
        event: &Event,
        actor: &EntityRef,
        honeytoken: &str,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let mut output = AgentOutput::default();
        let trip_link =
            EvidenceRef::new(EvidenceKind::Event, event.id).with_note(HONEYTOKEN_TRIP_NOTE);
        let is_known = incident
            .timeline
            .iter()
            .any(|entry| entry.evidence.contains(&trip_link));
        if is_known {
            return Ok(output);
        }
        incident.severity = Severity::Critical;
        if incident.status == IncidentStatus::Contained {
            incident.status = IncidentStatus::Investigating;
        }
        for entity in std::iter::once(actor).chain(event.target.iter()) {
            if !incident
                .entities
                .iter()
                .any(|known| same_entity(known, entity))
            {
                incident.entities.push(entity.clone());
            }
        }
        let links = vec![
            trip_link,
            EvidenceRef::new(EvidenceKind::Incident, incident.id),
        ];
        support::add_timeline(
            &mut incident,
            &AgentRole::Deception,
            one_line(&format!(
                "The honeytoken {honeytoken} was used by {}. A honeytoken has no legitimate \
                 use. The severity is now critical.",
                entity_label(actor)
            )),
            links,
        );
        if let Err(error) = sync_incident_node(context.graph.as_ref(), &incident).await {
            output.notes.push(one_line(&format!(
                "The Defensive Graph did not take the state of incident {}: {error}.",
                incident.id
            )));
        }
        output.notes.push(one_line(&format!(
            "Escalated the incident {} to critical: the honeytoken {honeytoken} was used by {}.",
            incident.id,
            entity_label(actor)
        )));
        let next = [AgentRole::Analyst, AgentRole::Responder]
            .into_iter()
            .find(|role| self.roster.has(role));
        if let Some(role) = next {
            output.tasks.push(
                AgentTask::new(role, AgentInput::Incident(Box::new(incident.clone())))
                    .for_incident(incident.id),
            );
        }
        output.incidents.push(incident);
        Ok(output)
    }

    /// Records a note from the runtime that the dispatcher could not take an action.
    async fn on_note(
        &self,
        task: &AgentTask,
        note: &str,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let action_id = ActionId(task.id.0);
        let node = self
            .honeytoken_for(context.graph.as_ref(), &action_id.to_string())
            .await?;
        let is_open_proposal = node.is_some_and(|node| {
            node.properties
                .get(prop::HONEYTOKEN_STATE)
                .and_then(Value::as_str)
                == Some(token(&ActionState::Proposed).as_str())
        });
        if !is_open_proposal {
            return Ok(AgentOutput::default());
        }
        self.record(
            task,
            action_id,
            ActionState::Failed,
            &format!("failed. {note}"),
            context,
        )
        .await
    }
}

#[async_trait]
impl Agent for Deception {
    fn role(&self) -> AgentRole {
        AgentRole::Deception
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Event(event) if event.action == action::HONEYTOKEN_TRIP => {
                self.on_trip(&task, event, context).await
            }
            AgentInput::Incident(incident) => self.on_incident(incident, context).await,
            AgentInput::Tick | AgentInput::Goal(_) => self.review(context).await,
            AgentInput::ActionResult(disposition) => {
                self.on_result(&task, disposition, context).await
            }
            AgentInput::Note(note) => self.on_note(&task, note, context).await,
            AgentInput::Event(_) | AgentInput::Detection(_) => Ok(AgentOutput::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::{ActionOutcome, ActionStatus};
    use aegis_contracts::common::{ApprovalId, IncidentId, TaskId};
    use aegis_contracts::graph::Direction;
    use aegis_contracts::incident::IncidentStore;
    use aegis_contracts::policy::{ActionTier, PolicyDecision, PolicyEffect};
    use aegis_testkit::{Harness, ScriptedModel, fixtures};

    use super::*;
    use crate::ledger::tracked_actions;
    use crate::support::has_honeytoken_trip;
    use crate::support::testing::{attack_incident, incident_task, rogue, spray_ip, victim};

    const DECOY_NODE: &str = "secret:honeytoken-credential-tenant-contoso";
    const TRIPPED_SECRET: &str = "secret:kv-prod/legacy-admin-password";

    fn deception() -> Deception {
        Deception::new(DeceptionConfig::default(), Roster::all())
    }

    fn harness() -> Harness {
        Harness::new(ScriptedModel::new("fake"))
    }

    fn confirmed_incident() -> Incident {
        let mut incident = attack_incident();
        incident.status = IncidentStatus::Investigating;
        incident
    }

    /// Does what the runtime does with the incidents of an output.
    async fn save(harness: &Harness, output: &AgentOutput) {
        for incident in &output.incidents {
            harness.incidents.save(incident).await.unwrap();
        }
    }

    async fn node(harness: &Harness, id: &str) -> GraphNode {
        harness
            .graph
            .node(&NodeId(id.to_owned()))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the graph must have the node {id}"))
    }

    /// The honeytoken trip of the recorded attack log.
    fn trip() -> Event {
        let trips: Vec<Event> = fixtures::artex_style_attack()
            .into_iter()
            .filter(|event| event.action == action::HONEYTOKEN_TRIP)
            .collect();
        assert_eq!(trips.len(), 1);
        trips.into_iter().next().unwrap()
    }

    fn trip_task(incident: Option<IncidentId>) -> AgentTask {
        let mut task = AgentTask::new(AgentRole::Deception, AgentInput::Event(Box::new(trip())));
        task.incident_id = incident;
        task
    }

    fn result_task(action: &ActionRequest, input: AgentInput) -> AgentTask {
        AgentTask {
            id: TaskId(action.id.0),
            to: AgentRole::Deception,
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

    /// Proposes the decoy for the confirmed incident and saves the incident.
    async fn proposed(harness: &Harness) -> (Incident, ActionRequest) {
        let incident = confirmed_incident();
        let mut output = deception()
            .handle(
                incident_task(AgentRole::Deception, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        save(harness, &output).await;
        assert_eq!(output.actions.len(), 1);
        (incident, output.actions.remove(0))
    }

    #[tokio::test]
    async fn a_confirmed_incident_gets_one_decoy_credential_in_its_tenant() {
        let harness = harness();
        let context = harness.context("goal");
        let incident = confirmed_incident();
        let output = deception()
            .handle(incident_task(AgentRole::Deception, &incident), &context)
            .await
            .unwrap();

        assert_eq!(output.actions.len(), 1);
        let request = &output.actions[0];
        assert_eq!(request.kind, ActionKind::DeployHoneytoken);
        assert_eq!(
            request.target,
            EntityRef::new(EntityKind::Secret, "honeytoken-credential-tenant-contoso")
                .with_name("Decoy administrator credential")
                .with_tenant("tenant-contoso")
        );
        assert_eq!(request.requested_by, "deception");
        assert_eq!(request.incident_id, Some(incident.id));
        assert_eq!(request.evidence, support::evidence(&incident));
        assert_eq!(request.evidence.len(), 4);
        assert_eq!(
            request.reason,
            format!(
                "The incident {} shows misuse of an identity in the tenant tenant-contoso. A \
                 decoy credential shows if the attacker comes back.",
                incident.id
            )
        );
        assert_eq!(
            request.parameters,
            BTreeMap::from([
                ("decoy_type".to_owned(), json!("credential")),
                ("tenant".to_owned(), json!("tenant-contoso")),
                (
                    "mimics".to_owned(),
                    json!(["user:user-dana", "service_principal:sp-sync-helper"])
                ),
            ])
        );

        let decoy = node(&harness, DECOY_NODE).await;
        assert!(flag(&decoy, prop::HONEYTOKEN));
        assert_eq!(decoy.properties[prop::HONEYTOKEN_STATE], "proposed");
        assert_eq!(
            decoy.properties[prop::HONEYTOKEN_ACTION_ID],
            json!(request.id)
        );
        let tenants = harness
            .graph
            .neighbors(&decoy.id, Some(relation::MEMBER_OF), Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].id.0, "tenant:tenant-contoso");

        assert_eq!(output.incidents.len(), 1);
        let updated = &output.incidents[0];
        let entry = updated.timeline.last().unwrap();
        assert_eq!(entry.author, "deception");
        assert_eq!(
            entry.description,
            "Proposed deploy_honeytoken for the tenant tenant-contoso."
        );
        let tracked = tracked_actions(updated);
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].action_id, request.id.to_string());
        assert_eq!(tracked[0].state, ActionState::Proposed);
        assert_eq!(tracked[0].target, DECOY_NODE);
        assert_eq!(
            output.notes,
            [format!(
                "Proposed a honeytoken for the tenant tenant-contoso because of the incident {}.",
                incident.id
            )]
        );

        // The tenant has a honeytoken now. A second task proposes nothing.
        save(&harness, &output).await;
        let again = deception()
            .handle(incident_task(AgentRole::Deception, &incident), &context)
            .await
            .unwrap();
        assert_eq!(again, AgentOutput::default());
    }

    #[tokio::test]
    async fn an_incident_with_no_confirmed_identity_misuse_gets_no_honeytoken() {
        let harness = harness();
        let context = harness.context("goal");
        let open = attack_incident();
        let mut no_identity = confirmed_incident();
        no_identity.entities = vec![spray_ip()];
        no_identity.detections.clear();
        for incident in [open, no_identity] {
            let output = deception()
                .handle(incident_task(AgentRole::Deception, &incident), &context)
                .await
                .unwrap();
            assert_eq!(output, AgentOutput::default());
        }
        assert_eq!(harness.graph.node_count(), 0);
    }

    #[tokio::test]
    async fn a_review_proposes_a_decoy_for_each_tenant_that_has_none() {
        let harness = harness();
        let context = harness.context("goal");
        let graph = harness.graph.as_ref();
        upsert_entity(graph, &victim()).await.unwrap();
        for tenant in ["tenant-contoso", "tenant-fabrikam"] {
            upsert_entity(graph, &EntityRef::new(EntityKind::Tenant, tenant))
                .await
                .unwrap();
        }
        let tick = AgentTask::new(AgentRole::Deception, AgentInput::Tick);

        let output = deception().handle(tick.clone(), &context).await.unwrap();
        let mut targets: Vec<&str> = output
            .actions
            .iter()
            .map(|action| action.target.id.as_str())
            .collect();
        targets.sort_unstable();
        assert_eq!(
            targets,
            [
                "honeytoken-credential-tenant-contoso",
                "honeytoken-credential-tenant-fabrikam"
            ]
        );
        for action in &output.actions {
            assert_eq!(action.kind, ActionKind::DeployHoneytoken);
            assert_eq!(action.incident_id, None);
            assert!(action.evidence.is_empty());
            assert!(!action.parameters.contains_key("mimics"));
            let tenant = action.target.tenant.as_deref().unwrap();
            assert_eq!(
                action.reason,
                format!(
                    "The tenant {tenant} has no honeytoken. A decoy credential shows the theft \
                     of credentials early."
                )
            );
        }
        assert_eq!(output.notes.len(), 2);
        assert!(output.incidents.is_empty());

        let again = deception().handle(tick.clone(), &context).await.unwrap();
        assert_eq!(again, AgentOutput::default());

        // One task proposes at most the configured number of honeytokens.
        let limited_harness = self::harness();
        for tenant in ["tenant-a", "tenant-b", "tenant-c"] {
            upsert_entity(
                limited_harness.graph.as_ref(),
                &EntityRef::new(EntityKind::Tenant, tenant),
            )
            .await
            .unwrap();
        }
        let config = DeceptionConfig {
            max_honeytokens_per_task: 2,
            ..DeceptionConfig::default()
        };
        let limited = Deception::new(config, Roster::all())
            .handle(tick, &limited_harness.context("goal"))
            .await
            .unwrap();
        assert_eq!(limited.actions.len(), 2);
    }

    #[tokio::test]
    async fn the_result_of_the_action_sets_the_state_of_the_honeytoken() {
        let harness = harness();
        let context = harness.context("goal");
        let (incident, request) = proposed(&harness).await;

        let approval = ApprovalId::new();
        let pending = AgentInput::ActionResult(Box::new(ActionDisposition::PendingApproval {
            approval_id: approval,
            decision: decision(PolicyEffect::RequireApproval),
        }));
        let output = deception()
            .handle(result_task(&request, pending.clone()), &context)
            .await
            .unwrap();
        save(&harness, &output).await;
        assert_eq!(
            output.notes,
            [format!(
                "The honeytoken {DECOY_NODE} has the state pending_approval: waits for approval \
                 {approval}."
            )]
        );
        assert_eq!(
            node(&harness, DECOY_NODE).await.properties[prop::HONEYTOKEN_STATE],
            "pending_approval"
        );

        // The same result a second time changes nothing.
        let repeat = deception()
            .handle(result_task(&request, pending), &context)
            .await
            .unwrap();
        assert_eq!(repeat, AgentOutput::default());

        let output = deception()
            .handle(
                result_task(&request, executed(&request, ActionStatus::Succeeded)),
                &context,
            )
            .await
            .unwrap();
        save(&harness, &output).await;
        assert_eq!(
            node(&harness, DECOY_NODE).await.properties[prop::HONEYTOKEN_STATE],
            "succeeded"
        );
        let stored = harness.incidents.get(incident.id).await.unwrap().unwrap();
        assert_eq!(
            stored.timeline.last().unwrap().description,
            format!("deploy_honeytoken on {DECOY_NODE}: succeeded by the connector test. Done.")
        );
        let tracked = tracked_actions(&stored);
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].state, ActionState::Succeeded);
        assert_eq!(tracked[0].author, "deception");
        // The state of the incident is the work of the Responder.
        assert_eq!(stored.status, IncidentStatus::Investigating);
    }

    #[tokio::test]
    async fn a_denied_honeytoken_stays_denied_and_a_failed_one_is_proposed_again() {
        let harness = harness();
        let context = harness.context("goal");
        let (incident, request) = proposed(&harness).await;
        let denied = AgentInput::ActionResult(Box::new(ActionDisposition::Denied(decision(
            PolicyEffect::Deny,
        ))));
        let output = deception()
            .handle(result_task(&request, denied), &context)
            .await
            .unwrap();
        save(&harness, &output).await;
        assert_eq!(
            output.notes,
            [format!(
                "The honeytoken {DECOY_NODE} has the state denied: denied by policy. The test \
                 policy decided."
            )]
        );
        let again = deception()
            .handle(incident_task(AgentRole::Deception, &incident), &context)
            .await
            .unwrap();
        assert!(again.actions.is_empty());

        // A note of the runtime for a different action changes nothing.
        let mut other = request.clone();
        other.id = aegis_contracts::ActionId::new();
        let note = AgentInput::Note("The dispatcher did not take the action: down".to_owned());
        let ignored = deception()
            .handle(result_task(&other, note.clone()), &context)
            .await
            .unwrap();
        assert_eq!(ignored, AgentOutput::default());

        let second = self::harness();
        let context = second.context("goal");
        let (incident, request) = proposed(&second).await;
        let output = deception()
            .handle(result_task(&request, note), &context)
            .await
            .unwrap();
        save(&second, &output).await;
        assert_eq!(
            node(&second, DECOY_NODE).await.properties[prop::HONEYTOKEN_STATE],
            "failed"
        );
        let again = deception()
            .handle(incident_task(AgentRole::Deception, &incident), &context)
            .await
            .unwrap();
        assert_eq!(again.actions.len(), 1);
        assert_ne!(again.actions[0].id, request.id);
        assert_eq!(
            node(&second, DECOY_NODE).await.properties[prop::HONEYTOKEN_STATE],
            "proposed"
        );
    }

    #[tokio::test]
    async fn a_trip_makes_one_task_for_each_active_incident_of_the_actor() {
        let harness = harness();
        let context = harness.context("goal");
        let active = confirmed_incident();
        let mut closed = attack_incident();
        closed.status = IncidentStatus::FalsePositive;
        let mut unrelated = attack_incident();
        unrelated.entities = vec![victim()];
        unrelated.detections.clear();
        for incident in [&active, &closed, &unrelated] {
            harness.incidents.save(incident).await.unwrap();
        }

        let output = deception().handle(trip_task(None), &context).await.unwrap();
        assert_eq!(
            output.tasks,
            [AgentTask {
                id: output.tasks[0].id,
                to: AgentRole::Deception,
                from: None,
                incident_id: Some(active.id),
                input: AgentInput::Event(Box::new(trip())),
                created_at: output.tasks[0].created_at,
            }]
        );
        assert_eq!(
            output.notes,
            [
                "The honeytoken honeytoken-legacy-admin was used by service_principal \
                 sp-sync-helper. 1 active incidents have this identity."
            ]
        );
        // The first task changes no incident. The task of the incident does that.
        assert!(output.incidents.is_empty());
        assert_eq!(
            harness.incidents.get(active.id).await.unwrap(),
            Some(active)
        );

        // The graph has the use of the honeytoken.
        let secret = node(&harness, TRIPPED_SECRET).await;
        assert!(flag(&secret, prop::HONEYTOKEN));
        assert_eq!(
            secret.properties[prop::HONEYTOKEN_TRIPPED_BY],
            "service_principal:sp-sync-helper"
        );
        assert_eq!(
            secret.properties[prop::HONEYTOKEN_TRIPPED_AT],
            json!(trip().time)
        );
        let users = harness
            .graph
            .neighbors(&secret.id, Some(relation::ACTED_ON), Direction::Incoming)
            .await
            .unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, NodeId::for_entity(&rogue()));
    }

    #[tokio::test]
    async fn a_trip_escalates_its_incident_and_gives_it_to_the_analyst() {
        let harness = harness();
        let context = harness.context("goal");
        let mut incident = attack_incident();
        incident.status = IncidentStatus::Contained;
        incident.severity = Severity::Medium;
        harness.incidents.save(&incident).await.unwrap();

        let output = deception()
            .handle(trip_task(Some(incident.id)), &context)
            .await
            .unwrap();
        assert_eq!(output.incidents.len(), 1);
        let escalated = &output.incidents[0];
        assert_eq!(escalated.severity, Severity::Critical);
        assert_eq!(escalated.status, IncidentStatus::Investigating);
        assert_eq!(escalated.entities.len(), 4);
        assert_eq!(NodeId::for_entity(&escalated.entities[3]).0, TRIPPED_SECRET);
        let entry = escalated.timeline.last().unwrap();
        assert_eq!(entry.author, "deception");
        assert_eq!(
            entry.description,
            "The honeytoken honeytoken-legacy-admin was used by service_principal \
             sp-sync-helper. A honeytoken has no legitimate use. The severity is now critical."
        );
        assert_eq!(
            entry.evidence,
            [
                EvidenceRef::new(EvidenceKind::Event, trip().id).with_note(HONEYTOKEN_TRIP_NOTE),
                EvidenceRef::new(EvidenceKind::Incident, incident.id),
            ]
        );
        assert!(!has_honeytoken_trip(&incident));
        assert!(has_honeytoken_trip(escalated));
        assert_eq!(
            output.notes,
            [format!(
                "Escalated the incident {} to critical: the honeytoken honeytoken-legacy-admin \
                 was used by service_principal sp-sync-helper.",
                incident.id
            )]
        );
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Analyst);
        assert_eq!(output.tasks[0].incident_id, Some(incident.id));
        assert_eq!(
            output.tasks[0].input,
            AgentInput::Incident(Box::new(escalated.clone()))
        );
        let incident_node = node(&harness, &NodeId::for_incident(incident.id).0).await;
        assert_eq!(incident_node.properties[prop::SEVERITY], "critical");
        assert_eq!(incident_node.properties[prop::STATUS], "investigating");

        // The same trip a second time changes nothing.
        save(&harness, &output).await;
        let again = deception()
            .handle(trip_task(Some(incident.id)), &context)
            .await
            .unwrap();
        assert_eq!(again, AgentOutput::default());

        // With no Analyst, the Responder gets the incident.
        let other = attack_incident();
        harness.incidents.save(&other).await.unwrap();
        let roster = Roster::new([AgentRole::Deception, AgentRole::Responder]);
        let output = Deception::new(DeceptionConfig::default(), roster)
            .handle(trip_task(Some(other.id)), &context)
            .await
            .unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Responder);
    }

    #[tokio::test]
    async fn a_trip_with_no_active_incident_is_a_finding() {
        let harness = harness();
        let context = harness.context("goal");
        let mut closed = attack_incident();
        closed.status = IncidentStatus::Resolved;
        harness.incidents.save(&closed).await.unwrap();

        // One task has no incident. One task names an incident that is closed.
        for incident in [None, Some(closed.id)] {
            let output = deception()
                .handle(trip_task(incident), &context)
                .await
                .unwrap();
            assert_eq!(
                output.notes,
                [
                    "Finding: The honeytoken honeytoken-legacy-admin was used by \
                     service_principal sp-sync-helper and no active incident has this identity."
                ]
            );
            assert!(output.tasks.is_empty());
            assert!(output.incidents.is_empty());
            assert!(output.actions.is_empty());
        }
        let findings = harness
            .graph
            .nodes_by_kind(NodeKind::Finding, 10)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].id.0,
            "finding:honeytoken-trip:service_principal:sp-sync-helper:honeytoken-legacy-admin"
        );
        assert_eq!(findings[0].properties[prop::HUNT], "honeytoken_trip");
        let involved = harness
            .graph
            .neighbors(
                &findings[0].id,
                Some(relation::INVOLVES),
                Direction::Outgoing,
            )
            .await
            .unwrap();
        assert_eq!(involved.len(), 1);
        assert_eq!(involved[0].id, NodeId::for_entity(&rogue()));
        assert_eq!(
            harness.incidents.get(closed.id).await.unwrap(),
            Some(closed)
        );

        // A trip for an incident that the store does not have is an error.
        let missing = IncidentId::new();
        let error = deception()
            .handle(trip_task(Some(missing)), &context)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, aegis_contracts::Error::NotFound(what) if *what == format!("incident {missing}")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn other_events_and_detections_make_no_work() {
        let harness = harness();
        let sign_in = fixtures::artex_style_attack().remove(0);
        assert_eq!(sign_in.action, action::SIGN_IN);
        let output = deception()
            .handle(
                AgentTask::new(AgentRole::Deception, AgentInput::Event(Box::new(sign_in))),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(output, AgentOutput::default());
        assert_eq!(harness.graph.node_count(), 0);
    }
}
