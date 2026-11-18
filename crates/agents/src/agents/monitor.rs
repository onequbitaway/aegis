//! The Monitor: keeps the Defensive Graph current and gives incidents to the Analyst.

use std::collections::BTreeMap;

use aegis_contracts::common::{EntityKind, EntityRef, IncidentId};
use aegis_contracts::detection::Detection;
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::graph::{DefensiveGraph, NodeId, relation};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use serde_json::{Value, json};

use super::Roster;
use crate::config::MonitorConfig;
use crate::graph_ops::{
    alert_node, flag, link, link_tenant, prop, sync_incident_node, upsert_entity,
    upsert_entity_with, upsert_merged,
};
use crate::support::{self, involved_entities, one_line};

/// The Monitor agent.
///
/// - For an incident, the Monitor writes the incident, its alerts, and its entities to the
///   Defensive Graph. Then it gives the incident to the Analyst.
/// - For a detection, it writes the alert and its entities.
/// - For an event, it writes the identities, the addresses, the roles, and their
///   relations. It gives a honeytoken trip to the Deception agent.
/// - For a `Tick` or a goal, it gives each open incident in the store to the Analyst.
///
/// The Monitor uses no model.
#[derive(Debug, Clone)]
pub struct Monitor {
    config: MonitorConfig,
    roster: Roster,
}

impl Monitor {
    /// Makes the agent. `roster` holds the roles that can receive tasks.
    #[must_use]
    pub fn new(config: MonitorConfig, roster: Roster) -> Self {
        Self { config, roster }
    }

    async fn on_incident(
        &self,
        incoming: &Incident,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let (mut incident, delta) = support::current(context, incoming).await?;
        let mut output = AgentOutput::default();
        let has_new_data = delta.is_new || delta.new_detections > 0;
        match write_incident(context.graph.as_ref(), &incident).await {
            Ok((alerts, entities)) => {
                if has_new_data {
                    support::add_entry(
                        &mut incident,
                        &AgentRole::Monitor,
                        format!(
                            "The Defensive Graph has the incident: {alerts} alerts and \
                             {entities} entities."
                        ),
                    );
                }
            }
            // The Analyst must get the incident also when the graph is not available.
            Err(error) => output.notes.push(one_line(&format!(
                "The Defensive Graph did not take incident {}: {error}.",
                incident.id
            ))),
        }
        let needs_analysis = has_new_data || incident.status == IncidentStatus::Open;
        if needs_analysis && self.roster.has(&AgentRole::Analyst) {
            output.tasks.push(
                AgentTask::new(
                    AgentRole::Analyst,
                    AgentInput::Incident(Box::new(incident.clone())),
                )
                .for_incident(incident.id),
            );
            output.notes.push(format!(
                "Added incident {} to the Defensive Graph and gave it to the analyst.",
                incident.id
            ));
        } else if delta.changed {
            output.notes.push(format!(
                "Updated incident {} in the Defensive Graph.",
                incident.id
            ));
        }
        if delta.changed {
            output.incidents.push(incident);
        }
        Ok(output)
    }

    async fn on_detection(
        &self,
        detection: &Detection,
        incident_id: Option<IncidentId>,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let graph = context.graph.as_ref();
        let alert = write_alert(graph, detection).await?;
        if let Some(id) = incident_id {
            let incident_node = NodeId::for_incident(id);
            if graph.node(&incident_node).await?.is_some() {
                link(
                    graph,
                    &alert,
                    relation::PART_OF,
                    &incident_node,
                    BTreeMap::new(),
                )
                .await?;
            }
        }
        Ok(AgentOutput::default())
    }

    async fn on_event(&self, event: &Event, context: &AgentContext) -> Result<AgentOutput> {
        write_event(context.graph.as_ref(), event).await?;
        let mut output = AgentOutput::default();
        if event.action == action::HONEYTOKEN_TRIP && self.roster.has(&AgentRole::Deception) {
            output.tasks.push(AgentTask::new(
                AgentRole::Deception,
                AgentInput::Event(Box::new(event.clone())),
            ));
            output.notes.push(format!(
                "Event {} is a honeytoken trip. The deception agent gets the event.",
                event.id
            ));
        }
        Ok(output)
    }

    async fn sweep(&self, context: &AgentContext) -> Result<AgentOutput> {
        let mut output = AgentOutput::default();
        if !self.roster.has(&AgentRole::Analyst) {
            return Ok(output);
        }
        let open = context
            .incidents
            .list(Some(IncidentStatus::Open), self.config.sweep_limit)
            .await?;
        if open.is_empty() {
            return Ok(output);
        }
        output.notes.push(format!(
            "The sweep found {} open incidents. The analyst gets them.",
            open.len()
        ));
        output.tasks = open
            .into_iter()
            .map(|incident| {
                let id = incident.id;
                AgentTask::new(AgentRole::Analyst, AgentInput::Incident(Box::new(incident)))
                    .for_incident(id)
            })
            .collect();
        Ok(output)
    }
}

#[async_trait]
impl Agent for Monitor {
    fn role(&self) -> AgentRole {
        AgentRole::Monitor
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Incident(incident) => self.on_incident(incident, context).await,
            AgentInput::Detection(detection) => {
                self.on_detection(detection, task.incident_id, context)
                    .await
            }
            AgentInput::Event(event) => self.on_event(event, context).await,
            AgentInput::Tick | AgentInput::Goal(_) => self.sweep(context).await,
            AgentInput::ActionResult(_) | AgentInput::Note(_) => Ok(AgentOutput::default()),
        }
    }
}

/// Writes the node of an entity and its `member_of` relation.
async fn write_entity(graph: &dyn DefensiveGraph, entity: &EntityRef) -> Result<NodeId> {
    let node = upsert_entity(graph, entity).await?;
    if let Some(tenant) = &entity.tenant {
        link_tenant(graph, &node, tenant).await?;
    }
    Ok(node)
}

/// Writes the node of a detection, the nodes of its entities, and the `involves` relations.
async fn write_alert(graph: &dyn DefensiveGraph, detection: &Detection) -> Result<NodeId> {
    let node = alert_node(detection);
    let alert = node.id.clone();
    upsert_merged(graph, node).await?;
    for entity in &detection.entities {
        let entity_node = write_entity(graph, entity).await?;
        link(
            graph,
            &alert,
            relation::INVOLVES,
            &entity_node,
            BTreeMap::new(),
        )
        .await?;
    }
    Ok(alert)
}

/// Writes an incident to the graph. Returns the number of alerts and entities.
async fn write_incident(graph: &dyn DefensiveGraph, incident: &Incident) -> Result<(usize, usize)> {
    let incident_node = sync_incident_node(graph, incident).await?;
    if let Some(tenant) = &incident.tenant {
        link_tenant(graph, &incident_node, tenant).await?;
    }
    let entities = involved_entities(incident);
    for entity in &entities {
        let entity_node = write_entity(graph, entity).await?;
        link(
            graph,
            &incident_node,
            relation::INVOLVES,
            &entity_node,
            BTreeMap::new(),
        )
        .await?;
    }
    for detection in &incident.detections {
        let alert = write_alert(graph, detection).await?;
        link(
            graph,
            &alert,
            relation::PART_OF,
            &incident_node,
            BTreeMap::new(),
        )
        .await?;
    }
    Ok((incident.detections.len(), entities.len()))
}

/// Writes the identities, the address, and the relations of one event.
///
/// Only an event with the outcome "success" gives relations. A failed sign-in for a user
/// does not show that the user did something.
async fn write_event(graph: &dyn DefensiveGraph, event: &Event) -> Result<()> {
    let actor = event.actor.entity();
    let actor_node = write_entity(graph, &actor).await?;
    let success = event.outcome == Outcome::Success;
    let time = json!(event.time);
    if success && let Some(ip) = event.actor.ip {
        let address = EntityRef::new(EntityKind::IpAddress, ip.to_string());
        let address_node = upsert_entity(graph, &address).await?;
        let properties = BTreeMap::from([(prop::TIME.to_owned(), time.clone())]);
        link(
            graph,
            &actor_node,
            relation::AUTHENTICATED_FROM,
            &address_node,
            properties,
        )
        .await?;
    }
    let Some(target) = &event.target else {
        return Ok(());
    };
    let target_node = write_entity(graph, target).await?;
    if !success {
        return Ok(());
    }
    if target_node != actor_node {
        let properties = BTreeMap::from([
            (prop::ACTION.to_owned(), json!(event.action)),
            (prop::TIME.to_owned(), time.clone()),
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
    match event.action.as_str() {
        action::APP_CREATE | action::SERVICE_PRINCIPAL_CREATE if target_node != actor_node => {
            link(
                graph,
                &actor_node,
                relation::OWNS,
                &target_node,
                BTreeMap::new(),
            )
            .await?;
        }
        action::ROLE_ASSIGN | action::APP_PERMISSION_GRANT => {
            write_role(
                graph,
                event,
                target,
                &target_node,
                target_node == actor_node,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

/// Writes the role of a role assignment, the `has_role` relation, and the privileged-role
/// properties of the identity that got the role.
async fn write_role(
    graph: &dyn DefensiveGraph,
    event: &Event,
    holder: &EntityRef,
    holder_node: &NodeId,
    self_assigned: bool,
) -> Result<()> {
    let Some(role_id) = event.attribute_str(attr::ROLE_ID) else {
        return Ok(());
    };
    let privileged = event.attribute_bool(attr::PRIVILEGED).unwrap_or(false);
    let mut role = EntityRef::new(EntityKind::Role, role_id);
    if let Some(name) = event.attribute_str(attr::ROLE_NAME) {
        role = role.with_name(name);
    }
    let role_label = role.name.clone().unwrap_or_else(|| role.id.clone());
    let role_node = upsert_entity_with(
        graph,
        &role,
        BTreeMap::from([(prop::PRIVILEGED.to_owned(), json!(privileged))]),
    )
    .await?;
    let time = json!(event.time);
    let properties = BTreeMap::from([
        (prop::TIME.to_owned(), time.clone()),
        (prop::PRIVILEGED.to_owned(), json!(privileged)),
    ]);
    link(
        graph,
        holder_node,
        relation::HAS_ROLE,
        &role_node,
        properties,
    )
    .await?;
    if !privileged {
        return Ok(());
    }
    let existing = graph.node(holder_node).await?;
    let mut roles: Vec<Value> = existing
        .as_ref()
        .and_then(|node| node.properties.get(prop::PRIVILEGED_ROLES))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !roles
        .iter()
        .any(|known| known.as_str() == Some(&role_label))
    {
        roles.push(json!(role_label));
    }
    let was_self_assigned = existing
        .as_ref()
        .is_some_and(|node| flag(node, prop::PRIVILEGED_ROLE_SELF_ASSIGNED));
    let properties = BTreeMap::from([
        (prop::PRIVILEGED_ROLES.to_owned(), Value::Array(roles)),
        (prop::PRIVILEGED_ROLE_ASSIGNED_AT.to_owned(), time),
        (
            prop::PRIVILEGED_ROLE_SELF_ASSIGNED.to_owned(),
            json!(self_assigned || was_self_assigned),
        ),
    ]);
    upsert_entity_with(graph, holder, properties).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aegis_contracts::graph::{Direction, GraphEdge, NodeKind};
    use aegis_contracts::incident::IncidentStore;
    use aegis_testkit::{Harness, ScriptedModel, fixtures};

    use super::*;
    use crate::support::testing::{
        attack_incident, incident_task, rogue, spray_ip, suspicious_incident, victim,
    };

    fn monitor() -> Monitor {
        Monitor::new(MonitorConfig::default(), Roster::all())
    }

    fn harness() -> Harness {
        Harness::new(ScriptedModel::new("fake"))
    }

    fn has_edge(edges: &[GraphEdge], from: &NodeId, relation: &str, to: &NodeId) -> bool {
        edges
            .iter()
            .any(|edge| &edge.from == from && edge.relation == relation && &edge.to == to)
    }

    fn event_task(event: &Event) -> AgentTask {
        AgentTask::new(
            AgentRole::Monitor,
            AgentInput::Event(Box::new(event.clone())),
        )
    }

    fn attack_event(name: &str) -> Event {
        let mut matches: Vec<Event> = fixtures::artex_style_attack()
            .into_iter()
            .filter(|event| event.action == name && event.actor.id != "sp-backup")
            .collect();
        assert!(!matches.is_empty(), "the log must have the action {name}");
        matches.remove(0)
    }

    #[tokio::test]
    async fn a_new_incident_goes_to_the_graph_and_to_the_analyst() {
        let harness = harness();
        let incident = attack_incident();
        let output = monitor()
            .handle(
                incident_task(AgentRole::Monitor, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();

        let incident_node = NodeId::for_incident(incident.id);
        let node = harness.graph.node(&incident_node).await.unwrap().unwrap();
        assert_eq!(node.kind, NodeKind::Incident);
        assert_eq!(node.properties[prop::STATUS], "open");
        let edges = harness.graph.edges();
        for entity in [spray_ip(), victim(), rogue()] {
            let entity_node = NodeId::for_entity(&entity);
            assert!(harness.graph.node(&entity_node).await.unwrap().is_some());
            assert!(has_edge(
                &edges,
                &incident_node,
                relation::INVOLVES,
                &entity_node
            ));
        }
        let tenant = NodeId("tenant:tenant-contoso".to_owned());
        assert!(has_edge(
            &edges,
            &incident_node,
            relation::MEMBER_OF,
            &tenant
        ));
        assert!(has_edge(
            &edges,
            &NodeId::for_entity(&rogue()),
            relation::MEMBER_OF,
            &tenant
        ));
        assert_eq!(incident.detections.len(), 3);
        for detection in &incident.detections {
            let alert = NodeId::for_detection(detection.id);
            assert!(has_edge(&edges, &alert, relation::PART_OF, &incident_node));
            assert!(!detection.entities.is_empty());
            for entity in &detection.entities {
                assert!(has_edge(
                    &edges,
                    &alert,
                    relation::INVOLVES,
                    &NodeId::for_entity(entity)
                ));
            }
        }
        // 1 incident, 3 alerts, 3 entities, 1 tenant.
        assert_eq!(harness.graph.node_count(), 8);

        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Analyst);
        assert_eq!(output.tasks[0].incident_id, Some(incident.id));
        assert_eq!(output.incidents.len(), 1);
        let saved = &output.incidents[0];
        assert_eq!(saved.status, IncidentStatus::Open);
        assert_eq!(saved.timeline.len(), 1);
        assert_eq!(saved.timeline[0].author, "monitor");
        assert_eq!(
            saved.timeline[0].description,
            "The Defensive Graph has the incident: 3 alerts and 3 entities."
        );
        assert_eq!(saved.timeline[0].evidence.len(), 4);
        assert_eq!(
            output.tasks[0].input,
            AgentInput::Incident(Box::new(saved.clone()))
        );
        assert!(output.actions.is_empty());
    }

    #[tokio::test]
    async fn an_incident_with_no_new_data_does_not_go_to_the_analyst_again() {
        let harness = harness();
        let context = harness.context("goal");
        let mut stored = attack_incident();
        stored.status = IncidentStatus::Contained;
        harness.incidents.save(&stored).await.unwrap();

        let mut incoming = stored.clone();
        incoming.status = IncidentStatus::Open;
        let output = monitor()
            .handle(incident_task(AgentRole::Monitor, &incoming), &context)
            .await
            .unwrap();
        assert_eq!(output, AgentOutput::default());
        let node = harness
            .graph
            .node(&NodeId::for_incident(stored.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.properties[prop::STATUS], "contained");

        incoming.detections.push(crate::support::testing::detection(
            "velocity.cross_tenant",
            aegis_contracts::Verdict::Malicious,
            fixtures::expected::CLOUD_ACCOUNT,
            vec![rogue()],
        ));
        let output = monitor()
            .handle(incident_task(AgentRole::Monitor, &incoming), &context)
            .await
            .unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.incidents.len(), 1);
        assert_eq!(output.incidents[0].detections.len(), 4);
        assert_eq!(output.incidents[0].status, IncidentStatus::Contained);
    }

    #[tokio::test]
    async fn the_analyst_gets_the_incident_when_the_graph_write_fails() {
        struct BrokenGraph;

        #[async_trait]
        impl DefensiveGraph for BrokenGraph {
            async fn upsert_node(&self, _: aegis_contracts::GraphNode) -> Result<()> {
                Err(aegis_contracts::Error::Unavailable(
                    "graph is down".to_owned(),
                ))
            }
            async fn upsert_edge(&self, _: GraphEdge) -> Result<()> {
                Err(aegis_contracts::Error::Unavailable(
                    "graph is down".to_owned(),
                ))
            }
            async fn node(&self, _: &NodeId) -> Result<Option<aegis_contracts::GraphNode>> {
                Err(aegis_contracts::Error::Unavailable(
                    "graph is down".to_owned(),
                ))
            }
            async fn neighbors(
                &self,
                _: &NodeId,
                _: Option<&str>,
                _: Direction,
            ) -> Result<Vec<aegis_contracts::GraphNode>> {
                Err(aegis_contracts::Error::Unavailable(
                    "graph is down".to_owned(),
                ))
            }
            async fn nodes_by_kind(
                &self,
                _: NodeKind,
                _: usize,
            ) -> Result<Vec<aegis_contracts::GraphNode>> {
                Err(aegis_contracts::Error::Unavailable(
                    "graph is down".to_owned(),
                ))
            }
        }

        let harness = harness();
        let mut context = harness.context("goal");
        context.graph = std::sync::Arc::new(BrokenGraph);
        let incident = attack_incident();
        let output = monitor()
            .handle(incident_task(AgentRole::Monitor, &incident), &context)
            .await
            .unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Analyst);
        assert_eq!(
            output.notes[0],
            format!(
                "The Defensive Graph did not take incident {}: unavailable: graph is down.",
                incident.id
            )
        );
        assert!(output.incidents[0].timeline.is_empty());
    }

    #[tokio::test]
    async fn without_an_analyst_the_monitor_only_writes_the_graph() {
        let harness = harness();
        let monitor = Monitor::new(MonitorConfig::default(), Roster::new([AgentRole::Monitor]));
        let incident = attack_incident();
        let output = monitor
            .handle(
                incident_task(AgentRole::Monitor, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert!(output.tasks.is_empty());
        assert_eq!(output.incidents.len(), 1);
        assert_eq!(
            output.notes,
            [format!(
                "Updated incident {} in the Defensive Graph.",
                incident.id
            )]
        );
        assert_eq!(harness.graph.node_count(), 8);
    }

    #[tokio::test]
    async fn a_successful_sign_in_links_the_identity_to_the_address() {
        let harness = harness();
        let context = harness.context("goal");
        let foothold = fixtures::artex_style_attack()
            .into_iter()
            .find(|event| {
                event.action == action::SIGN_IN
                    && event.outcome == Outcome::Success
                    && event.actor.id == fixtures::VICTIM_USER_ID
            })
            .unwrap();
        let output = monitor()
            .handle(event_task(&foothold), &context)
            .await
            .unwrap();
        assert_eq!(output, AgentOutput::default());

        let user = NodeId::for_entity(&victim());
        let address = NodeId::for_entity(&spray_ip());
        let portal = NodeId("application:app-portal".to_owned());
        let edges = harness.graph.edges();
        assert!(has_edge(
            &edges,
            &user,
            relation::AUTHENTICATED_FROM,
            &address
        ));
        assert!(has_edge(&edges, &user, relation::ACTED_ON, &portal));
        assert!(has_edge(
            &edges,
            &user,
            relation::MEMBER_OF,
            &NodeId("tenant:tenant-contoso".to_owned())
        ));
        let acted = edges
            .iter()
            .find(|edge| edge.relation == relation::ACTED_ON)
            .unwrap();
        assert_eq!(acted.properties[prop::ACTION], "sign_in");
    }

    #[tokio::test]
    async fn a_failed_sign_in_gives_nodes_but_no_relations_to_the_address_or_the_target() {
        let harness = harness();
        let failed = fixtures::artex_style_attack()
            .into_iter()
            .find(|event| event.outcome == Outcome::Failure)
            .unwrap();
        monitor()
            .handle(event_task(&failed), &harness.context("goal"))
            .await
            .unwrap();
        let edges = harness.graph.edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relation, relation::MEMBER_OF);
        assert!(
            harness
                .graph
                .node(&NodeId::for_entity(&spray_ip()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_privileged_role_assignment_marks_the_role_and_the_identity() {
        let harness = harness();
        let assignment = attack_event(action::ROLE_ASSIGN);
        monitor()
            .handle(event_task(&assignment), &harness.context("goal"))
            .await
            .unwrap();

        let principal = NodeId::for_entity(&rogue());
        let roles = harness
            .graph
            .neighbors(&principal, Some(relation::HAS_ROLE), Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].label, "Global Administrator");
        assert!(flag(&roles[0], prop::PRIVILEGED));
        let node = harness.graph.node(&principal).await.unwrap().unwrap();
        assert_eq!(
            node.properties[prop::PRIVILEGED_ROLES],
            json!(["Global Administrator"])
        );
        assert!(flag(&node, prop::PRIVILEGED_ROLE_SELF_ASSIGNED));
        assert_eq!(
            node.properties[prop::PRIVILEGED_ROLE_ASSIGNED_AT],
            json!(assignment.time)
        );
        assert_eq!(node.label, "Sync Helper");
        // The actor is the target, so the graph has no relation from the node to itself.
        assert!(
            harness
                .graph
                .edges()
                .iter()
                .all(|edge| edge.from != edge.to)
        );
    }

    #[tokio::test]
    async fn a_honeytoken_trip_goes_to_the_deception_agent() {
        let harness = harness();
        let trip = attack_event(action::HONEYTOKEN_TRIP);
        let output = monitor()
            .handle(event_task(&trip), &harness.context("goal"))
            .await
            .unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Deception);
        assert_eq!(
            output.tasks[0].input,
            AgentInput::Event(Box::new(trip.clone()))
        );
        assert_eq!(
            output.notes,
            [format!(
                "Event {} is a honeytoken trip. The deception agent gets the event.",
                trip.id
            )]
        );
        let secret = NodeId("secret:kv-prod/legacy-admin-password".to_owned());
        assert!(has_edge(
            &harness.graph.edges(),
            &NodeId::for_entity(&rogue()),
            relation::ACTED_ON,
            &secret
        ));
    }

    #[tokio::test]
    async fn a_detection_becomes_an_alert_that_is_part_of_a_known_incident() {
        let harness = harness();
        let context = harness.context("goal");
        let incident = attack_incident();
        let detection = incident.detections[2].clone();
        let task = AgentTask::new(
            AgentRole::Monitor,
            AgentInput::Detection(Box::new(detection.clone())),
        )
        .for_incident(incident.id);

        monitor().handle(task.clone(), &context).await.unwrap();
        let alert = NodeId::for_detection(detection.id);
        assert!(harness.graph.node(&alert).await.unwrap().is_some());
        assert_eq!(
            harness
                .graph
                .edges()
                .iter()
                .filter(|edge| edge.relation == relation::PART_OF)
                .count(),
            0
        );

        sync_incident_node(harness.graph.as_ref(), &incident)
            .await
            .unwrap();
        monitor().handle(task, &context).await.unwrap();
        assert!(has_edge(
            &harness.graph.edges(),
            &alert,
            relation::PART_OF,
            &NodeId::for_incident(incident.id)
        ));
    }

    #[tokio::test]
    async fn a_sweep_gives_each_open_incident_to_the_analyst() {
        let harness = harness();
        let context = harness.context("goal");
        let tick = AgentTask::new(AgentRole::Monitor, AgentInput::Tick);
        assert_eq!(
            monitor().handle(tick.clone(), &context).await.unwrap(),
            AgentOutput::default()
        );

        let open = suspicious_incident();
        let mut contained = attack_incident();
        contained.status = IncidentStatus::Contained;
        harness.incidents.save(&open).await.unwrap();
        harness.incidents.save(&contained).await.unwrap();
        let output = monitor().handle(tick, &context).await.unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Analyst);
        assert_eq!(output.tasks[0].incident_id, Some(open.id));
        assert_eq!(
            output.notes,
            ["The sweep found 1 open incidents. The analyst gets them."]
        );
    }
}
