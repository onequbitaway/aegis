//! Helpers for writes to the Defensive Graph, and the property names that the agents use.

use std::collections::BTreeMap;

use aegis_contracts::Result;
use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::detection::Detection;
use aegis_contracts::graph::{DefensiveGraph, GraphEdge, GraphNode, NodeId, NodeKind, relation};
use aegis_contracts::incident::Incident;
use chrono::Utc;
use serde_json::{Value, json};

use crate::support::token;

/// The property names that the agents read and write on graph nodes.
///
/// An inventory connector that writes asset nodes must use the names
/// [`INTERNET_EXPOSED`](prop::INTERNET_EXPOSED) and [`OPEN_PORTS`](prop::OPEN_PORTS), so
/// that the Hunter can review the external exposure of the assets.
pub mod prop {
    /// The entity type of a node for an entity, for example `service_principal`.
    pub const ENTITY_KIND: &str = "entity_kind";
    /// The tenant of the node.
    pub const TENANT: &str = "tenant";
    /// The severity of an incident node or an alert node.
    pub const SEVERITY: &str = "severity";
    /// The state of an incident node.
    pub const STATUS: &str = "status";
    /// The number of detections of an incident node.
    pub const DETECTION_COUNT: &str = "detection_count";
    /// The rule of an alert node.
    pub const RULE_ID: &str = "rule_id";
    /// The verdict of an alert node.
    pub const VERDICT: &str = "verdict";
    /// The time of an alert node, or the time of a relation.
    pub const TIME: &str = "time";
    /// The ATT&CK technique identifiers of an alert node, as an array of strings.
    pub const TECHNIQUES: &str = "techniques";
    /// `true` on a role node if the role gives privileged access.
    pub const PRIVILEGED: &str = "privileged";
    /// The names of the privileged roles of an identity node, as an array of strings.
    pub const PRIVILEGED_ROLES: &str = "privileged_roles";
    /// The time of the last privileged role assignment of an identity node.
    pub const PRIVILEGED_ROLE_ASSIGNED_AT: &str = "privileged_role_assigned_at";
    /// `true` on an identity node if the identity assigned a privileged role to itself.
    pub const PRIVILEGED_ROLE_SELF_ASSIGNED: &str = "privileged_role_self_assigned";
    /// `true` on an asset node if the inventory says that the internet can reach the asset.
    pub const INTERNET_EXPOSED: &str = "internet_exposed";
    /// The open ports of an asset node from the inventory, as an array of numbers.
    pub const OPEN_PORTS: &str = "open_ports";
    /// `true` on an asset node that is a honeytoken.
    pub const HONEYTOKEN: &str = "honeytoken";
    /// The state of a honeytoken node, for example `proposed` or `succeeded`.
    pub const HONEYTOKEN_STATE: &str = "honeytoken_state";
    /// The identifier of the action that deploys a honeytoken node.
    pub const HONEYTOKEN_ACTION_ID: &str = "honeytoken_action_id";
    /// The time of the last use of a honeytoken node.
    pub const HONEYTOKEN_TRIPPED_AT: &str = "honeytoken_tripped_at";
    /// The node identifier of the identity that last used a honeytoken node.
    pub const HONEYTOKEN_TRIPPED_BY: &str = "honeytoken_tripped_by";
    /// The name of the hunt that made a finding node.
    pub const HUNT: &str = "hunt";
    /// The explanation of a finding node.
    pub const DESCRIPTION: &str = "description";
    /// The origin of a finding node: `deterministic` or `model`.
    pub const SOURCE: &str = "source";
    /// The incident of a finding node, a honeytoken node, or a relation.
    pub const INCIDENT_ID: &str = "incident_id";
    /// The operation of an `acted_on` relation, for example `secret.read`.
    pub const ACTION: &str = "action";
    /// The action type of a `contained_by` relation.
    pub const ACTION_KIND: &str = "action_kind";
    /// The action identifier of a `contained_by` relation.
    pub const ACTION_ID: &str = "action_id";
}

/// Writes `node`. Properties of an existing node that `node` does not have stay.
///
/// The contract replaces a node on each write. This function reads the node first, so
/// that data from a different agent or from an inventory connector is not lost.
pub(crate) async fn upsert_merged(graph: &dyn DefensiveGraph, mut node: GraphNode) -> Result<()> {
    if let Some(existing) = graph.node(&node.id).await? {
        for (key, value) in existing.properties {
            node.properties.entry(key).or_insert(value);
        }
    }
    graph.upsert_node(node).await
}

/// Writes the node for an entity and returns its identifier.
///
/// An existing node keeps its properties. It keeps its label if `entity` has no name.
pub(crate) async fn upsert_entity(
    graph: &dyn DefensiveGraph,
    entity: &EntityRef,
) -> Result<NodeId> {
    let mut node = GraphNode::from_entity(entity);
    let id = node.id.clone();
    if let Some(existing) = graph.node(&id).await? {
        if entity.name.is_none() {
            node.label = existing.label;
        }
        for (key, value) in existing.properties {
            node.properties.entry(key).or_insert(value);
        }
    }
    graph.upsert_node(node).await?;
    Ok(id)
}

/// Writes the node for an entity with more properties and returns its identifier.
pub(crate) async fn upsert_entity_with(
    graph: &dyn DefensiveGraph,
    entity: &EntityRef,
    properties: BTreeMap<String, Value>,
) -> Result<NodeId> {
    let id = upsert_entity(graph, entity).await?;
    if !properties.is_empty()
        && let Some(mut node) = graph.node(&id).await?
    {
        node.properties.extend(properties);
        node.updated_at = Utc::now();
        graph.upsert_node(node).await?;
    }
    Ok(id)
}

/// Writes one relation.
pub(crate) async fn link(
    graph: &dyn DefensiveGraph,
    from: &NodeId,
    relation: &str,
    to: &NodeId,
    properties: BTreeMap<String, Value>,
) -> Result<()> {
    let mut edge = GraphEdge::new(from.clone(), relation, to.clone());
    edge.properties = properties;
    graph.upsert_edge(edge).await
}

/// Writes the node of the tenant `tenant` and the `member_of` relation from `member`.
pub(crate) async fn link_tenant(
    graph: &dyn DefensiveGraph,
    member: &NodeId,
    tenant: &str,
) -> Result<()> {
    let tenant_node = upsert_entity(graph, &EntityRef::new(EntityKind::Tenant, tenant)).await?;
    if &tenant_node != member {
        link(
            graph,
            member,
            relation::MEMBER_OF,
            &tenant_node,
            BTreeMap::new(),
        )
        .await?;
    }
    Ok(())
}

/// Makes the node for an incident.
pub(crate) fn incident_node(incident: &Incident) -> GraphNode {
    let mut properties = BTreeMap::new();
    properties.insert(prop::SEVERITY.to_owned(), json!(incident.severity));
    properties.insert(prop::STATUS.to_owned(), json!(incident.status));
    properties.insert(
        prop::DETECTION_COUNT.to_owned(),
        json!(incident.detections.len()),
    );
    if let Some(tenant) = &incident.tenant {
        properties.insert(prop::TENANT.to_owned(), json!(tenant));
    }
    GraphNode {
        id: NodeId::for_incident(incident.id),
        kind: NodeKind::Incident,
        label: incident.title.clone(),
        properties,
        updated_at: Utc::now(),
    }
}

/// Makes the node for a detection.
pub(crate) fn alert_node(detection: &Detection) -> GraphNode {
    let mut properties = BTreeMap::new();
    properties.insert(prop::RULE_ID.to_owned(), json!(detection.rule_id));
    properties.insert(prop::SEVERITY.to_owned(), json!(detection.severity));
    properties.insert(prop::VERDICT.to_owned(), json!(detection.verdict));
    properties.insert(prop::TIME.to_owned(), json!(detection.time));
    properties.insert(
        prop::TECHNIQUES.to_owned(),
        json!(
            detection
                .attack
                .iter()
                .map(|technique| technique.technique_id.as_str())
                .collect::<Vec<_>>()
        ),
    );
    if let Some(tenant) = &detection.tenant {
        properties.insert(prop::TENANT.to_owned(), json!(tenant));
    }
    GraphNode {
        id: NodeId::for_detection(detection.id),
        kind: NodeKind::Alert,
        label: detection.title.clone(),
        properties,
        updated_at: Utc::now(),
    }
}

/// Writes the node of an incident with its present severity and state.
pub(crate) async fn sync_incident_node(
    graph: &dyn DefensiveGraph,
    incident: &Incident,
) -> Result<NodeId> {
    let node = incident_node(incident);
    let id = node.id.clone();
    upsert_merged(graph, node).await?;
    Ok(id)
}

/// Returns the entity type of a node for an entity, for example `tenant`.
pub(crate) fn entity_kind_of(node: &GraphNode) -> Option<&str> {
    node.properties
        .get(prop::ENTITY_KIND)
        .and_then(Value::as_str)
}

/// Returns `true` if the node is for an entity of the type `kind`.
pub(crate) fn is_entity_kind(node: &GraphNode, kind: EntityKind) -> bool {
    entity_kind_of(node) == Some(token(&kind).as_str())
}

/// Returns `true` if the property `key` of the node is `true`.
pub(crate) fn flag(node: &GraphNode, key: &str) -> bool {
    node.properties.get(key).and_then(Value::as_bool) == Some(true)
}

#[cfg(test)]
mod tests {
    use aegis_contracts::graph::Direction;
    use aegis_testkit::MemoryGraph;

    use super::*;
    use crate::support::testing::{attack_incident, rogue};

    #[tokio::test]
    async fn an_entity_write_keeps_the_properties_and_the_label_of_the_node() {
        let graph = MemoryGraph::default();
        let inventory = BTreeMap::from([(prop::INTERNET_EXPOSED.to_owned(), json!(true))]);
        let id = upsert_entity_with(&graph, &rogue(), inventory)
            .await
            .unwrap();
        assert_eq!(id, NodeId("service_principal:sp-sync-helper".to_owned()));

        let unnamed = EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper");
        upsert_entity(&graph, &unnamed).await.unwrap();
        let node = graph.node(&id).await.unwrap().unwrap();
        assert_eq!(node.label, "Sync Helper");
        assert!(flag(&node, prop::INTERNET_EXPOSED));
        assert!(is_entity_kind(&node, EntityKind::ServicePrincipal));
        assert!(!is_entity_kind(&node, EntityKind::User));
        assert_eq!(node.properties[prop::TENANT], "tenant-contoso");
        assert_eq!(graph.node_count(), 1);
    }

    #[tokio::test]
    async fn a_merged_write_lets_new_values_replace_old_values() {
        let graph = MemoryGraph::default();
        let mut incident = attack_incident();
        let id = sync_incident_node(&graph, &incident).await.unwrap();
        let mut marked = graph.node(&id).await.unwrap().unwrap();
        marked.properties.insert("owner".to_owned(), json!("soc"));
        graph.upsert_node(marked).await.unwrap();

        incident.status = aegis_contracts::IncidentStatus::Contained;
        sync_incident_node(&graph, &incident).await.unwrap();
        let node = graph.node(&id).await.unwrap().unwrap();
        assert_eq!(node.kind, NodeKind::Incident);
        assert_eq!(node.properties[prop::STATUS], "contained");
        assert_eq!(node.properties[prop::SEVERITY], "critical");
        assert_eq!(node.properties[prop::DETECTION_COUNT], 3);
        assert_eq!(node.properties["owner"], "soc");
    }

    #[tokio::test]
    async fn the_tenant_link_makes_the_tenant_node_and_one_relation() {
        let graph = MemoryGraph::default();
        let member = upsert_entity(&graph, &rogue()).await.unwrap();
        link_tenant(&graph, &member, "tenant-contoso")
            .await
            .unwrap();
        link_tenant(&graph, &member, "tenant-contoso")
            .await
            .unwrap();
        let tenants = graph
            .neighbors(&member, Some(relation::MEMBER_OF), Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].id, NodeId("tenant:tenant-contoso".to_owned()));
        assert_eq!(graph.edges().len(), 1);

        link_tenant(&graph, &tenants[0].id, "tenant-contoso")
            .await
            .unwrap();
        assert_eq!(graph.edges().len(), 1);
    }

    #[test]
    fn an_alert_node_has_the_rule_and_the_techniques() {
        let incident = attack_incident();
        let node = alert_node(&incident.detections[0]);
        assert_eq!(node.id, NodeId::for_detection(incident.detections[0].id));
        assert_eq!(node.kind, NodeKind::Alert);
        assert_eq!(node.properties[prop::RULE_ID], "velocity.sign_in_burst");
        assert_eq!(node.properties[prop::VERDICT], "malicious");
        assert_eq!(node.properties[prop::TECHNIQUES], json!(["T1110.003"]));
    }
}
