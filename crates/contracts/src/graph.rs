//! The Defensive Graph and the vector store.
//!
//! The Defensive Graph is the shared state of the agents. It holds assets, identities,
//! alerts, findings, incidents, and the relations between them.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{DetectionId, EntityKind, EntityRef, IncidentId};
use crate::error::Result;

/// Normalized values for [`GraphEdge::relation`].
pub mod relation {
    /// An incident or an alert involves an entity.
    pub const INVOLVES: &str = "involves";
    /// An alert is part of an incident.
    pub const PART_OF: &str = "part_of";
    /// An identity did an operation on an entity.
    pub const ACTED_ON: &str = "acted_on";
    /// An identity has a role.
    pub const HAS_ROLE: &str = "has_role";
    /// An identity owns an entity.
    pub const OWNS: &str = "owns";
    /// An identity authenticated from an IP address.
    pub const AUTHENTICATED_FROM: &str = "authenticated_from";
    /// An entity is in a tenant.
    pub const MEMBER_OF: &str = "member_of";
    /// A response action changed an entity.
    pub const CONTAINED_BY: &str = "contained_by";
}

/// The type of a node in the Defensive Graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// A host, a device, an address, a secret, or a different resource of the operator.
    Asset,
    /// A user, a service principal, or an application.
    Identity,
    /// A detection.
    Alert,
    /// A result of a threat hunt or an exposure check.
    Finding,
    /// An incident.
    Incident,
}

impl From<EntityKind> for NodeKind {
    fn from(kind: EntityKind) -> Self {
        match kind {
            EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application => {
                Self::Identity
            }
            EntityKind::Device
            | EntityKind::Host
            | EntityKind::IpAddress
            | EntityKind::Domain
            | EntityKind::Tenant
            | EntityKind::Session
            | EntityKind::Secret
            | EntityKind::Role
            | EntityKind::Resource
            | EntityKind::Other => Self::Asset,
        }
    }
}

/// The identifier of a node. All subsystems must make identifiers with the functions of
/// this type, so that they address the same node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub String);

impl NodeId {
    /// Returns the identifier of the node for an entity.
    #[must_use]
    pub fn for_entity(entity: &EntityRef) -> Self {
        let kind = serde_json::to_value(entity.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "other".to_owned());
        Self(format!("{kind}:{}", entity.id))
    }

    /// Returns the identifier of the node for an incident.
    #[must_use]
    pub fn for_incident(id: IncidentId) -> Self {
        Self(format!("incident:{id}"))
    }

    /// Returns the identifier of the node for a detection.
    #[must_use]
    pub fn for_detection(id: DetectionId) -> Self {
        Self(format!("alert:{id}"))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One node in the Defensive Graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    /// The identifier of the node.
    pub id: NodeId,
    /// The type of the node.
    pub kind: NodeKind,
    /// The display name of the node.
    pub label: String,
    /// More data about the node.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, serde_json::Value>,
    /// The time of the last change.
    pub updated_at: DateTime<Utc>,
}

impl GraphNode {
    /// Makes the node for an entity. The time of the last change is the present time.
    #[must_use]
    pub fn from_entity(entity: &EntityRef) -> Self {
        let mut properties = BTreeMap::new();
        if let Ok(kind) = serde_json::to_value(entity.kind) {
            properties.insert("entity_kind".to_owned(), kind);
        }
        if let Some(tenant) = &entity.tenant {
            properties.insert("tenant".to_owned(), tenant.clone().into());
        }
        Self {
            id: NodeId::for_entity(entity),
            kind: entity.kind.into(),
            label: entity.name.clone().unwrap_or_else(|| entity.id.clone()),
            properties,
            updated_at: Utc::now(),
        }
    }
}

/// One directed relation between two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    /// The node at the start of the relation.
    pub from: NodeId,
    /// The node at the end of the relation.
    pub to: NodeId,
    /// The name of the relation. Refer to the [`relation`] module.
    pub relation: String,
    /// More data about the relation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, serde_json::Value>,
}

impl GraphEdge {
    /// Makes a relation with no properties.
    pub fn new(from: NodeId, relation: impl Into<String>, to: NodeId) -> Self {
        Self {
            from,
            to,
            relation: relation.into(),
            properties: BTreeMap::new(),
        }
    }
}

/// The direction in which a graph query follows relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Follow relations that start at the node.
    Outgoing,
    /// Follow relations that end at the node.
    Incoming,
    /// Follow relations in the two directions.
    Both,
}

/// The shared graph state of the agents.
#[async_trait]
pub trait DefensiveGraph: Send + Sync {
    /// Writes a node. A node with the same identifier is replaced.
    async fn upsert_node(&self, node: GraphNode) -> Result<()>;

    /// Writes a relation. A relation with the same start, end, and name is replaced.
    ///
    /// An implementation must return an error if the start node or the end node does not
    /// exist.
    async fn upsert_edge(&self, edge: GraphEdge) -> Result<()>;

    /// Reads one node.
    async fn node(&self, id: &NodeId) -> Result<Option<GraphNode>>;

    /// Lists the nodes that have a relation with the node `id`.
    ///
    /// With a relation name, the query follows only relations with that name.
    async fn neighbors(
        &self,
        id: &NodeId,
        relation: Option<&str>,
        direction: Direction,
    ) -> Result<Vec<GraphNode>>;

    /// Lists nodes of one type, newest first.
    async fn nodes_by_kind(&self, kind: NodeKind, limit: usize) -> Result<Vec<GraphNode>>;
}

/// One text with its embedding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VectorRecord {
    /// The identifier of the record.
    pub id: String,
    /// The embedding of the text.
    pub embedding: Vec<f32>,
    /// The text.
    pub text: String,
    /// More data about the record.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// One result of a vector search.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VectorMatch {
    /// The record that the search found.
    pub record: VectorRecord,
    /// The cosine similarity between the query and the record. A larger value is nearer.
    pub score: f32,
}

/// A store for embeddings.
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Writes a record to a collection. A record with the same identifier is replaced.
    async fn upsert(&self, collection: &str, record: VectorRecord) -> Result<()>;

    /// Finds the records in a collection that are nearest to `embedding`, nearest first.
    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorMatch>>;
}
