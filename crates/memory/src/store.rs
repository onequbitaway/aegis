use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use aegis_contracts::common::IncidentId;
use aegis_contracts::graph::{
    DefensiveGraph, Direction, GraphEdge, GraphNode, NodeId, NodeKind, VectorMatch, VectorRecord,
    VectorStore,
};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;

use crate::lock;

#[derive(Default)]
struct GraphState {
    nodes: BTreeMap<NodeId, GraphNode>,
    edges: Vec<GraphEdge>,
}

/// A Defensive Graph that keeps all nodes and relations in memory.
#[derive(Default)]
pub struct MemoryGraph {
    state: Mutex<GraphState>,
}

impl MemoryGraph {
    /// Returns all relations, in the order in which the graph first received them.
    #[must_use]
    pub fn edges(&self) -> Vec<GraphEdge> {
        lock(&self.state).edges.clone()
    }

    /// Returns the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        lock(&self.state).nodes.len()
    }
}

#[async_trait]
impl DefensiveGraph for MemoryGraph {
    async fn upsert_node(&self, node: GraphNode) -> Result<()> {
        lock(&self.state).nodes.insert(node.id.clone(), node);
        Ok(())
    }

    async fn upsert_edge(&self, edge: GraphEdge) -> Result<()> {
        let mut state = lock(&self.state);
        for id in [&edge.from, &edge.to] {
            if !state.nodes.contains_key(id) {
                return Err(Error::NotFound(format!("graph node {id}")));
            }
        }
        let existing = state.edges.iter_mut().find(|candidate| {
            candidate.from == edge.from
                && candidate.to == edge.to
                && candidate.relation == edge.relation
        });
        match existing {
            Some(candidate) => *candidate = edge,
            None => state.edges.push(edge),
        }
        Ok(())
    }

    async fn node(&self, id: &NodeId) -> Result<Option<GraphNode>> {
        Ok(lock(&self.state).nodes.get(id).cloned())
    }

    async fn neighbors(
        &self,
        id: &NodeId,
        relation: Option<&str>,
        direction: Direction,
    ) -> Result<Vec<GraphNode>> {
        let state = lock(&self.state);
        let mut neighbor_ids: Vec<&NodeId> = Vec::new();
        for edge in &state.edges {
            if relation.is_some_and(|name| name != edge.relation) {
                continue;
            }
            let outgoing = matches!(direction, Direction::Outgoing | Direction::Both);
            let incoming = matches!(direction, Direction::Incoming | Direction::Both);
            if outgoing && &edge.from == id && !neighbor_ids.contains(&&edge.to) {
                neighbor_ids.push(&edge.to);
            }
            if incoming && &edge.to == id && !neighbor_ids.contains(&&edge.from) {
                neighbor_ids.push(&edge.from);
            }
        }
        Ok(neighbor_ids
            .into_iter()
            .filter_map(|neighbor| state.nodes.get(neighbor).cloned())
            .collect())
    }

    async fn nodes_by_kind(&self, kind: NodeKind, limit: usize) -> Result<Vec<GraphNode>> {
        let mut nodes: Vec<GraphNode> = lock(&self.state)
            .nodes
            .values()
            .filter(|node| node.kind == kind)
            .cloned()
            .collect();
        nodes.sort_by_key(|node| std::cmp::Reverse(node.updated_at));
        nodes.truncate(limit);
        Ok(nodes)
    }
}

/// A vector store that keeps all records in memory and searches by cosine similarity.
#[derive(Default)]
pub struct MemoryVectors {
    collections: Mutex<HashMap<String, BTreeMap<String, VectorRecord>>>,
}

fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let dot: f32 = left.iter().zip(right).map(|(a, b)| a * b).sum();
    let norm = |vector: &[f32]| vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    let scale = norm(left) * norm(right);
    if scale > 0.0 { dot / scale } else { 0.0 }
}

#[async_trait]
impl VectorStore for MemoryVectors {
    async fn upsert(&self, collection: &str, record: VectorRecord) -> Result<()> {
        if record.embedding.is_empty() {
            return Err(Error::InvalidInput(format!(
                "vector record {} has an empty embedding",
                record.id
            )));
        }
        lock(&self.collections)
            .entry(collection.to_owned())
            .or_default()
            .insert(record.id.clone(), record);
        Ok(())
    }

    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorMatch>> {
        let collections = lock(&self.collections);
        let Some(records) = collections.get(collection) else {
            return Ok(Vec::new());
        };
        if let Some(record) = records
            .values()
            .find(|record| record.embedding.len() != embedding.len())
        {
            return Err(Error::InvalidInput(format!(
                "the query has {} dimensions, but record {} has {}",
                embedding.len(),
                record.id,
                record.embedding.len()
            )));
        }
        let mut matches: Vec<VectorMatch> = records
            .values()
            .map(|record| VectorMatch {
                score: cosine(embedding, &record.embedding),
                record: record.clone(),
            })
            .collect();
        matches.sort_by(|left, right| right.score.total_cmp(&left.score));
        matches.truncate(limit);
        Ok(matches)
    }
}

/// An incident store that keeps all incidents in memory.
#[derive(Default)]
pub struct MemoryIncidents {
    incidents: Mutex<BTreeMap<IncidentId, Incident>>,
}

#[async_trait]
impl IncidentStore for MemoryIncidents {
    async fn save(&self, incident: &Incident) -> Result<()> {
        lock(&self.incidents).insert(incident.id, incident.clone());
        Ok(())
    }

    async fn get(&self, id: IncidentId) -> Result<Option<Incident>> {
        Ok(lock(&self.incidents).get(&id).cloned())
    }

    async fn list(&self, status: Option<IncidentStatus>, limit: usize) -> Result<Vec<Incident>> {
        let mut incidents: Vec<Incident> = lock(&self.incidents)
            .values()
            .filter(|incident| status.is_none_or(|wanted| incident.status == wanted))
            .cloned()
            .collect();
        incidents.sort_by_key(|incident| std::cmp::Reverse(incident.created_at));
        incidents.truncate(limit);
        Ok(incidents)
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::{EntityKind, EntityRef, Severity};
    use aegis_contracts::graph::relation;
    use chrono::{Duration, Utc};

    use super::*;

    fn entity_node(kind: EntityKind, id: &str, age_seconds: i64) -> GraphNode {
        let mut node = GraphNode::from_entity(&EntityRef::new(kind, id));
        node.updated_at = Utc::now() - Duration::seconds(age_seconds);
        node
    }

    async fn sample_graph() -> (MemoryGraph, NodeId, NodeId, NodeId) {
        let graph = MemoryGraph::default();
        let user = entity_node(EntityKind::User, "user-1", 30);
        let app = entity_node(EntityKind::ServicePrincipal, "sp-1", 10);
        let role = entity_node(EntityKind::Role, "global-admin", 20);
        let ids = (user.id.clone(), app.id.clone(), role.id.clone());
        for node in [user, app, role] {
            graph.upsert_node(node).await.unwrap();
        }
        graph
            .upsert_edge(GraphEdge::new(ids.0.clone(), relation::OWNS, ids.1.clone()))
            .await
            .unwrap();
        graph
            .upsert_edge(GraphEdge::new(
                ids.1.clone(),
                relation::HAS_ROLE,
                ids.2.clone(),
            ))
            .await
            .unwrap();
        (graph, ids.0, ids.1, ids.2)
    }

    fn labels(nodes: &[GraphNode]) -> Vec<&str> {
        nodes.iter().map(|node| node.label.as_str()).collect()
    }

    #[tokio::test]
    async fn neighbors_follow_the_direction_and_the_relation() {
        let (graph, user, app, role) = sample_graph().await;
        let outgoing = graph
            .neighbors(&app, None, Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(labels(&outgoing), ["global-admin"]);
        let incoming = graph
            .neighbors(&app, None, Direction::Incoming)
            .await
            .unwrap();
        assert_eq!(labels(&incoming), ["user-1"]);
        let both = graph.neighbors(&app, None, Direction::Both).await.unwrap();
        assert_eq!(both.len(), 2);
        let filtered = graph
            .neighbors(&app, Some(relation::OWNS), Direction::Both)
            .await
            .unwrap();
        assert_eq!(labels(&filtered), ["user-1"]);
        assert!(
            graph
                .neighbors(&user, None, Direction::Incoming)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            graph.node(&role).await.unwrap().map(|node| node.kind),
            Some(NodeKind::Asset)
        );
    }

    #[tokio::test]
    async fn an_edge_to_a_missing_node_is_rejected() {
        let (graph, user, _, _) = sample_graph().await;
        let missing = NodeId("host:absent".to_owned());
        let error = graph
            .upsert_edge(GraphEdge::new(user, relation::ACTED_ON, missing))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::NotFound(message) if message.contains("host:absent")));
        assert_eq!(graph.edges().len(), 2);
    }

    #[tokio::test]
    async fn the_same_edge_and_node_are_replaced_and_not_duplicated() {
        let (graph, user, app, _) = sample_graph().await;
        let mut edge = GraphEdge::new(user.clone(), relation::OWNS, app);
        edge.properties.insert("since".to_owned(), "2026".into());
        graph.upsert_edge(edge.clone()).await.unwrap();
        assert_eq!(graph.edges().len(), 2);
        assert_eq!(graph.edges()[0], edge);

        let mut renamed = entity_node(EntityKind::User, "user-1", 0);
        renamed.label = "Alice".to_owned();
        graph.upsert_node(renamed).await.unwrap();
        assert_eq!(graph.node_count(), 3);
        assert_eq!(
            graph.node(&user).await.unwrap().map(|node| node.label),
            Some("Alice".to_owned())
        );
    }

    #[tokio::test]
    async fn nodes_by_kind_lists_newest_first_up_to_the_limit() {
        let (graph, _, _, _) = sample_graph().await;
        let identities = graph.nodes_by_kind(NodeKind::Identity, 10).await.unwrap();
        assert_eq!(labels(&identities), ["sp-1", "user-1"]);
        let limited = graph.nodes_by_kind(NodeKind::Identity, 1).await.unwrap();
        assert_eq!(labels(&limited), ["sp-1"]);
        assert!(
            graph
                .nodes_by_kind(NodeKind::Incident, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn vector_search_returns_the_nearest_records_first() {
        let store = MemoryVectors::default();
        for (id, embedding) in [
            ("east", vec![1.0, 0.0, 0.0]),
            ("north", vec![0.0, 1.0, 0.0]),
            ("north_east", vec![1.0, 1.0, 0.0]),
        ] {
            let record = VectorRecord {
                id: id.to_owned(),
                embedding,
                text: id.to_owned(),
                metadata: serde_json::Value::Null,
            };
            store.upsert("notes", record).await.unwrap();
        }
        let matches = store.search("notes", &[2.0, 0.1, 0.0], 2).await.unwrap();
        let ids: Vec<&str> = matches
            .iter()
            .map(|found| found.record.id.as_str())
            .collect();
        assert_eq!(ids, ["east", "north_east"]);
        assert!(matches[0].score > matches[1].score);
        assert!(
            (matches[0].score - 0.998_752).abs() < 1e-4,
            "{}",
            matches[0].score
        );
        assert!(
            store
                .search("absent", &[1.0, 0.0, 0.0], 2)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn vector_store_rejects_empty_and_mismatched_embeddings() {
        let store = MemoryVectors::default();
        let record = |embedding: Vec<f32>| VectorRecord {
            id: "a".to_owned(),
            embedding,
            text: String::new(),
            metadata: serde_json::Value::Null,
        };
        let empty = store.upsert("notes", record(Vec::new())).await.unwrap_err();
        assert!(matches!(empty, Error::InvalidInput(_)));
        store.upsert("notes", record(vec![1.0, 0.0])).await.unwrap();
        let mismatch = store
            .search("notes", &[1.0, 0.0, 0.0], 1)
            .await
            .unwrap_err();
        assert!(matches!(mismatch, Error::InvalidInput(message) if message.contains('3')));
    }

    #[tokio::test]
    async fn incidents_list_newest_first_with_an_optional_status_filter() {
        let store = MemoryIncidents::default();
        let incident = |title: &str, status: IncidentStatus, age_seconds: i64| Incident {
            id: IncidentId::new(),
            title: title.to_owned(),
            summary: String::new(),
            severity: Severity::High,
            status,
            created_at: Utc::now() - Duration::seconds(age_seconds),
            updated_at: Utc::now(),
            tenant: None,
            detections: Vec::new(),
            entities: Vec::new(),
            attack: Vec::new(),
            timeline: Vec::new(),
        };
        let old = incident("old", IncidentStatus::Open, 300);
        let contained = incident("contained", IncidentStatus::Contained, 200);
        let new = incident("new", IncidentStatus::Open, 100);
        for item in [&old, &contained, &new] {
            store.save(item).await.unwrap();
        }
        let titles = |incidents: Vec<Incident>| -> Vec<String> {
            incidents.into_iter().map(|item| item.title).collect()
        };
        assert_eq!(
            titles(store.list(None, 10).await.unwrap()),
            ["new", "contained", "old"]
        );
        assert_eq!(
            titles(store.list(Some(IncidentStatus::Open), 10).await.unwrap()),
            ["new", "old"]
        );
        assert_eq!(titles(store.list(None, 1).await.unwrap()), ["new"]);

        let mut changed = old.clone();
        changed.status = IncidentStatus::Resolved;
        store.save(&changed).await.unwrap();
        assert_eq!(store.get(old.id).await.unwrap(), Some(changed));
        assert_eq!(store.get(IncidentId::new()).await.unwrap(), None);
        assert_eq!(store.list(None, 10).await.unwrap().len(), 3);
    }
}
