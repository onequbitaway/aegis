//! Read-only tools that a model can call in a tool loop.
//!
//! The tools read the Defensive Graph and the incident store of AEGIS. They do not change
//! data. They do not connect to a system of the operator or to a different system.

use std::sync::Arc;

use aegis_contracts::graph::{DefensiveGraph, Direction, GraphNode, NodeId, NodeKind};
use aegis_contracts::incident::{IncidentStatus, IncidentStore};
use aegis_contracts::model::ToolSpec;
use aegis_contracts::{AgentContext, Error, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::llm::ToolSet;

/// The maximum number of records that one tool call returns.
pub const MAX_TOOL_RECORDS: usize = 50;

/// The name of the tool that reads one graph node.
pub const GRAPH_NODE: &str = "graph_node";
/// The name of the tool that lists the neighbors of a graph node.
pub const GRAPH_NEIGHBORS: &str = "graph_neighbors";
/// The name of the tool that lists graph nodes of one type.
pub const GRAPH_NODES_BY_KIND: &str = "graph_nodes_by_kind";
/// The name of the tool that lists incidents.
pub const LIST_INCIDENTS: &str = "list_incidents";

/// Read-only tools for the Defensive Graph and the incident store.
#[derive(Clone)]
pub struct GraphTools {
    graph: Arc<dyn DefensiveGraph>,
    incidents: Arc<dyn IncidentStore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeArguments {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeighborArguments {
    id: String,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    direction: Option<Direction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KindArguments {
    kind: NodeKind,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncidentArguments {
    #[serde(default)]
    status: Option<IncidentStatus>,
    #[serde(default)]
    limit: Option<usize>,
}

fn arguments<T: DeserializeOwned>(tool: &str, value: &Value) -> Result<T> {
    serde_json::from_value(value.clone())
        .map_err(|error| Error::InvalidInput(format!("arguments of {tool}: {error}")))
}

fn limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(MAX_TOOL_RECORDS)
        .clamp(1, MAX_TOOL_RECORDS)
}

fn node_view(node: &GraphNode) -> Value {
    json!({
        "id": node.id,
        "kind": node.kind,
        "label": node.label,
        "properties": node.properties,
    })
}

impl GraphTools {
    /// Makes the tools for the graph and the incident store of `context`.
    #[must_use]
    pub fn new(context: &AgentContext) -> Self {
        Self {
            graph: context.graph.clone(),
            incidents: context.incidents.clone(),
        }
    }
}

#[async_trait]
impl ToolSet for GraphTools {
    fn specs(&self) -> Vec<ToolSpec> {
        let node_kinds = json!(["asset", "identity", "alert", "finding", "incident"]);
        vec![
            ToolSpec {
                name: GRAPH_NODE.to_owned(),
                description: "Reads one node of the Defensive Graph.".to_owned(),
                parameters: json!({
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"],
                    "additionalProperties": false
                }),
            },
            ToolSpec {
                name: GRAPH_NEIGHBORS.to_owned(),
                description: "Lists the nodes that have a relation with one node.".to_owned(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "relation": { "type": "string" },
                        "direction": { "enum": ["outgoing", "incoming", "both"] }
                    },
                    "required": ["id"],
                    "additionalProperties": false
                }),
            },
            ToolSpec {
                name: GRAPH_NODES_BY_KIND.to_owned(),
                description: "Lists nodes of one type, newest first.".to_owned(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "kind": { "enum": node_kinds },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_TOOL_RECORDS }
                    },
                    "required": ["kind"],
                    "additionalProperties": false
                }),
            },
            ToolSpec {
                name: LIST_INCIDENTS.to_owned(),
                description: "Lists incidents, newest first.".to_owned(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "status": {
                            "enum": ["open", "investigating", "contained", "resolved", "false_positive"]
                        },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_TOOL_RECORDS }
                    },
                    "additionalProperties": false
                }),
            },
        ]
    }

    async fn call(&self, name: &str, value: &Value) -> Result<Value> {
        match name {
            GRAPH_NODE => {
                let input: NodeArguments = arguments(name, value)?;
                let node = self.graph.node(&NodeId(input.id)).await?;
                Ok(json!({ "node": node.as_ref().map(node_view) }))
            }
            GRAPH_NEIGHBORS => {
                let input: NeighborArguments = arguments(name, value)?;
                let nodes = self
                    .graph
                    .neighbors(
                        &NodeId(input.id),
                        input.relation.as_deref(),
                        input.direction.unwrap_or(Direction::Both),
                    )
                    .await?;
                Ok(json!({
                    "total": nodes.len(),
                    "nodes": nodes.iter().take(MAX_TOOL_RECORDS).map(node_view).collect::<Vec<_>>(),
                }))
            }
            GRAPH_NODES_BY_KIND => {
                let input: KindArguments = arguments(name, value)?;
                let nodes = self
                    .graph
                    .nodes_by_kind(input.kind, limit(input.limit))
                    .await?;
                Ok(json!({ "nodes": nodes.iter().map(node_view).collect::<Vec<_>>() }))
            }
            LIST_INCIDENTS => {
                let input: IncidentArguments = arguments(name, value)?;
                let incidents = self
                    .incidents
                    .list(input.status, limit(input.limit))
                    .await?;
                let views: Vec<Value> = incidents
                    .iter()
                    .map(|incident| {
                        json!({
                            "id": incident.id,
                            "node": NodeId::for_incident(incident.id),
                            "title": incident.title,
                            "severity": incident.severity,
                            "status": incident.status,
                            "entities": incident
                                .entities
                                .iter()
                                .map(|entity| NodeId::for_entity(entity).0)
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                Ok(json!({ "incidents": views }))
            }
            other => Err(Error::InvalidInput(format!(
                "the tool {other} does not exist"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::graph::relation;
    use aegis_testkit::{Harness, ScriptedModel};

    use super::*;
    use crate::graph_ops::{link, upsert_entity};
    use crate::support::testing::{attack_incident, rogue, spray_ip};

    async fn tools() -> (Harness, GraphTools) {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let principal = upsert_entity(harness.graph.as_ref(), &rogue())
            .await
            .unwrap();
        let address = upsert_entity(harness.graph.as_ref(), &spray_ip())
            .await
            .unwrap();
        link(
            harness.graph.as_ref(),
            &principal,
            relation::AUTHENTICATED_FROM,
            &address,
            Default::default(),
        )
        .await
        .unwrap();
        harness.incidents.save(&attack_incident()).await.unwrap();
        let tools = GraphTools::new(&harness.context("goal"));
        (harness, tools)
    }

    #[tokio::test]
    async fn the_tools_read_nodes_neighbors_and_incidents() {
        let (_harness, tools) = tools().await;
        let node = tools
            .call(
                GRAPH_NODE,
                &json!({ "id": "service_principal:sp-sync-helper" }),
            )
            .await
            .unwrap();
        assert_eq!(node["node"]["label"], "Sync Helper");
        assert_eq!(node["node"]["kind"], "identity");
        let missing = tools
            .call(GRAPH_NODE, &json!({ "id": "user:nobody" }))
            .await
            .unwrap();
        assert_eq!(missing, json!({ "node": null }));

        let neighbors = tools
            .call(
                GRAPH_NEIGHBORS,
                &json!({ "id": "ip_address:203.0.113.50", "direction": "incoming" }),
            )
            .await
            .unwrap();
        assert_eq!(neighbors["total"], 1);
        assert_eq!(
            neighbors["nodes"][0]["id"],
            "service_principal:sp-sync-helper"
        );
        let none = tools
            .call(
                GRAPH_NEIGHBORS,
                &json!({ "id": "ip_address:203.0.113.50", "direction": "outgoing" }),
            )
            .await
            .unwrap();
        assert_eq!(none["total"], 0);

        let assets = tools
            .call(
                GRAPH_NODES_BY_KIND,
                &json!({ "kind": "asset", "limit": 500 }),
            )
            .await
            .unwrap();
        assert_eq!(assets["nodes"].as_array().unwrap().len(), 1);

        let open = tools
            .call(LIST_INCIDENTS, &json!({ "status": "open" }))
            .await
            .unwrap();
        assert_eq!(open["incidents"].as_array().unwrap().len(), 1);
        assert_eq!(open["incidents"][0]["severity"], "critical");
        let contained = tools
            .call(LIST_INCIDENTS, &json!({ "status": "contained" }))
            .await
            .unwrap();
        assert_eq!(contained, json!({ "incidents": [] }));
    }

    #[tokio::test]
    async fn bad_arguments_and_unknown_tools_are_input_errors() {
        let (_harness, tools) = tools().await;
        for (name, input) in [
            (GRAPH_NODE, json!({})),
            (GRAPH_NODE, json!({ "id": "x", "delete": true })),
            (GRAPH_NODES_BY_KIND, json!({ "kind": "secret" })),
            (LIST_INCIDENTS, json!({ "status": "closed" })),
            ("graph_delete", json!({ "id": "x" })),
        ] {
            let error = tools.call(name, &input).await.unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{name}: {error}");
        }
    }

    #[tokio::test]
    async fn each_described_tool_exists_and_is_read_only() {
        let (harness, tools) = tools().await;
        let nodes_before = harness.graph.node_count();
        let edges_before = harness.graph.edges();
        let specs = tools.specs();
        assert_eq!(specs.len(), 4);
        for spec in &specs {
            let input = match spec.name.as_str() {
                GRAPH_NODES_BY_KIND => json!({ "kind": "identity" }),
                LIST_INCIDENTS => json!({}),
                _ => json!({ "id": "service_principal:sp-sync-helper" }),
            };
            tools.call(&spec.name, &input).await.unwrap();
        }
        assert_eq!(harness.graph.node_count(), nodes_before);
        assert_eq!(harness.graph.edges(), edges_before);
    }
}
