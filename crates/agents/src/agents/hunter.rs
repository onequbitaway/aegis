//! The Hunter: looks for threats in the data that AEGIS already has.

use std::collections::BTreeMap;

use aegis_contracts::common::{EntityKind, IncidentId};
use aegis_contracts::graph::{DefensiveGraph, Direction, GraphNode, NodeId, NodeKind, relation};
use aegis_contracts::incident::Incident;
use aegis_contracts::model::TaskKind;
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::HunterConfig;
use crate::graph_ops::{flag, link, prop};
use crate::llm::{ModelOutput, run_tool_loop_json};
use crate::prompt::{Prompt, truncate};
use crate::support::{self, involved_entities, one_line};
use crate::tools::GraphTools;

const MAX_MODEL_FINDINGS: usize = 10;
const MAX_NAMES_IN_ENTRY: usize = 10;

const INSTRUCTIONS: &str = "You are the hunter agent of AEGIS, a defensive security system. You \
    look for signs of an attack in data that AEGIS already has: the Defensive Graph and the \
    incident store. You can only read this data with the tools. You cannot scan, probe, or \
    connect to a system, and you must not propose that. Report only what the data shows.";

const OUTPUT_FORMAT: &str = r#"{"findings": [{"title": one short sentence, "description": at most three sentences, "node_ids": identifiers of graph nodes that the tools returned}]}. Use an empty array if the data shows no problem."#;

#[derive(Debug, Deserialize)]
struct HuntAnswer {
    #[serde(default)]
    findings: Vec<HuntFinding>,
}

#[derive(Debug, Deserialize)]
struct HuntFinding {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    node_ids: Vec<String>,
}

impl ModelOutput for HuntAnswer {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.findings.len() > MAX_MODEL_FINDINGS {
            return Err(format!(
                "the answer has more than {MAX_MODEL_FINDINGS} findings"
            ));
        }
        Ok(())
    }
}

/// One result of a hunt, before the Hunter writes it to the graph.
#[derive(Debug, Clone, PartialEq)]
struct Finding {
    /// The stable part of the node identifier. The same result gives the same key.
    key: String,
    hunt: &'static str,
    source: &'static str,
    title: String,
    description: String,
    nodes: Vec<NodeId>,
    incident: Option<IncidentId>,
}

/// The Hunter agent.
///
/// The Hunter reads only the Defensive Graph and the incident store. It does not scan or
/// probe a system, and it does not connect to an asset. It records each result as a
/// [`NodeKind::Finding`] node with `involves` relations to the nodes of the result.
///
/// The deterministic hunts are:
///
/// - **Shared address** (for an incident): identities that authenticated from an address
///   of the incident and are not in the incident.
/// - **Privileged role**: identities that got a privileged role. The Monitor writes this
///   data from role assignment events.
/// - **External exposure**: assets of the operator that the inventory marks as open to
///   the internet, with a management port or with an incident.
///
/// A goal or a note in natural language also starts a model-guided hunt with the
/// read-only [`GraphTools`]. The Hunter records a finding of the model only if the finding
/// names a node that is in the graph.
#[derive(Debug, Clone)]
pub struct Hunter {
    config: HunterConfig,
}

impl Hunter {
    /// Makes the agent.
    #[must_use]
    pub fn new(config: HunterConfig) -> Self {
        Self { config }
    }

    /// Writes the findings that the graph does not have. Returns the new findings.
    async fn record(
        &self,
        graph: &dyn DefensiveGraph,
        findings: Vec<Finding>,
        budget: &mut usize,
    ) -> Result<Vec<Finding>> {
        let mut new = Vec::new();
        for finding in findings {
            if *budget == 0 {
                break;
            }
            let id = NodeId(format!("finding:{}", finding.key));
            if graph.node(&id).await?.is_some() {
                continue;
            }
            let mut properties = BTreeMap::from([
                (prop::HUNT.to_owned(), json!(finding.hunt)),
                (prop::SOURCE.to_owned(), json!(finding.source)),
                (prop::DESCRIPTION.to_owned(), json!(finding.description)),
            ]);
            if let Some(incident) = finding.incident {
                properties.insert(prop::INCIDENT_ID.to_owned(), json!(incident));
            }
            graph
                .upsert_node(GraphNode {
                    id: id.clone(),
                    kind: NodeKind::Finding,
                    label: finding.title.clone(),
                    properties,
                    updated_at: Utc::now(),
                })
                .await?;
            for node in &finding.nodes {
                if graph.node(node).await?.is_some() {
                    link(graph, &id, relation::INVOLVES, node, BTreeMap::new()).await?;
                }
            }
            if let Some(incident) = finding.incident {
                let incident_node = NodeId::for_incident(incident);
                if graph.node(&incident_node).await?.is_some() {
                    link(
                        graph,
                        &id,
                        relation::PART_OF,
                        &incident_node,
                        BTreeMap::new(),
                    )
                    .await?;
                }
            }
            *budget -= 1;
            new.push(finding);
        }
        Ok(new)
    }

    /// Finds identities that authenticated from an address of the incident and are not
    /// in the incident.
    async fn shared_addresses(
        &self,
        graph: &dyn DefensiveGraph,
        incident: &Incident,
    ) -> Result<Vec<Finding>> {
        let entities = involved_entities(incident);
        let known: Vec<NodeId> = entities.iter().map(NodeId::for_entity).collect();
        let mut findings = Vec::new();
        for address in entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::IpAddress)
        {
            let address_node = NodeId::for_entity(address);
            let identities = graph
                .neighbors(
                    &address_node,
                    Some(relation::AUTHENTICATED_FROM),
                    Direction::Incoming,
                )
                .await?;
            for identity in identities
                .iter()
                .filter(|identity| !known.contains(&identity.id))
                .take(self.config.scan_limit)
            {
                findings.push(Finding {
                    key: format!(
                        "shared-address:{}:{}:{}",
                        incident.id, address.id, identity.id
                    ),
                    hunt: "shared_address",
                    source: "deterministic",
                    title: one_line(&format!(
                        "{} ({}) used the address {} of an incident",
                        identity.label, identity.id, address.id
                    )),
                    description: one_line(&format!(
                        "The identity {} authenticated from the address {}. The incident {} \
                         has this address, but it does not have this identity. Check if the \
                         identity is compromised.",
                        identity.id, address.id, incident.id
                    )),
                    nodes: vec![identity.id.clone(), address_node.clone()],
                    incident: Some(incident.id),
                });
            }
        }
        Ok(findings)
    }

    /// Finds identities that got a privileged role.
    async fn privileged_roles(
        &self,
        graph: &dyn DefensiveGraph,
        only: Option<&[NodeId]>,
    ) -> Result<Vec<Finding>> {
        let identities = graph
            .nodes_by_kind(NodeKind::Identity, self.config.scan_limit)
            .await?;
        let mut findings = Vec::new();
        for identity in identities
            .iter()
            .filter(|identity| only.is_none_or(|nodes| nodes.contains(&identity.id)))
        {
            let roles: Vec<&str> = identity
                .properties
                .get(prop::PRIVILEGED_ROLES)
                .and_then(Value::as_array)
                .map(|roles| roles.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let self_assigned = flag(identity, prop::PRIVILEGED_ROLE_SELF_ASSIGNED);
            let assigned_at = identity
                .properties
                .get(prop::PRIVILEGED_ROLE_ASSIGNED_AT)
                .and_then(Value::as_str)
                .unwrap_or("an unknown time");
            for role in roles {
                let how = if self_assigned {
                    "The identity assigned a privileged role to itself."
                } else {
                    "A different identity assigned the role."
                };
                findings.push(Finding {
                    key: format!("privileged-role:{}:{role}", identity.id),
                    hunt: "privileged_role",
                    source: "deterministic",
                    title: one_line(&format!(
                        "{} ({}) has the privileged role {role}",
                        identity.label, identity.id
                    )),
                    description: one_line(&format!(
                        "The last privileged role assignment for {} was at {assigned_at}. \
                         {how} Check that the assignment is approved.",
                        identity.id
                    )),
                    nodes: vec![identity.id.clone()],
                    incident: None,
                });
            }
        }
        Ok(findings)
    }

    /// Reviews the external exposure of the assets of the operator.
    ///
    /// The function reads the inventory properties of the asset nodes. It connects to no
    /// asset.
    async fn exposure(&self, graph: &dyn DefensiveGraph) -> Result<Vec<Finding>> {
        let assets = graph
            .nodes_by_kind(NodeKind::Asset, self.config.scan_limit)
            .await?;
        let mut findings = Vec::new();
        for asset in assets
            .iter()
            .filter(|asset| flag(asset, prop::INTERNET_EXPOSED))
        {
            let mut ports: Vec<u64> = asset
                .properties
                .get(prop::OPEN_PORTS)
                .and_then(Value::as_array)
                .map(|ports| ports.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default();
            ports.retain(|port| {
                self.config
                    .management_ports
                    .iter()
                    .any(|management| u64::from(*management) == *port)
            });
            ports.sort_unstable();
            ports.dedup();
            if !ports.is_empty() {
                let list = ports
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(Finding {
                    key: format!("exposure:ports:{}:{}", asset.id, list.replace(", ", "-")),
                    hunt: "external_exposure",
                    source: "deterministic",
                    title: one_line(&format!(
                        "{} ({}) is open to the internet on management ports: {list}",
                        asset.label, asset.id
                    )),
                    description: "The inventory says that the internet can reach this asset \
                                  and that management ports are open. Limit the access to \
                                  these ports."
                        .to_owned(),
                    nodes: vec![asset.id.clone()],
                    incident: None,
                });
            }
            let incidents = graph
                .neighbors(&asset.id, Some(relation::INVOLVES), Direction::Incoming)
                .await?;
            for incident in incidents
                .iter()
                .filter(|node| node.kind == NodeKind::Incident)
            {
                findings.push(Finding {
                    key: format!("exposure:incident:{}:{}", asset.id, incident.id),
                    hunt: "external_exposure",
                    source: "deterministic",
                    title: one_line(&format!(
                        "{} ({}) is open to the internet and is part of an incident",
                        asset.label, asset.id
                    )),
                    description: one_line(&format!(
                        "The inventory says that the internet can reach this asset. The \
                         incident {} involves the asset. Review the exposure first.",
                        incident.id
                    )),
                    nodes: vec![asset.id.clone(), incident.id.clone()],
                    incident: None,
                });
            }
        }
        Ok(findings)
    }

    /// Runs a hunt in which the model reads the graph with the read-only tools.
    ///
    /// Returns the findings that name a node of the graph, and the number of findings
    /// that the function ignored.
    async fn model_hunt(
        &self,
        request: &str,
        context: &AgentContext,
    ) -> std::result::Result<(Vec<Finding>, usize), crate::error::ModelCallError> {
        let prompt = Prompt::new(INSTRUCTIONS)
            .task(
                "Do the hunt request in the data section. Read the data with the tools. Then \
                 give the findings.",
            )
            .output_format(OUTPUT_FORMAT)
            .data("hunt_request", &json!({ "request": request }));
        let tools = GraphTools::new(context);
        let answer: HuntAnswer = run_tool_loop_json(
            context.models.as_ref(),
            TaskKind::Analysis,
            &prompt,
            &tools,
            self.config.max_tool_steps,
        )
        .await?;
        let mut findings = Vec::new();
        let mut ignored = 0;
        for item in answer.findings {
            let title = one_line(&item.title);
            let mut nodes = Vec::new();
            for id in item.node_ids.iter().take(MAX_NAMES_IN_ENTRY) {
                let node = NodeId(id.clone());
                let exists = context
                    .graph
                    .node(&node)
                    .await
                    .map_err(crate::error::ModelCallError::Tool)?
                    .is_some();
                if exists && !nodes.contains(&node) {
                    nodes.push(node);
                }
            }
            // The model can only report about nodes that the graph has.
            let Some(first) = nodes.first() else {
                ignored += 1;
                continue;
            };
            if title.is_empty() {
                ignored += 1;
                continue;
            }
            findings.push(Finding {
                key: format!("model:{first}:{}", slug(&title)),
                hunt: "model_guided",
                source: "model",
                title,
                description: one_line(&item.description),
                nodes,
                incident: None,
            });
        }
        Ok((findings, ignored))
    }

    async fn on_incident(
        &self,
        incoming: &Incident,
        context: &AgentContext,
    ) -> Result<AgentOutput> {
        let (mut incident, _) = support::current(context, incoming).await?;
        let graph = context.graph.as_ref();
        let mut budget = self.config.max_findings;
        let mut findings = self.shared_addresses(graph, &incident).await?;
        let identities: Vec<NodeId> = involved_entities(&incident)
            .iter()
            .map(NodeId::for_entity)
            .collect();
        let mut privileged = self.privileged_roles(graph, Some(&identities)).await?;
        for finding in &mut privileged {
            finding.incident = Some(incident.id);
        }
        findings.extend(privileged);
        let new = self.record(graph, findings, &mut budget).await?;

        let mut output = AgentOutput::default();
        if new.is_empty() {
            return Ok(output);
        }
        let titles: Vec<&str> = new
            .iter()
            .take(MAX_NAMES_IN_ENTRY)
            .map(|finding| finding.title.as_str())
            .collect();
        support::add_entry(
            &mut incident,
            &AgentRole::Hunter,
            one_line(&format!(
                "The hunter recorded {} findings for the incident: {}",
                new.len(),
                titles.join("; ")
            )),
        );
        output.notes = new
            .iter()
            .map(|finding| format!("Finding: {}.", finding.title))
            .collect();
        output.incidents.push(incident);
        Ok(output)
    }

    async fn sweep(&self, request: Option<&str>, context: &AgentContext) -> Result<AgentOutput> {
        let graph = context.graph.as_ref();
        let mut budget = self.config.max_findings;
        let mut findings = self.privileged_roles(graph, None).await?;
        findings.extend(self.exposure(graph).await?);
        let mut new = self.record(graph, findings, &mut budget).await?;
        let mut output = AgentOutput::default();

        if let Some(request) = request.filter(|_| self.config.model_guided) {
            match self.model_hunt(request, context).await {
                Ok((findings, ignored)) => {
                    let recorded = self.record(graph, findings, &mut budget).await?;
                    output.notes.push(format!(
                        "The model-guided hunt recorded {} findings. {ignored} findings named \
                         no node of the graph and were ignored.",
                        recorded.len()
                    ));
                    new.extend(recorded);
                }
                Err(error) => output.notes.push(one_line(&format!(
                    "The model-guided hunt did not complete: {error}. The deterministic hunts \
                     ran."
                ))),
            }
        }
        output.notes.extend(
            new.iter()
                .map(|finding| format!("Finding: {}.", finding.title)),
        );
        Ok(output)
    }
}

/// Makes a short identifier part from a title.
fn slug(title: &str) -> String {
    let lower: String = title
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let joined = lower
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    truncate(&joined, 60)
}

#[async_trait]
impl Agent for Hunter {
    fn role(&self) -> AgentRole {
        AgentRole::Hunter
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Incident(incident) => self.on_incident(incident, context).await,
            AgentInput::Tick => self.sweep(None, context).await,
            AgentInput::Goal(request) | AgentInput::Note(request) => {
                self.sweep(Some(request), context).await
            }
            AgentInput::Event(_) | AgentInput::Detection(_) | AgentInput::ActionResult(_) => {
                Ok(AgentOutput::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::EntityRef;
    use aegis_contracts::model::Role;
    use aegis_testkit::{Harness, ScriptedModel};

    use super::*;
    use crate::graph_ops::{sync_incident_node, upsert_entity, upsert_entity_with};
    use crate::prompt::DATA_START;
    use crate::support::testing::{attack_incident, incident_task, rogue, spray_ip, victim};

    fn hunter() -> Hunter {
        Hunter::new(HunterConfig::default())
    }

    async fn findings(harness: &Harness) -> Vec<GraphNode> {
        let mut nodes = harness
            .graph
            .nodes_by_kind(NodeKind::Finding, 100)
            .await
            .unwrap();
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        nodes
    }

    async fn authenticated_from(harness: &Harness, identity: &EntityRef, address: &EntityRef) {
        let graph = harness.graph.as_ref();
        let from = upsert_entity(graph, identity).await.unwrap();
        let to = upsert_entity(graph, address).await.unwrap();
        link(
            graph,
            &from,
            relation::AUTHENTICATED_FROM,
            &to,
            BTreeMap::new(),
        )
        .await
        .unwrap();
    }

    fn privileged(self_assigned: bool) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                prop::PRIVILEGED_ROLES.to_owned(),
                json!(["Global Administrator"]),
            ),
            (
                prop::PRIVILEGED_ROLE_ASSIGNED_AT.to_owned(),
                json!("2026-11-03T09:10:46Z"),
            ),
            (
                prop::PRIVILEGED_ROLE_SELF_ASSIGNED.to_owned(),
                json!(self_assigned),
            ),
        ])
    }

    #[tokio::test]
    async fn the_incident_hunt_finds_other_identities_on_the_address_of_the_incident() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        let incident = attack_incident();
        sync_incident_node(harness.graph.as_ref(), &incident)
            .await
            .unwrap();
        let other =
            EntityRef::new(EntityKind::User, "user-042").with_name("user-042@contoso.example");
        authenticated_from(&harness, &victim(), &spray_ip()).await;
        authenticated_from(&harness, &other, &spray_ip()).await;

        let output = hunter()
            .handle(incident_task(AgentRole::Hunter, &incident), &context)
            .await
            .unwrap();

        let nodes = findings(&harness).await;
        assert_eq!(nodes.len(), 1);
        let finding = &nodes[0];
        assert_eq!(
            finding.id.0,
            format!(
                "finding:shared-address:{}:203.0.113.50:user:user-042",
                incident.id
            )
        );
        assert_eq!(
            finding.label,
            "user-042@contoso.example (user:user-042) used the address 203.0.113.50 of an incident"
        );
        assert_eq!(finding.properties[prop::HUNT], "shared_address");
        assert_eq!(finding.properties[prop::SOURCE], "deterministic");
        let involved = harness
            .graph
            .neighbors(&finding.id, Some(relation::INVOLVES), Direction::Outgoing)
            .await
            .unwrap();
        let mut ids: Vec<&str> = involved.iter().map(|node| node.id.0.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["ip_address:203.0.113.50", "user:user-042"]);
        let parents = harness
            .graph
            .neighbors(&finding.id, Some(relation::PART_OF), Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].id, NodeId::for_incident(incident.id));

        assert_eq!(output.incidents.len(), 1);
        let entry = output.incidents[0].timeline.last().unwrap();
        assert_eq!(entry.author, "hunter");
        assert!(
            entry
                .description
                .starts_with("The hunter recorded 1 findings for the incident:")
        );
        assert_eq!(output.notes.len(), 1);
        assert!(output.actions.is_empty());
        assert!(output.tasks.is_empty());
        assert!(harness.model.requests().is_empty());

        let again = hunter()
            .handle(incident_task(AgentRole::Hunter, &incident), &context)
            .await
            .unwrap();
        assert_eq!(again, AgentOutput::default());
        assert_eq!(findings(&harness).await.len(), 1);
    }

    #[tokio::test]
    async fn the_sweep_finds_privileged_roles_one_time() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        upsert_entity_with(harness.graph.as_ref(), &rogue(), privileged(true))
            .await
            .unwrap();
        upsert_entity(harness.graph.as_ref(), &victim())
            .await
            .unwrap();
        let tick = AgentTask::new(AgentRole::Hunter, AgentInput::Tick);

        let output = hunter().handle(tick.clone(), &context).await.unwrap();
        assert_eq!(
            output.notes,
            [
                "Finding: Sync Helper (service_principal:sp-sync-helper) has the privileged role \
              Global Administrator."
            ]
        );
        let nodes = findings(&harness).await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].id.0,
            "finding:privileged-role:service_principal:sp-sync-helper:Global Administrator"
        );
        assert_eq!(
            nodes[0].properties[prop::DESCRIPTION],
            "The last privileged role assignment for service_principal:sp-sync-helper was at \
             2026-11-03T09:10:46Z. The identity assigned a privileged role to itself. Check \
             that the assignment is approved."
        );
        assert!(harness.model.requests().is_empty());

        let again = hunter().handle(tick, &context).await.unwrap();
        assert_eq!(again, AgentOutput::default());
    }

    #[tokio::test]
    async fn the_exposure_review_reads_only_the_inventory_data() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        let graph = harness.graph.as_ref();
        let jump = EntityRef::new(EntityKind::Host, "host-jump").with_name("Jump host");
        let web = EntityRef::new(EntityKind::Host, "host-web").with_name("Web server");
        let internal = EntityRef::new(EntityKind::Host, "host-db").with_name("Database");
        let exposed = |ports: Value| {
            BTreeMap::from([
                (prop::INTERNET_EXPOSED.to_owned(), json!(true)),
                (prop::OPEN_PORTS.to_owned(), ports),
            ])
        };
        upsert_entity_with(graph, &jump, exposed(json!([443, 3389, 22])))
            .await
            .unwrap();
        upsert_entity_with(graph, &web, exposed(json!([80, 443])))
            .await
            .unwrap();
        upsert_entity_with(
            graph,
            &internal,
            BTreeMap::from([(prop::OPEN_PORTS.to_owned(), json!([5432]))]),
        )
        .await
        .unwrap();
        let incident = attack_incident();
        let incident_node = sync_incident_node(graph, &incident).await.unwrap();
        link(
            graph,
            &incident_node,
            relation::INVOLVES,
            &NodeId::for_entity(&web),
            BTreeMap::new(),
        )
        .await
        .unwrap();
        let edges_before = harness.graph.edges().len();

        let output = hunter()
            .handle(
                AgentTask::new(AgentRole::Hunter, AgentInput::Tick),
                &context,
            )
            .await
            .unwrap();
        let nodes = findings(&harness).await;
        let ids: Vec<&str> = nodes.iter().map(|node| node.id.0.as_str()).collect();
        assert_eq!(
            ids,
            [
                format!(
                    "finding:exposure:incident:host:host-web:incident:{}",
                    incident.id
                )
                .as_str(),
                "finding:exposure:ports:host:host-jump:22-3389",
            ]
        );
        assert_eq!(
            nodes[1].label,
            "Jump host (host:host-jump) is open to the internet on management ports: 22, 3389"
        );
        assert_eq!(output.notes.len(), 2);
        assert!(output.actions.is_empty());
        // The hunt only added the relations of the two findings.
        assert_eq!(harness.graph.edges().len(), edges_before + 3);
    }

    #[tokio::test]
    async fn a_goal_runs_a_model_hunt_with_read_only_tools() {
        let model = ScriptedModel::new("fake")
            .reply_tool_call("graph_nodes_by_kind", json!({ "kind": "identity" }))
            .reply_json(&json!({
                "findings": [
                    {
                        "title": "The service principal has no owner",
                        "description": "No identity owns the service principal.",
                        "node_ids": ["service_principal:sp-sync-helper", "user:invented"]
                    },
                    {
                        "title": "An invented problem",
                        "description": "This names no node of the graph.",
                        "node_ids": ["host:invented"]
                    }
                ]
            }));
        let harness = Harness::new(model);
        let context = harness.context("goal");
        upsert_entity(harness.graph.as_ref(), &rogue())
            .await
            .unwrap();

        let task = AgentTask::new(
            AgentRole::Hunter,
            AgentInput::Goal("Look for service principals with no owner.".to_owned()),
        );
        let output = hunter().handle(task, &context).await.unwrap();
        assert_eq!(
            output.notes,
            [
                "The model-guided hunt recorded 1 findings. 1 findings named no node of the \
                 graph and were ignored.",
                "Finding: The service principal has no owner."
            ]
        );
        let nodes = findings(&harness).await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].id.0,
            "finding:model:service_principal:sp-sync-helper:the-service-principal-has-no-owner"
        );
        assert_eq!(nodes[0].properties[prop::SOURCE], "model");
        let involved = harness
            .graph
            .neighbors(&nodes[0].id, Some(relation::INVOLVES), Direction::Outgoing)
            .await
            .unwrap();
        assert_eq!(involved.len(), 1);

        let requests = harness.model.requests();
        assert_eq!(requests.len(), 2);
        let tool_names: Vec<&str> = requests[0]
            .tools
            .iter()
            .map(|spec| spec.name.as_str())
            .collect();
        assert_eq!(
            tool_names,
            [
                "graph_node",
                "graph_neighbors",
                "graph_nodes_by_kind",
                "list_incidents"
            ]
        );
        let tool_message = &requests[1].messages[3];
        assert_eq!(tool_message.role, Role::Tool);
        assert!(tool_message.content.starts_with(DATA_START));
        assert!(tool_message.content.contains("sp-sync-helper"));
        assert!(output.actions.is_empty());
    }

    #[tokio::test]
    async fn the_deterministic_hunts_run_when_the_model_is_not_available() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        upsert_entity_with(harness.graph.as_ref(), &rogue(), privileged(false))
            .await
            .unwrap();
        let task = AgentTask::new(
            AgentRole::Hunter,
            AgentInput::Goal("Keep this tenant safe.".to_owned()),
        );
        let output = hunter().handle(task.clone(), &context).await.unwrap();
        assert_eq!(output.notes.len(), 2);
        assert!(
            output.notes[0]
                .starts_with("The model-guided hunt did not complete: the model call failed:")
        );
        assert!(output.notes[1].starts_with("Finding: Sync Helper"));
        assert_eq!(findings(&harness).await.len(), 1);

        let config = HunterConfig {
            model_guided: false,
            ..HunterConfig::default()
        };
        let output = Hunter::new(config).handle(task, &context).await.unwrap();
        assert_eq!(output, AgentOutput::default());
        assert_eq!(harness.model.requests().len(), 1);
    }

    #[tokio::test]
    async fn one_task_records_at_most_the_configured_number_of_findings() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        for index in 0..4 {
            let principal = EntityRef::new(EntityKind::ServicePrincipal, format!("sp-{index}"));
            upsert_entity_with(harness.graph.as_ref(), &principal, privileged(false))
                .await
                .unwrap();
        }
        let config = HunterConfig {
            max_findings: 3,
            ..HunterConfig::default()
        };
        let hunter = Hunter::new(config);
        let tick = AgentTask::new(AgentRole::Hunter, AgentInput::Tick);
        let first = hunter.handle(tick.clone(), &context).await.unwrap();
        assert_eq!(first.notes.len(), 3);
        let second = hunter.handle(tick, &context).await.unwrap();
        assert_eq!(second.notes.len(), 1);
        assert_eq!(findings(&harness).await.len(), 4);
    }

    #[test]
    fn a_slug_has_only_lower_case_letters_digits_and_hyphens() {
        assert_eq!(slug("The SP has  no owner!"), "the-sp-has-no-owner");
        assert_eq!(slug("---"), "");
        assert_eq!(slug(&"a".repeat(100)).len(), 60);
    }
}
