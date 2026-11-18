//! The Analyst: triages an incident and gives true positives to the Responder.

use std::collections::BTreeMap;

use aegis_contracts::graph::{Direction, NodeId, NodeKind};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::model::TaskKind;
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Roster;
use crate::config::AnalystConfig;
use crate::graph_ops::sync_incident_node;
use crate::llm::{ModelOutput, chat_json};
use crate::prompt::Prompt;
use crate::support::{
    self, has_honeytoken_trip, has_malicious_detection, incident_view, involved_entities, one_line,
};

const MAX_NEIGHBORS: usize = 12;
const MAX_RECOMMENDATIONS: usize = 8;

const INSTRUCTIONS: &str = "You are the analyst agent of AEGIS, a defensive security system. You \
    triage one security incident in the environment of the operator. Decide if the incident \
    describes a real attack (a true positive) or harmless activity (a false positive). Use \
    only the facts in the data sections. If the facts are not sufficient, give a low \
    confidence.";

const OUTPUT_FORMAT: &str = r#"{"verdict": "true_positive" or "false_positive", "confidence": a number from 0 to 1, "summary": at most five sentences, "recommended_containment": an array of short sentences}"#;

/// The conclusion of the model about an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentVerdict {
    /// The incident describes a real attack.
    TruePositive,
    /// The incident describes harmless activity.
    FalsePositive,
}

/// The assessment of an incident that the model returns as JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    /// The conclusion.
    pub verdict: AssessmentVerdict,
    /// How sure the model is, from 0 to 1.
    pub confidence: f64,
    /// A short explanation of the incident.
    pub summary: String,
    /// Containment steps that the model recommends. A person reads this text. The
    /// Responder does not run it.
    #[serde(default)]
    pub recommended_containment: Vec<String>,
}

impl ModelOutput for Assessment {
    fn validate(&self) -> std::result::Result<(), String> {
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence must be a number from 0 to 1".to_owned());
        }
        if self.summary.trim().is_empty() {
            return Err("summary must not be empty".to_owned());
        }
        Ok(())
    }
}

/// The Analyst agent.
///
/// The Analyst reads the graph context of an incident and asks the model for an
/// [`Assessment`]. Then it changes the state, the summary, and the timeline of the
/// incident.
///
/// These rules keep the result safe:
///
/// - A model failure or an answer that is not valid never closes an incident. The incident
///   stays open, and the timeline gets the reason.
/// - If a deterministic detection has the verdict "malicious", or a honeytoken trip is in
///   the incident, the incident is a true positive. The model cannot change that.
/// - The model can close an incident as a false positive only with a confidence of
///   [`AnalystConfig::false_positive_min_confidence`] or more.
#[derive(Debug, Clone)]
pub struct Analyst {
    config: AnalystConfig,
    roster: Roster,
}

impl Analyst {
    /// Makes the agent. `roster` holds the roles that can receive tasks.
    #[must_use]
    pub fn new(config: AnalystConfig, roster: Roster) -> Self {
        Self { config, roster }
    }

    /// Reads the nodes of the entities of the incident, their neighbors, and the other
    /// incidents that involve the same entities.
    async fn graph_context(&self, incident: &Incident, context: &AgentContext) -> Result<Value> {
        let graph = context.graph.as_ref();
        let own = NodeId::for_incident(incident.id);
        let mut entities = Vec::new();
        let mut related: BTreeMap<String, Value> = BTreeMap::new();
        let involved = involved_entities(incident);
        for entity in involved.iter().take(self.config.max_context_entities) {
            let id = NodeId::for_entity(entity);
            let Some(node) = graph.node(&id).await? else {
                continue;
            };
            let neighbors = graph.neighbors(&id, None, Direction::Both).await?;
            for neighbor in &neighbors {
                if neighbor.kind == NodeKind::Incident && neighbor.id != own {
                    related.insert(
                        neighbor.id.0.clone(),
                        json!({ "title": neighbor.label, "properties": neighbor.properties }),
                    );
                }
            }
            let near: Vec<Value> = neighbors
                .iter()
                .filter(|neighbor| neighbor.kind != NodeKind::Incident)
                .take(MAX_NEIGHBORS)
                .map(|neighbor| {
                    json!({ "id": neighbor.id, "kind": neighbor.kind, "label": neighbor.label })
                })
                .collect();
            entities.push(json!({
                "node": id,
                "label": node.label,
                "properties": node.properties,
                "neighbors": near,
            }));
        }
        Ok(json!({ "entities": entities, "related_incidents": related }))
    }

    async fn triage(&self, incoming: &Incident, context: &AgentContext) -> Result<AgentOutput> {
        let (mut incident, _) = support::current(context, incoming).await?;
        let before = incident.clone();
        let mut output = AgentOutput::default();

        let graph_context = match self.graph_context(&incident, context).await {
            Ok(value) => value,
            Err(error) => {
                output.notes.push(one_line(&format!(
                    "The graph context for incident {} is not available: {error}.",
                    incident.id
                )));
                Value::Null
            }
        };
        let prompt = Prompt::new(INSTRUCTIONS)
            .task("Assess the incident in the data section `incident`. The data section `graph_context` holds what AEGIS knows about its entities.")
            .output_format(OUTPUT_FORMAT)
            .data("incident", &incident_view(&incident))
            .data("graph_context", &graph_context);
        let deterministic = has_malicious_detection(&incident) || has_honeytoken_trip(&incident);
        let assessment =
            chat_json::<Assessment>(context.models.as_ref(), TaskKind::Analysis, &prompt).await;

        let (confirmed, description) = match assessment {
            Ok(assessment) => {
                let confidence = assessment.confidence;
                match assessment.verdict {
                    AssessmentVerdict::TruePositive => {
                        incident.summary = one_line(&assessment.summary);
                        let recommended: Vec<String> = assessment
                            .recommended_containment
                            .iter()
                            .take(MAX_RECOMMENDATIONS)
                            .map(|text| one_line(text))
                            .filter(|text| !text.is_empty())
                            .collect();
                        let mut text = format!(
                            "The analyst assessed a true positive. Model confidence: \
                             {confidence:.2}."
                        );
                        if !recommended.is_empty() {
                            text.push_str(" The model recommends: ");
                            text.push_str(&recommended.join(" | "));
                        }
                        (true, text)
                    }
                    AssessmentVerdict::FalsePositive if deterministic => (
                        true,
                        format!(
                            "The model assessed a false positive with the confidence \
                             {confidence:.2}. The incident has deterministic evidence of an \
                             attack, so it stays a true positive. {}",
                            deterministic_summary(&incident)
                        ),
                    ),
                    AssessmentVerdict::FalsePositive
                        if confidence >= self.config.false_positive_min_confidence =>
                    {
                        incident.status = IncidentStatus::FalsePositive;
                        incident.summary = one_line(&assessment.summary);
                        (
                            false,
                            format!(
                                "The analyst assessed a false positive. Model confidence: \
                                 {confidence:.2}."
                            ),
                        )
                    }
                    AssessmentVerdict::FalsePositive => {
                        incident.status = IncidentStatus::Investigating;
                        (
                            false,
                            format!(
                                "The model assessed a false positive with the confidence \
                                 {confidence:.2}. The limit is {:.2}. The incident stays open \
                                 for a person.",
                                self.config.false_positive_min_confidence
                            ),
                        )
                    }
                }
            }
            Err(error) if deterministic => (
                true,
                one_line(&format!(
                    "The model gave no assessment: {error}. {}",
                    deterministic_summary(&incident)
                )),
            ),
            Err(error) => {
                // New data arrived for an incident that was closed. A person or a later
                // triage must look at it again.
                if matches!(
                    incident.status,
                    IncidentStatus::FalsePositive | IncidentStatus::Resolved
                ) {
                    incident.status = IncidentStatus::Open;
                }
                (
                    false,
                    one_line(&format!(
                        "The model gave no assessment: {error}. No deterministic detection \
                         confirms an attack. The incident stays open."
                    )),
                )
            }
        };

        if confirmed {
            incident.status = IncidentStatus::Investigating;
            if incident.summary.is_empty() {
                incident.summary = deterministic_summary(&incident);
            }
        }
        let is_repeat = support::last_entry_by(&incident, &AgentRole::Analyst)
            .is_some_and(|entry| entry.description == description);
        if !is_repeat {
            support::add_entry(&mut incident, &AgentRole::Analyst, description.clone());
        }
        output
            .notes
            .push(format!("Incident {}: {description}", incident.id));

        if confirmed {
            for role in [
                AgentRole::Responder,
                AgentRole::Hunter,
                AgentRole::Deception,
            ] {
                if self.roster.has(&role) {
                    output.tasks.push(
                        AgentTask::new(role, AgentInput::Incident(Box::new(incident.clone())))
                            .for_incident(incident.id),
                    );
                }
            }
        }
        if incident != before {
            if let Err(error) = sync_incident_node(context.graph.as_ref(), &incident).await {
                output.notes.push(one_line(&format!(
                    "The Defensive Graph did not take the state of incident {}: {error}.",
                    incident.id
                )));
            }
            output.incidents.push(incident);
        }
        Ok(output)
    }
}

/// Describes the deterministic evidence of an incident in one or two sentences.
fn deterministic_summary(incident: &Incident) -> String {
    let malicious: Vec<&str> = incident
        .detections
        .iter()
        .filter(|detection| detection.verdict == aegis_contracts::Verdict::Malicious)
        .map(|detection| detection.rule_id.as_str())
        .collect();
    let mut techniques: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    techniques.sort_unstable();
    techniques.dedup();
    let mut text = format!(
        "Deterministic triage: {} detections have the verdict malicious",
        malicious.len()
    );
    if !malicious.is_empty() {
        text.push_str(&format!(" ({})", malicious.join(", ")));
    }
    text.push('.');
    if has_honeytoken_trip(incident) {
        text.push_str(" A honeytoken was used.");
    }
    if !techniques.is_empty() {
        text.push_str(&format!(" ATT&CK techniques: {}.", techniques.join(", ")));
    }
    one_line(&text)
}

#[async_trait]
impl Agent for Analyst {
    fn role(&self) -> AgentRole {
        AgentRole::Analyst
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Incident(incident) => self.triage(incident, context).await,
            AgentInput::Goal(_)
            | AgentInput::Tick
            | AgentInput::Event(_)
            | AgentInput::Detection(_)
            | AgentInput::ActionResult(_)
            | AgentInput::Note(_) => Ok(AgentOutput::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::Error;
    use aegis_contracts::graph::DefensiveGraph;
    use aegis_contracts::incident::IncidentStore;
    use aegis_testkit::{Harness, ScriptedModel};

    use super::*;
    use crate::graph_ops::{prop, upsert_entity_with};
    use crate::prompt::{data_sections, outside_data_sections};
    use crate::support::testing::{attack_incident, incident_task, rogue, suspicious_incident};

    fn analyst() -> Analyst {
        Analyst::new(AnalystConfig::default(), Roster::all())
    }

    fn answer(verdict: &str, confidence: f64) -> Value {
        json!({
            "verdict": verdict,
            "confidence": confidence,
            "summary": "A password spray gave access. A rogue service principal got a role.",
            "recommended_containment": ["Disable the service principal.", "Block the address."]
        })
    }

    async fn run(model: ScriptedModel, incident: &Incident) -> (Harness, AgentOutput) {
        let harness = Harness::new(model);
        let output = analyst()
            .handle(
                incident_task(AgentRole::Analyst, incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        (harness, output)
    }

    fn roles(output: &AgentOutput) -> Vec<AgentRole> {
        output.tasks.iter().map(|task| task.to.clone()).collect()
    }

    #[tokio::test]
    async fn a_true_positive_updates_the_incident_and_goes_to_the_responder() {
        let incident = attack_incident();
        let model = ScriptedModel::new("fake").reply_json(&answer("true_positive", 0.93));
        let (harness, output) = run(model, &incident).await;

        assert_eq!(output.incidents.len(), 1);
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert_eq!(
            updated.summary,
            "A password spray gave access. A rogue service principal got a role."
        );
        assert_eq!(updated.timeline.len(), 1);
        assert_eq!(updated.timeline[0].author, "analyst");
        assert_eq!(
            updated.timeline[0].description,
            "The analyst assessed a true positive. Model confidence: 0.93. The model \
             recommends: Disable the service principal. | Block the address."
        );
        assert_eq!(updated.timeline[0].evidence.len(), 4);
        assert_eq!(
            roles(&output),
            [
                AgentRole::Responder,
                AgentRole::Hunter,
                AgentRole::Deception
            ]
        );
        for task in &output.tasks {
            assert_eq!(task.incident_id, Some(incident.id));
            assert_eq!(task.input, AgentInput::Incident(Box::new(updated.clone())));
        }
        assert_eq!(output.notes.len(), 1);
        assert!(output.notes[0].starts_with(&format!("Incident {}: The analyst", incident.id)));

        let requests = harness.model.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].task, TaskKind::Analysis);
        let node = harness
            .graph
            .node(&NodeId::for_incident(incident.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.properties[prop::STATUS], "investigating");
    }

    #[tokio::test]
    async fn the_prompt_has_the_incident_and_the_graph_context_as_data() {
        let incident = attack_incident();
        let harness =
            Harness::new(ScriptedModel::new("fake").reply_json(&answer("true_positive", 0.9)));
        upsert_entity_with(
            harness.graph.as_ref(),
            &rogue(),
            BTreeMap::from([(
                prop::PRIVILEGED_ROLES.to_owned(),
                json!(["Global Administrator"]),
            )]),
        )
        .await
        .unwrap();
        analyst()
            .handle(
                incident_task(AgentRole::Analyst, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        let request = &harness.model.requests()[0];
        let user = &request.messages[1].content;
        let sections = data_sections(user);
        assert_eq!(sections.len(), 2);
        let view: Value = serde_json::from_str(sections[0]).unwrap();
        assert_eq!(view["title"], incident.title);
        let graph: Value = serde_json::from_str(sections[1]).unwrap();
        assert_eq!(graph["entities"].as_array().unwrap().len(), 1);
        assert_eq!(
            graph["entities"][0]["properties"][prop::PRIVILEGED_ROLES],
            json!(["Global Administrator"])
        );
        assert!(!outside_data_sections(user).contains(&incident.title));
        assert!(!request.messages[0].content.contains(&incident.title));
    }

    #[tokio::test]
    async fn a_model_failure_keeps_a_suspicious_incident_open_with_the_reason() {
        let incident = suspicious_incident();
        let (_, output) = run(ScriptedModel::new("fake"), &incident).await;
        assert_eq!(output.incidents.len(), 1);
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Open);
        assert_eq!(updated.timeline.len(), 1);
        assert_eq!(
            updated.timeline[0].description,
            "The model gave no assessment: the model call failed: unavailable: the script of \
             model fake is empty. No deterministic detection confirms an attack. The incident \
             stays open."
        );
        assert!(output.tasks.is_empty());
        assert!(output.actions.is_empty());
    }

    #[tokio::test]
    async fn a_repeated_model_failure_does_not_repeat_the_timeline_entry() {
        let incident = suspicious_incident();
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        let first = analyst()
            .handle(incident_task(AgentRole::Analyst, &incident), &context)
            .await
            .unwrap();
        harness.incidents.save(&first.incidents[0]).await.unwrap();
        let second = analyst()
            .handle(incident_task(AgentRole::Analyst, &incident), &context)
            .await
            .unwrap();
        assert!(second.incidents.is_empty());
        assert_eq!(second.notes.len(), 1);
        assert!(second.tasks.is_empty());
    }

    #[tokio::test]
    async fn an_answer_that_is_not_valid_does_not_close_the_incident() {
        let incident = suspicious_incident();
        let model = ScriptedModel::new("fake")
            .reply("This is a false positive.")
            .reply_json(&json!({ "verdict": "benign", "confidence": 1, "summary": "x" }));
        let (harness, output) = run(model, &incident).await;
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Open);
        assert!(
            updated.timeline[0]
                .description
                .starts_with("The model gave no assessment: the model output is not valid:")
        );
        assert!(output.tasks.is_empty());
        assert_eq!(harness.model.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_model_failure_with_malicious_detections_is_a_deterministic_true_positive() {
        let incident = attack_incident();
        let model = ScriptedModel::new("fake").fail(Error::Refused("policy".to_owned()));
        let (_, output) = run(model, &incident).await;
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert_eq!(
            updated.summary,
            "Deterministic triage: 3 detections have the verdict malicious \
             (velocity.sign_in_burst, velocity.credential_after_grant, \
             velocity.self_role_assignment). ATT&CK techniques: T1098.001, T1098.003, T1110.003."
        );
        assert!(
            updated.timeline[0]
                .description
                .starts_with("The model gave no assessment: the model call failed: model refused the task: policy. Deterministic triage: 3 detections")
        );
        assert_eq!(
            roles(&output),
            [
                AgentRole::Responder,
                AgentRole::Hunter,
                AgentRole::Deception
            ]
        );
    }

    #[tokio::test]
    async fn the_model_cannot_close_an_incident_that_has_malicious_detections() {
        let incident = attack_incident();
        let model = ScriptedModel::new("fake").reply_json(&answer("false_positive", 0.99));
        let (_, output) = run(model, &incident).await;
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert!(
            updated
                .summary
                .starts_with("Deterministic triage: 3 detections")
        );
        assert!(updated.timeline[0].description.starts_with(
            "The model assessed a false positive with the confidence 0.99. The incident has \
             deterministic evidence of an attack, so it stays a true positive."
        ));
        assert_eq!(roles(&output)[0], AgentRole::Responder);
    }

    #[tokio::test]
    async fn a_confident_false_positive_closes_a_suspicious_incident() {
        let incident = suspicious_incident();
        let model = ScriptedModel::new("fake").reply_json(&answer("false_positive", 0.8));
        let (_, output) = run(model, &incident).await;
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::FalsePositive);
        assert_eq!(
            updated.timeline[0].description,
            "The analyst assessed a false positive. Model confidence: 0.80."
        );
        assert!(output.tasks.is_empty());
    }

    #[tokio::test]
    async fn a_false_positive_with_low_confidence_stays_open_for_a_person() {
        let incident = suspicious_incident();
        let model = ScriptedModel::new("fake").reply_json(&answer("false_positive", 0.79));
        let (_, output) = run(model, &incident).await;
        let updated = &output.incidents[0];
        assert_eq!(updated.status, IncidentStatus::Investigating);
        assert_eq!(
            updated.timeline[0].description,
            "The model assessed a false positive with the confidence 0.79. The limit is 0.80. \
             The incident stays open for a person."
        );
        assert!(output.tasks.is_empty());
    }

    #[tokio::test]
    async fn a_model_failure_opens_a_closed_incident_again() {
        let mut incident = suspicious_incident();
        incident.status = IncidentStatus::FalsePositive;
        let (_, output) = run(ScriptedModel::new("fake"), &incident).await;
        assert_eq!(output.incidents[0].status, IncidentStatus::Open);
    }

    #[tokio::test]
    async fn the_roster_limits_the_hand_off() {
        let incident = attack_incident();
        let harness = Harness::new(ScriptedModel::new("fake"));
        let analyst = Analyst::new(
            AnalystConfig::default(),
            Roster::new([AgentRole::Analyst, AgentRole::Responder]),
        );
        let output = analyst
            .handle(
                incident_task(AgentRole::Analyst, &incident),
                &harness.context("goal"),
            )
            .await
            .unwrap();
        assert_eq!(roles(&output), [AgentRole::Responder]);
    }

    #[test]
    fn the_assessment_checks_its_values() {
        let good: Assessment = serde_json::from_value(answer("true_positive", 1.0)).unwrap();
        assert_eq!(good.validate(), Ok(()));
        let mut out_of_range = good.clone();
        out_of_range.confidence = 1.01;
        assert_eq!(
            out_of_range.validate(),
            Err("confidence must be a number from 0 to 1".to_owned())
        );
        let mut empty = good;
        empty.summary = "  ".to_owned();
        assert_eq!(
            empty.validate(),
            Err("summary must not be empty".to_owned())
        );
        assert!(serde_json::from_value::<Assessment>(answer("maybe", 0.5)).is_err());
    }
}
