//! The Reporter: writes the incident report as Markdown and JSON.

use aegis_contracts::bus::publish_json;
use aegis_contracts::incident::Incident;
use aegis_contracts::model::TaskKind;
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::llm::{ModelOutput, chat_json};
use crate::prompt::Prompt;
use crate::report::IncidentReport;
use crate::support::{self, incident_view, one_line, token};

/// The bus subject for incident reports. The Reporter publishes each report to
/// `aegis.reports.{incident identifier}`. The payload is a [`ReportDocument`].
pub const REPORT_SUBJECT: &str = "aegis.reports";
const MAX_RECOMMENDATIONS: usize = 10;

const INSTRUCTIONS: &str = "You are the reporter agent of AEGIS, a defensive security system. \
    You write the summary and the recommendations of an incident report for the security team \
    of the operator. The code adds the facts of the report: the timeline, the entities, the \
    techniques, the actions, and the evidence. Use only the facts in the data section. Do not \
    invent a fact. Use short sentences.";

const OUTPUT_FORMAT: &str = r#"{"summary": at most eight sentences that say what occurred, what the agents did, and what the state is, "recommendations": an array of at most ten short sentences}"#;

#[derive(Debug, Deserialize)]
struct Narrative {
    summary: String,
    #[serde(default)]
    recommendations: Vec<String>,
}

impl ModelOutput for Narrative {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.summary.trim().is_empty() {
            return Err("summary must not be empty".to_owned());
        }
        if self.recommendations.len() > MAX_RECOMMENDATIONS {
            return Err(format!(
                "recommendations must have at most {MAX_RECOMMENDATIONS} items"
            ));
        }
        Ok(())
    }
}

/// The payload that the Reporter publishes on the bus: the report in its two forms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportDocument {
    /// The report as a structure. Its JSON encoding is the JSON form of the report.
    pub report: IncidentReport,
    /// The report as Markdown.
    pub markdown: String,
}

/// The Reporter agent.
///
/// For an incident, the Reporter makes an [`IncidentReport`] and publishes it as a
/// [`ReportDocument`] on [`REPORT_SUBJECT`]. The code makes all facts of the report. The
/// model writes only the summary and the recommendations. If the model is not available,
/// the deterministic template makes this text.
#[derive(Debug, Clone, Default)]
pub struct Reporter;

impl Reporter {
    /// Makes the agent.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    async fn write(&self, incoming: &Incident, context: &AgentContext) -> Result<AgentOutput> {
        let (mut incident, _) = support::current(context, incoming).await?;
        let mut output = AgentOutput::default();
        let mut report = IncidentReport::from_incident(&incident, Utc::now());

        let prompt = Prompt::new(INSTRUCTIONS)
            .task("Write the summary and the recommendations for the incident in the data section.")
            .output_format(OUTPUT_FORMAT)
            .data(
                "report_facts",
                &json!({
                    "incident": incident_view(&incident),
                    "actions": report.actions,
                }),
            );
        match chat_json::<Narrative>(context.models.as_ref(), TaskKind::Reporting, &prompt).await {
            Ok(narrative) => {
                let recommendations = narrative
                    .recommendations
                    .iter()
                    .map(|text| one_line(text))
                    .filter(|text| !text.is_empty())
                    .collect();
                report = report.with_narrative(one_line(&narrative.summary), recommendations);
            }
            Err(error) => output.notes.push(one_line(&format!(
                "The model wrote no report text for incident {}: {error}. The template applies.",
                incident.id
            ))),
        }

        let source = token(&report.narrative_source);
        let document = ReportDocument {
            markdown: report.to_markdown(),
            report,
        };
        publish_json(
            context.bus.as_ref(),
            &format!("{REPORT_SUBJECT}.{}", incident.id),
            &document,
        )
        .await?;

        let description = format!(
            "The reporter wrote the incident report. Text source: {source}. State in the \
             report: {}.",
            token(&incident.status)
        );
        let is_repeat = support::last_entry_by(&incident, &AgentRole::Reporter)
            .is_some_and(|entry| entry.description == description);
        if !is_repeat {
            support::add_entry(&mut incident, &AgentRole::Reporter, description);
            output.incidents.push(incident.clone());
        }
        output.notes.push(format!(
            "Wrote the report for incident {} on {REPORT_SUBJECT}.{}. Text source: {source}.",
            incident.id, incident.id
        ));
        Ok(output)
    }
}

#[async_trait]
impl Agent for Reporter {
    fn role(&self) -> AgentRole {
        AgentRole::Reporter
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        match &task.input {
            AgentInput::Incident(incident) => self.write(incident, context).await,
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
    use std::sync::Arc;

    use aegis_contracts::bus::{BusStream, MessageBus};
    use aegis_contracts::incident::{IncidentStatus, IncidentStore};
    use aegis_contracts::model::ResponseFormat;
    use aegis_contracts::{ActionKind, Error};
    use aegis_testkit::{Harness, ScriptedModel};

    use super::*;
    use crate::ledger::{ActionState, marker};
    use crate::prompt::{data_sections, outside_data_sections};
    use crate::report::NarrativeSource;
    use crate::support::add_timeline;
    use crate::support::testing::{attack_incident, incident_task, spray_ip};

    /// An incident in work with one action that ran.
    fn incident() -> Incident {
        let mut incident = attack_incident();
        incident.status = IncidentStatus::Investigating;
        let id = aegis_contracts::ActionId::new();
        for state in [ActionState::Proposed, ActionState::Succeeded] {
            add_timeline(
                &mut incident,
                &AgentRole::Responder,
                "Action entry.",
                vec![marker(id, state, &ActionKind::BlockIp, &spray_ip())],
            );
        }
        incident
    }

    async fn write(harness: &Harness, incident: &Incident) -> AgentOutput {
        Reporter::new()
            .handle(
                incident_task(AgentRole::Reporter, incident),
                &harness.context("goal"),
            )
            .await
            .unwrap()
    }

    fn published(harness: &Harness, incident: &Incident) -> Vec<ReportDocument> {
        harness
            .bus
            .published_to(&format!("{REPORT_SUBJECT}.{}", incident.id))
            .iter()
            .map(|message| message.decode().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn the_report_has_the_facts_of_the_code_and_the_text_of_the_model() {
        let model = ScriptedModel::new("fake").reply_json(&json!({
            "summary": "A password spray gave access.\nThe agents blocked the address.",
            "recommendations": ["Reset the password of the user.", "  "]
        }));
        let harness = Harness::new(model);
        let incident = incident();
        let output = write(&harness, &incident).await;

        let documents = published(&harness, &incident);
        assert_eq!(documents.len(), 1);
        assert_eq!(harness.bus.published().len(), 1);
        let report = &documents[0].report;
        assert_eq!(report.narrative_source, NarrativeSource::Model);
        assert_eq!(
            report.summary,
            "A password spray gave access. The agents blocked the address."
        );
        assert_eq!(report.recommendations, ["Reset the password of the user."]);
        // The model cannot change the facts.
        assert_eq!(report.incident_id, incident.id);
        assert_eq!(report.status, IncidentStatus::Investigating);
        assert_eq!(report.timeline, incident.timeline);
        assert_eq!(report.entities, incident.entities);
        assert_eq!(report.detections.len(), 3);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, "block_ip");
        assert_eq!(report.actions[0].state, ActionState::Succeeded);
        assert_eq!(documents[0].markdown, report.to_markdown());
        assert!(documents[0].markdown.contains(
            "## Summary\n\nA password spray gave access. The agents blocked the address.\n"
        ));

        assert_eq!(output.incidents.len(), 1);
        let entry = output.incidents[0].timeline.last().unwrap();
        assert_eq!(entry.author, "reporter");
        assert_eq!(
            entry.description,
            "The reporter wrote the incident report. Text source: model. State in the report: \
             investigating."
        );
        assert_eq!(
            output.notes,
            [format!(
                "Wrote the report for incident {id} on aegis.reports.{id}. Text source: model.",
                id = incident.id
            )]
        );
        assert!(output.actions.is_empty());
        assert!(output.tasks.is_empty());

        let requests = harness.model.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].task, TaskKind::Reporting);
        assert_eq!(requests[0].response_format, ResponseFormat::Json);
        let user = &requests[0].messages[1].content;
        assert!(!requests[0].messages[0].content.contains(&incident.title));
        assert!(!outside_data_sections(user).contains(&incident.title));
        let sections = data_sections(user);
        assert_eq!(sections.len(), 1);
        let facts: serde_json::Value = serde_json::from_str(sections[0]).unwrap();
        assert_eq!(facts["incident"]["title"], incident.title);
        assert_eq!(facts["actions"][0]["state"], "succeeded");
    }

    #[tokio::test]
    async fn the_template_applies_when_the_model_is_not_available() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let incident = incident();
        let output = write(&harness, &incident).await;

        let documents = published(&harness, &incident);
        assert_eq!(documents.len(), 1);
        let report = &documents[0].report;
        assert_eq!(report.narrative_source, NarrativeSource::Template);
        assert_eq!(
            report.summary,
            "The incident has the severity critical and the state investigating. It has 3 \
             detections and 3 entities. ATT&CK techniques: T1098.001, T1098.003, T1110.003. \
             The agents proposed 1 actions. 1 actions ran."
        );
        assert!(documents[0].markdown.contains("| Text source | template |"));
        assert_eq!(
            output.notes,
            [
                format!(
                    "The model wrote no report text for incident {}: the model call failed: \
                     unavailable: the script of model fake is empty. The template applies.",
                    incident.id
                ),
                format!(
                    "Wrote the report for incident {id} on aegis.reports.{id}. Text source: \
                     template.",
                    id = incident.id
                ),
            ]
        );
        assert_eq!(
            output.incidents[0].timeline.last().unwrap().description,
            "The reporter wrote the incident report. Text source: template. State in the \
             report: investigating."
        );
    }

    #[tokio::test]
    async fn model_text_that_is_not_valid_gives_the_template() {
        let model = ScriptedModel::new("fake")
            .reply_json(&json!({ "summary": " ", "recommendations": [] }))
            .reply("The report is ready.");
        let harness = Harness::new(model);
        let incident = incident();
        let output = write(&harness, &incident).await;
        let documents = published(&harness, &incident);
        assert_eq!(documents.len(), 1);
        assert_eq!(
            documents[0].report.narrative_source,
            NarrativeSource::Template
        );
        assert!(output.notes[0].contains("the model output is not valid"));
        assert_eq!(harness.model.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_second_report_for_the_same_state_adds_no_timeline_entry() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let incident = incident();
        let first = write(&harness, &incident).await;
        harness.incidents.save(&first.incidents[0]).await.unwrap();

        let second = write(&harness, &incident).await;
        assert!(second.incidents.is_empty());
        assert_eq!(second.notes.len(), 2);
        let documents = published(&harness, &incident);
        assert_eq!(documents.len(), 2);
        // The second report has the entry of the first report.
        assert_eq!(
            documents[1].report.timeline.len(),
            incident.timeline.len() + 1
        );

        // A new state gives a new entry.
        let mut contained = first.incidents[0].clone();
        contained.status = IncidentStatus::Contained;
        harness.incidents.save(&contained).await.unwrap();
        let third = write(&harness, &incident).await;
        assert_eq!(
            third.incidents[0].timeline.last().unwrap().description,
            "The reporter wrote the incident report. Text source: template. State in the \
             report: contained."
        );
    }

    #[tokio::test]
    async fn a_bus_that_does_not_take_the_report_is_an_error() {
        struct DownBus;

        #[async_trait]
        impl MessageBus for DownBus {
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<()> {
                Err(Error::Unavailable("the bus is down".to_owned()))
            }

            async fn subscribe(&self, _: &str, _: Option<&str>) -> Result<BusStream> {
                Err(Error::Unavailable("the bus is down".to_owned()))
            }
        }

        let harness = Harness::new(ScriptedModel::new("fake"));
        let mut context = harness.context("goal");
        context.bus = Arc::new(DownBus);
        let error = Reporter::new()
            .handle(incident_task(AgentRole::Reporter, &incident()), &context)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unavailable(reason) if reason == "the bus is down"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn inputs_with_no_incident_make_no_report() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        for input in [AgentInput::Tick, AgentInput::Goal("Report.".to_owned())] {
            let output = Reporter::new()
                .handle(
                    AgentTask::new(AgentRole::Reporter, input),
                    &harness.context("goal"),
                )
                .await
                .unwrap();
            assert_eq!(output, AgentOutput::default());
        }
        assert!(harness.bus.published().is_empty());
        assert!(harness.model.requests().is_empty());
    }
}
