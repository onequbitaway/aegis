//! The incident report as a structure, as JSON, and as Markdown.
//!
//! The code makes all facts of a report from the incident: the timeline, the entities,
//! the ATT&CK mapping, the actions, and the evidence. A model can only supply the summary
//! text and the recommendations. A model can thus not change a fact of the report.

use aegis_contracts::Result;
use aegis_contracts::common::{
    DetectionId, EntityRef, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::detection::{AttackTechnique, Verdict};
use aegis_contracts::incident::{Incident, IncidentStatus, TimelineEntry};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::ledger::{ActionState, TrackedAction, tracked_actions};
use crate::support::{one_line, token};

const MAX_EVIDENCE: usize = 200;

/// The origin of the summary and the recommendations of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarrativeSource {
    /// A model wrote the text.
    Model,
    /// The deterministic template made the text.
    Template,
}

/// One detection in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedDetection {
    /// The identifier of the detection.
    pub id: DetectionId,
    /// The rule or the detector that made the detection.
    pub rule_id: String,
    /// The title of the detection.
    pub title: String,
    /// The severity of the detection.
    pub severity: Severity,
    /// The conclusion of the detector.
    pub verdict: Verdict,
    /// The time of the last event that caused the detection.
    pub time: DateTime<Utc>,
    /// The ATT&CK technique identifiers of the detection.
    pub techniques: Vec<String>,
    /// The number of events that caused the detection.
    pub event_count: usize,
}

/// The report of one incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReport {
    /// The identifier of the incident.
    pub incident_id: IncidentId,
    /// The title of the incident.
    pub title: String,
    /// The severity of the incident.
    pub severity: Severity,
    /// The state of the incident.
    pub status: IncidentStatus,
    /// The tenant of the incident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The time at which the correlator made the incident.
    pub created_at: DateTime<Utc>,
    /// The time of the last change of the incident.
    pub updated_at: DateTime<Utc>,
    /// The time at which the report was made.
    pub generated_at: DateTime<Utc>,
    /// The summary of the incident.
    pub summary: String,
    /// The origin of the summary and the recommendations.
    pub narrative_source: NarrativeSource,
    /// The recommended next steps.
    pub recommendations: Vec<String>,
    /// The timeline of the incident, in time order.
    pub timeline: Vec<TimelineEntry>,
    /// The entities of the incident.
    pub entities: Vec<EntityRef>,
    /// The ATT&CK techniques of the incident.
    pub attack: Vec<AttackTechnique>,
    /// The detections of the incident.
    pub detections: Vec<ReportedDetection>,
    /// The proposed actions and their last known states.
    pub actions: Vec<TrackedAction>,
    /// The evidence for the report.
    pub evidence: Vec<EvidenceRef>,
}

impl IncidentReport {
    /// Makes the report of `incident` with the deterministic template.
    #[must_use]
    pub fn from_incident(incident: &Incident, generated_at: DateTime<Utc>) -> Self {
        let actions = tracked_actions(incident);
        let detections: Vec<ReportedDetection> = incident
            .detections
            .iter()
            .map(|detection| ReportedDetection {
                id: detection.id,
                rule_id: detection.rule_id.clone(),
                title: detection.title.clone(),
                severity: detection.severity,
                verdict: detection.verdict,
                time: detection.time,
                techniques: detection
                    .attack
                    .iter()
                    .map(|technique| technique.technique_id.clone())
                    .collect(),
                event_count: detection.event_ids.len(),
            })
            .collect();
        let mut attack = incident.attack.clone();
        for technique in incident
            .detections
            .iter()
            .flat_map(|detection| &detection.attack)
        {
            if !attack.contains(technique) {
                attack.push(technique.clone());
            }
        }
        attack.sort();

        let mut evidence = vec![EvidenceRef::new(EvidenceKind::Incident, incident.id)];
        let detection_links = incident
            .detections
            .iter()
            .map(|detection| EvidenceRef::new(EvidenceKind::Detection, detection.id));
        let timeline_links = incident
            .timeline
            .iter()
            .flat_map(|entry| &entry.evidence)
            .map(|link| EvidenceRef::new(link.kind, &link.id));
        for link in detection_links.chain(timeline_links) {
            if evidence.len() >= MAX_EVIDENCE {
                break;
            }
            if !evidence.contains(&link) {
                evidence.push(link);
            }
        }

        Self {
            incident_id: incident.id,
            title: incident.title.clone(),
            severity: incident.severity,
            status: incident.status,
            tenant: incident.tenant.clone(),
            created_at: incident.created_at,
            updated_at: incident.updated_at,
            generated_at,
            summary: template_summary(incident, &actions),
            narrative_source: NarrativeSource::Template,
            recommendations: template_recommendations(incident, &actions),
            timeline: incident.timeline.clone(),
            entities: incident.entities.clone(),
            attack,
            detections,
            actions,
            evidence,
        }
    }

    /// Replaces the summary and the recommendations with text from a model.
    ///
    /// The facts of the report do not change.
    #[must_use]
    pub fn with_narrative(mut self, summary: String, recommendations: Vec<String>) -> Self {
        self.summary = summary;
        self.recommendations = recommendations;
        self.narrative_source = NarrativeSource::Model;
        self
    }

    /// Returns the report as a JSON value.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }

    /// Returns the report as Markdown.
    ///
    /// The function escapes all text from the incident, so that the text cannot add
    /// links, images, or structure to the document.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut text = format!("# Incident report: {}\n\n", md(&self.title));
        text.push_str("| Field | Value |\n| --- | --- |\n");
        let fields = [
            ("Incident", self.incident_id.to_string()),
            ("Severity", token(&self.severity)),
            ("State", token(&self.status)),
            (
                "Tenant",
                self.tenant.clone().unwrap_or_else(|| "-".to_owned()),
            ),
            ("Created", time(self.created_at)),
            ("Last change", time(self.updated_at)),
            ("Report time", time(self.generated_at)),
            ("Text source", token(&self.narrative_source)),
        ];
        for (name, value) in fields {
            text.push_str(&format!("| {name} | {} |\n", md(&value)));
        }

        text.push_str("\n## Summary\n\n");
        text.push_str(&md(&self.summary));
        text.push('\n');

        text.push_str("\n## Timeline\n\n");
        if self.timeline.is_empty() {
            text.push_str("The timeline has no entries.\n");
        } else {
            text.push_str("| Time | Author | Description |\n| --- | --- | --- |\n");
            for entry in &self.timeline {
                text.push_str(&format!(
                    "| {} | {} | {} |\n",
                    time(entry.time),
                    md(&entry.author),
                    md(&entry.description)
                ));
            }
        }

        text.push_str("\n## Entities\n\n");
        if self.entities.is_empty() {
            text.push_str("The incident has no entities.\n");
        } else {
            text.push_str("| Type | Identifier | Name | Tenant |\n| --- | --- | --- | --- |\n");
            for entity in &self.entities {
                text.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    token(&entity.kind),
                    md(&entity.id),
                    md(entity.name.as_deref().unwrap_or("-")),
                    md(entity.tenant.as_deref().unwrap_or("-"))
                ));
            }
        }

        text.push_str("\n## ATT&CK mapping\n\n");
        if self.attack.is_empty() {
            text.push_str("The incident has no ATT&CK techniques.\n");
        } else {
            text.push_str("| Tactic | Technique | Name |\n| --- | --- | --- |\n");
            for technique in &self.attack {
                text.push_str(&format!(
                    "| {} | {} | {} |\n",
                    md(&technique.tactic),
                    md(&technique.technique_id),
                    md(&technique.name)
                ));
            }
        }

        text.push_str("\n## Detections\n\n");
        if self.detections.is_empty() {
            text.push_str("The incident has no detections.\n");
        } else {
            text.push_str(
                "| Time | Rule | Title | Severity | Verdict | Techniques | Events |\n\
                 | --- | --- | --- | --- | --- | --- | --- |\n",
            );
            for detection in &self.detections {
                text.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} |\n",
                    time(detection.time),
                    md(&detection.rule_id),
                    md(&detection.title),
                    token(&detection.severity),
                    token(&detection.verdict),
                    md(&detection.techniques.join(", ")),
                    detection.event_count
                ));
            }
        }

        text.push_str("\n## Actions taken\n\n");
        if self.actions.is_empty() {
            text.push_str("No agent proposed an action.\n");
        } else {
            text.push_str(
                "| Action | Target | State | Proposed by | Action identifier |\n\
                 | --- | --- | --- | --- | --- |\n",
            );
            for action in &self.actions {
                text.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    md(&action.kind),
                    md(&action.target),
                    token(&action.state),
                    md(&action.author),
                    md(&action.action_id)
                ));
            }
        }

        text.push_str("\n## Recommendations\n\n");
        if self.recommendations.is_empty() {
            text.push_str("The report has no recommendations.\n");
        } else {
            for recommendation in &self.recommendations {
                text.push_str(&format!("- {}\n", md(recommendation)));
            }
        }

        text.push_str("\n## Evidence\n\n");
        for link in &self.evidence {
            text.push_str(&format!("- {} {}\n", token(&link.kind), md(&link.id)));
        }
        text
    }
}

fn time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Escapes text for Markdown: one line, with no character that starts a link, an image,
/// emphasis, a table cell, a heading, or HTML.
fn md(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '!' | '(' | ')' => {
                escaped.push('\\');
                escaped.push(character);
            }
            control if control.is_control() => escaped.push(' '),
            other => escaped.push(other),
        }
    }
    escaped
}

fn count(actions: &[TrackedAction], state: ActionState) -> usize {
    actions
        .iter()
        .filter(|action| action.state == state)
        .count()
}

fn template_summary(incident: &Incident, actions: &[TrackedAction]) -> String {
    let mut text = String::new();
    if !incident.summary.is_empty() {
        text.push_str(&one_line(&incident.summary));
        text.push(' ');
    }
    let mut techniques: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    techniques.sort_unstable();
    techniques.dedup();
    text.push_str(&format!(
        "The incident has the severity {} and the state {}. It has {} detections and {} \
         entities.",
        token(&incident.severity),
        token(&incident.status),
        incident.detections.len(),
        incident.entities.len()
    ));
    if !techniques.is_empty() {
        text.push_str(&format!(" ATT&CK techniques: {}.", techniques.join(", ")));
    }
    let done = actions
        .iter()
        .filter(|action| action.state.is_done())
        .count();
    text.push_str(&format!(
        " The agents proposed {} actions. {done} actions ran.",
        actions.len()
    ));
    text
}

fn template_recommendations(incident: &Incident, actions: &[TrackedAction]) -> Vec<String> {
    let mut recommendations = Vec::new();
    let pending = count(actions, ActionState::PendingApproval);
    if pending > 0 {
        recommendations.push(format!(
            "Approve or reject the {pending} actions that wait for approval."
        ));
    }
    let denied = count(actions, ActionState::Denied);
    if denied > 0 {
        recommendations.push(format!(
            "Review the {denied} actions that policy denied. Contain these entities manually if it is necessary."
        ));
    }
    let failed = count(actions, ActionState::Failed);
    if failed > 0 {
        recommendations.push(format!("Examine the {failed} actions that failed."));
    }
    let simulated = count(actions, ActionState::Simulated);
    if simulated > 0 {
        recommendations.push(format!(
            "The {simulated} dry-run actions changed nothing. Set dry_run to false to contain the incident."
        ));
    }
    match incident.status {
        IncidentStatus::Contained => recommendations.push(
            "Make sure that the activity stopped. Then set the incident to resolved.".to_owned(),
        ),
        IncidentStatus::Open | IncidentStatus::Investigating if actions.is_empty() => {
            recommendations
                .push("No action was proposed. A person must examine the incident.".to_owned());
        }
        _ => {}
    }
    recommendations
}

#[cfg(test)]
mod tests {
    use aegis_contracts::AgentRole;
    use aegis_contracts::action::ActionKind;
    use aegis_contracts::common::ActionId;
    use chrono::TimeZone;

    use super::*;
    use crate::ledger::marker;
    use crate::support::add_timeline;
    use crate::support::testing::{attack_incident, rogue, spray_ip};

    fn report_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, 10, 0, 0).unwrap()
    }

    fn incident_with_actions() -> (Incident, ActionId, ActionId) {
        let mut incident = attack_incident();
        let block = ActionId::new();
        let disable = ActionId::new();
        for (id, state, kind, target) in [
            (
                block,
                ActionState::Proposed,
                ActionKind::BlockIp,
                spray_ip(),
            ),
            (
                disable,
                ActionState::Proposed,
                ActionKind::DisableServicePrincipal,
                rogue(),
            ),
            (
                block,
                ActionState::Succeeded,
                ActionKind::BlockIp,
                spray_ip(),
            ),
            (
                disable,
                ActionState::PendingApproval,
                ActionKind::DisableServicePrincipal,
                rogue(),
            ),
        ] {
            add_timeline(
                &mut incident,
                &AgentRole::Responder,
                "Action entry.",
                vec![marker(id, state, &kind, &target)],
            );
        }
        (incident, block, disable)
    }

    #[test]
    fn the_template_report_has_the_facts_of_the_incident() {
        let (incident, block, disable) = incident_with_actions();
        let report = IncidentReport::from_incident(&incident, report_time());
        assert_eq!(report.incident_id, incident.id);
        assert_eq!(report.narrative_source, NarrativeSource::Template);
        assert_eq!(report.timeline, incident.timeline);
        assert_eq!(report.entities, incident.entities);
        assert_eq!(report.detections.len(), 3);
        assert_eq!(report.detections[0].rule_id, "velocity.sign_in_burst");
        assert_eq!(
            report
                .attack
                .iter()
                .map(|technique| technique.technique_id.as_str())
                .collect::<Vec<_>>(),
            ["T1098.001", "T1098.003", "T1110.003"]
        );
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].action_id, block.to_string());
        assert_eq!(report.actions[0].state, ActionState::Succeeded);
        assert_eq!(report.actions[1].action_id, disable.to_string());
        assert_eq!(report.actions[1].state, ActionState::PendingApproval);
        assert_eq!(
            report.summary,
            "The incident has the severity critical and the state open. It has 3 detections \
             and 3 entities. ATT&CK techniques: T1098.001, T1098.003, T1110.003. The agents \
             proposed 2 actions. 1 actions ran."
        );
        assert_eq!(
            report.recommendations,
            ["Approve or reject the 1 actions that wait for approval."]
        );
        // The incident, 3 detections, and 2 actions.
        assert_eq!(report.evidence.len(), 6);
        assert_eq!(
            report.evidence[0],
            EvidenceRef::new(EvidenceKind::Incident, incident.id)
        );
        assert!(
            report
                .evidence
                .contains(&EvidenceRef::new(EvidenceKind::Action, block))
        );
    }

    #[test]
    fn the_json_form_round_trips() {
        let (incident, _, _) = incident_with_actions();
        let report = IncidentReport::from_incident(&incident, report_time());
        let json = report.to_json().unwrap();
        assert_eq!(json["status"], "open");
        assert_eq!(json["narrative_source"], "template");
        assert_eq!(json["actions"][0]["kind"], "block_ip");
        assert_eq!(json["actions"][0]["state"], "succeeded");
        let decoded: IncidentReport = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, report);
    }

    #[test]
    fn a_model_narrative_changes_only_the_text() {
        let (incident, _, _) = incident_with_actions();
        let template = IncidentReport::from_incident(&incident, report_time());
        let report = template.clone().with_narrative(
            "An attacker sprayed passwords.".to_owned(),
            vec!["Rotate the credentials.".to_owned()],
        );
        assert_eq!(report.narrative_source, NarrativeSource::Model);
        assert_eq!(report.summary, "An attacker sprayed passwords.");
        assert_eq!(report.recommendations, ["Rotate the credentials."]);
        assert_eq!(report.actions, template.actions);
        assert_eq!(report.timeline, template.timeline);
        assert_eq!(report.evidence, template.evidence);
    }

    #[test]
    fn the_markdown_has_each_section_with_the_facts() {
        let (mut incident, block, _) = incident_with_actions();
        incident.status = IncidentStatus::Investigating;
        let markdown = IncidentReport::from_incident(&incident, report_time()).to_markdown();
        let headings: Vec<&str> = markdown
            .lines()
            .filter(|line| line.starts_with('#'))
            .collect();
        assert_eq!(
            headings,
            [
                "# Incident report: Password spray and rogue service principal",
                "## Summary",
                "## Timeline",
                "## Entities",
                "## ATT&CK mapping",
                "## Detections",
                "## Actions taken",
                "## Recommendations",
                "## Evidence",
            ]
        );
        assert!(markdown.contains(&format!("| Incident | {} |", incident.id)));
        assert!(markdown.contains("| Severity | critical |"));
        assert!(markdown.contains("| State | investigating |"));
        assert!(markdown.contains("| Report time | 2026-11-03T10:00:00Z |"));
        assert!(
            markdown
                .contains("| service_principal | sp-sync-helper | Sync Helper | tenant-contoso |")
        );
        assert!(markdown.contains("| tactic | T1110.003 | Technique |"));
        assert!(markdown.contains(&format!(
            "| block\\_ip | ip\\_address:203.0.113.50 | succeeded | responder | {block} |"
        )));
        assert!(markdown.contains("- Approve or reject the 1 actions that wait for approval."));
        assert!(markdown.contains(&format!("- incident {}", incident.id)));
    }

    #[test]
    fn untrusted_text_cannot_add_markdown_structure() {
        let mut incident = attack_incident();
        incident.title = "Spray | [click](https://evil.example) <b>\n# Injected".to_owned();
        incident.entities[2].name = Some("![x](https://evil.example/p.png)".to_owned());
        let report = IncidentReport::from_incident(&incident, report_time()).with_narrative(
            "See [the portal](https://evil.example).\n\n## Fake".to_owned(),
            vec![],
        );
        let markdown = report.to_markdown();
        assert!(!markdown.contains("](https://evil.example"));
        assert!(!markdown.contains("\n# Injected"));
        assert!(!markdown.contains("\n## Fake"));
        assert!(!markdown.contains("<b>"));
        assert!(markdown.contains(
            "# Incident report: Spray \\| \\[click\\]\\(https://evil.example\\) \\<b\\> \\# Injected"
        ));
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.starts_with('#'))
                .count(),
            9
        );
    }

    #[test]
    fn the_template_recommends_the_next_step_for_each_state() {
        let mut incident = attack_incident();
        let open = IncidentReport::from_incident(&incident, report_time());
        assert_eq!(
            open.recommendations,
            ["No action was proposed. A person must examine the incident."]
        );

        let id = ActionId::new();
        for state in [ActionState::Proposed, ActionState::Simulated] {
            add_timeline(
                &mut incident,
                &AgentRole::Responder,
                "Entry.",
                vec![marker(id, state, &ActionKind::BlockIp, &spray_ip())],
            );
        }
        incident.status = IncidentStatus::Investigating;
        let simulated = IncidentReport::from_incident(&incident, report_time());
        assert_eq!(
            simulated.recommendations,
            [
                "The 1 dry-run actions changed nothing. Set dry_run to false to contain the incident."
            ]
        );

        incident.status = IncidentStatus::Contained;
        incident.timeline.clear();
        let contained = IncidentReport::from_incident(&incident, report_time());
        assert_eq!(
            contained.recommendations,
            ["Make sure that the activity stopped. Then set the incident to resolved."]
        );
    }
}
