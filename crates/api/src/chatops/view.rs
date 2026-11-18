//! The content of chat messages, before a chat format renders it.
//!
//! All text in a [`Card`] is raw. Text from an incident, an event, or an action is
//! untrusted: an attacker can write it. Each chat format must escape each value before it
//! puts the value in a message.

use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::common::EntityRef;
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus};
use serde::Serialize;
use uuid::Uuid;

use crate::state::ApprovalDecision;

/// The maximum number of ATT&CK techniques that a message lists.
const MAX_TECHNIQUES: usize = 8;

/// The content of one chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Card {
    /// The title. This text comes from AEGIS and is trusted.
    pub title: &'static str,
    /// One line of untrusted text below the title, for example the incident title.
    pub headline: Option<String>,
    /// Pairs of a trusted label and an untrusted value.
    pub facts: Vec<(&'static str, String)>,
    /// The identifier line. The label is trusted. The identifier is a UUID, so it needs no
    /// escape.
    pub reference: (&'static str, Uuid),
}

/// Returns the name that a value has in JSON, for example `false_positive`.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// Returns the name of an action type. A plugin action is `custom:<name>`.
pub(crate) fn action_label(kind: &ActionKind) -> String {
    match kind {
        ActionKind::Custom(name) => format!("custom:{name}"),
        other => wire_name(other),
    }
}

/// Returns the type and the name of an entity, for example `user alice (u-1)`.
pub(crate) fn entity_label(entity: &EntityRef) -> String {
    let kind = wire_name(&entity.kind);
    match &entity.name {
        Some(name) if *name != entity.id => format!("{kind} {name} ({})", entity.id),
        _ => format!("{kind} {}", entity.id),
    }
}

/// Makes the content of a message about one approval request.
pub(crate) fn approval_card(request: &ApprovalRequest) -> Card {
    let mut facts = vec![
        ("Action", action_label(&request.action.kind)),
        ("Target", entity_label(&request.action.target)),
        ("Reason", request.action.reason.clone()),
        ("Requested by", request.requested_by.id.clone()),
    ];
    if !request.decision.reasons.is_empty() {
        facts.push(("Policy", request.decision.reasons.join(" ")));
    }
    if request.action.dry_run {
        facts.push(("Mode", "dry run".to_owned()));
    }
    if let Some(incident) = request.action.incident_id {
        facts.push(("Incident", incident.to_string()));
    }
    let title = match request.status {
        ApprovalStatus::Pending => "AEGIS approval needed",
        ApprovalStatus::Approved => "AEGIS action approved",
        ApprovalStatus::Rejected => "AEGIS action rejected",
    };
    if request.status != ApprovalStatus::Pending {
        if let Some(decided_by) = &request.decided_by {
            facts.push(("Decided by", decided_by.clone()));
        }
        if let Some(note) = &request.note {
            facts.push(("Note", note.clone()));
        }
    }
    Card {
        title,
        headline: None,
        facts,
        reference: ("Approval", request.id.0),
    }
}

/// Makes the content of a message about one incident.
pub(crate) fn incident_card(incident: &Incident) -> Card {
    let mut facts = vec![
        ("Severity", wire_name(&incident.severity)),
        ("Status", wire_name(&incident.status)),
    ];
    if let Some(tenant) = &incident.tenant {
        facts.push(("Tenant", tenant.clone()));
    }
    if !incident.attack.is_empty() {
        let mut techniques: Vec<&str> = incident
            .attack
            .iter()
            .take(MAX_TECHNIQUES)
            .map(|technique| technique.technique_id.as_str())
            .collect();
        if incident.attack.len() > MAX_TECHNIQUES {
            techniques.push("...");
        }
        facts.push(("Techniques", techniques.join(", ")));
    }
    facts.push(("Entities", incident.entities.len().to_string()));
    if !incident.summary.trim().is_empty() {
        facts.push(("Summary", incident.summary.clone()));
    }
    Card {
        title: "AEGIS incident",
        headline: Some(incident.title.clone()),
        facts,
        reference: ("Incident", incident.id.0),
    }
}

/// Returns one sentence that tells what the dispatcher did with an action.
pub(crate) fn disposition_line(disposition: &ActionDisposition) -> String {
    match disposition {
        ActionDisposition::Executed(outcome) => {
            let status = match outcome.status {
                ActionStatus::Succeeded => "The action ran",
                ActionStatus::Failed => "The action failed",
                ActionStatus::Simulated => "The action was a dry run",
                ActionStatus::Skipped => "No change was necessary",
            };
            format!("{status}: {}", outcome.message)
        }
        ActionDisposition::PendingApproval { approval_id, .. } => {
            format!("The action waits for one more approval: {approval_id}")
        }
        ActionDisposition::Denied(decision) => {
            format!("Policy denied the action. {}", decision.reasons.join(" "))
        }
    }
}

/// Returns the lines that tell the result of a decision. The lines hold untrusted text.
pub(crate) fn decision_lines(decision: &ApprovalDecision) -> Vec<String> {
    let request = &decision.request;
    let verb = match request.status {
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Rejected => "rejected",
        ApprovalStatus::Pending => "did not decide",
    };
    let by = request.decided_by.as_deref().unwrap_or("A person");
    let mut lines = vec![format!(
        "{by} {verb} the action {} on {}.",
        action_label(&request.action.kind),
        entity_label(&request.action.target)
    )];
    if let Some(disposition) = &decision.disposition {
        lines.push(disposition_line(disposition));
    }
    lines
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::{EntityKind, Severity};
    use aegis_contracts::incident::IncidentStatus;

    use super::*;

    #[test]
    fn a_wire_name_is_the_json_name() {
        assert_eq!(wire_name(&IncidentStatus::FalsePositive), "false_positive");
        assert_eq!(wire_name(&Severity::Critical), "critical");
        assert_eq!(wire_name(&ActionKind::Custom("x".into())), "unknown");
    }

    #[test]
    fn an_action_label_names_a_plugin_action() {
        assert_eq!(action_label(&ActionKind::DisableUser), "disable_user");
        assert_eq!(
            action_label(&ActionKind::Custom("quarantine_mail".into())),
            "custom:quarantine_mail"
        );
    }

    #[test]
    fn an_entity_label_shows_the_name_and_the_identifier() {
        let entity = EntityRef::new(EntityKind::ServicePrincipal, "sp-1");
        assert_eq!(entity_label(&entity), "service_principal sp-1");
        assert_eq!(
            entity_label(&entity.clone().with_name("sync-helper")),
            "service_principal sync-helper (sp-1)"
        );
        assert_eq!(
            entity_label(&entity.with_name("sp-1")),
            "service_principal sp-1"
        );
    }
}
