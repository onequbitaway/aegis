//! Explanations from the audit log.
//!
//! An explanation answers the question "why did AEGIS do this?". It is the ordered list of
//! the audit records that link to one action or to one incident: the proposal, the policy
//! decision, the approval, and the execution.
//!
//! # How a record links to an action or an incident
//!
//! A record links to an action or to an incident if one of these conditions is true:
//!
//! - Its evidence has an [`EvidenceRef`] with the identifier of the action or the incident.
//! - Its payload holds the identifier as a string value, at any depth.
//!
//! The explanation of an incident also has the records of each action of the incident. An
//! action is an action of the incident if a record that links to the incident names it: in
//! an evidence link of the type [`EvidenceKind::Action`], in an `action_id` field of the
//! payload, or in the `id` field of an `action` object in the payload.
//!
//! When you write an audit record for an action, add an evidence link to the action. Add
//! a link to the incident too, if the action has one.
//!
//! # Integrity
//!
//! The functions in this module read the log. They do not check the full chain. Call
//! [`AuditLog::verify`] when you must know that no record is missing.

use std::collections::BTreeSet;
use std::fmt;

use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::common::{ActionId, EvidenceKind, EvidenceRef, IncidentId};
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The number of records that one read of the log asks for.
const PAGE_SIZE: usize = 512;

/// The thing that an explanation is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// One action.
    Action(ActionId),
    /// One incident and all its actions.
    Incident(IncidentId),
}

impl fmt::Display for Subject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action(id) => write!(formatter, "action {id}"),
            Self::Incident(id) => write!(formatter, "incident {id}"),
        }
    }
}

/// The audit records that explain one action or one incident.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Explanation {
    /// The thing that the explanation is about.
    pub subject: Subject,
    /// The records that link to the subject, in sequence order. The list is not empty.
    pub records: Vec<AuditRecord>,
}

impl Explanation {
    /// Returns the type of each record, in sequence order.
    #[must_use]
    pub fn kinds(&self) -> Vec<AuditKind> {
        self.records.iter().map(|record| record.kind).collect()
    }

    /// Returns the evidence links of all records, in the order of first use, with no
    /// duplicates. Two links are duplicates if they have the same type and identifier.
    #[must_use]
    pub fn evidence(&self) -> Vec<EvidenceRef> {
        let mut evidence: Vec<EvidenceRef> = Vec::new();
        for link in self.records.iter().flat_map(|record| &record.evidence) {
            let known = evidence
                .iter()
                .any(|other| other.kind == link.kind && other.id == link.id);
            if !known {
                evidence.push(link.clone());
            }
        }
        evidence
    }
}

impl fmt::Display for Explanation {
    /// Writes one line for each record and one indented line for each evidence link.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Audit records for {}:", self.subject)?;
        for record in &self.records {
            writeln!(
                formatter,
                "#{} {} {} {}: {}",
                record.sequence,
                record
                    .time
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                wire_name(&record.kind),
                record.actor,
                record.summary
            )?;
            for link in &record.evidence {
                write!(
                    formatter,
                    "    evidence: {} {}",
                    wire_name(&link.kind),
                    link.id
                )?;
                match &link.note {
                    Some(note) => writeln!(formatter, " ({note})")?,
                    None => writeln!(formatter)?,
                }
            }
        }
        Ok(())
    }
}

/// Returns the audit records that explain one action.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if no record links to the action. Returns the error of the
/// log if a read fails.
pub async fn explain_action(log: &dyn AuditLog, action: ActionId) -> Result<Explanation> {
    explain(log, Subject::Action(action)).await
}

/// Returns the audit records that explain one incident and all its actions.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if no record links to the incident. Returns the error of
/// the log if a read fails.
pub async fn explain_incident(log: &dyn AuditLog, incident: IncidentId) -> Result<Explanation> {
    explain(log, Subject::Incident(incident)).await
}

/// Returns the audit records that explain `subject`.
///
/// This function reads the full log one time for an action and two times for an incident.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if no record links to the subject. Returns the error of the
/// log if a read fails.
pub async fn explain(log: &dyn AuditLog, subject: Subject) -> Result<Explanation> {
    let mut identifiers = BTreeSet::new();
    match subject {
        Subject::Action(id) => {
            identifiers.insert(normal(&id.to_string()));
        }
        Subject::Incident(id) => {
            let incident = BTreeSet::from([normal(&id.to_string())]);
            scan(log, |record| {
                if links_to(&record, &incident) {
                    collect_action_ids(&record, &mut identifiers);
                }
            })
            .await?;
            identifiers.extend(incident);
        }
    }

    let mut records = Vec::new();
    scan(log, |record| {
        if links_to(&record, &identifiers) {
            records.push(record);
        }
    })
    .await?;
    if records.is_empty() {
        return Err(Error::NotFound(format!(
            "no audit record links to {subject}"
        )));
    }
    Ok(Explanation { subject, records })
}

/// Gives each record of the log to `visit`, in sequence order.
async fn scan(log: &dyn AuditLog, mut visit: impl FnMut(AuditRecord)) -> Result<()> {
    let mut next: u64 = 1;
    loop {
        let page = log.read(next, PAGE_SIZE).await?;
        let Some(last) = page.last().map(|record| record.sequence) else {
            return Ok(());
        };
        if last < next {
            return Err(Error::Integrity(format!(
                "the audit log returned sequence {last} for a read that starts at sequence \
                 {next}"
            )));
        }
        for record in page {
            visit(record);
        }
        let Some(after) = last.checked_add(1) else {
            return Ok(());
        };
        next = after;
    }
}

/// Returns the form of an identifier that the comparisons use.
fn normal(identifier: &str) -> String {
    identifier.trim().to_ascii_lowercase()
}

/// Returns `true` if an evidence link or a payload value of `record` is in `identifiers`.
fn links_to(record: &AuditRecord, identifiers: &BTreeSet<String>) -> bool {
    record
        .evidence
        .iter()
        .any(|link| identifiers.contains(&normal(&link.id)))
        || holds(&record.payload, identifiers)
}

/// Returns `true` if a string value in `value`, at any depth, is in `identifiers`.
fn holds(value: &Value, identifiers: &BTreeSet<String>) -> bool {
    match value {
        Value::String(text) => identifiers.contains(&normal(text)),
        Value::Array(items) => items.iter().any(|item| holds(item, identifiers)),
        Value::Object(fields) => fields.values().any(|field| holds(field, identifiers)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Adds the identifiers of the actions that `record` names to `actions`.
fn collect_action_ids(record: &AuditRecord, actions: &mut BTreeSet<String>) {
    for link in &record.evidence {
        if link.kind == EvidenceKind::Action {
            actions.insert(normal(&link.id));
        }
    }
    collect_payload_action_ids(&record.payload, actions);
}

fn collect_payload_action_ids(value: &Value, actions: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(id)) = fields.get("action_id") {
                actions.insert(normal(id));
            }
            if let Some(Value::String(id)) =
                fields.get("action").and_then(|action| action.get("id"))
            {
                actions.insert(normal(id));
            }
            for field in fields.values() {
                collect_payload_action_ids(field, actions);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_payload_action_ids(item, actions);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Returns the name that the contract gives to a value, for example `action_proposed`.
fn wire_name<T: Serialize + fmt::Debug>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        _ => format!("{value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::audit::{AuditEntry, seal};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn record(payload: Value, evidence: Vec<EvidenceRef>) -> AuditRecord {
        seal(
            None,
            AuditEntry::new(
                AuditKind::ActionProposed,
                "responder",
                "Proposed an action.",
            )
            .with_payload(payload)
            .with_evidence(evidence),
            Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_record_links_by_evidence_or_by_a_payload_value_at_any_depth() {
        let id = "0198c0de-0000-7000-8000-000000000001";
        let identifiers = BTreeSet::from([id.to_owned()]);
        let by_evidence = record(
            Value::Null,
            vec![EvidenceRef::new(EvidenceKind::Action, id)],
        );
        let by_payload = record(json!({ "outcome": [{ "action_id": id }] }), Vec::new());
        let upper_case = record(json!({ "action": { "id": id.to_uppercase() } }), Vec::new());
        for linked in [&by_evidence, &by_payload, &upper_case] {
            assert!(links_to(linked, &identifiers));
        }

        let other_id = record(
            json!({ "action_id": "0198c0de-0000-7000-8000-000000000002" }),
            vec![EvidenceRef::new(
                EvidenceKind::Action,
                "0198c0de-0000-7000-8000-000000000003",
            )],
        );
        let as_key = record(json!({ id: true }), Vec::new());
        let as_part = record(json!({ "note": format!("about {id}") }), Vec::new());
        for unlinked in [&other_id, &as_key, &as_part] {
            assert!(!links_to(unlinked, &identifiers));
        }
        assert!(!links_to(&by_evidence, &BTreeSet::new()));
    }

    #[test]
    fn the_actions_of_a_record_come_from_three_places() {
        let found = record(
            json!({
                "action_id": "A-1",
                "action": { "id": "a-2", "kind": "notify" },
                "nested": [{ "action_id": "a-3" }],
                "id": "not-an-action",
                "target": { "id": "also-not-an-action" }
            }),
            vec![
                EvidenceRef::new(EvidenceKind::Action, "a-4"),
                EvidenceRef::new(EvidenceKind::Detection, "det-1"),
            ],
        );
        let mut actions = BTreeSet::new();
        collect_action_ids(&found, &mut actions);
        assert_eq!(
            actions.into_iter().collect::<Vec<_>>(),
            ["a-1", "a-2", "a-3", "a-4"]
        );
    }

    #[test]
    fn the_text_form_has_one_line_for_each_record_and_each_link() {
        let action = ActionId::new();
        let explanation = Explanation {
            subject: Subject::Action(action),
            records: vec![record(
                Value::Null,
                vec![
                    EvidenceRef::new(EvidenceKind::Action, action),
                    EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("cause"),
                ],
            )],
        };
        let text = explanation.to_string();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                format!("Audit records for action {action}:"),
                "#1 2026-01-02T03:04:05.000000Z action_proposed responder: Proposed an action."
                    .to_owned(),
                format!("    evidence: action {action}"),
                "    evidence: detection det-1 (cause)".to_owned(),
            ]
        );
    }
}
