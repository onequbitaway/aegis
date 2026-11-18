//! The text form and the JSON form of the reports.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use aegis_app::actions::{ActionRecord, DispatchResult};
use aegis_app::report::ReplayReport;
use aegis_contracts::Detection;
use aegis_contracts::action::ActionDisposition;
use aegis_contracts::audit::{AuditRecord, ChainVerification};
use aegis_contracts::incident::Incident;
use anyhow::Context as _;
use serde::Serialize;

/// Returns the wire name of a value that serializes as one string, for example a severity.
pub fn token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        Ok(serde_json::Value::Object(fields)) => fields
            .iter()
            .next()
            .map(|(key, value)| match value.as_str() {
                Some(text) => format!("{key}:{text}"),
                None => key.clone(),
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Writes `text` to the standard output stream.
///
/// A reader that closes the stream early, for example `head`, is not an error of the
/// program, but the program must stop. Thus the caller gets the error.
pub fn print(text: &str) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .context("cannot write the report to the standard output stream")
}

/// Writes `value` to the standard output stream as indented JSON with a line feed.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut text = serde_json::to_string_pretty(value).context("cannot encode the report")?;
    text.push('\n');
    print(&text)
}

/// Writes `value` to the standard output stream as one line of JSON.
pub fn print_json_line<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut text = serde_json::to_string(value).context("cannot encode the report")?;
    text.push('\n');
    print(&text)
}

/// Returns the identifiers of the ATT&CK techniques of a detection, with `, ` between them.
fn techniques(detection: &Detection) -> String {
    let ids: Vec<&str> = detection
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.join(", ")
    }
}

/// Returns one line for a detection.
pub fn detection_line(detection: &Detection) -> String {
    format!(
        "{}  {:<13}  {:<10}  {:<22}  {}  [{}]",
        detection.time.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        token(&detection.severity),
        token(&detection.verdict),
        techniques(detection),
        detection.title,
        detection.rule_id
    )
}

/// Returns the lines for an incident: one line for the incident and three for its data.
pub fn incident_lines(incident: &Incident) -> String {
    let technique_ids: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    let entities: Vec<String> = incident
        .entities
        .iter()
        .map(|entity| format!("{} {}", token(&entity.kind), entity.id))
        .collect();
    let mut text = String::new();
    let _ = writeln!(
        text,
        "{}  {:<13}  {:<14}  {}",
        incident.id,
        token(&incident.severity),
        token(&incident.status),
        incident.title
    );
    let _ = writeln!(text, "    Detections: {}", incident.detections.len());
    let _ = writeln!(text, "    Techniques: {}", technique_ids.join(", "));
    let _ = writeln!(text, "    Entities:   {}", entities.join("; "));
    text
}

/// Returns the result of an action request in a few words.
pub fn result_text(result: &DispatchResult) -> String {
    match result {
        DispatchResult::Disposition(ActionDisposition::Executed(outcome)) => format!(
            "executed: {} (connector {})",
            token(&outcome.status),
            outcome.connector
        ),
        DispatchResult::Disposition(ActionDisposition::PendingApproval { approval_id, .. }) => {
            format!("pending approval {approval_id}")
        }
        DispatchResult::Disposition(ActionDisposition::Denied(decision)) => format!(
            "denied: {}",
            decision
                .reasons
                .first()
                .map_or("the policy gives no reason", String::as_str)
        ),
        DispatchResult::Failed { kind, message, .. } => format!("failed ({kind}): {message}"),
    }
}

fn action_line(action: &ActionRecord) -> String {
    format!(
        "{:<26}  {:<46}  {:<40}  {}",
        token(&action.request.kind),
        format!(
            "{} {}",
            token(&action.request.target.kind),
            action.request.target.id
        ),
        action.request.requested_by,
        result_text(&action.result)
    )
}

/// Returns the lines for the result of a chain check.
pub fn chain_lines(verification: &ChainVerification) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "  Records checked: {}", verification.checked);
    if verification.valid {
        let _ = writeln!(text, "  Chain: valid");
    } else {
        let _ = writeln!(text, "  Chain: NOT VALID");
        if let Some(sequence) = verification.first_invalid_sequence {
            let _ = writeln!(text, "  First invalid sequence: {sequence}");
        }
        if let Some(reason) = &verification.reason {
            let _ = writeln!(text, "  Reason: {reason}");
        }
    }
    text
}

/// Returns the text form of a replay report.
pub fn replay_text(title: &str, report: &ReplayReport, audit_file: Option<&Path>) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "{title}: {} events, {}, {}",
        report.events,
        if report.dry_run {
            "dry run"
        } else {
            "LIVE: actions can change the environment"
        },
        if report.model {
            "with a model"
        } else {
            "no model"
        }
    );

    let _ = writeln!(text, "\nDetections ({})", report.detections.len());
    for detection in &report.detections {
        let _ = writeln!(text, "  {}", detection_line(detection));
    }

    let _ = writeln!(text, "\nIncidents ({})", report.incidents.len());
    for incident in &report.incidents {
        for line in incident_lines(incident).lines() {
            let _ = writeln!(text, "  {line}");
        }
    }

    let _ = writeln!(text, "\nActions ({})", report.actions.len());
    for action in &report.actions {
        let _ = writeln!(text, "  {}", action_line(action).trim_end());
    }
    if !report.actions.is_empty() {
        let changed = report
            .actions
            .iter()
            .filter(|action| action.result.changed_the_environment())
            .count();
        if changed == 0 {
            let _ = writeln!(text, "  No action changed the environment.");
        } else {
            let _ = writeln!(text, "  {changed} actions changed the environment.");
        }
    }

    if !report.playbook_runs.is_empty() {
        let _ = writeln!(text, "\nPlaybooks ({})", report.playbook_runs.len());
        for run in &report.playbook_runs {
            let requests = run
                .steps
                .iter()
                .filter(|step| step.request_id.is_some())
                .count();
            let _ = writeln!(
                text,
                "  {}: {requests} requests, {} failures",
                run.playbook,
                run.failures()
            );
        }
    }

    let _ = writeln!(text, "\nAudit log");
    let _ = writeln!(text, "  Records: {}", report.audit.records);
    text.push_str(&chain_lines(&report.audit.verification));
    if let Some(path) = audit_file {
        let _ = writeln!(text, "  File: {}", path.display());
    }
    text
}

/// Returns one line for an audit record.
pub fn audit_line(record: &AuditRecord) -> String {
    format!(
        "{:>7}  {}  {:<18}  {:<20}  {}",
        record.sequence,
        record.time.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
        token(&record.kind),
        record.actor,
        record.summary
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_contracts::action::ActionKind;
    use aegis_contracts::common::{EntityKind, Severity};
    use aegis_contracts::incident::IncidentStatus;

    use super::*;

    #[test]
    fn token_gives_the_wire_name_of_plain_and_custom_values() {
        assert_eq!(token(&Severity::Critical), "critical");
        assert_eq!(token(&IncidentStatus::FalsePositive), "false_positive");
        assert_eq!(token(&EntityKind::ServicePrincipal), "service_principal");
        assert_eq!(token(&ActionKind::BlockIp), "block_ip");
        assert_eq!(
            token(&ActionKind::Custom("quarantine_mailbox".to_owned())),
            "custom:quarantine_mailbox"
        );
        assert_eq!(token(&7), "");
    }

    #[test]
    fn the_chain_lines_name_the_first_invalid_sequence() {
        let valid = ChainVerification {
            valid: true,
            checked: 12,
            first_invalid_sequence: None,
            reason: None,
        };
        assert_eq!(
            chain_lines(&valid),
            "  Records checked: 12\n  Chain: valid\n"
        );
        let broken = ChainVerification {
            valid: false,
            checked: 4,
            first_invalid_sequence: Some(5),
            reason: Some("hash does not match the record contents".to_owned()),
        };
        assert_eq!(
            chain_lines(&broken),
            "  Records checked: 4\n  Chain: NOT VALID\n  First invalid sequence: 5\n  Reason: \
             hash does not match the record contents\n"
        );
    }
}
