//! The end-to-end acceptance test: a replay of the recorded attack log through an
//! application that is built from the starter configuration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;

use aegis_app::actions::{ActionRecord, DispatchResult, SIMULATION_CONNECTOR};
use aegis_app::report::ReplayReport;
use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::common::{EntityKind, Severity};
use aegis_contracts::event::Event;
use aegis_contracts::incident::{IncidentStatus, IncidentStore};
use aegis_contracts::policy::PrincipalKind;
use aegis_policy::FileAuditLog;
use aegis_testkit::fixtures::{self, expected};

use support::Starter;

const HONEYTOKEN_RULE_ID: &str = "0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940";

fn is_normal(event: &Event) -> bool {
    let attack_addresses = [
        Some(fixtures::SPRAY_IP),
        Some(fixtures::WORKLOAD_IP),
        Some(fixtures::DISTANT_IP),
    ];
    !attack_addresses.contains(&event.actor.ip)
}

async fn replay_attack(starter: &Starter) -> (aegis_app::App, ReplayReport) {
    let app = starter.app().await;
    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();
    (app, report)
}

fn by(report: &ReplayReport, requester: &str) -> Vec<(ActionKind, String)> {
    report
        .actions
        .iter()
        .filter(|action| action.request.requested_by == requester)
        .map(|action| {
            (
                action.request.kind.clone(),
                action.request.target.id.clone(),
            )
        })
        .collect()
}

fn simulated(action: &ActionRecord) -> bool {
    matches!(
        &action.result,
        DispatchResult::Disposition(ActionDisposition::Executed(outcome))
            if outcome.status == ActionStatus::Simulated && outcome.action_id == action.request.id
    )
}

async fn all_records(log: &dyn AuditLog) -> Vec<AuditRecord> {
    log.read(1, 100_000).await.unwrap()
}

#[tokio::test]
async fn the_replay_finds_the_five_techniques_and_the_honeytoken() {
    let starter = Starter::new();
    let (_app, report) = replay_attack(&starter).await;

    assert_eq!(report.events, fixtures::ATTACK_LOG_EVENTS as u64);
    assert!(report.dry_run);
    assert!(!report.model);
    let techniques = report.techniques();
    for technique in [
        expected::PASSWORD_SPRAY,
        expected::CONSENT_GRANT,
        expected::CREDENTIAL_ADD,
        expected::ROLE_ASSIGN,
        expected::CLOUD_ACCOUNT,
    ] {
        assert!(
            techniques.contains(technique),
            "{technique} is not in {techniques:?}"
        );
    }
    assert_eq!(report.detections.len(), 8);
    let honeytoken: Vec<_> = report
        .detections
        .iter()
        .filter(|detection| detection.rule_id == HONEYTOKEN_RULE_ID)
        .collect();
    assert_eq!(honeytoken.len(), 1);
    assert_eq!(honeytoken[0].title, "Honeytoken used");
    assert_eq!(honeytoken[0].severity, Severity::Critical);
    assert!(
        honeytoken[0]
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::ServicePrincipal
                && entity.id == fixtures::ROGUE_PRINCIPAL_ID)
    );
}

#[tokio::test]
async fn the_replay_gives_one_critical_incident_with_the_attack_entities() {
    let starter = Starter::new();
    let (app, report) = replay_attack(&starter).await;

    assert_eq!(report.incidents.len(), 1);
    let incident = &report.incidents[0];
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.tenant.as_deref(), Some(fixtures::TENANT));
    assert_eq!(incident.detections.len(), 8);
    let has = |kind: EntityKind, id: &str| {
        incident
            .entities
            .iter()
            .any(|entity| entity.kind == kind && entity.id == id)
    };
    assert!(has(EntityKind::IpAddress, &fixtures::SPRAY_IP.to_string()));
    assert!(has(EntityKind::User, fixtures::VICTIM_USER_ID));
    assert!(has(
        EntityKind::ServicePrincipal,
        fixtures::ROGUE_PRINCIPAL_ID
    ));

    // The report has the state of the store, which holds the work of the agents. The
    // actions were dry runs, so the incident is in work and not contained.
    assert_eq!(incident.status, IncidentStatus::Investigating);
    let stored = app.incidents().list(None, 10).await.unwrap();
    assert_eq!(stored, std::slice::from_ref(incident));
    let authors: BTreeSet<&str> = incident
        .timeline
        .iter()
        .map(|entry| entry.author.as_str())
        .collect();
    assert_eq!(
        authors,
        BTreeSet::from([
            "analyst",
            "correlator",
            "deception",
            "hunter",
            "reporter",
            "responder"
        ])
    );
}

#[tokio::test]
async fn the_containment_actions_go_through_the_dispatcher_as_dry_runs() {
    let starter = Starter::new();
    let (_app, report) = replay_attack(&starter).await;

    // The Responder proposes the baseline action for each attack entity, in the order in
    // which the detections name the entities.
    assert_eq!(
        by(&report, "responder"),
        [
            (ActionKind::BlockIp, fixtures::SPRAY_IP.to_string()),
            (ActionKind::KillSession, fixtures::VICTIM_USER_ID.to_owned()),
            (
                ActionKind::DisableServicePrincipal,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (
                ActionKind::RevokeCredential,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (ActionKind::BlockIp, fixtures::WORKLOAD_IP.to_string()),
            (ActionKind::BlockIp, fixtures::DISTANT_IP.to_string()),
        ]
    );
    // The request to remove the credential names the credential of the attack.
    let revoke = report
        .actions
        .iter()
        .find(|action| {
            action.request.requested_by == "responder"
                && action.request.kind == ActionKind::RevokeCredential
        })
        .unwrap();
    assert_eq!(
        revoke.request.parameters.get("credential_id"),
        Some(&serde_json::json!("credential-1"))
    );
    assert_eq!(revoke.principal.kind, PrincipalKind::Agent);
    assert_eq!(revoke.principal.id, "responder");

    // The playbooks of the operator ran one time each, with no failure.
    let playbooks: Vec<(&str, usize, usize)> = report
        .playbook_runs
        .iter()
        .map(|run| (run.playbook.as_str(), run.steps.len(), run.failures()))
        .collect();
    assert_eq!(
        playbooks,
        [
            ("block-password-spray-source", 2, 0),
            ("contain-compromised-user", 3, 0),
            ("contain-rogue-service-principal", 6, 0),
            ("respond-to-honeytoken-trip", 5, 0),
        ]
    );
    assert_eq!(
        by(&report, "playbook:contain-rogue-service-principal"),
        [
            (
                ActionKind::DisableServicePrincipal,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (
                ActionKind::RevokeCredential,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (ActionKind::KillSession, fixtures::VICTIM_USER_ID.to_owned()),
            (ActionKind::BlockIp, fixtures::SPRAY_IP.to_string()),
            (ActionKind::Notify, "security-operations".to_owned()),
            (ActionKind::OpenTicket, "incident-response".to_owned()),
        ]
    );

    // Each action of the agents and of the playbooks went through the one dispatcher. The
    // default policy permits a dry run, so each result is `executed` with the status
    // `simulated`. No action changed anything.
    assert_eq!(report.actions.len(), 23);
    for action in &report.actions {
        assert!(action.request.dry_run, "{:?}", action.request.kind);
        assert!(simulated(action), "{:?}", action.result);
    }
    assert!(!report.changed_the_environment());
    let connectors: BTreeSet<&str> = report
        .actions
        .iter()
        .filter_map(|action| match &action.result {
            DispatchResult::Disposition(ActionDisposition::Executed(outcome)) => {
                Some(outcome.connector.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        connectors,
        BTreeSet::from(["honeytokens", SIMULATION_CONNECTOR])
    );
    let sequences: Vec<u64> = report
        .actions
        .iter()
        .map(|action| action.sequence)
        .collect();
    assert_eq!(sequences, (1..=23).collect::<Vec<u64>>());
    let agents = report.agents.unwrap();
    assert_eq!(agents.actions_dispatched, 7);
    assert_eq!(agents.tasks_failed, 0);
    assert_eq!(agents.dispatch_failures, 0);
    assert_eq!(agents.audit_failures, 0);
}

#[tokio::test]
async fn the_audit_log_has_each_step_and_its_chain_verifies_from_the_file() {
    let starter = Starter::new();
    let (app, report) = replay_attack(&starter).await;

    let records = all_records(app.audit().as_ref()).await;
    assert_eq!(records.len() as u64, report.audit.records);
    let count = |kind: AuditKind| records.iter().filter(|record| record.kind == kind).count();
    // One record for the start, for each detection, and for each state of the incident.
    assert_eq!(count(AuditKind::ConfigChange), 1);
    assert_eq!(records[0].kind, AuditKind::ConfigChange);
    assert_eq!(count(AuditKind::Detection), 8);
    assert_eq!(count(AuditKind::Incident), 7);
    // Three records for each action: the proposal, the policy decision, the execution.
    assert_eq!(count(AuditKind::ActionProposed), report.actions.len());
    assert_eq!(count(AuditKind::PolicyDecision), report.actions.len());
    assert_eq!(count(AuditKind::ActionExecuted), report.actions.len());
    assert_eq!(count(AuditKind::ApprovalRequested), 0);
    for action in &report.actions {
        let id = serde_json::json!(action.request.id);
        let kinds: Vec<AuditKind> = records
            .iter()
            .filter(|record| {
                record.payload["action_id"] == id || record.payload["action"]["id"] == id
            })
            .filter(|record| {
                record.actor == "dispatcher" || record.kind == AuditKind::ActionProposed
            })
            .map(|record| record.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                AuditKind::ActionProposed,
                AuditKind::PolicyDecision,
                AuditKind::ActionExecuted
            ],
            "{:?}",
            action.request.kind
        );
    }
    let executed: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| record.kind == AuditKind::ActionExecuted)
        .collect();
    for record in executed {
        assert_eq!(record.payload["dry_run"], true);
        assert_eq!(record.payload["dry_run_violation"], false);
        assert_eq!(record.payload["outcome"]["status"], "simulated");
    }

    // The report has the result of the check. A second check reads the file on the disk
    // with no use of the open log.
    assert!(report.audit.verification.valid);
    assert_eq!(app.audit_path(), Some(starter.audit_file().as_path()));
    let from_file = FileAuditLog::verify_file(starter.audit_file()).unwrap();
    assert!(from_file.valid, "{from_file:?}");
    assert_eq!(from_file.checked, report.audit.records);
    assert_eq!(from_file.first_invalid_sequence, None);
    let lines = std::fs::read_to_string(starter.audit_file()).unwrap();
    assert_eq!(lines.lines().count() as u64, report.audit.records);
}

#[tokio::test]
async fn the_normal_events_cause_nothing() {
    let all = fixtures::artex_style_attack();
    let normal: Vec<Event> = all
        .iter()
        .filter(|event| is_normal(event))
        .cloned()
        .collect();
    assert_eq!(normal.len(), 36);

    // A replay of only the normal events: no detection, no incident, and no action.
    let starter = Starter::new();
    let app = starter.app().await;
    let report = app.replay(normal.clone()).await.unwrap();
    assert_eq!(report.events, 36);
    assert_eq!(report.detections, []);
    assert_eq!(report.incidents, []);
    assert_eq!(report.actions, []);
    assert_eq!(report.playbook_runs, []);
    assert_eq!(app.incidents().list(None, 10).await.unwrap(), []);
    assert_eq!(app.progress().monitor_events, 0);
    // The audit log has only the record of the start.
    let records = all_records(app.audit().as_ref()).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::ConfigChange);
    assert!(report.audit.verification.valid);

    // In the full replay, no detection names a normal event as its cause.
    let full = Starter::new();
    let (_app, report) = replay_attack(&full).await;
    let normal_ids: BTreeSet<_> = normal.iter().map(|event| event.id).collect();
    assert_eq!(report.detections.len(), 8);
    for detection in &report.detections {
        assert!(
            detection
                .event_ids
                .iter()
                .all(|id| !normal_ids.contains(id)),
            "{}",
            detection.rule_id
        );
    }
}

#[tokio::test]
async fn a_second_replay_of_the_same_events_changes_nothing() {
    let starter = Starter::new();
    let (app, first) = replay_attack(&starter).await;

    let second = app.replay(fixtures::artex_style_attack()).await.unwrap();

    assert_eq!(second.events, fixtures::ATTACK_LOG_EVENTS as u64);
    assert_eq!(second.incidents, []);
    assert_eq!(second.actions, []);
    assert_eq!(second.playbook_runs, []);
    assert_eq!(
        app.incidents().list(None, 10).await.unwrap(),
        first.incidents
    );
    assert!(second.audit.verification.valid);
}

#[tokio::test]
async fn the_report_is_json_that_decodes_to_the_same_report() {
    let starter = Starter::new();
    let (_app, report) = replay_attack(&starter).await;
    let text = serde_json::to_string(&report).unwrap();
    let decoded: ReplayReport = serde_json::from_str(&text).unwrap();
    assert_eq!(decoded, report);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["events"], 648);
    assert_eq!(value["audit"]["verification"]["valid"], true);
    assert_eq!(value["incidents"][0]["severity"], "critical");
}
