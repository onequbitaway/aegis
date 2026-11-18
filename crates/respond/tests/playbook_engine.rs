//! Integration tests for the playbook engine. Each request goes through the real dispatcher.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_contracts::Error;
use aegis_contracts::action::{
    ActionConnector, ActionDisposition, ActionKind, ActionOutcome, ActionRequest, ActionResult,
    ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::bus::subject;
use aegis_contracts::common::{EntityKind, EntityRef, EvidenceKind, EvidenceRef, Severity};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{ApprovalQueue, PolicyEffect};
use aegis_respond::playbook::{PLAYBOOK_PRINCIPAL_ID, PlaybookOrigin};
use aegis_respond::{
    ActionRegistry, Dispatcher, Playbook, PlaybookEngine, PlaybookError, PlaybookRun, RunMode,
    StepResult, StepRun,
};
use aegis_testkit::fixtures::TENANT;
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};
use serde_json::json;

use common::{
    ROGUE_CREDENTIAL_ID, Stack, incident_with, rogue_incident, rogue_principal,
    sample_playbook_dir, spray_address, victim_user,
};

const ROGUE_PLAYBOOK: &str = "contain-rogue-service-principal";

/// Reads one sample playbook from the `playbooks/` directory of the repository.
fn sample(name: &str) -> Playbook {
    let file = format!("{name}.yaml");
    let text = std::fs::read_to_string(sample_playbook_dir().join(&file)).unwrap();
    Playbook::from_yaml(&file, &text).unwrap()
}

fn playbook(yaml: &str) -> Playbook {
    Playbook::from_yaml("test.yaml", yaml).unwrap()
}

fn engine(stack: &Stack) -> PlaybookEngine {
    PlaybookEngine::new(stack.dispatcher.clone())
}

/// Returns the evidence that the engine puts on each request of one step.
fn step_evidence(incident: &Incident, playbook: &str, step: &str) -> Vec<EvidenceRef> {
    let mut links = vec![
        EvidenceRef::new(EvidenceKind::Incident, incident.id)
            .with_note(format!("playbook {playbook}, step {step}")),
    ];
    links.extend(incident.detections.iter().map(|detection| {
        EvidenceRef::new(EvidenceKind::Detection, detection.id).with_note(detection.rule_id.clone())
    }));
    links
}

fn executed(line: &StepRun) -> &ActionOutcome {
    match &line.result {
        StepResult::Dispatched(ActionDisposition::Executed(outcome)) => outcome,
        other => panic!(
            "step {}: expected an executed action, found {other:?}",
            line.step
        ),
    }
}

/// Returns the name of each step line with a short name of its result.
fn shape(run: &PlaybookRun) -> Vec<(String, &'static str)> {
    run.steps
        .iter()
        .map(|line| {
            let result = match &line.result {
                StepResult::Dispatched(ActionDisposition::Executed(_)) => "executed",
                StepResult::Dispatched(ActionDisposition::PendingApproval { .. }) => "pending",
                StepResult::Dispatched(ActionDisposition::Denied(_)) => "denied",
                StepResult::Failed { .. } => "failed",
                StepResult::Skipped { .. } => "skipped",
                StepResult::NotRun => "not_run",
            };
            (line.step.clone(), result)
        })
        .collect()
}

fn names(pairs: &[(&str, &'static str)]) -> Vec<(String, &'static str)> {
    pairs
        .iter()
        .map(|(step, result)| ((*step).to_owned(), *result))
        .collect()
}

/// The six requests that the rogue service principal playbook makes for the fixture incident.
fn rogue_playbook_plan() -> [(&'static str, ActionKind, EntityRef, &'static str); 6] {
    let channel = EntityRef::new(EntityKind::Other, "security-operations")
        .with_name("Security operations channel");
    let queue =
        EntityRef::new(EntityKind::Other, "incident-response").with_name("Incident response queue");
    [
        (
            "disable-service-principal",
            ActionKind::DisableServicePrincipal,
            rogue_principal(),
            "identity",
        ),
        (
            "revoke-credential",
            ActionKind::RevokeCredential,
            rogue_principal(),
            "identity",
        ),
        (
            "kill-user-sessions",
            ActionKind::KillSession,
            victim_user(),
            "identity",
        ),
        (
            "block-source-address",
            ActionKind::BlockIp,
            spray_address(),
            "firewall",
        ),
        ("notify-security-team", ActionKind::Notify, channel, "chat"),
        ("open-ticket", ActionKind::OpenTicket, queue, "chat"),
    ]
}

/// Returns the requests that the three connectors of the stack received, in step order.
///
/// The rogue service principal playbook calls the identity connector first, then the
/// firewall, then the chat connector.
fn connector_calls(stack: &Stack) -> Vec<ActionRequest> {
    let mut calls = stack.identity.executed();
    calls.extend(stack.firewall.executed());
    calls.extend(stack.chat.executed());
    calls
}

#[tokio::test]
async fn the_rogue_principal_playbook_runs_in_dry_run_through_the_dispatcher() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let playbook = sample(ROGUE_PLAYBOOK);
    let incident = rogue_incident();
    assert!(playbook.matches(&incident));

    let run = engine(&stack)
        .run(&playbook, &incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(run.playbook, ROGUE_PLAYBOOK);
    assert_eq!(run.incident_id, incident.id);
    assert_eq!(run.mode, RunMode::DryRun);
    assert_eq!(run.stopped_at, None);
    assert!(run.completed());
    assert_eq!(run.failures(), 0);
    assert!(run.started_at <= run.completed_at);

    // The report has one line for each request, in step order. Each action was simulated.
    let plan = rogue_playbook_plan();
    assert_eq!(run.steps.len(), plan.len());
    for (line, (step, action, target, connector)) in run.steps.iter().zip(&plan) {
        assert_eq!(line.step, *step);
        assert_eq!(line.action, *action, "{step}");
        assert_eq!(line.target.as_ref(), Some(target), "{step}");
        let outcome = executed(line);
        assert_eq!(outcome.status, ActionStatus::Simulated, "{step}");
        assert_eq!(outcome.connector, *connector, "{step}");
        assert_eq!(Some(outcome.action_id), line.request_id, "{step}");
    }

    // The connectors received the same requests. Each call was a dry run.
    assert_eq!(stack.identity.executed().len(), 3);
    assert_eq!(stack.firewall.executed().len(), 1);
    assert_eq!(stack.chat.executed().len(), 2);
    let requests = connector_calls(&stack);
    assert_eq!(requests.len(), plan.len());
    for (request, (line, (step, action, target, _))) in
        requests.iter().zip(run.steps.iter().zip(&plan))
    {
        assert!(request.dry_run, "{step}");
        assert_eq!(Some(request.id), line.request_id, "{step}");
        assert_eq!(request.kind, *action, "{step}");
        assert_eq!(request.target, *target, "{step}");
        assert_eq!(request.incident_id, Some(incident.id), "{step}");
        assert_eq!(
            request.requested_by,
            format!("playbook:{ROGUE_PLAYBOOK}"),
            "{step}"
        );
        assert_eq!(
            request.evidence,
            step_evidence(&incident, ROGUE_PLAYBOOK, step),
            "{step}"
        );
        assert!(
            request.reason.contains(&incident.id.to_string()),
            "{step}: {}",
            request.reason
        );
        assert!(!request.reason.contains("{{"), "{step}: {}", request.reason);
    }
    assert_eq!(stack.identity.reverted(), []);
    // The key of the credential comes from the detection of the new credential.
    assert_eq!(
        requests[1].parameters,
        BTreeMap::from([("key_id".to_owned(), json!(ROGUE_CREDENTIAL_ID))])
    );
    assert!(
        requests[0].reason.contains("Sync Helper"),
        "{}",
        requests[0].reason
    );
    assert_eq!(
        requests[3].parameters["comment"],
        json!(format!("AEGIS incident {}", incident.id))
    );

    // The audit log has three records for each request, with the evidence links.
    let records = stack.audit.records();
    assert_eq!(records.len(), 3 * plan.len());
    for (index, request) in requests.iter().enumerate() {
        let step = plan[index].0;
        let group = &records[3 * index..3 * index + 3];
        assert_eq!(
            group.iter().map(|record| record.kind).collect::<Vec<_>>(),
            [
                AuditKind::ActionProposed,
                AuditKind::PolicyDecision,
                AuditKind::ActionExecuted
            ],
            "{step}"
        );
        let mut links = vec![EvidenceRef::new(EvidenceKind::Action, request.id)];
        links.extend(step_evidence(&incident, ROGUE_PLAYBOOK, step));
        for record in group {
            assert_eq!(record.evidence, links, "{step}: {:?}", record.kind);
        }
        assert_eq!(group[0].actor, PLAYBOOK_PRINCIPAL_ID, "{step}");
        assert_eq!(group[0].payload["action"], json!(request), "{step}");
        assert_eq!(
            group[0].payload["principal"],
            json!({ "id": "playbook-engine", "kind": "system", "roles": ["playbook"] }),
            "{step}"
        );
        assert_eq!(group[0].payload["dry_run"], true, "{step}");
        assert_eq!(group[0].payload["dry_run_forced"], false, "{step}");
        assert_eq!(group[1].payload["decision"]["effect"], "allow", "{step}");
        assert_eq!(group[1].payload["action_id"], json!(request.id), "{step}");
        assert_eq!(group[2].payload["dry_run"], true, "{step}");
        assert_eq!(group[2].payload["dry_run_violation"], false, "{step}");
        assert_eq!(group[2].payload["connector"], plan[index].3, "{step}");
        assert_eq!(
            group[2].payload["outcome"],
            json!(executed(&run.steps[index])),
            "{step}"
        );
        assert!(
            group[2]
                .summary
                .ends_with("This was a dry run. Nothing changed."),
            "{step}: {}",
            group[2].summary
        );
    }
    let verification = stack.audit.verify().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checked, 18);
    assert_eq!(verification.first_invalid_sequence, None);

    // Each result is on the bus.
    let results = stack.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), plan.len());
    for (message, line) in results.iter().zip(&run.steps) {
        let result = message.decode::<ActionResult>().unwrap();
        assert_eq!(Some(result.action_id), line.request_id, "{}", line.step);
        assert_eq!(result.incident_id, Some(incident.id), "{}", line.step);
        assert_eq!(
            StepResult::Dispatched(result.disposition),
            line.result,
            "{}",
            line.step
        );
    }
}

#[tokio::test]
async fn a_live_run_sends_gated_actions_to_the_approval_queue() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let incident = rogue_incident();

    let run = engine(&stack)
        .run(&sample(ROGUE_PLAYBOOK), &incident, RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.mode, RunMode::Live);
    assert!(run.completed());
    assert_eq!(run.failures(), 0);
    assert_eq!(
        shape(&run),
        names(&[
            ("disable-service-principal", "pending"),
            ("revoke-credential", "pending"),
            ("kill-user-sessions", "pending"),
            ("block-source-address", "pending"),
            ("notify-security-team", "executed"),
            ("open-ticket", "executed"),
        ])
    );
    // No gated action reached a connector. The two automatic actions changed their targets.
    assert_eq!(stack.identity.executed(), []);
    assert_eq!(stack.firewall.executed(), []);
    let chat = stack.chat.executed();
    assert_eq!(chat.len(), 2);
    assert!(chat.iter().all(|request| !request.dry_run));
    assert_eq!(executed(&run.steps[4]).status, ActionStatus::Succeeded);
    assert_eq!(executed(&run.steps[5]).status, ActionStatus::Succeeded);

    let queued = stack.approvals.pending().await.unwrap();
    assert_eq!(queued.len(), 4);
    for line in &run.steps[..4] {
        let StepResult::Dispatched(ActionDisposition::PendingApproval {
            approval_id,
            decision,
        }) = &line.result
        else {
            panic!(
                "{}: expected a pending approval, found {:?}",
                line.step, line.result
            );
        };
        assert_eq!(
            decision.effect,
            PolicyEffect::RequireApproval,
            "{}",
            line.step
        );
        let approval = queued
            .iter()
            .find(|approval| approval.id == *approval_id)
            .unwrap_or_else(|| panic!("{}: the approval is not in the queue", line.step));
        assert_eq!(Some(approval.action.id), line.request_id, "{}", line.step);
        assert_eq!(approval.action.kind, line.action, "{}", line.step);
        assert!(!approval.action.dry_run, "{}", line.step);
        assert_eq!(approval.requested_by.id, PLAYBOOK_PRINCIPAL_ID);
    }
}

#[tokio::test]
async fn the_global_dry_run_switch_also_applies_to_a_live_playbook_run() {
    let stack = Stack::new(StaticPolicy::AllowAll, true);

    let run = engine(&stack)
        .run(&sample(ROGUE_PLAYBOOK), &rogue_incident(), RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.steps.len(), 6);
    for line in &run.steps {
        assert_eq!(
            executed(line).status,
            ActionStatus::Simulated,
            "{}",
            line.step
        );
    }
    let calls = connector_calls(&stack);
    assert_eq!(calls.len(), 6);
    assert!(calls.iter().all(|request| request.dry_run));
    let records = stack.audit.records();
    assert_eq!(records.len(), 18);
    assert_eq!(records[0].payload["dry_run_forced"], true);
}

#[tokio::test]
async fn a_denial_is_in_the_report_and_is_not_a_failure() {
    let stack = Stack::new(StaticPolicy::DenyAll, false);

    let run = engine(&stack)
        .run(&sample(ROGUE_PLAYBOOK), &rogue_incident(), RunMode::Live)
        .await
        .unwrap();

    assert!(run.completed());
    assert_eq!(run.failures(), 0);
    assert_eq!(run.steps.len(), 6);
    for line in &run.steps {
        assert!(line.request_id.is_some(), "{}", line.step);
        assert!(
            matches!(
                &line.result,
                StepResult::Dispatched(ActionDisposition::Denied(decision))
                    if decision.effect == PolicyEffect::Deny
            ),
            "{}: {:?}",
            line.step,
            line.result
        );
    }
    assert_eq!(connector_calls(&stack), []);
    assert_eq!(stack.audit.records().len(), 12);
}

/// A dispatcher with one working chat connector and one firewall that fails.
struct BrokenFirewall {
    engine: PlaybookEngine,
    firewall: Arc<RecordingConnector>,
    identity: Arc<RecordingConnector>,
    chat: Arc<RecordingConnector>,
    audit: Arc<MemoryAuditLog>,
}

fn broken_firewall() -> BrokenFirewall {
    let firewall = Arc::new(
        RecordingConnector::new("firewall", vec![ActionKind::BlockIp]).failing("firewall is down"),
    );
    let identity = Arc::new(RecordingConnector::new(
        "identity",
        vec![ActionKind::DisableUser],
    ));
    let chat = Arc::new(RecordingConnector::new("chat", vec![ActionKind::Notify]));
    let mut registry = ActionRegistry::new();
    for connector in [&firewall, &identity, &chat] {
        let connector: Arc<dyn ActionConnector> = connector.clone();
        registry.register(connector).unwrap();
    }
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();
    BrokenFirewall {
        engine: PlaybookEngine::new(Arc::new(dispatcher)),
        firewall,
        identity,
        chat,
        audit,
    }
}

const THREE_STEPS: &str = r#"
name: three-steps
description: Block the addresses, disable the users, and tell the team.
trigger:
  min_severity: low
steps:
  - id: block
    action: block_ip
    target:
      each_entity: ip_address
    reason: "Block {{target.id}}."
  - id: disable
    action: disable_user
    target:
      each_entity: user
    reason: "Disable {{target.name}}."
  - id: tell
    action: notify
    target:
      fixed:
        kind: other
        id: soc
    reason: "Tell the team about {{incident.title}}."
"#;

fn two_addresses_and_a_user() -> Incident {
    incident_with(
        Severity::High,
        &["T1110.003"],
        vec![
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
            victim_user(),
        ],
    )
}

#[tokio::test]
async fn a_failure_stops_the_run_and_the_report_names_the_steps_that_did_not_run() {
    let rig = broken_firewall();
    let incident = two_addresses_and_a_user();

    let run = rig
        .engine
        .run(&playbook(THREE_STEPS), &incident, RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.stopped_at.as_deref(), Some("block"));
    assert!(!run.completed());
    assert_eq!(run.failures(), 1);
    assert_eq!(
        shape(&run),
        names(&[
            ("block", "failed"),
            ("block", "not_run"),
            ("disable", "not_run"),
            ("tell", "not_run"),
        ])
    );
    let failed = &run.steps[0];
    assert_eq!(
        failed.target,
        Some(EntityRef::new(EntityKind::IpAddress, "203.0.113.50"))
    );
    assert_eq!(
        failed.result,
        StepResult::Failed {
            error: "unavailable: firewall is down".to_owned(),
            kind: "unavailable".to_owned(),
            retryable: true,
        }
    );
    let calls = rig.firewall.executed();
    assert_eq!(calls.len(), 1);
    assert_eq!(Some(calls[0].id), failed.request_id);
    // The second address has a line with its target and no request.
    assert_eq!(
        run.steps[1].target,
        Some(EntityRef::new(EntityKind::IpAddress, "203.0.113.51"))
    );
    assert_eq!(run.steps[1].request_id, None);
    assert_eq!(run.steps[2].target, None);
    assert_eq!(run.steps[2].request_id, None);
    assert_eq!(rig.identity.executed(), []);
    assert_eq!(rig.chat.executed(), []);
    // The dispatcher wrote the failure to the audit log.
    let records = rig.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[2].kind, AuditKind::ActionExecuted);
    assert_eq!(records[2].payload["error"]["kind"], "unavailable");
}

#[tokio::test]
async fn a_step_with_continue_on_error_does_not_stop_the_run() {
    let rig = broken_firewall();
    let incident = two_addresses_and_a_user();
    let yaml = THREE_STEPS.replace(
        "    reason: \"Block {{target.id}}.\"\n",
        "    reason: \"Block {{target.id}}.\"\n    continue_on_error: true\n",
    );
    assert_ne!(yaml, THREE_STEPS);

    let run = rig
        .engine
        .run(&playbook(&yaml), &incident, RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.stopped_at, None);
    assert!(run.completed());
    assert_eq!(run.failures(), 2);
    assert_eq!(
        shape(&run),
        names(&[
            ("block", "failed"),
            ("block", "failed"),
            ("disable", "executed"),
            ("tell", "executed"),
        ])
    );
    assert_eq!(rig.firewall.executed().len(), 2);
    let disabled = rig.identity.executed();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].target, victim_user());
    assert_eq!(disabled[0].reason, "Disable dana@contoso.example.");
    assert!(!disabled[0].dry_run);
    let told = rig.chat.executed();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].target, EntityRef::new(EntityKind::Other, "soc"));
    assert_eq!(told[0].reason, "Tell the team about Test incident.");
    assert_eq!(told[0].requested_by, "playbook:three-steps");
    assert_eq!(
        told[0].evidence,
        [EvidenceRef::new(EvidenceKind::Incident, incident.id)
            .with_note("playbook three-steps, step tell")]
    );
}

const STEPS_THAT_MAKE_NO_REQUEST: &str = r#"
name: no-request
description: Steps that the engine cannot send, and one step that it can.
trigger:
  min_severity: low
steps:
  - id: isolate
    action: isolate_host
    target:
      each_entity: host
    reason: Isolate the host.
  - id: block
    action: block_ip
    target:
      each_entity: ip_address
    max_targets: 1
    reason: Block the address.
    continue_on_error: true
  - id: revoke
    action: revoke_credential
    target:
      each_entity: service_principal
    parameters:
      key_id: "{{detection.key_reference}}"
    reason: Revoke the credential.
    continue_on_error: true
  - id: label
    action: tag
    target: incident_tenant
    reason: "Label the tenant {{target.id}}."
    continue_on_error: true
  - id: tell
    action: notify
    target:
      fixed:
        kind: other
        id: soc
    parameters:
      severity: "{{incident.severity}}"
      techniques: ["{{incident.techniques}}", 7]
    reason: "{{playbook.name}}: {{incident.status}} in {{incident.tenant}}."
"#;

#[tokio::test]
async fn a_step_that_the_engine_cannot_send_makes_no_request() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut incident = two_addresses_and_a_user();
    incident.entities.push(rogue_principal());

    let run = engine(&stack)
        .run(
            &playbook(STEPS_THAT_MAKE_NO_REQUEST),
            &incident,
            RunMode::DryRun,
        )
        .await
        .unwrap();

    assert!(run.completed());
    assert_eq!(run.failures(), 3);
    assert_eq!(
        shape(&run),
        names(&[
            ("isolate", "skipped"),
            ("block", "failed"),
            ("revoke", "failed"),
            ("label", "failed"),
            ("tell", "executed"),
        ])
    );

    // No host: the step has no target and is not a failure.
    assert_eq!(
        run.steps[0].result,
        StepResult::Skipped {
            reason: "The incident has no entity that the target selector matches.".to_owned(),
        }
    );
    assert_eq!(run.steps[0].request_id, None);

    // More targets than the limit: no request for any of them.
    assert_eq!(run.steps[1].target, None);
    assert_eq!(run.steps[1].request_id, None);
    assert_eq!(
        run.steps[1].result,
        StepResult::Failed {
            error: "the step has 2 targets; its limit (max_targets) is 1".to_owned(),
            kind: "invalid_input".to_owned(),
            retryable: false,
        }
    );
    assert_eq!(stack.firewall.executed(), []);

    // A template variable with no value: no request.
    assert_eq!(run.steps[2].target, Some(rogue_principal()));
    assert_eq!(run.steps[2].request_id, None);
    assert_eq!(
        run.steps[2].result,
        StepResult::Failed {
            error: "parameter key_id: no detection of the incident has the attribute key_reference"
                .to_owned(),
            kind: "invalid_input".to_owned(),
            retryable: false,
        }
    );
    assert_eq!(stack.identity.executed(), []);

    // No connector for the action: the dispatcher returns the error and writes it to the log.
    let label = &run.steps[3];
    assert_eq!(
        label.target,
        Some(EntityRef::new(EntityKind::Tenant, TENANT))
    );
    assert!(label.request_id.is_some());
    assert!(
        matches!(
            &label.result,
            StepResult::Failed { kind, retryable: false, error }
                if kind == "unsupported" && error.contains("Tag")
        ),
        "{:?}",
        label.result
    );

    // The last step ran. The engine filled each template.
    let told = stack.chat.executed();
    assert_eq!(told.len(), 1);
    assert!(told[0].dry_run);
    assert_eq!(told[0].reason, "no-request: open in tenant-contoso.");
    assert_eq!(
        told[0].parameters,
        BTreeMap::from([
            ("severity".to_owned(), json!("high")),
            ("techniques".to_owned(), json!(["T1110.003", 7])),
        ])
    );
    // Only the two requests that reached the dispatcher are in the audit log.
    let actions: Vec<_> = stack
        .audit
        .records()
        .iter()
        .filter(|record| record.kind == AuditKind::ActionProposed)
        .map(|record| record.payload["action"]["id"].clone())
        .collect();
    assert_eq!(
        actions,
        [json!(label.request_id), json!(run.steps[4].request_id)]
    );
}

#[tokio::test]
async fn each_entity_gives_one_request_for_each_target_in_incident_order() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut incident = two_addresses_and_a_user();
    // A second reference to the same address must not give a second request.
    incident
        .entities
        .push(EntityRef::new(EntityKind::IpAddress, "203.0.113.50").with_name("again"));

    let run = engine(&stack)
        .run(&playbook(THREE_STEPS), &incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(
        shape(&run),
        names(&[
            ("block", "executed"),
            ("block", "executed"),
            ("disable", "executed"),
            ("tell", "executed"),
        ])
    );
    let blocked = stack.firewall.executed();
    assert_eq!(
        blocked
            .iter()
            .map(|request| request.target.id.as_str())
            .collect::<Vec<_>>(),
        ["203.0.113.50", "203.0.113.51"]
    );
    assert_eq!(blocked[0].reason, "Block 203.0.113.50.");
    assert_eq!(blocked[1].reason, "Block 203.0.113.51.");
    assert_ne!(blocked[0].id, blocked[1].id);
}

#[tokio::test]
async fn a_step_with_revert_after_gives_each_request_the_timed_revert_parameter() {
    let yaml = THREE_STEPS.replace(
        "    action: block_ip\n",
        "    action: block_ip\n    revert_after: 90m\n",
    );
    let playbook = playbook(&yaml);
    assert_eq!(
        playbook
            .steps()
            .iter()
            .map(|step| step.revert_after().map(|time| time.as_secs()))
            .collect::<Vec<_>>(),
        [Some(5_400), None, None]
    );
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let incident = incident_with(
        Severity::High,
        &["T1110.003"],
        vec![
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
        ],
    );

    let run = engine(&stack)
        .run(&playbook, &incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(run.failures(), 0, "{:?}", run.steps);
    // Each request of the step has the parameter. A step with no `revert_after` has none.
    let blocks = stack.firewall.executed();
    assert_eq!(blocks.len(), 2);
    for block in &blocks {
        assert_eq!(
            block.parameters.get("revert_after_seconds"),
            Some(&json!(5_400)),
            "{}",
            block.target.id
        );
    }
    let others = stack.chat.executed();
    assert!(!others.is_empty());
    for other in &others {
        assert_eq!(other.parameters.get("revert_after_seconds"), None);
    }
}

#[tokio::test]
async fn matching_selects_the_playbooks_whose_trigger_is_true() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut engine = engine(&stack);
    engine.add(playbook(THREE_STEPS)).unwrap();
    let high_only = THREE_STEPS
        .replace("name: three-steps", "name: critical-only")
        .replace("min_severity: low", "min_severity: critical");
    engine.add(playbook(&high_only)).unwrap();
    let other_tenant = THREE_STEPS
        .replace("name: three-steps", "name: other-tenant")
        .replace(
            "  min_severity: low\n",
            "  min_severity: low\n  tenants: [tenant-fabrikam]\n",
        );
    engine.add(playbook(&other_tenant)).unwrap();

    let mut incident = two_addresses_and_a_user();
    let matched = |engine: &PlaybookEngine, incident: &Incident| -> Vec<String> {
        engine
            .matching(incident)
            .iter()
            .map(|playbook| playbook.name().to_owned())
            .collect()
    };

    assert_eq!(matched(&engine, &incident), ["three-steps"]);
    incident.severity = Severity::Critical;
    assert_eq!(
        matched(&engine, &incident),
        ["three-steps", "critical-only"]
    );
    incident.tenant = Some("tenant-fabrikam".to_owned());
    assert_eq!(
        matched(&engine, &incident),
        ["three-steps", "critical-only", "other-tenant"]
    );
    incident.status = IncidentStatus::Resolved;
    assert_eq!(matched(&engine, &incident), Vec::<String>::new());

    assert_eq!(
        engine
            .playbooks()
            .iter()
            .map(Playbook::name)
            .collect::<Vec<_>>(),
        ["three-steps", "critical-only", "other-tenant"]
    );
    assert_eq!(
        engine.playbook("critical-only").map(Playbook::origin),
        Some(&PlaybookOrigin::Operator)
    );
    assert!(engine.playbook("unknown").is_none());
}

#[tokio::test]
async fn run_matching_runs_each_matching_playbook() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut engine = engine(&stack);
    engine.add(playbook(THREE_STEPS)).unwrap();
    let critical_only = THREE_STEPS
        .replace("name: three-steps", "name: critical-only")
        .replace("min_severity: low", "min_severity: critical");
    engine.add(playbook(&critical_only)).unwrap();
    let incident = two_addresses_and_a_user();

    let runs = engine
        .run_matching(&incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].playbook, "three-steps");
    assert_eq!(runs[0].steps.len(), 4);
    assert_eq!(connector_calls(&stack).len(), 4);

    let mut resolved = incident;
    resolved.status = IncidentStatus::Resolved;
    let none = engine
        .run_matching(&resolved, RunMode::DryRun)
        .await
        .unwrap();
    assert_eq!(none, []);
    assert_eq!(connector_calls(&stack).len(), 4);
}

#[tokio::test]
async fn a_second_playbook_with_the_same_name_is_rejected() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut engine = engine(&stack);
    engine.add(playbook(THREE_STEPS)).unwrap();

    let error = engine.add(playbook(THREE_STEPS)).unwrap_err();

    assert!(
        matches!(&error, Error::Config(message) if message == "a playbook with the name three-steps is already loaded"),
        "{error:?}"
    );
    assert_eq!(engine.playbooks().len(), 1);
}

#[tokio::test]
async fn load_dir_loads_valid_files_and_rejects_the_others_with_the_file_name() {
    let directory = tempfile::tempdir().unwrap();
    let write = |file: &str, text: &str| std::fs::write(directory.path().join(file), text).unwrap();
    write("10-three-steps.yaml", THREE_STEPS);
    write(
        "20-unknown-action.yaml",
        &THREE_STEPS
            .replace("name: three-steps", "name: unknown-action")
            .replace("action: block_ip", "action: launch_counter_attack"),
    );
    write(
        "30-second.YML",
        &THREE_STEPS.replace("name: three-steps", "name: second"),
    );
    write("40-duplicate.yaml", THREE_STEPS);
    write("50-not-yaml.yaml", "steps: [unclosed");
    write("notes.txt", "This file is not a playbook.");
    std::fs::create_dir(directory.path().join("60-directory.yaml")).unwrap();

    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut engine = engine(&stack);
    let report = engine.load_dir(directory.path()).await.unwrap();

    assert_eq!(report.loaded, ["three-steps", "second"]);
    assert_eq!(
        engine
            .playbooks()
            .iter()
            .map(Playbook::name)
            .collect::<Vec<_>>(),
        ["three-steps", "second"]
    );
    assert_eq!(report.rejected.len(), 3);
    let rejected: Vec<(String, String)> = report
        .rejected
        .iter()
        .map(|error| match error {
            PlaybookError::Invalid { file, reason } => (file.clone(), reason.clone()),
            other => panic!("expected an invalid playbook, found {other:?}"),
        })
        .collect();
    assert_eq!(rejected[0].0, "20-unknown-action.yaml");
    assert!(
        rejected[0].1.contains("launch_counter_attack"),
        "{}",
        rejected[0].1
    );
    assert_eq!(
        rejected[1],
        (
            "40-duplicate.yaml".to_owned(),
            "configuration error: a playbook with the name three-steps is already loaded"
                .to_owned()
        )
    );
    assert_eq!(rejected[2].0, "50-not-yaml.yaml");
    assert!(
        report.rejected[0]
            .to_string()
            .starts_with("playbook 20-unknown-action.yaml: "),
        "{}",
        report.rejected[0]
    );
}

#[tokio::test]
async fn load_dir_rejects_a_file_that_is_too_large_and_reports_a_missing_directory() {
    let directory = tempfile::tempdir().unwrap();
    let padding = format!("# {}\n", "x".repeat(1022)).repeat(257);
    std::fs::write(
        directory.path().join("large.yaml"),
        format!("{padding}{THREE_STEPS}"),
    )
    .unwrap();
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut engine = engine(&stack);

    let report = engine.load_dir(directory.path()).await.unwrap();

    assert_eq!(report.loaded, Vec::<String>::new());
    assert_eq!(report.rejected.len(), 1);
    assert!(
        matches!(
            &report.rejected[0],
            PlaybookError::Invalid { file, reason }
                if file == "large.yaml" && reason.ends_with("the limit is 262144")
        ),
        "{:?}",
        report.rejected[0]
    );

    let missing = directory.path().join("no-such-directory");
    let error = engine.load_dir(&missing).await.unwrap_err();
    assert!(
        matches!(
            &error,
            PlaybookError::Io { file, source }
                if file == &missing.display().to_string()
                    && source.kind() == std::io::ErrorKind::NotFound
        ),
        "{error:?}"
    );
    assert_eq!(engine.playbooks().len(), 0);
}
