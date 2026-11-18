//! Integration tests for `Dispatcher::revert`: the lookup in the audit log, policy,
//! approval, the connector call, the audit records, and the bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionResult, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::bus::subject;
use aegis_contracts::common::{
    ActionId, ApprovalId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId,
};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalStatus, PolicyDecision, PolicyEffect, PolicyEngine,
    PolicyInput, Principal, PrincipalKind,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use aegis_respond::dispatcher::{DISPATCHER_ACTOR, REVERT_OPERATION};
use aegis_respond::revert::{EXECUTION_DETAILS_PARAMETER, REVERT_ACTION, REVERTS_PARAMETER};
use aegis_respond::{ActionRegistry, Dispatcher};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, MemoryBus, StaticPolicy};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use common::{
    ToggleConnector, alice, request, responder, revert_records, rogue_principal, victim_user,
};

const REASON: &str = "The account is not compromised. Enable it again.";

/// A policy that gives one effect to a revert and a different effect to all other actions.
struct RevertPolicy {
    actions: PolicyEffect,
    reverts: Mutex<PolicyEffect>,
    inputs: Mutex<Vec<PolicyInput>>,
}

impl RevertPolicy {
    fn new(actions: PolicyEffect, reverts: PolicyEffect) -> Self {
        Self {
            actions,
            reverts: Mutex::new(reverts),
            inputs: Mutex::default(),
        }
    }

    fn set_reverts(&self, effect: PolicyEffect) {
        *self.reverts.lock().unwrap() = effect;
    }

    fn inputs(&self) -> Vec<PolicyInput> {
        self.inputs.lock().unwrap().clone()
    }
}

#[async_trait]
impl PolicyEngine for RevertPolicy {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision> {
        self.inputs.lock().unwrap().push(input.clone());
        let is_revert = input.action.kind == ActionKind::Custom(REVERT_ACTION.to_owned());
        let effect = if is_revert {
            *self.reverts.lock().unwrap()
        } else {
            self.actions
        };
        Ok(PolicyDecision {
            effect,
            tier: input.default_tier,
            reasons: vec!["The revert policy decided.".to_owned()],
            policy: Some("test.revert".to_owned()),
            evaluated_at: Utc::now(),
        })
    }
}

/// A connector that does not implement `revert`. It uses the default of the contract.
struct NoRevertConnector {
    /// What the connector reports in `ActionOutcome::reversible`.
    claims_reversible: bool,
    calls: Mutex<Vec<ActionRequest>>,
}

impl NoRevertConnector {
    fn new(claims_reversible: bool) -> Self {
        Self {
            claims_reversible,
            calls: Mutex::default(),
        }
    }
}

#[async_trait]
impl ActionConnector for NoRevertConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "one-way".to_owned(),
            vendor: "test".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::DisableUser]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.calls.lock().unwrap().push(request.clone());
        Ok(ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Succeeded,
            connector: "one-way".to_owned(),
            message: "Disabled the account.".to_owned(),
            details: serde_json::Value::Null,
            reversible: self.claims_reversible,
            completed_at: Utc::now(),
        })
    }
}

/// One dispatcher with a connector that the test controls.
struct Rig {
    dispatcher: Arc<Dispatcher>,
    connector: Arc<ToggleConnector>,
    audit: Arc<MemoryAuditLog>,
    approvals: Arc<MemoryApprovals>,
    bus: Arc<MemoryBus>,
    registry: Arc<ActionRegistry>,
}

fn toggle() -> Arc<ToggleConnector> {
    Arc::new(ToggleConnector::new(
        "identity",
        vec![ActionKind::DisableUser, ActionKind::DisableServicePrincipal],
    ))
}

fn rig_with(policy: Arc<dyn PolicyEngine>, dry_run: bool) -> Rig {
    let connector = toggle();
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let registry = Arc::new(registry);
    let audit = Arc::new(MemoryAuditLog::default());
    let approvals = Arc::new(MemoryApprovals::default());
    let bus = Arc::new(MemoryBus::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(registry.clone(), policy, approvals.clone(), audit.clone())
            .bus(bus.clone())
            .dry_run(dry_run)
            .build(),
    );
    Rig {
        dispatcher,
        connector,
        audit,
        approvals,
        bus,
        registry,
    }
}

fn rig() -> Rig {
    rig_with(Arc::new(StaticPolicy::AllowAll), false)
}

fn disable_user() -> ActionRequest {
    request(ActionKind::DisableUser, victim_user())
}

fn executed(disposition: &ActionDisposition) -> &ActionOutcome {
    match disposition {
        ActionDisposition::Executed(outcome) => outcome,
        other => panic!("expected an executed action, found {other:?}"),
    }
}

fn pending(disposition: &ActionDisposition) -> ApprovalId {
    match disposition {
        ActionDisposition::PendingApproval { approval_id, .. } => *approval_id,
        other => panic!("expected a pending approval, found {other:?}"),
    }
}

fn kinds(records: &[AuditRecord]) -> Vec<AuditKind> {
    records.iter().map(|record| record.kind).collect()
}

/// Dispatches `action` and asserts that the connector changed the target.
async fn run(rig: &Rig, action: &ActionRequest) -> ActionOutcome {
    let disposition = rig
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();
    let outcome = executed(&disposition).clone();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    outcome
}

#[tokio::test]
async fn a_revert_undoes_the_action_and_links_each_audit_record() {
    let rig = rig();
    let mut action = disable_user();
    let incident_id = IncidentId::new();
    action.incident_id = Some(incident_id);
    action.evidence = vec![EvidenceRef::new(EvidenceKind::Detection, "detection-7")];
    let executed_outcome = run(&rig, &action).await;

    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();

    // The result is the outcome of the revert request, which is a request of its own.
    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.connector, "identity");
    assert_ne!(outcome.action_id, action.id);
    assert!(!outcome.reversible);
    assert_eq!(outcome.details["reverted_action_id"], json!(action.id));
    assert_eq!(
        outcome.details["connector_details"],
        json!({ "saved_state": "enabled" })
    );

    // The connector got the initial request, with the details of its outcome.
    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    let mut expected = action.clone();
    expected.parameters.insert(
        EXECUTION_DETAILS_PARAMETER.to_owned(),
        executed_outcome.details.clone(),
    );
    assert_eq!(reverted[0], expected);
    assert_eq!(rig.connector.changes(), vec![action.clone()]);

    // Three records for the action, then three records for the revert.
    let records = rig.audit.records();
    assert_eq!(
        kinds(&records),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted,
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted,
        ]
    );
    let revert = revert_records(&records);
    assert_eq!(revert.len(), 3);
    assert_eq!(revert, records[3..]);
    let links = vec![
        EvidenceRef::new(EvidenceKind::Action, outcome.action_id),
        EvidenceRef::new(EvidenceKind::Incident, incident_id),
        EvidenceRef::new(EvidenceKind::Action, action.id)
            .with_note("The action that this request reverts."),
        EvidenceRef::new(EvidenceKind::Detection, "detection-7"),
    ];
    for record in &revert {
        assert_eq!(record.evidence, links, "{:?}", record.kind);
        assert_eq!(record.payload["operation"], REVERT_OPERATION);
        assert_eq!(record.payload["reverts"]["action_id"], json!(action.id));
        assert_eq!(record.payload["reverts"]["kind"], "disable_user");
        assert_eq!(record.payload["reverts"]["target"], json!(action.target));
    }
    // The records of the action itself have no revert mark.
    for record in &records[..3] {
        assert_eq!(record.payload.get("operation"), None, "{:?}", record.kind);
    }

    let proposed = &revert[0];
    assert_eq!(proposed.actor, "alice@example.com");
    assert_eq!(
        proposed.summary,
        "alice@example.com proposed the revert of the action disable_user on user user-dana."
    );
    assert_eq!(proposed.payload["action"]["id"], json!(outcome.action_id));
    assert_eq!(
        proposed.payload["action"]["kind"],
        json!({ "custom": "revert" })
    );
    assert_eq!(proposed.payload["action"]["reason"], REASON);
    assert_eq!(
        proposed.payload["action"]["requested_by"],
        "alice@example.com"
    );
    assert_eq!(proposed.payload["principal"], json!(alice()));
    assert_eq!(proposed.payload["dry_run"], false);

    let decided = &revert[1];
    assert_eq!(decided.actor, DISPATCHER_ACTOR);
    assert_eq!(
        decided.summary,
        "Policy permits the revert of the action disable_user on user user-dana."
    );
    assert_eq!(decided.payload["action_id"], json!(outcome.action_id));
    assert_eq!(decided.payload["decision"]["effect"], "allow");

    let done = &revert[2];
    assert_eq!(done.kind, AuditKind::ActionExecuted);
    assert_eq!(done.actor, DISPATCHER_ACTOR);
    assert_eq!(
        done.summary,
        "Connector identity completed the revert of the action disable_user on user user-dana with the status succeeded."
    );
    assert_eq!(done.payload["action_id"], json!(outcome.action_id));
    assert_eq!(done.payload["connector"], "identity");
    assert_eq!(done.payload["dry_run"], false);
    assert_eq!(done.payload["dry_run_violation"], false);
    assert_eq!(done.payload["outcome"], json!(outcome));

    let verification = rig.audit.verify().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checked, 6);

    // The result of the revert is on the bus, after the result of the action.
    let results = rig.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[1].decode::<ActionResult>().unwrap(),
        ActionResult {
            action_id: outcome.action_id,
            incident_id: Some(incident_id),
            disposition,
        }
    );
}

#[tokio::test]
async fn the_policy_gets_a_revert_request_that_names_the_action() {
    let policy = Arc::new(RevertPolicy::new(PolicyEffect::Allow, PolicyEffect::Allow));
    let rig = rig_with(policy.clone(), false);
    let action = disable_user();
    let executed_outcome = run(&rig, &action).await;

    rig.dispatcher
        .revert(action.id, &alice(), "  Undo\nit.  ")
        .await
        .unwrap();

    let inputs = policy.inputs();
    assert_eq!(inputs.len(), 2);
    let input = &inputs[1];
    assert_eq!(input.principal, alice());
    // A revert is a custom action, so an existing rule for `disable_user` does not match it
    // and its default tier is `gated`.
    assert_eq!(input.action.kind, ActionKind::Custom("revert".to_owned()));
    assert_eq!(input.default_tier, ActionTier::Gated);
    assert_eq!(input.action.target, action.target);
    assert_eq!(input.action.requested_by, "alice@example.com");
    // The reason is one line with no control characters.
    assert_eq!(input.action.reason, "Undo it.");
    assert!(!input.action.dry_run);
    assert_eq!(
        input.action.parameters[REVERTS_PARAMETER],
        json!({
            "action_id": action.id,
            "kind": "disable_user",
            "requested_by": "responder",
            "connector": "identity",
            "executed_at": executed_outcome.completed_at,
        })
    );
}

#[tokio::test]
async fn one_execution_can_be_reverted_one_time() {
    let rig = rig();
    let action = disable_user();
    run(&rig, &action).await;
    executed(
        &rig.dispatcher
            .revert(action.id, &alice(), REASON)
            .await
            .unwrap(),
    );

    let second = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    assert!(
        matches!(&second, Error::InvalidInput(message)
            if message.contains("was reverted before; one execution can be reverted one time")),
        "{second:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 1);
    // The refused request is in the audit log: the proposal and the refusal.
    let records = rig.audit.records();
    assert_eq!(records.len(), 8);
    assert_eq!(records[6].kind, AuditKind::ActionProposed);
    assert_eq!(records[7].kind, AuditKind::ActionExecuted);
    assert_eq!(
        records[7].summary,
        "The dispatcher refused the revert of the action disable_user on user user-dana."
    );
    assert_eq!(records[7].payload["error"]["kind"], "invalid_input");
    assert_eq!(records[7].payload["operation"], "revert");
    assert_eq!(records[7].payload["connector"], json!(null));
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test]
async fn a_second_revert_fails_after_a_restart() {
    let first = rig();
    let action = disable_user();
    run(&first, &action).await;
    executed(
        &first
            .dispatcher
            .revert(action.id, &alice(), REASON)
            .await
            .unwrap(),
    );

    // A new dispatcher has no memory of the revert. It reads the audit log.
    let after_restart = Dispatcher::builder(
        first.registry.clone(),
        Arc::new(StaticPolicy::AllowAll),
        first.approvals.clone(),
        first.audit.clone(),
    )
    .build();
    let error = after_restart
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("was reverted before")),
        "{error:?}"
    );
    assert_eq!(first.connector.reverted().len(), 1);
}

#[tokio::test]
async fn an_action_from_before_a_restart_can_be_reverted() {
    let first = rig();
    let action = disable_user();
    run(&first, &action).await;

    let after_restart = Dispatcher::builder(
        first.registry.clone(),
        Arc::new(StaticPolicy::AllowAll),
        first.approvals.clone(),
        first.audit.clone(),
    )
    .build();
    let disposition = after_restart
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(first.connector.reverted().len(), 1);
    assert_eq!(first.connector.reverted()[0].id, action.id);
}

#[tokio::test]
async fn a_dry_run_has_nothing_to_revert() {
    let rig = rig();
    let mut action = disable_user();
    action.dry_run = true;
    let disposition = rig
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Simulated);

    let error = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.contains("was a dry run; a dry run has nothing to revert")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
}

#[tokio::test]
async fn an_action_that_did_not_change_the_target_has_nothing_to_revert() {
    // A connector error: the action did not complete.
    let rig = rig();
    rig.connector.fail_execute(Some("graph is down"));
    let failed = disable_user();
    let error = rig
        .dispatcher
        .dispatch(failed.clone(), &responder())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
    let error = rig
        .dispatcher
        .revert(failed.id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.contains("did not complete, so there is nothing to revert")),
        "{error:?}"
    );

    // The connector found that no change was necessary.
    rig.connector.fail_execute(None);
    rig.connector.set_live_status(ActionStatus::Skipped);
    let skipped = disable_user();
    rig.dispatcher
        .dispatch(skipped.clone(), &responder())
        .await
        .unwrap();
    let error = rig
        .dispatcher
        .revert(skipped.id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.contains("has the status skipped; it did not change the target")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
}

#[tokio::test]
async fn an_action_that_the_audit_log_does_not_hold_is_not_found() {
    let rig = rig();
    let records_before = rig.audit.records().len();

    let unknown = rig
        .dispatcher
        .revert(ActionId::new(), &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&unknown, Error::NotFound(message) if message.starts_with("the audit log has no action ")),
        "{unknown:?}"
    );
    assert_eq!(rig.audit.records().len(), records_before);

    // A request that waits for approval did not run.
    let gated = rig_with(Arc::new(StaticPolicy::ByTier), false);
    let waiting = disable_user();
    pending(
        &gated
            .dispatcher
            .dispatch(waiting.clone(), &responder())
            .await
            .unwrap(),
    );
    let not_run = gated
        .dispatcher
        .revert(waiting.id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&not_run, Error::NotFound(message)
            if message.starts_with("the audit log has no execution of the action ")),
        "{not_run:?}"
    );
    assert_eq!(gated.connector.reverted(), []);
}

#[tokio::test]
async fn a_connector_with_no_revert_gives_unsupported() {
    for claims_reversible in [false, true] {
        let connector = Arc::new(NoRevertConnector::new(claims_reversible));
        let mut registry = ActionRegistry::new();
        registry.register(connector.clone()).unwrap();
        let audit = Arc::new(MemoryAuditLog::default());
        let dispatcher = Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .build();
        let action = disable_user();
        let disposition = dispatcher
            .dispatch(action.clone(), &responder())
            .await
            .unwrap();
        assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);

        let error = dispatcher
            .revert(action.id, &alice(), REASON)
            .await
            .unwrap_err();

        let expected = if claims_reversible {
            // The default `revert` of the contract answers.
            "connector one-way cannot revert action"
        } else {
            // The dispatcher reads the outcome of the execution and does not call the
            // connector.
            "connector one-way reported that it cannot undo the action"
        };
        assert!(
            matches!(&error, Error::Unsupported(message) if message.contains(expected)),
            "{claims_reversible}: {error:?}"
        );
        assert_eq!(connector.calls.lock().unwrap().len(), 1);
        let records = audit.records();
        let last = records.last().unwrap();
        assert_eq!(last.kind, AuditKind::ActionExecuted);
        assert_eq!(last.payload["operation"], "revert");
        assert_eq!(last.payload["error"]["kind"], "unsupported");
        // The action is not reverted, so a later revert is not "reverted before".
        let again = dispatcher
            .revert(action.id, &alice(), REASON)
            .await
            .unwrap_err();
        assert!(matches!(again, Error::Unsupported(_)), "{again:?}");
    }
}

#[tokio::test]
async fn a_connector_that_is_not_in_the_registry_gives_unsupported() {
    let first = rig();
    let action = disable_user();
    run(&first, &action).await;

    // The new registry has a connector with a different name for the same action type.
    let other = Arc::new(ToggleConnector::new(
        "identity-2",
        vec![ActionKind::DisableUser],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(other.clone()).unwrap();
    let after_change = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        first.approvals.clone(),
        first.audit.clone(),
    )
    .build();
    let error = after_change
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unsupported(message)
            if message.contains("connector identity did the action") && message.contains("is not in the registry")),
        "{error:?}"
    );
    // The revert never goes to a connector that did not do the action.
    assert_eq!(other.reverted(), []);
}

#[tokio::test]
async fn a_denied_revert_does_not_reach_the_connector_and_does_not_use_the_one_time() {
    let policy = Arc::new(RevertPolicy::new(PolicyEffect::Allow, PolicyEffect::Deny));
    let rig = rig_with(policy.clone(), false);
    let action = disable_user();
    run(&rig, &action).await;

    let denied = rig
        .dispatcher
        .revert(action.id, &responder(), REASON)
        .await
        .unwrap();

    assert!(
        matches!(&denied, ActionDisposition::Denied(decision) if decision.effect == PolicyEffect::Deny),
        "{denied:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
    let records = rig.audit.records();
    assert_eq!(
        kinds(&records[3..]),
        [AuditKind::ActionProposed, AuditKind::PolicyDecision]
    );
    assert_eq!(
        records[4].summary,
        "Policy denies the revert of the action disable_user on user user-dana."
    );
    // The denial is on the bus with the identifier of the revert request.
    let results = rig.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 2);
    let result = results[1].decode::<ActionResult>().unwrap();
    assert_eq!(json!(result.action_id), records[3].payload["action"]["id"]);
    assert_eq!(result.disposition, denied);

    // The policy changes. The revert is still possible.
    policy.set_reverts(PolicyEffect::Allow);
    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(rig.connector.reverted().len(), 1);
}

#[tokio::test]
async fn a_gated_revert_waits_for_approval_and_resume_runs_it_one_time() {
    let policy = Arc::new(RevertPolicy::new(
        PolicyEffect::Allow,
        PolicyEffect::RequireApproval,
    ));
    let rig = rig_with(policy, false);
    let action = disable_user();
    run(&rig, &action).await;
    let requester = Principal::new("bob@example.com", PrincipalKind::Human, &["analyst"]);

    let disposition = rig
        .dispatcher
        .revert(action.id, &requester, REASON)
        .await
        .unwrap();

    let approval_id = pending(&disposition);
    assert_eq!(rig.connector.reverted(), []);
    let queued = rig.approvals.pending().await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, approval_id);
    assert_eq!(queued[0].status, ApprovalStatus::Pending);
    assert_eq!(queued[0].requested_by, requester);
    assert_eq!(
        queued[0].action.kind,
        ActionKind::Custom("revert".to_owned())
    );
    assert_eq!(
        queued[0].action.parameters[REVERTS_PARAMETER]["action_id"],
        json!(action.id)
    );
    let records = rig.audit.records();
    assert_eq!(
        kinds(&records[3..]),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ApprovalRequested
        ]
    );
    assert_eq!(records[5].payload["operation"], "revert");
    assert_eq!(
        records[5].summary,
        format!(
            "The revert of the action disable_user on user user-dana waits for the approval {approval_id}."
        )
    );

    // A person approves. The dispatcher then undoes the action.
    rig.approvals
        .decide(approval_id, true, &alice(), None)
        .await
        .unwrap();
    let resumed = rig.dispatcher.resume(approval_id).await.unwrap();

    let outcome = executed(&resumed);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, queued[0].action.id);
    assert_eq!(outcome.details["reverted_action_id"], json!(action.id));
    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action.id);
    assert_eq!(reverted[0].kind, ActionKind::DisableUser);
    let records = rig.audit.records();
    assert_eq!(
        kinds(&records[6..]),
        [AuditKind::PolicyDecision, AuditKind::ActionExecuted]
    );
    assert_eq!(records[7].payload["operation"], "revert");
    assert_eq!(records[7].payload["approval"]["id"], json!(approval_id));
    assert_eq!(
        records[7].payload["approval"]["decided_by"],
        "alice@example.com"
    );
    assert!(rig.audit.verify().await.unwrap().valid);

    // One approval permits one revert, and the action is now reverted.
    let second = rig.dispatcher.resume(approval_id).await.unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.contains("already ran")),
        "{second:?}"
    );
    let again = rig
        .dispatcher
        .revert(action.id, &requester, REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(message) if message.contains("was reverted before")),
        "{again:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 1);
}

#[tokio::test]
async fn an_approved_revert_of_an_action_that_is_reverted_uses_the_approval() {
    let policy = Arc::new(RevertPolicy::new(
        PolicyEffect::Allow,
        PolicyEffect::RequireApproval,
    ));
    let rig = rig_with(policy.clone(), false);
    let action = disable_user();
    run(&rig, &action).await;
    let approval_id = pending(
        &rig.dispatcher
            .revert(action.id, &responder(), REASON)
            .await
            .unwrap(),
    );
    // A different revert runs before the approval.
    policy.set_reverts(PolicyEffect::Allow);
    executed(
        &rig.dispatcher
            .revert(action.id, &alice(), REASON)
            .await
            .unwrap(),
    );
    rig.approvals
        .decide(approval_id, true, &alice(), None)
        .await
        .unwrap();

    let error = rig.dispatcher.resume(approval_id).await.unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("was reverted before")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 1);
    let records = rig.audit.records();
    let last = records.last().unwrap();
    assert_eq!(last.payload["approval"]["id"], json!(approval_id));
    assert_eq!(last.payload["error"]["kind"], "invalid_input");
    let second = rig.dispatcher.resume(approval_id).await.unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.contains("already ran")),
        "{second:?}"
    );
}

#[tokio::test]
async fn a_revert_that_fails_is_in_the_audit_log_and_can_run_again() {
    let rig = rig();
    let action = disable_user();
    run(&rig, &action).await;
    rig.connector.fail_revert(Some("graph is down"));

    let error = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message) if message == "graph is down"),
        "{error:?}"
    );
    let records = rig.audit.records();
    assert_eq!(records.len(), 6);
    assert_eq!(records[5].kind, AuditKind::ActionExecuted);
    assert_eq!(
        records[5].summary,
        "Connector identity could not complete the revert of the action disable_user on user user-dana."
    );
    assert_eq!(records[5].payload["operation"], "revert");
    assert_eq!(records[5].payload["error"]["kind"], "unavailable");
    assert_eq!(records[5].payload["error"]["retryable"], true);
    // The bus has a result with the status `failed` for the revert request.
    let results = rig.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 2);
    let failed = results[1].decode::<ActionResult>().unwrap();
    assert_eq!(executed(&failed.disposition).status, ActionStatus::Failed);

    rig.connector.fail_revert(None);
    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(rig.connector.reverted().len(), 2);
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test]
async fn with_the_global_dry_run_switch_a_revert_changes_nothing() {
    let rig = rig();
    let action = disable_user();
    run(&rig, &action).await;
    rig.dispatcher.set_dry_run(true);

    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Simulated);
    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert!(reverted[0].dry_run);
    let records = rig.audit.records();
    assert_eq!(records[3].payload["dry_run"], true);
    assert_eq!(records[3].payload["dry_run_forced"], true);
    assert_eq!(
        records[5].summary,
        "Connector identity simulated the revert of the action disable_user on user user-dana. This was a dry run. Nothing changed."
    );

    // The dry run did not use the one time.
    rig.dispatcher.set_dry_run(false);
    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert!(!rig.connector.reverted()[1].dry_run);
}

#[tokio::test]
async fn a_revert_cannot_be_reverted_and_needs_a_reason() {
    let rig = rig();
    let action = disable_user();
    run(&rig, &action).await;

    let no_reason = rig
        .dispatcher
        .revert(action.id, &alice(), " \n ")
        .await
        .unwrap_err();
    assert!(
        matches!(&no_reason, Error::InvalidInput(message) if message.ends_with("needs a reason")),
        "{no_reason:?}"
    );
    assert_eq!(rig.audit.records().len(), 3);

    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap();
    let revert_id = executed(&disposition).action_id;

    let error = rig
        .dispatcher
        .revert(revert_id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("is a revert; a revert cannot be reverted")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 1);
}

#[tokio::test]
async fn dispatch_refuses_the_reserved_revert_action_type() {
    // A connector that claims the reserved type does not change the rule.
    let claims = Arc::new(ToggleConnector::new(
        "claims-revert",
        vec![ActionKind::Custom(REVERT_ACTION.to_owned())],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(claims.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();
    let mut forged = ActionRequest::new(
        ActionKind::Custom(REVERT_ACTION.to_owned()),
        rogue_principal(),
        "responder",
        "Enable the service principal.",
    );
    forged.parameters.insert(
        REVERTS_PARAMETER.to_owned(),
        json!({ "action_id": ActionId::new() }),
    );

    let error = dispatcher.dispatch(forged, &responder()).await.unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.contains("custom:revert is reserved; call Dispatcher::revert")),
        "{error:?}"
    );
    assert_eq!(claims.executed(), []);
    // The proposal and the refusal are in the audit log. The policy did not run.
    let records = audit.records();
    assert_eq!(
        kinds(&records),
        [AuditKind::ActionProposed, AuditKind::ActionExecuted]
    );
    assert_eq!(
        records[1].summary,
        "The dispatcher refused the action custom:revert on service_principal sp-sync-helper."
    );
}

#[tokio::test]
async fn two_different_requests_with_one_identifier_cannot_be_reverted() {
    let rig = rig();
    let action = disable_user();
    run(&rig, &action).await;
    // A second request uses the same identifier for a different target.
    let mut other = request(
        ActionKind::DisableUser,
        EntityRef::new(EntityKind::User, "user-admin"),
    );
    other.id = action.id;
    run(&rig, &other).await;

    let error = rig
        .dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();

    // The dispatcher cannot know which target to restore, so it restores none.
    assert!(
        matches!(&error, Error::Integrity(message)
            if message.contains("has two different requests with the identifier")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted(), []);

    // The same request two times is not a conflict.
    let twice = disable_user();
    run(&rig, &twice).await;
    run(&rig, &twice).await;
    let disposition = rig
        .dispatcher
        .revert(twice.id, &alice(), REASON)
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(rig.connector.reverted().len(), 1);
}

/// A connector whose `revert` waits until the test releases it.
struct SlowRevert {
    started: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

#[async_trait]
impl ActionConnector for SlowRevert {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "slow".to_owned(),
            vendor: "test".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::DisableUser]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        Ok(ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Succeeded,
            connector: "slow".to_owned(),
            message: "Disabled the account.".to_owned(),
            details: serde_json::Value::Null,
            reversible: true,
            completed_at: Utc::now(),
        })
    }

    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.started.add_permits(1);
        let permit = self
            .release
            .acquire()
            .await
            .map_err(|error| Error::other("slow", error))?;
        permit.forget();
        Ok(ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Succeeded,
            connector: "slow".to_owned(),
            message: "Enabled the account.".to_owned(),
            details: serde_json::Value::Null,
            reversible: true,
            completed_at: Utc::now(),
        })
    }
}

#[tokio::test]
async fn a_second_revert_fails_while_the_first_revert_is_in_progress() {
    let connector = Arc::new(SlowRevert {
        started: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            Arc::new(MemoryAuditLog::default()),
        )
        .build(),
    );
    let action = disable_user();
    dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    let first = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let id = action.id;
        async move { dispatcher.revert(id, &alice(), REASON).await }
    });
    connector.started.acquire().await.unwrap().forget();

    let second = dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.ends_with("is in progress")),
        "{second:?}"
    );

    connector.release.add_permits(1);
    let disposition = first.await.unwrap().unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    let third = dispatcher
        .revert(action.id, &alice(), REASON)
        .await
        .unwrap_err();
    assert!(
        matches!(&third, Error::InvalidInput(message) if message.contains("was reverted before")),
        "{third:?}"
    );
}

#[tokio::test]
async fn the_target_of_an_approved_revert_must_be_the_target_of_the_action() {
    let policy = Arc::new(RevertPolicy::new(
        PolicyEffect::Allow,
        PolicyEffect::RequireApproval,
    ));
    let rig = rig_with(policy, false);
    let action = disable_user();
    run(&rig, &action).await;
    let approval_id = pending(
        &rig.dispatcher
            .revert(action.id, &responder(), REASON)
            .await
            .unwrap(),
    );
    // A request in the queue that names a different target is not the request that the
    // dispatcher made.
    let mut forged = rig.approvals.get(approval_id).await.unwrap().unwrap();
    forged.id = ApprovalId::new();
    forged.action.target = EntityRef::new(EntityKind::User, "user-harmless");
    rig.approvals.submit(forged.clone()).await.unwrap();
    rig.approvals
        .decide(forged.id, true, &alice(), None)
        .await
        .unwrap();

    let error = rig.dispatcher.resume(forged.id).await.unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.contains("names the target user user-harmless") && message.contains("changed user user-dana")),
        "{error:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
}
