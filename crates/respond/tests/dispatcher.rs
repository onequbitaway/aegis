//! Integration tests for the dispatcher: policy, approval, execution, audit, and the bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification};
use aegis_contracts::bus::{BusStream, MessageBus, subject};
use aegis_contracts::common::{
    ApprovalId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, IncidentContext, PolicyDecision,
    PolicyEffect, PolicyEngine, PolicyInput, Principal, PrincipalKind,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use aegis_respond::dispatcher::{DISPATCHER_ACTOR, FAIL_CLOSED_POLICY};
use aegis_respond::{ActionRegistry, Dispatcher};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use common::{
    Stack, records_for, request, responder, rogue_incident, rogue_principal, spray_address,
};

fn approver() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

fn disable_request() -> ActionRequest {
    request(ActionKind::DisableServicePrincipal, rogue_principal())
}

/// A policy engine with an effect that the test can change. It records each input.
struct SwitchPolicy {
    effect: Mutex<std::result::Result<PolicyEffect, String>>,
    inputs: Mutex<Vec<PolicyInput>>,
}

impl SwitchPolicy {
    fn new(effect: PolicyEffect) -> Self {
        Self {
            effect: Mutex::new(Ok(effect)),
            inputs: Mutex::default(),
        }
    }

    fn failing(message: &str) -> Self {
        Self {
            effect: Mutex::new(Err(message.to_owned())),
            inputs: Mutex::default(),
        }
    }

    fn set(&self, effect: PolicyEffect) {
        *self.effect.lock().unwrap() = Ok(effect);
    }

    fn inputs(&self) -> Vec<PolicyInput> {
        self.inputs.lock().unwrap().clone()
    }
}

#[async_trait]
impl PolicyEngine for SwitchPolicy {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision> {
        self.inputs.lock().unwrap().push(input.clone());
        match self.effect.lock().unwrap().clone() {
            Ok(effect) => Ok(PolicyDecision {
                effect,
                tier: input.default_tier,
                reasons: vec!["The switch policy decided.".to_owned()],
                policy: Some("test.switch".to_owned()),
                evaluated_at: Utc::now(),
            }),
            Err(message) => Err(Error::Unavailable(message)),
        }
    }
}

/// An audit log that fails for the record kinds that the test selects.
#[derive(Default)]
struct SelectiveAudit {
    inner: MemoryAuditLog,
    failing: Mutex<Vec<AuditKind>>,
}

impl SelectiveAudit {
    fn fail_on(&self, kind: AuditKind) {
        self.failing.lock().unwrap().push(kind);
    }
}

#[async_trait]
impl AuditLog for SelectiveAudit {
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord> {
        if self.failing.lock().unwrap().contains(&entry.kind) {
            return Err(Error::Unavailable("the audit store is down".to_owned()));
        }
        self.inner.append(entry).await
    }

    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
        self.inner.read(from_sequence, limit).await
    }

    async fn verify(&self) -> Result<ChainVerification> {
        self.inner.verify().await
    }
}

/// A bus that refuses each message.
struct DownBus;

#[async_trait]
impl MessageBus for DownBus {
    async fn publish(&self, _subject: &str, _payload: Vec<u8>) -> Result<()> {
        Err(Error::Unavailable("the bus is down".to_owned()))
    }

    async fn subscribe(&self, _pattern: &str, _durable: Option<&str>) -> Result<BusStream> {
        Err(Error::Unavailable("the bus is down".to_owned()))
    }
}

/// An incident store that fails each read.
struct DownIncidents;

#[async_trait]
impl IncidentStore for DownIncidents {
    async fn save(&self, _incident: &Incident) -> Result<()> {
        Err(Error::Unavailable("the incident store is down".to_owned()))
    }

    async fn get(&self, _id: IncidentId) -> Result<Option<Incident>> {
        Err(Error::Unavailable("the incident store is down".to_owned()))
    }

    async fn list(&self, _status: Option<IncidentStatus>, _limit: usize) -> Result<Vec<Incident>> {
        Err(Error::Unavailable("the incident store is down".to_owned()))
    }
}

/// How a [`ScriptedConnector`] answers.
#[derive(Clone, Copy)]
enum Behavior {
    /// Never completes.
    Hang,
    /// Reports that it changed the target, also in a dry run.
    IgnoreDryRun,
}

struct ScriptedConnector {
    behavior: Behavior,
    calls: Mutex<Vec<ActionRequest>>,
}

impl ScriptedConnector {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            calls: Mutex::default(),
        }
    }
}

#[async_trait]
impl ActionConnector for ScriptedConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "scripted".to_owned(),
            vendor: "test".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::BlockIp]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.calls.lock().unwrap().push(request.clone());
        match self.behavior {
            Behavior::Hang => std::future::pending().await,
            Behavior::IgnoreDryRun => Ok(ActionOutcome {
                action_id: request.id,
                status: ActionStatus::Succeeded,
                connector: "scripted".to_owned(),
                message: "Changed the target.".to_owned(),
                details: serde_json::Value::Null,
                reversible: false,
                completed_at: Utc::now(),
            }),
        }
    }
}

/// A connector that waits in each call until the test releases it.
struct GateConnector {
    started: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    calls: Mutex<Vec<ActionRequest>>,
}

impl GateConnector {
    fn new() -> Self {
        Self {
            started: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            calls: Mutex::default(),
        }
    }
}

#[async_trait]
impl ActionConnector for GateConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "gate".to_owned(),
            vendor: "test".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::DisableServicePrincipal]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.calls.lock().unwrap().push(request.clone());
        self.started.add_permits(1);
        let permit = self
            .release
            .acquire()
            .await
            .map_err(|error| Error::other("gate", error))?;
        permit.forget();
        Ok(ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Succeeded,
            connector: "gate".to_owned(),
            message: "Changed the target.".to_owned(),
            details: serde_json::Value::Null,
            reversible: true,
            completed_at: Utc::now(),
        })
    }
}

fn registry_with(connector: Arc<dyn ActionConnector>) -> Arc<ActionRegistry> {
    let mut registry = ActionRegistry::new();
    registry.register(connector).unwrap();
    Arc::new(registry)
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

#[tokio::test]
async fn an_allowed_action_runs_and_each_step_is_in_the_audit_log() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let mut action = disable_request();
    let incident_id = IncidentId::new();
    action.incident_id = Some(incident_id);
    action.evidence = vec![EvidenceRef::new(EvidenceKind::Detection, "detection-7")];

    let disposition = stack
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.connector, "identity");
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(stack.identity.executed(), vec![action.clone()]);

    let records = stack.audit.records();
    assert_eq!(
        stack.audit_kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    let links = vec![
        EvidenceRef::new(EvidenceKind::Action, action.id),
        EvidenceRef::new(EvidenceKind::Incident, incident_id),
        EvidenceRef::new(EvidenceKind::Detection, "detection-7"),
    ];
    for record in &records {
        assert_eq!(record.evidence, links, "{:?}", record.kind);
    }
    assert_eq!(records[0].actor, "responder");
    assert_eq!(records[0].payload["action"], json!(action));
    assert_eq!(records[0].payload["principal"]["id"], "responder");
    assert_eq!(records[0].payload["dry_run"], false);
    assert_eq!(records[1].actor, DISPATCHER_ACTOR);
    assert_eq!(records[1].payload["decision"]["effect"], "allow");
    assert_eq!(records[1].payload["decision"]["policy"], "testkit.static");
    assert_eq!(records[1].payload["fail_closed"], false);
    assert_eq!(records[2].payload["connector"], "identity");
    assert_eq!(records[2].payload["dry_run"], false);
    assert_eq!(records[2].payload["outcome"], json!(outcome));
    assert_eq!(
        records[2].summary,
        "Connector identity completed the action disable_service_principal on service_principal sp-sync-helper with the status succeeded."
    );

    let verification = stack.audit.verify().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checked, 3);

    let results = stack.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].decode::<ActionDisposition>().unwrap(),
        disposition
    );
}

#[tokio::test]
async fn a_denied_action_does_not_reach_a_connector() {
    let stack = Stack::new(StaticPolicy::DenyAll, false);
    let action = disable_request();

    let disposition = stack
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    match &disposition {
        ActionDisposition::Denied(decision) => {
            assert_eq!(decision.effect, PolicyEffect::Deny);
            assert_eq!(decision.policy.as_deref(), Some("testkit.static"));
        }
        other => panic!("expected a denial, found {other:?}"),
    }
    assert_eq!(stack.identity.executed(), []);
    assert_eq!(
        stack.audit_kinds(),
        [AuditKind::ActionProposed, AuditKind::PolicyDecision]
    );
    let records = stack.audit.records();
    assert_eq!(records[1].payload["decision"]["effect"], "deny");
    assert_eq!(
        records[1].summary,
        "Policy denies the action disable_service_principal on service_principal sp-sync-helper."
    );
    assert!(stack.approvals.pending().await.unwrap().is_empty());
    let results = stack.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].decode::<ActionDisposition>().unwrap(),
        disposition
    );
}

#[tokio::test]
async fn a_gated_action_waits_in_the_approval_queue() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let action = disable_request();

    let disposition = stack
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    let approval_id = pending(&disposition);
    assert_eq!(stack.identity.executed(), []);
    let queued = stack.approvals.pending().await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, approval_id);
    assert_eq!(queued[0].action, action);
    assert_eq!(queued[0].requested_by, responder());
    assert_eq!(queued[0].status, ApprovalStatus::Pending);
    assert_eq!(queued[0].decision.effect, PolicyEffect::RequireApproval);
    assert_eq!(queued[0].decision.tier, ActionTier::Gated);

    assert_eq!(
        stack.audit_kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ApprovalRequested
        ]
    );
    let records = stack.audit.records();
    assert_eq!(records[2].payload["approval_id"], json!(approval_id));
    assert_eq!(records[2].payload["action_id"], json!(action.id));
    assert_eq!(
        records[2].evidence,
        [EvidenceRef::new(EvidenceKind::Action, action.id)]
    );

    let announced = stack.bus.published_to(subject::APPROVALS);
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].decode::<ApprovalRequest>().unwrap(), queued[0]);
    let results = stack.bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].decode::<ActionDisposition>().unwrap(),
        disposition
    );
}

#[tokio::test]
async fn resume_runs_an_approved_action_one_time() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let action = disable_request();
    let approval_id = pending(
        &stack
            .dispatcher
            .dispatch(action.clone(), &responder())
            .await
            .unwrap(),
    );
    stack
        .approvals
        .decide(approval_id, true, &approver(), Some("Go.".to_owned()))
        .await
        .unwrap();

    let disposition = stack.dispatcher.resume(approval_id).await.unwrap();

    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(stack.identity.executed(), vec![action.clone()]);
    assert_eq!(
        stack.audit_kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ApprovalRequested,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    let records = stack.audit.records();
    assert_eq!(records[3].payload["approval"]["id"], json!(approval_id));
    assert_eq!(records[4].payload["approval"]["id"], json!(approval_id));
    assert_eq!(
        records[4].payload["approval"]["decided_by"],
        "alice@example.com"
    );
    assert_eq!(records[4].payload["outcome"]["status"], "succeeded");
    assert_eq!(records_for(&records, &action).len(), 5);
    assert!(stack.audit.verify().await.unwrap().valid);

    let second = stack.dispatcher.resume(approval_id).await.unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.contains("already ran")),
        "{second:?}"
    );
    assert_eq!(stack.identity.executed().len(), 1);
    assert_eq!(stack.audit.records().len(), 5);
}

#[tokio::test]
async fn resume_rejects_a_request_that_is_pending_rejected_or_unknown() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let waiting = pending(
        &stack
            .dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    let refused = pending(
        &stack
            .dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    stack
        .approvals
        .decide(refused, false, &approver(), None)
        .await
        .unwrap();
    let records_before = stack.audit.records().len();

    let pending_error = stack.dispatcher.resume(waiting).await.unwrap_err();
    assert!(
        matches!(&pending_error, Error::InvalidInput(message) if message.contains("has no decision")),
        "{pending_error:?}"
    );
    let rejected_error = stack.dispatcher.resume(refused).await.unwrap_err();
    assert!(
        matches!(&rejected_error, Error::Denied(message) if message.contains("was rejected")),
        "{rejected_error:?}"
    );
    let unknown_error = stack
        .dispatcher
        .resume(ApprovalId::new())
        .await
        .unwrap_err();
    assert!(
        matches!(unknown_error, Error::NotFound(_)),
        "{unknown_error:?}"
    );

    assert_eq!(stack.identity.executed(), []);
    assert_eq!(stack.audit.records().len(), records_before);
}

#[tokio::test]
async fn an_approval_cannot_run_again_after_a_restart() {
    let (identity, _, _) = common::recording_connectors();
    let registry = registry_with(identity.clone());
    let approvals = Arc::new(MemoryApprovals::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let build = || {
        Dispatcher::builder(
            registry.clone(),
            Arc::new(StaticPolicy::ByTier),
            approvals.clone(),
            audit.clone(),
        )
        .build()
    };
    let first = build();
    let approval_id = pending(
        &first
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    approvals
        .decide(approval_id, true, &approver(), None)
        .await
        .unwrap();
    executed(&first.resume(approval_id).await.unwrap());
    drop(first);

    let after_restart = build();
    let error = after_restart.resume(approval_id).await.unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("already ran")),
        "{error:?}"
    );
    assert_eq!(identity.executed().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_second_resume_fails_while_the_first_resume_is_in_progress() {
    let connector = Arc::new(GateConnector::new());
    let approvals = Arc::new(MemoryApprovals::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(
            registry_with(connector.clone()),
            Arc::new(StaticPolicy::ByTier),
            approvals.clone(),
            audit.clone(),
        )
        .build(),
    );
    let approval_id = pending(
        &dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    approvals
        .decide(approval_id, true, &approver(), None)
        .await
        .unwrap();

    // The first resume reaches the connector and waits there. The audit log has no
    // execution record at this time.
    let first = tokio::spawn({
        let dispatcher = dispatcher.clone();
        async move { dispatcher.resume(approval_id).await }
    });
    let wait = Duration::from_secs(5);
    tokio::time::timeout(wait, connector.started.acquire())
        .await
        .expect("the first resume did not reach the connector")
        .unwrap()
        .forget();
    assert_eq!(
        audit
            .records()
            .iter()
            .filter(|record| record.kind == AuditKind::ActionExecuted)
            .count(),
        0
    );

    let second = tokio::time::timeout(wait, dispatcher.resume(approval_id))
        .await
        .expect("the second resume must fail immediately")
        .unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.contains("already ran")),
        "{second:?}"
    );

    connector.release.add_permits(1);
    let disposition = tokio::time::timeout(wait, first)
        .await
        .expect("the first resume did not complete")
        .unwrap()
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(connector.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_attempt_uses_the_approval() {
    let failing: Arc<RecordingConnector> = Arc::new(
        RecordingConnector::new("identity", vec![ActionKind::DisableServicePrincipal])
            .failing("graph is down"),
    );
    let approvals = Arc::new(MemoryApprovals::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(failing.clone()),
        Arc::new(StaticPolicy::ByTier),
        approvals.clone(),
        audit.clone(),
    )
    .build();
    let approval_id = pending(
        &dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    approvals
        .decide(approval_id, true, &approver(), None)
        .await
        .unwrap();

    let first = dispatcher.resume(approval_id).await.unwrap_err();
    assert!(
        matches!(&first, Error::Unavailable(message) if message == "graph is down"),
        "{first:?}"
    );
    let second = dispatcher.resume(approval_id).await.unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.contains("already ran")),
        "{second:?}"
    );
    assert_eq!(failing.executed().len(), 1);
}

#[tokio::test]
async fn resume_evaluates_the_policy_again() {
    let (identity, _, _) = common::recording_connectors();
    let policy = Arc::new(SwitchPolicy::new(PolicyEffect::RequireApproval));
    let approvals = Arc::new(MemoryApprovals::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(identity.clone()),
        policy.clone(),
        approvals.clone(),
        audit.clone(),
    )
    .build();
    let action = disable_request();
    let approval_id = pending(
        &dispatcher
            .dispatch(action.clone(), &responder())
            .await
            .unwrap(),
    );
    approvals
        .decide(approval_id, true, &approver(), None)
        .await
        .unwrap();

    policy.set(PolicyEffect::Deny);
    let denied = dispatcher.resume(approval_id).await.unwrap();
    assert!(
        matches!(&denied, ActionDisposition::Denied(decision) if decision.effect == PolicyEffect::Deny),
        "{denied:?}"
    );
    assert_eq!(identity.executed(), []);
    let inputs = policy.inputs();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[1].action, action);
    assert_eq!(inputs[1].principal, responder());

    policy.set(PolicyEffect::RequireApproval);
    let disposition = dispatcher.resume(approval_id).await.unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(identity.executed(), vec![action]);
}

#[tokio::test]
async fn a_policy_error_is_a_denial() {
    let (identity, _, _) = common::recording_connectors();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(identity.clone()),
        Arc::new(SwitchPolicy::failing("the policy bundle did not load")),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();

    let disposition = dispatcher
        .dispatch(disable_request(), &responder())
        .await
        .unwrap();

    let ActionDisposition::Denied(decision) = &disposition else {
        panic!("expected a denial, found {disposition:?}");
    };
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.tier, ActionTier::Gated);
    assert_eq!(decision.policy.as_deref(), Some(FAIL_CLOSED_POLICY));
    assert_eq!(
        decision.reasons,
        [
            "The policy evaluation failed, so the dispatcher denies the action: unavailable: the policy bundle did not load."
        ]
    );
    assert_eq!(identity.executed(), []);

    let records = audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [AuditKind::ActionProposed, AuditKind::PolicyDecision]
    );
    assert_eq!(records[1].payload["fail_closed"], true);
    assert_eq!(records[1].payload["error"]["kind"], "unavailable");
    assert_eq!(
        records[1].payload["error"]["message"],
        "unavailable: the policy bundle did not load"
    );
    assert_eq!(records[1].payload["decision"]["effect"], "deny");
}

#[tokio::test]
async fn an_incident_store_error_is_a_denial() {
    let (identity, _, _) = common::recording_connectors();
    let policy = Arc::new(SwitchPolicy::new(PolicyEffect::Allow));
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(identity.clone()),
        policy.clone(),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .incidents(Arc::new(DownIncidents))
    .build();
    let mut action = disable_request();
    action.incident_id = Some(IncidentId::new());

    let disposition = dispatcher.dispatch(action, &responder()).await.unwrap();

    assert!(
        matches!(&disposition, ActionDisposition::Denied(decision) if decision.policy.as_deref() == Some(FAIL_CLOSED_POLICY)),
        "{disposition:?}"
    );
    assert_eq!(policy.inputs().len(), 0);
    assert_eq!(identity.executed(), []);
    assert_eq!(
        audit.records()[1].payload["error"]["message"],
        "unavailable: the incident store is down"
    );
}

#[tokio::test]
async fn the_policy_gets_the_incident_and_the_environment() {
    let (identity, _, _) = common::recording_connectors();
    let policy = Arc::new(SwitchPolicy::new(PolicyEffect::Allow));
    let incidents = Arc::new(aegis_testkit::MemoryIncidents::default());
    let mut incident = rogue_incident();
    incident.status = IncidentStatus::Investigating;
    incidents.save(&incident).await.unwrap();
    let dispatcher = Dispatcher::builder(
        registry_with(identity),
        policy.clone(),
        Arc::new(MemoryApprovals::default()),
        Arc::new(MemoryAuditLog::default()),
    )
    .incidents(incidents)
    .environment(json!({ "maintenance_window": false }))
    .build();

    let mut known = disable_request();
    known.incident_id = Some(incident.id);
    dispatcher
        .dispatch(known.clone(), &responder())
        .await
        .unwrap();
    let mut unknown = disable_request();
    unknown.incident_id = Some(IncidentId::new());
    dispatcher.dispatch(unknown, &responder()).await.unwrap();
    dispatcher
        .dispatch(disable_request(), &responder())
        .await
        .unwrap();

    let inputs = policy.inputs();
    assert_eq!(inputs.len(), 3);
    assert_eq!(
        inputs[0].incident,
        Some(IncidentContext {
            id: incident.id,
            severity: Severity::Critical,
            status: IncidentStatus::Investigating,
        })
    );
    assert_eq!(inputs[0].action, known);
    assert_eq!(inputs[0].principal, responder());
    assert_eq!(inputs[0].default_tier, ActionTier::Gated);
    assert_eq!(
        inputs[0].environment,
        json!({ "maintenance_window": false })
    );
    assert_eq!(inputs[1].incident, None);
    assert_eq!(inputs[2].incident, None);
}

#[tokio::test]
async fn a_connector_error_is_in_the_audit_log_and_goes_to_the_caller() {
    let failing: Arc<RecordingConnector> = Arc::new(
        RecordingConnector::new("firewall", vec![ActionKind::BlockIp]).failing("firewall is down"),
    );
    let audit = Arc::new(MemoryAuditLog::default());
    let bus = Arc::new(aegis_testkit::MemoryBus::default());
    let dispatcher = Dispatcher::builder(
        registry_with(failing.clone()),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .bus(bus.clone())
    .build();
    let action = request(ActionKind::BlockIp, spray_address());

    let error = dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message) if message == "firewall is down"),
        "{error:?}"
    );
    assert_eq!(failing.executed(), vec![action.clone()]);
    let records = audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    assert_eq!(records[2].payload["connector"], "firewall");
    assert_eq!(
        records[2].payload["error"],
        json!({ "kind": "unavailable", "message": "unavailable: firewall is down", "retryable": true })
    );
    assert_eq!(records[2].payload.get("outcome"), None);
    assert_eq!(
        records[2].summary,
        "Connector firewall could not complete the action block_ip on ip_address 203.0.113.50."
    );
    assert_eq!(
        records[2].evidence,
        [EvidenceRef::new(EvidenceKind::Action, action.id)]
    );
    assert!(audit.verify().await.unwrap().valid);

    let results = bus.published_to(subject::ACTION_RESULTS);
    assert_eq!(results.len(), 1);
    let published = results[0].decode::<ActionDisposition>().unwrap();
    let outcome = executed(&published);
    assert_eq!(outcome.status, ActionStatus::Failed);
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(outcome.connector, "firewall");
    assert_eq!(outcome.message, "unavailable: firewall is down");
}

#[tokio::test]
async fn an_action_with_no_connector_is_unsupported() {
    let stack = Stack::new(StaticPolicy::AllowAll, false);
    let action = request(
        ActionKind::IsolateHost,
        EntityRef::new(EntityKind::Host, "host-1"),
    );

    let error = stack
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unsupported(message) if message.contains("IsolateHost")),
        "{error:?}"
    );
    assert_eq!(
        stack.audit_kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    let records = stack.audit.records();
    assert_eq!(records[2].payload["connector"], json!(null));
    assert_eq!(records[2].payload["error"]["kind"], "unsupported");
    assert_eq!(
        records[2].summary,
        "No connector can do the action isolate_host on host host-1."
    );
}

#[tokio::test]
async fn a_gated_action_with_no_connector_does_not_enter_the_approval_queue() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let action = request(
        ActionKind::IsolateHost,
        EntityRef::new(EntityKind::Host, "host-1"),
    );

    let error = stack
        .dispatcher
        .dispatch(action, &responder())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Unsupported(_)), "{error:?}");
    assert!(stack.approvals.pending().await.unwrap().is_empty());
    assert_eq!(
        stack.audit_kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
}

#[tokio::test]
async fn the_global_dry_run_switch_forces_a_dry_run() {
    let stack = Stack::new(StaticPolicy::AllowAll, true);
    assert!(stack.dispatcher.dry_run());
    let action = disable_request();
    assert!(!action.dry_run);

    let disposition = stack
        .dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Simulated);
    let received = stack.identity.executed();
    assert_eq!(received.len(), 1);
    assert!(received[0].dry_run);
    assert_eq!(received[0].id, action.id);

    let records = stack.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].payload["dry_run"], true);
    assert_eq!(records[0].payload["dry_run_forced"], true);
    assert_eq!(records[0].payload["action"]["dry_run"], true);
    assert_eq!(records[2].payload["dry_run"], true);
    assert_eq!(records[2].payload["dry_run_violation"], false);
    assert_eq!(records[2].payload["outcome"]["status"], "simulated");
    assert_eq!(
        records[2].summary,
        "Connector identity simulated the action disable_service_principal on service_principal sp-sync-helper. This was a dry run. Nothing changed."
    );

    stack.dispatcher.set_dry_run(false);
    assert!(!stack.dispatcher.dry_run());
    let live = stack
        .dispatcher
        .dispatch(disable_request(), &responder())
        .await
        .unwrap();
    assert_eq!(executed(&live).status, ActionStatus::Succeeded);
    assert_eq!(stack.audit.records()[3].payload["dry_run_forced"], false);
}

#[tokio::test]
async fn the_global_dry_run_switch_also_applies_to_resume() {
    let stack = Stack::new(StaticPolicy::ByTier, false);
    let approval_id = pending(
        &stack
            .dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap(),
    );
    stack
        .approvals
        .decide(approval_id, true, &approver(), None)
        .await
        .unwrap();
    stack.dispatcher.set_dry_run(true);

    let disposition = stack.dispatcher.resume(approval_id).await.unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Simulated);
    let received = stack.identity.executed();
    assert_eq!(received.len(), 1);
    assert!(received[0].dry_run);
}

#[tokio::test]
async fn a_connector_that_ignores_the_dry_run_flag_is_reported() {
    let connector = Arc::new(ScriptedConnector::new(Behavior::IgnoreDryRun));
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(connector.clone()),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .dry_run(true)
    .build();

    let disposition = dispatcher
        .dispatch(request(ActionKind::BlockIp, spray_address()), &responder())
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    let records = audit.records();
    assert_eq!(records[2].payload["dry_run"], true);
    assert_eq!(records[2].payload["dry_run_violation"], true);
    assert_eq!(
        records[2].summary,
        "Connector scripted did not obey the dry-run flag for the action block_ip on ip_address 203.0.113.50."
    );
}

#[tokio::test(start_paused = true)]
async fn a_connector_that_does_not_answer_times_out() {
    let connector = Arc::new(ScriptedConnector::new(Behavior::Hang));
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(connector.clone()),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .execution_timeout(Duration::from_secs(45))
    .build();
    let action = request(ActionKind::BlockIp, spray_address());

    let error = dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Timeout(message) if message == &format!("connector scripted did not complete the action {} in 45 seconds", action.id)),
        "{error:?}"
    );
    assert_eq!(connector.calls.lock().unwrap().len(), 1);
    let records = audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[2].kind, AuditKind::ActionExecuted);
    assert_eq!(records[2].payload["error"]["kind"], "timeout");
    assert_eq!(records[2].payload["error"]["retryable"], true);
}

#[tokio::test]
async fn an_action_that_the_audit_log_cannot_record_does_not_run() {
    for failing_kind in [AuditKind::ActionProposed, AuditKind::PolicyDecision] {
        let (identity, _, _) = common::recording_connectors();
        let audit = Arc::new(SelectiveAudit::default());
        audit.fail_on(failing_kind);
        let dispatcher = Dispatcher::builder(
            registry_with(identity.clone()),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .build();

        let error = dispatcher
            .dispatch(disable_request(), &responder())
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::Unavailable(message) if message == "the audit store is down"),
            "{failing_kind:?}: {error:?}"
        );
        assert_eq!(identity.executed(), [], "{failing_kind:?}");
    }
}

#[tokio::test]
async fn a_missing_audit_record_after_the_action_is_an_integrity_error() {
    let (identity, _, _) = common::recording_connectors();
    let audit = Arc::new(SelectiveAudit::default());
    audit.fail_on(AuditKind::ActionExecuted);
    let dispatcher = Dispatcher::builder(
        registry_with(identity.clone()),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();
    let action = disable_request();

    let error = dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap_err();

    assert_eq!(identity.executed().len(), 1);
    assert!(
        matches!(&error, Error::Integrity(message) if message == &format!("connector identity completed the action {} but the audit log did not record it: unavailable: the audit store is down", action.id)),
        "{error:?}"
    );
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn a_bus_failure_does_not_change_the_result() {
    let (identity, _, _) = common::recording_connectors();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        registry_with(identity.clone()),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .bus(Arc::new(DownBus))
    .build();
    let action = disable_request();

    let disposition = dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    let records = audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted,
            AuditKind::Other
        ]
    );
    assert_eq!(records[3].payload["subject"], subject::ACTION_RESULTS);
    assert_eq!(
        records[3].payload["error"]["message"],
        "unavailable: the bus is down"
    );
    assert_eq!(records[3].payload["action_id"], json!(action.id));
}
