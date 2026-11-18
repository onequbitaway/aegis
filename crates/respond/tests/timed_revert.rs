//! Integration tests for the timed revert: the pending reverts, their stores, and the
//! scheduler. The tests drive the time with the paused Tokio clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::bus::subject;
use aegis_contracts::common::{ActionId, ApprovalId, EvidenceKind, EvidenceRef, IncidentId};
use aegis_contracts::policy::{
    ApprovalQueue, PolicyDecision, PolicyEffect, PolicyEngine, PolicyInput, Principal,
    PrincipalKind,
};
use aegis_contracts::{Error, Result};
use aegis_respond::revert::{
    MAX_REVERT_AFTER_SECONDS, REVERT_ACTION, REVERT_AFTER_PARAMETER, SCHEDULER_ACTOR,
    SCHEDULER_PRINCIPAL_ID, event,
};
use aegis_respond::{
    ActionRegistry, Dispatcher, FileRevertStore, MemoryRevertStore, PendingRevert, PendingState,
    RevertClock, RevertProgress, RevertScheduler, RevertSchedulerConfig, RevertStats, RevertStore,
};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, MemoryBus, StaticPolicy};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;

use common::{
    ToggleConnector, alice, events, playbook_engine, request, responder, revert_records, timed,
    victim_user,
};

/// A policy with one effect for the initial actions and one effect for the reverts.
struct TwoPolicy {
    actions: PolicyEffect,
    reverts: Mutex<PolicyEffect>,
    inputs: Mutex<Vec<PolicyInput>>,
}

impl TwoPolicy {
    fn new(actions: PolicyEffect, reverts: PolicyEffect) -> Arc<Self> {
        Arc::new(Self {
            actions,
            reverts: Mutex::new(reverts),
            inputs: Mutex::default(),
        })
    }

    fn set_reverts(&self, effect: PolicyEffect) {
        *self.reverts.lock().unwrap() = effect;
    }

    fn inputs(&self) -> Vec<PolicyInput> {
        self.inputs.lock().unwrap().clone()
    }
}

#[async_trait]
impl PolicyEngine for TwoPolicy {
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
            reasons: vec!["The test policy decided.".to_owned()],
            policy: Some("test.two".to_owned()),
            evaluated_at: Utc::now(),
        })
    }
}

/// A store that the test can make fail.
#[derive(Default)]
struct FlakyStore {
    inner: MemoryRevertStore,
    fail_put: AtomicBool,
}

#[async_trait]
impl RevertStore for FlakyStore {
    async fn put(&self, revert: PendingRevert) -> Result<()> {
        if self.fail_put.load(Ordering::SeqCst) {
            return Err(Error::Unavailable("the disk is full".to_owned()));
        }
        self.inner.put(revert).await
    }

    async fn get(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        self.inner.get(action_id).await
    }

    async fn remove(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        self.inner.remove(action_id).await
    }

    async fn list(&self) -> Result<Vec<PendingRevert>> {
        self.inner.list().await
    }
}

/// One dispatcher with a revert store, its scheduler, and a connector that the test
/// controls.
struct Rig {
    dispatcher: Arc<Dispatcher>,
    scheduler: RevertScheduler,
    connector: Arc<ToggleConnector>,
    audit: Arc<MemoryAuditLog>,
    approvals: Arc<MemoryApprovals>,
    bus: Arc<MemoryBus>,
}

fn toggle() -> Arc<ToggleConnector> {
    Arc::new(ToggleConnector::new(
        "identity",
        vec![
            ActionKind::DisableUser,
            ActionKind::KillSession,
            ActionKind::BlockIp,
        ],
    ))
}

/// The retry delays of the tests: 30 seconds, then two times as long, up to 2 minutes.
fn config() -> RevertSchedulerConfig {
    RevertSchedulerConfig {
        retry_base: Duration::from_secs(30),
        retry_max: Duration::from_secs(120),
        approval_poll: Duration::from_secs(60),
    }
}

/// Builds a dispatcher and its scheduler over services that a test can share.
fn build(
    policy: Arc<dyn PolicyEngine>,
    store: Arc<dyn RevertStore>,
    clock: RevertClock,
    connector: Arc<ToggleConnector>,
    audit: Arc<MemoryAuditLog>,
    approvals: Arc<MemoryApprovals>,
) -> Rig {
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let bus = Arc::new(MemoryBus::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(Arc::new(registry), policy, approvals.clone(), audit.clone())
            .bus(bus.clone())
            .revert_store(store)
            .revert_clock(clock)
            .build(),
    );
    let scheduler = RevertScheduler::with_config(dispatcher.clone(), config()).unwrap();
    Rig {
        dispatcher,
        scheduler,
        connector,
        audit,
        approvals,
        bus,
    }
}

fn rig_with(policy: Arc<dyn PolicyEngine>, store: Arc<dyn RevertStore>) -> Rig {
    build(
        policy,
        store,
        RevertClock::new(),
        toggle(),
        Arc::new(MemoryAuditLog::default()),
        Arc::new(MemoryApprovals::default()),
    )
}

fn rig() -> Rig {
    rig_with(
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryRevertStore::default()),
    )
}

/// A request to disable the user, with a timed revert of `seconds`.
fn disable_for(seconds: u64) -> ActionRequest {
    timed(request(ActionKind::DisableUser, victim_user()), seconds)
}

fn executed(disposition: &ActionDisposition) -> &ActionOutcome {
    match disposition {
        ActionDisposition::Executed(outcome) => outcome,
        other => panic!("expected an executed action, found {other:?}"),
    }
}

fn approval_of(disposition: &ActionDisposition) -> ApprovalId {
    match disposition {
        ActionDisposition::PendingApproval { approval_id, .. } => *approval_id,
        other => panic!("expected a pending approval, found {other:?}"),
    }
}

fn after(time: DateTime<Utc>, seconds: i64) -> DateTime<Utc> {
    time + TimeDelta::try_seconds(seconds).unwrap()
}

async fn advance(seconds: u64) {
    tokio::time::advance(Duration::from_secs(seconds)).await;
}

/// Dispatches a request that policy permits, and returns the outcome of the connector.
async fn contain(rig: &Rig, action: &ActionRequest) -> ActionOutcome {
    let disposition = rig
        .dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap();
    let outcome = executed(&disposition).clone();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    outcome
}

/// Starts the scheduler loop in a task. Returns the handles that stop it.
fn start(
    scheduler: &RevertScheduler,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let scheduler = scheduler.clone();
    let task = tokio::spawn(async move {
        scheduler
            .run(async {
                // The loop also stops if the test drops the sender.
                let _ = stopped.await;
            })
            .await;
    });
    (stop, task)
}

#[tokio::test(start_paused = true)]
async fn an_action_that_nobody_confirms_is_reverted_at_its_time() {
    let rig = rig();
    let (stop, task) = start(&rig.scheduler);
    let mut action = disable_for(600);
    let incident_id = IncidentId::new();
    action.incident_id = Some(incident_id);
    let started = rig.scheduler.now();

    let outcome = contain(&rig, &action).await;

    // The connector got one dry run, for the check that it can undo the action, and then
    // the action itself.
    assert_eq!(rig.connector.dry_runs().len(), 1);
    assert_eq!(rig.connector.changes(), vec![action.clone()]);
    // The dispatcher holds the pending revert.
    let pending = rig.scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0],
        PendingRevert {
            action_id: action.id,
            kind: ActionKind::DisableUser,
            target: action.target.clone(),
            incident_id: Some(incident_id),
            requested_by: "responder".to_owned(),
            revert_after_seconds: 600,
            armed_at: started,
            due_at: after(started, 600),
            state: PendingState::Waiting,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            approval_id: None,
            audit_sequence: Some(1),
        }
    );
    // The audit record of the execution has the revert time.
    let records = rig.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[2].payload["timed_revert"],
        json!({
            "after_seconds": 600,
            "state": "scheduled",
            "due_at": after(started, 600),
            "store_error": null,
        })
    );
    assert_eq!(records[2].payload["outcome"], json!(outcome));

    // One second before the time, nothing is reverted.
    advance(599).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted(), []);
    assert_eq!(rig.scheduler.stats(), RevertStats::default());

    // The scheduler loop reverts the action at the time.
    let mut stats = rig.scheduler.watch();
    stats.wait_for(|stats| stats.reverted == 1).await.unwrap();
    assert_eq!(rig.scheduler.now(), after(started, 600));

    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action.id);
    assert!(!reverted[0].dry_run);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);

    // The revert went through the dispatcher with the principal of the scheduler, and the
    // request says why.
    let records = rig.audit.records();
    let revert = revert_records(&records);
    assert_eq!(
        revert.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    assert_eq!(revert[0].actor, SCHEDULER_PRINCIPAL_ID);
    assert_eq!(
        revert[0].payload["principal"],
        json!({ "id": "revert-scheduler", "kind": "system", "roles": ["revert-scheduler"] })
    );
    assert_eq!(
        revert[0].payload["action"]["reason"],
        format!(
            "Nobody confirmed the action disable_user on user user-dana before {}. The timed revert of 600 seconds is due.",
            after(started, 600)
        )
    );
    assert_eq!(
        revert[0].payload["action"]["parameters"]["reverts"]["revert_after_seconds"],
        600
    );
    assert_eq!(revert[2].payload["outcome"]["status"], "succeeded");
    assert_eq!(revert[2].payload["pending_revert_removed"], true);
    let completed = events(&records, event::COMPLETED);
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].actor, SCHEDULER_ACTOR);
    assert_eq!(
        completed[0].summary,
        format!(
            "Nobody confirmed the action disable_user on user user-dana before {}. The scheduler reverted the action.",
            after(started, 600)
        )
    );
    assert_eq!(completed[0].payload["action_id"], json!(action.id));
    assert_eq!(
        completed[0].evidence,
        [
            EvidenceRef::new(EvidenceKind::Action, action.id),
            EvidenceRef::new(EvidenceKind::Incident, incident_id),
        ]
    );
    assert!(rig.audit.verify().await.unwrap().valid);
    // The result of the revert is on the bus.
    assert_eq!(rig.bus.published_to(subject::ACTION_RESULTS).len(), 2);

    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_confirmed_action_is_never_reverted() {
    let rig = rig();
    let (stop, task) = start(&rig.scheduler);
    let action = disable_for(600);
    contain(&rig, &action).await;
    advance(300).await;

    let confirmed = rig.scheduler.confirm(action.id, &alice()).await.unwrap();

    assert_eq!(confirmed.action_id, action.id);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let records = rig.audit.records();
    let confirmations = events(&records, event::CONFIRMED);
    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].actor, "alice@example.com");
    assert_eq!(
        confirmations[0].summary,
        "alice@example.com confirmed the action disable_user on user user-dana. The containment stays. The scheduler does not revert it."
    );
    assert_eq!(confirmations[0].payload["principal"], json!(alice()));
    assert_eq!(
        confirmations[0].evidence,
        [EvidenceRef::new(EvidenceKind::Action, action.id)]
    );

    // A long time after the revert time, the containment is still in place.
    advance(MAX_REVERT_AFTER_SECONDS).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted(), []);
    assert_eq!(revert_records(&rig.audit.records()), []);
    assert_eq!(
        rig.scheduler.stats(),
        RevertStats {
            confirmed: 1,
            ..RevertStats::default()
        }
    );
    // A second confirmation finds no pending revert.
    let again = rig
        .scheduler
        .confirm(action.id, &alice())
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::NotFound(message) if message.ends_with("has no pending revert")),
        "{again:?}"
    );
    assert!(rig.audit.verify().await.unwrap().valid);

    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn extend_moves_the_revert_time() {
    let rig = rig();
    let (stop, task) = start(&rig.scheduler);
    let action = disable_for(600);
    let started = rig.scheduler.now();
    contain(&rig, &action).await;
    advance(500).await;

    let extended = rig
        .scheduler
        .extend(action.id, &alice(), Duration::from_secs(900))
        .await
        .unwrap();

    // The new time is 900 seconds after the first revert time.
    assert_eq!(extended.due_at, after(started, 1_500));
    assert_eq!(
        rig.scheduler.get(action.id).await.unwrap(),
        Some(extended.clone())
    );
    let records = rig.audit.records();
    let moved = events(&records, event::EXTENDED);
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].actor, "alice@example.com");
    assert_eq!(
        moved[0].payload["previous_due_at"],
        json!(after(started, 600))
    );
    assert_eq!(moved[0].payload["due_at"], json!(after(started, 1_500)));

    // The first revert time passes. Nothing is reverted.
    advance(1_000 - 1).await;
    assert_eq!(rig.scheduler.now(), after(started, 1_499));
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted(), []);

    // The scheduler loop reverts the action at the new time.
    let mut stats = rig.scheduler.watch();
    stats.wait_for(|stats| stats.reverted == 1).await.unwrap();
    assert_eq!(rig.scheduler.now(), after(started, 1_500));
    assert_eq!(rig.connector.reverted().len(), 1);
    assert_eq!(rig.scheduler.stats().extended, 1);

    // The limits of an extension.
    let second = disable_for(600);
    contain(&rig, &second).await;
    let zero = rig
        .scheduler
        .extend(second.id, &alice(), Duration::from_millis(999))
        .await
        .unwrap_err();
    assert!(
        matches!(&zero, Error::InvalidInput(message) if message.contains("one second or more")),
        "{zero:?}"
    );
    let too_long = rig
        .scheduler
        .extend(
            second.id,
            &alice(),
            Duration::from_secs(MAX_REVERT_AFTER_SECONDS),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&too_long, Error::InvalidInput(message) if message.contains("is more than 2592000 seconds")),
        "{too_long:?}"
    );
    let unknown = rig
        .scheduler
        .extend(ActionId::new(), &alice(), Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(matches!(unknown, Error::NotFound(_)), "{unknown:?}");
    assert_eq!(
        rig.scheduler.get(second.id).await.unwrap().unwrap().due_at,
        after(started, 2_100)
    );

    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancel_reverts_the_action_immediately() {
    let rig = rig();
    let action = disable_for(600);
    contain(&rig, &action).await;
    advance(60).await;

    let disposition = rig.scheduler.cancel(action.id, &alice()).await.unwrap();

    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.details["reverted_action_id"], json!(action.id));
    assert_eq!(rig.connector.reverted().len(), 1);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);

    // The revert went through the dispatcher with the principal of the person.
    let records = rig.audit.records();
    let revert = revert_records(&records);
    assert_eq!(revert.len(), 3);
    assert_eq!(revert[0].actor, "alice@example.com");
    assert_eq!(revert[0].payload["principal"], json!(alice()));
    assert!(
        revert[0].payload["action"]["reason"]
            .as_str()
            .unwrap()
            .starts_with("alice@example.com cancelled the action disable_user on user user-dana before the revert time "),
        "{}",
        revert[0].payload["action"]["reason"]
    );
    let cancelled = events(&records, event::CANCELLED);
    assert_eq!(cancelled.len(), 1);
    assert_eq!(cancelled[0].actor, "alice@example.com");
    assert_eq!(
        cancelled[0].payload["revert_action_id"],
        json!(outcome.action_id)
    );
    assert_eq!(
        rig.scheduler.stats(),
        RevertStats {
            cancelled: 1,
            ..RevertStats::default()
        }
    );

    // At the revert time, there is nothing more to do.
    advance(600).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted().len(), 1);
    let again = rig.scheduler.cancel(action.id, &alice()).await.unwrap_err();
    assert!(matches!(again, Error::NotFound(_)), "{again:?}");
}

#[tokio::test(start_paused = true)]
async fn a_cancel_that_policy_does_not_permit_keeps_the_pending_revert() {
    let policy = TwoPolicy::new(PolicyEffect::Allow, PolicyEffect::Deny);
    let rig = rig_with(policy.clone(), Arc::new(MemoryRevertStore::default()));
    let action = disable_for(600);
    contain(&rig, &action).await;

    // An agent asks. The policy applies to its request and denies it.
    let disposition = rig.scheduler.cancel(action.id, &responder()).await.unwrap();

    assert!(
        matches!(&disposition, ActionDisposition::Denied(_)),
        "{disposition:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);
    assert_eq!(events(&rig.audit.records(), event::CANCELLED), []);
    let revert_inputs: Vec<PolicyInput> = policy
        .inputs()
        .into_iter()
        .filter(|input| input.action.kind == ActionKind::Custom(REVERT_ACTION.to_owned()))
        .collect();
    assert_eq!(revert_inputs.len(), 1);
    assert_eq!(revert_inputs[0].principal, responder());
}

#[tokio::test(start_paused = true)]
async fn a_restart_with_the_file_store_keeps_the_pending_reverts_and_runs_an_overdue_one() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state").join("reverts.json");
    let clock = RevertClock::new();
    let connector = toggle();
    let audit = Arc::new(MemoryAuditLog::default());
    let approvals = Arc::new(MemoryApprovals::default());
    let policy: Arc<dyn PolicyEngine> = Arc::new(StaticPolicy::AllowAll);
    let started = clock.now();

    // The first process contains two entities and then stops.
    let short = disable_for(600);
    let long = timed(request(ActionKind::BlockIp, common::spray_address()), 7_200);
    {
        let store = Arc::new(FileRevertStore::open(&path).await.unwrap());
        let first = build(
            policy.clone(),
            store,
            clock.clone(),
            connector.clone(),
            audit.clone(),
            approvals.clone(),
        );
        contain(&first, &short).await;
        contain(&first, &long).await;
        assert_eq!(first.scheduler.pending().await.unwrap().len(), 2);
    }
    assert_eq!(connector.reverted(), []);

    // The process is down for 15 minutes. The first revert time passes.
    advance(900).await;

    // The second process reads the same file.
    let store = Arc::new(FileRevertStore::open(&path).await.unwrap());
    let kept = store.list().await.unwrap();
    assert_eq!(
        kept.iter()
            .map(|pending| (pending.action_id, pending.due_at, pending.state))
            .collect::<Vec<_>>(),
        [
            (short.id, after(started, 600), PendingState::Waiting),
            (long.id, after(started, 7_200), PendingState::Waiting),
        ]
    );
    let second = build(
        policy,
        store,
        clock.clone(),
        connector.clone(),
        audit.clone(),
        approvals,
    );
    let (stop, task) = start(&second.scheduler);

    // The overdue revert runs at once, with no more time.
    let mut stats = second.scheduler.watch();
    stats.wait_for(|stats| stats.reverted == 1).await.unwrap();
    assert_eq!(second.scheduler.now(), after(started, 900));
    let reverted = connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, short.id);
    let records = audit.records();
    let revert = revert_records(&records);
    assert_eq!(revert.len(), 3);
    assert_eq!(
        revert[0].payload["action"]["reason"],
        format!(
            "Nobody confirmed the action disable_user on user user-dana before {}. The timed revert of 600 seconds is due. The scheduler started after this time, so the revert runs now.",
            after(started, 600)
        )
    );

    // The other pending revert continues to wait, in the file and in the scheduler.
    let waiting = second.scheduler.pending().await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].action_id, long.id);
    let reopened = FileRevertStore::open(&path).await.unwrap();
    assert_eq!(reopened.list().await.unwrap(), waiting);

    // It runs at its own time.
    stats.wait_for(|stats| stats.reverted == 2).await.unwrap();
    assert_eq!(second.scheduler.now(), after(started, 7_200));
    assert_eq!(connector.reverted()[1].id, long.id);
    assert_eq!(
        FileRevertStore::open(&path)
            .await
            .unwrap()
            .list()
            .await
            .unwrap(),
        []
    );
    assert!(audit.verify().await.unwrap().valid);

    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_revert_that_fails_keeps_the_containment_and_the_scheduler_tries_again() {
    let rig = rig();
    let action = disable_for(60);
    let started = rig.scheduler.now();
    contain(&rig, &action).await;
    rig.connector.fail_revert(Some("graph is down"));
    advance(60).await;

    // The first attempt fails. The next attempt is 30 seconds later.
    let report = rig.scheduler.run_due().await.unwrap();

    assert_eq!(report.len(), 1);
    assert_eq!(report[0].action_id, action.id);
    assert_eq!(
        report[0].progress,
        RevertProgress::Failed {
            error: "unavailable: graph is down".to_owned(),
            attempts: 1,
            next_attempt_at: after(started, 90),
        }
    );
    assert_eq!(rig.connector.reverted().len(), 1);
    // The pending revert stays in the store, with the error.
    let pending = rig.scheduler.get(action.id).await.unwrap().unwrap();
    assert_eq!(pending.attempts, 1);
    assert_eq!(pending.next_attempt_at, Some(after(started, 90)));
    assert_eq!(
        pending.last_error.as_deref(),
        Some("unavailable: graph is down")
    );
    assert_eq!(pending.due_at, after(started, 60));
    // The audit log has the attempt of the dispatcher and the record of the scheduler.
    let records = rig.audit.records();
    let revert = revert_records(&records);
    assert_eq!(revert.len(), 3);
    assert_eq!(revert[2].kind, AuditKind::ActionExecuted);
    assert_eq!(revert[2].payload["error"]["kind"], "unavailable");
    let failures = events(&records, event::FAILED);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].actor, SCHEDULER_ACTOR);
    assert_eq!(
        failures[0].summary,
        format!(
            "The timed revert of the action disable_user on user user-dana failed. The containment stays. The scheduler tries again at {}.",
            after(started, 90)
        )
    );
    assert_eq!(failures[0].payload["error"], "unavailable: graph is down");
    assert_eq!(failures[0].payload["attempts"], 1);
    assert_eq!(
        failures[0].payload["next_attempt_at"],
        json!(after(started, 90))
    );
    assert_eq!(
        failures[0].evidence,
        [EvidenceRef::new(EvidenceKind::Action, action.id)]
    );

    // Before the next attempt time, the scheduler does not call the connector.
    advance(29).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted().len(), 1);

    // The second attempt fails. The delay is two times as long.
    advance(1).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert_eq!(
        report[0].progress,
        RevertProgress::Failed {
            error: "unavailable: graph is down".to_owned(),
            attempts: 2,
            next_attempt_at: after(started, 150),
        }
    );
    // The third and the fourth delay stop at the maximum of 120 seconds.
    advance(60).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(&report[0].progress, RevertProgress::Failed { attempts: 3, next_attempt_at, .. }
            if *next_attempt_at == after(started, 270)),
        "{report:?}"
    );
    advance(120).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(&report[0].progress, RevertProgress::Failed { attempts: 4, next_attempt_at, .. }
            if *next_attempt_at == after(started, 390)),
        "{report:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 4);
    assert_eq!(events(&rig.audit.records(), event::FAILED).len(), 4);
    assert_eq!(rig.scheduler.stats().failed_attempts, 4);
    assert_eq!(rig.scheduler.stats().reverted, 0);
    // No revert succeeded, so the containment stays.
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);

    // The connector works again. The next attempt reverts the action.
    rig.connector.fail_revert(None);
    advance(120).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(outcome)
            if outcome.status == ActionStatus::Succeeded),
        "{report:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 5);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    assert_eq!(events(&rig.audit.records(), event::COMPLETED).len(), 1);
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test(start_paused = true)]
async fn the_scheduler_loop_tries_a_failed_revert_again() {
    let rig = rig();
    let (stop, task) = start(&rig.scheduler);
    let action = disable_for(60);
    let started = rig.scheduler.now();
    contain(&rig, &action).await;
    rig.connector.fail_revert(Some("graph is down"));

    let mut stats = rig.scheduler.watch();
    stats
        .wait_for(|stats| stats.failed_attempts == 2)
        .await
        .unwrap();
    // The attempts were at 60 seconds and at 90 seconds.
    assert_eq!(rig.scheduler.now(), after(started, 90));
    rig.connector.fail_revert(None);
    stats.wait_for(|stats| stats.reverted == 1).await.unwrap();
    assert_eq!(rig.scheduler.now(), after(started, 150));
    assert_eq!(rig.connector.reverted().len(), 3);

    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_timed_revert_that_policy_denies_stays_and_runs_when_policy_permits_it() {
    let policy = TwoPolicy::new(PolicyEffect::Allow, PolicyEffect::Deny);
    let rig = rig_with(policy.clone(), Arc::new(MemoryRevertStore::default()));
    let action = disable_for(60);
    contain(&rig, &action).await;
    advance(60).await;

    let report = rig.scheduler.run_due().await.unwrap();

    assert!(
        matches!(&report[0].progress, RevertProgress::Failed { error, attempts: 1, .. }
            if error == "policy denied the revert: The test policy decided."),
        "{report:?}"
    );
    assert_eq!(rig.connector.reverted(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);
    // The policy got the request of the scheduler.
    let inputs = policy.inputs();
    let last = inputs.last().unwrap();
    assert_eq!(last.principal, RevertScheduler::principal());
    assert_eq!(last.principal.kind, PrincipalKind::System);
    assert_eq!(last.action.kind, ActionKind::Custom("revert".to_owned()));

    policy.set_reverts(PolicyEffect::Allow);
    advance(30).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(_)),
        "{report:?}"
    );
    assert_eq!(rig.connector.reverted().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_timed_revert_that_needs_approval_keeps_the_containment_until_a_person_decides() {
    let policy = TwoPolicy::new(PolicyEffect::Allow, PolicyEffect::RequireApproval);
    let rig = rig_with(policy, Arc::new(MemoryRevertStore::default()));
    let approved = disable_for(60);
    let rejected = timed(request(ActionKind::BlockIp, common::spray_address()), 60);
    contain(&rig, &approved).await;
    contain(&rig, &rejected).await;
    advance(60).await;

    // Policy requires approval for each revert. Both reverts wait in the approval queue.
    let report = rig.scheduler.run_due().await.unwrap();

    assert_eq!(report.len(), 2);
    let queued = rig.approvals.pending().await.unwrap();
    assert_eq!(queued.len(), 2);
    let approval_for = |action: &ActionRequest| {
        queued
            .iter()
            .find(|approval| approval.action.parameters["reverts"]["action_id"] == json!(action.id))
            .unwrap()
            .clone()
    };
    let to_approve = approval_for(&approved);
    let to_reject = approval_for(&rejected);
    assert_eq!(
        report[0].progress,
        RevertProgress::AwaitingApproval(to_approve.id)
    );
    assert_eq!(to_approve.requested_by, RevertScheduler::principal());
    assert_eq!(rig.connector.reverted(), []);
    let waiting = events(&rig.audit.records(), event::AWAITING_APPROVAL);
    assert_eq!(waiting.len(), 2);
    assert_eq!(waiting[0].payload["approval_id"], json!(to_approve.id));
    assert_eq!(
        rig.scheduler
            .get(approved.id)
            .await
            .unwrap()
            .unwrap()
            .approval_id,
        Some(to_approve.id)
    );

    // Nobody decides. The scheduler examines the approvals again and makes no new request.
    advance(60).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert_eq!(report.len(), 2);
    assert_eq!(
        report[0].progress,
        RevertProgress::AwaitingApproval(to_approve.id)
    );
    assert_eq!(rig.approvals.pending().await.unwrap().len(), 2);
    assert_eq!(
        events(&rig.audit.records(), event::AWAITING_APPROVAL).len(),
        2
    );
    assert_eq!(rig.connector.reverted(), []);

    // One person approves a revert. A different person rejects the other revert.
    rig.approvals
        .decide(to_approve.id, true, &alice(), None)
        .await
        .unwrap();
    let bob = Principal::new("bob@example.com", PrincipalKind::Human, &["approver"]);
    rig.approvals
        .decide(to_reject.id, false, &bob, None)
        .await
        .unwrap();
    advance(60).await;
    let report = rig.scheduler.run_due().await.unwrap();

    assert_eq!(report.len(), 2);
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(outcome)
            if outcome.status == ActionStatus::Succeeded),
        "{report:?}"
    );
    assert_eq!(
        report[1].progress,
        RevertProgress::Closed {
            reason: format!(
                "bob@example.com rejected the approval {} of the revert. The containment stays.",
                to_reject.id
            ),
        }
    );
    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, approved.id);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let closed = events(&rig.audit.records(), event::CLOSED);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].payload["action_id"], json!(rejected.id));
    assert_eq!(
        rig.scheduler.stats(),
        RevertStats {
            reverted: 1,
            closed: 1,
            ..RevertStats::default()
        }
    );
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test(start_paused = true)]
async fn an_approved_action_also_gets_a_pending_revert() {
    let rig = rig_with(
        TwoPolicy::new(PolicyEffect::RequireApproval, PolicyEffect::Allow),
        Arc::new(MemoryRevertStore::default()),
    );
    let action = disable_for(600);
    let approval_id = approval_of(
        &rig.dispatcher
            .dispatch(action.clone(), &playbook_engine())
            .await
            .unwrap(),
    );
    // No change and no pending revert while the request waits for approval.
    assert_eq!(rig.connector.executed(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    advance(1_000).await;
    rig.approvals
        .decide(approval_id, true, &alice(), None)
        .await
        .unwrap();
    let resumed_at = rig.scheduler.now();

    let disposition = rig.dispatcher.resume(approval_id).await.unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    // The time of the revert starts when the connector completes the action.
    let pending = rig.scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action_id, action.id);
    assert_eq!(pending[0].due_at, after(resumed_at, 600));
    advance(600).await;
    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(_)),
        "{report:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn only_an_action_type_with_an_inverse_can_have_a_timed_revert() {
    let policy = TwoPolicy::new(PolicyEffect::Allow, PolicyEffect::Allow);
    let rig = rig_with(policy.clone(), Arc::new(MemoryRevertStore::default()));
    let action = timed(request(ActionKind::KillSession, victim_user()), 600);

    let error = rig
        .dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message
            == "the parameter revert_after_seconds is not valid: the action kill_session has no inverse, so it cannot have a timed revert"),
        "{error:?}"
    );
    // The request stopped before the policy and before the connector.
    assert_eq!(policy.inputs(), []);
    assert_eq!(rig.connector.executed(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let records = rig.audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [AuditKind::ActionProposed, AuditKind::ActionExecuted]
    );
    assert_eq!(
        records[1].summary,
        "The dispatcher refused the action kill_session on user user-dana."
    );
    assert_eq!(records[1].payload["error"]["kind"], "invalid_input");

    // The same action with no timed revert runs.
    let plain = request(ActionKind::KillSession, victim_user());
    contain(&rig, &plain).await;
    assert_eq!(rig.connector.changes(), vec![plain]);
}

#[tokio::test(start_paused = true)]
async fn a_revert_time_that_is_not_valid_is_refused_before_any_change() {
    let rig = rig();
    for value in [
        json!(0),
        json!(MAX_REVERT_AFTER_SECONDS + 1),
        json!("600"),
        json!(1.5),
        json!(null),
    ] {
        let mut action = request(ActionKind::DisableUser, victim_user());
        action
            .parameters
            .insert(REVERT_AFTER_PARAMETER.to_owned(), value.clone());

        let error = rig
            .dispatcher
            .dispatch(action, &playbook_engine())
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::InvalidInput(message)
                if message.starts_with("the parameter revert_after_seconds is not valid: ")),
            "{value}: {error:?}"
        );
    }
    assert_eq!(rig.connector.executed(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
}

#[tokio::test(start_paused = true)]
async fn a_connector_that_cannot_undo_the_action_is_refused_before_any_change() {
    let rig = rig();
    rig.connector.set_reversible(false);
    let action = disable_for(600);

    let error = rig
        .dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message
            == "connector identity cannot undo the action disable_user; an action with a timed revert must have an inverse; the action did not run"),
        "{error:?}"
    );
    // The connector got only the dry run of the check.
    assert_eq!(rig.connector.dry_runs().len(), 1);
    assert_eq!(rig.connector.changes(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let records = rig.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[2].summary,
        "The dispatcher refused the action disable_user on user user-dana."
    );
    assert_eq!(records[2].payload["connector"], "identity");
    assert_eq!(records[2].payload["error"]["kind"], "invalid_input");
}

#[tokio::test(start_paused = true)]
async fn a_timed_revert_needs_a_revert_store() {
    let connector = toggle();
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .build(),
    );

    let error = dispatcher
        .dispatch(disable_for(600), &playbook_engine())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Config(message)
            if message.contains("the dispatcher has no revert store") && message.ends_with("the action did not run")),
        "{error:?}"
    );
    assert_eq!(connector.executed(), []);
    assert_eq!(audit.records()[2].payload["error"]["kind"], "config");

    // A scheduler cannot start for this dispatcher.
    let no_store = RevertScheduler::new(dispatcher.clone()).err().unwrap();
    assert!(
        matches!(&no_store, Error::Config(message) if message.contains("has no revert store")),
        "{no_store:?}"
    );

    // A dry run needs no store, because it schedules nothing.
    let mut dry = disable_for(600);
    dry.dry_run = true;
    let disposition = dispatcher.dispatch(dry, &playbook_engine()).await.unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Simulated);
}

#[tokio::test(start_paused = true)]
async fn a_dry_run_with_a_timed_revert_schedules_nothing() {
    let rig = rig();
    let mut action = disable_for(600);
    action.dry_run = true;

    let disposition = rig
        .dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Simulated);
    // One call: the dry run itself. The check before a change is not necessary.
    assert_eq!(rig.connector.executed(), vec![action]);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let records = rig.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[2].payload["timed_revert"],
        json!({
            "after_seconds": 600,
            "state": "not_scheduled",
            "reason": "The request was a dry run. A dry run has nothing to revert.",
        })
    );
    advance(600).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted(), []);
}

#[tokio::test(start_paused = true)]
async fn an_action_that_did_not_change_the_target_has_no_pending_revert() {
    let rig = rig();
    // The connector finds that no change is necessary.
    rig.connector.set_live_status(ActionStatus::Skipped);
    let skipped = disable_for(600);
    let disposition = rig
        .dispatcher
        .dispatch(skipped, &playbook_engine())
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Skipped);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    assert_eq!(
        rig.audit.records()[2].payload["timed_revert"],
        json!({
            "after_seconds": 600,
            "state": "not_scheduled",
            "reason": "The connector did not change the target, so there is nothing to revert.",
        })
    );

    // The connector fails after the check.
    rig.connector.set_live_status(ActionStatus::Succeeded);
    let failing = disable_for(600);
    rig.connector.fail_execute(Some("graph is down"));
    let error = rig
        .dispatcher
        .dispatch(failing, &playbook_engine())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    assert_eq!(rig.connector.changes().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_action_does_not_run_if_the_store_cannot_keep_the_pending_revert() {
    let store = Arc::new(FlakyStore::default());
    let rig = rig_with(Arc::new(StaticPolicy::AllowAll), store.clone());
    store.fail_put.store(true, Ordering::SeqCst);
    let action = disable_for(600);

    let error = rig
        .dispatcher
        .dispatch(action, &playbook_engine())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.contains("could not store the pending revert")
                && message.contains("so the action did not run")
                && message.ends_with("the disk is full")),
        "{error:?}"
    );
    assert_eq!(rig.connector.changes(), []);
    let records = rig.audit.records();
    assert_eq!(records[2].payload["error"]["kind"], "unavailable");
    assert_eq!(
        records[2].summary,
        "The dispatcher refused the action disable_user on user user-dana."
    );

    // The store works again, and the same containment runs with its pending revert.
    store.fail_put.store(false, Ordering::SeqCst);
    let action = disable_for(600);
    contain(&rig, &action).await;
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_failed_attempt_that_the_store_cannot_save_still_waits_for_its_delay() {
    let store = Arc::new(FlakyStore::default());
    let rig = rig_with(Arc::new(StaticPolicy::AllowAll), store.clone());
    let action = disable_for(60);
    contain(&rig, &action).await;
    rig.connector.fail_revert(Some("graph is down"));
    store.fail_put.store(true, Ordering::SeqCst);
    advance(60).await;

    let report = rig.scheduler.run_due().await.unwrap();
    assert!(
        matches!(
            &report[0].progress,
            RevertProgress::Failed { attempts: 1, .. }
        ),
        "{report:?}"
    );
    // The store has no record of the attempt, but the scheduler keeps the delay.
    assert_eq!(
        rig.scheduler
            .get(action.id)
            .await
            .unwrap()
            .unwrap()
            .attempts,
        0
    );
    advance(29).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted().len(), 1);
    advance(1).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap().len(), 1);
    assert_eq!(rig.connector.reverted().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_decision_of_a_person_during_a_pass_of_the_scheduler_has_its_effect() {
    let rig = rig();
    let first = disable_for(60);
    let extended = timed(request(ActionKind::BlockIp, common::spray_address()), 61);
    let confirmed = timed(request(ActionKind::DisableUser, common::victim_user()), 62);
    let started = rig.scheduler.now();
    contain(&rig, &first).await;
    contain(&rig, &extended).await;
    contain(&rig, &confirmed).await;
    advance(62).await;

    // The scheduler starts a pass. All three reverts are due. The connector does not
    // answer the first revert, so the pass waits there.
    rig.connector.hold_reverts();
    let pass = tokio::spawn({
        let scheduler = rig.scheduler.clone();
        async move { scheduler.run_due().await }
    });
    rig.connector.revert_entered().await;

    // In this time, a person moves the time of the second action and confirms the third
    // action. Then the connector answers.
    let person = alice();
    let (moved, kept, report) = tokio::join!(
        rig.scheduler
            .extend(extended.id, &person, Duration::from_secs(600)),
        rig.scheduler.confirm(confirmed.id, &person),
        async {
            rig.connector.release_reverts();
            pass.await.unwrap()
        }
    );

    // The pass reverted only the first action.
    let report = report.unwrap();
    assert_eq!(report.len(), 1, "{report:?}");
    assert_eq!(report[0].action_id, first.id);
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(_)),
        "{report:?}"
    );
    let reverted = rig.connector.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, first.id);
    // The second action waits for its new time. The third action has no pending revert.
    assert_eq!(moved.unwrap().due_at, after(started, 662));
    assert_eq!(kept.unwrap().action_id, confirmed.id);
    let pending = rig.scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action_id, extended.id);
    assert_eq!(pending[0].due_at, after(started, 662));
}

#[tokio::test(start_paused = true)]
async fn a_revert_through_the_dispatcher_removes_the_pending_revert() {
    let rig = rig();
    let action = disable_for(600);
    contain(&rig, &action).await;

    let disposition = rig
        .dispatcher
        .revert(action.id, &alice(), "The account is not compromised.")
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    let records = rig.audit.records();
    assert_eq!(
        records.last().unwrap().payload["pending_revert_removed"],
        true
    );
    advance(600).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_revert_that_the_connector_skips_closes_the_pending_revert() {
    let rig = rig();
    let action = disable_for(60);
    contain(&rig, &action).await;
    rig.connector.set_revert_status(ActionStatus::Skipped);
    advance(60).await;

    let report = rig.scheduler.run_due().await.unwrap();

    assert!(
        matches!(&report[0].progress, RevertProgress::Closed { reason }
            if reason.starts_with("The connector found that no change was necessary: ")),
        "{report:?}"
    );
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    assert_eq!(events(&rig.audit.records(), event::CLOSED).len(), 1);
    assert_eq!(rig.scheduler.stats().closed, 1);
    assert_eq!(rig.scheduler.stats().reverted, 0);
}

#[tokio::test(start_paused = true)]
async fn a_pending_revert_with_no_result_in_the_audit_log_stays_until_a_person_confirms() {
    // The process stopped between the store write and the audit record of the action. The
    // store has the pending revert, and the audit log has only the proposal.
    let store = Arc::new(MemoryRevertStore::default());
    let rig = rig_with(Arc::new(StaticPolicy::DenyAll), store.clone());
    let action = disable_for(60);
    rig.dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap();
    let now = rig.scheduler.now();
    let armed = PendingRevert {
        action_id: action.id,
        kind: action.kind.clone(),
        target: action.target.clone(),
        incident_id: None,
        requested_by: action.requested_by.clone(),
        revert_after_seconds: 60,
        armed_at: now,
        due_at: after(now, 60),
        state: PendingState::Armed,
        attempts: 0,
        next_attempt_at: None,
        last_error: None,
        approval_id: None,
        audit_sequence: Some(1),
    };
    store.put(armed).await.unwrap();
    advance(60).await;

    let report = rig.scheduler.run_due().await.unwrap();

    assert!(
        matches!(&report[0].progress, RevertProgress::Failed { error, attempts: 1, .. }
            if error.starts_with("the process stopped while the action ran, and the audit log has no result; examine the target, then confirm the action: ")),
        "{report:?}"
    );
    // The scheduler does not remove the pending revert. It tells a person in the audit log.
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);
    assert_eq!(events(&rig.audit.records(), event::FAILED).len(), 1);
    assert_eq!(rig.connector.reverted(), []);

    rig.scheduler.confirm(action.id, &alice()).await.unwrap();
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
}

#[tokio::test(start_paused = true)]
async fn only_a_person_can_confirm_or_extend() {
    let rig = rig();
    let action = disable_for(600);
    contain(&rig, &action).await;
    let records_before = rig.audit.records().len();

    for principal in [responder(), playbook_engine(), RevertScheduler::principal()] {
        let confirm = rig
            .scheduler
            .confirm(action.id, &principal)
            .await
            .unwrap_err();
        assert!(
            matches!(&confirm, Error::Unauthorized(message)
                if message.starts_with("only a person can confirm a timed revert")),
            "{confirm:?}"
        );
        let extend = rig
            .scheduler
            .extend(action.id, &principal, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            matches!(&extend, Error::Unauthorized(message)
                if message.starts_with("only a person can extend a timed revert")),
            "{extend:?}"
        );
    }

    let pending = rig.scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].revert_after_seconds, 600);
    assert_eq!(rig.audit.records().len(), records_before);
}

#[tokio::test]
async fn the_scheduler_refuses_settings_that_are_not_valid() {
    let rig = rig();
    for bad in [
        RevertSchedulerConfig {
            retry_base: Duration::ZERO,
            ..config()
        },
        RevertSchedulerConfig {
            approval_poll: Duration::ZERO,
            ..config()
        },
        RevertSchedulerConfig {
            retry_base: Duration::from_secs(60),
            retry_max: Duration::from_secs(30),
            ..config()
        },
    ] {
        let error = RevertScheduler::with_config(rig.dispatcher.clone(), bad.clone())
            .err()
            .unwrap();
        assert!(matches!(error, Error::Config(_)), "{bad:?}: {error:?}");
    }
    assert!(RevertScheduler::new(rig.dispatcher.clone()).is_ok());
    assert_eq!(
        RevertSchedulerConfig::default(),
        RevertSchedulerConfig {
            retry_base: Duration::from_secs(30),
            retry_max: Duration::from_secs(1_800),
            approval_poll: Duration::from_secs(60),
        }
    );
}

#[tokio::test(start_paused = true)]
async fn the_file_store_replaces_its_file_in_one_step() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reverts.json");
    let store = Arc::new(FileRevertStore::open(&path).await.unwrap());
    assert_eq!(store.path(), path.as_path());
    // A store with no change has no file.
    assert!(!path.exists());
    let rig = rig_with(Arc::new(StaticPolicy::AllowAll), store.clone());
    let first = disable_for(600);
    let second = timed(request(ActionKind::BlockIp, common::spray_address()), 60);
    contain(&rig, &first).await;
    contain(&rig, &second).await;

    // The file is a complete document, and the directory has no temporary file.
    let text = std::fs::read_to_string(&path).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["schema"], "aegis.pending_reverts.v1");
    let reverts = document["reverts"].as_array().unwrap();
    assert_eq!(reverts.len(), 2);
    // The pending revert with the earliest time is first.
    assert_eq!(reverts[0]["action_id"], json!(second.id));
    assert_eq!(reverts[0]["state"], "waiting");
    assert_eq!(reverts[0]["kind"], "block_ip");
    assert_eq!(reverts[1]["action_id"], json!(first.id));
    let names: Vec<String> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["reverts.json"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The data in the file is the data of the store.
    let reopened = FileRevertStore::open(&path).await.unwrap();
    assert_eq!(reopened.list().await.unwrap(), store.list().await.unwrap());
    assert_eq!(
        reopened.get(first.id).await.unwrap(),
        store.get(first.id).await.unwrap()
    );
    assert_eq!(reopened.remove(ActionId::new()).await.unwrap(), None);
    let removed = reopened.remove(second.id).await.unwrap().unwrap();
    assert_eq!(removed.action_id, second.id);
    let after_remove = FileRevertStore::open(&path).await.unwrap();
    assert_eq!(after_remove.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_store_file_that_is_not_valid_is_an_integrity_error() {
    let directory = tempfile::tempdir().unwrap();
    for (name, text) in [
        (
            "cut.json",
            "{\"schema\": \"aegis.pending_reverts.v1\", \"reverts\": [{",
        ),
        ("empty.json", ""),
        (
            "other.json",
            "{\"schema\": \"something.else\", \"reverts\": []}",
        ),
        ("fields.json", "{\"schema\": \"aegis.pending_reverts.v1\"}"),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, text).unwrap();

        let error = FileRevertStore::open(&path).await.err().unwrap();

        assert!(
            matches!(&error, Error::Integrity(message)
                if message.contains(name) && message.contains("is not valid") && message.contains("examine the file")),
            "{name}: {error:?}"
        );
        // The function does not replace the file with an empty store.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}

#[tokio::test(start_paused = true)]
async fn a_write_that_fails_does_not_change_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state").join("reverts.json");
    let store = Arc::new(FileRevertStore::open(&path).await.unwrap());
    let rig = rig_with(Arc::new(StaticPolicy::AllowAll), store.clone());
    let kept = disable_for(600);
    contain(&rig, &kept).await;
    let before = std::fs::read_to_string(&path).unwrap();

    // The directory of the file is gone, so the next write fails.
    let moved = directory.path().join("moved");
    std::fs::rename(directory.path().join("state"), &moved).unwrap();
    let error = rig
        .dispatcher
        .dispatch(disable_for(600), &playbook_engine())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.contains("cannot write the revert store") && message.contains("so the action did not run")),
        "{error:?}"
    );
    // The connector made no second change, and the store has the data from before.
    assert_eq!(rig.connector.changes(), vec![kept.clone()]);
    let listed = store.list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].action_id, kept.id);
    assert_eq!(
        std::fs::read_to_string(moved.join("reverts.json")).unwrap(),
        before
    );
}
