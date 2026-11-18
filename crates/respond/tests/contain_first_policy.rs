//! Integration tests for the policy example `contain_first_with_timed_revert.rego`, with the
//! real policy engine and the real dispatcher.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::incident::{Incident, IncidentStore};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, PolicyDecision, PolicyEffect, Principal, PrincipalKind,
};
use aegis_contracts::{Error, PolicyEngine};
use aegis_policy::{PolicySources, RegoPolicyEngine};
use aegis_respond::revert::REVERTS_PARAMETER;
use aegis_respond::{
    ActionRegistry, Dispatcher, MemoryRevertStore, Playbook, PlaybookEngine, RevertProgress,
    RevertScheduler, RunMode, StepResult, friction,
};
use aegis_testkit::fixtures::TENANT;
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, MemoryIncidents};
use serde_json::json;

use common::{
    ToggleConnector, alice, playbook_engine, request, responder, rogue_incident,
    sample_playbook_dir, spray_address, timed, victim_user,
};

const RULE: &str = "aegis.response.decision";
const CONTAIN_FIRST: &str = "The action has an inverse and a timed revert of a permitted length. It runs first. AEGIS reverts it if no person confirms it.";
const TIMED_REVERT: &str =
    "Nobody confirmed the action before its revert time. The revert scheduler reverts it.";
const GATED: &str = "The action is in the gated tier. A person must approve it.";
/// The longest revert time of the example: 4 hours.
const LIMIT: u64 = 14_400;

fn policy() -> Arc<RegoPolicyEngine> {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies/examples/contain_first_with_timed_revert.rego");
    Arc::new(RegoPolicyEngine::load(PolicySources::new().policy_file(file)).unwrap())
}

/// One dispatcher with the example policy, a revert store, and an incident store.
struct Rig {
    dispatcher: Arc<Dispatcher>,
    scheduler: RevertScheduler,
    connector: Arc<ToggleConnector>,
    audit: Arc<MemoryAuditLog>,
    approvals: Arc<MemoryApprovals>,
    incidents: Arc<MemoryIncidents>,
}

fn rig() -> Rig {
    let connector = Arc::new(ToggleConnector::new(
        "containment",
        vec![
            ActionKind::DisableUser,
            ActionKind::DisableServicePrincipal,
            ActionKind::BlockIp,
            ActionKind::IsolateHost,
            ActionKind::KillSession,
            ActionKind::OpenTicket,
            ActionKind::Notify,
            friction::restrict_user_consent(),
            friction::raise_friction(),
            ActionKind::Custom("quarantine_mailbox".to_owned()),
        ],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let approvals = Arc::new(MemoryApprovals::default());
    let incidents = Arc::new(MemoryIncidents::default());
    let engine: Arc<dyn PolicyEngine> = policy();
    let dispatcher = Arc::new(
        Dispatcher::builder(Arc::new(registry), engine, approvals.clone(), audit.clone())
            .incidents(incidents.clone())
            .revert_store(Arc::new(MemoryRevertStore::default()))
            .build(),
    );
    let scheduler = RevertScheduler::new(dispatcher.clone()).unwrap();
    Rig {
        dispatcher,
        scheduler,
        connector,
        audit,
        approvals,
        incidents,
    }
}

impl Rig {
    /// Saves an incident with this severity and returns its identifier.
    async fn incident(&self, severity: Severity) -> IncidentId {
        let mut incident: Incident = rogue_incident();
        incident.severity = severity;
        self.incidents.save(&incident).await.unwrap();
        incident.id
    }

    /// Returns the decision of the policy for the last request, from the audit log.
    fn last_decision(&self) -> PolicyDecision {
        let records = self.audit.records();
        let record = records
            .iter()
            .rev()
            .find(|record| record.kind == AuditKind::PolicyDecision)
            .unwrap();
        serde_json::from_value(record.payload["decision"].clone()).unwrap()
    }

    async fn dispatch(&self, action: ActionRequest, principal: &Principal) -> ActionDisposition {
        self.dispatcher.dispatch(action, principal).await.unwrap()
    }
}

fn for_incident(mut action: ActionRequest, incident_id: IncidentId) -> ActionRequest {
    action.incident_id = Some(incident_id);
    action
}

fn status(disposition: &ActionDisposition) -> ActionStatus {
    match disposition {
        ActionDisposition::Executed(outcome) => outcome.status,
        other => panic!("expected an executed action, found {other:?}"),
    }
}

fn is_pending(disposition: &ActionDisposition) -> bool {
    matches!(disposition, ActionDisposition::PendingApproval { .. })
}

#[tokio::test(start_paused = true)]
async fn a_reversible_action_with_a_short_timed_revert_runs_first() {
    let rig = rig();
    let critical = rig.incident(Severity::Critical).await;
    let high = rig.incident(Severity::High).await;
    let targets = [
        (ActionKind::DisableUser, victim_user()),
        (
            ActionKind::DisableServicePrincipal,
            common::rogue_principal(),
        ),
        (ActionKind::BlockIp, spray_address()),
        (
            ActionKind::IsolateHost,
            EntityRef::new(EntityKind::Host, "host-1"),
        ),
        (
            friction::restrict_user_consent(),
            EntityRef::new(EntityKind::Tenant, TENANT),
        ),
        (
            friction::raise_friction(),
            EntityRef::new(EntityKind::Tenant, TENANT),
        ),
    ];

    let mut expected_pending = 0;
    for (kind, target) in targets {
        for (incident_id, seconds) in [(critical, LIMIT), (high, 1)] {
            let action = for_incident(
                timed(request(kind.clone(), target.clone()), seconds),
                incident_id,
            );

            let disposition = rig.dispatch(action, &playbook_engine()).await;

            assert_eq!(status(&disposition), ActionStatus::Succeeded, "{kind:?}");
            let decision = rig.last_decision();
            assert_eq!(decision.policy.as_deref(), Some(RULE), "{kind:?}");
            assert_eq!(
                (decision.effect, decision.tier),
                (PolicyEffect::Allow, ActionTier::Auto),
                "{kind:?}"
            );
            assert_eq!(decision.reasons, [CONTAIN_FIRST], "{kind:?}");
            expected_pending += 1;
        }
    }
    // Each action that ran first has a pending revert.
    assert_eq!(expected_pending, 12);
    assert_eq!(
        rig.scheduler.pending().await.unwrap().len(),
        expected_pending
    );
    assert_eq!(rig.approvals.pending().await.unwrap(), []);
}

#[tokio::test(start_paused = true)]
async fn a_containment_action_with_no_short_timed_revert_needs_approval() {
    let rig = rig();
    let critical = rig.incident(Severity::Critical).await;
    let medium = rig.incident(Severity::Medium).await;
    let disable = || request(ActionKind::DisableUser, victim_user());
    let cases = [
        ("no timed revert", for_incident(disable(), critical)),
        (
            "a revert time above the limit",
            for_incident(timed(disable(), LIMIT + 1), critical),
        ),
        (
            "an incident that is not urgent",
            for_incident(timed(disable(), 600), medium),
        ),
        ("no incident", timed(disable(), 600)),
        (
            "an incident that the store does not have",
            for_incident(timed(disable(), 600), IncidentId::new()),
        ),
        (
            "a custom action that is not in the list",
            for_incident(
                timed(
                    request(
                        ActionKind::Custom("quarantine_mailbox".to_owned()),
                        victim_user(),
                    ),
                    600,
                ),
                critical,
            ),
        ),
        (
            "an action with no inverse",
            for_incident(request(ActionKind::KillSession, victim_user()), critical),
        ),
    ];
    let count = cases.len();
    assert_eq!(count, 7);

    for (case, action) in cases {
        let disposition = rig.dispatch(action, &playbook_engine()).await;

        assert!(is_pending(&disposition), "{case}: {disposition:?}");
        let decision = rig.last_decision();
        assert_eq!(
            (decision.effect, decision.tier),
            (PolicyEffect::RequireApproval, ActionTier::Gated),
            "{case}"
        );
        assert_eq!(decision.reasons, [GATED], "{case}");
    }
    // Nothing ran, and nothing has a pending revert.
    assert_eq!(rig.connector.executed(), []);
    assert_eq!(rig.scheduler.pending().await.unwrap(), []);
    assert_eq!(rig.approvals.pending().await.unwrap().len(), count);

    // The dispatcher refuses a timed revert for an action with no inverse before the policy.
    let error = rig
        .dispatcher
        .dispatch(
            for_incident(
                timed(request(ActionKind::KillSession, victim_user()), 600),
                critical,
            ),
            &playbook_engine(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)), "{error:?}");

    // An action in the auto tier and a dry run follow the default rules.
    let ticket = rig
        .dispatch(
            request(
                ActionKind::OpenTicket,
                EntityRef::new(EntityKind::Other, "identity-team"),
            ),
            &playbook_engine(),
        )
        .await;
    assert_eq!(status(&ticket), ActionStatus::Succeeded);
    assert_eq!(
        rig.last_decision().reasons,
        ["The action is in the auto tier."]
    );
    let mut dry = disable();
    dry.dry_run = true;
    let simulated = rig.dispatch(dry, &playbook_engine()).await;
    assert_eq!(status(&simulated), ActionStatus::Simulated);
    assert_eq!(
        rig.last_decision().reasons,
        ["The request is a dry run. A dry run changes nothing."]
    );
}

#[tokio::test(start_paused = true)]
async fn the_scheduler_reverts_an_action_that_nobody_confirmed_with_no_approval() {
    let rig = rig();
    let critical = rig.incident(Severity::Critical).await;
    let action = for_incident(
        timed(request(ActionKind::DisableUser, victim_user()), 600),
        critical,
    );
    rig.dispatch(action.clone(), &playbook_engine()).await;
    tokio::time::advance(std::time::Duration::from_secs(600)).await;

    let report = rig.scheduler.run_due().await.unwrap();

    assert_eq!(report.len(), 1);
    assert!(
        matches!(&report[0].progress, RevertProgress::Reverted(outcome)
            if outcome.status == ActionStatus::Succeeded),
        "{report:?}"
    );
    let decision = rig.last_decision();
    assert_eq!(
        (decision.effect, decision.tier),
        (PolicyEffect::Allow, ActionTier::Auto)
    );
    assert_eq!(decision.reasons, [TIMED_REVERT]);
    assert_eq!(rig.connector.reverted().len(), 1);
    assert_eq!(rig.connector.reverted()[0].id, action.id);
    assert_eq!(rig.approvals.pending().await.unwrap(), []);
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test(start_paused = true)]
async fn a_revert_that_a_different_identity_requests_needs_approval() {
    let rig = rig();
    let critical = rig.incident(Severity::Critical).await;
    let timed_action = for_incident(
        timed(request(ActionKind::DisableUser, victim_user()), 600),
        critical,
    );
    rig.dispatch(timed_action.clone(), &playbook_engine()).await;
    // An identity with the name of the scheduler that is not a system component.
    let impostor = Principal::new(
        "revert-scheduler",
        PrincipalKind::Agent,
        &["revert-scheduler"],
    );

    for principal in [alice(), responder(), impostor] {
        let disposition = rig
            .dispatcher
            .revert(timed_action.id, &principal, "Enable the account again.")
            .await
            .unwrap();

        assert!(is_pending(&disposition), "{principal:?}: {disposition:?}");
        assert_eq!(rig.last_decision().reasons, [GATED], "{principal:?}");
    }
    assert_eq!(rig.connector.reverted(), []);
    // The containment and its pending revert stay.
    assert_eq!(rig.scheduler.pending().await.unwrap().len(), 1);

    // The scheduler has no free pass for an action that had no timed revert.
    let ticket = request(
        ActionKind::Custom("quarantine_mailbox".to_owned()),
        victim_user(),
    );
    let approval = rig.dispatch(ticket.clone(), &playbook_engine()).await;
    let ActionDisposition::PendingApproval { approval_id, .. } = approval else {
        panic!("expected a pending approval, found {approval:?}");
    };
    rig.approvals
        .decide(approval_id, true, &alice(), None)
        .await
        .unwrap();
    rig.dispatcher.resume(approval_id).await.unwrap();
    let by_scheduler = rig
        .dispatcher
        .revert(
            ticket.id,
            &RevertScheduler::principal(),
            "Remove the quarantine.",
        )
        .await
        .unwrap();
    assert!(is_pending(&by_scheduler), "{by_scheduler:?}");
    let queued = rig.approvals.pending().await.unwrap();
    let last = queued.last().unwrap();
    assert_eq!(
        last.action.parameters[REVERTS_PARAMETER].get("revert_after_seconds"),
        None
    );
    assert_eq!(rig.connector.reverted(), []);
}

#[tokio::test(start_paused = true)]
async fn the_user_playbook_contains_first_under_the_example_policy() {
    let rig = rig();
    let mut incident = rogue_incident();
    incident.severity = Severity::Critical;
    rig.incidents.save(&incident).await.unwrap();
    let text = std::fs::read_to_string(sample_playbook_dir().join("contain-compromised-user.yaml"))
        .unwrap();
    let playbook = Playbook::from_yaml("contain-compromised-user.yaml", &text).unwrap();
    let dispatcher: Arc<dyn ActionDispatcher> = rig.dispatcher.clone();

    let run = PlaybookEngine::new(dispatcher)
        .run(&playbook, &incident, RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.failures(), 0, "{:?}", run.steps);
    let results: Vec<(&str, &str)> = run
        .steps
        .iter()
        .map(|line| {
            let result = match &line.result {
                StepResult::Dispatched(ActionDisposition::Executed(_)) => "executed",
                StepResult::Dispatched(ActionDisposition::PendingApproval { .. }) => "pending",
                _ => "other",
            };
            (line.step.as_str(), result)
        })
        .collect();
    // The stop of the sessions has no inverse, so it waits for a person. The account is
    // disabled immediately, because the step has a timed revert of 4 hours.
    assert_eq!(
        results,
        [
            ("kill-user-sessions", "pending"),
            ("disable-user", "executed"),
            ("open-ticket", "executed"),
        ]
    );
    let changes = rig.connector.changes();
    assert_eq!(
        changes
            .iter()
            .map(|change| change.kind.clone())
            .collect::<Vec<_>>(),
        [ActionKind::DisableUser, ActionKind::OpenTicket]
    );
    assert_eq!(
        changes[0].parameters,
        std::collections::BTreeMap::from([("revert_after_seconds".to_owned(), json!(LIMIT))])
    );
    let pending = rig.scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action_id, changes[0].id);
    assert_eq!(pending[0].revert_after_seconds, LIMIT);

    // A person confirms the disabled account. It then stays disabled.
    rig.scheduler
        .confirm(pending[0].action_id, &alice())
        .await
        .unwrap();
    tokio::time::advance(std::time::Duration::from_secs(LIMIT)).await;
    assert_eq!(rig.scheduler.run_due().await.unwrap(), []);
    assert_eq!(rig.connector.reverted(), []);
}
