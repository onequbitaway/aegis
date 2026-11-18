//! The timed revert in the application: contain first, revert at the revert time unless a
//! person confirms, and keep each pending revert over a restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use aegis_app::report::RunSummary;
use aegis_app::{App, RunOptions};
use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::common::{ActionId, EntityKind, EntityRef, EvidenceKind};
use aegis_contracts::incident::{Incident, IncidentStore};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::{Error, Result};
use aegis_core::{Config, Shutdown};
use aegis_policy::FileAuditLog;
use aegis_respond::revert::{SCHEDULER_ACTOR, event};
use aegis_respond::{PendingRevert, PendingState};
use aegis_testkit::{RecordingConnector, fixtures};
use serde_json::json;
use tokio::task::JoinHandle;

use support::{Starter, WAIT, live, replace_once, spray_events, with_modules};

const MODULES: [&str; 5] = ["ingest", "detection", "monitor", "analyst", "responder"];

/// The revert time of the sample playbooks: 4 hours.
const PLAYBOOK_REVERT_SECONDS: u64 = 4 * 60 * 60;

fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

/// The text of a live configuration with the example policy for "contain first": a
/// reversible action with a short revert time runs with no approval, and the revert
/// scheduler reverts it with no approval. The playbooks run live.
fn contain_first(text: &str) -> String {
    let text = with_modules(&live(text), &MODULES);
    let text = replace_once(&text, "playbooks = \"off\"", "playbooks = \"live\"");
    replace_once(
        &text,
        "paths = [\"policies/default.rego\"]",
        "paths = [\"policies/examples/contain_first_with_timed_revert.rego\"]",
    )
}

fn firewall() -> Arc<RecordingConnector> {
    Arc::new(RecordingConnector::new(
        "firewall",
        vec![ActionKind::BlockIp],
    ))
}

async fn build(starter: &Starter, config: &Config, firewall: &Arc<RecordingConnector>) -> App {
    starter
        .build(config, |builder| builder.action_connector(firewall.clone()))
        .await
}

/// A live application after the password spray. The playbook for the spray blocked the
/// spray address with a revert time of 4 hours.
struct Scenario {
    starter: Starter,
    config: Config,
    app: Arc<App>,
    firewall: Arc<RecordingConnector>,
    incident: Incident,
    pending: PendingRevert,
}

impl Scenario {
    async fn new() -> Self {
        let starter = Starter::new();
        let config = starter.config_with(|text| contain_first(&text));
        let firewall = firewall();
        let app = build(&starter, &config, &firewall).await;

        let report = app.replay(spray_events()).await.unwrap();

        assert!(!report.dry_run);
        assert_eq!(report.incidents.len(), 1);
        let incident = report.incidents[0].clone();
        // The playbook blocked the address. The connector got two calls for the one
        // request: the dry run with which the dispatcher asks if the connector can undo
        // the action, and then the live call.
        let executed = firewall.executed();
        assert_eq!(executed.len(), 2, "{executed:?}");
        assert!(executed[0].dry_run);
        assert!(!executed[1].dry_run);
        assert_eq!(executed[0].id, executed[1].id);
        let live = &executed[1];
        assert_eq!(live.kind, ActionKind::BlockIp);
        assert_eq!(live.target.id, fixtures::SPRAY_IP.to_string());
        assert_eq!(live.requested_by, "playbook:block-password-spray-source");
        assert_eq!(
            live.parameters["revert_after_seconds"],
            json!(PLAYBOOK_REVERT_SECONDS)
        );
        assert_eq!(firewall.reverted(), []);

        let mut pending = app.pending_reverts().await.unwrap();
        assert_eq!(pending.len(), 1);
        let pending = pending.remove(0);
        assert_eq!(pending.action_id, live.id);
        assert_eq!(pending.kind, ActionKind::BlockIp);
        assert_eq!(pending.state, PendingState::Waiting);
        assert_eq!(pending.revert_after_seconds, PLAYBOOK_REVERT_SECONDS);
        assert_eq!(pending.incident_id, Some(incident.id));
        Self {
            starter,
            config,
            app: Arc::new(app),
            firewall,
            incident,
            pending,
        }
    }

    /// Starts the service of the application.
    fn run(&self) -> (Shutdown, JoinHandle<Result<RunSummary>>) {
        let shutdown = Shutdown::new();
        let run = tokio::spawn({
            let (app, shutdown) = (self.app.clone(), shutdown.clone());
            async move { app.run_with(shutdown, RunOptions::default()).await }
        });
        (shutdown, run)
    }
}

async fn stop(shutdown: &Shutdown, run: JoinHandle<Result<RunSummary>>) {
    shutdown.trigger();
    tokio::time::timeout(WAIT, run)
        .await
        .expect("the application did not stop in time")
        .unwrap()
        .unwrap();
}

async fn records(app: &App) -> Vec<AuditRecord> {
    app.audit().read(1, 100_000).await.unwrap()
}

/// Returns the records of the scheduler that have the field `event` set to `name`.
fn scheduler_records<'a>(records: &'a [AuditRecord], name: &str) -> Vec<&'a AuditRecord> {
    records
        .iter()
        .filter(|record| record.kind == AuditKind::Other && record.payload["event"] == name)
        .collect()
}

/// Returns the records of one kind for the revert of `action`.
fn revert_records(records: &[AuditRecord], kind: AuditKind, action: ActionId) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|record| {
            record.kind == kind
                && record.payload["operation"] == "revert"
                && record.payload["reverts"]["action_id"] == json!(action)
        })
        .collect()
}

fn links_to(record: &AuditRecord, kind: EvidenceKind, id: impl ToString) -> bool {
    let id = id.to_string();
    record
        .evidence
        .iter()
        .any(|link| link.kind == kind && link.id == id)
}

#[tokio::test]
async fn the_service_reverts_an_action_at_its_time_when_nobody_confirms() {
    let scenario = Scenario::new().await;
    let action = scenario.pending.action_id;
    let scheduler = scenario.app.revert_scheduler().unwrap();
    let (shutdown, run) = scenario.run();

    // The clock of the test moves to the next timer when no task has work. Thus the 4
    // hours of the revert time pass at once.
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let mut stats = scheduler.watch();
    tokio::time::timeout(
        Duration::from_secs(PLAYBOOK_REVERT_SECONDS + 3600),
        stats.wait_for(|stats| stats.reverted == 1),
    )
    .await
    .expect("the scheduler did not revert the action")
    .unwrap();
    let waited = started.elapsed();
    tokio::time::resume();
    stop(&shutdown, run).await;

    // The scheduler did the revert at the revert time, not before.
    assert!(
        waited >= Duration::from_secs(PLAYBOOK_REVERT_SECONDS - 60)
            && waited <= Duration::from_secs(PLAYBOOK_REVERT_SECONDS + 60),
        "{waited:?}"
    );
    let reverted = scenario.firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action);
    assert_eq!(reverted[0].target.id, fixtures::SPRAY_IP.to_string());
    assert_eq!(scenario.app.pending_reverts().await.unwrap(), []);
    assert_eq!(scheduler.stats().reverted, 1);
    assert_eq!(scheduler.stats().failed_attempts, 0);

    // The audit log has each step of the revert, and each record links to the action.
    let records = records(&scenario.app).await;
    let executed: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| {
            record.kind == AuditKind::ActionExecuted && record.payload["action_id"] == json!(action)
        })
        .collect();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].payload["timed_revert"]["state"], "scheduled");
    assert_eq!(
        executed[0].payload["timed_revert"]["after_seconds"],
        PLAYBOOK_REVERT_SECONDS
    );

    let proposed = revert_records(&records, AuditKind::ActionProposed, action);
    assert_eq!(proposed.len(), 1);
    // The scheduler requests the revert as itself. No person and no agent did.
    assert_eq!(proposed[0].actor, SCHEDULER_ACTOR);
    assert_eq!(proposed[0].payload["principal"]["kind"], "system");
    assert_eq!(
        proposed[0].payload["action"]["kind"],
        json!({ "custom": "revert" })
    );
    let decisions = revert_records(&records, AuditKind::PolicyDecision, action);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].payload["decision"]["effect"], "allow");
    let done = revert_records(&records, AuditKind::ActionExecuted, action);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].payload["outcome"]["status"], "succeeded");
    assert_eq!(done[0].payload["connector"], "firewall");
    let revert_id = done[0].payload["action_id"].as_str().unwrap().to_owned();
    assert_ne!(revert_id, action.to_string());
    for record in [proposed[0], decisions[0], done[0]] {
        assert!(links_to(record, EvidenceKind::Action, action), "{record:?}");
        assert!(
            links_to(record, EvidenceKind::Action, &revert_id),
            "{record:?}"
        );
        assert!(
            links_to(record, EvidenceKind::Incident, scenario.incident.id),
            "{record:?}"
        );
    }
    let completed = scheduler_records(&records, event::COMPLETED);
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].actor, SCHEDULER_ACTOR);
    assert_eq!(completed[0].payload["action_id"], json!(action));
    assert!(links_to(completed[0], EvidenceKind::Action, action));
    // The order in the chain: the action, the proposal of the revert, its execution, and
    // the record of the scheduler.
    assert!(executed[0].sequence < proposed[0].sequence);
    assert!(proposed[0].sequence < done[0].sequence);
    assert!(done[0].sequence < completed[0].sequence);

    // The chain verifies in the application and from the file.
    let verification = scenario.app.audit().verify().await.unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.checked, records.len() as u64);
    drop(scenario.app);
    let from_file = FileAuditLog::verify_file(scenario.starter.audit_file()).unwrap();
    assert!(from_file.valid, "{from_file:?}");
    assert_eq!(from_file.checked, records.len() as u64);
}

#[tokio::test]
async fn a_confirmation_keeps_the_action_and_needs_the_permission_to_approve() {
    let scenario = Scenario::new().await;
    let action = scenario.pending.action_id;
    let scheduler = scenario.app.revert_scheduler().unwrap();

    // A person who can only read, and an agent with the role of an approver.
    let vera = Principal::new("vera@example.com", PrincipalKind::Human, &["analyst"]);
    let error = scenario
        .app
        .confirm_revert(action, &vera)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    let agent = Principal::new("responder", PrincipalKind::Agent, &["approver"]);
    let error = scenario
        .app
        .confirm_revert(action, &agent)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message)
            if message == "only a person can confirm a timed revert; responder is not a person"),
        "{error:?}"
    );
    for refused in [&vera, &agent] {
        let error = scenario
            .app
            .extend_revert(action, refused, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    }
    let error = scenario.app.cancel_revert(action, &vera).await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    let error = scenario
        .app
        .revert_action(action, &vera, "A test.")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    assert_eq!(scenario.app.pending_reverts().await.unwrap().len(), 1);
    assert_eq!(scenario.firewall.reverted(), []);

    let confirmed = scenario.app.confirm_revert(action, &alice()).await.unwrap();
    assert_eq!(confirmed, scenario.pending);
    assert_eq!(scenario.app.pending_reverts().await.unwrap(), []);

    // The service runs past the revert time. It reverts nothing.
    let (shutdown, run) = scenario.run();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(PLAYBOOK_REVERT_SECONDS + 3600)).await;
    assert_eq!(scheduler.run_due().await.unwrap(), []);
    tokio::time::resume();
    stop(&shutdown, run).await;
    assert_eq!(scenario.firewall.reverted(), []);
    assert_eq!(scheduler.stats().confirmed, 1);
    assert_eq!(scheduler.stats().reverted, 0);

    let records = records(&scenario.app).await;
    let confirmations = scheduler_records(&records, event::CONFIRMED);
    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].actor, "alice@example.com");
    assert_eq!(
        confirmations[0].payload["principal"],
        serde_json::to_value(alice()).unwrap()
    );
    assert!(links_to(confirmations[0], EvidenceKind::Action, action));
    assert_eq!(
        revert_records(&records, AuditKind::ActionProposed, action).len(),
        0
    );
    assert!(scenario.app.audit().verify().await.unwrap().valid);
}

#[tokio::test]
async fn a_restart_keeps_the_pending_revert_and_the_new_process_does_the_revert() {
    let scenario = Scenario::new().await;
    let action = scenario.pending.action_id;
    let Scenario {
        starter,
        config,
        app,
        firewall,
        pending,
        ..
    } = scenario;
    let store = starter.path().join("data/pending-reverts.json");
    assert!(store.is_file());
    // The first process stops. One process writes one audit file.
    drop(app);

    // The second process reads the pending revert from the file.
    let second = Arc::new(build(&starter, &config, &firewall).await);
    assert_eq!(second.pending_reverts().await.unwrap(), [pending]);
    assert_eq!(firewall.reverted(), []);

    let scheduler = second.revert_scheduler().unwrap();
    let shutdown = Shutdown::new();
    let run = tokio::spawn({
        let (app, shutdown) = (second.clone(), shutdown.clone());
        async move { app.run_with(shutdown, RunOptions::default()).await }
    });
    tokio::time::pause();
    let mut stats = scheduler.watch();
    tokio::time::timeout(
        Duration::from_secs(PLAYBOOK_REVERT_SECONDS + 3600),
        stats.wait_for(|stats| stats.reverted == 1),
    )
    .await
    .expect("the second process did not revert the action")
    .unwrap();
    tokio::time::resume();
    stop(&shutdown, run).await;

    let reverted = firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action);
    assert_eq!(second.pending_reverts().await.unwrap(), []);
    // The audit log of the two processes is one chain. The revert links to the action
    // that the first process did.
    let records = records(&second).await;
    let done = revert_records(&records, AuditKind::ActionExecuted, action);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].payload["outcome"]["status"], "succeeded");
    assert!(links_to(done[0], EvidenceKind::Action, action));
    assert_eq!(scheduler_records(&records, event::COMPLETED).len(), 1);
    assert!(second.audit().verify().await.unwrap().valid);
}

/// Makes a request to block one address for the incident, with a revert time.
fn block_request(incident: &Incident, address: &str, revert_after: Option<u64>) -> ActionRequest {
    let mut request = ActionRequest::new(
        ActionKind::BlockIp,
        EntityRef::new(EntityKind::IpAddress, address),
        "responder",
        "The attack came from this address.",
    );
    request.incident_id = Some(incident.id);
    if let Some(seconds) = revert_after {
        request
            .parameters
            .insert("revert_after_seconds".to_owned(), seconds.into());
    }
    request
}

fn responder() -> Principal {
    Principal::new("responder", PrincipalKind::Agent, &["responder"])
}

#[tokio::test]
async fn a_person_reverts_an_action_now_and_the_revert_goes_through_the_policy() {
    let scenario = Scenario::new().await;
    let action = scenario.pending.action_id;

    // With the example policy, a revert that a person requests needs approval. The
    // containment stays, and the pending revert stays.
    let disposition = scenario.app.cancel_revert(action, &alice()).await.unwrap();
    let ActionDisposition::PendingApproval { approval_id, .. } = disposition else {
        panic!("expected a pending approval, found {disposition:?}");
    };
    assert_eq!(scenario.firewall.reverted(), []);
    assert_eq!(scenario.app.pending_reverts().await.unwrap().len(), 1);
    let approval = scenario
        .app
        .approvals()
        .get(approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approval.requested_by, alice());
    assert_eq!(
        approval.action.kind,
        ActionKind::Custom("revert".to_owned())
    );

    // The four-eyes rule: a second person approves the revert of Alice.
    let error = scenario
        .app
        .decide_approval(approval_id, true, &alice(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    let bob = Principal::new("bob@example.com", PrincipalKind::Human, &["approver"]);
    let outcome = scenario
        .app
        .decide_approval(approval_id, true, &bob, None)
        .await
        .unwrap();
    assert!(
        matches!(&outcome.disposition, Some(ActionDisposition::Executed(done))
            if done.status == ActionStatus::Succeeded),
        "{outcome:?}"
    );
    let reverted = scenario.firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action);
    // The action is reverted, so no timed revert waits for it.
    assert_eq!(scenario.app.pending_reverts().await.unwrap(), []);

    // One execution can be reverted one time.
    let error = scenario
        .app
        .revert_action(action, &alice(), "A second revert.")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)), "{error:?}");
    assert_eq!(scenario.firewall.reverted().len(), 1);

    let records = records(&scenario.app).await;
    let proposed = revert_records(&records, AuditKind::ActionProposed, action);
    assert_eq!(proposed.len(), 2);
    assert_eq!(proposed[0].actor, "alice@example.com");
    assert!(scenario.app.audit().verify().await.unwrap().valid);
}

#[tokio::test]
async fn with_no_revert_table_a_live_action_with_a_revert_time_does_not_run() {
    let starter = Starter::new();
    // The configuration has no `[response.revert]` table.
    let config = starter.config_with(|text| {
        let text = contain_first(&text);
        let start = text.find("[response.revert]").unwrap();
        let end = start + text[start..].find("\n\n").unwrap();
        format!("{}{}", &text[..start], &text[end..])
    });
    let firewall = firewall();
    let app = build(&starter, &config, &firewall).await;
    assert!(app.revert_scheduler().is_none());
    assert!(app.settings().response.revert.is_none());

    let report = app.replay(spray_events()).await.unwrap();

    // The dispatcher cannot keep the pending revert, so the connector got no live call.
    assert_eq!(firewall.executed(), []);
    assert_eq!(firewall.reverted(), []);
    let refused: Vec<_> = report
        .actions
        .iter()
        .filter(|record| record.request.requested_by == "playbook:block-password-spray-source")
        .filter(|record| record.request.kind == ActionKind::BlockIp)
        .collect();
    assert_eq!(refused.len(), 1);
    assert!(
        matches!(&refused[0].result, aegis_app::actions::DispatchResult::Failed { kind, message, .. }
            if kind == "config" && message.contains("the dispatcher has no revert store")),
        "{:?}",
        refused[0].result
    );
    assert_eq!(app.pending_reverts().await.unwrap(), []);
    assert!(!starter.path().join("data/pending-reverts.json").exists());

    // A person cannot decide a timed revert in this process.
    let error = app
        .confirm_revert(refused[0].request.id, &alice())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unsupported(message)
            if message == "the timed revert is off: the configuration has no `[response.revert]` table"),
        "{error:?}"
    );

    // A request with no revert time runs as before: the default tier gates it.
    let incident = &report.incidents[0];
    let disposition = app
        .actions()
        .dispatch(block_request(incident, "203.0.113.99", None), &responder())
        .await
        .unwrap();
    assert!(
        matches!(disposition, ActionDisposition::PendingApproval { .. }),
        "{disposition:?}"
    );
}

#[tokio::test]
async fn a_second_application_with_its_own_audit_file_has_no_revert_store() {
    let scenario = Scenario::new().await;
    // A second application on the same host, for example `aegis replay --audit-file`. It
    // must not write the revert store of the service.
    let second = scenario
        .starter
        .build(&scenario.config, |builder| {
            builder
                .action_connector(scenario.firewall.clone())
                .audit_file("data/second-audit.jsonl")
        })
        .await;
    assert!(second.revert_scheduler().is_none());
    second.incidents().save(&scenario.incident).await.unwrap();

    let error = second
        .actions()
        .dispatch(
            block_request(&scenario.incident, "203.0.113.77", Some(600)),
            &responder(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("has no revert store")),
        "{error:?}"
    );
    // The connector got no call for this request, and the store of the service has its
    // one revert.
    assert_eq!(scenario.firewall.executed().len(), 2);
    assert_eq!(
        scenario.app.pending_reverts().await.unwrap(),
        std::slice::from_ref(&scenario.pending)
    );
}

#[tokio::test]
async fn a_store_file_that_is_not_valid_stops_the_build() {
    let starter = Starter::new();
    std::fs::write(
        starter.path().join("data/pending-reverts.json"),
        "{ not a store file",
    )
    .unwrap();
    let error = match App::builder(&starter.config())
        .base_dir(starter.path())
        .build()
        .await
    {
        Ok(_) => panic!("the build must fail"),
        Err(error) => error,
    };
    // An empty store in place of the file would lose the pending reverts.
    assert!(
        matches!(&error, Error::Integrity(message) if message.starts_with("[response] ")),
        "{error:?}"
    );
}
