//! Service mode: the application reads a file source through the bus, and stops cleanly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aegis_app::actions::DispatchResult;
use aegis_app::{App, RunOptions, Service, starter};
use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::bus::subject;
use aegis_contracts::common::Severity;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::{Detection, Error};
use aegis_core::Shutdown;
use aegis_ingest::RunOutcome;
use aegis_policy::FileAuditLog;
use aegis_testkit::fixtures;
use futures::StreamExt;

use support::{Starter, WAIT, replace_once, with_modules};

const SOURCE: &str =
    "\n[[sources]]\ntype = \"file\"\nname = \"recorded\"\npath = \"events.jsonl\"\n";

/// A starter directory with the recorded attack log as a file source.
fn starter_with_source() -> Starter {
    let starter = Starter::new();
    std::fs::write(starter.path().join("events.jsonl"), starter::attack_log()).unwrap();
    starter
}

async fn the_incident(app: &App) -> Option<Incident> {
    let mut incidents = app.incidents().list(None, 10).await.unwrap();
    assert!(incidents.len() <= 1, "{}", incidents.len());
    incidents.pop()
}

/// The (kind, target) pairs of the actions that the Responder proposed.
fn responder_actions(app: &App) -> BTreeSet<(ActionKind, String)> {
    app.actions()
        .records()
        .iter()
        .filter(|action| action.request.requested_by == "responder")
        .map(|action| {
            (
                action.request.kind.clone(),
                action.request.target.id.clone(),
            )
        })
        .collect()
}

/// Returns `true` if the Responder recorded the result of each of its six actions.
fn has_each_result(incident: &Incident) -> bool {
    incident.timeline.iter().any(|entry| {
        entry.author == "responder"
            && entry.description
                == "Containment is not complete. Of 6 actions: 0 ran, 6 were dry runs, 0 wait \
                    for approval, 0 were denied, 0 failed. The incident stays open."
    })
}

fn expected_responder_actions() -> BTreeSet<(ActionKind, String)> {
    BTreeSet::from([
        (ActionKind::BlockIp, fixtures::SPRAY_IP.to_string()),
        (ActionKind::BlockIp, fixtures::WORKLOAD_IP.to_string()),
        (ActionKind::BlockIp, fixtures::DISTANT_IP.to_string()),
        (ActionKind::KillSession, fixtures::VICTIM_USER_ID.to_owned()),
        (
            ActionKind::DisableServicePrincipal,
            fixtures::ROGUE_PRINCIPAL_ID.to_owned(),
        ),
        (
            ActionKind::RevokeCredential,
            fixtures::ROGUE_PRINCIPAL_ID.to_owned(),
        ),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_service_processes_the_file_source_end_to_end_and_stops_on_shutdown() {
    let starter = starter_with_source();
    let config = starter.config_with(|text| text + SOURCE);
    let app = Arc::new(starter.build(&config, |builder| builder).await);
    assert_eq!(app.sources().names(), ["recorded"]);

    let shutdown = Shutdown::new();
    let service = tokio::spawn({
        let (app, shutdown) = (app.clone(), shutdown.clone());
        async move { app.run(shutdown).await }
    });

    // Wait for the state that the full attack log gives: all events examined, the
    // incident with all detections in the store, each playbook, and each containment
    // action of the Responder through the dispatcher and back in the timeline.
    let reached = app
        .wait_until(WAIT, || {
            let app = app.clone();
            async move {
                let progress = app.progress();
                if progress.events_processed < fixtures::ATTACK_LOG_EVENTS as u64
                    || progress.playbook_runs < 4
                {
                    return false;
                }
                let Some(incident) = the_incident(&app).await else {
                    return false;
                };
                incident.detections.len() == 8
                    && incident.status == IncidentStatus::Investigating
                    && responder_actions(&app) == expected_responder_actions()
                    && has_each_result(&incident)
            }
        })
        .await;
    assert!(
        reached.is_ok(),
        "progress {:?}, incident {:?}, responder actions {:?}",
        app.progress(),
        the_incident(&app).await.map(|incident| (
            incident.status,
            incident.detections.len(),
            incident
                .timeline
                .iter()
                .map(|entry| format!("{}: {}", entry.author, entry.description))
                .collect::<Vec<_>>()
        )),
        responder_actions(&app)
    );
    assert!(!service.is_finished());

    shutdown.trigger();
    let result = tokio::time::timeout(WAIT, service).await.unwrap().unwrap();
    assert!(result.is_ok(), "{result:?}");

    // The source published each event one time, and the engine examined each one.
    let progress = app.progress();
    assert_eq!(
        progress.events_published,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(
        progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(progress.detections, 8);
    assert_eq!(progress.playbook_runs, 4);

    let incident = the_incident(&app).await.unwrap();
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.status, IncidentStatus::Investigating);
    assert_eq!(incident.detections.len(), 8);

    // Each action was a dry run. Nothing changed.
    let actions = app.actions().records();
    assert!(actions.len() >= 16, "{}", actions.len());
    for action in &actions {
        assert!(action.request.dry_run, "{:?}", action.request.kind);
        assert!(
            matches!(&action.result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated),
            "{:?}",
            action.result
        );
    }

    // The audit log on the disk verifies, and it has the records of each step.
    let verification = FileAuditLog::verify_file(starter.audit_file()).unwrap();
    assert!(verification.valid, "{verification:?}");
    let records = app.audit().read(1, 100_000).await.unwrap();
    assert_eq!(records.len() as u64, verification.checked);
    let count = |kind: AuditKind| records.iter().filter(|record| record.kind == kind).count();
    assert_eq!(count(AuditKind::Detection), 8);
    assert_eq!(count(AuditKind::ActionProposed), actions.len());
    assert_eq!(count(AuditKind::ActionExecuted), actions.len());

    // A second run of the same application is possible after the first one stopped.
    let again = Shutdown::new();
    again.trigger();
    let summary = tokio::time::timeout(WAIT, app.run_with(again, RunOptions::default()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        summary.progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_monitoring_session_stops_at_the_end_of_the_sources_and_takes_no_action() {
    let starter = starter_with_source();
    let config = starter
        .config_with(|text| with_modules(&text, &["ingest", "detection", "monitor"]) + SOURCE);
    let app = Arc::new(starter.build(&config, |builder| builder).await);
    let bus = app.bus();
    let mut detections = bus
        .subscribe(&format!("{}.>", subject::DETECTIONS), None)
        .await
        .unwrap();
    let mut incidents = bus.subscribe(subject::INCIDENTS, None).await.unwrap();

    let options = RunOptions {
        stop_when_sources_end: true,
        services: Vec::new(),
    };
    let summary = tokio::time::timeout(WAIT, app.run_with(Shutdown::new(), options))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(summary.sources.len(), 1);
    assert_eq!(summary.sources[0].name, "recorded");
    assert_eq!(summary.sources[0].outcome, RunOutcome::Completed);
    assert_eq!(
        summary.sources[0].stats.events_published,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(
        summary.progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(summary.progress.detections, 8);
    assert_eq!(summary.progress.incident_updates, 7);
    assert_eq!(summary.progress.playbook_runs, 0);

    // The bus has each detection and each state of the incident, in order.
    let mut rule_ids = Vec::new();
    for _ in 0..8 {
        let message = tokio::time::timeout(WAIT, detections.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(message.subject, "aegis.detections.deterministic");
        rule_ids.push(message.decode::<Detection>().unwrap().rule_id);
    }
    assert_eq!(rule_ids[0], "aegis.velocity.sign_in_burst");
    assert_eq!(rule_ids[7], "0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940");
    let mut states = Vec::new();
    for _ in 0..7 {
        let message = tokio::time::timeout(WAIT, incidents.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        states.push(message.decode::<Incident>().unwrap());
    }
    assert_eq!(
        states
            .iter()
            .map(|state| state.detections.len())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 6, 7, 8]
    );
    assert_eq!(states[6].severity, Severity::Critical);

    // A monitoring session has no Responder: no action request went to the dispatcher.
    assert_eq!(app.actions().records(), []);
    let incident = the_incident(&app).await.unwrap();
    assert_eq!(incident.detections.len(), 8);
    let records = app.audit().read(1, 100_000).await.unwrap();
    assert!(
        records
            .iter()
            .all(|record| record.kind != AuditKind::ActionProposed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_component_that_fails_stops_the_service_with_its_error() {
    // The source file has a line that is not an event. The ingestion runner fails, and
    // the service must not continue as a half-running system.
    let starter = Starter::new();
    let good = starter::attack_log().lines().next().unwrap();
    std::fs::write(
        starter.path().join("events.jsonl"),
        format!("{good}\nthis line is not an event\n"),
    )
    .unwrap();
    let config = starter.config_with(|text| text + SOURCE);
    let app = starter.build(&config, |builder| builder).await;
    let stopped = Arc::new(AtomicBool::new(false));
    let extra = Service::new("watcher", {
        let stopped = stopped.clone();
        move |shutdown: Shutdown| async move {
            shutdown.wait().await;
            stopped.store(true, Ordering::SeqCst);
            Ok(())
        }
    });
    let shutdown = Shutdown::new();

    let options = RunOptions {
        stop_when_sources_end: false,
        services: vec![extra],
    };
    let error = tokio::time::timeout(WAIT, app.run_with(shutdown.clone(), options))
        .await
        .unwrap()
        .unwrap_err();

    assert!(
        matches!(&error, Error::Serialization(message) if message.contains("line 2")),
        "{error:?}"
    );
    // The other components got the stop signal. The signal of the caller is not changed.
    assert!(stopped.load(Ordering::SeqCst));
    assert!(!shutdown.is_triggered());
    assert_eq!(app.progress().events_published, 1);
}

#[tokio::test]
async fn one_run_at_a_time_and_the_api_module_needs_a_service() {
    let starter = Starter::new();
    let app = Arc::new(starter.app().await);
    let shutdown = Shutdown::new();
    let first = tokio::spawn({
        let (app, shutdown) = (app.clone(), shutdown.clone());
        async move { app.run(shutdown).await }
    });
    // The first run holds the application when its start record is in the audit log.
    app.wait_until(WAIT, || {
        let app = app.clone();
        async move { app.audit().read(1, 1).await.unwrap().len() == 1 }
    })
    .await
    .unwrap();

    let second = app.run(Shutdown::new()).await.unwrap_err();
    assert!(
        matches!(&second, Error::InvalidInput(message) if message.starts_with("the application already runs")),
        "{second:?}"
    );
    let replay = app.replay(Vec::new()).await.unwrap_err();
    assert!(matches!(replay, Error::InvalidInput(_)), "{replay:?}");
    shutdown.trigger();
    tokio::time::timeout(WAIT, first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // The module `api` is in the set, and the program gives no service for it.
    let with_api = Starter::new();
    let config =
        with_api.config_with(|text| replace_once(&text, "\"reporter\"]", "\"reporter\", \"api\"]"));
    let app = with_api.build(&config, |builder| builder).await;
    let error = app.run(Shutdown::new()).await.unwrap_err();
    assert!(
        matches!(&error, Error::Config(message)
            if message == "the section `modules` is not valid: the module `api` is enabled, \
                but this program has no operator API"),
        "{error:?}"
    );
    // With a service for the module, the run starts.
    let started = Arc::new(AtomicBool::new(false));
    let api = Service::new("api", {
        let started = started.clone();
        move |shutdown: Shutdown| async move {
            started.store(true, Ordering::SeqCst);
            shutdown.wait().await;
            Ok(())
        }
    })
    .for_module(aegis_core::Module::Api);
    let shutdown = Shutdown::new();
    shutdown.trigger();
    let options = RunOptions {
        stop_when_sources_end: false,
        services: vec![api],
    };
    tokio::time::timeout(WAIT, app.run_with(shutdown, options))
        .await
        .unwrap()
        .unwrap();
    assert!(started.load(Ordering::SeqCst));
}
