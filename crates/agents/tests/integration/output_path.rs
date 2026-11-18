//! The path from an agent output to the stores, the dispatcher, the audit log, and the bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_agents::{RunReport, RuntimeConfig, RuntimeLimits, TaskState};
use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification};
use aegis_contracts::bus::subject;
use aegis_contracts::common::{
    EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId, TaskId,
};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::{
    Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Error, Result,
};
use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
use async_trait::async_trait;
use serde_json::json;

use crate::support::{Bench, GOAL, Probe, attack_incident, config_for, drive, runtime_with};

fn host() -> EntityRef {
    EntityRef::new(EntityKind::Host, "host-1")
}

fn tag(reason: &str) -> ActionRequest {
    ActionRequest::new(ActionKind::Tag, host(), "someone-else", reason)
}

fn note(role: AgentRole, text: &str) -> AgentTask {
    AgentTask::new(role, AgentInput::Note(text.to_owned()))
}

/// Makes a Monitor that returns `output` for a note and nothing for each other input.
fn monitor_with(output: AgentOutput) -> Arc<Probe> {
    Probe::new(AgentRole::Monitor, move |task| {
        Ok(match &task.input {
            AgentInput::Note(text) if text == "start" => output.clone(),
            _ => AgentOutput::default(),
        })
    })
}

fn live(roles: &[AgentRole]) -> RuntimeConfig {
    RuntimeConfig {
        dry_run: false,
        ..config_for(roles)
    }
}

#[tokio::test]
async fn the_runtime_applies_each_part_of_an_agent_output() {
    let mut incident = attack_incident();
    incident.status = IncidentStatus::Investigating;
    let detection_link = EvidenceRef::new(EvidenceKind::Detection, incident.detections[0].id);
    let mut request = tag("Label the host\nfor the security team.");
    request.evidence = vec![detection_link.clone()];
    let action_id = request.id;
    let monitor = monitor_with(AgentOutput {
        // The agent names a different sender. The runtime knows the real one.
        tasks: vec![note(AgentRole::Analyst, "next").from_role(AgentRole::Reporter)],
        actions: vec![request.clone()],
        incidents: vec![incident.clone()],
        notes: vec![
            "The first decision.".to_owned(),
            "The second\n  decision.".to_owned(),
        ],
    });
    let analyst = Probe::quiet(AgentRole::Analyst);
    let bench = Bench::with_agents(
        config_for(&[AgentRole::Monitor, AgentRole::Analyst]),
        vec![monitor.clone(), analyst.clone()],
    );
    let start = note(AgentRole::Monitor, "start").for_incident(incident.id);
    bench.runtime.submit(start.clone()).unwrap();
    let run = bench.drive().await;
    assert_eq!(
        run,
        RunReport {
            tasks_completed: 3,
            actions_dispatched: 1,
            ..RunReport::default()
        }
    );

    // The incident is in the store.
    assert_eq!(bench.stored(incident.id).await, incident);

    // The dispatcher got the action with a principal for the agent. The runtime set the
    // requester, the incident, and the dry run.
    let requests = bench.dispatcher.requests();
    assert_eq!(requests.len(), 1);
    let (dispatched, principal) = &requests[0];
    assert_eq!(
        *dispatched,
        ActionRequest {
            requested_by: "monitor".to_owned(),
            incident_id: Some(incident.id),
            dry_run: true,
            ..request.clone()
        }
    );
    assert_eq!(
        *principal,
        Principal::new("monitor", PrincipalKind::Agent, &["monitor"])
    );

    // The bus has the request. The runtime does not publish the result: the dispatcher is
    // the single publisher of `aegis.actions.results`.
    let published: Vec<ActionRequest> = bench
        .harness
        .bus
        .published_to(subject::ACTION_REQUESTS)
        .iter()
        .map(|message| message.decode().unwrap())
        .collect();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0], *dispatched);
    assert_eq!(bench.harness.bus.published_to(subject::ACTION_RESULTS), []);
    assert_eq!(bench.harness.bus.published().len(), 1);

    // The agent got the result as a task with the identifier of the action.
    let seen = monitor.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], start);
    assert_eq!(seen[1].id, TaskId(action_id.0));
    assert_eq!(seen[1].to, AgentRole::Monitor);
    assert_eq!(seen[1].from, None);
    assert_eq!(seen[1].incident_id, Some(incident.id));
    let AgentInput::ActionResult(result) = &seen[1].input else {
        panic!("the task must hold an action result: {:?}", seen[1].input);
    };
    assert!(
        matches!(result.as_ref(), ActionDisposition::Executed(outcome)
            if outcome.action_id == action_id && outcome.status == ActionStatus::Simulated),
        "{result:?}"
    );

    // The new task is in the queue of its role, with the real sender and the incident.
    let next = analyst.seen();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].from, Some(AgentRole::Monitor));
    assert_eq!(next[0].incident_id, Some(incident.id));
    assert_eq!(next[0].input, AgentInput::Note("next".to_owned()));

    // The audit log has the change of the incident, each note, and the decision for the
    // action, in this order.
    let records = bench.harness.audit.records();
    let found: Vec<(AuditKind, &str, &str)> = records
        .iter()
        .map(|record| (record.kind, record.actor.as_str(), record.summary.as_str()))
        .collect();
    let changed = format!(
        "The monitor agent changed the incident {} from no state to investigating.",
        incident.id
    );
    assert_eq!(
        found,
        [
            (AuditKind::AgentDecision, "monitor", changed.as_str()),
            (AuditKind::AgentDecision, "monitor", "The first decision."),
            (AuditKind::AgentDecision, "monitor", "The second decision."),
            (
                AuditKind::AgentDecision,
                "monitor",
                "The monitor agent proposed tag on host:host-1: Label the host for the \
                 security team."
            ),
        ]
    );
    let incident_link = EvidenceRef::new(EvidenceKind::Incident, incident.id);
    assert_eq!(records[0].evidence.len(), 6);
    assert_eq!(records[0].evidence[0], incident_link);
    assert_eq!(
        records[0].payload,
        json!({
            "task_id": start.id,
            "incident_id": incident.id,
            "from": null,
            "to": "investigating"
        })
    );
    assert_eq!(records[1].evidence, std::slice::from_ref(&incident_link));
    assert_eq!(
        records[1].payload,
        json!({ "task_id": start.id, "incident_id": incident.id, "input": "note" })
    );
    assert_eq!(
        records[3].evidence,
        [
            detection_link,
            EvidenceRef::new(EvidenceKind::Action, action_id)
        ]
    );
    assert_eq!(
        records[3].payload,
        json!({
            "task_id": start.id,
            "action_id": action_id,
            "incident_id": incident.id,
            "kind": "tag",
            "target": "host:host-1",
            "dry_run": true
        })
    );
    let verification = bench.harness.audit.verify().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checked, 4);

    // The records of the tasks have the depth of each task.
    let tasks: Vec<(AgentRole, u64, TaskState)> = bench
        .runtime
        .recent_tasks()
        .into_iter()
        .map(|record| (record.role, record.depth, record.state))
        .collect();
    assert_eq!(
        tasks,
        [
            (AgentRole::Monitor, 0, TaskState::Completed),
            (AgentRole::Monitor, 1, TaskState::Completed),
            (AgentRole::Analyst, 1, TaskState::Completed),
        ]
    );
}

#[tokio::test]
async fn with_the_dry_run_off_an_agent_can_still_ask_for_a_dry_run() {
    let mut cautious = tag("Try the label.");
    cautious.dry_run = true;
    let real = tag("Set the label.");
    let monitor = monitor_with(AgentOutput {
        actions: vec![real.clone(), cautious.clone()],
        ..AgentOutput::default()
    });
    let bench = Bench::with_agents(live(&[AgentRole::Monitor]), vec![monitor.clone()]);
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "start"))
        .unwrap();
    let run = bench.drive().await;
    assert_eq!(run.actions_dispatched, 2);

    let requests = bench.dispatcher.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0.id, real.id);
    assert!(!requests[0].0.dry_run);
    assert_eq!(requests[0].0.incident_id, None);
    assert_eq!(requests[1].0.id, cautious.id);
    assert!(requests[1].0.dry_run);

    let statuses: Vec<ActionStatus> = monitor.seen()[1..]
        .iter()
        .map(|task| match &task.input {
            AgentInput::ActionResult(disposition) => match disposition.as_ref() {
                ActionDisposition::Executed(outcome) => outcome.status,
                other => panic!("the action must run: {other:?}"),
            },
            other => panic!("the task must hold a result: {other:?}"),
        })
        .collect();
    assert_eq!(statuses, [ActionStatus::Succeeded, ActionStatus::Simulated]);
}

#[tokio::test]
async fn an_agent_error_goes_to_the_audit_log_and_does_not_stop_the_runtime() {
    let monitor = Probe::new(AgentRole::Monitor, |task| match &task.input {
        AgentInput::Note(text) if text == "fail" => {
            Err(Error::Unavailable("the graph is down".to_owned()))
        }
        _ => Ok(AgentOutput {
            notes: vec!["The work is done.".to_owned()],
            ..AgentOutput::default()
        }),
    });
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![monitor.clone()]);
    let incident = IncidentId::new();
    let failing = note(AgentRole::Monitor, "fail").for_incident(incident);
    let working = note(AgentRole::Monitor, "work").for_incident(incident);
    bench.runtime.submit(failing.clone()).unwrap();
    bench.runtime.submit(working.clone()).unwrap();
    let run = bench.drive().await;

    assert_eq!(
        run,
        RunReport {
            tasks_completed: 1,
            tasks_failed: 1,
            ..RunReport::default()
        }
    );
    assert_eq!(monitor.seen(), [failing.clone(), working.clone()]);
    assert_eq!(
        bench.runtime.task_state(failing.id),
        Some(TaskState::Failed)
    );
    assert_eq!(
        bench.runtime.task_state(working.id),
        Some(TaskState::Completed)
    );
    assert_eq!(
        bench.runtime.recent_tasks()[0].detail.as_deref(),
        Some("unavailable: the graph is down")
    );

    let records = bench.harness.audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].kind, AuditKind::Other);
    assert_eq!(records[0].actor, "monitor");
    assert_eq!(
        records[0].summary,
        format!(
            "The monitor agent failed on the task {}: unavailable: the graph is down",
            failing.id
        )
    );
    assert_eq!(
        records[0].payload,
        json!({
            "task_id": failing.id,
            "incident_id": incident,
            "input": "note",
            "retryable": true
        })
    );
    assert_eq!(
        records[0].evidence,
        [EvidenceRef::new(EvidenceKind::Incident, incident)]
    );
    assert_eq!(records[1].kind, AuditKind::AgentDecision);
    assert_eq!(records[1].summary, "The work is done.");
    assert!(bench.runtime.is_idle());
}

#[tokio::test]
async fn a_panic_of_an_agent_is_a_failed_task() {
    struct Defective;

    #[async_trait]
    impl Agent for Defective {
        fn role(&self) -> AgentRole {
            AgentRole::Hunter
        }

        async fn handle(&self, _: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
            panic!("the agent has a defect")
        }
    }

    let monitor = Probe::quiet(AgentRole::Monitor);
    let bench = Bench::with_agents(
        config_for(&[AgentRole::Monitor, AgentRole::Hunter]),
        vec![Arc::new(Defective), monitor.clone()],
    );
    let defective = note(AgentRole::Hunter, "hunt");
    bench.runtime.submit(defective.clone()).unwrap();
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "work"))
        .unwrap();
    let run = bench.drive().await;
    assert_eq!(run.tasks_failed, 1);
    assert_eq!(run.tasks_completed, 1);
    assert_eq!(monitor.seen().len(), 1);
    let failed: Vec<_> = bench
        .runtime
        .recent_tasks()
        .into_iter()
        .filter(|record| record.state == TaskState::Failed)
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].id, defective.id);
    assert_eq!(
        failed[0].detail.as_deref(),
        Some("agent task: the agent panicked")
    );
    let records = bench.audit_of(AuditKind::Other);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].actor, "hunter");
    assert_eq!(records[0].payload["retryable"], json!(false));
}

#[tokio::test(start_paused = true)]
async fn a_task_that_takes_too_long_fails_and_frees_its_incident() {
    struct Stuck;

    #[async_trait]
    impl Agent for Stuck {
        fn role(&self) -> AgentRole {
            AgentRole::Hunter
        }

        async fn handle(&self, _: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
            std::future::pending().await
        }
    }

    let monitor = Probe::quiet(AgentRole::Monitor);
    let config = RuntimeConfig {
        limits: RuntimeLimits {
            task_timeout_seconds: 5,
            ..RuntimeLimits::default()
        },
        ..config_for(&[AgentRole::Monitor, AgentRole::Hunter])
    };
    let bench = Bench::with_agents(config, vec![Arc::new(Stuck), monitor.clone()]);
    let incident = IncidentId::new();
    let stuck = note(AgentRole::Hunter, "hunt").for_incident(incident);
    bench.runtime.submit(stuck.clone()).unwrap();
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "work").for_incident(incident))
        .unwrap();
    let started = tokio::time::Instant::now();
    let run = bench.drive().await;
    assert_eq!(started.elapsed().as_secs(), 5);
    assert_eq!(run.tasks_failed, 1);
    assert_eq!(run.tasks_completed, 1);
    // The task of the same incident ran after the timeout.
    assert_eq!(monitor.seen().len(), 1);
    assert_eq!(
        bench.runtime.recent_tasks()[0].detail.as_deref(),
        Some("timeout: the task did not complete in 5 seconds")
    );
    let records = bench.audit_of(AuditKind::Other);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].summary,
        format!(
            "The hunter agent failed on the task {}: timeout: the task did not complete in 5 \
             seconds",
            stuck.id
        )
    );
    assert_eq!(records[0].payload["retryable"], json!(true));
}

struct DownDispatcher;

#[async_trait]
impl ActionDispatcher for DownDispatcher {
    async fn dispatch(&self, _: ActionRequest, _: &Principal) -> Result<ActionDisposition> {
        Err(Error::Unavailable("the connector is down".to_owned()))
    }
}

struct SilentDispatcher;

#[async_trait]
impl ActionDispatcher for SilentDispatcher {
    async fn dispatch(&self, _: ActionRequest, _: &Principal) -> Result<ActionDisposition> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn a_dispatcher_error_goes_back_to_the_agent_as_a_note() {
    let request = tag("Set the label.");
    let monitor = monitor_with(AgentOutput {
        actions: vec![request.clone()],
        ..AgentOutput::default()
    });
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let runtime = runtime_with(
        harness.context(GOAL),
        Arc::new(DownDispatcher),
        live(&[AgentRole::Monitor]),
        vec![monitor.clone()],
    );
    let incident = IncidentId::new();
    runtime
        .submit(note(AgentRole::Monitor, "start").for_incident(incident))
        .unwrap();
    let run = drive(&runtime).await;
    assert_eq!(
        run,
        RunReport {
            tasks_completed: 2,
            dispatch_failures: 1,
            ..RunReport::default()
        }
    );

    let seen = monitor.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].id, TaskId(request.id.0));
    assert_eq!(seen[1].incident_id, Some(incident));
    assert_eq!(
        seen[1].input,
        AgentInput::Note(
            "The dispatcher did not take the action: unavailable: the connector is down".to_owned()
        )
    );

    let records = harness.audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].kind, AuditKind::AgentDecision);
    assert_eq!(records[1].kind, AuditKind::Other);
    assert_eq!(records[1].actor, "runtime");
    assert_eq!(
        records[1].summary,
        format!(
            "The dispatcher did not take the action {} (tag on host:host-1): unavailable: the \
             connector is down",
            request.id
        )
    );
    assert_eq!(records[1].payload["retryable"], json!(true));
    assert_eq!(
        records[1].evidence,
        [EvidenceRef::new(EvidenceKind::Action, request.id)]
    );
    // The bus has the request and no result.
    assert_eq!(harness.bus.published_to(subject::ACTION_REQUESTS).len(), 1);
    assert_eq!(harness.bus.published().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_dispatcher_that_does_not_answer_is_a_dispatch_failure() {
    let monitor = monitor_with(AgentOutput {
        actions: vec![tag("Set the label.")],
        ..AgentOutput::default()
    });
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let config = RuntimeConfig {
        limits: RuntimeLimits {
            task_timeout_seconds: 7,
            ..RuntimeLimits::default()
        },
        ..live(&[AgentRole::Monitor])
    };
    let runtime = runtime_with(
        harness.context(GOAL),
        Arc::new(SilentDispatcher),
        config,
        vec![monitor.clone()],
    );
    runtime.submit(note(AgentRole::Monitor, "start")).unwrap();
    let started = tokio::time::Instant::now();
    let run = drive(&runtime).await;
    assert_eq!(started.elapsed().as_secs(), 7);
    assert_eq!(run.dispatch_failures, 1);
    assert_eq!(run.actions_dispatched, 0);
    assert_eq!(run.tasks_completed, 2);
    assert_eq!(
        monitor.seen()[1].input,
        AgentInput::Note(
            "The dispatcher did not take the action: timeout: the dispatcher did not answer in \
             7 seconds"
                .to_owned()
        )
    );
    assert!(runtime.is_idle());
}

#[tokio::test]
async fn no_action_runs_without_its_audit_record() {
    struct DownAudit;

    #[async_trait]
    impl AuditLog for DownAudit {
        async fn append(&self, _: AuditEntry) -> Result<AuditRecord> {
            Err(Error::Unavailable("the audit log is down".to_owned()))
        }

        async fn read(&self, _: u64, _: usize) -> Result<Vec<AuditRecord>> {
            Ok(Vec::new())
        }

        async fn verify(&self) -> Result<ChainVerification> {
            Err(Error::Unavailable("the audit log is down".to_owned()))
        }
    }

    let monitor = monitor_with(AgentOutput {
        actions: vec![tag("Set the label.")],
        notes: vec!["A decision.".to_owned()],
        ..AgentOutput::default()
    });
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
    let mut context = harness.context(GOAL);
    context.audit = Arc::new(DownAudit);
    let runtime = runtime_with(
        context,
        dispatcher.clone(),
        live(&[AgentRole::Monitor]),
        vec![monitor.clone()],
    );
    runtime.submit(note(AgentRole::Monitor, "start")).unwrap();
    let run = drive(&runtime).await;

    assert!(dispatcher.requests().is_empty());
    assert!(harness.bus.published().is_empty());
    assert_eq!(monitor.seen().len(), 1);
    // The note, the decision, and the record of the rejection did not reach the log.
    assert_eq!(
        run,
        RunReport {
            tasks_completed: 1,
            actions_rejected: 1,
            audit_failures: 3,
            ..RunReport::default()
        }
    );
}

#[tokio::test]
async fn an_incident_that_the_store_does_not_take_fails_the_task_and_stops_its_actions() {
    struct DownStore;

    #[async_trait]
    impl IncidentStore for DownStore {
        async fn save(&self, _: &Incident) -> Result<()> {
            Err(Error::Unavailable("the incident store is down".to_owned()))
        }

        async fn get(&self, _: IncidentId) -> Result<Option<Incident>> {
            Ok(None)
        }

        async fn list(&self, _: Option<IncidentStatus>, _: usize) -> Result<Vec<Incident>> {
            Ok(Vec::new())
        }
    }

    let incident = attack_incident();
    let monitor = monitor_with(AgentOutput {
        tasks: vec![note(AgentRole::Monitor, "next")],
        actions: vec![tag("Set the label.")],
        incidents: vec![incident.clone()],
        notes: vec!["A decision.".to_owned()],
    });
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
    let mut context = harness.context(GOAL);
    context.incidents = Arc::new(DownStore);
    let runtime = runtime_with(
        context,
        dispatcher.clone(),
        live(&[AgentRole::Monitor]),
        vec![monitor.clone()],
    );
    let start = note(AgentRole::Monitor, "start");
    runtime.submit(start.clone()).unwrap();
    let run = drive(&runtime).await;

    assert_eq!(
        run,
        RunReport {
            tasks_failed: 1,
            ..RunReport::default()
        }
    );
    assert!(dispatcher.requests().is_empty());
    assert_eq!(monitor.seen().len(), 1);
    let records = harness.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::Other);
    assert_eq!(
        records[0].summary,
        format!(
            "The monitor agent failed on the task {}: unavailable: the incident store is down",
            start.id
        )
    );
}

#[tokio::test]
async fn the_runtime_limits_the_actions_and_the_notes_of_one_task() {
    let actions: Vec<ActionRequest> = (0..3)
        .map(|index| tag(&format!("Label {index}.")))
        .collect();
    let notes: Vec<String> = (0..70).map(|index| format!("Note {index}.")).collect();
    let monitor = monitor_with(AgentOutput {
        actions: actions.clone(),
        notes,
        ..AgentOutput::default()
    });
    let config = RuntimeConfig {
        limits: RuntimeLimits {
            max_actions_per_task: 2,
            ..RuntimeLimits::default()
        },
        ..live(&[AgentRole::Monitor])
    };
    let bench = Bench::with_agents(config, vec![monitor.clone()]);
    let start = note(AgentRole::Monitor, "start");
    bench.runtime.submit(start.clone()).unwrap();
    let run = bench.drive().await;

    assert_eq!(run.actions_dispatched, 2);
    assert_eq!(run.actions_rejected, 1);
    let dispatched: Vec<_> = bench
        .dispatcher
        .requests()
        .into_iter()
        .map(|(request, _)| request.id)
        .collect();
    assert_eq!(dispatched, [actions[0].id, actions[1].id]);

    let decisions = bench.audit_of(AuditKind::AgentDecision);
    // 64 notes and 2 decisions for actions.
    assert_eq!(decisions.len(), 66);
    assert_eq!(decisions[63].summary, "Note 63.");
    let other: Vec<String> = bench
        .audit_of(AuditKind::Other)
        .into_iter()
        .map(|record| {
            assert_eq!(record.actor, "runtime");
            record.summary
        })
        .collect();
    assert_eq!(
        other,
        [
            format!(
                "The runtime dropped 6 notes of the monitor agent for the task {}: the limit \
                 is 64 notes for one task.",
                start.id
            ),
            format!(
                "The runtime did not dispatch 1 actions of the monitor agent from the task {}: \
                 the task has more actions than limits.max_actions_per_task.",
                start.id
            ),
        ]
    );
}
