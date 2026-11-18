//! The guard rails of the runtime: limits, the order of tasks, and the life of the queue.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aegis_agents::{
    AgentRuntime, CancellationToken, RunReport, RuntimeConfig, RuntimeLimits, RuntimeState,
    TaskState,
};
use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::audit::AuditKind;
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, TaskId};
use aegis_contracts::{
    Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Error, Result,
};
use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
use async_trait::async_trait;
use tokio::sync::{Notify, mpsc};

use crate::support::{Bench, GOAL, Probe, attack_incident, config_for, drive};

fn note(role: AgentRole, text: &str) -> AgentTask {
    AgentTask::new(role, AgentInput::Note(text.to_owned()))
}

fn limits(change: impl FnOnce(&mut RuntimeLimits)) -> RuntimeConfig {
    let mut config = config_for(&[AgentRole::Monitor]);
    change(&mut config.limits);
    config
}

/// Makes a Monitor that answers each task with one new task for itself.
fn looper() -> Arc<Probe> {
    Probe::new(AgentRole::Monitor, |_| {
        Ok(AgentOutput {
            tasks: vec![note(AgentRole::Monitor, "again")],
            ..AgentOutput::default()
        })
    })
}

fn runtime_notes(bench: &Bench) -> Vec<String> {
    bench
        .audit_of(AuditKind::Other)
        .into_iter()
        .map(|record| {
            assert_eq!(record.actor, "runtime");
            record.summary
        })
        .collect()
}

#[tokio::test]
async fn the_step_limit_stops_a_task_loop() {
    let agent = looper();
    let bench = Bench::with_agents(
        limits(|limits| {
            limits.max_steps_per_incident = 5;
            limits.max_task_depth = 1_000;
        }),
        vec![agent.clone()],
    );
    let incident = IncidentId::new();
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "start").for_incident(incident))
        .unwrap();
    let run = bench.drive().await;

    // The agent got five tasks. The runtime rejected the sixth task.
    assert_eq!(agent.seen().len(), 5);
    assert_eq!(
        run,
        RunReport {
            tasks_completed: 5,
            tasks_rejected: 1,
            ..RunReport::default()
        }
    );
    assert!(bench.runtime.is_idle());
    assert_eq!(bench.runtime.state(), RuntimeState::Idle);
    let last_task = agent.seen()[4].id;
    assert_eq!(
        runtime_notes(&bench),
        [format!(
            "The runtime rejected 1 tasks of the monitor agent from the task {last_task}: the \
             incident has more tasks from one input than limits.max_steps_per_incident."
        )]
    );
    let records = bench.runtime.recent_tasks();
    assert_eq!(records.len(), 6);
    let rejected = &records[4];
    assert_eq!(rejected.state, TaskState::Rejected);
    assert_eq!(rejected.incident_id, Some(incident));
    assert_eq!(rejected.depth, 5);
    assert_eq!(
        rejected.detail.as_deref(),
        Some("the incident has more tasks from one input than limits.max_steps_per_incident")
    );

    // A new input from the operator has its own step count.
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "start").for_incident(incident))
        .unwrap();
    let second = bench.drive().await;
    assert_eq!(second.tasks_completed, 5);
    assert_eq!(second.tasks_rejected, 1);
    assert_eq!(agent.seen().len(), 10);
}

#[tokio::test]
async fn the_depth_limit_stops_a_chain_of_tasks() {
    let agent = looper();
    let bench = Bench::with_agents(
        limits(|limits| {
            limits.max_steps_per_incident = 1_000;
            limits.max_task_depth = 3;
        }),
        vec![agent.clone()],
    );
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "start"))
        .unwrap();
    let run = bench.drive().await;

    // The depths 0, 1, 2, and 3 ran.
    assert_eq!(agent.seen().len(), 4);
    assert_eq!(run.tasks_completed, 4);
    assert_eq!(run.tasks_rejected, 1);
    let last_task = agent.seen()[3].id;
    assert_eq!(
        runtime_notes(&bench),
        [format!(
            "The runtime rejected 1 tasks of the monitor agent from the task {last_task}: the \
             chain of tasks is longer than limits.max_task_depth."
        )]
    );
    assert!(bench.runtime.is_idle());
}

#[tokio::test]
async fn the_step_limit_stops_a_loop_of_actions_and_results() {
    // The agent proposes one action for each task, also for each result.
    let agent = Probe::new(AgentRole::Monitor, |_| {
        Ok(AgentOutput {
            actions: vec![ActionRequest::new(
                ActionKind::Tag,
                EntityRef::new(EntityKind::Host, "host-1"),
                "monitor",
                "Set the label again.",
            )],
            ..AgentOutput::default()
        })
    });
    let bench = Bench::with_agents(
        limits(|limits| {
            limits.max_steps_per_incident = 4;
            limits.max_task_depth = 1_000;
        }),
        vec![agent.clone()],
    );
    bench
        .runtime
        .submit(note(AgentRole::Monitor, "start"))
        .unwrap();
    let run = bench.drive().await;

    assert_eq!(
        run,
        RunReport {
            tasks_completed: 4,
            actions_dispatched: 3,
            actions_rejected: 1,
            ..RunReport::default()
        }
    );
    // The runtime did not dispatch the action that has no place for its result.
    assert_eq!(bench.dispatcher.requests().len(), 3);
    assert_eq!(agent.seen().len(), 4);
    let last_task = agent.seen()[3].id;
    assert_eq!(
        runtime_notes(&bench),
        [format!(
            "The runtime did not dispatch 1 actions of the monitor agent from the task \
             {last_task}: the incident has more tasks from one input than \
             limits.max_steps_per_incident."
        )]
    );
}

#[tokio::test]
async fn a_full_queue_rejects_a_new_task() {
    let agent = Probe::quiet(AgentRole::Monitor);
    let bench = Bench::with_agents(
        limits(|limits| limits.max_queued_tasks = 2),
        vec![agent.clone()],
    );
    for text in ["one", "two"] {
        bench
            .runtime
            .submit(note(AgentRole::Monitor, text))
            .unwrap();
    }
    let third = note(AgentRole::Monitor, "three");
    let error = bench.runtime.submit(third.clone()).unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(reason) if reason == "the task queue is full"),
        "{error}"
    );
    assert!(error.is_retryable());
    assert_eq!(bench.runtime.queued(), 2);
    assert_eq!(
        bench.runtime.task_state(third.id),
        Some(TaskState::Rejected)
    );

    let run = bench.drive().await;
    assert_eq!(run.tasks_completed, 2);
    assert_eq!(bench.runtime.stats().tasks_rejected, 1);
    // The queue has room again.
    bench.runtime.submit(third).unwrap();
    assert_eq!(bench.drive().await.tasks_completed, 1);
    assert_eq!(agent.seen().len(), 3);
}

#[tokio::test]
async fn a_role_that_is_not_enabled_gets_no_task() {
    // The Monitor makes a task for the Responder. The Responder is not enabled.
    let monitor = Probe::new(AgentRole::Monitor, |_| {
        Ok(AgentOutput {
            tasks: vec![note(AgentRole::Responder, "contain")],
            ..AgentOutput::default()
        })
    });
    let responder = Probe::quiet(AgentRole::Responder);
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
    let runtime = AgentRuntime::builder(harness.context(GOAL), dispatcher)
        .config(config_for(&[AgentRole::Monitor]))
        .agent(monitor.clone())
        .agent(responder.clone())
        .build()
        .unwrap();
    assert!(runtime.roster().has(&AgentRole::Monitor));
    assert!(!runtime.roster().has(&AgentRole::Responder));

    let error = runtime
        .submit(note(AgentRole::Responder, "contain"))
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(reason) if reason == "no enabled agent has the role responder"),
        "{error}"
    );
    let incident_task = runtime.submit_incident(attack_incident()).unwrap();
    assert_eq!(runtime.task_state(incident_task), Some(TaskState::Queued));

    let run = drive(&runtime).await;
    // The incident went to the Monitor. Its task for the Responder was dropped.
    assert_eq!(run.tasks_completed, 1);
    assert_eq!(run.tasks_rejected, 1);
    assert_eq!(monitor.seen().len(), 1);
    assert!(responder.seen().is_empty());
    // A role that the operator did not enable is not an error.
    assert!(harness.audit.records().is_empty());
}

#[tokio::test]
async fn an_incident_needs_the_supervisor_the_monitor_or_the_analyst() {
    let hunter = Probe::quiet(AgentRole::Hunter);
    let bench = Bench::with_agents(config_for(&[AgentRole::Hunter]), vec![hunter]);
    let error = bench
        .runtime
        .submit_incident(attack_incident())
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(reason) if reason.starts_with("no enabled agent can take an incident")),
        "{error}"
    );
    assert_eq!(bench.runtime.stats().tasks_rejected, 1);
    assert!(bench.runtime.is_idle());

    // The Analyst takes the incident when the Supervisor and the Monitor are off.
    let analyst = Probe::quiet(AgentRole::Analyst);
    let bench = Bench::with_agents(
        config_for(&[AgentRole::Analyst, AgentRole::Hunter]),
        vec![analyst.clone(), Probe::quiet(AgentRole::Hunter)],
    );
    let incident = attack_incident();
    let id = bench.runtime.submit_incident(incident.clone()).unwrap();
    bench.drive().await;
    let seen = analyst.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].id, id);
    assert_eq!(seen[0].incident_id, Some(incident.id));
    assert_eq!(seen[0].input, AgentInput::Incident(Box::new(incident)));
}

#[tokio::test]
async fn a_task_with_an_incident_as_input_belongs_to_that_incident() {
    let monitor = Probe::quiet(AgentRole::Monitor);
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![monitor.clone()]);
    let incident = attack_incident();
    // One task has no incident identifier. One task has the identifier of a different
    // incident.
    let plain = AgentTask::new(
        AgentRole::Monitor,
        AgentInput::Incident(Box::new(incident.clone())),
    );
    let wrong = plain.clone().for_incident(IncidentId::new());
    bench.runtime.submit(plain).unwrap();
    bench.runtime.submit(wrong).unwrap();
    bench.drive().await;
    let seen = monitor.seen();
    assert_eq!(seen.len(), 2);
    for task in seen {
        assert_eq!(task.incident_id, Some(incident.id));
    }
}

/// An agent that counts how many of its tasks run at the same time.
#[derive(Default)]
struct Overlap {
    active: AtomicUsize,
    most: AtomicUsize,
    handled: AtomicUsize,
}

#[async_trait]
impl Agent for Overlap {
    fn role(&self) -> AgentRole {
        AgentRole::Monitor
    }

    async fn handle(&self, _: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(active, Ordering::SeqCst);
        // Give the other tasks the opportunity to start.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.handled.fetch_add(1, Ordering::SeqCst);
        Ok(AgentOutput::default())
    }
}

async fn most_overlap(concurrency: u64, incidents: &[Option<IncidentId>]) -> usize {
    let agent = Arc::new(Overlap::default());
    let bench = Bench::with_agents(
        limits(|limits| limits.max_concurrency = concurrency),
        vec![agent.clone()],
    );
    for incident in incidents {
        let mut task = note(AgentRole::Monitor, "work");
        task.incident_id = *incident;
        bench.runtime.submit(task).unwrap();
    }
    let run = bench.drive().await;
    assert_eq!(run.tasks_completed, incidents.len() as u64);
    assert_eq!(agent.handled.load(Ordering::SeqCst), incidents.len());
    assert_eq!(agent.active.load(Ordering::SeqCst), 0);
    agent.most.load(Ordering::SeqCst)
}

#[tokio::test]
async fn the_concurrency_limit_and_the_incident_set_the_number_of_running_tasks() {
    // Tasks with no incident run at the same time, up to the limit.
    assert_eq!(most_overlap(3, &[None; 8]).await, 3);
    assert_eq!(most_overlap(1, &[None; 8]).await, 1);

    // The tasks of one incident run one at a time.
    let one = Some(IncidentId::new());
    assert_eq!(most_overlap(4, &[one; 6]).await, 1);

    // The tasks of two incidents run two at a time.
    let other = Some(IncidentId::new());
    assert_eq!(
        most_overlap(4, &[one, one, one, other, other, other]).await,
        2
    );
}

#[tokio::test]
async fn the_tasks_of_one_incident_run_in_the_order_of_the_queue() {
    let agent = Probe::quiet(AgentRole::Monitor);
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![agent.clone()]);
    let incident = IncidentId::new();
    let tasks: Vec<AgentTask> = (0..6)
        .map(|index| note(AgentRole::Monitor, &format!("task {index}")).for_incident(incident))
        .collect();
    for task in &tasks {
        bench.runtime.submit(task.clone()).unwrap();
    }
    bench.drive().await;
    assert_eq!(agent.seen(), tasks);
}

/// An agent that reports the start of each task and then waits for a permit.
struct Gate {
    started: mpsc::UnboundedSender<TaskId>,
    release: Arc<Notify>,
}

fn gate() -> (Arc<Gate>, mpsc::UnboundedReceiver<TaskId>, Arc<Notify>) {
    let (started, receiver) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let agent = Arc::new(Gate {
        started,
        release: release.clone(),
    });
    (agent, receiver, release)
}

#[async_trait]
impl Agent for Gate {
    fn role(&self) -> AgentRole {
        AgentRole::Monitor
    }

    async fn handle(&self, task: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
        // The test can drop the channel before the runtime stops.
        let _ = self.started.send(task.id);
        self.release.notified().await;
        Ok(AgentOutput::default())
    }
}

#[tokio::test]
async fn only_one_function_drives_the_queue() {
    let (agent, mut started, release) = gate();
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![agent]);
    let token = CancellationToken::new();
    let running = tokio::spawn({
        let runtime = bench.runtime.clone();
        let token = token.clone();
        async move { runtime.run(token).await }
    });

    let task = note(AgentRole::Monitor, "work");
    bench.runtime.submit(task.clone()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .expect("the task must start");
    assert_eq!(first, Some(task.id));
    assert_eq!(bench.runtime.state(), RuntimeState::Running);
    assert_eq!(bench.runtime.task_state(task.id), Some(TaskState::Running));
    assert!(!bench.runtime.is_idle());

    let expected = "the runtime already runs: wait for run or run_until_idle to return";
    let error = bench.runtime.run_until_idle().await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(reason) if reason == expected),
        "{error}"
    );
    let error = bench
        .runtime
        .run(CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(reason) if reason == expected),
        "{error}"
    );
    // The rejected calls did not stop the first one.
    assert_eq!(bench.runtime.state(), RuntimeState::Running);

    // The cancellation waits for the task that runs.
    token.cancel();
    release.notify_one();
    let report = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("run must stop after the cancellation")
        .unwrap()
        .unwrap();
    assert_eq!(report.tasks_completed, 1);
    assert_eq!(bench.runtime.state(), RuntimeState::Idle);
    assert_eq!(
        bench.runtime.task_state(task.id),
        Some(TaskState::Completed)
    );
    assert!(bench.runtime.is_idle());
}

#[tokio::test(start_paused = true)]
async fn a_dropped_drive_frees_the_incident_of_its_task() {
    /// The first task never completes. Each later task completes.
    #[derive(Default)]
    struct StuckOnce {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Agent for StuckOnce {
        fn role(&self) -> AgentRole {
            AgentRole::Monitor
        }

        async fn handle(&self, _: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                std::future::pending::<()>().await;
            }
            Ok(AgentOutput::default())
        }
    }

    let agent = Arc::new(StuckOnce::default());
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![agent.clone()]);
    let incident = IncidentId::new();
    let stuck = note(AgentRole::Monitor, "stuck").for_incident(incident);
    let waiting = note(AgentRole::Monitor, "waiting").for_incident(incident);
    bench.runtime.submit(stuck.clone()).unwrap();
    bench.runtime.submit(waiting.clone()).unwrap();

    // The caller stops the drive before the first task completes.
    let dropped =
        tokio::time::timeout(Duration::from_secs(1), bench.runtime.run_until_idle()).await;
    assert!(dropped.is_err());
    assert_eq!(bench.runtime.state(), RuntimeState::Idle);
    assert_eq!(bench.runtime.task_state(stuck.id), Some(TaskState::Failed));
    assert_eq!(
        bench.runtime.task_state(waiting.id),
        Some(TaskState::Queued)
    );
    assert_eq!(bench.runtime.queued(), 1);
    let records = bench.runtime.recent_tasks();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].detail.as_deref(),
        Some("the runtime stopped before the task completed")
    );
    assert_eq!(bench.runtime.stats().tasks_failed, 1);

    // The task that waited for the same incident runs in the next drive.
    let run = bench.drive().await;
    assert_eq!(run.tasks_completed, 1);
    assert_eq!(
        bench.runtime.task_state(waiting.id),
        Some(TaskState::Completed)
    );
    assert!(bench.runtime.is_idle());
    assert_eq!(agent.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_builder_checks_the_configuration_and_the_agents() {
    let build = |config: RuntimeConfig, agents: Vec<Arc<dyn Agent>>| {
        let harness = Harness::new(ScriptedModel::new("scripted"));
        let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
        let mut builder = AgentRuntime::builder(harness.context(GOAL), dispatcher).config(config);
        for agent in agents {
            builder = builder.agent(agent);
        }
        builder.build()
    };

    let no_agent = build(RuntimeConfig::default(), Vec::new()).err().unwrap();
    assert!(
        matches!(&no_agent, Error::Config(reason) if reason == "the runtime has no enabled agent: add agents and check enabled_roles"),
        "{no_agent}"
    );
    // The only agent has a role that is not enabled.
    let not_enabled = build(
        config_for(&[AgentRole::Monitor]),
        vec![Probe::quiet(AgentRole::Hunter)],
    )
    .err()
    .unwrap();
    assert!(matches!(not_enabled, Error::Config(_)), "{not_enabled}");
    let bad_limit = build(
        limits(|limits| limits.max_concurrency = 0),
        vec![Probe::quiet(AgentRole::Monitor)],
    )
    .err()
    .unwrap();
    assert!(
        matches!(&bad_limit, Error::Config(reason) if reason == "limits.max_concurrency must be larger than 0"),
        "{bad_limit}"
    );
}

#[tokio::test]
async fn an_added_agent_replaces_the_built_in_agent_with_the_same_role() {
    let monitor = Probe::quiet(AgentRole::Monitor);
    let triage = Probe::quiet(AgentRole::Custom("triage".to_owned()));
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
    let mut config = RuntimeConfig::default();
    config
        .enabled_roles
        .push(AgentRole::Custom("triage".to_owned()));
    let runtime = AgentRuntime::builder(harness.context(GOAL), dispatcher)
        .config(config)
        .with_default_agents()
        .agent(monitor.clone())
        .agent(triage.clone())
        .build()
        .unwrap();
    assert_eq!(runtime.roster().roles().count(), 8);

    // The built-in Supervisor gives the incident to the Monitor of the test.
    let incident = attack_incident();
    runtime.submit_incident(incident.clone()).unwrap();
    runtime
        .submit(note(AgentRole::Custom("triage".to_owned()), "look"))
        .unwrap();
    let run = drive(&runtime).await;
    assert_eq!(run.tasks_completed, 3);
    let seen = monitor.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].from, Some(AgentRole::Supervisor));
    assert_eq!(seen[0].input, AgentInput::Incident(Box::new(incident)));
    assert_eq!(triage.seen().len(), 1);
    // The Monitor of the test wrote nothing to the graph.
    assert_eq!(harness.graph.node_count(), 0);
}
