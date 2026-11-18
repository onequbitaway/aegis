//! The long-running loop: tasks and incidents from the bus, `Tick` tasks, and the stop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_agents::agents::ReportDocument;
use aegis_agents::{AgentRuntime, CancellationToken, RunReport, RuntimeConfig, RuntimeState};
use aegis_contracts::action::{ActionDisposition, ActionOutcome, ActionRequest, ActionStatus};
use aegis_contracts::audit::AuditKind;
use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, encode, publish_json, subject};
use aegis_contracts::incident::IncidentStatus;
use aegis_contracts::{AgentInput, AgentRole, AgentTask, Error, Result};
use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream;
use tokio::task::JoinHandle;

use crate::support::{
    Bench, GOAL, Probe, attack_incident, config_for, next_task, runtime_with, tap,
};

const SOON: Duration = Duration::from_secs(5);

fn note(role: AgentRole, text: &str) -> AgentTask {
    AgentTask::new(role, AgentInput::Note(text.to_owned()))
}

fn start(runtime: &Arc<AgentRuntime>) -> (CancellationToken, JoinHandle<Result<RunReport>>) {
    let token = CancellationToken::new();
    let handle = tokio::spawn({
        let runtime = runtime.clone();
        let token = token.clone();
        async move { runtime.run(token).await }
    });
    (token, handle)
}

async fn stop(token: &CancellationToken, handle: JoinHandle<Result<RunReport>>) -> RunReport {
    token.cancel();
    finish(handle).await.expect("run must return its counts")
}

async fn finish(handle: JoinHandle<Result<RunReport>>) -> Result<RunReport> {
    tokio::time::timeout(SOON, handle)
        .await
        .expect("run must return")
        .expect("run must not panic")
}

async fn publish_task(bench: &Bench, role_token: &str, task: &AgentTask) {
    publish_json(
        bench.harness.bus.as_ref(),
        &format!("{}.{role_token}", subject::AGENT_TASKS),
        task,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_takes_an_incident_from_the_bus_and_the_agents_contain_it() {
    let config = RuntimeConfig {
        dry_run: false,
        ..RuntimeConfig::default()
    };
    let bench = Bench::with_default_agents(
        ScriptedModel::new("scripted"),
        DispatchMode::Execute,
        config,
    );
    let incident = attack_incident();
    let mut reports = bench
        .harness
        .bus
        .subscribe("aegis.reports.>", None)
        .await
        .unwrap();
    // The incident is on the bus before the runtime starts. The durable consumer of the
    // runtime gets it.
    publish_json(bench.harness.bus.as_ref(), subject::INCIDENTS, &incident)
        .await
        .unwrap();

    let (token, handle) = start(&bench.runtime);
    let report = tokio::time::timeout(SOON, reports.next())
        .await
        .expect("the reporter must publish the report")
        .expect("the bus must stay open")
        .unwrap();
    assert_eq!(report.subject, format!("aegis.reports.{}", incident.id));
    let run = stop(&token, handle).await;

    assert_eq!(run.tasks_failed, 0);
    assert_eq!(run.tasks_rejected, 0);
    assert_eq!(run.actions_dispatched, 5);
    assert_eq!(bench.dispatcher.requests().len(), 5);
    let stored = bench.stored(incident.id).await;
    assert_eq!(stored.status, IncidentStatus::Contained);
    assert_eq!(stored.timeline.last().unwrap().author, "reporter");
    assert_eq!(bench.runtime.state(), RuntimeState::Idle);
    assert!(bench.runtime.is_idle());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_from_the_bus_after_an_approval_completes_the_containment() {
    let config = RuntimeConfig {
        dry_run: false,
        ..RuntimeConfig::default()
    };
    let bench = Bench::with_default_agents(
        ScriptedModel::new("scripted"),
        DispatchMode::RequireApproval,
        config,
    );
    let incident = attack_incident();
    let mut reports = bench
        .harness
        .bus
        .subscribe("aegis.reports.>", None)
        .await
        .unwrap();
    let (token, handle) = start(&bench.runtime);
    publish_json(bench.harness.bus.as_ref(), subject::INCIDENTS, &incident)
        .await
        .unwrap();

    // Each action waits for approval. The first report says that.
    let first: ReportDocument = tokio::time::timeout(SOON, reports.next())
        .await
        .expect("the reporter must publish the first report")
        .expect("the bus must stay open")
        .unwrap()
        .decode()
        .unwrap();
    assert_eq!(first.report.status, IncidentStatus::Investigating);
    assert_eq!(
        first.report.recommendations,
        ["Approve or reject the 5 actions that wait for approval."]
    );

    // A person approves the containment actions. The component that runs them publishes
    // each result as a task for the Responder. The tasks name no incident.
    let approved: Vec<ActionRequest> = bench
        .dispatcher
        .requests()
        .into_iter()
        .map(|(request, _)| request)
        .filter(|request| request.requested_by == "responder")
        .collect();
    assert_eq!(approved.len(), 4);
    for request in &approved {
        let outcome = ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Succeeded,
            connector: "entra".to_owned(),
            message: "The change is done.".to_owned(),
            details: serde_json::Value::Null,
            reversible: true,
            completed_at: chrono::Utc::now(),
        };
        let result = AgentTask::new(
            AgentRole::Responder,
            AgentInput::ActionResult(Box::new(ActionDisposition::Executed(outcome))),
        );
        publish_task(&bench, "responder", &result).await;
    }

    // The Reporter writes a new report after each result. The last result completes the
    // containment. A report can have the state of a result that arrived after its own
    // result, because the results arrive at the same time.
    let mut states = Vec::new();
    for _ in &approved {
        let next: ReportDocument = tokio::time::timeout(SOON, reports.next())
            .await
            .expect("the reporter must publish a report after each result")
            .expect("the bus must stay open")
            .unwrap()
            .decode()
            .unwrap();
        states.push(next.report.status);
    }
    assert_eq!(states.len(), 4);
    assert_eq!(states[3], IncidentStatus::Contained);
    let first_contained = states
        .iter()
        .position(|state| *state == IncidentStatus::Contained)
        .unwrap();
    assert!(
        states[..first_contained]
            .iter()
            .all(|state| *state == IncidentStatus::Investigating),
        "{states:?}"
    );
    assert!(
        states[first_contained..]
            .iter()
            .all(|state| *state == IncidentStatus::Contained),
        "{states:?}"
    );
    let run = stop(&token, handle).await;
    assert_eq!(run.tasks_failed, 0);
    assert_eq!(run.tasks_rejected, 0);

    let stored = bench.stored(incident.id).await;
    assert_eq!(stored.status, IncidentStatus::Contained);
    let responder: Vec<&str> = stored
        .timeline
        .iter()
        .filter(|entry| entry.author == "responder")
        .map(|entry| entry.description.as_str())
        .collect();
    assert_eq!(
        responder[responder.len() - 2..],
        [
            "block_ip on ip_address:203.0.113.50: succeeded by the connector entra. The change \
             is done.",
            "Containment is complete. All 4 actions ran.",
        ]
    );
    // The dispatcher got each action one time only.
    assert_eq!(bench.dispatcher.requests().len(), 5);
}

#[tokio::test]
async fn run_takes_tasks_from_the_bus_and_discards_what_it_cannot_use() {
    let soc = AgentRole::Custom("soc.tier1".to_owned());
    let (monitor, mut monitor_tasks) = tap(AgentRole::Monitor);
    let (custom, mut custom_tasks) = tap(soc.clone());
    let bench = Bench::with_agents(
        config_for(&[AgentRole::Monitor, soc.clone()]),
        vec![monitor, custom],
    );
    let (token, handle) = start(&bench.runtime);
    let bus = bench.harness.bus.as_ref();

    // Three task messages that the runtime cannot use.
    bus.publish(
        "aegis.agents.tasks.monitor",
        b"secret that is not JSON".to_vec(),
    )
    .await
    .unwrap();
    publish_task(
        &bench,
        "monitor",
        &note(AgentRole::Analyst, "wrong subject"),
    )
    .await;
    publish_task(&bench, "responder", &note(AgentRole::Responder, "no agent")).await;
    // Two good tasks. One is for a custom role with a `.` in its name.
    let good = note(AgentRole::Monitor, "from the bus");
    publish_task(&bench, "monitor", &good).await;
    let for_soc = note(soc, "for the tier");
    publish_task(&bench, "soc.tier1", &for_soc).await;
    // One incident message that the runtime cannot use, and one good incident.
    bus.publish(subject::INCIDENTS, encode(&good).unwrap())
        .await
        .unwrap();
    let incident = attack_incident();
    publish_json(bus, subject::INCIDENTS, &incident)
        .await
        .unwrap();

    // The messages of one subscription arrive in order. When the last good message of each
    // subscription is at its agent, the runtime looked at each message before it. The
    // order between the two subscriptions is not fixed.
    assert_eq!(next_task(&mut custom_tasks, SOON).await, for_soc);
    let mut for_monitor = [
        next_task(&mut monitor_tasks, SOON).await,
        next_task(&mut monitor_tasks, SOON).await,
    ];
    for_monitor.sort_by_key(|task| task.incident_id.is_some());
    assert_eq!(for_monitor[0], good);
    let from_incident = &for_monitor[1];
    assert_eq!(from_incident.to, AgentRole::Monitor);
    assert_eq!(from_incident.from, None);
    assert_eq!(from_incident.incident_id, Some(incident.id));
    assert_eq!(
        from_incident.input,
        AgentInput::Incident(Box::new(incident))
    );
    let run = stop(&token, handle).await;

    assert_eq!(
        run,
        RunReport {
            tasks_completed: 3,
            tasks_rejected: 4,
            ..RunReport::default()
        }
    );
    let records = bench.harness.audit.records();
    let mut discards: Vec<&str> = records
        .iter()
        .map(|record| {
            assert_eq!(record.kind, AuditKind::Other);
            assert_eq!(record.actor, "runtime");
            // A record of a discarded message has no data of the message.
            assert!(record.payload.is_null());
            assert!(!record.summary.contains("secret"));
            record.summary.as_str()
        })
        .collect();
    discards.sort_unstable();
    assert_eq!(
        discards,
        [
            "The runtime discarded a message on aegis.agents.tasks.monitor: the payload is not \
             a task.",
            "The runtime discarded a message on aegis.agents.tasks.monitor: the subject does \
             not name the role of the task.",
            "The runtime discarded a message on aegis.agents.tasks.responder: invalid input: \
             no enabled agent has the role responder.",
            "The runtime discarded a message on aegis.incidents: the payload is not an \
             incident.",
        ]
    );
    assert!(monitor_tasks.try_recv().is_err());
    assert!(custom_tasks.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn run_sends_a_tick_task_to_each_agent_at_the_interval() {
    let (monitor, mut monitor_tasks) = tap(AgentRole::Monitor);
    let (hunter, mut hunter_tasks) = tap(AgentRole::Hunter);
    let config = RuntimeConfig {
        tick_interval_seconds: 30,
        ..config_for(&[AgentRole::Monitor, AgentRole::Hunter])
    };
    let bench = Bench::with_agents(config, vec![monitor, hunter]);
    let began = tokio::time::Instant::now();
    let (token, handle) = start(&bench.runtime);
    let hour = Duration::from_secs(3_600);

    for round in 1..=3_u64 {
        for tasks in [&mut monitor_tasks, &mut hunter_tasks] {
            let tick = next_task(tasks, hour).await;
            assert_eq!(tick.input, AgentInput::Tick);
            assert_eq!(tick.from, None);
            assert_eq!(tick.incident_id, None);
        }
        assert_eq!(began.elapsed().as_secs(), round * 30);
    }
    let run = stop(&token, handle).await;
    assert_eq!(run.tasks_completed, 6);
    assert_eq!(run.tasks_rejected, 0);
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_is_slow_gets_one_tick_task_at_a_time() {
    let release = Arc::new(tokio::sync::Notify::new());
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let waiter = release.clone();
    // The agent tells the test that a task started. Then the test lets the task end.
    let monitor = {
        struct Slow {
            started: tokio::sync::mpsc::UnboundedSender<AgentTask>,
            release: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl aegis_contracts::Agent for Slow {
            fn role(&self) -> AgentRole {
                AgentRole::Monitor
            }

            async fn handle(
                &self,
                task: AgentTask,
                _: &aegis_contracts::AgentContext,
            ) -> Result<aegis_contracts::AgentOutput> {
                // The test can drop the channel before the runtime stops.
                let _ = self.started.send(task);
                self.release.notified().await;
                Ok(aegis_contracts::AgentOutput::default())
            }
        }

        Arc::new(Slow {
            started,
            release: waiter,
        })
    };
    let mut config = config_for(&[AgentRole::Monitor]);
    config.tick_interval_seconds = 30;
    config.limits.task_timeout_seconds = 1_000_000;
    let bench = Bench::with_agents(config, vec![monitor]);
    let (token, handle) = start(&bench.runtime);
    let hour = Duration::from_secs(3_600);

    let first = next_task(&mut starts, hour).await;
    assert_eq!(first.input, AgentInput::Tick);
    // Ten intervals go by while the first tick task runs. No second tick task starts or
    // waits.
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert!(starts.try_recv().is_err());
    assert_eq!(bench.runtime.queued(), 0);
    assert_eq!(bench.runtime.stats().tasks_completed, 0);

    // After the first tick task ends, the next interval gives a new one.
    release.notify_one();
    let second = next_task(&mut starts, hour).await;
    assert_eq!(second.input, AgentInput::Tick);
    assert_ne!(second.id, first.id);
    release.notify_one();
    let run = stop(&token, handle).await;
    assert_eq!(run.tasks_completed, 2);
    assert_eq!(run.tasks_rejected, 0);
}

#[tokio::test(start_paused = true)]
async fn the_interval_zero_stops_the_tick_tasks() {
    let (monitor, mut monitor_tasks) = tap(AgentRole::Monitor);
    let config = RuntimeConfig {
        tick_interval_seconds: 0,
        ..config_for(&[AgentRole::Monitor])
    };
    let bench = Bench::with_agents(config, vec![monitor]);
    let (token, handle) = start(&bench.runtime);
    tokio::time::sleep(Duration::from_secs(86_400)).await;
    assert_eq!(bench.runtime.state(), RuntimeState::Running);
    let run = stop(&token, handle).await;
    assert_eq!(run, RunReport::default());
    assert!(monitor_tasks.try_recv().is_err());
}

#[tokio::test]
async fn after_the_cancellation_no_new_task_starts() {
    let monitor = Probe::quiet(AgentRole::Monitor);
    let bench = Bench::with_agents(config_for(&[AgentRole::Monitor]), vec![monitor.clone()]);
    for text in ["one", "two", "three"] {
        bench
            .runtime
            .submit(note(AgentRole::Monitor, text))
            .unwrap();
    }
    let token = CancellationToken::new();
    token.cancel();
    let run = tokio::time::timeout(SOON, bench.runtime.run(token))
        .await
        .expect("run must return")
        .unwrap();
    assert_eq!(run, RunReport::default());
    assert!(monitor.seen().is_empty());
    // The tasks stay in the queue for the next run.
    assert_eq!(bench.runtime.queued(), 3);
    assert_eq!(bench.runtime.state(), RuntimeState::Idle);
    assert_eq!(bench.drive().await.tasks_completed, 3);
}

/// The function that makes the stream for a subscription pattern.
type StreamFor = Box<dyn Fn(&str) -> Result<BusStream> + Send + Sync>;

/// A bus that gives each subscription a stream from a function and records the
/// subscriptions.
struct ScriptedBus {
    subscriptions: Mutex<Vec<(String, Option<String>)>>,
    stream_for: StreamFor,
}

impl ScriptedBus {
    fn new(stream_for: impl Fn(&str) -> Result<BusStream> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            subscriptions: Mutex::default(),
            stream_for: Box::new(stream_for),
        })
    }

    fn subscriptions(&self) -> Vec<(String, Option<String>)> {
        self.subscriptions.lock().unwrap().clone()
    }
}

#[async_trait]
impl MessageBus for ScriptedBus {
    async fn publish(&self, _: &str, _: Vec<u8>) -> Result<()> {
        Ok(())
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        self.subscriptions
            .lock()
            .unwrap()
            .push((pattern.to_owned(), durable.map(str::to_owned)));
        (self.stream_for)(pattern)
    }
}

fn silent() -> BusStream {
    Box::pin(stream::pending())
}

fn link_error() -> Result<BusMessage> {
    Err(Error::Unavailable("the link is down".to_owned()))
}

fn on_scripted_bus(
    bus: Arc<ScriptedBus>,
    config: RuntimeConfig,
) -> (
    Harness,
    Arc<AgentRuntime>,
    tokio::sync::mpsc::UnboundedReceiver<AgentTask>,
) {
    let (monitor, tasks) = tap(AgentRole::Monitor);
    let harness = Harness::new(ScriptedModel::new("scripted"));
    let mut context = harness.context(GOAL);
    context.bus = bus;
    let runtime = runtime_with(
        context,
        Arc::new(RecordingDispatcher::new(DispatchMode::Execute)),
        config,
        vec![monitor],
    );
    (harness, runtime, tasks)
}

#[tokio::test]
async fn run_uses_one_durable_consumer_for_each_subscription() {
    let bus = ScriptedBus::new(|_| Ok(silent()));
    let config = RuntimeConfig {
        bus_consumer: Some("soc".to_owned()),
        ..config_for(&[AgentRole::Monitor])
    };
    let (_harness, runtime, _tasks) = on_scripted_bus(bus.clone(), config);
    let (token, handle) = start(&runtime);
    assert_eq!(stop(&token, handle).await, RunReport::default());
    assert_eq!(
        bus.subscriptions(),
        [
            (
                "aegis.agents.tasks.>".to_owned(),
                Some("soc-tasks".to_owned())
            ),
            (
                "aegis.incidents".to_owned(),
                Some("soc-incidents".to_owned())
            ),
        ]
    );

    let bus = ScriptedBus::new(|_| Ok(silent()));
    let config = RuntimeConfig {
        bus_consumer: None,
        ..config_for(&[AgentRole::Monitor])
    };
    let (_harness, runtime, _tasks) = on_scripted_bus(bus.clone(), config);
    let (token, handle) = start(&runtime);
    stop(&token, handle).await;
    assert_eq!(
        bus.subscriptions(),
        [
            ("aegis.agents.tasks.>".to_owned(), None),
            ("aegis.incidents".to_owned(), None),
        ]
    );
}

#[tokio::test]
async fn a_subscription_that_fails_or_ends_stops_run_with_an_error() {
    // The bus refuses the subscription.
    let bus = ScriptedBus::new(|_| Err(Error::Unauthorized("no permission".to_owned())));
    let (_harness, runtime, _tasks) = on_scripted_bus(bus, config_for(&[AgentRole::Monitor]));
    let error = runtime.run(CancellationToken::new()).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(reason) if reason == "no permission"),
        "{error}"
    );
    assert_eq!(runtime.state(), RuntimeState::Idle);

    // One subscription ends.
    for (ended, name) in [
        ("aegis.agents.tasks.>", "agent tasks"),
        ("aegis.incidents", "incidents"),
    ] {
        let bus = ScriptedBus::new(move |pattern| {
            Ok(if pattern == ended {
                Box::pin(stream::empty())
            } else {
                silent()
            })
        });
        let (_harness, runtime, _tasks) = on_scripted_bus(bus, config_for(&[AgentRole::Monitor]));
        let (_token, handle) = start(&runtime);
        let error = finish(handle).await.unwrap_err();
        assert!(
            matches!(&error, Error::Unavailable(reason) if *reason == format!("the bus subscription for {name} ended")),
            "{error}"
        );
        assert!(error.is_retryable());
        assert_eq!(runtime.state(), RuntimeState::Idle);
    }
}

#[tokio::test]
async fn bus_errors_in_sequence_stop_run_and_one_good_message_starts_the_count_again() {
    // The subscription for tasks gives only errors.
    let bus = ScriptedBus::new(|pattern| {
        Ok(if pattern == "aegis.incidents" {
            silent()
        } else {
            Box::pin(stream::repeat_with(link_error))
        })
    });
    let (harness, runtime, _tasks) = on_scripted_bus(bus, config_for(&[AgentRole::Monitor]));
    let (_token, handle) = start(&runtime);
    let error = finish(handle).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(reason) if reason == "the bus subscription for agent tasks gave 16 errors in sequence"),
        "{error}"
    );
    let records = harness.audit.records();
    assert_eq!(records.len(), 16);
    for record in &records {
        assert_eq!(record.kind, AuditKind::Other);
        assert_eq!(
            record.summary,
            "The runtime discarded a message on aegis.agents.tasks: unavailable: the link is \
             down."
        );
    }
    assert_eq!(runtime.stats().tasks_rejected, 16);

    // 15 errors, one task, 15 errors, one task: the runtime continues.
    let first = note(AgentRole::Monitor, "first");
    let second = note(AgentRole::Monitor, "second");
    let message = |task: &AgentTask| BusMessage {
        subject: "aegis.agents.tasks.monitor".to_owned(),
        payload: encode(task).unwrap(),
    };
    let mut items: Vec<Result<BusMessage>> = Vec::new();
    for task in [&first, &second] {
        items.extend((0..15).map(|_| link_error()));
        items.push(Ok(message(task)));
    }
    let items = Mutex::new(Some(items));
    let bus = ScriptedBus::new(move |pattern| {
        Ok(if pattern == "aegis.incidents" {
            silent()
        } else {
            let items = items.lock().unwrap().take().unwrap_or_default();
            Box::pin(stream::iter(items).chain(stream::pending()))
        })
    });
    let (harness, runtime, mut tasks) = on_scripted_bus(bus, config_for(&[AgentRole::Monitor]));
    let (token, handle) = start(&runtime);
    assert_eq!(next_task(&mut tasks, SOON).await, first);
    assert_eq!(next_task(&mut tasks, SOON).await, second);
    let run = stop(&token, handle).await;
    assert_eq!(run.tasks_completed, 2);
    assert_eq!(run.tasks_rejected, 30);
    assert_eq!(harness.audit.records().len(), 30);
}
