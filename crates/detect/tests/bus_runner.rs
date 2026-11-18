//! Tests of the bus runner of the detection engine, with the in-memory bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, publish_json};
use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Error, Incident, Result, Verdict};
use aegis_detect::engine::{BusRunnerConfig, DetectionEngine, EngineConfig, RunSummary};
use aegis_detect::pack::{PackManifest, RulePack};
use aegis_detect::sigma::SigmaRule;
use aegis_testkit::fixtures;
use aegis_testkit::{MemoryBus, ScriptedModel};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use futures::StreamExt;
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MARKER_PRINCIPAL: &str = "sp-end-of-test";
const HONEYTOKEN_RULE_ID: &str = "0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940";

fn shipped_pack() -> RulePack {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity");
    RulePack::load(directory).unwrap()
}

fn time(seconds: i64) -> DateTime<Utc> {
    fixtures::base_time() + TimeDelta::seconds(seconds)
}

/// A honeytoken event of a principal that no other event names. The shipped pack gives one
/// detection and one new incident for it. A test sends it last and waits for that incident.
fn marker(sequence: u128) -> Event {
    Event::new(
        time(7_200),
        EventSource::new("marker", "test", "test").with_tenant("tenant-marker"),
        EventClass::ApiActivity,
        action::HONEYTOKEN_TRIP,
        Actor::new(EntityKind::ServicePrincipal, MARKER_PRINCIPAL),
    )
    .with_id(EventId(Uuid::from_u128(0xffff_0000 + sequence)))
    .with_outcome(Outcome::Success)
    .with_attribute(attr::HONEYTOKEN_ID, format!("marker-{sequence}"))
}

fn is_marker(incident: &Incident) -> bool {
    incident.entities
        == [EntityRef::new(
            EntityKind::ServicePrincipal,
            MARKER_PRINCIPAL,
        )]
}

async fn next(stream: &mut BusStream) -> BusMessage {
    tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .expect("the bus must deliver a message")
        .expect("the stream must stay open")
        .expect("the message must be valid")
}

/// Reads incidents until the incident of the marker event comes.
async fn wait_for_marker(incidents: &mut BusStream) {
    loop {
        let incident: Incident = next(incidents).await.decode().unwrap();
        if is_marker(&incident) {
            return;
        }
    }
}

fn start(
    engine: &Arc<DetectionEngine>,
    bus: &Arc<dyn MessageBus>,
    config: BusRunnerConfig,
    cancel: &CancellationToken,
) -> JoinHandle<Result<RunSummary>> {
    let (engine, bus, cancel) = (engine.clone(), bus.clone(), cancel.clone());
    tokio::spawn(async move { engine.run(bus.as_ref(), &config, cancel).await })
}

/// Calls the runner and waits for its result. A runner that does not return fails the
/// test, so that a defect in the runner cannot stop the test run.
async fn run_now(
    engine: &DetectionEngine,
    bus: &dyn MessageBus,
    config: &BusRunnerConfig,
    cancel: CancellationToken,
) -> Result<RunSummary> {
    tokio::time::timeout(Duration::from_secs(20), engine.run(bus, config, cancel))
        .await
        .expect("the runner must return")
}

async fn stop(
    cancel: &CancellationToken,
    task: JoinHandle<Result<RunSummary>>,
) -> Result<RunSummary> {
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the runner must stop after the cancellation")
        .expect("the runner task must not panic")
}

fn detections_on(bus: &MemoryBus, pattern: &str) -> Vec<Detection> {
    bus.published_to(pattern)
        .iter()
        .map(|message| message.decode().unwrap())
        .collect()
}

#[tokio::test]
async fn the_runner_publishes_the_detections_and_the_incident_of_the_attack_log() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    for event in fixtures::artex_style_attack() {
        publish_json(bus.as_ref(), "aegis.events.fixture", &event)
            .await
            .unwrap();
    }
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();

    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap());
    let cancel = CancellationToken::new();
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    wait_for_marker(&mut incidents).await;
    let summary = stop(&cancel, task).await.unwrap();

    assert_eq!(
        summary,
        RunSummary {
            events: 649,
            rejected_messages: 0,
            // Nine detections of the attack log and one of the marker event.
            detections: 10,
            incidents: 8,
            stream_errors: 0,
            coalesced_incident_updates: 0,
        }
    );

    // Each detection is on the subject of its tier, in the order of the events.
    let tier_one = detections_on(&memory, "aegis.detections.deterministic");
    assert_eq!(tier_one.len(), 10);
    assert!(
        tier_one
            .iter()
            .all(|detection| detection.tier == DetectionTier::Deterministic)
    );
    assert!(tier_one.is_sorted_by_key(|detection| detection.time));
    assert_eq!(tier_one[0].rule_id, "aegis.velocity.sign_in_burst");
    assert_eq!(tier_one[9].rule_id, HONEYTOKEN_RULE_ID);
    assert_eq!(memory.published_to("aegis.detections.>").len(), 10);

    // The last state of the attack incident is the incident that the engine keeps.
    let states: Vec<Incident> = memory
        .published_to("aegis.incidents")
        .iter()
        .map(|message| message.decode().unwrap())
        .collect();
    assert_eq!(states.len(), 8);
    let attack = &states[6];
    assert!(!is_marker(attack));
    assert_eq!(attack.severity, Severity::Critical);
    assert_eq!(attack.detections.len(), 9);
    assert_eq!(attack.tenant.as_deref(), Some(fixtures::TENANT));
    assert!(states[..6].iter().all(|state| state.id == attack.id));
    assert!(is_marker(&states[7]));
    assert_eq!(engine.incidents(), [attack.clone(), states[7].clone()]);
}

#[tokio::test]
async fn a_message_that_is_not_an_event_is_dropped_and_counted() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    bus.publish("aegis.events.broken", b"not json".to_vec())
        .await
        .unwrap();
    publish_json(bus.as_ref(), "aegis.events.broken", &json!({ "id": 5 }))
        .await
        .unwrap();
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    // A message on a different subject is not for the runner.
    bus.publish("aegis.audit", b"not json".to_vec())
        .await
        .unwrap();

    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap());
    let cancel = CancellationToken::new();
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    wait_for_marker(&mut incidents).await;
    let summary = stop(&cancel, task).await.unwrap();
    assert_eq!(
        summary,
        RunSummary {
            events: 1,
            rejected_messages: 2,
            detections: 1,
            incidents: 1,
            stream_errors: 0,
            coalesced_incident_updates: 0,
        }
    );
}

#[tokio::test]
async fn a_runner_that_starts_again_continues_after_its_last_event() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap());
    let config = BusRunnerConfig {
        durable_name: "detect-test".to_owned(),
        ..BusRunnerConfig::default()
    };
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();

    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, config.clone(), &cancel);
    wait_for_marker(&mut incidents).await;
    let first = stop(&cancel, task).await.unwrap();
    assert_eq!(first.events, 1);
    assert_eq!(first.detections, 1);

    // Events that come while no runner operates stay on the bus for the durable name.
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(2))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, config, &cancel);
    wait_for_marker(&mut incidents).await;
    let second = stop(&cancel, task).await.unwrap();
    assert_eq!(second.events, 1);
    assert_eq!(second.detections, 1);

    let detections = detections_on(&memory, "aegis.detections.deterministic");
    assert_eq!(detections.len(), 2);
    assert_eq!(detections[0].event_ids, [marker(1).id]);
    assert_eq!(detections[1].event_ids, [marker(2).id]);
}

#[tokio::test]
async fn a_tier_two_result_goes_to_the_subject_of_tier_two() {
    let rule = SigmaRule::parse(
        "title: Account change\nid: account-change\nlevel: medium\ndetection:\n  selection:\n    \
         action: user.update\n  condition: selection\n",
        "inline",
    )
    .unwrap();
    let manifest = PackManifest {
        name: "runner-test".to_owned(),
        version: "1".to_owned(),
        description: "One suspicious rule.".to_owned(),
    };
    let pack = RulePack::new(manifest, vec![rule], Vec::new()).unwrap();
    let answer = json!({ "verdict": "malicious", "confidence": 0.9, "reasons": ["A script."] });
    let model = Arc::new(ScriptedModel::new("fake").reply_json(&answer));
    let engine = Arc::new(
        DetectionEngine::new(EngineConfig::default(), pack)
            .unwrap()
            .with_triage(model.clone())
            .unwrap(),
    );

    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    let mut change = marker(1);
    change.action = action::USER_UPDATE.to_owned();
    publish_json(bus.as_ref(), "aegis.events.marker", &change)
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    wait_for_marker(&mut incidents).await;
    let summary = stop(&cancel, task).await.unwrap();
    assert_eq!(summary.detections, 2);
    assert_eq!(summary.incidents, 1);

    let tier_one = detections_on(&memory, "aegis.detections.deterministic");
    assert_eq!(tier_one.len(), 1);
    assert_eq!(tier_one[0].verdict, Verdict::Suspicious);
    assert_eq!(tier_one[0].tier, DetectionTier::Deterministic);
    let tier_two = detections_on(&memory, "aegis.detections.llm");
    assert_eq!(tier_two.len(), 1);
    assert_eq!(tier_two[0].verdict, Verdict::Malicious);
    assert_eq!(tier_two[0].tier, DetectionTier::Llm);
    assert_eq!(tier_two[0].rule_id, "account-change");
    assert_eq!(model.requests().len(), 1);
}

#[tokio::test]
async fn a_cancellation_stops_a_runner_that_waits_for_events() {
    let bus: Arc<dyn MessageBus> = Arc::new(MemoryBus::default());
    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap());
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    let summary = stop(&cancel, task).await.unwrap();
    assert_eq!(summary, RunSummary::default());

    // A runner that starts with a cancelled token examines no event.
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let summary = run_now(
        &engine,
        bus.as_ref(),
        &BusRunnerConfig::default(),
        cancelled,
    )
    .await
    .unwrap();
    assert_eq!(summary, RunSummary::default());
    assert_eq!(engine.incidents(), []);
}

#[tokio::test]
async fn settings_that_are_not_valid_are_configuration_errors() {
    let bus = MemoryBus::default();
    let engine = DetectionEngine::new(EngineConfig::default(), RulePack::empty()).unwrap();
    let no_name = BusRunnerConfig {
        durable_name: "  ".to_owned(),
        ..BusRunnerConfig::default()
    };
    let error = run_now(&engine, &bus, &no_name, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message == "the durable name of the detection runner is empty"),
        "{error}"
    );
    let no_attempts = BusRunnerConfig {
        publish_attempts: 0,
        ..BusRunnerConfig::default()
    };
    let error = run_now(&engine, &bus, &no_attempts, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("publish_attempts")),
        "{error}"
    );
}

#[test]
fn the_default_settings_use_the_durable_name_of_the_subsystem() {
    let config = BusRunnerConfig::default();
    assert_eq!(config.durable_name, "aegis-detect");
    assert_eq!(config.publish_attempts, 5);
    let partial: BusRunnerConfig =
        serde_json::from_value(json!({ "durable_name": "detect-eu" })).unwrap();
    assert_eq!(partial.durable_name, "detect-eu");
    assert_eq!(partial.publish_backoff_milliseconds, 50);
    assert!(serde_json::from_value::<BusRunnerConfig>(json!({ "durable": "x" })).is_err());
}

/// A bus that fails some operations and sends all others to an in-memory bus.
#[derive(Default)]
struct FaultyBus {
    inner: MemoryBus,
    /// The errors for the next publishes to a detection subject, in order.
    detection_publish_errors: Mutex<VecDeque<Error>>,
    /// The number of publishes to a detection subject, including those that failed.
    detection_publish_attempts: Mutex<u32>,
    subscribe_error: Mutex<Option<Error>>,
}

impl FaultyBus {
    fn failing_detection_publishes(errors: Vec<Error>) -> Arc<Self> {
        Arc::new(Self {
            detection_publish_errors: Mutex::new(errors.into()),
            ..Self::default()
        })
    }

    fn attempts(&self) -> u32 {
        *self.detection_publish_attempts.lock().unwrap()
    }
}

#[async_trait]
impl MessageBus for FaultyBus {
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        if subject.starts_with("aegis.detections.") {
            *self.detection_publish_attempts.lock().unwrap() += 1;
            let error = self.detection_publish_errors.lock().unwrap().pop_front();
            if let Some(error) = error {
                return Err(error);
            }
        }
        self.inner.publish(subject, payload).await
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        let error = self.subscribe_error.lock().unwrap().take();
        match error {
            Some(error) => Err(error),
            None => self.inner.subscribe(pattern, durable).await,
        }
    }
}

fn unavailable() -> Error {
    Error::Unavailable("the bus is not available".to_owned())
}

#[tokio::test(start_paused = true)]
async fn a_publish_that_fails_with_a_retryable_error_is_tried_again() {
    let faulty = FaultyBus::failing_detection_publishes(vec![unavailable(), unavailable()]);
    let bus: Arc<dyn MessageBus> = faulty.clone();
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap());
    let cancel = CancellationToken::new();
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    wait_for_marker(&mut incidents).await;
    // The runner waited 50 and then 100 milliseconds before the second and third attempt.
    assert_eq!(started.elapsed(), Duration::from_millis(150));
    let summary = stop(&cancel, task).await.unwrap();

    assert_eq!(summary.detections, 1);
    assert_eq!(summary.incidents, 1);
    assert_eq!(faulty.attempts(), 3);
    let published = detections_on(&faulty.inner, "aegis.detections.deterministic");
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].rule_id, HONEYTOKEN_RULE_ID);
}

#[tokio::test(start_paused = true)]
async fn a_publish_that_fails_each_time_stops_the_runner_with_the_error_of_the_bus() {
    let faulty = FaultyBus::failing_detection_publishes(vec![
        unavailable(),
        Error::RateLimited("slow down".to_owned()),
        Error::Timeout("the bus gave no answer".to_owned()),
    ]);
    let bus: Arc<dyn MessageBus> = faulty.clone();
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    let config = BusRunnerConfig {
        publish_attempts: 3,
        ..BusRunnerConfig::default()
    };
    let error = run_now(&engine, bus.as_ref(), &config, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Timeout(message) if message == "the bus gave no answer"),
        "{error}"
    );
    assert_eq!(faulty.attempts(), 3);
    assert_eq!(faulty.inner.published_to("aegis.detections.>").len(), 0);
    assert_eq!(faulty.inner.published_to("aegis.incidents").len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_publish_error_that_a_retry_cannot_correct_stops_the_runner_immediately() {
    let faulty = FaultyBus::failing_detection_publishes(vec![Error::Unauthorized(
        "the bus refused the credentials".to_owned(),
    )]);
    let bus: Arc<dyn MessageBus> = faulty.clone();
    publish_json(bus.as_ref(), "aegis.events.marker", &marker(1))
        .await
        .unwrap();
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    let started = tokio::time::Instant::now();
    let error = run_now(
        &engine,
        bus.as_ref(),
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message == "the bus refused the credentials"),
        "{error}"
    );
    assert_eq!(faulty.attempts(), 1);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test]
async fn a_subscription_that_fails_is_the_error_of_the_runner() {
    let faulty = Arc::new(FaultyBus {
        subscribe_error: Mutex::new(Some(Error::Unauthorized("no permission".to_owned()))),
        ..FaultyBus::default()
    });
    let engine = DetectionEngine::new(EngineConfig::default(), RulePack::empty()).unwrap();
    let error = run_now(
        &engine,
        faulty.as_ref(),
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message == "no permission"),
        "{error}"
    );
}

/// A bus with a subscription that gives the items of a script and then closes.
struct ScriptedStreamBus {
    items: Mutex<Vec<Result<BusMessage>>>,
    inner: MemoryBus,
}

#[async_trait]
impl MessageBus for ScriptedStreamBus {
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        self.inner.publish(subject, payload).await
    }

    async fn subscribe(&self, _pattern: &str, _durable: Option<&str>) -> Result<BusStream> {
        let items = std::mem::take(&mut *self.items.lock().unwrap());
        Ok(futures::stream::iter(items).boxed())
    }
}

fn message(event: &Event) -> Result<BusMessage> {
    Ok(BusMessage {
        subject: "aegis.events.marker".to_owned(),
        payload: serde_json::to_vec(event).unwrap(),
    })
}

#[tokio::test]
async fn a_subscription_that_closes_is_an_unavailable_error_after_its_events() {
    let bus = ScriptedStreamBus {
        items: Mutex::new(vec![message(&marker(1))]),
        inner: MemoryBus::default(),
    };
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    let error = run_now(
        &engine,
        &bus,
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("closed the event subscription")),
        "{error}"
    );
    assert!(error.is_retryable());
    // The runner examined and published the event that came before the close.
    assert_eq!(
        bus.inner
            .published_to("aegis.detections.deterministic")
            .len(),
        1
    );
    assert_eq!(bus.inner.published_to("aegis.incidents").len(), 1);
}

#[tokio::test]
async fn the_runner_continues_after_a_temporary_error_of_the_subscription() {
    let bus = ScriptedStreamBus {
        items: Mutex::new(vec![
            message(&marker(1)),
            Err(unavailable()),
            Err(Error::Timeout("no heartbeat".to_owned())),
            message(&marker(2)),
        ]),
        inner: MemoryBus::default(),
    };
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    // The scripted stream closes after its items, so the run ends with the close error.
    let error = run_now(
        &engine,
        &bus,
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("closed the event subscription")),
        "{error}"
    );
    // The runner examined the event before the errors and the event after them.
    assert_eq!(
        bus.inner
            .published_to("aegis.detections.deterministic")
            .len(),
        2
    );
}

#[tokio::test]
async fn temporary_errors_in_sequence_stop_the_runner_at_the_limit() {
    let mut items = vec![message(&marker(1))];
    items.extend((0..16).map(|_| Err(unavailable())));
    items.push(message(&marker(2)));
    let bus = ScriptedStreamBus {
        items: Mutex::new(items),
        inner: MemoryBus::default(),
    };
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    let error = run_now(
        &engine,
        &bus,
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message == "the bus is not available"),
        "{error}"
    );
    // The runner stopped at the sixteenth error and did not reach the second event.
    assert_eq!(
        bus.inner
            .published_to("aegis.detections.deterministic")
            .len(),
        1
    );
}

#[tokio::test]
async fn an_error_of_the_subscription_stops_the_runner_with_that_error() {
    let bus = ScriptedStreamBus {
        items: Mutex::new(vec![
            message(&marker(1)),
            Err(Error::Integrity("the stream lost its position".to_owned())),
            message(&marker(2)),
        ]),
        inner: MemoryBus::default(),
    };
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack()).unwrap();
    let error = run_now(
        &engine,
        &bus,
        &BusRunnerConfig::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Integrity(message) if message == "the stream lost its position"),
        "{error}"
    );
    assert_eq!(
        bus.inner
            .published_to("aegis.detections.deterministic")
            .len(),
        1
    );
}
