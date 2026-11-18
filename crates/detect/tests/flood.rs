//! The acceptance tests of the flood protection: suppression, the tier 2 quota, and the
//! bound on published incident states.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::{BusStream, MessageBus, publish_json};
use aegis_contracts::common::{EntityKind, EventId, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Incident, Result, Verdict};
use aegis_detect::engine::{BusRunnerConfig, DetectionEngine, EngineConfig, RunSummary};
use aegis_detect::flood::FloodCounters;
use aegis_detect::llm::LlmTriageConfig;
use aegis_detect::pack::{PackManifest, RulePack};
use aegis_detect::sigma::SigmaRule;
use aegis_testkit::fixtures;
use aegis_testkit::{MemoryBus, ScriptedModel};
use chrono::{DateTime, TimeDelta, Utc};
use futures::StreamExt;
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TENANT: &str = "tenant-1";
const ATTACKER: &str = "203.0.113.66";

fn at(milliseconds: i64) -> DateTime<Utc> {
    fixtures::base_time() + TimeDelta::milliseconds(milliseconds)
}

/// One decoy contact from an address, `sequence` times 10 milliseconds after the start.
fn contact(sequence: u32, ip: &str) -> Event {
    Event::new(
        at(i64::from(sequence) * 10),
        EventSource::new("decoy-1", "aegis", "decoy").with_tenant(TENANT),
        EventClass::NetworkActivity,
        action::DECOY_CONTACT,
        Actor::new(EntityKind::Other, "unknown")
            .with_ip(ip.parse::<IpAddr>().unwrap())
            .with_user_agent("scan-tool/3.1"),
    )
    .with_id(EventId(Uuid::from_u128(u128::from(sequence) + 1)))
    .with_outcome(Outcome::Success)
    .with_attribute(attr::DECOY_ID, "maze-1")
    .with_attribute(attr::CLIENT_FINGERPRINT, "fp-66")
}

fn pack(rule_text: &str) -> RulePack {
    let manifest = PackManifest {
        name: "flood-test".to_owned(),
        version: "1".to_owned(),
        description: "One rule for the flood tests.".to_owned(),
    };
    let rule = SigmaRule::parse(rule_text, "inline").unwrap();
    RulePack::new(manifest, vec![rule], Vec::new()).unwrap()
}

const SUPPRESSED_RULE: &str = "title: Decoy contact\nid: contact\nlevel: low\ntags:\n  - \
                               attack.t1595\ndetection:\n  selection:\n    action: \
                               decoy.contact\n  condition: selection\naegis.suppress:\n  \
                               window_seconds: 600\n  fields:\n    - actor.ip\n    - \
                               client_fingerprint\n";

const LOUD_SUSPICIOUS_RULE: &str = "title: Decoy contact\nid: contact\nlevel: low\ntags:\n  - \
                                    attack.t1595\ndetection:\n  selection:\n    action: \
                                    decoy.contact\n  condition: selection\n";

const LOUD_MALICIOUS_RULE: &str = "title: Decoy contact\nid: contact\nlevel: high\ntags:\n  - \
                                   attack.t1595\ndetection:\n  selection:\n    action: \
                                   decoy.contact\n  condition: selection\n";

#[tokio::test]
async fn ten_thousand_matching_events_give_one_detection_and_one_count() {
    let engine = DetectionEngine::new(EngineConfig::default(), pack(SUPPRESSED_RULE)).unwrap();
    let mut detections: Vec<Detection> = Vec::new();
    let mut incident_states = 0_usize;
    for sequence in 0..10_000 {
        let output = engine.process(&contact(sequence, ATTACKER)).await.unwrap();
        detections.extend(output.detections);
        incident_states += output.incidents.len();
    }
    // One detection, for the first event. The 10,000 events are 100 seconds of event time,
    // which is in one window of 600 seconds.
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, "contact");
    assert_eq!(detections[0].event_ids, [contact(0, ATTACKER).id]);
    assert_eq!(incident_states, 1);
    assert_eq!(engine.incidents().len(), 1);
    assert_eq!(engine.incidents()[0].detections.len(), 1);

    // One count, with all matches.
    let summaries = engine.suppression_summaries();
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.rule_id, "contact");
    assert_eq!(summary.key, "203.0.113.66, fp-66");
    assert_eq!(summary.tenant.as_deref(), Some(TENANT));
    assert_eq!(summary.matches, 10_000);
    assert_eq!(summary.window_start, at(0));
    assert_eq!(summary.last_seen, at(99_990));
    assert_eq!(summary.detection_id, detections[0].id);
    assert_eq!(
        engine.flood_counters(),
        FloodCounters {
            suppressed_matches: 9_999,
            ..FloodCounters::default()
        }
    );
}

#[tokio::test]
async fn a_rule_with_no_suppression_gives_a_detection_for_each_event() {
    // The same events with the same rule, but with no `aegis.suppress` key. This shows that
    // the key makes the difference in the test above.
    let engine = DetectionEngine::new(EngineConfig::default(), pack(LOUD_SUSPICIOUS_RULE)).unwrap();
    let mut detections = 0_usize;
    for sequence in 0..500 {
        let output = engine.process(&contact(sequence, ATTACKER)).await.unwrap();
        detections += output.detections.len();
    }
    assert_eq!(detections, 500);
    assert_eq!(engine.suppression_summaries(), []);
    assert_eq!(engine.flood_counters(), FloodCounters::default());
}

#[tokio::test]
async fn one_thousand_suspicious_detections_from_one_source_use_at_most_the_quota() {
    const QUOTA: u32 = 25;
    let answer = json!({ "verdict": "suspicious", "reasons": ["A scanner."] });
    let mut script = ScriptedModel::new("fake");
    for _ in 0..QUOTA {
        script = script.reply_json(&answer);
    }
    let model = Arc::new(script);
    let config = EngineConfig {
        triage: LlmTriageConfig {
            quota_window_seconds: 3_600,
            max_requests_per_source: QUOTA,
            max_requests_per_tenant: 10_000,
            ..LlmTriageConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine = DetectionEngine::new(config, pack(LOUD_SUSPICIOUS_RULE))
        .unwrap()
        .with_triage(model.clone())
        .unwrap();

    let mut tier_one = 0_usize;
    let mut tier_two = 0_usize;
    let mut over_quota = 0_usize;
    for sequence in 0..1_000_u32 {
        // Each event comes from a different address, so each event is a different client.
        let ip = format!("203.0.{}.{}", 100 + sequence / 250, sequence % 250);
        let output = engine.process(&contact(sequence, &ip)).await.unwrap();
        for detection in &output.detections {
            assert_eq!(detection.verdict, Verdict::Suspicious);
            match detection.tier {
                DetectionTier::Llm => tier_two += 1,
                DetectionTier::Deterministic => {
                    tier_one += 1;
                    if let Some(triage) = detection.attributes.get("triage") {
                        assert_eq!(
                            *triage,
                            json!({
                                "status": "quota",
                                "scope": "source",
                                "limit": QUOTA,
                                "window_seconds": 3_600,
                            })
                        );
                        over_quota += 1;
                    }
                }
            }
        }
    }
    assert_eq!(tier_one, 1_000);
    // The model got exactly the quota of requests, and each request used one answer.
    assert_eq!(model.requests().len(), 25);
    assert_eq!(model.remaining(), 0);
    assert_eq!(tier_two, 25);
    assert_eq!(over_quota, 975);
    assert_eq!(engine.flood_counters().triage_quota_denials, 975);
}

async fn next(stream: &mut BusStream) -> Incident {
    tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .expect("the bus must deliver a message")
        .expect("the stream must stay open")
        .expect("the message must be valid")
        .decode()
        .unwrap()
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

async fn stop(cancel: &CancellationToken, task: JoinHandle<Result<RunSummary>>) -> RunSummary {
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the runner must stop after the cancellation")
        .expect("the runner task must not panic")
        .unwrap()
}

/// An event of a different client in a different tenant. It gives one new incident. A
/// test sends it last and waits for that incident.
fn marker(seconds: i64) -> Event {
    let mut event = contact(900_000, "198.51.100.200");
    event.time = at(seconds * 1_000);
    event.source.tenant = Some("tenant-marker".to_owned());
    event
}

fn is_marker(incident: &Incident) -> bool {
    incident.tenant.as_deref() == Some("tenant-marker")
}

/// Publishes 1,000 events of one client in 10 seconds of event time, and then the marker.
async fn publish_flood(bus: &dyn MessageBus, marker_seconds: i64) {
    for sequence in 0..1_000 {
        publish_json(bus, "aegis.events.decoy", &contact(sequence, ATTACKER))
            .await
            .unwrap();
    }
    publish_json(bus, "aegis.events.decoy", &marker(marker_seconds))
        .await
        .unwrap();
}

/// Returns the states of the incident of the flood that the bus has, in order.
fn flood_states(bus: &MemoryBus) -> Vec<Incident> {
    bus.published_to("aegis.incidents")
        .iter()
        .map(|message| message.decode::<Incident>().unwrap())
        .filter(|incident| !is_marker(incident))
        .collect()
}

async fn wait_for_marker(incidents: &mut BusStream) {
    loop {
        if is_marker(&next(incidents).await) {
            return;
        }
    }
}

const BOUND: u32 = 5;

fn runner_config() -> BusRunnerConfig {
    BusRunnerConfig {
        max_incident_updates: BOUND,
        incident_update_window_seconds: 60,
        ..BusRunnerConfig::default()
    }
}

#[tokio::test]
async fn the_published_states_of_one_incident_stay_under_the_bound() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    // The marker is 2 hours after the flood: an event after the end of the window.
    publish_flood(bus.as_ref(), 7_200).await;
    let engine =
        Arc::new(DetectionEngine::new(EngineConfig::default(), pack(LOUD_MALICIOUS_RULE)).unwrap());
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, runner_config(), &cancel);
    wait_for_marker(&mut incidents).await;

    // The flood gave 1,000 detections and 1,000 states of one incident. The runner
    // published the first five states in the window of the flood. The event after the
    // window released the newest state.
    assert_eq!(
        memory.published_to("aegis.detections.deterministic").len(),
        1_001
    );
    let states = flood_states(&memory);
    assert_eq!(states.len(), 6);
    assert!(states.iter().all(|state| state.id == states[0].id));
    let in_window: Vec<usize> = states[..5]
        .iter()
        .map(|state| state.detections.len())
        .collect();
    assert_eq!(in_window, [1, 2, 3, 4, 5]);
    // The released state is the last state of the incident: it counts all detections. The
    // incident stores the first 200 of them.
    let last = &states[5];
    assert_eq!(engine.incidents()[0], *last);
    assert_eq!(last.detections.len(), 200);
    assert!(
        last.summary.starts_with("1000 detections from "),
        "{}",
        last.summary
    );
    assert_eq!(last.severity, Severity::High);

    let summary = stop(&cancel, task).await;
    assert_eq!(summary.events, 1_001);
    assert_eq!(summary.detections, 1_001);
    // Six states of the flood incident and one of the marker incident.
    assert_eq!(summary.incidents, 7);
    assert_eq!(summary.coalesced_incident_updates, 994);
    assert_eq!(engine.flood_counters().coalesced_incident_updates, 994);
    // The stop published nothing more.
    assert_eq!(flood_states(&memory).len(), 6);
}

#[tokio::test]
async fn a_runner_that_stops_publishes_the_state_that_it_holds() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    // The marker is 20 seconds after the start: in the window of the flood.
    publish_flood(bus.as_ref(), 20).await;
    let engine =
        Arc::new(DetectionEngine::new(EngineConfig::default(), pack(LOUD_MALICIOUS_RULE)).unwrap());
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, runner_config(), &cancel);
    wait_for_marker(&mut incidents).await;

    // The window is not over, so the bus has only the five states of the bound.
    let before: Vec<usize> = flood_states(&memory)
        .iter()
        .map(|state| state.detections.len())
        .collect();
    assert_eq!(before, [1, 2, 3, 4, 5]);

    let summary = stop(&cancel, task).await;
    let states = flood_states(&memory);
    assert_eq!(states.len(), 6);
    assert_eq!(engine.incidents()[0], states[5]);
    assert!(
        states[5].summary.starts_with("1000 detections from "),
        "{}",
        states[5].summary
    );
    assert_eq!(summary.incidents, 7);
    assert_eq!(summary.coalesced_incident_updates, 994);
}

#[tokio::test(start_paused = true)]
async fn a_held_state_leaves_when_the_window_passes_on_the_clock_with_no_event() {
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    publish_flood(bus.as_ref(), 20).await;
    let engine =
        Arc::new(DetectionEngine::new(EngineConfig::default(), pack(LOUD_MALICIOUS_RULE)).unwrap());
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, runner_config(), &cancel);
    wait_for_marker(&mut incidents).await;
    assert_eq!(flood_states(&memory).len(), 5);

    // No more events arrive. After 59 seconds the runner still holds the state. After the
    // window of 60 seconds, the state is on the bus.
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert_eq!(flood_states(&memory).len(), 5);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let states = flood_states(&memory);
    assert_eq!(states.len(), 6);
    assert_eq!(engine.incidents()[0], states[5]);

    // The runner has nothing more to publish when it stops.
    let summary = stop(&cancel, task).await;
    assert_eq!(flood_states(&memory).len(), 6);
    assert_eq!(summary.incidents, 7);
}

#[tokio::test]
async fn the_default_bound_publishes_each_state_of_a_short_attack() {
    // Fifteen detections of one incident in one window are under the default bound of 20.
    let memory = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory.clone();
    for sequence in 0..15 {
        publish_json(
            bus.as_ref(),
            "aegis.events.decoy",
            &contact(sequence, ATTACKER),
        )
        .await
        .unwrap();
    }
    publish_json(bus.as_ref(), "aegis.events.decoy", &marker(20))
        .await
        .unwrap();
    let engine =
        Arc::new(DetectionEngine::new(EngineConfig::default(), pack(LOUD_MALICIOUS_RULE)).unwrap());
    let mut incidents = bus
        .subscribe("aegis.incidents", Some("test"))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = start(&engine, &bus, BusRunnerConfig::default(), &cancel);
    wait_for_marker(&mut incidents).await;
    let summary = stop(&cancel, task).await;
    assert_eq!(flood_states(&memory).len(), 15);
    assert_eq!(summary.coalesced_incident_updates, 0);
    assert_eq!(engine.flood_counters(), FloodCounters::default());
}

#[tokio::test]
async fn runner_settings_for_the_bound_that_are_not_valid_are_configuration_errors() {
    let bus = MemoryBus::default();
    let engine = DetectionEngine::new(EngineConfig::default(), RulePack::empty()).unwrap();
    for (config, expected) in [
        (
            BusRunnerConfig {
                max_incident_updates: 0,
                ..BusRunnerConfig::default()
            },
            "the detection runner: detector configuration: max_incident_updates must be 1 or \
             more, but it is 0",
        ),
        (
            BusRunnerConfig {
                incident_update_window_seconds: 0,
                ..BusRunnerConfig::default()
            },
            "the detection runner: detector configuration: incident_update_window_seconds \
             must be 1 or more and must fit a time difference, but it is 0",
        ),
    ] {
        let error = tokio::time::timeout(
            Duration::from_secs(20),
            engine.run(&bus, &config, CancellationToken::new()),
        )
        .await
        .expect("the runner must return")
        .unwrap_err();
        assert!(
            matches!(&error, aegis_contracts::Error::Config(message) if message == expected),
            "{error}"
        );
    }
}
