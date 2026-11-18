//! The acceptance tests of the endpoint-probe detector, through the engine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::Arc;

use aegis_contracts::common::{EntityKind, EntityRef, EventId};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Verdict};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::pack::RulePack;
use aegis_detect::velocity::{
    DECOY_PATH_RULE_ID, ENDPOINT_PROBE_RULE_ID, EndpointProbe, EndpointProbeConfig, VelocityConfig,
};
use aegis_testkit::ScriptedModel;
use aegis_testkit::fixtures;
use chrono::TimeDelta;
use uuid::Uuid;

const CLIENT: &str = "203.0.113.80";

fn probe_config() -> EndpointProbeConfig {
    EndpointProbeConfig {
        decoy_paths: vec!["/.git/config".to_owned(), "/internal/backup/*".to_owned()],
        ..EndpointProbeConfig::default()
    }
}

fn engine() -> DetectionEngine {
    let config = EngineConfig {
        velocity: VelocityConfig {
            endpoint_probe: probe_config(),
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    DetectionEngine::new(config, RulePack::empty()).unwrap()
}

/// One request to a web endpoint of the operator, `sequence` times 200 milliseconds after
/// the start of the log.
fn request(sequence: u32, client: &str, path: &str, status: u16) -> Event {
    Event::new(
        fixtures::base_time() + TimeDelta::milliseconds(i64::from(sequence) * 200),
        EventSource::new("web", "example", "gateway").with_tenant("tenant-1"),
        EventClass::NetworkActivity,
        action::HTTP_REQUEST,
        Actor::new(EntityKind::Other, "anonymous")
            .with_ip(client.parse::<IpAddr>().unwrap())
            .with_user_agent("scan-tool/3.1"),
    )
    .with_id(EventId(Uuid::from_u128(u128::from(sequence) + 1)))
    .with_outcome(if status < 400 {
        Outcome::Success
    } else {
        Outcome::Failure
    })
    .with_attribute(attr::HTTP_METHOD, "GET")
    .with_attribute(attr::HTTP_PATH, path)
    .with_attribute(attr::HTTP_STATUS, status)
}

async fn process_all(engine: &DetectionEngine, events: &[Event]) -> Vec<Detection> {
    let mut detections = Vec::new();
    for event in events {
        detections.extend(engine.process(event).await.unwrap().detections);
    }
    detections
}

#[tokio::test]
async fn fifty_requests_for_fifty_missing_paths_give_one_detection() {
    let engine = engine();
    let events: Vec<Event> = (0..50)
        .map(|index| request(index, CLIENT, &format!("/admin/tool-{index}.php"), 404))
        .collect();
    let detections = process_all(&engine, &events).await;
    assert_eq!(detections.len(), 1);
    let probe = &detections[0];
    assert_eq!(probe.rule_id, ENDPOINT_PROBE_RULE_ID);
    assert_eq!(probe.verdict, Verdict::Suspicious);
    assert_eq!(probe.tier, DetectionTier::Deterministic);
    assert_eq!(
        probe.entities,
        [EntityRef::new(EntityKind::IpAddress, CLIENT)]
    );
    // The default threshold is 20 paths. The detection names those 20 requests.
    assert_eq!(probe.attributes["distinct_paths"], serde_json::json!(20));
    assert_eq!(
        probe.event_ids,
        events[..20]
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(probe.time, events[19].time);
    assert_eq!(probe.tenant.as_deref(), Some("tenant-1"));
    // One client gave one incident.
    assert_eq!(engine.incidents().len(), 1);
    assert_eq!(engine.incidents()[0].detections.len(), 1);
}

#[tokio::test]
async fn fifty_requests_for_one_path_that_exists_give_no_detection() {
    let engine = engine();
    let events: Vec<Event> = (0..50)
        .map(|index| request(index, CLIENT, "/api/v1/status", 200))
        .collect();
    assert_eq!(process_all(&engine, &events).await, []);
    // Fifty different paths that exist are also not a probe: the status decides.
    let many: Vec<Event> = (50..100)
        .map(|index| request(index, CLIENT, &format!("/api/v1/items/{index}"), 200))
        .collect();
    assert_eq!(process_all(&engine, &many).await, []);
    assert_eq!(engine.incidents(), []);
}

#[tokio::test]
async fn one_request_for_a_decoy_path_gives_one_detection() {
    let engine = engine();
    let hit = request(0, CLIENT, "/.git/config", 404);
    let detections = process_all(&engine, std::slice::from_ref(&hit)).await;
    assert_eq!(detections.len(), 1);
    let found = &detections[0];
    assert_eq!(found.rule_id, DECOY_PATH_RULE_ID);
    assert_eq!(found.event_ids, [hit.id]);
    assert_eq!(found.verdict, Verdict::Suspicious);
    assert_eq!(
        found.attributes["decoy_path"],
        serde_json::json!("/.git/config")
    );
    assert_eq!(
        found.entities,
        [EntityRef::new(EntityKind::IpAddress, CLIENT)]
    );

    // The client asks again, and for a path below the second decoy path. The engine makes
    // no more detections for this client.
    let more = vec![
        request(1, CLIENT, "/.git/config", 404),
        request(2, CLIENT, "/internal/backup/2026.tar", 200),
    ];
    assert_eq!(process_all(&engine, &more).await, []);
    // A different client gives its own detection.
    let other = request(3, "203.0.113.81", "/internal/backup/2026.tar", 200);
    let detections = process_all(&engine, &[other]).await;
    assert_eq!(detections.len(), 1);
    assert_eq!(
        detections[0].attributes["decoy_path"],
        serde_json::json!("/internal/backup/*")
    );
}

#[tokio::test]
async fn a_probe_is_suspicious_so_tier_two_examines_it_one_time() {
    let answer = serde_json::json!({
        "verdict": "malicious",
        "confidence": 0.9,
        "reasons": ["The client asked for the paths of a known scanner word list."]
    });
    let model = Arc::new(ScriptedModel::new("fake").reply_json(&answer));
    let config = EngineConfig {
        velocity: VelocityConfig {
            endpoint_probe: probe_config(),
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine = DetectionEngine::new(config, RulePack::empty())
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    let events: Vec<Event> = (0..200)
        .map(|index| request(index, CLIENT, &format!("/wp-content/{index}"), 404))
        .collect();
    let detections = process_all(&engine, &events).await;
    // The tier 1 detection and its tier 2 result, for 200 requests.
    assert_eq!(detections.len(), 2);
    assert_eq!(detections[0].tier, DetectionTier::Deterministic);
    assert_eq!(detections[1].tier, DetectionTier::Llm);
    assert_eq!(detections[1].verdict, Verdict::Malicious);
    assert_eq!(model.requests().len(), 1);
}

#[tokio::test]
async fn the_detector_contract_gives_the_same_detections() {
    let detector: Arc<dyn Detector> = Arc::new(EndpointProbe::new(probe_config()).unwrap());
    assert_eq!(detector.id(), "aegis.velocity.endpoint_probe");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);
    let mut events: Vec<Event> = (0..50)
        .map(|index| request(index, CLIENT, &format!("/missing/{index}"), 410))
        .collect();
    events.push(request(50, "203.0.113.82", "/.git/config", 403));
    let mut rule_ids = Vec::new();
    for event in &events {
        for detection in detector.inspect(event).await.unwrap() {
            rule_ids.push(detection.rule_id);
        }
    }
    assert_eq!(rule_ids, [ENDPOINT_PROBE_RULE_ID, DECOY_PATH_RULE_ID]);
    // The recorded attack log has no request to a web endpoint.
    for event in fixtures::artex_style_attack() {
        assert_eq!(detector.inspect(&event).await.unwrap(), []);
    }
}
