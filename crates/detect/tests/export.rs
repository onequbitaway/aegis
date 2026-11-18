//! The acceptance test of the indicator export: the detections of decoys become an
//! indicator file, a pack loads the file, and the pack matches a later event.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, Verdict};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::export::{ExportOptions, export_decoy_indicators, merge_indicators};
use aegis_detect::ioc::{
    Indicator, IndicatorKind, indicators_from_yaml, indicators_to_json, indicators_to_yaml,
    load_indicators,
};
use aegis_detect::pack::RulePack;
use aegis_testkit::fixtures;
use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

const SCANNER: &str = "203.0.113.80";
const AGENT: &str = "203.0.113.81";

fn shipped_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity")
}

fn at(seconds: i64) -> DateTime<Utc> {
    fixtures::base_time() + TimeDelta::seconds(seconds)
}

/// One event of a decoy service.
fn decoy_event(
    sequence: u32,
    seconds: i64,
    name: &str,
    ip: &str,
    fingerprint: &str,
    user_agent: &str,
) -> Event {
    Event::new(
        at(seconds),
        EventSource::new("decoy-1", "aegis", "decoy").with_tenant("tenant-1"),
        EventClass::NetworkActivity,
        name,
        Actor::new(EntityKind::Other, "unknown")
            .with_ip(ip.parse::<IpAddr>().unwrap())
            .with_user_agent(user_agent),
    )
    .with_id(EventId(Uuid::from_u128(u128::from(sequence) + 1)))
    .with_outcome(Outcome::Success)
    .with_attribute(attr::DECOY_ID, "maze-1")
    .with_attribute(attr::DECOY_KIND, "maze")
    .with_attribute(attr::CLIENT_FINGERPRINT, fingerprint)
    .with_attribute(attr::HTTP_PATH, "/docs/page-7")
}

/// Sends decoy events and one normal event through the engine with the shipped pack.
async fn decoy_detections() -> Vec<Detection> {
    let engine = DetectionEngine::new(
        EngineConfig::default(),
        RulePack::load(shipped_directory()).unwrap(),
    )
    .unwrap();
    let mut events = vec![
        decoy_event(
            1,
            0,
            action::DECOY_CONTACT,
            SCANNER,
            "fp-scan",
            "scan-tool/3.1",
        ),
        decoy_event(
            2,
            700,
            action::DECOY_CONTACT,
            SCANNER,
            "fp-scan",
            "scan-tool/3.1",
        ),
        decoy_event(
            3,
            900,
            action::DECOY_CONTACT,
            AGENT,
            "fp-agent",
            "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/126.0",
        ),
        decoy_event(
            4,
            930,
            action::DECOY_CANARY_HIT,
            AGENT,
            "fp-agent",
            "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/126.0",
        )
        .with_attribute(attr::CANARY_ID, "canary-12"),
    ];
    // A normal event with a detection that is not from a decoy: a sign-in with a legacy
    // mail protocol from an office address.
    events.push(
        fixtures::sign_in(at(1_000), "user-001", fixtures::OFFICE_IP, true)
            .with_attribute(attr::AUTH_PROTOCOL, "imap"),
    );
    let mut detections = Vec::new();
    for event in &events {
        detections.extend(engine.process(event).await.unwrap().detections);
    }
    detections
}

/// Writes a pack directory with the manifest and one indicator file.
fn write_pack(directory: &Path, file: &str, text: &str) {
    fs::create_dir_all(directory.join("indicators")).unwrap();
    fs::write(
        directory.join("pack.yml"),
        "name: decoy-export\nversion: \"1\"\ndescription: Indicators from the decoys.\n",
    )
    .unwrap();
    fs::write(directory.join("indicators").join(file), text).unwrap();
}

#[tokio::test]
async fn exported_indicators_load_in_a_pack_and_match_a_later_event_from_that_address() {
    let detections = decoy_detections().await;
    // Two contacts of the scanner in two windows, one contact and one canary hit of the
    // agent, and one detection that is not from a decoy.
    assert_eq!(detections.len(), 5);
    let indicators = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
    let found: Vec<(IndicatorKind, &str, Severity)> = indicators
        .iter()
        .map(|indicator| (indicator.kind, indicator.value.as_str(), indicator.severity))
        .collect();
    assert_eq!(
        found,
        [
            (IndicatorKind::Ip, SCANNER, Severity::Low),
            // The canary hit is `high`. The export limits the severity to `medium`.
            (IndicatorKind::Ip, AGENT, Severity::Medium),
            // The user agent of the agent starts with `Mozilla/`, so it is not exported.
            (IndicatorKind::UserAgent, "scan-tool/3.1", Severity::Low),
            (
                IndicatorKind::ClientFingerprint,
                "fp-agent",
                Severity::Medium
            ),
            (IndicatorKind::ClientFingerprint, "fp-scan", Severity::Low),
        ]
    );
    // No value of the normal event is in the export.
    let office = fixtures::OFFICE_IP.to_string();
    assert!(indicators.iter().all(|indicator| indicator.value != office));
    let scanner = &indicators[0];
    assert_eq!(scanner.first_seen, Some(at(0)));
    assert_eq!(scanner.last_seen, Some(at(700)));
    assert_eq!(scanner.source.as_deref(), Some("aegis decoy detections"));
    let agent = &indicators[1];
    assert_eq!(agent.first_seen, Some(at(900)));
    assert_eq!(agent.last_seen, Some(at(930)));

    // The file round trip: the text gives the same indicators, as YAML and as JSON.
    let yaml = indicators_to_yaml(&indicators, "decoy.yml").unwrap();
    assert_eq!(
        indicators_from_yaml(&yaml, "decoy.yml").unwrap(),
        indicators
    );
    let directory = tempfile::tempdir().unwrap();
    write_pack(directory.path(), "decoy.yml", &yaml);
    let json_path = directory.path().join("copy.json");
    fs::write(
        &json_path,
        indicators_to_json(&indicators, "copy.json").unwrap(),
    )
    .unwrap();
    assert_eq!(load_indicators(&json_path).unwrap(), indicators);

    // A pack loads the file.
    let pack = RulePack::load(directory.path()).unwrap();
    let loaded: Vec<Indicator> = pack.indicators().indicators().cloned().collect();
    assert_eq!(loaded, indicators);

    // A later event from the address of the scanner matches. The event is a sign-in to
    // the identity system, not a decoy contact.
    let engine = DetectionEngine::new(EngineConfig::default(), pack).unwrap();
    let later = fixtures::sign_in(at(86_400), "user-004", SCANNER.parse().unwrap(), true);
    let output = engine.process(&later).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    let detection = &output.detections[0];
    assert_eq!(detection.rule_id, format!("ioc:ip:{SCANNER}"));
    assert_eq!(detection.event_ids, [later.id]);
    assert_eq!(detection.verdict, Verdict::Suspicious);
    assert_eq!(detection.severity, Severity::Low);
    assert!(
        detection
            .entities
            .contains(&EntityRef::new(EntityKind::IpAddress, SCANNER))
    );
    let technique_ids: Vec<&str> = detection
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    assert_eq!(technique_ids, ["T1595"]);

    // The fingerprint of the agent matches from a new address.
    let mut moved = fixtures::sign_in(
        at(86_500),
        "user-005",
        "203.0.113.99".parse().unwrap(),
        true,
    );
    moved
        .attributes
        .insert(attr::CLIENT_FINGERPRINT.to_owned(), "FP-Agent".into());
    let output = engine.process(&moved).await.unwrap();
    let rule_ids: Vec<&str> = output
        .detections
        .iter()
        .map(|detection| detection.rule_id.as_str())
        .collect();
    assert_eq!(rule_ids, ["ioc:client_fingerprint:fp-agent"]);

    // An event from an office address matches nothing.
    let normal = fixtures::sign_in(at(86_600), "user-006", fixtures::OFFICE_IP, true);
    assert!(engine.process(&normal).await.unwrap().is_empty());

    // The exported indicators have a suppression time: the scanner address signs in as
    // the same user 50 more times in one hour and gives no more detections.
    let mut repeated = 0;
    for step in 1..=50 {
        let again = fixtures::sign_in(
            at(86_400 + step * 60),
            "user-004",
            SCANNER.parse().unwrap(),
            true,
        );
        repeated += engine.process(&again).await.unwrap().detections.len();
    }
    assert_eq!(repeated, 0);
    assert_eq!(engine.flood_counters().suppressed_matches, 50);
}

#[tokio::test]
async fn a_second_export_merges_into_the_file_of_the_first_export() {
    let detections = decoy_detections().await;
    let first = export_decoy_indicators(&detections[..1], &ExportOptions::default()).unwrap();
    assert_eq!(first.len(), 3);
    let second = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
    let merged = merge_indicators(first.clone(), second.clone());
    // The three indicators of the first export stay first, with the newer times.
    assert_eq!(merged.len(), 5);
    assert_eq!(merged[0].value, SCANNER);
    assert_eq!(merged[0].first_seen, Some(at(0)));
    assert_eq!(merged[0].last_seen, Some(at(700)));
    assert_eq!(first[0].last_seen, Some(at(0)));

    // The two exports in two files of one pack are not valid: one indicator is there two
    // times. The merged file is valid.
    let directory = tempfile::tempdir().unwrap();
    write_pack(
        directory.path(),
        "first.yml",
        &indicators_to_yaml(&first, "first.yml").unwrap(),
    );
    fs::write(
        directory.path().join("indicators/second.yml"),
        indicators_to_yaml(&second, "second.yml").unwrap(),
    )
    .unwrap();
    let error = RulePack::load(directory.path()).unwrap_err();
    assert!(
        error.to_string().contains("is in the set two times"),
        "{error}"
    );
    fs::remove_file(directory.path().join("indicators/second.yml")).unwrap();
    fs::write(
        directory.path().join("indicators/first.yml"),
        indicators_to_yaml(&merged, "first.yml").unwrap(),
    )
    .unwrap();
    let pack = RulePack::load(directory.path()).unwrap();
    assert_eq!(pack.indicators().len(), 5);
}

#[tokio::test]
async fn the_export_of_the_recorded_attack_log_is_empty() {
    // The attack log has no decoy. Its detections give no indicator.
    let engine = DetectionEngine::new(
        EngineConfig::default(),
        RulePack::load(shipped_directory()).unwrap(),
    )
    .unwrap();
    let mut detections = Vec::new();
    for event in fixtures::artex_style_attack() {
        detections.extend(engine.process(&event).await.unwrap().detections);
    }
    assert_eq!(detections.len(), 9);
    assert_eq!(
        export_decoy_indicators(&detections, &ExportOptions::default()).unwrap(),
        []
    );
}
