//! Tests of the engine: tier 1, tier 2, the correlator, and the rule pack as one unit.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Actor, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::model::{ResponseFormat, TaskKind};
use aegis_contracts::{Error, IncidentStatus};
use aegis_testkit::ScriptedModel;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::flood::FloodCounters;
use crate::ioc::{Indicator, IndicatorKind};
use crate::llm::TRIAGE_ATTRIBUTE;
use crate::pack::PackManifest;
use crate::sigma::SigmaRule;
use crate::velocity::{
    PRIVILEGED_SELF_ASSIGNMENT_RULE_ID, SIGN_IN_BURST_RULE_ID, SignInBurstConfig,
};

const TENANT: &str = "tenant-1";

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_793_696_400, 0).unwrap() + TimeDelta::seconds(seconds)
}

fn event(sequence: u32, seconds: i64, action: &str, actor_id: &str) -> Event {
    let actor =
        Actor::new(EntityKind::User, actor_id).with_ip("198.51.100.10".parse::<IpAddr>().unwrap());
    Event::new(
        at(seconds),
        EventSource::new("test", "vendor", "product").with_tenant(TENANT),
        EventClass::Other,
        action,
        actor,
    )
    .with_id(EventId(Uuid::from_u128(u128::from(sequence))))
    .with_outcome(Outcome::Success)
}

fn rule(id: &str, level: &str, action: &str) -> SigmaRule {
    let text = format!(
        "title: Rule {id}\nid: {id}\nlevel: {level}\ntags:\n  - attack.t1098\ndetection:\n  \
         selection:\n    action: {action}\n  condition: selection\n"
    );
    SigmaRule::parse(&text, "inline").unwrap()
}

fn pack(rules: Vec<SigmaRule>) -> RulePack {
    let manifest = PackManifest {
        name: "test-pack".to_owned(),
        version: "1".to_owned(),
        description: "Rules for the engine tests.".to_owned(),
    };
    RulePack::new(manifest, rules, Vec::new()).unwrap()
}

/// A pack with one `medium` rule (`suspicious`) and one `high` rule (`malicious`).
fn two_tier_pack() -> RulePack {
    pack(vec![
        rule("rule-suspicious", "medium", action::USER_UPDATE),
        rule("rule-malicious", "high", action::USER_PASSWORD_RESET),
    ])
}

fn engine_with(model: ScriptedModel) -> (Arc<ScriptedModel>, DetectionEngine) {
    let model = Arc::new(model);
    let engine = DetectionEngine::new(EngineConfig::default(), two_tier_pack())
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    (model, engine)
}

fn rule_ids(output: &EngineOutput) -> Vec<&str> {
    output
        .detections
        .iter()
        .map(|detection| detection.rule_id.as_str())
        .collect()
}

#[tokio::test]
async fn an_event_with_no_detection_gives_an_empty_output_and_no_model_request() {
    let (model, engine) = engine_with(ScriptedModel::new("fake").reply("unused"));
    let output = engine
        .process(&event(1, 0, action::SIGN_IN, "user-1"))
        .await
        .unwrap();
    assert_eq!(output, EngineOutput::default());
    assert!(output.is_empty());
    assert_eq!(model.requests().len(), 0);
    assert_eq!(engine.incidents(), []);
}

#[tokio::test]
async fn a_malicious_tier_one_detection_does_not_reach_the_model() {
    let (model, engine) = engine_with(ScriptedModel::new("fake").reply("unused"));
    let output = engine
        .process(&event(1, 0, action::USER_PASSWORD_RESET, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&output), ["rule-malicious"]);
    assert_eq!(output.detections[0].verdict, Verdict::Malicious);
    assert_eq!(output.detections[0].tier, DetectionTier::Deterministic);
    // The engine did not start tier 2 for the detection, so it has no tier 2 record.
    assert_eq!(output.detections[0].attributes.get(TRIAGE_ATTRIBUTE), None);
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections, output.detections);
    assert!(!output.is_empty());
    assert_eq!(model.requests().len(), 0);
    assert_eq!(model.remaining(), 1);
}

#[tokio::test]
async fn a_suspicious_detection_goes_to_tier_two_and_a_malicious_result_joins_an_incident() {
    let answer = json!({
        "verdict": "malicious",
        "confidence": 0.9,
        "reasons": ["The change came from a script."],
        "severity": "high"
    });
    let (model, engine) = engine_with(ScriptedModel::new("fake").reply_json(&answer));
    let event = event(1, 0, action::USER_UPDATE, "user-1");
    let output = engine.process(&event).await.unwrap();

    assert_eq!(rule_ids(&output), ["rule-suspicious", "rule-suspicious"]);
    let (first, second) = (&output.detections[0], &output.detections[1]);
    assert_eq!(first.tier, DetectionTier::Deterministic);
    assert_eq!(first.verdict, Verdict::Suspicious);
    assert_eq!(first.severity, Severity::Medium);
    assert_eq!(first.attributes.get(TRIAGE_ATTRIBUTE), None);
    assert_eq!(second.tier, DetectionTier::Llm);
    assert_eq!(second.verdict, Verdict::Malicious);
    assert_eq!(second.severity, Severity::High);
    assert_ne!(second.id, first.id);
    assert_eq!(
        second.attributes[TRIAGE_ATTRIBUTE]["source_detection"],
        json!(first.id)
    );

    // The incident holds the tier 2 result and not the tier 1 detection.
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections, std::slice::from_ref(second));
    assert_eq!(output.incidents[0].severity, Severity::High);
    assert_eq!(engine.incidents(), output.incidents);

    // The request is a JSON triage request that holds the event.
    let requests = model.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].task, TaskKind::Triage);
    assert_eq!(requests[0].response_format, ResponseFormat::Json);
    let document: Value = serde_json::from_str(&requests[0].messages[1].content).unwrap();
    assert_eq!(document["detection"]["rule_id"], json!("rule-suspicious"));
    assert_eq!(document["events"].as_array().unwrap().len(), 1);
    assert_eq!(document["events"][0]["id"], json!(event.id));
}

#[tokio::test]
async fn a_benign_result_is_in_the_output_and_joins_no_incident() {
    let answer = json!({
        "verdict": "benign",
        "confidence": 0.95,
        "reasons": ["A known provisioning job made the change."]
    });
    let (model, engine) = engine_with(ScriptedModel::new("fake").reply_json(&answer));
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(output.detections.len(), 2);
    assert_eq!(output.detections[0].verdict, Verdict::Suspicious);
    assert_eq!(output.detections[1].verdict, Verdict::Benign);
    assert_eq!(output.detections[1].tier, DetectionTier::Llm);
    assert_eq!(output.detections[1].severity, Severity::Informational);
    assert_eq!(output.incidents, []);
    // The output has detections, so it is not empty.
    assert!(!output.is_empty());
    assert_eq!(engine.incidents(), []);
    assert_eq!(model.requests().len(), 1);
}

#[tokio::test]
async fn model_output_that_is_not_json_keeps_the_detection_suspicious_in_an_incident() {
    let (model, engine) = engine_with(ScriptedModel::new("fake").reply("It is benign."));
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(output.detections.len(), 2);
    let result = &output.detections[1];
    assert_eq!(result.tier, DetectionTier::Llm);
    assert_eq!(result.verdict, Verdict::Suspicious);
    assert_eq!(result.severity, Severity::Medium);
    assert_eq!(
        result.attributes[TRIAGE_ATTRIBUTE]["status"],
        json!("invalid_output")
    );
    // The detection is not lost: it is in an incident.
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections, std::slice::from_ref(result));
    assert_eq!(output.incidents[0].severity, Severity::Medium);
    assert_eq!(model.requests().len(), 1);
}

#[tokio::test]
async fn a_model_failure_is_not_an_error_and_the_tier_one_detection_records_it() {
    let (model, engine) =
        engine_with(ScriptedModel::new("fake").fail(Error::RateLimited("slow down".to_owned())));
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(output.detections.len(), 1);
    let detection = &output.detections[0];
    assert_eq!(detection.tier, DetectionTier::Deterministic);
    assert_eq!(detection.verdict, Verdict::Suspicious);
    assert_eq!(
        detection.attributes[TRIAGE_ATTRIBUTE],
        json!({
            "status": "model_error",
            "error": "rate limited: slow down",
            "retryable": true,
        })
    );
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(
        output.incidents[0].detections,
        std::slice::from_ref(detection)
    );
    assert_eq!(model.requests().len(), 1);
}

#[tokio::test]
async fn an_engine_with_no_model_sends_a_suspicious_detection_to_the_correlator() {
    let engine = DetectionEngine::new(EngineConfig::default(), two_tier_pack()).unwrap();
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(output.detections.len(), 1);
    assert_eq!(output.detections[0].verdict, Verdict::Suspicious);
    assert_eq!(output.detections[0].tier, DetectionTier::Deterministic);
    assert_eq!(output.detections[0].attributes.get(TRIAGE_ATTRIBUTE), None);
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections, output.detections);
}

#[tokio::test]
async fn each_suspicious_detection_of_one_event_gets_its_own_request() {
    let malicious = json!({ "verdict": "malicious", "reasons": ["r"] });
    let benign = json!({ "verdict": "benign", "confidence": 1.0, "reasons": ["r"] });
    let model = Arc::new(
        ScriptedModel::new("fake")
            .reply_json(&malicious)
            .reply_json(&benign),
    );
    let rules = vec![
        rule("first", "medium", action::USER_UPDATE),
        rule("second", "low", "user.*"),
        rule("third", "high", action::USER_UPDATE),
    ];
    let engine = DetectionEngine::new(EngineConfig::default(), pack(rules))
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    let found: Vec<(&str, DetectionTier, Verdict)> = output
        .detections
        .iter()
        .map(|detection| {
            (
                detection.rule_id.as_str(),
                detection.tier,
                detection.verdict,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("first", DetectionTier::Deterministic, Verdict::Suspicious),
            ("first", DetectionTier::Llm, Verdict::Malicious),
            ("second", DetectionTier::Deterministic, Verdict::Suspicious),
            ("second", DetectionTier::Llm, Verdict::Benign),
            ("third", DetectionTier::Deterministic, Verdict::Malicious),
        ]
    );
    assert_eq!(model.requests().len(), 2);
    // One event changed one incident. The output has one state of it, the last one.
    assert_eq!(output.incidents.len(), 1);
    let stored: Vec<(&str, DetectionTier)> = output.incidents[0]
        .detections
        .iter()
        .map(|detection| (detection.rule_id.as_str(), detection.tier))
        .collect();
    assert_eq!(stored.len(), 2);
    assert!(stored.contains(&("first", DetectionTier::Llm)));
    assert!(stored.contains(&("third", DetectionTier::Deterministic)));
}

#[tokio::test]
async fn the_velocity_detectors_run_after_the_rules_of_the_pack() {
    let rules = vec![rule("role-rule", "high", action::ROLE_ASSIGN)];
    let engine = DetectionEngine::new(EngineConfig::default(), pack(rules)).unwrap();
    let mut assignment = event(1, 0, action::ROLE_ASSIGN, "sp-1")
        .with_target(EntityRef::new(EntityKind::ServicePrincipal, "sp-1"))
        .with_attribute(attr::PRIVILEGED, true);
    assignment.actor.kind = EntityKind::ServicePrincipal;
    let output = engine.process(&assignment).await.unwrap();
    assert_eq!(
        rule_ids(&output),
        ["role-rule", PRIVILEGED_SELF_ASSIGNMENT_RULE_ID]
    );
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections.len(), 2);
}

#[tokio::test]
async fn the_indicators_of_the_pack_run_after_its_rules_and_before_the_velocity_detectors() {
    let manifest = PackManifest {
        name: "indicator-pack".to_owned(),
        version: "1".to_owned(),
        description: "One rule and one indicator.".to_owned(),
    };
    let indicator = Indicator {
        kind: IndicatorKind::Ip,
        value: "192.0.2.200".to_owned(),
        description: "An example address.".to_owned(),
        severity: Severity::High,
        tags: vec!["attack.t1090".to_owned()],
        verdict: None,
        id: None,
        first_seen: None,
        last_seen: None,
        source: None,
        suppress_seconds: None,
    };
    let pack = RulePack::new(
        manifest,
        vec![rule("role-rule", "high", action::ROLE_ASSIGN)],
        vec![indicator],
    )
    .unwrap();
    let engine = DetectionEngine::new(EngineConfig::default(), pack).unwrap();

    let mut assignment = event(1, 0, action::ROLE_ASSIGN, "sp-1")
        .with_target(EntityRef::new(EntityKind::ServicePrincipal, "sp-1"))
        .with_attribute(attr::PRIVILEGED, true);
    assignment.actor.kind = EntityKind::ServicePrincipal;
    assignment.actor.ip = Some("192.0.2.200".parse::<IpAddr>().unwrap());
    let output = engine.process(&assignment).await.unwrap();
    assert_eq!(
        rule_ids(&output),
        [
            "role-rule",
            "ioc:ip:192.0.2.200",
            PRIVILEGED_SELF_ASSIGNMENT_RULE_ID
        ]
    );
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections.len(), 3);

    // An event from a different address does not match the indicator.
    let other = engine
        .process(&event(2, 1, action::SIGN_IN, "user-1"))
        .await
        .unwrap();
    assert!(other.is_empty());
}

#[tokio::test]
async fn a_detection_that_links_two_incidents_gives_the_replaced_incident_and_then_the_live_one() {
    let rules = vec![
        rule("update", "high", action::USER_UPDATE),
        rule("create", "high", action::USER_CREATE),
    ];
    let engine = DetectionEngine::new(EngineConfig::default(), pack(rules)).unwrap();
    let mut first = event(1, 0, action::USER_UPDATE, "user-1");
    first.actor.ip = None;
    let mut second = event(2, 10, action::USER_UPDATE, "user-2");
    second.actor.ip = None;
    let older = engine.process(&first).await.unwrap().incidents.remove(0);
    let newer = engine.process(&second).await.unwrap().incidents.remove(0);
    assert_ne!(older.id, newer.id);

    // The actor of this event is the first user, and its target is the second user.
    let mut bridge = event(3, 20, action::USER_CREATE, "user-1")
        .with_target(EntityRef::new(EntityKind::User, "user-2"));
    bridge.actor.ip = None;
    let output = engine.process(&bridge).await.unwrap();
    let states: Vec<(aegis_contracts::common::IncidentId, IncidentStatus, usize)> = output
        .incidents
        .iter()
        .map(|incident| (incident.id, incident.status, incident.detections.len()))
        .collect();
    assert_eq!(
        states,
        [
            (newer.id, IncidentStatus::Resolved, 1),
            (older.id, IncidentStatus::Open, 3),
        ]
    );
    assert_eq!(engine.incidents().len(), 1);
}

/// A detector that fails one time for the events of one actor, and finds nothing.
struct FailsOnce {
    actor_id: &'static str,
    failed: AtomicBool,
}

#[async_trait]
impl Detector for FailsOnce {
    fn id(&self) -> &str {
        "test.fails_once"
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        if event.actor.id == self.actor_id && !self.failed.swap(true, Ordering::SeqCst) {
            return Err(Error::Timeout("the plugin gave no answer".to_owned()));
        }
        Ok(Vec::new())
    }
}

/// A detector that returns one fixed detection for each `user.update` event.
struct Fixed {
    verdict: Verdict,
    tier: DetectionTier,
}

#[async_trait]
impl Detector for Fixed {
    fn id(&self) -> &str {
        "test.fixed"
    }

    fn tier(&self) -> DetectionTier {
        self.tier
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        if event.action != action::USER_UPDATE {
            return Ok(Vec::new());
        }
        let mut detection = rule("added-rule", "medium", action::USER_UPDATE)
            .detect(event)
            .ok_or_else(|| Error::InvalidInput("the test rule did not match".to_owned()))?;
        detection.verdict = self.verdict;
        detection.tier = self.tier;
        Ok(vec![detection])
    }
}

#[tokio::test]
async fn an_added_detector_runs_and_its_detections_come_last() {
    let engine = DetectionEngine::new(EngineConfig::default(), two_tier_pack())
        .unwrap()
        .with_detector(Arc::new(Fixed {
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
        }));
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&output), ["rule-suspicious", "added-rule"]);
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].detections.len(), 2);
    let none = engine
        .process(&event(2, 1, action::SIGN_IN, "user-1"))
        .await
        .unwrap();
    assert_eq!(none, EngineOutput::default());
}

#[tokio::test]
async fn a_suspicious_tier_two_detection_of_an_added_detector_gets_no_second_analysis() {
    let model = Arc::new(ScriptedModel::new("fake").reply("unused"));
    let engine = DetectionEngine::new(EngineConfig::default(), RulePack::empty())
        .unwrap()
        .with_triage(model.clone())
        .unwrap()
        .with_detector(Arc::new(Fixed {
            verdict: Verdict::Suspicious,
            tier: DetectionTier::Llm,
        }));
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(output.detections.len(), 1);
    assert_eq!(output.detections[0].tier, DetectionTier::Llm);
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(model.requests().len(), 0);
}

#[tokio::test]
async fn an_error_of_an_added_detector_is_returned_and_the_event_changes_no_state() {
    let config = EngineConfig {
        velocity: VelocityConfig {
            sign_in_burst: SignInBurstConfig {
                distinct_user_threshold: 3,
                ..SignInBurstConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine = DetectionEngine::new(config, RulePack::empty())
        .unwrap()
        .with_detector(Arc::new(FailsOnce {
            actor_id: "user-2",
            failed: AtomicBool::new(false),
        }));
    let failure = |sequence: u32, user: &str| {
        event(sequence, i64::from(sequence), action::SIGN_IN, user).with_outcome(Outcome::Failure)
    };

    assert!(
        engine
            .process(&failure(1, "user-1"))
            .await
            .unwrap()
            .is_empty()
    );
    let error = engine.process(&failure(2, "user-2")).await.unwrap_err();
    assert!(
        matches!(&error, Error::Timeout(message) if message == "the plugin gave no answer"),
        "{error}"
    );
    // The burst detector did not count the event that failed. The third user is thus only
    // the second user in the window.
    assert!(
        engine
            .process(&failure(3, "user-3"))
            .await
            .unwrap()
            .is_empty()
    );
    // The same event again, with no failure, is the third user.
    let output = engine.process(&failure(2, "user-2")).await.unwrap();
    assert_eq!(rule_ids(&output), [SIGN_IN_BURST_RULE_ID]);
    assert_eq!(output.detections[0].attributes["distinct_users"], json!(3));
}

#[tokio::test]
async fn reload_replaces_the_rules_and_keeps_the_incidents_and_the_detector_state() {
    let config = EngineConfig {
        velocity: VelocityConfig {
            sign_in_burst: SignInBurstConfig {
                distinct_user_threshold: 3,
                ..SignInBurstConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine =
        DetectionEngine::new(config, pack(vec![rule("old", "high", action::USER_UPDATE)])).unwrap();
    assert_eq!(engine.pack().manifest().name, "test-pack");
    let failure = |sequence: u32, user: &str| {
        event(sequence, i64::from(sequence), action::SIGN_IN, user).with_outcome(Outcome::Failure)
    };
    engine.process(&failure(1, "user-1")).await.unwrap();
    engine.process(&failure(2, "user-2")).await.unwrap();
    let before = engine
        .process(&event(3, 3, action::USER_UPDATE, "user-9"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&before), ["old"]);

    let previous = engine.reload(pack(vec![rule("new", "high", action::USER_CREATE)]));
    let old_ids: Vec<&str> = previous.rules().iter().map(SigmaRule::id).collect();
    assert_eq!(old_ids, ["old"]);
    let new_ids: Vec<String> = engine
        .pack()
        .rules()
        .iter()
        .map(|rule| rule.id().to_owned())
        .collect();
    assert_eq!(new_ids, ["new"]);

    // The old rule is no longer active, and the new rule is.
    let after = engine
        .process(&event(4, 4, action::USER_UPDATE, "user-9"))
        .await
        .unwrap();
    assert!(after.is_empty());
    let created = engine
        .process(&event(5, 5, action::USER_CREATE, "user-9"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&created), ["new"]);
    // The new detection joins the incident from before the reload.
    assert_eq!(created.incidents.len(), 1);
    assert_eq!(created.incidents[0].id, before.incidents[0].id);
    assert_eq!(created.incidents[0].detections.len(), 2);
    // The burst detector kept the two failures from before the reload.
    let burst = engine.process(&failure(6, "user-3")).await.unwrap();
    assert_eq!(rule_ids(&burst), [SIGN_IN_BURST_RULE_ID]);
}

#[tokio::test]
async fn reload_from_a_directory_that_is_not_a_valid_pack_keeps_the_active_pack() {
    let engine = DetectionEngine::new(
        EngineConfig::default(),
        pack(vec![rule("old", "high", action::USER_UPDATE)]),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("pack.yml"),
        "name: broken\nversion: \"1\"\ndescription: d\n",
    )
    .unwrap();
    std::fs::create_dir(directory.path().join("rules")).unwrap();
    std::fs::write(
        directory.path().join("rules").join("bad.yml"),
        "title: Bad\ndetection:\n  selection:\n    action: sign_in\n  condition: missing\n",
    )
    .unwrap();

    let error = engine.reload_from_dir(directory.path()).err().unwrap();
    assert!(
        matches!(
            &error,
            DetectError::Rule { reason, .. }
                if reason == "the condition names the selection \"missing\", which the rule \
                              does not have"
        ),
        "{error}"
    );
    assert_eq!(engine.pack().manifest().name, "test-pack");
    let output = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&output), ["old"]);

    // The same directory with a valid rule is accepted.
    std::fs::write(
        directory.path().join("rules").join("bad.yml"),
        "title: Good\nid: good\nlevel: high\ndetection:\n  selection:\n    action: sign_in\n  \
         condition: selection\n",
    )
    .unwrap();
    let previous = engine.reload_from_dir(directory.path()).unwrap();
    assert_eq!(previous.manifest().name, "test-pack");
    assert_eq!(engine.pack().manifest().name, "broken");
    let output = engine
        .process(&event(2, 1, action::SIGN_IN, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&output), ["good"]);
}

#[tokio::test]
async fn a_forgotten_incident_gets_no_more_detections() {
    let engine = DetectionEngine::new(EngineConfig::default(), two_tier_pack()).unwrap();
    let first = engine
        .process(&event(1, 0, action::USER_PASSWORD_RESET, "user-1"))
        .await
        .unwrap();
    let id = first.incidents[0].id;
    assert!(engine.forget_incident(id));
    assert!(!engine.forget_incident(id));
    assert_eq!(engine.incidents(), []);
    let second = engine
        .process(&event(2, 1, action::USER_PASSWORD_RESET, "user-1"))
        .await
        .unwrap();
    assert_eq!(second.incidents.len(), 1);
    assert_ne!(second.incidents[0].id, id);
    assert_eq!(second.incidents[0].detections.len(), 1);
}

#[test]
fn settings_that_are_not_valid_are_errors() {
    let burst = EngineConfig {
        velocity: VelocityConfig {
            sign_in_burst: SignInBurstConfig {
                failure_threshold: 0,
                ..SignInBurstConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let correlator = EngineConfig {
        correlator: CorrelatorConfig {
            max_incidents: 0,
            ..CorrelatorConfig::default()
        },
        ..EngineConfig::default()
    };
    let triage = EngineConfig {
        triage: LlmTriageConfig {
            timeout_seconds: 0,
            ..LlmTriageConfig::default()
        },
        ..EngineConfig::default()
    };
    for (config, expected) in [
        (
            burst,
            "sign_in_burst.failure_threshold must be 2 or more, but it is 0",
        ),
        (
            correlator,
            "correlator.max_incidents must be 1 or more, but it is 0",
        ),
        (
            triage,
            "llm_triage.timeout_seconds must be 1 or more, but it is 0",
        ),
    ] {
        let error = DetectionEngine::new(config, RulePack::empty())
            .err()
            .unwrap();
        assert!(
            matches!(&error, DetectError::Config(message) if message == expected),
            "{error}"
        );
    }
}

#[test]
fn the_settings_read_from_a_partial_map_and_reject_unknown_keys() {
    let config: EngineConfig = serde_json::from_value(json!({
        "velocity": { "sign_in_burst": { "failure_threshold": 50 } },
        "correlator": { "window_seconds": 600 },
        "triage": { "model": "fast-model" }
    }))
    .unwrap();
    assert_eq!(config.velocity.sign_in_burst.failure_threshold, 50);
    assert_eq!(config.velocity.sign_in_burst.window_seconds, 60);
    assert_eq!(config.correlator.window_seconds, 600);
    assert_eq!(config.triage.model.as_deref(), Some("fast-model"));
    assert_eq!(
        serde_json::from_value::<EngineConfig>(json!({})).unwrap(),
        EngineConfig::default()
    );
    let error = serde_json::from_value::<EngineConfig>(json!({ "sigma": {} })).unwrap_err();
    assert!(
        error.to_string().contains("unknown field `sigma`"),
        "{error}"
    );
}

#[tokio::test]
async fn the_engine_works_from_a_task_on_a_different_thread() {
    let engine = Arc::new(DetectionEngine::new(EngineConfig::default(), two_tier_pack()).unwrap());
    let shared = engine.clone();
    let output = tokio::spawn(async move {
        shared
            .process(&event(1, 0, action::USER_PASSWORD_RESET, "user-1"))
            .await
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rule_ids(&output), ["rule-malicious"]);
    assert_eq!(engine.incidents().len(), 1);
}

/// A `medium` rule (`suspicious`) for `user.update` with the given `aegis.suppress` text.
fn suppressed_rule(id: &str, level: &str, suppress: &str) -> SigmaRule {
    let text = format!(
        "title: Rule {id}\nid: {id}\ndescription: A change.\nlevel: {level}\ntags:\n  - \
         attack.t1098\ndetection:\n  selection:\n    action: user.update\n  condition: \
         selection\naegis.suppress:\n{suppress}"
    );
    SigmaRule::parse(&text, "inline").unwrap()
}

#[tokio::test]
async fn a_rule_with_suppression_gives_one_detection_for_one_key_in_the_window() {
    let rule = suppressed_rule(
        "quiet",
        "high",
        "  window_seconds: 60\n  fields: [actor.id]\n",
    );
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule])).unwrap();
    assert_eq!(engine.flood_counters(), FloodCounters::default());
    assert_eq!(engine.suppression_summaries(), []);

    let first = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&first), ["quiet"]);
    assert_eq!(
        first.detections[0]
            .attributes
            .get(PREVIOUS_MATCHES_ATTRIBUTE),
        None
    );
    for sequence in 2..=20 {
        let output = engine
            .process(&event(
                sequence,
                i64::from(sequence),
                action::USER_UPDATE,
                "user-1",
            ))
            .await
            .unwrap();
        assert_eq!(output, EngineOutput::default(), "event {sequence}");
    }
    // A different key is not suppressed.
    let other = engine
        .process(&event(30, 30, action::USER_UPDATE, "user-2"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&other), ["quiet"]);

    assert_eq!(
        engine.flood_counters(),
        FloodCounters {
            suppressed_matches: 19,
            ..FloodCounters::default()
        }
    );
    let summaries = engine.suppression_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].rule_id, "quiet");
    assert_eq!(summaries[0].key, "user-1");
    assert_eq!(summaries[0].tenant.as_deref(), Some(TENANT));
    assert_eq!(summaries[0].matches, 20);
    assert_eq!(summaries[0].window_start, at(0));
    assert_eq!(summaries[0].last_seen, at(20));
    assert_eq!(summaries[0].detection_id, first.detections[0].id);
    // The two users share one address, so their detections are in one incident. It has
    // one detection for each user, and none for the 19 other matches.
    assert_eq!(engine.incidents().len(), 1);
    assert_eq!(engine.incidents()[0].detections.len(), 2);
}

#[tokio::test]
async fn a_match_after_the_window_gives_a_detection_that_reports_the_count_before() {
    let rule = suppressed_rule(
        "quiet",
        "high",
        "  window_seconds: 60\n  fields: [actor.id]\n",
    );
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule])).unwrap();
    for sequence in 1..=5 {
        engine
            .process(&event(
                sequence,
                i64::from(sequence),
                action::USER_UPDATE,
                "user-1",
            ))
            .await
            .unwrap();
    }
    // The window started at second 1 and ends at second 61.
    let next = engine
        .process(&event(6, 61, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&next), ["quiet"]);
    assert_eq!(
        next.detections[0].attributes[PREVIOUS_MATCHES_ATTRIBUTE],
        json!(5)
    );
    assert_eq!(engine.flood_counters().suppressed_matches, 4);
}

#[tokio::test]
async fn a_rule_with_no_fields_uses_the_entities_of_the_detection_as_the_key() {
    let rule = suppressed_rule("quiet", "high", "  window_seconds: 60\n");
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule])).unwrap();
    let change = |sequence: u32, target: &str| {
        event(sequence, i64::from(sequence), action::USER_UPDATE, "user-1")
            .with_target(EntityRef::new(EntityKind::User, target))
    };
    let mut found = Vec::new();
    for (sequence, target) in [(1, "user-a"), (2, "user-a"), (3, "user-b"), (4, "user-a")] {
        found.push(
            engine
                .process(&change(sequence, target))
                .await
                .unwrap()
                .detections
                .len(),
        );
    }
    // The second and the fourth change have the same actor, address, and target.
    assert_eq!(found, [1, 0, 1, 0]);
    let summaries = engine.suppression_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].key,
        "ip_address:198.51.100.10, user:user-1, user:user-a"
    );
}

#[tokio::test]
async fn the_repeat_setting_gives_one_malicious_detection_at_its_count() {
    let rule = suppressed_rule(
        "contact",
        "low",
        "  window_seconds: 60\n  fields: [actor.id]\n  repeat:\n    count: 3\n    level: high\n",
    );
    let model = Arc::new(
        ScriptedModel::new("fake")
            .reply_json(&json!({ "verdict": "suspicious", "reasons": ["One contact."] })),
    );
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule]))
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    let mut outputs = Vec::new();
    for sequence in 1..=6 {
        outputs.push(
            engine
                .process(&event(
                    sequence,
                    i64::from(sequence),
                    action::USER_UPDATE,
                    "user-1",
                ))
                .await
                .unwrap(),
        );
    }
    // The first match is suspicious, and tier 2 examines it.
    assert_eq!(rule_ids(&outputs[0]), ["contact", "contact"]);
    assert_eq!(outputs[0].detections[0].verdict, Verdict::Suspicious);
    assert_eq!(outputs[1], EngineOutput::default());
    // The third match gives the repeat detection. It is malicious, so no model examines it.
    assert_eq!(rule_ids(&outputs[2]), ["contact:repeated"]);
    let repeated = &outputs[2].detections[0];
    assert_eq!(repeated.verdict, Verdict::Malicious);
    assert_eq!(repeated.severity, Severity::High);
    assert_eq!(repeated.attributes["matches"], json!(3));
    assert_eq!(
        repeated.attributes["first_detection"],
        json!(outputs[0].detections[0].id)
    );
    assert_eq!(repeated.event_ids.len(), 2);
    // The repeat detection is in the incident of the first detection.
    assert_eq!(outputs[2].incidents.len(), 1);
    assert_eq!(outputs[2].incidents[0].id, outputs[0].incidents[0].id);
    assert_eq!(outputs[2].incidents[0].severity, Severity::High);
    for output in &outputs[3..] {
        assert_eq!(*output, EngineOutput::default());
    }
    assert_eq!(model.requests().len(), 1);
    assert_eq!(
        engine.flood_counters(),
        FloodCounters {
            suppressed_matches: 5,
            repeat_detections: 1,
            ..FloodCounters::default()
        }
    );
}

#[tokio::test]
async fn an_indicator_with_a_suppression_time_gives_one_detection_for_one_actor() {
    let manifest = PackManifest {
        name: "indicator-pack".to_owned(),
        version: "1".to_owned(),
        description: "Two indicators.".to_owned(),
    };
    let mut quiet = Indicator::new(
        IndicatorKind::Ip,
        "198.51.100.0/24",
        "An example network.",
        Severity::High,
    );
    quiet.suppress_seconds = Some(60);
    let loud = Indicator::new(
        IndicatorKind::UserAgent,
        "loud-agent",
        "An example user agent.",
        Severity::High,
    );
    let pack = RulePack::new(manifest, Vec::new(), vec![quiet, loud]).unwrap();
    let engine = DetectionEngine::new(EngineConfig::default(), pack).unwrap();

    let mut counts = Vec::new();
    for sequence in 1..=5 {
        let output = engine
            .process(&event(
                sequence,
                i64::from(sequence),
                action::SIGN_IN,
                "user-1",
            ))
            .await
            .unwrap();
        counts.push(output.detections.len());
    }
    assert_eq!(counts, [1, 0, 0, 0, 0]);
    // A different actor from the same network is a different key.
    let other = engine
        .process(&event(6, 6, action::SIGN_IN, "user-2"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&other), ["ioc:ip:198.51.100.0/24"]);
    // After the window, the first actor gives a detection with the count before.
    let later = engine
        .process(&event(7, 61, action::SIGN_IN, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&later), ["ioc:ip:198.51.100.0/24"]);
    assert_eq!(
        later.detections[0].attributes[PREVIOUS_MATCHES_ATTRIBUTE],
        json!(5)
    );
    assert_eq!(engine.flood_counters().suppressed_matches, 4);

    // An indicator with no suppression time gives a detection for each event.
    let mut loud_counts = 0;
    for sequence in 10..15 {
        let mut noisy = event(
            sequence,
            100 + i64::from(sequence),
            action::SIGN_IN,
            "user-3",
        );
        noisy.actor.ip = None;
        noisy.actor.user_agent = Some("Loud-Agent/1.0".to_owned());
        loud_counts += engine.process(&noisy).await.unwrap().detections.len();
    }
    assert_eq!(loud_counts, 5);
}

/// An engine with one `suspicious` rule, a model that always answers `suspicious`, and
/// the given quota.
fn engine_with_quota(
    answers: usize,
    per_source: u32,
    per_tenant: u32,
) -> (Arc<ScriptedModel>, DetectionEngine) {
    let answer = json!({ "verdict": "suspicious", "reasons": ["Not sufficient."] });
    let mut model = ScriptedModel::new("fake");
    for _ in 0..answers {
        model = model.reply_json(&answer);
    }
    let model = Arc::new(model);
    let config = EngineConfig {
        triage: LlmTriageConfig {
            quota_window_seconds: 60,
            max_requests_per_source: per_source,
            max_requests_per_tenant: per_tenant,
            ..LlmTriageConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine = DetectionEngine::new(config, two_tier_pack())
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    (model, engine)
}

#[tokio::test]
async fn a_detection_over_the_source_quota_stays_suspicious_and_gets_no_model_request() {
    let (model, engine) = engine_with_quota(10, 3, 100);
    let mut outputs = Vec::new();
    for sequence in 1..=5 {
        let user = format!("user-{sequence}");
        outputs.push(
            engine
                .process(&event(
                    sequence,
                    i64::from(sequence),
                    action::USER_UPDATE,
                    &user,
                ))
                .await
                .unwrap(),
        );
    }
    for output in &outputs[..3] {
        assert_eq!(output.detections.len(), 2);
        assert_eq!(output.detections[1].tier, DetectionTier::Llm);
    }
    for output in &outputs[3..] {
        // One detection: tier 1, suspicious, with the quota record.
        assert_eq!(output.detections.len(), 1);
        let detection = &output.detections[0];
        assert_eq!(detection.tier, DetectionTier::Deterministic);
        assert_eq!(detection.verdict, Verdict::Suspicious);
        assert_eq!(
            detection.attributes[TRIAGE_ATTRIBUTE],
            json!({
                "status": "quota",
                "scope": "source",
                "limit": 3,
                "window_seconds": 60,
            })
        );
        // The detection is not lost: it is in the incident, as the tier 1 detection.
        assert_eq!(output.incidents.len(), 1);
        assert!(output.incidents[0].detections.contains(detection));
    }
    assert_eq!(outputs[4].incidents[0].detections.len(), 5);
    assert_eq!(model.requests().len(), 3);
    assert_eq!(engine.flood_counters().triage_quota_denials, 2);

    // A malicious detection needs no model, so the quota does not change it.
    let malicious = engine
        .process(&event(9, 9, action::USER_PASSWORD_RESET, "user-9"))
        .await
        .unwrap();
    assert_eq!(
        malicious.detections[0].attributes.get(TRIAGE_ATTRIBUTE),
        None
    );

    // A different source has its own quota.
    let mut other_source = event(10, 10, action::USER_UPDATE, "user-10");
    other_source.source.connector = "second".to_owned();
    let output = engine.process(&other_source).await.unwrap();
    assert_eq!(output.detections.len(), 2);
    assert_eq!(model.requests().len(), 4);

    // A new window in event time gives new requests.
    let later = engine
        .process(&event(11, 61, action::USER_UPDATE, "user-11"))
        .await
        .unwrap();
    assert_eq!(later.detections.len(), 2);
    assert_eq!(model.requests().len(), 5);
    assert_eq!(engine.flood_counters().triage_quota_denials, 2);
}

#[tokio::test]
async fn the_tenant_quota_counts_the_requests_of_all_sources_of_the_tenant() {
    let (model, engine) = engine_with_quota(10, 100, 2);
    let from = |sequence: u32, connector: &str, tenant: &str| {
        let user = format!("user-{sequence}");
        let mut event = event(sequence, i64::from(sequence), action::USER_UPDATE, &user);
        event.source.connector = connector.to_owned();
        event.source.tenant = Some(tenant.to_owned());
        event
    };
    let mut statuses = Vec::new();
    for (sequence, connector, tenant) in [
        (1, "a", TENANT),
        (2, "b", TENANT),
        (3, "c", TENANT),
        (4, "a", "tenant-2"),
    ] {
        let output = engine
            .process(&from(sequence, connector, tenant))
            .await
            .unwrap();
        statuses.push(
            output.detections[0]
                .attributes
                .get(TRIAGE_ATTRIBUTE)
                .map(|triage| (triage["status"].clone(), triage["scope"].clone())),
        );
    }
    assert_eq!(
        statuses,
        [None, None, Some((json!("quota"), json!("tenant"))), None,]
    );
    assert_eq!(model.requests().len(), 3);
    assert_eq!(engine.flood_counters().triage_quota_denials, 1);
}

#[tokio::test]
async fn an_engine_with_no_model_uses_no_quota() {
    let config = EngineConfig {
        triage: LlmTriageConfig {
            max_requests_per_source: 1,
            ..LlmTriageConfig::default()
        },
        ..EngineConfig::default()
    };
    let engine = DetectionEngine::new(config, two_tier_pack()).unwrap();
    for sequence in 1..=5 {
        let user = format!("user-{sequence}");
        let output = engine
            .process(&event(
                sequence,
                i64::from(sequence),
                action::USER_UPDATE,
                &user,
            ))
            .await
            .unwrap();
        assert_eq!(output.detections[0].attributes.get(TRIAGE_ATTRIBUTE), None);
    }
    assert_eq!(engine.flood_counters().triage_quota_denials, 0);
}

#[tokio::test]
async fn a_detection_of_a_decoy_event_keeps_the_data_of_the_client() {
    let rule = SigmaRule::parse(
        "title: Contact\nid: contact\nlevel: low\ndetection:\n  selection:\n    action: \
         decoy.contact\n  condition: selection\n",
        "inline",
    )
    .unwrap();
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule]))
        .unwrap()
        .with_detector(Arc::new(Fixed {
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
        }));
    let mut contact = event(1, 0, action::DECOY_CONTACT, "unknown")
        .with_attribute(attr::DECOY_ID, "maze-1")
        .with_attribute(attr::DECOY_KIND, "maze")
        .with_attribute(attr::CLIENT_FINGERPRINT, "FP-1");
    contact.actor.user_agent = Some(format!("scan\r\n/1.0 {}", "x".repeat(400)));
    let output = engine.process(&contact).await.unwrap();
    assert_eq!(rule_ids(&output), ["contact"]);
    let attributes = &output.detections[0].attributes;
    assert_eq!(attributes["decoy_id"], json!("maze-1"));
    assert_eq!(attributes["decoy_kind"], json!("maze"));
    assert_eq!(attributes["client_fingerprint"], json!("fp-1"));
    let user_agent = attributes["user_agent"].as_str().unwrap();
    assert!(user_agent.starts_with("scan/1.0 xxx"), "{user_agent}");
    assert_eq!(user_agent.chars().count(), 256);
    // The fingerprint is an entity of the detection.
    assert!(output.detections[0].entities.contains(&EntityRef::new(
        EntityKind::Other,
        "client_fingerprint:fp-1"
    )));

    // An event with no decoy identifier gets none of these attributes.
    let normal = engine
        .process(&event(2, 1, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&normal), ["added-rule"]);
    for key in ["decoy_id", "decoy_kind", "client_fingerprint", "user_agent"] {
        assert_eq!(normal.detections[0].attributes.get(key), None, "{key}");
    }

    // The detection of an added detector for a decoy event gets the attributes too.
    let mut added =
        event(3, 2, action::USER_UPDATE, "user-1").with_attribute(attr::DECOY_ID, "d-2");
    added.actor.user_agent = None;
    let output = engine.process(&added).await.unwrap();
    assert_eq!(rule_ids(&output), ["added-rule"]);
    assert_eq!(output.detections[0].attributes["decoy_id"], json!("d-2"));
    assert_eq!(output.detections[0].attributes.get("user_agent"), None);
}

#[tokio::test]
async fn the_cadence_and_the_probe_detectors_run_after_the_older_detectors() {
    let config = EngineConfig {
        velocity: VelocityConfig {
            endpoint_probe: crate::velocity::EndpointProbeConfig {
                decoy_paths: vec!["/.env".to_owned()],
                ..crate::velocity::EndpointProbeConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let rules = vec![rule("secret-rule", "high", action::SECRET_READ)];
    let engine = DetectionEngine::new(config, pack(rules))
        .unwrap()
        .with_detector(Arc::new(Fixed {
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
        }));
    let step = |sequence: u32, action: &str| event(sequence, i64::from(sequence), action, "user-1");
    for (sequence, action) in [
        (1, action::USER_CREATE),
        (2, action::MFA_METHOD_CHANGE),
        (3, action::USER_PASSWORD_RESET),
    ] {
        assert!(
            engine
                .process(&step(sequence, action))
                .await
                .unwrap()
                .is_empty()
        );
    }
    let output = engine.process(&step(4, action::SECRET_READ)).await.unwrap();
    assert_eq!(
        rule_ids(&output),
        ["secret-rule", crate::velocity::MACHINE_CADENCE_RULE_ID]
    );

    let request = step(5, action::HTTP_REQUEST).with_attribute(attr::HTTP_PATH, "/.env");
    let output = engine.process(&request).await.unwrap();
    assert_eq!(rule_ids(&output), [crate::velocity::DECOY_PATH_RULE_ID]);
    // A decoy path of an endpoint is not a decoy service: the event has no decoy id.
    assert_eq!(output.detections[0].attributes.get("decoy_id"), None);
    assert_eq!(
        output.detections[0].attributes["decoy_path"],
        json!("/.env")
    );
}

#[test]
fn settings_of_the_new_detectors_and_of_the_quota_that_are_not_valid_are_errors() {
    let cadence = EngineConfig {
        velocity: VelocityConfig {
            machine_cadence: crate::velocity::MachineCadenceConfig {
                min_actions: 0,
                ..crate::velocity::MachineCadenceConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let probe = EngineConfig {
        velocity: VelocityConfig {
            endpoint_probe: crate::velocity::EndpointProbeConfig {
                distinct_path_threshold: 0,
                ..crate::velocity::EndpointProbeConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let quota = |change: fn(&mut LlmTriageConfig)| {
        let mut triage = LlmTriageConfig::default();
        change(&mut triage);
        EngineConfig {
            triage,
            ..EngineConfig::default()
        }
    };
    for (config, expected) in [
        (
            cadence,
            "machine_cadence.min_actions must be 2 or more, but it is 0".to_owned(),
        ),
        (
            probe,
            "endpoint_probe.distinct_path_threshold must be 2 or more, but it is 0".to_owned(),
        ),
        (
            quota(|triage| triage.quota_window_seconds = 0),
            "llm_triage.quota_window_seconds must be 1 or more, but it is 0".to_owned(),
        ),
        (
            quota(|triage| triage.max_requests_per_source = 0),
            "llm_triage.max_requests_per_source must be 1 or more, but it is 0".to_owned(),
        ),
        (
            quota(|triage| triage.max_requests_per_tenant = 0),
            "llm_triage.max_requests_per_tenant must be 1 or more, but it is 0".to_owned(),
        ),
        (
            quota(|triage| triage.quota_window_seconds = u64::MAX),
            format!("llm_triage.quota_window_seconds is too large: {}", u64::MAX),
        ),
    ] {
        let error = DetectionEngine::new(config, RulePack::empty())
            .err()
            .unwrap();
        assert!(
            matches!(&error, DetectError::Config(message) if *message == expected),
            "{error}"
        );
    }
}

#[tokio::test]
async fn a_reload_keeps_the_suppression_windows() {
    let rule = || {
        suppressed_rule(
            "quiet",
            "high",
            "  window_seconds: 60\n  fields: [actor.id]\n",
        )
    };
    let engine = DetectionEngine::new(EngineConfig::default(), pack(vec![rule()])).unwrap();
    let first = engine
        .process(&event(1, 0, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert_eq!(rule_ids(&first), ["quiet"]);
    engine.reload(pack(vec![rule()]));
    let second = engine
        .process(&event(2, 1, action::USER_UPDATE, "user-1"))
        .await
        .unwrap();
    assert!(second.is_empty());
    assert_eq!(engine.flood_counters().suppressed_matches, 1);
}
