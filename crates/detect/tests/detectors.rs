//! Tests of each `Detector` implementation through the contract, with the recorded attack
//! log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{Event, action};
use aegis_contracts::{Detection, DetectionTier, Detector, Verdict};
use aegis_detect::ioc::{Indicator, IndicatorKind, IocStore};
use aegis_detect::sigma::{SigmaDetector, SigmaRule};
use aegis_detect::velocity::{
    CredentialAfterGrant, CredentialAfterGrantConfig, ImpossibleSpeed, ImpossibleSpeedConfig,
    PrivilegedSelfAssignment, PrivilegedSelfAssignmentConfig, SignInBurst, SignInBurstConfig,
};
use aegis_testkit::fixtures::{self, expected};
use chrono::TimeDelta;

/// Sends the attack log to one detector and returns all its detections.
async fn replay(detector: Arc<dyn Detector>) -> Vec<Detection> {
    let events = fixtures::artex_style_attack();
    assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
    let mut detections = Vec::new();
    for event in &events {
        detections.extend(detector.inspect(event).await.unwrap());
    }
    detections
}

fn events_with_action(name: &str) -> Vec<Event> {
    fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| event.action == name)
        .collect()
}

fn technique_ids(detection: &Detection) -> Vec<&str> {
    detection
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect()
}

fn at(milliseconds: i64) -> chrono::DateTime<chrono::Utc> {
    fixtures::base_time() + TimeDelta::milliseconds(milliseconds)
}

#[tokio::test]
async fn the_sigma_detector_finds_the_events_that_its_rules_describe() {
    let rule = SigmaRule::parse(
        "title: Script client signed in\nid: script-sign-in\nlevel: high\ntags:\n  - \
         attack.initial-access\n  - attack.t1078.004\ndetection:\n  selection:\n    action: \
         sign_in\n    outcome: success\n    actor.user_agent|startswith: python-\n  filter:\n    \
         actor.kind: service_principal\n  condition: selection and not filter\n",
        "inline",
    )
    .unwrap();
    let detector: Arc<dyn Detector> = Arc::new(SigmaDetector::new(vec![rule]));
    assert_eq!(detector.id(), "aegis.sigma");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    // Only the sign-in of the victim matches: the spray failed, and the rogue principal is
    // a service principal.
    let detections = replay(detector).await;
    assert_eq!(detections.len(), 1);
    let found = &detections[0];
    assert_eq!(found.rule_id, "script-sign-in");
    assert_eq!(found.time, at(631_000));
    assert_eq!(found.verdict, Verdict::Malicious);
    assert_eq!(technique_ids(found), ["T1078.004"]);
    assert_eq!(found.entities[0].id, fixtures::VICTIM_USER_ID);
    assert_eq!(found.tenant.as_deref(), Some(fixtures::TENANT));
}

#[tokio::test]
async fn the_indicator_store_finds_the_events_from_an_indicator_address() {
    let indicator = Indicator {
        kind: IndicatorKind::Ip,
        value: fixtures::DISTANT_IP.to_string(),
        description: "The second address of the rogue principal.".to_owned(),
        severity: Severity::High,
        tags: vec!["attack.t1078.004".to_owned()],
        verdict: None,
        id: Some("test-indicator".to_owned()),
    };
    let detector: Arc<dyn Detector> = Arc::new(IocStore::new(vec![indicator]).unwrap());
    assert_eq!(detector.id(), "aegis.ioc");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    // Three of the six API calls of the rogue principal come from the address.
    let detections = replay(detector).await;
    assert_eq!(detections.len(), 3);
    for found in &detections {
        assert_eq!(found.rule_id, "test-indicator");
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.event_ids.len(), 1);
        assert!(found.entities.contains(&EntityRef::new(
            EntityKind::IpAddress,
            fixtures::DISTANT_IP.to_string()
        )));
    }
    let times: Vec<_> = detections.iter().map(|found| found.time).collect();
    assert_eq!(times, [at(652_000), at(656_000), at(660_000)]);
}

#[tokio::test]
async fn the_sign_in_burst_detector_finds_the_spray_and_the_foothold() {
    let detector: Arc<dyn Detector> =
        Arc::new(SignInBurst::new(SignInBurstConfig::default()).unwrap());
    assert_eq!(detector.id(), "aegis.velocity.sign_in_burst");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    let detections = replay(detector).await;
    assert_eq!(detections.len(), 2);
    let (burst, foothold) = (&detections[0], &detections[1]);
    assert_eq!(burst.rule_id, "aegis.velocity.sign_in_burst");
    assert_eq!(technique_ids(burst), [expected::PASSWORD_SPRAY]);
    assert_eq!(burst.time, at(600_450));
    assert_eq!(
        burst.entities,
        [EntityRef::new(
            EntityKind::IpAddress,
            fixtures::SPRAY_IP.to_string()
        )]
    );
    assert_eq!(foothold.rule_id, "aegis.velocity.sign_in_after_burst");
    assert_eq!(foothold.time, at(631_000));
    assert_eq!(foothold.entities[0].id, fixtures::VICTIM_USER_ID);
}

#[tokio::test]
async fn a_larger_threshold_moves_the_burst_detection_to_a_later_event() {
    let config = SignInBurstConfig {
        distinct_user_threshold: 100,
        failure_threshold: 1_000,
        ..SignInBurstConfig::default()
    };
    let detector: Arc<dyn Detector> = Arc::new(SignInBurst::new(config).unwrap());
    let detections = replay(detector).await;
    assert_eq!(detections.len(), 2);
    // The spray sends one attempt each 50 milliseconds. The 100th user is attempt 100.
    assert_eq!(detections[0].time, at(600_000 + 99 * 50));
    assert_eq!(detections[0].event_ids.len(), 100);

    // A threshold that the spray does not reach gives no detection.
    let config = SignInBurstConfig {
        distinct_user_threshold: 151,
        failure_threshold: 601,
        ..SignInBurstConfig::default()
    };
    let detector: Arc<dyn Detector> = Arc::new(SignInBurst::new(config).unwrap());
    assert_eq!(replay(detector).await, []);
}

#[tokio::test]
async fn the_self_assignment_detector_finds_the_role_that_the_principal_gave_itself() {
    let detector: Arc<dyn Detector> = Arc::new(PrivilegedSelfAssignment::new(
        PrivilegedSelfAssignmentConfig::default(),
    ));
    assert_eq!(detector.id(), "aegis.velocity.privileged_self_assignment");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    let detections = replay(detector).await;
    assert_eq!(detections.len(), 1);
    let found = &detections[0];
    assert_eq!(technique_ids(found), [expected::ROLE_ASSIGN]);
    assert_eq!(found.time, at(646_000));
    let assignments = events_with_action(action::ROLE_ASSIGN);
    assert_eq!(assignments.len(), 1);
    assert_eq!(found.event_ids, [assignments[0].id]);
    assert_eq!(found.entities[0].id, fixtures::ROGUE_PRINCIPAL_ID);
    assert_eq!(found.entities[0].kind, EntityKind::ServicePrincipal);
}

#[tokio::test]
async fn the_credential_detector_finds_the_credential_three_seconds_after_the_grant() {
    let detector: Arc<dyn Detector> =
        Arc::new(CredentialAfterGrant::new(CredentialAfterGrantConfig::default()).unwrap());
    assert_eq!(detector.id(), "aegis.velocity.credential_after_grant");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    let detections = replay(detector).await;
    assert_eq!(detections.len(), 1);
    let found = &detections[0];
    assert_eq!(technique_ids(found), [expected::CREDENTIAL_ADD]);
    assert_eq!(found.time, at(640_000));
    let grants = events_with_action(action::OAUTH_CONSENT_GRANT);
    let credentials = events_with_action(action::APP_CREDENTIAL_ADD);
    assert_eq!((grants.len(), credentials.len()), (1, 1));
    assert_eq!(found.event_ids, [grants[0].id, credentials[0].id]);
    assert_eq!(
        found.attributes["milliseconds_after_grant"],
        serde_json::json!(3_000)
    );

    // With a window of two seconds, three seconds is too late.
    let config = CredentialAfterGrantConfig {
        window_seconds: 2,
        ..CredentialAfterGrantConfig::default()
    };
    let narrow: Arc<dyn Detector> = Arc::new(CredentialAfterGrant::new(config).unwrap());
    assert_eq!(replay(narrow).await, []);
}

#[tokio::test]
async fn the_speed_detector_finds_the_principal_in_two_tenants_on_two_continents() {
    let detector: Arc<dyn Detector> =
        Arc::new(ImpossibleSpeed::new(ImpossibleSpeedConfig::default()).unwrap());
    assert_eq!(detector.id(), "aegis.velocity.impossible_speed");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    // The six calls alternate between two places. The cooldown keeps this to one detection.
    let detections = replay(detector).await;
    assert_eq!(detections.len(), 1);
    let found = &detections[0];
    assert_eq!(technique_ids(found), [expected::CLOUD_ACCOUNT]);
    assert_eq!(found.verdict, Verdict::Malicious);
    assert_eq!(found.time, at(652_000));
    let calls: Vec<Event> = events_with_action(action::API_CALL)
        .into_iter()
        .filter(|event| event.actor.id == fixtures::ROGUE_PRINCIPAL_ID)
        .collect();
    assert_eq!(calls.len(), 6);
    assert_eq!(found.event_ids, [calls[0].id, calls[1].id]);
    assert_eq!(found.attributes["cross_tenant"], serde_json::json!(true));
    assert_eq!(
        found.attributes["to_resource_tenant"],
        serde_json::json!(fixtures::OTHER_TENANT)
    );
    // The one detection is for the rogue principal. The users that the spray tried from a
    // different country give none, because a failed sign-in is not activity of the user.
    assert_eq!(found.entities[0].id, fixtures::ROGUE_PRINCIPAL_ID);
}

#[tokio::test]
async fn a_speed_detector_with_no_cooldown_finds_each_change_of_place() {
    let config = ImpossibleSpeedConfig {
        cooldown_seconds: 0,
        ..ImpossibleSpeedConfig::default()
    };
    let detector: Arc<dyn Detector> = Arc::new(ImpossibleSpeed::new(config).unwrap());
    let detections = replay(detector).await;
    // Five changes of place between the six calls, and one more to the honeytoken read.
    assert_eq!(detections.len(), 6);
    assert!(
        detections
            .iter()
            .all(|found| found.entities[0].id == fixtures::ROGUE_PRINCIPAL_ID)
    );
}
