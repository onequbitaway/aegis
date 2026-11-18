//! The acceptance tests of the machine-cadence detector, with the recorded attack log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use aegis_contracts::common::{EntityKind, EventId};
use aegis_contracts::event::{Event, action};
use aegis_contracts::{Detection, DetectionTier, Detector, Verdict};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::pack::RulePack;
use aegis_detect::velocity::{
    MACHINE_CADENCE_RULE_ID, MachineCadence, MachineCadenceConfig, VelocityConfig,
};
use aegis_testkit::fixtures;
use chrono::TimeDelta;

fn detector() -> Arc<dyn Detector> {
    Arc::new(MachineCadence::new(MachineCadenceConfig::default()).unwrap())
}

async fn inspect_all(detector: &dyn Detector, events: &[Event]) -> Vec<Detection> {
    let mut detections = Vec::new();
    for event in events {
        detections.extend(detector.inspect(event).await.unwrap());
    }
    detections
}

fn is_normal(event: &Event) -> bool {
    let attack_addresses = [
        Some(fixtures::SPRAY_IP),
        Some(fixtures::WORKLOAD_IP),
        Some(fixtures::DISTANT_IP),
    ];
    !attack_addresses.contains(&event.actor.ip)
}

fn rogue_events() -> Vec<Event> {
    fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| event.actor.id == fixtures::ROGUE_PRINCIPAL_ID)
        .collect()
}

#[tokio::test]
async fn the_recorded_attack_log_gives_one_chain_and_it_is_the_chain_of_the_rogue_principal() {
    let events = fixtures::artex_style_attack();
    assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
    let detector = detector();
    assert_eq!(detector.id(), "aegis.velocity.machine_cadence");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);

    let detections = inspect_all(detector.as_ref(), &events).await;
    assert_eq!(detections.len(), 1);
    let chain = &detections[0];
    assert_eq!(chain.rule_id, MACHINE_CADENCE_RULE_ID);
    assert_eq!(chain.entities[0].kind, EntityKind::ServicePrincipal);
    assert_eq!(chain.entities[0].id, fixtures::ROGUE_PRINCIPAL_ID);
    assert_eq!(chain.tenant.as_deref(), Some(fixtures::TENANT));
    // The role assignment of the rogue principal is privileged.
    assert_eq!(chain.verdict, Verdict::Malicious);

    // Each event of the chain is an event of the rogue principal.
    let rogue: Vec<EventId> = rogue_events().iter().map(|event| event.id).collect();
    assert_eq!(rogue.len(), 9);
    assert_eq!(chain.event_ids.len(), 4);
    assert_eq!(chain.event_ids, rogue[..4]);
}

#[tokio::test]
async fn the_normal_events_of_the_attack_log_give_no_chain() {
    let normal: Vec<Event> = fixtures::artex_style_attack()
        .into_iter()
        .filter(is_normal)
        .collect();
    assert_eq!(normal.len(), 36);
    assert_eq!(inspect_all(detector().as_ref(), &normal).await, []);

    // In the full log, no chain names a normal event or a normal principal.
    let events = fixtures::artex_style_attack();
    let detections = inspect_all(detector().as_ref(), &events).await;
    assert_eq!(detections.len(), 1);
    let normal_ids: Vec<EventId> = normal.iter().map(|event| event.id).collect();
    assert!(
        detections[0]
            .event_ids
            .iter()
            .all(|id| !normal_ids.contains(id))
    );
}

#[tokio::test]
async fn the_actions_of_the_rogue_principal_at_the_speed_of_a_person_give_no_chain() {
    // The same nine events, with the gaps of a person: from 25 seconds to 3 minutes, and
    // not regular.
    let gaps_seconds = [0, 50, 95, 25, 180, 40, 130, 70, 110];
    let mut events = rogue_events();
    assert_eq!(events.len(), gaps_seconds.len());
    let mut time = events[0].time;
    for (event, gap) in events.iter_mut().zip(gaps_seconds) {
        time += TimeDelta::seconds(gap);
        event.time = time;
    }
    assert_eq!(inspect_all(detector().as_ref(), &events).await, []);

    // The recorded times of the same events give the chain.
    let recorded = inspect_all(detector().as_ref(), &rogue_events()).await;
    assert_eq!(recorded.len(), 1);
}

#[tokio::test]
async fn a_person_who_works_in_the_portal_gives_no_chain() {
    // An administrator signs in and makes four different changes in six minutes.
    let start = fixtures::base_time();
    let steps = [
        (0, action::SIGN_IN),
        (45, action::USER_CREATE),
        (110, action::ROLE_ASSIGN),
        (170, action::USER_PASSWORD_RESET),
        (290, action::MFA_METHOD_CHANGE),
        (360, action::SIGN_OUT),
    ];
    let events: Vec<Event> = steps
        .iter()
        .map(|(seconds, name)| {
            let mut event = fixtures::sign_in(
                start + TimeDelta::seconds(*seconds),
                "user-admin",
                fixtures::OFFICE_IP,
                true,
            );
            event.action = (*name).to_owned();
            event
                .attributes
                .insert("privileged".to_owned(), true.into());
            event
        })
        .collect();
    assert_eq!(inspect_all(detector().as_ref(), &events).await, []);
}

#[tokio::test]
async fn the_engine_setting_stops_the_detector() {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity");
    let replay = async |config: EngineConfig| -> Vec<String> {
        let engine = DetectionEngine::new(config, RulePack::load(&directory).unwrap()).unwrap();
        let mut rule_ids = Vec::new();
        for event in fixtures::artex_style_attack() {
            let output = engine.process(&event).await.unwrap();
            rule_ids.extend(output.detections.into_iter().map(|found| found.rule_id));
        }
        rule_ids
    };
    let with_detector = replay(EngineConfig::default()).await;
    assert_eq!(with_detector.len(), 9);
    assert_eq!(
        with_detector
            .iter()
            .filter(|rule_id| *rule_id == MACHINE_CADENCE_RULE_ID)
            .count(),
        1
    );

    let config = EngineConfig {
        velocity: VelocityConfig {
            machine_cadence: MachineCadenceConfig {
                enabled: false,
                ..MachineCadenceConfig::default()
            },
            ..VelocityConfig::default()
        },
        ..EngineConfig::default()
    };
    let without_detector = replay(config).await;
    assert_eq!(without_detector.len(), 8);
    assert!(
        !without_detector
            .iter()
            .any(|rule_id| rule_id == MACHINE_CADENCE_RULE_ID)
    );
}
