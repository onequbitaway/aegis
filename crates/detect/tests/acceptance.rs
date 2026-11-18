//! The acceptance test of the detection engine: a replay of the recorded attack log
//! through the engine with the shipped rule pack.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_contracts::common::{EntityKind, EventId, Severity};
use aegis_contracts::event::{Event, Outcome, action};
use aegis_contracts::{Detection, DetectionTier, Incident, IncidentStatus, Verdict};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::pack::RulePack;
use aegis_detect::velocity::{
    CREDENTIAL_AFTER_GRANT_RULE_ID, IMPOSSIBLE_SPEED_RULE_ID, MACHINE_CADENCE_RULE_ID,
    PRIVILEGED_SELF_ASSIGNMENT_RULE_ID, SIGN_IN_AFTER_BURST_RULE_ID, SIGN_IN_BURST_RULE_ID,
};
use aegis_testkit::ScriptedModel;
use aegis_testkit::fixtures::{self, expected};

const CONSENT_RULE_ID: &str = "5b0f3c2e-8a41-4d6f-9c57-2e1a7b90d314";
const HONEYTOKEN_RULE_ID: &str = "0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940";
const WORKLOAD_ROLE_RULE_ID: &str = "a4d7e1b9-6c35-4f02-8e7a-1b9c0d5f2a63";

fn shipped_pack() -> RulePack {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity");
    RulePack::load(directory).unwrap()
}

/// The result of a replay of the attack log.
struct Replay {
    events: Vec<Event>,
    /// The detections of each event, in the order of the events.
    by_event: Vec<Vec<Detection>>,
    /// Each incident state that the engine returned, in order.
    incident_states: Vec<Incident>,
    /// The incidents that the engine keeps at the end.
    incidents: Vec<Incident>,
    model: Arc<ScriptedModel>,
}

impl Replay {
    fn detections(&self) -> Vec<&Detection> {
        self.by_event.iter().flatten().collect()
    }

    fn with_rule(&self, rule_id: &str) -> Vec<&Detection> {
        self.detections()
            .into_iter()
            .filter(|detection| detection.rule_id == rule_id)
            .collect()
    }
}

async fn replay() -> Replay {
    // The model has an empty script. A request to it fails, and the test sees the request.
    let model = Arc::new(ScriptedModel::new("unused"));
    let engine = DetectionEngine::new(EngineConfig::default(), shipped_pack())
        .unwrap()
        .with_triage(model.clone())
        .unwrap();
    let events = fixtures::artex_style_attack();
    let mut by_event = Vec::with_capacity(events.len());
    let mut incident_states = Vec::new();
    for event in &events {
        let output = engine.process(event).await.unwrap();
        by_event.push(output.detections);
        incident_states.extend(output.incidents);
    }
    Replay {
        events,
        by_event,
        incident_states,
        incidents: engine.incidents(),
        model,
    }
}

fn is_normal(event: &Event) -> bool {
    let attack_addresses = [
        Some(fixtures::SPRAY_IP),
        Some(fixtures::WORKLOAD_IP),
        Some(fixtures::DISTANT_IP),
    ];
    !attack_addresses.contains(&event.actor.ip)
}

#[tokio::test]
async fn the_five_expected_techniques_are_detected() {
    let replay = replay().await;
    assert_eq!(replay.events.len(), fixtures::ATTACK_LOG_EVENTS);
    let found: BTreeSet<&str> = replay
        .detections()
        .into_iter()
        .flat_map(|detection| detection.attack.iter())
        .map(|technique| technique.technique_id.as_str())
        .collect();
    for technique_id in [
        expected::PASSWORD_SPRAY,
        expected::CONSENT_GRANT,
        expected::CREDENTIAL_ADD,
        expected::ROLE_ASSIGN,
        expected::CLOUD_ACCOUNT,
    ] {
        assert!(
            found.contains(technique_id),
            "{technique_id} is not in {found:?}"
        );
    }

    // Each technique comes from the detector that the design gives it to.
    let technique_of = |rule_id: &str| -> Vec<String> {
        let detections = replay.with_rule(rule_id);
        assert_eq!(detections.len(), 1, "{rule_id}");
        detections[0]
            .attack
            .iter()
            .map(|technique| technique.technique_id.clone())
            .collect()
    };
    assert_eq!(
        technique_of(SIGN_IN_BURST_RULE_ID),
        [expected::PASSWORD_SPRAY]
    );
    assert_eq!(technique_of(CONSENT_RULE_ID), [expected::CONSENT_GRANT]);
    assert_eq!(
        technique_of(CREDENTIAL_AFTER_GRANT_RULE_ID),
        [expected::CREDENTIAL_ADD]
    );
    assert_eq!(
        technique_of(PRIVILEGED_SELF_ASSIGNMENT_RULE_ID),
        [expected::ROLE_ASSIGN]
    );
    assert_eq!(technique_of(WORKLOAD_ROLE_RULE_ID), [expected::ROLE_ASSIGN]);
    assert_eq!(
        technique_of(IMPOSSIBLE_SPEED_RULE_ID),
        [expected::CLOUD_ACCOUNT]
    );
}

#[tokio::test]
async fn the_replay_gives_these_detections_in_this_order() {
    let replay = replay().await;
    let rule_ids: Vec<&str> = replay
        .detections()
        .into_iter()
        .map(|detection| detection.rule_id.as_str())
        .collect();
    assert_eq!(
        rule_ids,
        [
            SIGN_IN_BURST_RULE_ID,
            SIGN_IN_AFTER_BURST_RULE_ID,
            CONSENT_RULE_ID,
            CREDENTIAL_AFTER_GRANT_RULE_ID,
            WORKLOAD_ROLE_RULE_ID,
            PRIVILEGED_SELF_ASSIGNMENT_RULE_ID,
            IMPOSSIBLE_SPEED_RULE_ID,
            // The machine-cadence detector completes its chain with the same event as the
            // impossible speed detector: the second API call of the rogue principal.
            MACHINE_CADENCE_RULE_ID,
            HONEYTOKEN_RULE_ID,
        ]
    );
    for detection in replay.detections() {
        assert_eq!(
            detection.tier,
            DetectionTier::Deterministic,
            "{}",
            detection.rule_id
        );
        assert_eq!(
            detection.verdict,
            Verdict::Malicious,
            "{}",
            detection.rule_id
        );
        assert_eq!(detection.tenant.as_deref(), Some(fixtures::TENANT));
        // Tier 2 did not start for the detection.
        assert_eq!(
            detection.attributes.get("triage"),
            None,
            "{}",
            detection.rule_id
        );
    }
}

#[tokio::test]
async fn the_honeytoken_event_is_detected() {
    let replay = replay().await;
    let trips: Vec<&Event> = replay
        .events
        .iter()
        .filter(|event| event.action == action::HONEYTOKEN_TRIP)
        .collect();
    assert_eq!(trips.len(), 1);
    let detections = replay.with_rule(HONEYTOKEN_RULE_ID);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].event_ids, [trips[0].id]);
    assert_eq!(detections[0].severity, Severity::Critical);
    assert_eq!(detections[0].title, "Honeytoken used");
    assert!(
        detections[0]
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::ServicePrincipal
                && entity.id == fixtures::ROGUE_PRINCIPAL_ID)
    );
}

#[tokio::test]
async fn the_detections_fold_into_one_critical_incident_with_the_attack_entities() {
    let replay = replay().await;
    assert_eq!(replay.incidents.len(), 1);
    let incident = &replay.incidents[0];
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.status, IncidentStatus::Open);
    assert_eq!(incident.tenant.as_deref(), Some(fixtures::TENANT));
    // Eight detections of the rules and the older detectors, and one machine-cadence
    // detection.
    assert_eq!(incident.detections.len(), 9);
    // The incident holds each detection of the replay, in order of time and identifier.
    let mut all: Vec<Detection> = replay.detections().into_iter().cloned().collect();
    all.sort_by_key(|detection| (detection.time, detection.id));
    assert_eq!(incident.detections, all);

    let has = |kind: EntityKind, id: &str| {
        incident
            .entities
            .iter()
            .any(|entity| entity.kind == kind && entity.id == id)
    };
    assert!(has(EntityKind::IpAddress, &fixtures::SPRAY_IP.to_string()));
    assert!(has(EntityKind::User, fixtures::VICTIM_USER_ID));
    assert!(has(
        EntityKind::ServicePrincipal,
        fixtures::ROGUE_PRINCIPAL_ID
    ));
    assert!(has(EntityKind::Application, fixtures::ROGUE_APP_ID));
    // No user that the spray only tried is an entity of the incident.
    let users: Vec<&str> = incident
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::User)
        .map(|entity| entity.id.as_str())
        .collect();
    assert_eq!(users, [fixtures::VICTIM_USER_ID]);

    let technique_ids: Vec<&str> = incident
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    assert_eq!(
        technique_ids,
        [
            "T1110.003",
            "T1078",
            "T1528",
            "T1098.001",
            "T1098.003",
            "T1078.004",
            "T1059.009",
            "T1552"
        ]
    );
    assert_eq!(incident.timeline.len(), 9);
    assert!(incident.timeline.is_sorted_by_key(|entry| entry.time));

    // Each state that the engine returned is a state of this one incident. Seven events
    // gave detections, and the engine returns one state for each of them. The
    // machine-cadence detection comes from an event that had a detection before, so the
    // number of states did not change.
    assert_eq!(replay.incident_states.len(), 7);
    assert!(
        replay
            .incident_states
            .iter()
            .all(|state| state.id == incident.id)
    );
    assert_eq!(replay.incident_states.last(), Some(incident));
    // The incident becomes critical with its third technique.
    let severities: Vec<Severity> = replay
        .incident_states
        .iter()
        .map(|state| state.severity)
        .collect();
    assert_eq!(severities[..2], [Severity::High, Severity::High]);
    assert!(
        severities[2..]
            .iter()
            .all(|severity| *severity == Severity::Critical)
    );
}

#[tokio::test]
async fn the_normal_events_give_no_detection() {
    let replay = replay().await;
    let normal: Vec<usize> = replay
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| is_normal(event))
        .map(|(position, _)| position)
        .collect();
    assert_eq!(normal.len(), 36);
    for position in &normal {
        assert_eq!(
            replay.by_event[*position],
            [],
            "event {}",
            replay.events[*position].id
        );
    }
    // No detection names a normal event as its cause.
    let normal_ids: BTreeSet<EventId> = normal
        .iter()
        .map(|position| replay.events[*position].id)
        .collect();
    let detections = replay.detections();
    assert_eq!(detections.len(), 9);
    for detection in detections {
        assert!(
            detection
                .event_ids
                .iter()
                .all(|event_id| !normal_ids.contains(event_id)),
            "{}",
            detection.rule_id
        );
    }
}

#[tokio::test]
async fn the_machine_cadence_detector_finds_the_chain_of_the_rogue_principal() {
    let replay = replay().await;
    let detections = replay.with_rule(MACHINE_CADENCE_RULE_ID);
    assert_eq!(detections.len(), 1);
    let chain = detections[0];
    // The chain has a privileged role assignment, so no model examines it.
    assert_eq!(chain.verdict, Verdict::Malicious);
    assert_eq!(chain.severity, Severity::High);
    assert_eq!(chain.tier, DetectionTier::Deterministic);
    let technique_ids: Vec<&str> = chain
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect();
    assert_eq!(technique_ids, ["T1059.009"]);

    // The chain is the first four different actions of the rogue principal: the sign-in,
    // the role assignment, and two API operations. They are 3, 4, and 2 seconds apart.
    let rogue: Vec<&Event> = replay
        .events
        .iter()
        .filter(|event| event.actor.id == fixtures::ROGUE_PRINCIPAL_ID)
        .collect();
    assert_eq!(rogue.len(), 9);
    let actions: Vec<&str> = rogue[..4]
        .iter()
        .map(|event| event.action.as_str())
        .collect();
    assert_eq!(
        actions,
        [
            action::SIGN_IN,
            action::ROLE_ASSIGN,
            action::API_CALL,
            action::API_CALL
        ]
    );
    let first_four: Vec<EventId> = rogue[..4].iter().map(|event| event.id).collect();
    assert_eq!(chain.event_ids, first_four);
    assert_eq!(chain.time, rogue[3].time);
    assert_eq!(chain.attributes["subject"], serde_json::json!("principal"));
    assert_eq!(chain.attributes["cadence"], serde_json::json!("short_gaps"));
    assert_eq!(chain.attributes["distinct_actions"], serde_json::json!(4));
    assert_eq!(
        chain.attributes["median_gap_milliseconds"],
        serde_json::json!(3_000)
    );
    assert_eq!(
        chain.attributes["privileged_change"],
        serde_json::json!(true)
    );
    assert_eq!(
        chain.attributes["actions"],
        serde_json::json!([
            "sign_in",
            "role.assign",
            "api.call GET /users",
            "api.call GET /servicePrincipals"
        ])
    );
    let entities: Vec<(EntityKind, String)> = chain
        .entities
        .iter()
        .map(|entity| (entity.kind, entity.id.clone()))
        .collect();
    assert_eq!(
        entities,
        [
            (
                EntityKind::ServicePrincipal,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (EntityKind::IpAddress, fixtures::WORKLOAD_IP.to_string()),
            (EntityKind::IpAddress, fixtures::DISTANT_IP.to_string()),
        ]
    );
}

#[tokio::test]
async fn the_sign_in_burst_gives_one_detection_and_not_six_hundred() {
    let replay = replay().await;
    let spray: Vec<usize> = replay
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.action == action::SIGN_IN && event.outcome == Outcome::Failure)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(spray.len(), fixtures::SPRAY_ATTEMPTS);
    let from_spray: Vec<&Detection> = spray
        .iter()
        .flat_map(|position| replay.by_event[*position].iter())
        .collect();
    assert_eq!(from_spray.len(), 1);
    let burst = from_spray[0];
    assert_eq!(burst.rule_id, SIGN_IN_BURST_RULE_ID);
    assert_eq!(replay.with_rule(SIGN_IN_BURST_RULE_ID).len(), 1);
    assert_eq!(burst.severity, Severity::High);
    assert_eq!(burst.attributes["password_spray"], serde_json::json!(true));
    assert_eq!(
        burst.attributes["address"],
        serde_json::json!(fixtures::SPRAY_IP.to_string())
    );
    // The tenth user crosses the default threshold. The detection names those ten events.
    assert_eq!(burst.attributes["distinct_users"], serde_json::json!(10));
    let first_ten: Vec<EventId> = spray[..10]
        .iter()
        .map(|position| replay.events[*position].id)
        .collect();
    assert_eq!(burst.event_ids, first_ten);
    assert_eq!(burst.time, replay.events[spray[9]].time);
}

#[tokio::test]
async fn the_replay_sends_no_request_to_the_model() {
    let replay = replay().await;
    assert_eq!(replay.detections().len(), 9);
    assert_eq!(replay.model.requests().len(), 0);
}

#[tokio::test]
async fn two_replays_give_the_same_detections_and_the_same_incident() {
    let first = replay().await;
    let second = replay().await;
    assert_eq!(first.by_event, second.by_event);
    assert_eq!(first.incident_states, second.incident_states);
    assert_eq!(first.incidents, second.incidents);
}
