//! The bridges between the detection engine, the incident store, the agents, the audit
//! log, and the honeytoken registry.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::HashSet;

use aegis_agents::ledger::tracked_actions;
use aegis_app::actions::DispatchResult;
use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionResult, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::bus::{BusStream, subject};
use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, Outcome, action, attr};
use aegis_contracts::graph::{Direction, NodeId, relation};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_respond::deception::HONEYTOKEN_DETECTOR_ID;
use aegis_testkit::fixtures;
use futures::StreamExt;

use support::{
    Starter, WAIT, events_after_the_spray, live, replace_once, spray_events, with_modules,
};

async fn next<T: serde::de::DeserializeOwned>(stream: &mut BusStream) -> T {
    tokio::time::timeout(WAIT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .decode()
        .unwrap()
}

#[tokio::test]
async fn an_incident_that_an_agent_moved_past_open_keeps_its_state_and_gets_new_work() {
    let starter = Starter::new();
    let app = starter.app().await;
    let mut published = app
        .bus()
        .subscribe(subject::INCIDENTS, Some("test-incidents"))
        .await
        .unwrap();

    // The password spray gives the incident. The agents take it: the Analyst confirms it,
    // and the Responder proposes to block the spray address.
    let first = app.replay(spray_events()).await.unwrap();
    assert_eq!(first.incidents.len(), 1);
    let incident = first.incidents[0].clone();
    assert_eq!(incident.status, IncidentStatus::Investigating);
    assert_eq!(incident.detections.len(), 1);
    let agent_entries: Vec<_> = incident
        .timeline
        .iter()
        .filter(|entry| entry.author != "correlator")
        .cloned()
        .collect();
    assert!(agent_entries.len() >= 4, "{agent_entries:?}");
    assert_eq!(tracked_actions(&incident).len(), 1);

    // The later events add seven detections. Each state of the engine is `open`.
    let second = app.replay(events_after_the_spray()).await.unwrap();

    assert_eq!(second.detections.len(), 7);
    assert_eq!(second.incidents.len(), 1);
    let later = &second.incidents[0];
    assert_eq!(later.id, incident.id);
    assert_eq!(later.status, IncidentStatus::Investigating);
    assert_eq!(later.detections.len(), 8);
    assert_eq!(later.severity, Severity::Critical);
    // The work of the agents on the first state is in the last state.
    for entry in &agent_entries {
        assert!(later.timeline.contains(entry), "{entry:?}");
    }
    assert!(later.timeline.is_sorted_by_key(|entry| entry.time));

    // The bus never had a state that moved the incident back to `open`: the first state
    // is the new incident, and each later state has the state of the store.
    let mut states = Vec::new();
    for _ in 0..7 {
        states.push(next::<Incident>(&mut published).await);
    }
    assert_eq!(
        states
            .iter()
            .map(|state| (state.detections.len(), state.status))
            .collect::<Vec<_>>(),
        [
            (1, IncidentStatus::Open),
            (2, IncidentStatus::Investigating),
            (3, IncidentStatus::Investigating),
            (4, IncidentStatus::Investigating),
            (6, IncidentStatus::Investigating),
            (7, IncidentStatus::Investigating),
            (8, IncidentStatus::Investigating),
        ]
    );

    // The Analyst got each new state, also when the incident was not `open`. Thus the
    // Responder proposed containment for the entities of the later detections.
    let responder: Vec<(ActionKind, String)> = second
        .actions
        .iter()
        .filter(|record| record.request.requested_by == "responder")
        .map(|record| {
            (
                record.request.kind.clone(),
                record.request.target.id.clone(),
            )
        })
        .collect();
    assert_eq!(
        responder,
        [
            (ActionKind::KillSession, fixtures::VICTIM_USER_ID.to_owned()),
            (
                ActionKind::DisableServicePrincipal,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (
                ActionKind::RevokeCredential,
                fixtures::ROGUE_PRINCIPAL_ID.to_owned()
            ),
            (ActionKind::BlockIp, fixtures::WORKLOAD_IP.to_string()),
            (ActionKind::BlockIp, fixtures::DISTANT_IP.to_string()),
        ]
    );
    // The action of the first state is not proposed a second time: the timeline has six
    // actions of the Responder, and one honeytoken of the Deception agent.
    let authors: Vec<String> = tracked_actions(later)
        .into_iter()
        .map(|tracked| tracked.author)
        .collect();
    assert_eq!(
        authors
            .iter()
            .filter(|author| *author == "responder")
            .count(),
        6
    );
    assert_eq!(authors.len(), 7);
}

#[tokio::test]
async fn the_engine_output_keeps_a_state_that_no_agent_changes_again() {
    // Only the Monitor runs, so no agent changes the state after the test sets it.
    let starter = Starter::new();
    let config =
        starter.config_with(|text| with_modules(&text, &["ingest", "detection", "monitor"]));
    let app = starter.build(&config, |builder| builder).await;
    let first = app.replay(spray_events()).await.unwrap();
    assert_eq!(first.incidents.len(), 1);
    assert_eq!(first.incidents[0].status, IncidentStatus::Open);

    // A person contains the incident and writes a summary.
    let mut contained = first.incidents[0].clone();
    contained.status = IncidentStatus::Contained;
    contained.summary = "The network team blocked the address by hand.".to_owned();
    app.incidents().save(&contained).await.unwrap();

    let second = app.replay(events_after_the_spray()).await.unwrap();

    assert_eq!(second.incidents.len(), 1);
    let later = &second.incidents[0];
    assert_eq!(later.status, IncidentStatus::Contained);
    assert_eq!(
        later.summary,
        "The network team blocked the address by hand."
    );
    // The detections, the entities, the techniques, and the severity are from the engine.
    assert_eq!(later.detections.len(), 8);
    assert_eq!(later.attack.len(), 7);
    assert_eq!(later.severity, Severity::Critical);
    assert!(
        later
            .entities
            .iter()
            .any(|entity| entity.id == fixtures::ROGUE_PRINCIPAL_ID)
    );
    assert_eq!(second.actions, []);
}

#[tokio::test]
async fn a_closed_incident_is_forgotten_by_the_engine_and_a_new_incident_starts() {
    let starter = Starter::new();
    let config =
        starter.config_with(|text| with_modules(&text, &["ingest", "detection", "monitor"]));
    let app = starter.build(&config, |builder| builder).await;
    let first = app.replay(spray_events()).await.unwrap();
    let incident = first.incidents[0].clone();
    assert_eq!(app.engine().incidents().len(), 1);

    let mut closed = incident.clone();
    closed.status = IncidentStatus::FalsePositive;
    app.incidents().save(&closed).await.unwrap();

    // The shared store told the engine. The correlator does not keep the incident.
    assert_eq!(app.engine().incidents(), []);

    // The later detections share the spray address with the closed incident. They start
    // a new incident, and the closed incident stays as it is.
    let second = app.replay(events_after_the_spray()).await.unwrap();
    assert_eq!(second.incidents.len(), 1);
    assert_ne!(second.incidents[0].id, incident.id);
    assert_eq!(second.incidents[0].detections.len(), 7);
    let stored = app.incidents().get(incident.id).await.unwrap().unwrap();
    assert_eq!(stored.status, IncidentStatus::FalsePositive);
    assert_eq!(stored.detections.len(), 1);
}

#[tokio::test]
async fn the_events_of_a_detection_go_to_the_monitor_for_the_graph() {
    for (setting, expected) in [("detected", 17_u64), ("all", 648), ("none", 0)] {
        let starter = Starter::new();
        let config = starter.config_with(|text| {
            replace_once(
                &text,
                "monitor_events = \"detected\"",
                &format!("monitor_events = \"{setting}\""),
            )
        });
        let app = starter.build(&config, |builder| builder).await;

        let report = app.replay(fixtures::artex_style_attack()).await.unwrap();

        assert_eq!(report.detections.len(), 8, "{setting}");
        let progress = app.progress();
        assert_eq!(progress.monitor_events, expected, "{setting}");
        assert_eq!(progress.monitor_events_dropped, 0, "{setting}");

        // The Monitor writes the relation from an identity to the address of its sign-in
        // only from an event. The incident alone does not have it.
        let user = NodeId::for_entity(&EntityRef::new(EntityKind::User, fixtures::VICTIM_USER_ID));
        let addresses: Vec<String> = app
            .graph()
            .neighbors(
                &user,
                Some(relation::AUTHENTICATED_FROM),
                Direction::Outgoing,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|node| node.id.0)
            .collect();
        if setting == "none" {
            assert_eq!(addresses, Vec::<String>::new(), "{setting}");
        } else {
            assert_eq!(
                addresses,
                [format!("ip_address:{}", fixtures::SPRAY_IP)],
                "{setting}"
            );
        }
    }
}

#[tokio::test]
async fn each_audit_record_is_on_the_bus_as_the_log_sealed_it() {
    let starter = Starter::new();
    let app = starter.app().await;
    // A new durable name starts at the first message that the bus holds.
    let report = app.replay(spray_events()).await.unwrap();
    let records: Vec<AuditRecord> = app.audit().read(1, 10_000).await.unwrap();
    assert_eq!(records.len() as u64, report.audit.records);
    assert!(records.len() >= 10, "{}", records.len());

    let mut feed = app
        .bus()
        .subscribe(subject::AUDIT, Some("test-audit"))
        .await
        .unwrap();
    let mut published = Vec::new();
    for _ in 0..records.len() {
        published.push(next::<AuditRecord>(&mut feed).await);
    }

    assert_eq!(published, records);
    assert_eq!(app.audit().publish_failures(), 0);
    let kinds: HashSet<AuditKind> = published.iter().map(|record| record.kind).collect();
    assert!(kinds.contains(&AuditKind::Detection));
    assert!(kinds.contains(&AuditKind::Incident));
    assert!(kinds.contains(&AuditKind::ActionExecuted));
}

#[tokio::test]
async fn the_dispatcher_is_the_single_publisher_of_action_results() {
    let starter = Starter::new();
    let app = starter.app().await;
    let report = app.replay(spray_events()).await.unwrap();
    assert!(report.actions.len() >= 3, "{}", report.actions.len());

    let mut results = app
        .bus()
        .subscribe(subject::ACTION_RESULTS, Some("test-results"))
        .await
        .unwrap();
    // Each request has exactly one result on the bus, with its identifier.
    let mut seen = Vec::new();
    for _ in 0..report.actions.len() {
        seen.push(next::<ActionResult>(&mut results).await);
    }
    let published: Vec<_> = seen.iter().map(|result| result.action_id).collect();
    let requested: Vec<_> = report
        .actions
        .iter()
        .map(|record| record.request.id)
        .collect();
    assert_eq!(published, requested);
    for (result, record) in seen.iter().zip(&report.actions) {
        assert_eq!(result.incident_id, record.request.incident_id);
        assert_eq!(
            DispatchResult::Disposition(result.disposition.clone()),
            record.result
        );
    }
    let idle = tokio::time::timeout(std::time::Duration::from_millis(100), results.next()).await;
    assert!(idle.is_err(), "the bus has one more action result");
}

#[tokio::test]
async fn the_honeytoken_connector_and_the_honeytoken_detector_share_one_registry() {
    let starter = Starter::new();
    let config = starter.config_with(|text| live(&text));
    let app = starter.build(&config, |builder| builder).await;
    assert_eq!(app.honeytokens().list().await.unwrap(), []);

    // A person asks for a decoy secret. The default policy gates the action.
    let carol = Principal::new("carol@example.com", PrincipalKind::Human, &["admin"]);
    let placement = EntityRef::new(EntityKind::Secret, "kv-prod/decoy-backup-key")
        .with_tenant(fixtures::TENANT);
    let request = ActionRequest::new(
        ActionKind::DeployHoneytoken,
        placement.clone(),
        "carol@example.com",
        "Plant a decoy secret in the production vault.",
    );
    let disposition = app
        .actions()
        .dispatch(request.clone(), &carol)
        .await
        .unwrap();
    let ActionDisposition::PendingApproval { approval_id, .. } = disposition else {
        panic!("the action must wait for approval: {disposition:?}");
    };
    assert_eq!(app.honeytokens().list().await.unwrap(), []);

    let alice = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);
    let outcome = app
        .decide_approval(approval_id, true, &alice, None)
        .await
        .unwrap();
    let Some(ActionDisposition::Executed(result)) = outcome.disposition else {
        panic!("the action must run: {:?}", outcome.disposition);
    };
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.connector, "honeytokens");

    // The connector of the action registry issued the honeytoken in the registry.
    let tokens = app.honeytokens().list().await.unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].placement, placement);
    assert_eq!(tokens[0].action_id, Some(request.id));
    let token_id = tokens[0].id.clone();

    // An event that reads the decoy. No rule of the rule pack matches this event: only
    // the detector that reads the registry finds it.
    let read = Event::new(
        fixtures::base_time(),
        fixtures::source(),
        EventClass::ApiActivity,
        action::SECRET_READ,
        Actor::new(EntityKind::ServicePrincipal, "sp-unknown").with_tenant(fixtures::TENANT),
    )
    .with_outcome(Outcome::Success)
    .with_target(placement.clone())
    .with_attribute(attr::OPERATION, "SecretGet");
    let report = app.replay(vec![read.clone()]).await.unwrap();

    assert_eq!(report.detections.len(), 1);
    let detection = &report.detections[0];
    assert_eq!(detection.rule_id, HONEYTOKEN_DETECTOR_ID);
    assert_eq!(detection.event_ids, [read.id]);
    assert!(detection.severity >= Severity::High);
    assert_eq!(
        detection.attributes.get(attr::HONEYTOKEN_ID),
        Some(&serde_json::json!(token_id))
    );
    assert_eq!(report.incidents.len(), 1);

    // After the honeytoken is retired, the same read gives no detection.
    app.honeytokens().retire(&token_id).await.unwrap();
    let mut again = read.clone();
    again.id = aegis_contracts::common::EventId::new();
    let report = app.replay(vec![again]).await.unwrap();
    assert_eq!(report.detections, []);
}
