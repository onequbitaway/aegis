//! Integration tests for the sample playbooks in the `playbooks/` directory of the repository.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::AuditLog;
use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
use aegis_contracts::event::{action, attr};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_respond::deception::MemoryHoneytokenStore;
use aegis_respond::playbook::TargetSelector;
use aegis_respond::{
    ActionRegistry, Dispatcher, HoneytokenKind, HoneytokenRegistry, HoneytokenRequest,
    HoneytokenTripDetector, Playbook, PlaybookEngine, RunMode, StepResult,
};
use aegis_testkit::fixtures::{self, HONEYTOKEN_ID, TENANT, WORKLOAD_IP};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};
use serde_json::{Value, json};

use common::{rogue_incident, sample_playbook_dir};

/// A dispatcher that permits each action, with one connector that records each request.
struct Rig {
    engine: PlaybookEngine,
    connector: Arc<RecordingConnector>,
    audit: Arc<MemoryAuditLog>,
}

/// Makes a rig with a connector for `actions` and loads the sample playbooks.
async fn rig(actions: Vec<ActionKind>) -> Rig {
    let connector = Arc::new(RecordingConnector::new("recording", actions));
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();
    let mut engine = PlaybookEngine::new(Arc::new(dispatcher));
    let report = engine.load_dir(sample_playbook_dir()).await.unwrap();
    assert!(
        report.rejected.is_empty(),
        "a sample playbook is not valid: {:?}",
        report.rejected
    );
    assert!(!report.loaded.is_empty());
    Rig {
        engine,
        connector,
        audit,
    }
}

fn all_step_actions(playbooks: &[Playbook]) -> Vec<ActionKind> {
    let mut actions: Vec<ActionKind> = playbooks
        .iter()
        .flat_map(|playbook| playbook.steps().iter().map(|step| step.action().clone()))
        .collect();
    actions.sort();
    actions.dedup();
    actions
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn entity(kind: EntityKind) -> EntityRef {
    let id = match kind {
        EntityKind::IpAddress => "203.0.113.50".to_owned(),
        other => format!("{}-1", json!(other).as_str().unwrap()),
    };
    EntityRef::new(kind, id)
        .with_name("Example entity")
        .with_tenant(TENANT)
}

/// Builds an incident that satisfies the trigger of `playbook` and gives each step a target.
fn incident_for(playbook: &Playbook) -> Incident {
    let trigger = serde_json::to_value(playbook.trigger()).unwrap();
    let mut techniques = strings(&trigger["techniques_all"]);
    techniques.extend(strings(&trigger["techniques_any"]).into_iter().take(1));
    let mut kinds: Vec<EntityKind> = trigger
        .get("entity_kinds")
        .map(|kinds| serde_json::from_value(kinds.clone()).unwrap())
        .unwrap_or_default();
    for step in playbook.steps() {
        if let TargetSelector::EachEntity(kind) = step.target() {
            kinds.push(*kind);
        }
    }
    kinds.sort();
    kinds.dedup();
    let tenant = strings(&trigger["tenants"])
        .into_iter()
        .next()
        .unwrap_or_else(|| TENANT.to_owned());
    let detection = Detection {
        id: DetectionId::new(),
        rule_id: "test.rule".to_owned(),
        title: "A detection for a test".to_owned(),
        description: String::new(),
        severity: Severity::Critical,
        verdict: Verdict::Malicious,
        tier: DetectionTier::Deterministic,
        time: fixtures::base_time(),
        attack: Vec::new(),
        event_ids: Vec::new(),
        entities: Vec::new(),
        tenant: Some(tenant.clone()),
        attributes: BTreeMap::from([(attr::CREDENTIAL_ID.to_owned(), json!("credential-1"))]),
    };
    Incident {
        id: IncidentId::new(),
        title: "An incident for a sample playbook".to_owned(),
        summary: String::new(),
        severity: Severity::Critical,
        status: IncidentStatus::Open,
        created_at: fixtures::base_time(),
        updated_at: fixtures::base_time(),
        tenant: Some(tenant),
        detections: vec![detection],
        entities: kinds.into_iter().map(entity).collect(),
        attack: techniques
            .iter()
            .map(|id| AttackTechnique::new("tactic", id.clone(), "Technique"))
            .collect(),
        timeline: Vec::new(),
    }
}

#[tokio::test]
async fn each_sample_playbook_is_valid_and_runs_in_dry_run_with_no_failure() {
    // Load one time to learn the actions that the samples use.
    let probe = rig(Vec::new()).await;
    let playbooks = probe.engine.playbooks().to_vec();
    let rig = rig(all_step_actions(&playbooks)).await;
    assert!(
        playbooks
            .iter()
            .any(|playbook| playbook.name() == "contain-rogue-service-principal")
    );

    let mut calls_before = 0;
    for playbook in &playbooks {
        let name = playbook.name();
        let incident = incident_for(playbook);
        assert!(playbook.matches(&incident), "{name}");
        assert!(
            rig.engine
                .matching(&incident)
                .iter()
                .any(|matched| matched.name() == name),
            "{name}"
        );

        let run = rig
            .engine
            .run(playbook, &incident, RunMode::DryRun)
            .await
            .unwrap();

        assert!(run.completed(), "{name}: stopped at {:?}", run.stopped_at);
        assert_eq!(run.failures(), 0, "{name}: {:?}", run.steps);
        assert!(run.steps.len() >= playbook.steps().len(), "{name}");
        for line in &run.steps {
            match &line.result {
                StepResult::Dispatched(ActionDisposition::Executed(outcome)) => {
                    assert_eq!(
                        outcome.status,
                        ActionStatus::Simulated,
                        "{name} {}",
                        line.step
                    );
                }
                other => panic!(
                    "{name} {}: expected a simulated action, found {other:?}",
                    line.step
                ),
            }
        }
        let calls = rig.connector.executed();
        let new_calls = &calls[calls_before..];
        assert_eq!(new_calls.len(), run.steps.len(), "{name}");
        for call in new_calls {
            assert!(call.dry_run, "{name}: {:?}", call.kind);
            assert_eq!(call.incident_id, Some(incident.id), "{name}");
            assert_eq!(call.requested_by, format!("playbook:{name}"), "{name}");
            assert!(!call.reason.contains("{{"), "{name}: {}", call.reason);
            assert!(!call.reason.trim().is_empty(), "{name}");
        }
        calls_before = calls.len();
    }
    assert!(calls_before > 0);
    assert!(rig.audit.verify().await.unwrap().valid);
}

#[tokio::test]
async fn the_recorded_attack_incident_selects_the_rogue_service_principal_playbook() {
    let rig = rig(Vec::new()).await;
    let incident = rogue_incident();

    let matched: Vec<&str> = rig
        .engine
        .matching(&incident)
        .iter()
        .map(|playbook| playbook.name())
        .collect();

    assert!(
        matched.contains(&"contain-rogue-service-principal"),
        "{matched:?}"
    );
    // The incident has no host and no honeytoken trip.
    assert!(
        !matched.contains(&"isolate-compromised-host"),
        "{matched:?}"
    );
    assert!(
        !matched.contains(&"respond-to-honeytoken-trip"),
        "{matched:?}"
    );

    // A low severity incident with the same data selects no playbook.
    let mut low = rogue_incident();
    low.severity = Severity::Low;
    assert_eq!(rig.engine.matching(&low).len(), 0);
}

#[tokio::test]
async fn a_honeytoken_trip_in_the_recorded_attack_selects_the_honeytoken_playbook() {
    // The detector makes a detection for the honeytoken event of the recorded attack log.
    let honeytokens = Arc::new(
        HoneytokenRegistry::open(Arc::new(MemoryHoneytokenStore::default()))
            .await
            .unwrap(),
    );
    honeytokens
        .issue(
            HoneytokenRequest::new(
                HoneytokenKind::Secret,
                EntityRef::new(EntityKind::Secret, "kv-prod/legacy-admin-password")
                    .with_tenant(TENANT),
                "A decoy admin password in the production vault.",
            )
            .with_id(HONEYTOKEN_ID),
        )
        .await
        .unwrap();
    let event = fixtures::artex_style_attack()
        .into_iter()
        .find(|event| event.action == action::HONEYTOKEN_TRIP)
        .unwrap();
    let detections = HoneytokenTripDetector::new(honeytokens)
        .inspect(&event)
        .await
        .unwrap();
    assert_eq!(detections.len(), 1);
    let detection = detections.into_iter().next().unwrap();
    // The incident has the shape that a correlator makes from this one detection.
    let incident = Incident {
        id: IncidentId::new(),
        title: detection.title.clone(),
        summary: detection.description.clone(),
        severity: detection.severity,
        status: IncidentStatus::Open,
        created_at: detection.time,
        updated_at: detection.time,
        tenant: detection.tenant.clone(),
        entities: detection.entities.clone(),
        attack: detection.attack.clone(),
        detections: vec![detection],
        timeline: Vec::new(),
    };
    let rig = rig(vec![
        ActionKind::SnapshotEvidence,
        ActionKind::BlockIp,
        ActionKind::Notify,
    ])
    .await;

    let runs = rig
        .engine
        .run_matching(&incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].playbook, "respond-to-honeytoken-trip");
    assert_eq!(runs[0].failures(), 0);
    let calls = rig.connector.executed();
    assert_eq!(
        calls
            .iter()
            .map(|call| (call.kind.clone(), call.target.kind, call.target.id.clone()))
            .collect::<Vec<_>>(),
        [
            (
                ActionKind::SnapshotEvidence,
                EntityKind::Tenant,
                TENANT.to_owned()
            ),
            (
                ActionKind::BlockIp,
                EntityKind::IpAddress,
                WORKLOAD_IP.to_string()
            ),
            (
                ActionKind::Notify,
                EntityKind::Other,
                "security-operations".to_owned()
            ),
        ]
    );
    assert!(calls.iter().all(|call| call.dry_run));
    // The playbook does not act on the decoy itself.
    assert!(
        calls
            .iter()
            .all(|call| call.target.kind != EntityKind::Secret)
    );
}

#[tokio::test]
async fn the_rogue_principal_playbook_tells_the_team_when_the_containment_fails() {
    let identity = Arc::new(
        RecordingConnector::new(
            "identity",
            vec![
                ActionKind::DisableServicePrincipal,
                ActionKind::RevokeCredential,
                ActionKind::KillSession,
            ],
        )
        .failing("the identity provider is down"),
    );
    let bridge = Arc::new(RecordingConnector::new(
        "bridge",
        vec![
            ActionKind::BlockIp,
            ActionKind::Notify,
            ActionKind::OpenTicket,
        ],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(identity.clone()).unwrap();
    registry.register(bridge.clone()).unwrap();
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        Arc::new(MemoryAuditLog::default()),
    )
    .build();
    let mut engine = PlaybookEngine::new(Arc::new(dispatcher));
    let report = engine.load_dir(sample_playbook_dir()).await.unwrap();
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    let playbook = engine
        .playbook("contain-rogue-service-principal")
        .unwrap()
        .clone();

    let run = engine
        .run(&playbook, &rogue_incident(), RunMode::Live)
        .await
        .unwrap();

    // The three identity actions failed. The run did not stop.
    assert!(run.completed(), "stopped at {:?}", run.stopped_at);
    assert_eq!(run.failures(), 3);
    assert_eq!(identity.executed().len(), 3);
    for line in &run.steps[..3] {
        assert!(
            matches!(
                &line.result,
                StepResult::Failed { kind, retryable: true, .. } if kind == "unavailable"
            ),
            "{}: {:?}",
            line.step,
            line.result
        );
    }
    // The firewall block, the notification, and the ticket were still sent.
    assert_eq!(
        bridge
            .executed()
            .iter()
            .map(|call| call.kind.clone())
            .collect::<Vec<_>>(),
        [
            ActionKind::BlockIp,
            ActionKind::Notify,
            ActionKind::OpenTicket
        ]
    );
}
