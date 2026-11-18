//! Integration tests for the sample playbooks in the `playbooks/` directory of the repository.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
use aegis_contracts::event::{action, attr};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_respond::deception::MemoryHoneytokenStore;
use aegis_respond::playbook::TargetSelector;
use aegis_respond::revert::{REVERT_AFTER_PARAMETER, kind_has_inverse};
use aegis_respond::{
    ActionRegistry, Dispatcher, GraphActionConnector, GraphConfig, HoneytokenKind,
    HoneytokenRegistry, HoneytokenRequest, HoneytokenTripDetector, MemoryRevertStore,
    MemorySecretSink, Playbook, PlaybookEngine, RevertScheduler, RunMode, StepResult, friction,
};
use aegis_testkit::fixtures::{self, HONEYTOKEN_ID, TENANT, WORKLOAD_IP};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};
use secrecy::SecretString;
use serde_json::{Value, json};

use common::{rogue_incident, sample_playbook_dir};

const FRICTION_PLAYBOOK: &str = "raise-friction-critical-identity-incident";
/// The example tenant in the trigger of the friction playbook.
const FRICTION_TENANT: &str = "tenant.example.com";

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
    // The playbook has steps with a timed revert, so the dispatcher needs a revert store.
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            Arc::new(MemoryAuditLog::default()),
        )
        .revert_store(Arc::new(MemoryRevertStore::default()))
        .build(),
    );
    let scheduler = RevertScheduler::new(dispatcher.clone()).unwrap();
    let mut engine = PlaybookEngine::new(dispatcher);
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
    // Each identity step made one call. The step with a timed revert failed in the check
    // before the change, which is a dry run.
    let identity_calls: Vec<(ActionKind, bool)> = identity
        .executed()
        .iter()
        .map(|call| (call.kind.clone(), call.dry_run))
        .collect();
    assert_eq!(
        identity_calls,
        [
            (ActionKind::DisableServicePrincipal, true),
            (ActionKind::RevokeCredential, false),
            (ActionKind::KillSession, false),
        ]
    );
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
    // The firewall block, the notification, and the ticket were still sent. The block has
    // a timed revert: the dispatcher first asks for a dry run, to learn that the connector
    // can undo the block, and then sends the block.
    assert_eq!(
        bridge
            .executed()
            .iter()
            .map(|call| (call.kind.clone(), call.dry_run))
            .collect::<Vec<_>>(),
        [
            (ActionKind::BlockIp, true),
            (ActionKind::BlockIp, false),
            (ActionKind::Notify, false),
            (ActionKind::OpenTicket, false),
        ]
    );
    // The block that ran has a pending revert of 4 hours. A step that failed has none.
    let pending = scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, ActionKind::BlockIp);
    assert_eq!(pending[0].revert_after_seconds, 14_400);
    assert_eq!(
        pending[0].requested_by,
        "playbook:contain-rogue-service-principal"
    );
}

#[tokio::test]
async fn the_reversible_containment_steps_of_the_samples_have_a_timed_revert() {
    let rig = rig(Vec::new()).await;
    let playbooks = rig.engine.playbooks();
    assert_eq!(playbooks.len(), 6);

    // Each step for one of these actions has a wrong-containment cost and an inverse.
    let contain_first = [
        ActionKind::DisableUser,
        ActionKind::DisableServicePrincipal,
        ActionKind::BlockIp,
        ActionKind::IsolateHost,
        friction::restrict_user_consent(),
    ];
    let mut with_revert = Vec::new();
    for playbook in playbooks {
        for step in playbook.steps() {
            let name = format!("{}/{}", playbook.name(), step.id());
            if contain_first.contains(step.action()) {
                assert!(step.revert_after().is_some(), "{name}");
            } else {
                assert_eq!(step.revert_after(), None, "{name}");
            }
            if let Some(revert_after) = step.revert_after() {
                assert!(kind_has_inverse(step.action()), "{name}");
                with_revert.push((name, revert_after));
            }
        }
    }
    let hours = |count: u64| Duration::from_secs(count * 3_600);
    assert_eq!(
        with_revert,
        [
            (
                "block-password-spray-source/block-source-address".to_owned(),
                hours(4)
            ),
            ("contain-compromised-user/disable-user".to_owned(), hours(4)),
            (
                "contain-rogue-service-principal/disable-service-principal".to_owned(),
                hours(4)
            ),
            (
                "contain-rogue-service-principal/block-source-address".to_owned(),
                hours(4)
            ),
            ("isolate-compromised-host/isolate-host".to_owned(), hours(4)),
            (
                "raise-friction-critical-identity-incident/restrict-user-consent".to_owned(),
                hours(2)
            ),
            (
                "respond-to-honeytoken-trip/block-source-address".to_owned(),
                hours(4)
            ),
        ]
    );
}

/// Returns a critical identity incident in the tenant of the friction playbook.
fn friction_incident() -> Incident {
    let mut incident = rogue_incident();
    incident.tenant = Some(FRICTION_TENANT.to_owned());
    incident
}

#[tokio::test]
async fn the_friction_playbook_runs_only_for_a_critical_incident_in_a_permitted_tenant() {
    let rig = rig(Vec::new()).await;
    let matched = |incident: &Incident| {
        rig.engine
            .matching(incident)
            .iter()
            .any(|playbook| playbook.name() == FRICTION_PLAYBOOK)
    };

    assert!(matched(&friction_incident()));
    // The recorded attack is in a tenant that the sample does not name. A change for all
    // users of a tenant needs the tenant in the trigger.
    assert!(!matched(&rogue_incident()));
    let mut high = friction_incident();
    high.severity = Severity::High;
    assert!(!matched(&high));
    let mut no_tenant = friction_incident();
    no_tenant.tenant = None;
    assert!(!matched(&no_tenant));
    let mut other_technique = friction_incident();
    other_technique.attack = vec![AttackTechnique::new(
        "credential-access",
        "T1110.003",
        "Password Spraying",
    )];
    assert!(!matched(&other_technique));
}

#[tokio::test]
async fn the_friction_playbook_runs_in_dry_run_through_the_real_dispatcher() {
    // The real Microsoft Graph connector. A dry run sends no request, so the test needs
    // no server. The loopback address has no listener.
    let mut config = GraphConfig::new(
        FRICTION_TENANT,
        "client-aegis",
        SecretString::from("client-secret"),
    );
    config.graph_base_url = "http://127.0.0.1:9/v1.0".to_owned();
    config.login_base_url = "http://127.0.0.1:9".to_owned();
    let graph = GraphActionConnector::new(config, Arc::new(MemorySecretSink::default())).unwrap();
    let chat = Arc::new(RecordingConnector::new("chat", vec![ActionKind::Notify]));
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(graph)).unwrap();
    registry.register(chat.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .revert_store(Arc::new(MemoryRevertStore::default()))
        .build(),
    );
    let scheduler = RevertScheduler::new(dispatcher.clone()).unwrap();
    let mut engine = PlaybookEngine::new(dispatcher);
    let report = engine.load_dir(sample_playbook_dir()).await.unwrap();
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    let incident = friction_incident();
    let playbook = engine.playbook(FRICTION_PLAYBOOK).unwrap().clone();
    assert!(playbook.matches(&incident));

    let run = engine
        .run(&playbook, &incident, RunMode::DryRun)
        .await
        .unwrap();

    assert_eq!(run.playbook, FRICTION_PLAYBOOK);
    assert!(run.completed());
    assert_eq!(run.failures(), 0, "{:?}", run.steps);
    assert_eq!(run.steps.len(), 2);

    // Step 1: the friction action on the tenant, through the Graph connector.
    let restrict = &run.steps[0];
    assert_eq!(restrict.step, "restrict-user-consent");
    assert_eq!(restrict.action, friction::restrict_user_consent());
    assert_eq!(
        restrict.target,
        Some(EntityRef::new(EntityKind::Tenant, FRICTION_TENANT))
    );
    let StepResult::Dispatched(ActionDisposition::Executed(outcome)) = &restrict.result else {
        panic!("expected a simulated action, found {:?}", restrict.result);
    };
    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(outcome.connector, "entra-graph");
    assert!(outcome.reversible);
    assert_eq!(
        outcome.message,
        "Would stop user consent to applications in tenant tenant.example.com. This was a dry run. Nothing changed."
    );

    // Step 2: the notification.
    let notify = &run.steps[1];
    assert_eq!(notify.step, "notify-security-team");
    let calls = chat.executed();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].dry_run);
    assert_eq!(calls[0].target.id, "security-operations");
    assert!(
        calls[0].reason.contains(
            "stops user consent to applications in the tenant tenant.example.com for 2 hours"
        ),
        "{}",
        calls[0].reason
    );
    assert_eq!(Some(calls[0].id), notify.request_id);

    // The request of the friction step has the timed revert of 2 hours. A dry run
    // schedules nothing.
    let records = audit.records();
    let of_step: Vec<_> = records
        .iter()
        .filter(|record| {
            record.payload["action_id"] == json!(restrict.request_id)
                || record.payload["action"]["id"] == json!(restrict.request_id)
        })
        .collect();
    assert_eq!(
        of_step.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    assert_eq!(
        of_step[0].payload["action"]["parameters"],
        json!({ REVERT_AFTER_PARAMETER: 7_200 })
    );
    assert_eq!(
        of_step[0].payload["action"]["kind"],
        json!({ "custom": "restrict_user_consent" })
    );
    assert_eq!(of_step[0].payload["action"]["dry_run"], true);
    assert_eq!(of_step[2].payload["timed_revert"]["state"], "not_scheduled");
    assert_eq!(of_step[2].payload["timed_revert"]["after_seconds"], 7_200);
    assert_eq!(scheduler.pending().await.unwrap(), []);
    assert!(audit.verify().await.unwrap().valid);
}
