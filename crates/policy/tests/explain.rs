//! Tests for the explanations that the audit log gives.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_contracts::Error;
use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::common::{
    ActionId, ApprovalId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId,
};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    Principal, PrincipalKind,
};
use aegis_policy::{
    ApprovalService, FileAuditLog, Permission, Rbac, RbacConfig, Subject, explain_action,
    explain_incident,
};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog};
use chrono::Utc;
use serde_json::json;

/// The identifiers in the log that [`write_scenario`] makes.
struct Scenario {
    /// An incident with two actions.
    incident: IncidentId,
    /// A gated action of `incident`. A person approved it.
    gated: ActionId,
    /// An auto action of `incident`.
    auto: ActionId,
    /// A different incident with one action.
    other_incident: IncidentId,
    other_action: ActionId,
}

fn action_link(action: ActionId) -> EvidenceRef {
    EvidenceRef::new(EvidenceKind::Action, action)
}

fn incident_link(incident: IncidentId) -> EvidenceRef {
    EvidenceRef::new(EvidenceKind::Incident, incident)
}

async fn write(
    log: &dyn AuditLog,
    kind: AuditKind,
    actor: &str,
    payload: serde_json::Value,
    evidence: Vec<EvidenceRef>,
) -> u64 {
    let entry = AuditEntry::new(kind, actor, format!("{kind:?} by {actor}."))
        .with_payload(payload)
        .with_evidence(evidence);
    log.append(entry).await.unwrap().sequence
}

/// Writes the records of two incidents in the order in which a dispatcher writes them.
///
/// The records of the three actions alternate. The approval record comes from the approval
/// service.
async fn write_scenario(log: Arc<dyn AuditLog>) -> Scenario {
    let scenario = Scenario {
        incident: IncidentId::new(),
        gated: ActionId::new(),
        auto: ActionId::new(),
        other_incident: IncidentId::new(),
        other_action: ActionId::new(),
    };
    let detection = EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("cause");
    let log_ref = log.as_ref();

    // 1: not linked to an action or an incident.
    write(
        log_ref,
        AuditKind::Detection,
        "sigma",
        json!({ "rule": "r-1" }),
        vec![detection.clone()],
    )
    .await;
    // 2: the incident.
    write(
        log_ref,
        AuditKind::Incident,
        "correlator",
        json!({ "title": "Privilege escalation" }),
        vec![incident_link(scenario.incident), detection.clone()],
    )
    .await;
    // 3: the gated action, linked by evidence to the action and the incident.
    write(
        log_ref,
        AuditKind::ActionProposed,
        "responder",
        json!({ "kind": "disable_service_principal" }),
        vec![
            action_link(scenario.gated),
            incident_link(scenario.incident),
            detection,
        ],
    )
    .await;
    // 4: the action of the other incident.
    write(
        log_ref,
        AuditKind::ActionProposed,
        "responder",
        json!({}),
        vec![
            action_link(scenario.other_action),
            incident_link(scenario.other_incident),
        ],
    )
    .await;
    // 5: linked to the gated action by evidence only.
    write(
        log_ref,
        AuditKind::PolicyDecision,
        "policy",
        json!({ "effect": "require_approval" }),
        vec![action_link(scenario.gated)],
    )
    .await;
    // 6: linked to the gated action by the payload only.
    let approval = ApprovalId::new();
    write(
        log_ref,
        AuditKind::ApprovalRequested,
        "dispatcher",
        json!({ "approval_id": approval, "action": { "id": scenario.gated, "kind": "disable_service_principal" } }),
        Vec::new(),
    )
    .await;
    // 7: the other incident.
    write(
        log_ref,
        AuditKind::PolicyDecision,
        "policy",
        json!({ "action_id": scenario.other_action }),
        Vec::new(),
    )
    .await;
    // 8: the approval service writes the decision record.
    approve(log.clone(), approval, scenario.gated, scenario.incident).await;
    // 9: linked to the gated action by the payload only.
    write(
        log_ref,
        AuditKind::ActionExecuted,
        "graph",
        json!({ "outcome": { "action_id": scenario.gated, "status": "succeeded" } }),
        Vec::new(),
    )
    .await;
    // 10: the auto action, linked to the incident.
    write(
        log_ref,
        AuditKind::ActionProposed,
        "responder",
        json!({ "kind": "notify" }),
        vec![action_link(scenario.auto), incident_link(scenario.incident)],
    )
    .await;
    // 11: linked to the auto action only. It has no link to the incident.
    write(
        log_ref,
        AuditKind::ActionExecuted,
        "mail",
        json!({ "outcome": { "action_id": scenario.auto, "status": "succeeded" } }),
        Vec::new(),
    )
    .await;
    // 12: not linked.
    let last = write(
        log_ref,
        AuditKind::ConfigChange,
        "alice@example.com",
        json!({}),
        Vec::new(),
    )
    .await;
    assert_eq!(last, 12);
    scenario
}

async fn approve(
    log: Arc<dyn AuditLog>,
    approval: ApprovalId,
    action: ActionId,
    incident: IncidentId,
) {
    let mut request = ActionRequest::new(
        ActionKind::DisableServicePrincipal,
        EntityRef::new(EntityKind::ServicePrincipal, "sp-1"),
        "responder",
        "Contain the service principal.",
    );
    request.id = action;
    request.incident_id = Some(incident);
    let queue = Arc::new(MemoryApprovals::default());
    queue
        .submit(ApprovalRequest {
            id: approval,
            action: request,
            requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent"]),
            decision: PolicyDecision {
                effect: PolicyEffect::RequireApproval,
                tier: ActionTier::Gated,
                reasons: Vec::new(),
                policy: None,
                evaluated_at: Utc::now(),
            },
            status: ApprovalStatus::Pending,
            requested_at: Utc::now(),
            decided_by: None,
            decided_at: None,
            note: None,
        })
        .await
        .unwrap();
    let rbac =
        Rbac::new(RbacConfig::default().with_role("approver", &[Permission::ApproveActions]));
    let service = ApprovalService::new(queue, rbac, log);
    let approver = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);
    service
        .decide(approval, true, &approver, None)
        .await
        .unwrap();
}

fn sequences(explanation: &aegis_policy::Explanation) -> Vec<u64> {
    explanation
        .records
        .iter()
        .map(|record| record.sequence)
        .collect()
}

#[tokio::test]
async fn the_chain_of_one_action_comes_back_in_order() {
    let log = Arc::new(MemoryAuditLog::default());
    let scenario = write_scenario(log.clone()).await;

    let explanation = explain_action(log.as_ref(), scenario.gated).await.unwrap();
    assert_eq!(explanation.subject, Subject::Action(scenario.gated));
    assert_eq!(
        explanation.kinds(),
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ApprovalRequested,
            AuditKind::ApprovalDecided,
            AuditKind::ActionExecuted,
        ]
    );
    assert_eq!(sequences(&explanation), [3, 5, 6, 8, 9]);
    assert_eq!(explanation.records[3].actor, "alice@example.com");

    let evidence: Vec<(EvidenceKind, String)> = explanation
        .evidence()
        .into_iter()
        .map(|link| (link.kind, link.id))
        .collect();
    assert_eq!(
        evidence,
        [
            (EvidenceKind::Action, scenario.gated.to_string()),
            (EvidenceKind::Incident, scenario.incident.to_string()),
            (EvidenceKind::Detection, "det-1".to_owned()),
        ]
    );
    assert_eq!(explanation.evidence()[2].note.as_deref(), Some("cause"));
}

#[tokio::test]
async fn each_action_has_its_own_chain() {
    let log = Arc::new(MemoryAuditLog::default());
    let scenario = write_scenario(log.clone()).await;

    let auto = explain_action(log.as_ref(), scenario.auto).await.unwrap();
    assert_eq!(sequences(&auto), [10, 11]);
    assert_eq!(
        auto.kinds(),
        [AuditKind::ActionProposed, AuditKind::ActionExecuted]
    );

    let other = explain_action(log.as_ref(), scenario.other_action)
        .await
        .unwrap();
    assert_eq!(sequences(&other), [4, 7]);
}

#[tokio::test]
async fn an_incident_has_its_records_and_the_records_of_its_actions() {
    let log = Arc::new(MemoryAuditLog::default());
    let scenario = write_scenario(log.clone()).await;

    let explanation = explain_incident(log.as_ref(), scenario.incident)
        .await
        .unwrap();
    assert_eq!(explanation.subject, Subject::Incident(scenario.incident));
    assert_eq!(sequences(&explanation), [2, 3, 5, 6, 8, 9, 10, 11]);
    assert_eq!(explanation.records[0].kind, AuditKind::Incident);

    let other = explain_incident(log.as_ref(), scenario.other_incident)
        .await
        .unwrap();
    assert_eq!(sequences(&other), [4, 7]);
}

#[tokio::test]
async fn a_subject_with_no_record_is_not_found() {
    let log = Arc::new(MemoryAuditLog::default());
    let empty = explain_action(log.as_ref(), ActionId::new())
        .await
        .unwrap_err();
    assert!(matches!(empty, Error::NotFound(_)), "{empty:?}");

    write_scenario(log.clone()).await;
    let unknown_action = ActionId::new();
    let error = explain_action(log.as_ref(), unknown_action)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message.contains(&unknown_action.to_string())),
        "{error:?}"
    );
    let error = explain_incident(log.as_ref(), IncidentId::new())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");
}

#[tokio::test]
async fn an_explanation_reads_a_log_that_is_longer_than_one_page() {
    let log = MemoryAuditLog::default();
    let action = ActionId::new();
    let mut expected = Vec::new();
    for index in 0..1300 {
        if [0, 511, 512, 513, 1024, 1299].contains(&index) {
            let sequence = write(
                &log,
                AuditKind::ActionExecuted,
                "graph",
                json!({ "action_id": action }),
                Vec::new(),
            )
            .await;
            expected.push(sequence);
        } else {
            write(
                &log,
                AuditKind::Other,
                "filler",
                json!({ "index": index }),
                Vec::new(),
            )
            .await;
        }
    }
    assert_eq!(expected, [1, 512, 513, 514, 1025, 1300]);
    let explanation = explain_action(&log, action).await.unwrap();
    assert_eq!(sequences(&explanation), expected);
}

#[tokio::test]
async fn the_file_audit_log_gives_the_same_explanations() {
    let directory = tempfile::tempdir().unwrap();
    let log = Arc::new(FileAuditLog::open(directory.path().join("audit.jsonl")).unwrap());
    let scenario = write_scenario(log.clone()).await;

    let action = explain_action(log.as_ref(), scenario.gated).await.unwrap();
    assert_eq!(sequences(&action), [3, 5, 6, 8, 9]);
    let incident = explain_incident(log.as_ref(), scenario.incident)
        .await
        .unwrap();
    assert_eq!(sequences(&incident), [2, 3, 5, 6, 8, 9, 10, 11]);
    assert_eq!(
        action.records,
        log.read(1, 12)
            .await
            .unwrap()
            .into_iter()
            .filter(|record| [3, 5, 6, 8, 9].contains(&record.sequence))
            .collect::<Vec<_>>()
    );
}
