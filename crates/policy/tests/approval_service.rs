//! Tests for the approval service with the in-memory queue and audit log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification};
use aegis_contracts::common::{
    ApprovalId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId,
};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    Principal, PrincipalKind,
};
use aegis_contracts::{Error, Result};
use aegis_policy::{ApprovalRules, ApprovalService, Permission, Rbac, RbacConfig};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::json;

fn rbac() -> Rbac {
    Rbac::new(
        RbacConfig::default()
            .with_role("approver", &[Permission::ApproveActions])
            .with_role("analyst", &[Permission::ViewIncidents])
            .with_role("auditor", &[Permission::ViewAudit]),
    )
}

fn human(id: &str, roles: &[&str]) -> Principal {
    Principal::new(id, PrincipalKind::Human, roles)
}

fn alice() -> Principal {
    human("alice@example.com", &["approver"])
}

fn bob() -> Principal {
    human("bob@example.com", &["approver"])
}

fn approval(requested_by: Principal, age_seconds: i64) -> ApprovalRequest {
    let mut action = ActionRequest::new(
        ActionKind::DisableServicePrincipal,
        EntityRef::new(EntityKind::ServicePrincipal, "sp-1"),
        requested_by.id.clone(),
        "The service principal gave itself a privileged role.",
    );
    action.incident_id = Some(IncidentId::new());
    action.evidence = vec![EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("cause")];
    ApprovalRequest {
        id: ApprovalId::new(),
        action,
        requested_by,
        decision: PolicyDecision {
            effect: PolicyEffect::RequireApproval,
            tier: ActionTier::Gated,
            reasons: vec!["The action is in the gated tier.".to_owned()],
            policy: Some("aegis.response.decision".to_owned()),
            evaluated_at: Utc::now(),
        },
        status: ApprovalStatus::Pending,
        requested_at: Utc::now() - Duration::seconds(age_seconds),
        decided_by: None,
        decided_at: None,
        note: None,
    }
}

fn responder() -> Principal {
    Principal::new("responder", PrincipalKind::Agent, &["agent"])
}

struct Fixture {
    queue: Arc<MemoryApprovals>,
    audit: Arc<MemoryAuditLog>,
    service: ApprovalService,
}

impl Fixture {
    fn new() -> Self {
        let queue = Arc::new(MemoryApprovals::default());
        let audit = Arc::new(MemoryAuditLog::default());
        let service = ApprovalService::new(queue.clone(), rbac(), audit.clone());
        Self {
            queue,
            audit,
            service,
        }
    }

    fn with_rules(mut self, rules: ApprovalRules) -> Self {
        self.service = self.service.with_rules(rules);
        self
    }

    async fn submit(&self, requested_by: Principal) -> ApprovalRequest {
        let request = approval(requested_by, 1);
        self.queue.submit(request.clone()).await.unwrap();
        request
    }

    /// Asserts that a refused decision changed nothing.
    async fn assert_untouched(&self, id: ApprovalId) {
        let stored = self.queue.get(id).await.unwrap().unwrap();
        assert_eq!(stored.status, ApprovalStatus::Pending);
        assert_eq!(stored.decided_by, None);
        assert_eq!(self.audit.records(), Vec::new());
    }
}

fn link(kind: EvidenceKind, id: impl ToString) -> (EvidenceKind, String) {
    (kind, id.to_string())
}

fn links(record: &AuditRecord) -> Vec<(EvidenceKind, String)> {
    record
        .evidence
        .iter()
        .map(|evidence| (evidence.kind, evidence.id.clone()))
        .collect()
}

#[tokio::test]
async fn an_approval_is_recorded_in_the_queue_and_in_the_audit_log() {
    let fixture = Fixture::new();
    let request = fixture.submit(responder()).await;

    let decided = fixture
        .service
        .decide(
            request.id,
            true,
            &alice(),
            Some("Confirmed with the owner.".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(decided.id, request.id);
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(decided.decided_by.as_deref(), Some("alice@example.com"));
    assert_eq!(decided.note.as_deref(), Some("Confirmed with the owner."));
    assert_eq!(fixture.queue.get(request.id).await.unwrap(), Some(decided));

    let records = fixture.audit.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.kind, AuditKind::ApprovalDecided);
    assert_eq!(record.actor, "alice@example.com");
    assert_eq!(
        links(record),
        [
            link(EvidenceKind::Action, request.action.id),
            link(EvidenceKind::Incident, request.action.incident_id.unwrap()),
            link(EvidenceKind::Detection, "det-1"),
        ]
    );
    assert_eq!(
        record.payload,
        json!({
            "approval_id": request.id,
            "action_id": request.action.id,
            "incident_id": request.action.incident_id,
            "decision": "approved",
            "decided_by": { "id": "alice@example.com", "kind": "human", "roles": ["approver"] },
            "requested_by": "responder",
            "note": "Confirmed with the owner.",
            "action_kind": "disable_service_principal",
            "target": { "kind": "service_principal", "id": "sp-1" },
            "dry_run": false,
        })
    );
    assert_eq!(
        fixture.audit.verify().await.unwrap(),
        ChainVerification {
            valid: true,
            checked: 1,
            first_invalid_sequence: None,
            reason: None
        }
    );
}

#[tokio::test]
async fn a_rejection_is_recorded_in_the_queue_and_in_the_audit_log() {
    let fixture = Fixture::new();
    let request = fixture.submit(responder()).await;

    let decided = fixture
        .service
        .decide(request.id, false, &bob(), None)
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Rejected);
    assert_eq!(decided.decided_by.as_deref(), Some("bob@example.com"));
    assert_eq!(decided.note, None);

    let records = fixture.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::ApprovalDecided);
    assert_eq!(records[0].actor, "bob@example.com");
    assert_eq!(records[0].payload["decision"], "rejected");
    assert_eq!(records[0].payload["note"], json!(null));
    assert_eq!(
        links(&records[0])[0],
        link(EvidenceKind::Action, request.action.id)
    );
}

#[tokio::test]
async fn a_principal_without_the_permission_cannot_decide() {
    let fixture = Fixture::new();
    let request = fixture.submit(responder()).await;
    let principals = [
        human("carol@example.com", &["analyst"]),
        human("dave@example.com", &["auditor", "analyst"]),
        human("erin@example.com", &["administrator"]),
        human("frank@example.com", &[]),
    ];
    for principal in principals {
        for approve in [true, false] {
            let error = fixture
                .service
                .decide(request.id, approve, &principal, None)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, Error::Unauthorized(message) if message.contains("approve_actions")),
                "{}: {error:?}",
                principal.id
            );
        }
    }
    fixture.assert_untouched(request.id).await;
}

#[tokio::test]
async fn only_a_person_can_decide_unless_the_rules_permit_other_principals() {
    let fixture = Fixture::new();
    let request = fixture.submit(responder()).await;
    let agent = Principal::new("supervisor", PrincipalKind::Agent, &["approver"]);
    let system = Principal::new("playbooks", PrincipalKind::System, &["approver"]);
    for principal in [&agent, &system] {
        let error = fixture
            .service
            .decide(request.id, true, principal, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized(message) if message.contains(&principal.id)),
            "{error:?}"
        );
    }
    fixture.assert_untouched(request.id).await;

    let permissive = Fixture::new().with_rules(ApprovalRules {
        humans_only: false,
        ..ApprovalRules::default()
    });
    let request = permissive.submit(responder()).await;
    let decided = permissive
        .service
        .decide(request.id, true, &system, None)
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(decided.decided_by.as_deref(), Some("playbooks"));
}

#[tokio::test]
async fn the_requester_cannot_approve_its_own_request() {
    let fixture = Fixture::new();
    let request = fixture.submit(alice()).await;

    let same_person = [alice(), human("ALICE@Example.COM", &["approver"])];
    for principal in &same_person {
        let error = fixture
            .service
            .decide(request.id, true, principal, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized(message) if message.contains("four-eyes")),
            "{}: {error:?}",
            principal.id
        );
    }
    fixture.assert_untouched(request.id).await;

    let decided = fixture
        .service
        .decide(request.id, true, &bob(), None)
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(decided.decided_by.as_deref(), Some("bob@example.com"));
}

#[tokio::test]
async fn the_four_eyes_rule_reads_the_requester_of_the_action_too() {
    let fixture = Fixture::new();
    let mut request = approval(Principal::new("playbooks", PrincipalKind::System, &[]), 1);
    request.action.requested_by = "alice@example.com".to_owned();
    fixture.queue.submit(request.clone()).await.unwrap();

    let error = fixture
        .service
        .decide(request.id, true, &alice(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message.contains("four-eyes")),
        "{error:?}"
    );
    fixture.assert_untouched(request.id).await;
}

#[tokio::test]
async fn the_requester_can_reject_its_own_request() {
    let fixture = Fixture::new();
    let request = fixture.submit(alice()).await;
    let decided = fixture
        .service
        .decide(
            request.id,
            false,
            &alice(),
            Some("Not necessary.".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Rejected);
    assert_eq!(fixture.audit.records().len(), 1);
}

#[tokio::test]
async fn the_requester_can_approve_when_the_four_eyes_rule_is_off() {
    let fixture = Fixture::new().with_rules(ApprovalRules {
        four_eyes: false,
        ..ApprovalRules::default()
    });
    assert!(ApprovalRules::default().four_eyes);
    let request = fixture.submit(alice()).await;
    let decided = fixture
        .service
        .decide(request.id, true, &alice(), None)
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
}

#[tokio::test]
async fn a_second_decision_fails_and_writes_no_audit_record() {
    let fixture = Fixture::new();
    let request = fixture.submit(responder()).await;
    fixture
        .service
        .decide(request.id, true, &alice(), None)
        .await
        .unwrap();

    for (approve, principal) in [(false, bob()), (true, bob()), (true, alice())] {
        let error = fixture
            .service
            .decide(request.id, approve, &principal, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains(&request.id.to_string())),
            "{error:?}"
        );
    }
    let stored = fixture.queue.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Approved);
    assert_eq!(stored.decided_by.as_deref(), Some("alice@example.com"));
    let records = fixture.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].actor, "alice@example.com");
}

#[tokio::test]
async fn a_request_that_does_not_exist_is_not_found() {
    let fixture = Fixture::new();
    let unknown = ApprovalId::new();
    let error = fixture
        .service
        .decide(unknown, true, &alice(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message.contains(&unknown.to_string())),
        "{error:?}"
    );
    let error = fixture.service.get(unknown, &alice()).await.unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");
    assert_eq!(fixture.audit.records(), Vec::new());
}

#[tokio::test]
async fn pending_requests_are_listed_for_principals_that_can_read_them() {
    let fixture = Fixture::new();
    let newer = approval(responder(), 10);
    let older = approval(responder(), 600);
    fixture.queue.submit(newer.clone()).await.unwrap();
    fixture.queue.submit(older.clone()).await.unwrap();

    let analyst = human("carol@example.com", &["analyst"]);
    for reader in [&analyst, &alice()] {
        let pending: Vec<ApprovalId> = fixture
            .service
            .pending(reader)
            .await
            .unwrap()
            .iter()
            .map(|request| request.id)
            .collect();
        assert_eq!(pending, [older.id, newer.id], "{}", reader.id);
        assert_eq!(fixture.service.get(newer.id, reader).await.unwrap(), newer);
    }

    for principal in [
        human("dave@example.com", &["auditor"]),
        human("erin@example.com", &[]),
    ] {
        let error = fixture.service.pending(&principal).await.unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized(message) if message.contains("view_incidents") && message.contains("approve_actions")),
            "{error:?}"
        );
        let error = fixture.service.get(newer.id, &principal).await.unwrap_err();
        assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    }

    fixture
        .service
        .decide(older.id, false, &alice(), None)
        .await
        .unwrap();
    let pending = fixture.service.pending(&analyst).await.unwrap();
    assert_eq!(pending, [newer]);
}

/// An audit log that is not available.
struct BrokenAuditLog;

#[async_trait]
impl AuditLog for BrokenAuditLog {
    async fn append(&self, _entry: AuditEntry) -> Result<AuditRecord> {
        Err(Error::Unavailable("the audit store is down".to_owned()))
    }

    async fn read(&self, _from_sequence: u64, _limit: usize) -> Result<Vec<AuditRecord>> {
        Err(Error::Unavailable("the audit store is down".to_owned()))
    }

    async fn verify(&self) -> Result<ChainVerification> {
        Err(Error::Unavailable("the audit store is down".to_owned()))
    }
}

#[tokio::test]
async fn no_decision_takes_effect_when_the_audit_log_is_not_available() {
    let queue = Arc::new(MemoryApprovals::default());
    let service = ApprovalService::new(queue.clone(), rbac(), Arc::new(BrokenAuditLog));
    let request = approval(responder(), 1);
    queue.submit(request.clone()).await.unwrap();

    for approve in [true, false] {
        let error = service
            .decide(request.id, approve, &alice(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unavailable(message) if message == "the audit store is down"),
            "{error:?}"
        );
    }
    assert_eq!(queue.get(request.id).await.unwrap(), Some(request));
}

/// A queue that reads requests but refuses each decision.
struct ReadOnlyQueue(MemoryApprovals);

#[async_trait]
impl ApprovalQueue for ReadOnlyQueue {
    async fn submit(&self, request: ApprovalRequest) -> Result<()> {
        self.0.submit(request).await
    }

    async fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>> {
        self.0.get(id).await
    }

    async fn pending(&self) -> Result<Vec<ApprovalRequest>> {
        self.0.pending().await
    }

    async fn decide(
        &self,
        _id: ApprovalId,
        _approve: bool,
        _decided_by: &Principal,
        _note: Option<String>,
    ) -> Result<ApprovalRequest> {
        Err(Error::Unavailable("the queue is read-only".to_owned()))
    }
}

#[tokio::test]
async fn a_decision_that_the_queue_refuses_gets_a_correction_record() {
    let queue = Arc::new(ReadOnlyQueue(MemoryApprovals::default()));
    let audit = Arc::new(MemoryAuditLog::default());
    let service = ApprovalService::new(queue.clone(), rbac(), audit.clone());
    let request = approval(responder(), 1);
    queue.submit(request.clone()).await.unwrap();

    let error = service
        .decide(request.id, true, &alice(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message == "the queue is read-only"),
        "the caller gets the error of the queue: {error:?}"
    );
    assert_eq!(queue.get(request.id).await.unwrap(), Some(request.clone()));

    let records = audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [AuditKind::ApprovalDecided, AuditKind::Other]
    );
    let (decision, correction) = (&records[0], &records[1]);
    assert_eq!(correction.actor, aegis_policy::approval::SERVICE_ACTOR);
    assert_eq!(correction.payload["void_record"], json!(decision.id));
    assert_eq!(
        correction.payload["void_sequence"],
        json!(decision.sequence)
    );
    assert_eq!(correction.payload["approval_id"], json!(request.id));
    assert_eq!(correction.payload["action_id"], json!(request.action.id));
    let correction_links = links(correction);
    assert_eq!(
        correction_links[0],
        link(EvidenceKind::Action, request.action.id)
    );
    assert_eq!(
        correction_links.last(),
        Some(&link(EvidenceKind::AuditRecord, decision.id))
    );
}

/// A queue that lets a different task run during each read.
struct YieldingQueue(MemoryApprovals);

#[async_trait]
impl ApprovalQueue for YieldingQueue {
    async fn submit(&self, request: ApprovalRequest) -> Result<()> {
        self.0.submit(request).await
    }

    async fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>> {
        let request = self.0.get(id).await;
        tokio::task::yield_now().await;
        request
    }

    async fn pending(&self) -> Result<Vec<ApprovalRequest>> {
        self.0.pending().await
    }

    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        decided_by: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalRequest> {
        tokio::task::yield_now().await;
        self.0.decide(id, approve, decided_by, note).await
    }
}

#[tokio::test]
async fn two_decisions_at_the_same_time_write_one_decision_record() {
    let queue = Arc::new(YieldingQueue(MemoryApprovals::default()));
    let audit = Arc::new(MemoryAuditLog::default());
    let service = ApprovalService::new(queue.clone(), rbac(), audit.clone());
    let request = approval(responder(), 1);
    queue.submit(request.clone()).await.unwrap();

    let (alice, bob) = (alice(), bob());
    let (first, second) = tokio::join!(
        service.decide(request.id, true, &alice, None),
        service.decide(request.id, false, &bob, None),
    );
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        other => panic!("exactly one decision must succeed: {other:?}"),
    };
    assert!(matches!(loser, Error::InvalidInput(_)), "{loser:?}");
    assert_eq!(queue.get(request.id).await.unwrap(), Some(winner.clone()));

    let records = audit.records();
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [AuditKind::ApprovalDecided]
    );
    assert_eq!(
        Some(records[0].actor.as_str()),
        winner.decided_by.as_deref()
    );
}
