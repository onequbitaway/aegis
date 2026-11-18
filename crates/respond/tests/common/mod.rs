//! Helpers that the integration tests share.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_contracts::action::{ActionConnector, ActionKind, ActionRequest};
use aegis_contracts::audit::{AuditKind, AuditRecord};
use aegis_contracts::common::{
    DetectionId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::event::attr;
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_respond::{ActionRegistry, Dispatcher};
use aegis_testkit::fixtures::{
    ROGUE_APP_ID, ROGUE_PRINCIPAL_ID, SPRAY_IP, TENANT, VICTIM_USER_ID, base_time, expected,
};
use aegis_testkit::{
    MemoryApprovals, MemoryAuditLog, MemoryBus, MemoryIncidents, RecordingConnector, StaticPolicy,
};
use serde_json::json;

/// The credential that the attacker adds in the recorded attack log.
pub const ROGUE_CREDENTIAL_ID: &str = "credential-1";

/// Makes a request with no incident and no evidence.
pub fn request(kind: ActionKind, target: EntityRef) -> ActionRequest {
    ActionRequest::new(
        kind,
        target,
        "responder",
        "Contain the rogue service principal.",
    )
}

/// Returns the principal of the responder agent.
pub fn responder() -> Principal {
    Principal::new("responder", PrincipalKind::Agent, &["agent"])
}

/// Returns the rogue service principal of the recorded attack log.
pub fn rogue_principal() -> EntityRef {
    EntityRef::new(EntityKind::ServicePrincipal, ROGUE_PRINCIPAL_ID)
        .with_name("Sync Helper")
        .with_tenant(TENANT)
}

/// Returns the user that the password spray finds in the recorded attack log.
pub fn victim_user() -> EntityRef {
    EntityRef::new(EntityKind::User, VICTIM_USER_ID)
        .with_name("dana@contoso.example")
        .with_tenant(TENANT)
}

/// Returns the address that the password spray comes from.
pub fn spray_address() -> EntityRef {
    EntityRef::new(EntityKind::IpAddress, SPRAY_IP.to_string())
}

fn detection(
    rule_id: &str,
    title: &str,
    technique: AttackTechnique,
    entities: Vec<EntityRef>,
    attributes: BTreeMap<String, serde_json::Value>,
) -> Detection {
    Detection {
        id: DetectionId::new(),
        rule_id: rule_id.to_owned(),
        title: title.to_owned(),
        description: format!("{title}."),
        severity: Severity::High,
        verdict: Verdict::Malicious,
        tier: DetectionTier::Deterministic,
        time: base_time(),
        attack: vec![technique],
        event_ids: Vec::new(),
        entities,
        tenant: Some(TENANT.to_owned()),
        attributes,
    }
}

/// Returns an incident with the shape that the recorded attack log gives.
///
/// The incident has the rogue service principal, its application, the compromised user, and
/// the spray address. Its detections carry the expected ATT&CK techniques.
pub fn rogue_incident() -> Incident {
    let spray = AttackTechnique::new(
        "credential-access",
        expected::PASSWORD_SPRAY,
        "Password Spraying",
    );
    let consent = AttackTechnique::new(
        "credential-access",
        expected::CONSENT_GRANT,
        "Steal Application Access Token",
    );
    let credential = AttackTechnique::new(
        "persistence",
        expected::CREDENTIAL_ADD,
        "Additional Cloud Credentials",
    );
    let role = AttackTechnique::new(
        "privilege-escalation",
        expected::ROLE_ASSIGN,
        "Additional Cloud Roles",
    );
    let detections = vec![
        detection(
            "velocity.sign_in_burst",
            "Password spray from one address",
            spray.clone(),
            vec![spray_address(), victim_user()],
            BTreeMap::from([("count".to_owned(), json!(600))]),
        ),
        detection(
            "identity.consent_to_privileged_scopes",
            "Consent to privileged scopes",
            consent.clone(),
            vec![
                victim_user(),
                EntityRef::new(EntityKind::Application, ROGUE_APP_ID).with_name("Sync Helper"),
            ],
            BTreeMap::new(),
        ),
        detection(
            "velocity.credential_after_grant",
            "New credential immediately after a grant",
            credential.clone(),
            vec![rogue_principal()],
            BTreeMap::from([(attr::CREDENTIAL_ID.to_owned(), json!(ROGUE_CREDENTIAL_ID))]),
        ),
        detection(
            "identity.self_assigned_privileged_role",
            "Service principal assigns a privileged role to itself",
            role.clone(),
            vec![rogue_principal()],
            BTreeMap::new(),
        ),
    ];
    Incident {
        id: IncidentId::new(),
        title: "Rogue service principal after a password spray".to_owned(),
        summary: "A password spray found one account. The account consented to a rogue \
                  application. The service principal of the application has a new credential \
                  and a privileged role."
            .to_owned(),
        severity: Severity::Critical,
        status: IncidentStatus::Open,
        created_at: base_time(),
        updated_at: base_time(),
        tenant: Some(TENANT.to_owned()),
        detections,
        entities: vec![
            rogue_principal(),
            EntityRef::new(EntityKind::Application, ROGUE_APP_ID).with_name("Sync Helper"),
            victim_user(),
            spray_address(),
        ],
        attack: vec![spray, consent, credential, role],
        timeline: Vec::new(),
    }
}

/// Returns an open incident in the fixture tenant with these techniques and entities.
///
/// The incident has no detections.
pub fn incident_with(
    severity: Severity,
    techniques: &[&str],
    entities: Vec<EntityRef>,
) -> Incident {
    Incident {
        id: IncidentId::new(),
        title: "Test incident".to_owned(),
        summary: "An incident for a test.".to_owned(),
        severity,
        status: IncidentStatus::Open,
        created_at: base_time(),
        updated_at: base_time(),
        tenant: Some(TENANT.to_owned()),
        detections: Vec::new(),
        entities,
        attack: techniques
            .iter()
            .map(|id| AttackTechnique::new("tactic", *id, "Technique"))
            .collect(),
        timeline: Vec::new(),
    }
}

/// Returns the directory of the sample playbooks in the repository.
pub fn sample_playbook_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../playbooks")
}

/// One dispatcher with in-memory services and recording connectors.
pub struct Stack {
    /// The dispatcher under test.
    pub dispatcher: Arc<Dispatcher>,
    /// The audit log of the dispatcher.
    pub audit: Arc<MemoryAuditLog>,
    /// The approval queue of the dispatcher.
    pub approvals: Arc<MemoryApprovals>,
    /// The bus of the dispatcher.
    pub bus: Arc<MemoryBus>,
    /// The incident store of the dispatcher.
    pub incidents: Arc<MemoryIncidents>,
    /// A connector for the identity actions.
    pub identity: Arc<RecordingConnector>,
    /// A connector for `block_ip`.
    pub firewall: Arc<RecordingConnector>,
    /// A connector for `notify` and `open_ticket`.
    pub chat: Arc<RecordingConnector>,
}

/// Returns the three recording connectors of a [`Stack`].
pub fn recording_connectors() -> (
    Arc<RecordingConnector>,
    Arc<RecordingConnector>,
    Arc<RecordingConnector>,
) {
    let identity = Arc::new(RecordingConnector::new(
        "identity",
        vec![
            ActionKind::DisableServicePrincipal,
            ActionKind::DisableUser,
            ActionKind::KillSession,
            ActionKind::RevokeCredential,
            ActionKind::RotateCredential,
        ],
    ));
    let firewall = Arc::new(RecordingConnector::new(
        "firewall",
        vec![ActionKind::BlockIp],
    ));
    let chat = Arc::new(RecordingConnector::new(
        "chat",
        vec![ActionKind::Notify, ActionKind::OpenTicket],
    ));
    (identity, firewall, chat)
}

impl Stack {
    /// Makes a stack with the policy `policy`. The global dry-run switch is `dry_run`.
    pub fn new(policy: StaticPolicy, dry_run: bool) -> Self {
        let (identity, firewall, chat) = recording_connectors();
        let mut registry = ActionRegistry::new();
        for connector in [&identity, &firewall, &chat] {
            let connector: Arc<dyn ActionConnector> = connector.clone();
            registry.register(connector).unwrap();
        }
        let audit = Arc::new(MemoryAuditLog::default());
        let approvals = Arc::new(MemoryApprovals::default());
        let bus = Arc::new(MemoryBus::default());
        let incidents = Arc::new(MemoryIncidents::default());
        let dispatcher = Arc::new(
            Dispatcher::builder(
                Arc::new(registry),
                Arc::new(policy),
                approvals.clone(),
                audit.clone(),
            )
            .incidents(incidents.clone())
            .bus(bus.clone())
            .dry_run(dry_run)
            .build(),
        );
        Self {
            dispatcher,
            audit,
            approvals,
            bus,
            incidents,
            identity,
            firewall,
            chat,
        }
    }

    /// Returns the kinds of the audit records, in order.
    pub fn audit_kinds(&self) -> Vec<AuditKind> {
        self.audit
            .records()
            .iter()
            .map(|record| record.kind)
            .collect()
    }
}

/// Returns the audit records that have an evidence link to the action `request`.
pub fn records_for(records: &[AuditRecord], request: &ActionRequest) -> Vec<AuditRecord> {
    let link = EvidenceRef::new(EvidenceKind::Action, request.id);
    records
        .iter()
        .filter(|record| {
            record
                .evidence
                .iter()
                .any(|item| item.kind == link.kind && item.id == link.id)
        })
        .cloned()
        .collect()
}
