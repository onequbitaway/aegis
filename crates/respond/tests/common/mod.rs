//! Helpers that the integration tests share.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditRecord};
use aegis_contracts::common::{
    DetectionId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::event::attr;
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use aegis_respond::revert::REVERT_AFTER_PARAMETER;
use aegis_respond::{ActionRegistry, Dispatcher};
use aegis_testkit::fixtures::{
    ROGUE_APP_ID, ROGUE_PRINCIPAL_ID, SPRAY_IP, TENANT, VICTIM_USER_ID, base_time, expected,
};
use aegis_testkit::{
    MemoryApprovals, MemoryAuditLog, MemoryBus, MemoryIncidents, RecordingConnector, StaticPolicy,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};

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

/// Returns the principal of the playbook engine.
pub fn playbook_engine() -> Principal {
    Principal::new("playbook-engine", PrincipalKind::System, &["playbook"])
}

/// Returns a person who can approve and confirm.
pub fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

/// Sets a timed revert of `seconds` on the request.
pub fn timed(mut request: ActionRequest, seconds: u64) -> ActionRequest {
    request
        .parameters
        .insert(REVERT_AFTER_PARAMETER.to_owned(), json!(seconds));
    request
}

/// Returns the audit records of the type `Other` with this value of `event`.
pub fn events(records: &[AuditRecord], event: &str) -> Vec<AuditRecord> {
    records
        .iter()
        .filter(|record| record.kind == AuditKind::Other && record.payload["event"] == event)
        .cloned()
        .collect()
}

/// Returns the audit records of a revert: the records with `operation: "revert"`.
pub fn revert_records(records: &[AuditRecord]) -> Vec<AuditRecord> {
    records
        .iter()
        .filter(|record| record.payload["operation"] == "revert")
        .cloned()
        .collect()
}

/// A connector with behavior that the test changes while it runs. It records each call.
///
/// The connector can undo its actions. A live call changes nothing real.
pub struct ToggleConnector {
    name: String,
    kinds: Vec<ActionKind>,
    reversible: AtomicBool,
    execute_error: Mutex<Option<String>>,
    revert_error: Mutex<Option<String>>,
    live_status: Mutex<ActionStatus>,
    revert_status: Mutex<ActionStatus>,
    details: Mutex<Value>,
    executed: Mutex<Vec<ActionRequest>>,
    reverted: Mutex<Vec<ActionRequest>>,
    hold_reverts: AtomicBool,
    revert_entered: tokio::sync::Semaphore,
    revert_release: tokio::sync::Semaphore,
}

impl ToggleConnector {
    /// Makes a connector that supports `kinds` and reports that it can undo each action.
    pub fn new(name: &str, kinds: Vec<ActionKind>) -> Self {
        Self {
            name: name.to_owned(),
            kinds,
            reversible: AtomicBool::new(true),
            execute_error: Mutex::default(),
            revert_error: Mutex::default(),
            live_status: Mutex::new(ActionStatus::Succeeded),
            revert_status: Mutex::new(ActionStatus::Succeeded),
            details: Mutex::new(json!({ "saved_state": "enabled" })),
            executed: Mutex::default(),
            reverted: Mutex::default(),
            hold_reverts: AtomicBool::new(false),
            revert_entered: tokio::sync::Semaphore::new(0),
            revert_release: tokio::sync::Semaphore::new(0),
        }
    }

    /// Makes each `revert` call wait until `release_reverts`.
    pub fn hold_reverts(&self) {
        self.hold_reverts.store(true, Ordering::SeqCst);
    }

    /// Waits until one `revert` call is in the connector and waits there.
    pub async fn revert_entered(&self) {
        self.revert_entered.acquire().await.unwrap().forget();
    }

    /// Lets the `revert` call that waits continue. Later calls do not wait.
    pub fn release_reverts(&self) {
        self.hold_reverts.store(false, Ordering::SeqCst);
        self.revert_release.add_permits(1);
    }

    /// Sets what the connector reports in `ActionOutcome::reversible`.
    pub fn set_reversible(&self, reversible: bool) {
        self.reversible.store(reversible, Ordering::SeqCst);
    }

    /// Makes each `execute` call fail with `Error::Unavailable`, or succeed again.
    pub fn fail_execute(&self, message: Option<&str>) {
        *self.execute_error.lock().unwrap() = message.map(str::to_owned);
    }

    /// Makes each `revert` call fail with `Error::Unavailable`, or succeed again.
    pub fn fail_revert(&self, message: Option<&str>) {
        *self.revert_error.lock().unwrap() = message.map(str::to_owned);
    }

    /// Sets the status of an `execute` call that is not a dry run.
    pub fn set_live_status(&self, status: ActionStatus) {
        *self.live_status.lock().unwrap() = status;
    }

    /// Sets the status of a `revert` call that is not a dry run.
    pub fn set_revert_status(&self, status: ActionStatus) {
        *self.revert_status.lock().unwrap() = status;
    }

    /// Returns each request that `execute` received, with the dry runs.
    pub fn executed(&self) -> Vec<ActionRequest> {
        self.executed.lock().unwrap().clone()
    }

    /// Returns the requests that `execute` received and that were not dry runs.
    pub fn changes(&self) -> Vec<ActionRequest> {
        self.executed()
            .into_iter()
            .filter(|request| !request.dry_run)
            .collect()
    }

    /// Returns the dry runs that `execute` received.
    pub fn dry_runs(&self) -> Vec<ActionRequest> {
        self.executed()
            .into_iter()
            .filter(|request| request.dry_run)
            .collect()
    }

    /// Returns each request that `revert` received.
    pub fn reverted(&self) -> Vec<ActionRequest> {
        self.reverted.lock().unwrap().clone()
    }

    fn outcome(&self, request: &ActionRequest, live: ActionStatus, verb: &str) -> ActionOutcome {
        let status = if request.dry_run {
            ActionStatus::Simulated
        } else {
            live
        };
        ActionOutcome {
            action_id: request.id,
            status,
            connector: self.name.clone(),
            message: format!("{verb} {:?} on {}.", request.kind, request.target.id),
            details: self.details.lock().unwrap().clone(),
            reversible: self.reversible.load(Ordering::SeqCst),
            completed_at: Utc::now(),
        }
    }
}

#[async_trait]
impl ActionConnector for ToggleConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: "test".to_owned(),
            product: "toggle".to_owned(),
            version: "0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        self.kinds.clone()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.executed.lock().unwrap().push(request.clone());
        if let Some(message) = self.execute_error.lock().unwrap().clone() {
            return Err(Error::Unavailable(message));
        }
        let status = *self.live_status.lock().unwrap();
        Ok(self.outcome(request, status, "Executed"))
    }

    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.reverted.lock().unwrap().push(request.clone());
        if self.hold_reverts.load(Ordering::SeqCst) {
            self.revert_entered.add_permits(1);
            let permit = self
                .revert_release
                .acquire()
                .await
                .map_err(|error| Error::other("toggle", error))?;
            permit.forget();
        }
        if let Some(message) = self.revert_error.lock().unwrap().clone() {
            return Err(Error::Unavailable(message));
        }
        let status = *self.revert_status.lock().unwrap();
        Ok(self.outcome(request, status, "Reverted"))
    }
}
