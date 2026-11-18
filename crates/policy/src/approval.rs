//! The approval service.
//!
//! [`ApprovalService`] is the only path by which a person decides a gated action. It
//! checks the permission of the person, applies the approval rules, writes the audit
//! record, and then records the decision in the queue.
//!
//! # Order of the steps
//!
//! The service writes the [`AuditKind::ApprovalDecided`] record before it records the
//! decision in the queue. Thus no decision takes effect without an audit record. If the
//! audit log is not available, the request stays pending.
//!
//! If the queue then refuses the decision, the service writes a second record with
//! [`AuditKind::Other`]. This record says that the decision did not take effect, and it
//! links to the first record.

use std::sync::Arc;

use aegis_contracts::action::ActionKind;
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog, AuditRecord};
use aegis_contracts::common::{
    ActionId, ApprovalId, AuditId, EntityRef, EvidenceKind, EvidenceRef, IncidentId,
};
use aegis_contracts::policy::{
    ApprovalQueue, ApprovalRequest, ApprovalStatus, Principal, PrincipalKind,
};
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::rbac::{Permission, Rbac};

/// The name that the service uses as the actor of the audit records that it writes for
/// itself.
pub const SERVICE_ACTOR: &str = "approval-service";

/// The permissions that let a principal read approval requests. One of them is sufficient.
const READ_PERMISSIONS: [Permission; 2] = [Permission::ViewIncidents, Permission::ApproveActions];

/// The rules that the service applies to each decision, after the permission check.
///
/// This type is also the table of the approval service in the AEGIS configuration file. A
/// rule that the table does not name is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalRules {
    /// With `true`, the principal that requested an action cannot approve it. The
    /// principal can reject it.
    ///
    /// The service compares principal identifiers without regard to ASCII letter case.
    pub four_eyes: bool,
    /// With `true`, only a principal of the kind [`PrincipalKind::Human`] can decide.
    pub humans_only: bool,
}

impl Default for ApprovalRules {
    /// Both rules are on.
    fn default() -> Self {
        Self {
            four_eyes: true,
            humans_only: true,
        }
    }
}

/// The service that lists approval requests and records the decisions of persons.
///
/// Refer to the [module documentation](self) for the order of the steps.
pub struct ApprovalService {
    queue: Arc<dyn ApprovalQueue>,
    rbac: Arc<Rbac>,
    audit: Arc<dyn AuditLog>,
    rules: ApprovalRules,
    /// Decisions run one at a time, so that two decisions on one request cannot both
    /// write an audit record.
    decisions: tokio::sync::Mutex<()>,
}

impl ApprovalService {
    /// Makes a service with the default [`ApprovalRules`].
    pub fn new(
        queue: Arc<dyn ApprovalQueue>,
        rbac: impl Into<Arc<Rbac>>,
        audit: Arc<dyn AuditLog>,
    ) -> Self {
        Self {
            queue,
            rbac: rbac.into(),
            audit,
            rules: ApprovalRules::default(),
            decisions: tokio::sync::Mutex::new(()),
        }
    }

    /// Sets the approval rules.
    #[must_use]
    pub fn with_rules(mut self, rules: ApprovalRules) -> Self {
        self.rules = rules;
        self
    }

    /// Returns the approval rules.
    #[must_use]
    pub fn rules(&self) -> ApprovalRules {
        self.rules
    }

    /// Lists the requests that have no decision, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if `principal` has neither
    /// [`Permission::ViewIncidents`] nor [`Permission::ApproveActions`].
    pub async fn pending(&self, principal: &Principal) -> Result<Vec<ApprovalRequest>> {
        self.rbac.check_any(principal, &READ_PERMISSIONS)?;
        self.queue.pending().await
    }

    /// Reads one request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if `principal` has neither
    /// [`Permission::ViewIncidents`] nor [`Permission::ApproveActions`]. Returns
    /// [`Error::NotFound`] if the request does not exist.
    pub async fn get(&self, id: ApprovalId, principal: &Principal) -> Result<ApprovalRequest> {
        self.rbac.check_any(principal, &READ_PERMISSIONS)?;
        self.find(id).await
    }

    /// Records the decision of `principal` on the request `id`.
    ///
    /// `approve` is `true` to approve the action and `false` to reject it. The result is
    /// the request with the decision.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` does not have
    ///   [`Permission::ApproveActions`], or an approval rule does not permit the decision.
    /// - [`Error::NotFound`] if the request does not exist.
    /// - [`Error::InvalidInput`] if the request already has a decision.
    /// - The error of the audit log if the audit record cannot be written. Then the request
    ///   stays pending.
    /// - The error of the queue if the queue refuses the decision.
    pub async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalRequest> {
        self.authorize(principal).inspect_err(|error| {
            tracing::warn!(approval = %id, principal = %principal.id, %error, "refused a decision");
        })?;
        let _one_at_a_time = self.decisions.lock().await;
        let request = self.find(id).await?;
        if request.status != ApprovalStatus::Pending {
            return Err(Error::InvalidInput(format!(
                "approval request {id} already has a decision"
            )));
        }
        if approve && self.rules.four_eyes && requested(&request, principal) {
            tracing::warn!(approval = %id, principal = %principal.id, "refused a decision: four-eyes rule");
            return Err(Error::Unauthorized(format!(
                "principal {} requested the action of approval request {id} and cannot \
                 approve it (four-eyes rule)",
                principal.id
            )));
        }

        let evidence = evidence_links(&request);
        let entry = decision_entry(&request, approve, principal, note.as_deref(), &evidence)?;
        let record = self.audit.append(entry).await?;
        match self.queue.decide(id, approve, principal, note).await {
            Ok(decided) => {
                tracing::info!(approval = %id, principal = %principal.id, approve, "recorded a decision");
                Ok(decided)
            }
            Err(error) => {
                self.void(&request, principal, &record, &error, evidence)
                    .await;
                Err(error)
            }
        }
    }

    fn authorize(&self, principal: &Principal) -> Result<()> {
        self.rbac.check(principal, Permission::ApproveActions)?;
        if self.rules.humans_only && principal.kind != PrincipalKind::Human {
            return Err(Error::Unauthorized(format!(
                "principal {} is not a person, and only a person can decide an approval \
                 request",
                principal.id
            )));
        }
        Ok(())
    }

    async fn find(&self, id: ApprovalId) -> Result<ApprovalRequest> {
        self.queue
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("approval request {id}")))
    }

    /// Writes the record that says that the decision in `record` did not take effect.
    async fn void(
        &self,
        request: &ApprovalRequest,
        principal: &Principal,
        record: &AuditRecord,
        cause: &Error,
        mut evidence: Vec<EvidenceRef>,
    ) {
        evidence.push(
            EvidenceRef::new(EvidenceKind::AuditRecord, record.id)
                .with_note("The decision record that did not take effect."),
        );
        let payload = serde_json::to_value(VoidPayload {
            approval_id: request.id,
            action_id: request.action.id,
            incident_id: request.action.incident_id,
            void_record: record.id,
            void_sequence: record.sequence,
            cause: cause.to_string(),
        });
        let appended = match payload {
            Ok(payload) => {
                let entry = AuditEntry::new(
                    AuditKind::Other,
                    SERVICE_ACTOR,
                    format!(
                        "The decision of {} on approval request {} did not take effect.",
                        principal.id, request.id
                    ),
                )
                .with_payload(payload)
                .with_evidence(evidence);
                self.audit.append(entry).await.map(|_| ())
            }
            Err(error) => Err(Error::from(error)),
        };
        // The caller gets the error of the queue, which is the cause. This second failure
        // goes to the log, because one call can return only one error.
        if let Err(error) = appended {
            tracing::error!(
                approval = %request.id,
                void_sequence = record.sequence,
                %error,
                "the audit log holds a decision record that did not take effect, and the correction record was not written"
            );
        }
    }
}

/// Returns `true` if `principal` requested the action of `request`.
fn requested(request: &ApprovalRequest, principal: &Principal) -> bool {
    let same = |other: &str| principal.id.trim().eq_ignore_ascii_case(other.trim());
    same(&request.requested_by.id) || same(&request.action.requested_by)
}

/// Returns the links from a decision record to the action, the incident, and the evidence
/// of the action.
fn evidence_links(request: &ApprovalRequest) -> Vec<EvidenceRef> {
    let mut evidence = vec![
        EvidenceRef::new(EvidenceKind::Action, request.action.id)
            .with_note("The action that the decision is about."),
    ];
    if let Some(incident) = request.action.incident_id {
        evidence.push(
            EvidenceRef::new(EvidenceKind::Incident, incident)
                .with_note("The incident that the action responds to."),
        );
    }
    for item in &request.action.evidence {
        let known = evidence
            .iter()
            .any(|link| link.kind == item.kind && link.id == item.id);
        if !known {
            evidence.push(item.clone());
        }
    }
    evidence
}

#[derive(Serialize)]
struct DecisionPayload<'a> {
    approval_id: ApprovalId,
    action_id: ActionId,
    incident_id: Option<IncidentId>,
    decision: ApprovalStatus,
    decided_by: &'a Principal,
    requested_by: &'a str,
    note: Option<&'a str>,
    action_kind: &'a ActionKind,
    target: &'a EntityRef,
    dry_run: bool,
}

#[derive(Serialize)]
struct VoidPayload {
    approval_id: ApprovalId,
    action_id: ActionId,
    incident_id: Option<IncidentId>,
    void_record: AuditId,
    void_sequence: u64,
    cause: String,
}

fn decision_entry(
    request: &ApprovalRequest,
    approve: bool,
    principal: &Principal,
    note: Option<&str>,
    evidence: &[EvidenceRef],
) -> Result<AuditEntry> {
    let (decision, verb) = if approve {
        (ApprovalStatus::Approved, "approved")
    } else {
        (ApprovalStatus::Rejected, "rejected")
    };
    let payload = serde_json::to_value(DecisionPayload {
        approval_id: request.id,
        action_id: request.action.id,
        incident_id: request.action.incident_id,
        decision,
        decided_by: principal,
        requested_by: &request.requested_by.id,
        note,
        action_kind: &request.action.kind,
        target: &request.action.target,
        dry_run: request.action.dry_run,
    })?;
    let summary = format!(
        "{} {verb} the action {} on {}.",
        principal.id,
        kind_name(&request.action.kind),
        request.action.target.id
    );
    Ok(
        AuditEntry::new(AuditKind::ApprovalDecided, principal.id.clone(), summary)
            .with_payload(payload)
            .with_evidence(evidence.to_vec()),
    )
}

/// Returns the name of an action kind as the contract writes it, for example `block_ip`.
fn kind_name(kind: &ActionKind) -> String {
    match kind {
        ActionKind::Custom(name) => format!("custom:{name}"),
        other => match serde_json::to_value(other) {
            Ok(serde_json::Value::String(name)) => name,
            _ => format!("{other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::ActionRequest;
    use aegis_contracts::common::EntityKind;
    use aegis_contracts::policy::{ActionTier, PolicyDecision, PolicyEffect};
    use chrono::Utc;

    use super::*;

    fn request(requested_by: &str) -> ApprovalRequest {
        let action = ActionRequest::new(
            ActionKind::DisableUser,
            EntityRef::new(EntityKind::User, "user-1"),
            requested_by,
            "Test.",
        );
        ApprovalRequest {
            id: ApprovalId::new(),
            requested_by: Principal::new(requested_by, PrincipalKind::Agent, &["agent"]),
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
            action,
        }
    }

    #[test]
    fn the_requester_check_ignores_letter_case_and_outer_spaces() {
        let request = request("Alice@Example.com");
        let principal = |id: &str| Principal::new(id, PrincipalKind::Human, &[]);
        assert!(requested(&request, &principal("alice@example.com")));
        assert!(requested(&request, &principal(" ALICE@EXAMPLE.COM ")));
        assert!(!requested(&request, &principal("alice@example.org")));
        assert!(!requested(&request, &principal("alice")));
    }

    #[test]
    fn the_requester_check_reads_the_principal_and_the_action() {
        let mut request = request("responder");
        request.action.requested_by = "playbook:contain".to_owned();
        let principal = |id: &str| Principal::new(id, PrincipalKind::Human, &[]);
        assert!(requested(&request, &principal("responder")));
        assert!(requested(&request, &principal("playbook:contain")));
        assert!(!requested(&request, &principal("bob@example.com")));
    }

    #[test]
    fn the_links_start_with_the_action_and_have_no_duplicates() {
        let mut request = request("responder");
        let incident = IncidentId::new();
        request.action.incident_id = Some(incident);
        request.action.evidence = vec![
            EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("cause"),
            EvidenceRef::new(EvidenceKind::Incident, incident),
            EvidenceRef::new(EvidenceKind::Detection, "det-1"),
        ];
        let links: Vec<(EvidenceKind, String)> = evidence_links(&request)
            .into_iter()
            .map(|link| (link.kind, link.id))
            .collect();
        assert_eq!(
            links,
            [
                (EvidenceKind::Action, request.action.id.to_string()),
                (EvidenceKind::Incident, incident.to_string()),
                (EvidenceKind::Detection, "det-1".to_owned()),
            ]
        );
    }

    #[test]
    fn the_kind_name_is_the_wire_name() {
        assert_eq!(
            kind_name(&ActionKind::DisableServicePrincipal),
            "disable_service_principal"
        );
        assert_eq!(kind_name(&ActionKind::BlockIp), "block_ip");
        assert_eq!(
            kind_name(&ActionKind::Custom("quarantine_mail".to_owned())),
            "custom:quarantine_mail"
        );
    }
}
