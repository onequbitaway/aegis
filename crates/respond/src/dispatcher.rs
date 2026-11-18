//! The dispatcher: the only path from an action request to a change in the environment.
//!
//! Each request goes through these steps:
//!
//! 1. The dispatcher writes an [`AuditKind::ActionProposed`] record.
//! 2. The policy engine evaluates the request. The dispatcher writes an
//!    [`AuditKind::PolicyDecision`] record.
//! 3. A denied request stops. A gated request goes to the approval queue.
//! 4. A permitted request goes to its connector. The dispatcher writes an
//!    [`AuditKind::ActionExecuted`] record with the outcome or the error.
//!
//! The dispatcher fails closed. An error from the policy engine or the incident store is a
//! denial. A request that the audit log cannot record does not run.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionOutcome, ActionRequest,
    ActionResult, ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::{ApprovalId, EvidenceKind, EvidenceRef};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{
    ApprovalQueue, ApprovalRequest, ApprovalStatus, IncidentContext, PolicyDecision, PolicyEffect,
    PolicyEngine, PolicyInput, Principal,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use crate::lock;
use crate::names::{entity_label, error_payload, snake_name};
use crate::registry::ActionRegistry;

/// The audit actor of the records that the dispatcher writes for its own steps.
pub const DISPATCHER_ACTOR: &str = "dispatcher";

/// The policy name in a decision that the dispatcher makes when the policy engine fails.
pub const FAIL_CLOSED_POLICY: &str = "aegis.respond.fail_closed";

const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(120);
const AUDIT_PAGE_SIZE: usize = 512;

/// Sends each action request through policy, approval, a connector, and the audit log.
///
/// Make a dispatcher with [`Dispatcher::builder`].
pub struct Dispatcher {
    registry: Arc<ActionRegistry>,
    policy: Arc<dyn PolicyEngine>,
    approvals: Arc<dyn ApprovalQueue>,
    audit: Arc<dyn AuditLog>,
    incidents: Option<Arc<dyn IncidentStore>>,
    bus: Option<Arc<dyn MessageBus>>,
    environment: serde_json::Value,
    execution_timeout: Duration,
    dry_run: AtomicBool,
    claimed: Mutex<HashSet<ApprovalId>>,
    approval_sequences: Mutex<HashMap<ApprovalId, u64>>,
}

/// Sets the optional parts of a [`Dispatcher`].
pub struct DispatcherBuilder {
    registry: Arc<ActionRegistry>,
    policy: Arc<dyn PolicyEngine>,
    approvals: Arc<dyn ApprovalQueue>,
    audit: Arc<dyn AuditLog>,
    incidents: Option<Arc<dyn IncidentStore>>,
    bus: Option<Arc<dyn MessageBus>>,
    environment: serde_json::Value,
    execution_timeout: Duration,
    dry_run: bool,
}

impl DispatcherBuilder {
    /// Sets the incident store. The dispatcher then gives the incident data to the policy.
    #[must_use]
    pub fn incidents(mut self, incidents: Arc<dyn IncidentStore>) -> Self {
        self.incidents = Some(incidents);
        self
    }

    /// Sets the message bus. The dispatcher then publishes each result as an
    /// [`ActionResult`] on [`subject::ACTION_RESULTS`], and each new approval request on
    /// [`subject::APPROVALS`].
    ///
    /// The dispatcher is the single publisher of [`subject::ACTION_RESULTS`].
    #[must_use]
    pub fn bus(mut self, bus: Arc<dyn MessageBus>) -> Self {
        self.bus = Some(bus);
        self
    }

    /// Sets the operator data that the policy reads as `input.environment`.
    #[must_use]
    pub fn environment(mut self, environment: serde_json::Value) -> Self {
        self.environment = environment;
        self
    }

    /// Sets the global dry-run switch. The default is `false`.
    ///
    /// With `true`, the dispatcher sets `dry_run` on each request. No connector changes the
    /// environment.
    #[must_use]
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Sets the maximum time for one connector call. The default is 120 seconds.
    #[must_use]
    pub fn execution_timeout(mut self, timeout: Duration) -> Self {
        self.execution_timeout = timeout;
        self
    }

    /// Makes the dispatcher.
    #[must_use]
    pub fn build(self) -> Dispatcher {
        Dispatcher {
            registry: self.registry,
            policy: self.policy,
            approvals: self.approvals,
            audit: self.audit,
            incidents: self.incidents,
            bus: self.bus,
            environment: self.environment,
            execution_timeout: self.execution_timeout,
            dry_run: AtomicBool::new(self.dry_run),
            claimed: Mutex::default(),
            approval_sequences: Mutex::default(),
        }
    }
}

/// Removes the claim on an approval request when a resume stops before the connector call.
struct Claim<'a> {
    claimed: &'a Mutex<HashSet<ApprovalId>>,
    id: ApprovalId,
    keep: bool,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.keep {
            lock(self.claimed).remove(&self.id);
        }
    }
}

/// The data that the dispatcher keeps for one request while it handles the request.
struct Pass {
    request: ActionRequest,
    evidence: Vec<EvidenceRef>,
    approval: Option<ApprovalRequest>,
}

impl Pass {
    fn new(request: ActionRequest, approval: Option<ApprovalRequest>) -> Self {
        let evidence = evidence_links(&request);
        Self {
            request,
            evidence,
            approval,
        }
    }

    fn entry(&self, kind: AuditKind, actor: &str, summary: String) -> AuditEntry {
        AuditEntry::new(kind, actor, summary).with_evidence(self.evidence.clone())
    }

    fn label(&self) -> String {
        format!(
            "{} on {}",
            snake_name(&self.request.kind),
            entity_label(&self.request.target)
        )
    }

    fn approval_payload(&self) -> serde_json::Value {
        match &self.approval {
            Some(approval) => json!({
                "id": approval.id,
                "decided_by": approval.decided_by,
                "decided_at": approval.decided_at,
            }),
            None => serde_json::Value::Null,
        }
    }
}

/// Returns the evidence links for the audit records of one request.
///
/// The links are the request itself, its incident, and the evidence that the request names.
fn evidence_links(request: &ActionRequest) -> Vec<EvidenceRef> {
    let mut links = vec![EvidenceRef::new(EvidenceKind::Action, request.id)];
    let same =
        |left: &EvidenceRef, right: &EvidenceRef| left.kind == right.kind && left.id == right.id;
    if let Some(incident_id) = request.incident_id {
        let incident = EvidenceRef::new(EvidenceKind::Incident, incident_id);
        if !request.evidence.iter().any(|item| same(item, &incident)) {
            links.push(incident);
        }
    }
    for item in &request.evidence {
        if !links.iter().any(|link| same(link, item)) {
            links.push(item.clone());
        }
    }
    links
}

impl Dispatcher {
    /// Starts a dispatcher with the four necessary services.
    #[must_use]
    pub fn builder(
        registry: Arc<ActionRegistry>,
        policy: Arc<dyn PolicyEngine>,
        approvals: Arc<dyn ApprovalQueue>,
        audit: Arc<dyn AuditLog>,
    ) -> DispatcherBuilder {
        DispatcherBuilder {
            registry,
            policy,
            approvals,
            audit,
            incidents: None,
            bus: None,
            environment: serde_json::Value::Null,
            execution_timeout: DEFAULT_EXECUTION_TIMEOUT,
            dry_run: false,
        }
    }

    /// Returns the state of the global dry-run switch.
    #[must_use]
    pub fn dry_run(&self) -> bool {
        self.dry_run.load(Ordering::SeqCst)
    }

    /// Sets the global dry-run switch.
    ///
    /// With `true`, the dispatcher sets `dry_run` on each request. No connector changes the
    /// environment.
    pub fn set_dry_run(&self, enabled: bool) {
        self.dry_run.store(enabled, Ordering::SeqCst);
    }

    /// Runs the action of an approval request that a person approved.
    ///
    /// The dispatcher evaluates the policy again. If the policy now denies the action, the
    /// result is [`ActionDisposition::Denied`] and the approval stays available.
    ///
    /// One approval permits one connector call. A second call for the same approval fails,
    /// also when the first call returned an error.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: the approval queue has no request with this identifier.
    /// - [`Error::InvalidInput`]: the request has no decision, or it ran before.
    /// - [`Error::Denied`]: a person rejected the request.
    /// - The error of the connector, if the connector call fails.
    pub async fn resume(&self, approval_id: ApprovalId) -> Result<ActionDisposition> {
        let approval = self
            .approvals
            .get(approval_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("approval request {approval_id}")))?;
        match approval.status {
            ApprovalStatus::Approved => {}
            ApprovalStatus::Pending => {
                return Err(Error::InvalidInput(format!(
                    "approval request {approval_id} has no decision"
                )));
            }
            ApprovalStatus::Rejected => {
                return Err(Error::Denied(format!(
                    "approval request {approval_id} was rejected"
                )));
            }
        }
        let already_ran = || {
            Error::InvalidInput(format!(
                "approval request {approval_id} already ran; one approval permits one action"
            ))
        };
        if !lock(&self.claimed).insert(approval_id) {
            return Err(already_ran());
        }
        let mut claim = Claim {
            claimed: &self.claimed,
            id: approval_id,
            keep: false,
        };
        if self.audit_has_execution(approval_id).await? {
            claim.keep = true;
            return Err(already_ran());
        }

        let mut request = approval.action.clone();
        if self.dry_run() {
            request.dry_run = true;
        }
        let principal = approval.requested_by.clone();
        let pass = Pass::new(request, Some(approval));
        let decision = self.decide(&pass, &principal).await?;
        if decision.effect == PolicyEffect::Deny {
            let disposition = ActionDisposition::Denied(decision);
            self.publish_result(&pass, &disposition).await;
            return Ok(disposition);
        }
        claim.keep = true;
        lock(&self.approval_sequences).remove(&approval_id);
        self.execute(&pass).await
    }

    /// Returns `true` if the audit log has an execution record for this approval.
    ///
    /// This check finds an execution from before a restart of the process.
    async fn audit_has_execution(&self, approval_id: ApprovalId) -> Result<bool> {
        let wanted = json!(approval_id);
        let mut from_sequence = lock(&self.approval_sequences)
            .get(&approval_id)
            .copied()
            .unwrap_or(1);
        loop {
            let page = self.audit.read(from_sequence, AUDIT_PAGE_SIZE).await?;
            let Some(last) = page.last() else {
                return Ok(false);
            };
            from_sequence = last.sequence + 1;
            let found = page.iter().any(|record| {
                record.kind == AuditKind::ActionExecuted
                    && record.payload["approval"]["id"] == wanted
            });
            if found {
                return Ok(true);
            }
        }
    }

    async fn incident_context(&self, request: &ActionRequest) -> Result<Option<IncidentContext>> {
        let (Some(store), Some(incident_id)) = (&self.incidents, request.incident_id) else {
            return Ok(None);
        };
        Ok(store
            .get(incident_id)
            .await?
            .map(|incident| IncidentContext {
                id: incident.id,
                severity: incident.severity,
                status: incident.status,
            }))
    }

    /// Evaluates the policy and writes the decision to the audit log.
    ///
    /// An error from the incident store or the policy engine gives a denial.
    async fn decide(&self, pass: &Pass, principal: &Principal) -> Result<PolicyDecision> {
        let mut input = PolicyInput::new(pass.request.clone(), principal.clone());
        input.environment = self.environment.clone();
        let evaluation = match self.incident_context(&pass.request).await {
            Ok(context) => {
                input.incident = context;
                self.policy.evaluate(&input).await
            }
            Err(error) => Err(error),
        };
        let (decision, failure) = match evaluation {
            Ok(decision) => (decision, None),
            Err(error) => {
                tracing::error!(
                    action_id = %pass.request.id,
                    %error,
                    "the policy evaluation failed; the action is denied"
                );
                let decision = PolicyDecision {
                    effect: PolicyEffect::Deny,
                    tier: input.default_tier,
                    reasons: vec![format!(
                        "The policy evaluation failed, so the dispatcher denies the action: {error}."
                    )],
                    policy: Some(FAIL_CLOSED_POLICY.to_owned()),
                    evaluated_at: Utc::now(),
                };
                (decision, Some(error_payload(&error)))
            }
        };
        let summary = match (&failure, decision.effect) {
            (Some(_), _) => format!(
                "The policy evaluation failed. The dispatcher denies the action {}.",
                pass.label()
            ),
            (None, PolicyEffect::Allow) => {
                format!("Policy permits the action {}.", pass.label())
            }
            (None, PolicyEffect::RequireApproval) => {
                format!("Policy requires approval for the action {}.", pass.label())
            }
            (None, PolicyEffect::Deny) => format!("Policy denies the action {}.", pass.label()),
        };
        let payload = json!({
            "action_id": pass.request.id,
            "decision": decision,
            "fail_closed": failure.is_some(),
            "error": failure,
            "incident": input.incident,
            "approval": pass.approval_payload(),
        });
        self.audit
            .append(
                pass.entry(AuditKind::PolicyDecision, DISPATCHER_ACTOR, summary)
                    .with_payload(payload),
            )
            .await?;
        Ok(decision)
    }

    /// Puts a gated request in the approval queue.
    async fn request_approval(
        &self,
        pass: &Pass,
        principal: &Principal,
        decision: PolicyDecision,
    ) -> Result<ActionDisposition> {
        let approval = ApprovalRequest {
            id: ApprovalId::new(),
            action: pass.request.clone(),
            requested_by: principal.clone(),
            decision: decision.clone(),
            status: ApprovalStatus::Pending,
            requested_at: Utc::now(),
            decided_by: None,
            decided_at: None,
            note: None,
        };
        self.approvals.submit(approval.clone()).await?;
        let record = self
            .audit
            .append(
                pass.entry(
                    AuditKind::ApprovalRequested,
                    DISPATCHER_ACTOR,
                    format!(
                        "The action {} waits for the approval {}.",
                        pass.label(),
                        approval.id
                    ),
                )
                .with_payload(json!({
                    "approval_id": approval.id,
                    "action_id": pass.request.id,
                    "dry_run": pass.request.dry_run,
                    "decision": decision,
                })),
            )
            .await?;
        lock(&self.approval_sequences).insert(approval.id, record.sequence);
        if let Some(bus) = &self.bus
            && let Err(error) = publish_json(bus.as_ref(), subject::APPROVALS, &approval).await
        {
            self.record_publish_failure(pass, subject::APPROVALS, &error)
                .await;
        }
        let disposition = ActionDisposition::PendingApproval {
            approval_id: approval.id,
            decision,
        };
        self.publish_result(pass, &disposition).await;
        Ok(disposition)
    }

    /// Finds the connector for the request. Writes an audit record if there is none.
    async fn connector(&self, pass: &Pass) -> Result<Arc<dyn ActionConnector>> {
        match self.registry.select(&pass.request.kind) {
            Ok(connector) => Ok(connector),
            Err(error) => {
                self.record_failure(pass, None, &error).await?;
                Err(error)
            }
        }
    }

    /// Calls the connector and writes the result to the audit log.
    async fn execute(&self, pass: &Pass) -> Result<ActionDisposition> {
        let connector = self.connector(pass).await?;
        let name = connector.info().name;
        let call = tokio::time::timeout(self.execution_timeout, connector.execute(&pass.request));
        let result = match call.await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "connector {name} did not complete the action {} in {} seconds",
                pass.request.id,
                self.execution_timeout.as_secs()
            ))),
        };
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.record_failure(pass, Some(&name), &error).await?;
                return Err(error);
            }
        };

        let violation = pass.request.dry_run && outcome.status == ActionStatus::Succeeded;
        if violation {
            tracing::error!(
                action_id = %pass.request.id,
                connector = %name,
                "the connector did not obey the dry-run flag"
            );
        }
        let summary = match (violation, pass.request.dry_run) {
            (true, _) => format!(
                "Connector {name} did not obey the dry-run flag for the action {}.",
                pass.label()
            ),
            (false, true) => format!(
                "Connector {name} simulated the action {}. This was a dry run. Nothing changed.",
                pass.label()
            ),
            (false, false) => format!(
                "Connector {name} completed the action {} with the status {}.",
                pass.label(),
                snake_name(&outcome.status)
            ),
        };
        let payload = json!({
            "action_id": pass.request.id,
            "kind": pass.request.kind,
            "target": pass.request.target,
            "connector": name,
            "dry_run": pass.request.dry_run,
            "dry_run_violation": violation,
            "outcome": outcome,
            "approval": pass.approval_payload(),
        });
        self.audit
            .append(
                pass.entry(AuditKind::ActionExecuted, DISPATCHER_ACTOR, summary)
                    .with_payload(payload),
            )
            .await
            .map_err(|error| {
                Error::Integrity(format!(
                    "connector {name} completed the action {} but the audit log did not record it: {error}",
                    pass.request.id
                ))
            })?;
        let disposition = ActionDisposition::Executed(outcome);
        self.publish_result(pass, &disposition).await;
        Ok(disposition)
    }

    /// Writes the audit record of an action that did not complete, and publishes the result.
    async fn record_failure(
        &self,
        pass: &Pass,
        connector: Option<&str>,
        error: &Error,
    ) -> Result<()> {
        tracing::warn!(
            action_id = %pass.request.id,
            connector = connector.unwrap_or("none"),
            %error,
            "the action did not complete"
        );
        let summary = match connector {
            Some(name) => format!(
                "Connector {name} could not complete the action {}.",
                pass.label()
            ),
            None => format!("No connector can do the action {}.", pass.label()),
        };
        let payload = json!({
            "action_id": pass.request.id,
            "kind": pass.request.kind,
            "target": pass.request.target,
            "connector": connector,
            "dry_run": pass.request.dry_run,
            "error": error_payload(error),
            "approval": pass.approval_payload(),
        });
        let audit = self
            .audit
            .append(
                pass.entry(AuditKind::ActionExecuted, DISPATCHER_ACTOR, summary)
                    .with_payload(payload),
            )
            .await;
        let failed = ActionDisposition::Executed(ActionOutcome {
            action_id: pass.request.id,
            status: ActionStatus::Failed,
            connector: connector.unwrap_or_default().to_owned(),
            message: error.to_string(),
            details: json!({ "error": error_payload(error) }),
            reversible: false,
            completed_at: Utc::now(),
        });
        self.publish_result(pass, &failed).await;
        audit.map(|_| ()).map_err(|audit_error| {
            Error::Integrity(format!(
                "the action {} failed ({error}) and the audit log did not record it: {audit_error}",
                pass.request.id
            ))
        })
    }

    /// Publishes a result on the bus. A bus failure does not change the result.
    ///
    /// The message holds the identifier of the request, because a denial and a pending
    /// approval do not hold it.
    async fn publish_result(&self, pass: &Pass, disposition: &ActionDisposition) {
        let Some(bus) = &self.bus else {
            return;
        };
        let result = ActionResult {
            action_id: pass.request.id,
            incident_id: pass.request.incident_id,
            disposition: disposition.clone(),
        };
        if let Err(error) = publish_json(bus.as_ref(), subject::ACTION_RESULTS, &result).await {
            self.record_publish_failure(pass, subject::ACTION_RESULTS, &error)
                .await;
        }
    }

    /// Writes a bus failure to the audit log, so that the missing message is visible.
    async fn record_publish_failure(&self, pass: &Pass, subject: &str, error: &Error) {
        tracing::warn!(
            action_id = %pass.request.id,
            subject,
            %error,
            "could not publish on the bus"
        );
        let entry = pass
            .entry(
                AuditKind::Other,
                DISPATCHER_ACTOR,
                format!(
                    "The dispatcher could not publish a message about the action {} on the bus.",
                    pass.request.id
                ),
            )
            .with_payload(json!({
                "action_id": pass.request.id,
                "subject": subject,
                "error": error_payload(error),
            }));
        if let Err(audit_error) = self.audit.append(entry).await {
            tracing::error!(
                action_id = %pass.request.id,
                error = %audit_error,
                "could not record the bus failure in the audit log"
            );
        }
    }
}

#[async_trait]
impl ActionDispatcher for Dispatcher {
    async fn dispatch(
        &self,
        mut request: ActionRequest,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        let forced = self.dry_run() && !request.dry_run;
        if self.dry_run() {
            request.dry_run = true;
        }
        let pass = Pass::new(request, None);
        self.audit
            .append(
                pass.entry(
                    AuditKind::ActionProposed,
                    &principal.id,
                    format!("{} proposed the action {}.", principal.id, pass.label()),
                )
                .with_payload(json!({
                    "action": pass.request,
                    "principal": principal,
                    "dry_run": pass.request.dry_run,
                    "dry_run_forced": forced,
                })),
            )
            .await?;

        let decision = self.decide(&pass, principal).await?;
        match decision.effect {
            PolicyEffect::Deny => {
                let disposition = ActionDisposition::Denied(decision);
                self.publish_result(&pass, &disposition).await;
                Ok(disposition)
            }
            PolicyEffect::RequireApproval => {
                self.connector(&pass).await?;
                self.request_approval(&pass, principal, decision).await
            }
            PolicyEffect::Allow => self.execute(&pass).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::ActionKind;
    use aegis_contracts::common::{EntityKind, EntityRef, IncidentId};

    use super::*;

    #[test]
    fn evidence_links_start_with_the_action_and_the_incident() {
        let incident_id = IncidentId::new();
        let mut request = ActionRequest::new(
            ActionKind::BlockIp,
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            "responder",
            "Test.",
        );
        request.incident_id = Some(incident_id);
        request.evidence = vec![EvidenceRef::new(EvidenceKind::Detection, "detection-1")];

        assert_eq!(
            evidence_links(&request),
            [
                EvidenceRef::new(EvidenceKind::Action, request.id),
                EvidenceRef::new(EvidenceKind::Incident, incident_id),
                EvidenceRef::new(EvidenceKind::Detection, "detection-1"),
            ]
        );
    }

    #[test]
    fn evidence_links_keep_the_note_of_the_request_and_have_no_duplicates() {
        let incident_id = IncidentId::new();
        let noted = EvidenceRef::new(EvidenceKind::Incident, incident_id).with_note("playbook");
        let mut request = ActionRequest::new(
            ActionKind::Notify,
            EntityRef::new(EntityKind::Other, "soc"),
            "responder",
            "Test.",
        );
        request.incident_id = Some(incident_id);
        request.evidence = vec![noted.clone(), noted.clone()];

        assert_eq!(
            evidence_links(&request),
            [EvidenceRef::new(EvidenceKind::Action, request.id), noted]
        );
    }
}
