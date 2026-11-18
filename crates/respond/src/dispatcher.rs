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
//!
//! # Revert
//!
//! [`Dispatcher::revert`] undoes one executed action. A revert is a request of its own, with
//! the action type `{custom: revert}`. It goes through the same steps: an
//! [`AuditKind::ActionProposed`] record, the policy, the approval queue if policy requires
//! approval, the connector, and an [`AuditKind::ActionExecuted`] record. Each audit record
//! of a revert has `operation: "revert"` in its payload and an evidence link to the action
//! that the revert undoes.
//!
//! # Timed revert
//!
//! A request with the parameter `revert_after_seconds` asks for a timed revert. Refer to
//! [`revert`]. The dispatcher does these steps before the connector changes
//! the target:
//!
//! 1. It makes sure that the action type has an inverse. If not, the result is
//!    [`Error::InvalidInput`].
//! 2. It makes sure that it has a revert store. If not, the result is [`Error::Config`].
//! 3. It asks the connector for a dry run of the request. The connector must report that it
//!    can undo the action. If not, the result is [`Error::InvalidInput`].
//! 4. It writes the pending revert to the store. If the write fails, the action does not
//!    run.
//!
//! The dispatcher does step 3 also for each friction action. Refer to
//! [`friction`].

mod undo;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionOutcome, ActionRequest,
    ActionResult, ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::{ActionId, ApprovalId, EvidenceKind, EvidenceRef};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{
    ApprovalQueue, ApprovalRequest, ApprovalStatus, IncidentContext, PolicyDecision, PolicyEffect,
    PolicyEngine, PolicyInput, Principal,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use crate::friction;
use crate::lock;
use crate::names::{entity_label, error_payload, same_kind, snake_name};
use crate::registry::ActionRegistry;
use crate::revert::{
    self, Ledger, PendingRevert, PendingState, REVERT_AFTER_PARAMETER, RevertClock, RevertStore,
    add_seconds,
};

pub use undo::OPERATION as REVERT_OPERATION;
pub(crate) use undo::Refusal;

/// The audit actor of the records that the dispatcher writes for its own steps.
pub const DISPATCHER_ACTOR: &str = "dispatcher";

/// The policy name in a decision that the dispatcher makes when the policy engine fails.
pub const FAIL_CLOSED_POLICY: &str = "aegis.respond.fail_closed";

const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(120);
const AUDIT_PAGE_SIZE: usize = 512;
/// The largest number of entries in a set or a map that only makes a search faster.
const MAX_HINTS: usize = 8_192;

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
    /// The pending reverts. `None` if the dispatcher has no revert store.
    reverts: Option<Arc<Ledger>>,
    /// The sequence number of the proposal record of each recent request.
    proposal_sequences: Mutex<HashMap<ActionId, u64>>,
    /// The actions that a revert is in progress for.
    reverting: Mutex<HashSet<ActionId>>,
    /// The actions that this process reverted.
    reverted: Mutex<HashSet<ActionId>>,
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
    revert_store: Option<Arc<dyn RevertStore>>,
    revert_clock: Option<RevertClock>,
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

    /// Sets the store of the pending reverts.
    ///
    /// The dispatcher then accepts a request with a timed revert: the parameter
    /// `revert_after_seconds`. Give the dispatcher to a
    /// [`RevertScheduler`](crate::RevertScheduler), which does the reverts at their time.
    ///
    /// Without a store, a request with a timed revert does not run. The dispatcher returns
    /// [`Error::Config`] before the connector changes the target, because it cannot keep
    /// the pending revert.
    #[must_use]
    pub fn revert_store(mut self, store: Arc<dyn RevertStore>) -> Self {
        self.revert_store = Some(store);
        self
    }

    /// Sets the clock of the timed reverts. The default is a clock that starts at the
    /// present time.
    ///
    /// The dispatcher and its [`RevertScheduler`](crate::RevertScheduler) use the same
    /// clock. Without a revert store, the clock has no effect.
    #[must_use]
    pub fn revert_clock(mut self, clock: RevertClock) -> Self {
        self.revert_clock = Some(clock);
        self
    }

    /// Makes the dispatcher.
    #[must_use]
    pub fn build(self) -> Dispatcher {
        let reverts = self
            .revert_store
            .map(|store| Arc::new(Ledger::new(store, self.revert_clock.unwrap_or_default())));
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
            reverts,
            proposal_sequences: Mutex::default(),
            reverting: Mutex::default(),
            reverted: Mutex::default(),
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

/// Where the dispatcher stopped an action that no connector completed.
#[derive(Clone, Copy)]
enum Stopped<'a> {
    /// The dispatcher refused the request. The value is the connector, if the dispatcher
    /// selected one before.
    Refused(Option<&'a str>),
    /// No connector can do the action.
    NoConnector,
    /// The connector returned an error or did not answer in time.
    Connector(&'a str),
}

impl<'a> Stopped<'a> {
    fn connector(self) -> Option<&'a str> {
        match self {
            Self::Refused(connector) => connector,
            Self::NoConnector => None,
            Self::Connector(connector) => Some(connector),
        }
    }
}

/// An error from the checks before a connector call.
struct Halt {
    /// `true` if the dispatcher refused the request. `false` if the connector failed.
    refused: bool,
    error: Error,
}

impl Halt {
    fn refused(error: Error) -> Self {
        Self {
            refused: true,
            error,
        }
    }
}

/// The data that the dispatcher keeps for one request while it handles the request.
struct Pass {
    request: ActionRequest,
    evidence: Vec<EvidenceRef>,
    approval: Option<ApprovalRequest>,
    /// The action that this request undoes, if the request is a revert.
    undoes: Option<ActionRequest>,
}

impl Pass {
    fn new(request: ActionRequest, approval: Option<ApprovalRequest>) -> Self {
        let evidence = evidence_links(&request);
        Self {
            request,
            evidence,
            approval,
            undoes: None,
        }
    }

    /// Makes the pass of a revert request. `original` is the action that it undoes.
    fn revert(
        request: ActionRequest,
        approval: Option<ApprovalRequest>,
        original: ActionRequest,
    ) -> Self {
        Self {
            undoes: Some(original),
            ..Self::new(request, approval)
        }
    }

    fn entry(&self, kind: AuditKind, actor: &str, summary: String) -> AuditEntry {
        AuditEntry::new(kind, actor, summary).with_evidence(self.evidence.clone())
    }

    /// Returns the words that name the request in a summary, for example
    /// `action block_ip on ip_address 203.0.113.50`.
    fn title(&self) -> String {
        match &self.undoes {
            Some(original) => format!(
                "revert of the action {} on {}",
                snake_name(&original.kind),
                entity_label(&original.target)
            ),
            None => format!(
                "action {} on {}",
                snake_name(&self.request.kind),
                entity_label(&self.request.target)
            ),
        }
    }

    /// Adds the fields that mark the audit record of a revert to `payload`.
    fn mark(&self, mut payload: serde_json::Value) -> serde_json::Value {
        if let (Some(original), Some(fields)) = (&self.undoes, payload.as_object_mut()) {
            fields.insert("operation".to_owned(), json!(undo::OPERATION));
            fields.insert(
                "reverts".to_owned(),
                json!({
                    "action_id": original.id,
                    "kind": original.kind,
                    "target": original.target,
                }),
            );
        }
        payload
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
            revert_store: None,
            revert_clock: None,
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

    /// Returns the pending reverts of the dispatcher, if it has a revert store.
    pub(crate) fn ledger(&self) -> Option<&Arc<Ledger>> {
        self.reverts.as_ref()
    }

    /// Returns the audit log of the dispatcher.
    pub(crate) fn audit_log(&self) -> &dyn AuditLog {
        self.audit.as_ref()
    }

    /// Reads one approval request from the approval queue of the dispatcher.
    pub(crate) async fn approval(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>> {
        self.approvals.get(id).await
    }

    /// Runs the action of an approval request that a person approved.
    ///
    /// The dispatcher evaluates the policy again. If the policy now denies the action, the
    /// result is [`ActionDisposition::Denied`] and the approval stays available.
    ///
    /// One approval permits one connector call. A second call for the same approval fails,
    /// also when the first call returned an error.
    ///
    /// The approval request can also hold a revert that [`revert`](Self::revert) put in the
    /// queue. The dispatcher then undoes the action.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: the approval queue has no request with this identifier.
    /// - [`Error::InvalidInput`]: the request has no decision, or it ran before.
    /// - [`Error::Denied`]: a person rejected the request.
    /// - The error of the connector, if the connector call fails.
    /// - The errors of [`revert`](Self::revert), if the request is a revert.
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
        if revert::is_revert_request(&approval.action) {
            return self.resume_revert(approval, claim).await;
        }
        revert::check_request(&approval.action)?;

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
                "The policy evaluation failed. The dispatcher denies the {}.",
                pass.title()
            ),
            (None, PolicyEffect::Allow) => {
                format!("Policy permits the {}.", pass.title())
            }
            (None, PolicyEffect::RequireApproval) => {
                format!("Policy requires approval for the {}.", pass.title())
            }
            (None, PolicyEffect::Deny) => format!("Policy denies the {}.", pass.title()),
        };
        let payload = pass.mark(json!({
            "action_id": pass.request.id,
            "decision": decision,
            "fail_closed": failure.is_some(),
            "error": failure,
            "incident": input.incident,
            "approval": pass.approval_payload(),
        }));
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
                        "The {} waits for the approval {}.",
                        pass.title(),
                        approval.id
                    ),
                )
                .with_payload(pass.mark(json!({
                    "approval_id": approval.id,
                    "action_id": pass.request.id,
                    "dry_run": pass.request.dry_run,
                    "decision": decision,
                }))),
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
                self.record_failure(pass, Stopped::NoConnector, &error)
                    .await?;
                Err(error)
            }
        }
    }

    /// Calls a connector function with the execution time limit.
    async fn call<F>(&self, call: F, connector: &str, action_id: ActionId) -> Result<ActionOutcome>
    where
        F: Future<Output = Result<ActionOutcome>>,
    {
        match tokio::time::timeout(self.execution_timeout, call).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "connector {connector} did not complete the action {action_id} in {} seconds",
                self.execution_timeout.as_secs()
            ))),
        }
    }

    /// Saves the sequence number of the first proposal record of a request.
    ///
    /// The number only makes a later search in the audit log faster. The search must
    /// start at the first record of an identifier, so a later record with the same
    /// identifier does not replace the number.
    fn remember_proposal(&self, action_id: ActionId, sequence: u64) {
        let mut sequences = lock(&self.proposal_sequences);
        if sequences.len() >= MAX_HINTS && !sequences.contains_key(&action_id) {
            sequences.clear();
        }
        sequences.entry(action_id).or_insert(sequence);
    }

    /// Does the checks for a timed revert and for a friction action, before the connector
    /// changes the target. Stores the pending revert of a timed revert.
    ///
    /// Returns the pending revert that the function stored, if the request has a timed
    /// revert. A dry run and a revert have no pending revert.
    async fn arm(
        &self,
        pass: &Pass,
        connector: &dyn ActionConnector,
        name: &str,
    ) -> std::result::Result<Option<PendingRevert>, Halt> {
        if pass.request.dry_run || pass.undoes.is_some() {
            return Ok(None);
        }
        let request = &pass.request;
        let after = revert::revert_after(request).map_err(Halt::refused)?;
        if after.is_none() && !friction::is_friction(&request.kind) {
            return Ok(None);
        }
        if after.is_some() && self.reverts.is_none() {
            return Err(Halt::refused(Error::Config(format!(
                "the action {} has the parameter {REVERT_AFTER_PARAMETER}, but the dispatcher has no revert store, so it cannot keep the pending revert; the action did not run",
                request.id
            ))));
        }

        // The connector must say that it can undo the action. A dry run changes nothing.
        let mut probe = request.clone();
        probe.dry_run = true;
        let simulated = self
            .call(connector.execute(&probe), name, request.id)
            .await
            .map_err(|error| Halt {
                refused: false,
                error,
            })?;
        if simulated.status != ActionStatus::Simulated {
            return Err(Halt::refused(Error::Integrity(format!(
                "connector {name} did not obey the dry-run flag in the check before the action {}; examine the target",
                request.id
            ))));
        }
        if !simulated.reversible {
            let why = if after.is_some() {
                "an action with a timed revert must have an inverse"
            } else {
                "a friction action must have an inverse"
            };
            return Err(Halt::refused(Error::InvalidInput(format!(
                "connector {name} cannot undo the action {}; {why}; the action did not run",
                snake_name(&request.kind)
            ))));
        }

        let (Some(after), Some(ledger)) = (after, &self.reverts) else {
            return Ok(None);
        };
        let now = ledger.clock.now();
        let pending = PendingRevert {
            action_id: request.id,
            kind: request.kind.clone(),
            target: request.target.clone(),
            incident_id: request.incident_id,
            requested_by: request.requested_by.clone(),
            revert_after_seconds: after.as_secs(),
            armed_at: now,
            due_at: add_seconds(now, after.as_secs()),
            state: PendingState::Armed,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            approval_id: None,
            audit_sequence: lock(&self.proposal_sequences).get(&request.id).copied(),
        };
        ledger.store.put(pending.clone()).await.map_err(|error| {
            Halt::refused(same_kind(
                &error,
                format!(
                    "the dispatcher could not store the pending revert of the action {}, so the action did not run: {error}",
                    request.id
                ),
            ))
        })?;
        Ok(Some(pending))
    }

    /// Removes a pending revert that has no action to undo.
    ///
    /// If the store fails, the pending revert stays. The scheduler then finds at the revert
    /// time that the action did not change the target, and it closes the pending revert.
    async fn disarm(&self, pending: Option<&PendingRevert>) {
        let (Some(pending), Some(ledger)) = (pending, &self.reverts) else {
            return;
        };
        match ledger.store.remove(pending.action_id).await {
            Ok(_) => ledger.changed.notify_one(),
            Err(error) => tracing::warn!(
                action_id = %pending.action_id,
                %error,
                "could not remove the pending revert of an action that did not change the target"
            ),
        }
    }

    /// Sets the final state of the timed revert after the connector call.
    ///
    /// Returns the `timed_revert` field for the audit record of the execution.
    async fn settle(
        &self,
        pass: &Pass,
        armed: Option<PendingRevert>,
        outcome: &ActionOutcome,
    ) -> Option<serde_json::Value> {
        if pass.undoes.is_some() {
            return None;
        }
        let after = revert::revert_after(&pass.request).ok().flatten()?;
        let after_seconds = after.as_secs();
        let (Some(mut pending), Some(ledger)) = (armed, &self.reverts) else {
            return Some(json!({
                "after_seconds": after_seconds,
                "state": "not_scheduled",
                "reason": "The request was a dry run. A dry run has nothing to revert.",
            }));
        };
        if outcome.status != ActionStatus::Succeeded {
            self.disarm(Some(&pending)).await;
            return Some(json!({
                "after_seconds": after_seconds,
                "state": "not_scheduled",
                "reason": "The connector did not change the target, so there is nothing to revert.",
            }));
        }
        // The time of the revert starts when the connector completes the action.
        let armed_due = pending.due_at;
        pending.state = PendingState::Waiting;
        pending.due_at = add_seconds(ledger.clock.now(), after_seconds);
        let (due_at, store_error) = match ledger.store.put(pending.clone()).await {
            Ok(()) => (pending.due_at, None),
            Err(error) => {
                // The record from before the connector call stays in the store, so the
                // revert is not lost. It has the earlier revert time.
                tracing::warn!(
                    action_id = %pending.action_id,
                    %error,
                    "could not update the pending revert; the record from before the action stays"
                );
                (armed_due, Some(error.to_string()))
            }
        };
        ledger.changed.notify_one();
        Some(json!({
            "after_seconds": after_seconds,
            "state": "scheduled",
            "due_at": due_at,
            "store_error": store_error,
        }))
    }

    /// Calls the connector and writes the result to the audit log.
    async fn execute(&self, pass: &Pass) -> Result<ActionDisposition> {
        let connector = self.connector(pass).await?;
        let name = connector.info().name;
        let armed = match self.arm(pass, connector.as_ref(), &name).await {
            Ok(armed) => armed,
            Err(halt) => {
                let stopped = if halt.refused {
                    Stopped::Refused(Some(&name))
                } else {
                    Stopped::Connector(&name)
                };
                self.record_failure(pass, stopped, &halt.error).await?;
                return Err(halt.error);
            }
        };
        let result = self
            .call(connector.execute(&pass.request), &name, pass.request.id)
            .await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.disarm(armed.as_ref()).await;
                self.record_failure(pass, Stopped::Connector(&name), &error)
                    .await?;
                return Err(error);
            }
        };
        let mut extra = Vec::new();
        if let Some(timed) = self.settle(pass, armed, &outcome).await {
            extra.push(("timed_revert", timed));
        }
        self.finish(pass, &name, outcome, extra).await
    }

    /// Writes the audit record of a connector call that completed, and publishes the
    /// result. `extra` holds more fields for the payload of the record.
    async fn finish(
        &self,
        pass: &Pass,
        name: &str,
        outcome: ActionOutcome,
        extra: Vec<(&'static str, serde_json::Value)>,
    ) -> Result<ActionDisposition> {
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
                "Connector {name} did not obey the dry-run flag for the {}.",
                pass.title()
            ),
            (false, true) => format!(
                "Connector {name} simulated the {}. This was a dry run. Nothing changed.",
                pass.title()
            ),
            (false, false) => format!(
                "Connector {name} completed the {} with the status {}.",
                pass.title(),
                snake_name(&outcome.status)
            ),
        };
        let mut payload = pass.mark(json!({
            "action_id": pass.request.id,
            "kind": pass.request.kind,
            "target": pass.request.target,
            "connector": name,
            "dry_run": pass.request.dry_run,
            "dry_run_violation": violation,
            "outcome": outcome,
            "approval": pass.approval_payload(),
        }));
        if let Some(fields) = payload.as_object_mut() {
            for (key, value) in extra {
                fields.insert(key.to_owned(), value);
            }
        }
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
    async fn record_failure(&self, pass: &Pass, stopped: Stopped<'_>, error: &Error) -> Result<()> {
        let connector = stopped.connector();
        tracing::warn!(
            action_id = %pass.request.id,
            connector = connector.unwrap_or("none"),
            %error,
            "the action did not complete"
        );
        let summary = match stopped {
            Stopped::Connector(name) => {
                format!("Connector {name} could not complete the {}.", pass.title())
            }
            Stopped::NoConnector => format!("No connector can do the {}.", pass.title()),
            Stopped::Refused(_) => format!("The dispatcher refused the {}.", pass.title()),
        };
        let payload = pass.mark(json!({
            "action_id": pass.request.id,
            "kind": pass.request.kind,
            "target": pass.request.target,
            "connector": connector,
            "dry_run": pass.request.dry_run,
            "error": error_payload(error),
            "approval": pass.approval_payload(),
        }));
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
        let proposed = self
            .audit
            .append(
                pass.entry(
                    AuditKind::ActionProposed,
                    &principal.id,
                    format!("{} proposed the {}.", principal.id, pass.title()),
                )
                .with_payload(json!({
                    "action": pass.request,
                    "principal": principal,
                    "dry_run": pass.request.dry_run,
                    "dry_run_forced": forced,
                })),
            )
            .await?;
        self.remember_proposal(pass.request.id, proposed.sequence);
        // A request that is not valid stops here, before the policy and the connector.
        if let Err(error) = revert::check_request(&pass.request) {
            self.record_failure(&pass, Stopped::Refused(None), &error)
                .await?;
            return Err(error);
        }

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
