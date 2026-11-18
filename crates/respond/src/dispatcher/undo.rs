//! The revert path of the dispatcher.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use aegis_contracts::action::{
    ActionConnector, ActionDisposition, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::AuditKind;
use aegis_contracts::common::{ActionId, EvidenceKind, EvidenceRef};
use aegis_contracts::policy::{ApprovalRequest, PolicyEffect, Principal};
use aegis_contracts::{Error, Result};
use serde_json::{Value, json};

use super::{AUDIT_PAGE_SIZE, Claim, Dispatcher, MAX_HINTS, Pass, Stopped};
use crate::lock;
use crate::names::{clean_text, entity_label, snake_name};
use crate::revert::{
    self, EXECUTION_DETAILS_PARAMETER, REVERT_ACTION, REVERT_AFTER_PARAMETER, REVERTS_PARAMETER,
};

/// The value of the field `operation` in the payload of each audit record of a revert.
pub const OPERATION: &str = "revert";

/// The largest number of characters of the reason of a revert.
const MAX_REASON_LENGTH: usize = 2_000;

/// Why the dispatcher did not start a revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The audit log has no execution of the action.
    NotFound,
    /// The action did not change the target: a dry run, a failure, or no change.
    NothingToRevert,
    /// A revert of the action succeeded before.
    AlreadyReverted,
    /// A different cause, for example a connector that cannot undo the action.
    Other,
}

/// An error from the revert path, with its cause for the scheduler.
#[derive(Debug)]
pub(crate) struct RevertFailure {
    /// Why the revert did not start.
    pub(crate) refusal: Refusal,
    /// The error for the caller.
    pub(crate) error: Error,
}

impl RevertFailure {
    fn new(refusal: Refusal, error: Error) -> Self {
        Self { refusal, error }
    }
}

impl From<Error> for RevertFailure {
    fn from(error: Error) -> Self {
        Self::new(Refusal::Other, error)
    }
}

/// The connector call that did an action, as the audit log holds it.
pub(super) struct Execution {
    outcome: ActionOutcome,
    dry_run: bool,
}

/// The audit records of one action that the revert path reads.
#[derive(Default)]
pub(super) struct Trail {
    /// The request, from the record that proposed the action.
    request: Option<ActionRequest>,
    /// The last connector call that returned an outcome.
    execution: Option<Execution>,
    /// `true` if a connector call for the action returned an error.
    failed: bool,
    /// `true` if a revert of the action succeeded.
    reverted: bool,
    /// `true` if the log holds two different requests with the identifier of the action.
    conflict: bool,
}

/// Removes the mark of a revert in progress when the revert ends.
struct InProgress<'a> {
    reverting: &'a Mutex<HashSet<ActionId>>,
    id: ActionId,
}

impl Drop for InProgress<'_> {
    fn drop(&mut self) {
        lock(self.reverting).remove(&self.id);
    }
}

/// Makes the request of a revert of `original` for the policy and the audit log.
fn revert_request(
    original: &ActionRequest,
    execution: Option<&Execution>,
    principal: &Principal,
    reason: String,
) -> ActionRequest {
    let mut request = ActionRequest::new(
        ActionKind::Custom(REVERT_ACTION.to_owned()),
        original.target.clone(),
        principal.id.clone(),
        reason,
    );
    request.incident_id = original.incident_id;
    let mut reverts = json!({
        "action_id": original.id,
        "kind": original.kind,
        "requested_by": original.requested_by,
    });
    if let Some(execution) = execution {
        reverts["connector"] = json!(execution.outcome.connector);
        reverts["executed_at"] = json!(execution.outcome.completed_at);
    }
    if let Some(after) = original.parameters.get(REVERT_AFTER_PARAMETER) {
        reverts[REVERT_AFTER_PARAMETER] = after.clone();
    }
    request
        .parameters
        .insert(REVERTS_PARAMETER.to_owned(), reverts);
    request.evidence = vec![
        EvidenceRef::new(EvidenceKind::Action, original.id)
            .with_note("The action that this request reverts."),
    ];
    request.evidence.extend(original.evidence.iter().cloned());
    request
}

/// Reads the identifier of the action that a revert request undoes.
fn reverted_action_id(request: &ActionRequest) -> Result<ActionId> {
    request
        .parameters
        .get(REVERTS_PARAMETER)
        .and_then(|reverts| reverts.get("action_id"))
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<ActionId>().ok())
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "the revert request {} does not name the action that it reverts",
                request.id
            ))
        })
}

impl Dispatcher {
    /// Undoes one action that a connector did before.
    ///
    /// The dispatcher finds the request and its execution in the audit log. It makes a
    /// revert request with the action type `{custom: revert}` and sends this request
    /// through the normal steps: an [`AuditKind::ActionProposed`] record, the policy, the
    /// approval queue if policy requires approval, the connector that did the action, and
    /// an [`AuditKind::ActionExecuted`] record. The dispatcher publishes the result on the
    /// bus.
    ///
    /// Each audit record of the revert has `operation: "revert"` and the field `reverts` in
    /// its payload. Each record has evidence links to the revert request, to the action
    /// that the revert undoes, and to the evidence of that action.
    ///
    /// The policy gets the revert request. Its parameter `reverts` names the action, the
    /// type of the action, and the connector. The default tier of a revert is `gated`.
    ///
    /// The connector gets the initial request with one more parameter, `execution_details`:
    /// the details of the outcome of the execution. A connector reads the earlier state of
    /// the target from it.
    ///
    /// One execution can be reverted one time. A revert that fails or that policy does not
    /// permit does not use this one time.
    ///
    /// With the global dry-run switch, the revert is a dry run. It changes nothing, and
    /// the action can still be reverted later.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: the audit log has no execution of the action.
    /// - [`Error::InvalidInput`]: the reason is empty, the action was a dry run, the action
    ///   did not change the target, the action was reverted before, a revert of the action
    ///   is in progress, or the action is a revert.
    /// - [`Error::Unsupported`]: the connector reported that it cannot undo the action, or
    ///   the connector is not in the registry.
    /// - The error of the connector, if the connector call fails.
    pub async fn revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
    ) -> Result<ActionDisposition> {
        self.try_revert(action_id, principal, reason, None)
            .await
            .map_err(|failure| failure.error)
    }

    /// Does [`revert`](Self::revert) and keeps the cause of a refusal.
    ///
    /// `hint` is the sequence number of the audit record that proposed the action, if the
    /// caller knows it.
    pub(crate) async fn try_revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
        hint: Option<u64>,
    ) -> std::result::Result<ActionDisposition, RevertFailure> {
        let reason = clean_text(reason, MAX_REASON_LENGTH);
        if reason.is_empty() {
            return Err(Error::InvalidInput(format!(
                "the revert of the action {action_id} needs a reason"
            ))
            .into());
        }
        let trail = self.trail(action_id, hint).await?;
        let Some(original) = trail.request.clone() else {
            return Err(RevertFailure::new(
                Refusal::NotFound,
                Error::NotFound(format!("the audit log has no action {action_id}")),
            ));
        };
        let _in_progress = self.begin_revert(action_id)?;

        let mut request = revert_request(&original, trail.execution.as_ref(), principal, reason);
        let forced = self.dry_run() && !request.dry_run;
        if self.dry_run() {
            request.dry_run = true;
        }
        let pass = Pass::revert(request, None, original);
        self.audit
            .append(
                pass.entry(
                    AuditKind::ActionProposed,
                    &principal.id,
                    format!("{} proposed the {}.", principal.id, pass.title()),
                )
                .with_payload(pass.mark(json!({
                    "action": pass.request,
                    "principal": principal,
                    "dry_run": pass.request.dry_run,
                    "dry_run_forced": forced,
                }))),
            )
            .await?;

        let (execution, connector) = match self.eligible(action_id, &trail) {
            Ok(found) => found,
            Err(failure) => {
                self.record_failure(&pass, Stopped::Refused(None), &failure.error)
                    .await?;
                return Err(failure);
            }
        };
        let decision = self.decide(&pass, principal).await?;
        match decision.effect {
            PolicyEffect::Deny => {
                let disposition = ActionDisposition::Denied(decision);
                self.publish_result(&pass, &disposition).await;
                Ok(disposition)
            }
            PolicyEffect::RequireApproval => {
                Ok(self.request_approval(&pass, principal, decision).await?)
            }
            PolicyEffect::Allow => Ok(self.run_revert(&pass, execution, connector).await?),
        }
    }

    /// Runs the revert of an approval request that a person approved.
    pub(super) async fn resume_revert(
        &self,
        approval: ApprovalRequest,
        mut claim: Claim<'_>,
    ) -> Result<ActionDisposition> {
        let action_id = reverted_action_id(&approval.action)?;
        let trail = self.trail(action_id, None).await?;
        let Some(original) = trail.request.clone() else {
            return Err(Error::NotFound(format!(
                "the audit log has no action {action_id}"
            )));
        };
        if approval.action.target != original.target {
            return Err(Error::InvalidInput(format!(
                "the revert request {} names the target {}, but the action {action_id} changed {}",
                approval.action.id,
                entity_label(&approval.action.target),
                entity_label(&original.target)
            )));
        }
        let _in_progress = self
            .begin_revert(action_id)
            .map_err(|failure| failure.error)?;

        let mut request = approval.action.clone();
        if self.dry_run() {
            request.dry_run = true;
        }
        let approval_id = approval.id;
        let principal = approval.requested_by.clone();
        let pass = Pass::revert(request, Some(approval), original);
        let (execution, connector) = match self.eligible(action_id, &trail) {
            Ok(found) => found,
            Err(failure) => {
                // The revert is not possible. The record uses the approval, so that a
                // second resume does not write the same record again.
                claim.keep = true;
                self.record_failure(&pass, Stopped::Refused(None), &failure.error)
                    .await?;
                return Err(failure.error);
            }
        };
        let decision = self.decide(&pass, &principal).await?;
        if decision.effect == PolicyEffect::Deny {
            let disposition = ActionDisposition::Denied(decision);
            self.publish_result(&pass, &disposition).await;
            return Ok(disposition);
        }
        claim.keep = true;
        lock(&self.approval_sequences).remove(&approval_id);
        self.run_revert(&pass, execution, connector).await
    }

    /// Marks a revert of the action as in progress. One revert of an action runs at a time.
    fn begin_revert(
        &self,
        action_id: ActionId,
    ) -> std::result::Result<InProgress<'_>, RevertFailure> {
        if !lock(&self.reverting).insert(action_id) {
            return Err(Error::InvalidInput(format!(
                "a revert of the action {action_id} is in progress"
            ))
            .into());
        }
        Ok(InProgress {
            reverting: &self.reverting,
            id: action_id,
        })
    }

    /// Checks that the action can be reverted. Returns its execution and its connector.
    fn eligible(
        &self,
        action_id: ActionId,
        trail: &Trail,
    ) -> std::result::Result<(Execution, Arc<dyn ActionConnector>), RevertFailure> {
        let refuse = |refusal, message: String| RevertFailure::new(refusal, message_error(message));
        if trail.conflict {
            // A revert undoes the target of the first request. With two different
            // requests, the dispatcher cannot know which target the connector changed.
            return Err(RevertFailure::new(
                Refusal::Other,
                Error::Integrity(format!(
                    "the audit log has two different requests with the identifier {action_id}; the dispatcher cannot know which of them to revert"
                )),
            ));
        }
        if trail
            .request
            .as_ref()
            .is_some_and(revert::is_revert_request)
        {
            return Err(refuse(
                Refusal::Other,
                format!(
                    "the action {action_id} is a revert; a revert cannot be reverted; send a new request for the action"
                ),
            ));
        }
        let Some(execution) = &trail.execution else {
            return Err(if trail.failed {
                refuse(
                    Refusal::NothingToRevert,
                    format!(
                        "the action {action_id} did not complete, so there is nothing to revert"
                    ),
                )
            } else {
                RevertFailure::new(
                    Refusal::NotFound,
                    Error::NotFound(format!(
                        "the audit log has no execution of the action {action_id}"
                    )),
                )
            });
        };
        let outcome = &execution.outcome;
        if execution.dry_run || outcome.status == ActionStatus::Simulated {
            return Err(refuse(
                Refusal::NothingToRevert,
                format!("the action {action_id} was a dry run; a dry run has nothing to revert"),
            ));
        }
        if outcome.status != ActionStatus::Succeeded {
            return Err(refuse(
                Refusal::NothingToRevert,
                format!(
                    "the action {action_id} has the status {}; it did not change the target, so there is nothing to revert",
                    snake_name(&outcome.status)
                ),
            ));
        }
        if trail.reverted || lock(&self.reverted).contains(&action_id) {
            return Err(refuse(
                Refusal::AlreadyReverted,
                format!(
                    "the action {action_id} was reverted before; one execution can be reverted one time"
                ),
            ));
        }
        if !outcome.reversible {
            return Err(RevertFailure::new(
                Refusal::Other,
                Error::Unsupported(format!(
                    "connector {} reported that it cannot undo the action {action_id}",
                    outcome.connector
                )),
            ));
        }
        let Some(connector) = self.registry.connector(&outcome.connector) else {
            return Err(RevertFailure::new(
                Refusal::Other,
                Error::Unsupported(format!(
                    "connector {} did the action {action_id}, but it is not in the registry",
                    outcome.connector
                )),
            ));
        };
        Ok((
            Execution {
                outcome: outcome.clone(),
                dry_run: execution.dry_run,
            },
            connector,
        ))
    }

    /// Calls the connector to undo the action and writes the result to the audit log.
    async fn run_revert(
        &self,
        pass: &Pass,
        execution: Execution,
        connector: Arc<dyn ActionConnector>,
    ) -> Result<ActionDisposition> {
        let Some(original) = &pass.undoes else {
            return Err(Error::InvalidInput(format!(
                "the request {} is not a revert",
                pass.request.id
            )));
        };
        let name = connector.info().name;
        // The connector gets the initial request and the details of its outcome.
        let mut request = original.clone();
        request.dry_run = pass.request.dry_run;
        request.parameters.insert(
            EXECUTION_DETAILS_PARAMETER.to_owned(),
            execution.outcome.details,
        );
        let result = self
            .call(connector.revert(&request), &name, pass.request.id)
            .await;
        let reverted = match result {
            Ok(reverted) => reverted,
            Err(error) => {
                self.record_failure(pass, Stopped::Connector(&name), &error)
                    .await?;
                return Err(error);
            }
        };

        let mut extra = Vec::new();
        if reverted.status == ActionStatus::Succeeded {
            {
                let mut done = lock(&self.reverted);
                if done.len() >= MAX_HINTS {
                    done.clear();
                }
                done.insert(original.id);
            }
            if self.resolve_pending(original.id).await {
                extra.push(("pending_revert_removed", json!(true)));
            }
        }
        let outcome = ActionOutcome {
            action_id: pass.request.id,
            status: reverted.status,
            connector: name.clone(),
            message: reverted.message,
            details: json!({
                "reverted_action_id": original.id,
                "connector_details": reverted.details,
            }),
            reversible: false,
            completed_at: reverted.completed_at,
        };
        self.finish(pass, &name, outcome, extra).await
    }

    /// Removes the pending revert of an action that is now reverted.
    ///
    /// Returns `true` if the store had a pending revert for the action.
    async fn resolve_pending(&self, action_id: ActionId) -> bool {
        let Some(ledger) = &self.reverts else {
            return false;
        };
        match ledger.store.remove(action_id).await {
            Ok(removed) => {
                ledger.changed.notify_one();
                removed.is_some()
            }
            Err(error) => {
                // The scheduler finds at the revert time that the action is reverted.
                tracing::warn!(
                    %action_id,
                    %error,
                    "could not remove the pending revert of an action that is reverted"
                );
                false
            }
        }
    }

    /// Reads the audit records of one action.
    ///
    /// The search starts at `hint`, or at the proposal record that this process saw. If the
    /// search finds no proposal record, it starts again at the first record of the log.
    async fn trail(&self, action_id: ActionId, hint: Option<u64>) -> Result<Trail> {
        let start = hint
            .or_else(|| lock(&self.proposal_sequences).get(&action_id).copied())
            .unwrap_or(1)
            .max(1);
        let trail = self.scan(action_id, start).await?;
        if trail.request.is_none() && start > 1 {
            return self.scan(action_id, 1).await;
        }
        Ok(trail)
    }

    async fn scan(&self, action_id: ActionId, mut from_sequence: u64) -> Result<Trail> {
        let wanted = json!(action_id);
        let unreadable = |sequence: u64, part: &str| {
            Error::Integrity(format!(
                "the audit record {sequence} does not hold a valid {part} of the action {action_id}"
            ))
        };
        let mut trail = Trail::default();
        loop {
            let page = self.audit.read(from_sequence, AUDIT_PAGE_SIZE).await?;
            let Some(last) = page.last() else {
                return Ok(trail);
            };
            from_sequence = last.sequence + 1;
            for record in &page {
                let payload = &record.payload;
                match record.kind {
                    AuditKind::ActionProposed if payload["action"]["id"] == wanted => {
                        let request: ActionRequest =
                            serde_json::from_value(payload["action"].clone())
                                .map_err(|_| unreadable(record.sequence, "request"))?;
                        match &trail.request {
                            // The same request can be in the log two times, for example
                            // after a second delivery from the bus.
                            Some(first) => {
                                trail.conflict |=
                                    first.kind != request.kind || first.target != request.target;
                            }
                            None => trail.request = Some(request),
                        }
                    }
                    AuditKind::ActionExecuted if payload["action_id"] == wanted => {
                        if let Some(request) = &trail.request {
                            trail.conflict |= payload["kind"] != json!(request.kind)
                                || payload["target"] != json!(request.target);
                        }
                        if payload["outcome"].is_object() {
                            let outcome = serde_json::from_value(payload["outcome"].clone())
                                .map_err(|_| unreadable(record.sequence, "outcome"))?;
                            trail.execution = Some(Execution {
                                outcome,
                                dry_run: payload["dry_run"] == true,
                            });
                        } else {
                            trail.failed = true;
                        }
                    }
                    AuditKind::ActionExecuted
                        if payload["operation"] == OPERATION
                            && payload["reverts"]["action_id"] == wanted
                            && payload["outcome"]["status"] == "succeeded" =>
                    {
                        trail.reverted = true;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Makes the error for a request that the revert path refuses.
fn message_error(message: String) -> Error {
    Error::InvalidInput(message)
}
