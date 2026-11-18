//! The scheduler of the timed reverts.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{ActionDisposition, ActionOutcome, ActionStatus};
use aegis_contracts::audit::{AuditEntry, AuditKind};
use aegis_contracts::common::{ActionId, ApprovalId, EvidenceKind, EvidenceRef};
use aegis_contracts::policy::{ApprovalStatus, Principal, PrincipalKind};
use aegis_contracts::{Error, Result};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::watch;

use super::{
    Ledger, MAX_REVERT_AFTER_SECONDS, PendingRevert, PendingState, SCHEDULER_PRINCIPAL_ID,
    add_duration, add_seconds,
};
use crate::dispatcher::{Dispatcher, Refusal};
use crate::lock;
use crate::names::{entity_label, same_kind, snake_name, truncate};

/// The values of the field `event` in the audit records that the scheduler writes.
///
/// Each record has the type [`AuditKind::Other`] and an evidence link to the action.
pub mod event {
    /// A person confirmed the action. The containment stays.
    pub const CONFIRMED: &str = "timed_revert_confirmed";
    /// A person moved the revert time.
    pub const EXTENDED: &str = "timed_revert_extended";
    /// A principal reverted the action before the revert time.
    pub const CANCELLED: &str = "timed_revert_cancelled";
    /// Nobody confirmed the action, and the scheduler reverted it.
    pub const COMPLETED: &str = "timed_revert_completed";
    /// A revert attempt failed. The containment stays, and the scheduler tries again.
    pub const FAILED: &str = "timed_revert_failed";
    /// Policy requires approval for the revert. The containment stays.
    pub const AWAITING_APPROVAL: &str = "timed_revert_awaiting_approval";
    /// The pending revert ended with no revert by the scheduler.
    pub const CLOSED: &str = "timed_revert_closed";
}

/// The audit actor of the records that the scheduler writes for its own steps.
pub const SCHEDULER_ACTOR: &str = SCHEDULER_PRINCIPAL_ID;

const DEFAULT_RETRY_BASE: Duration = Duration::from_secs(30);
const DEFAULT_RETRY_MAX: Duration = Duration::from_secs(30 * 60);
const DEFAULT_APPROVAL_POLL: Duration = Duration::from_secs(60);
/// The shortest wait of the scheduler loop between two passes with no change signal.
const MIN_WAIT: Duration = Duration::from_secs(1);
const MAX_ERROR_LENGTH: usize = 500;

/// The settings of a [`RevertScheduler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertSchedulerConfig {
    /// The delay after the first revert attempt that fails. The default is 30 seconds.
    ///
    /// The delay is two times as long after each more attempt that fails.
    pub retry_base: Duration,
    /// The longest delay between two revert attempts. The default is 30 minutes.
    pub retry_max: Duration,
    /// The time between two examinations of an approval request that a revert waits for.
    /// The default is 60 seconds.
    pub approval_poll: Duration,
}

impl Default for RevertSchedulerConfig {
    fn default() -> Self {
        Self {
            retry_base: DEFAULT_RETRY_BASE,
            retry_max: DEFAULT_RETRY_MAX,
            approval_poll: DEFAULT_APPROVAL_POLL,
        }
    }
}

/// The counts of what a [`RevertScheduler`] did since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevertStats {
    /// The timed reverts that the scheduler completed.
    pub reverted: u64,
    /// The revert attempts that failed.
    pub failed_attempts: u64,
    /// The actions that a person confirmed.
    pub confirmed: u64,
    /// The changes of a revert time.
    pub extended: u64,
    /// The actions that a principal reverted before the revert time.
    pub cancelled: u64,
    /// The pending reverts that ended with no revert by the scheduler.
    pub closed: u64,
}

/// What the scheduler did with one pending revert at its time.
#[derive(Debug, Clone, PartialEq)]
pub enum RevertProgress {
    /// The connector undid the action. The pending revert is complete.
    Reverted(ActionOutcome),
    /// Policy requires approval for the revert. The containment stays until a person
    /// decides.
    AwaitingApproval(ApprovalId),
    /// The attempt failed. The containment stays, and the scheduler tries again.
    Failed {
        /// The error text.
        error: String,
        /// The number of attempts that failed.
        attempts: u32,
        /// The time of the next attempt.
        next_attempt_at: DateTime<Utc>,
    },
    /// The pending revert ended with no revert by the scheduler.
    Closed {
        /// Why the pending revert ended.
        reason: String,
    },
}

/// One line of the report of [`RevertScheduler::run_due`].
#[derive(Debug, Clone, PartialEq)]
pub struct RevertAttempt {
    /// The action of the pending revert.
    pub action_id: ActionId,
    /// What the scheduler did.
    pub progress: RevertProgress,
}

struct Inner {
    dispatcher: Arc<Dispatcher>,
    ledger: Arc<Ledger>,
    config: RevertSchedulerConfig,
    started_at: DateTime<Utc>,
    /// One operation on the pending reverts runs at a time.
    gate: tokio::sync::Mutex<()>,
    /// The earliest time of the next attempt for a pending revert that failed. This copy in
    /// memory keeps the delay if the store cannot save it.
    deferred: Mutex<HashMap<ActionId, DateTime<Utc>>>,
    stats: watch::Sender<RevertStats>,
}

/// Holds the timed reverts of one dispatcher and reverts each action at its time.
///
/// A request with the parameter `revert_after_seconds` gives a pending revert. Refer to
/// [`revert`](crate::revert).
///
/// - [`confirm`](Self::confirm): a person confirms the action. The containment stays.
/// - [`extend`](Self::extend): a person moves the revert time.
/// - [`cancel`](Self::cancel): a principal reverts the action immediately.
/// - Nobody confirms: the scheduler reverts the action at the revert time through
///   [`Dispatcher::revert`], with the principal [`SCHEDULER_PRINCIPAL_ID`]. Thus the policy
///   applies to each timed revert. If policy requires approval, the revert waits in the
///   approval queue and the containment stays.
///
/// Each of these operations writes an audit record. Refer to [`event`].
///
/// # Start and restart
///
/// Start [`run`](Self::run) in a task. The scheduler reads the pending reverts from the
/// store of the dispatcher. A revert with a time in the past runs immediately.
///
/// # Failure rule
///
/// If a revert fails, the containment stays. The scheduler writes an audit record with the
/// error and tries again after a delay. The delay starts at
/// [`RevertSchedulerConfig::retry_base`] and is two times as long after each failure, up
/// to [`RevertSchedulerConfig::retry_max`]. The pending revert stays in the store until
/// the revert succeeds or a person confirms the action.
///
/// A copy of a scheduler is the same scheduler.
#[derive(Clone)]
pub struct RevertScheduler {
    inner: Arc<Inner>,
}

fn require_person(principal: &Principal, operation: &str) -> Result<()> {
    if principal.kind == PrincipalKind::Human {
        return Ok(());
    }
    Err(Error::Unauthorized(format!(
        "only a person can {operation} a timed revert; {} is not a person",
        principal.id
    )))
}

fn label(pending: &PendingRevert) -> String {
    format!(
        "{} on {}",
        snake_name(&pending.kind),
        entity_label(&pending.target)
    )
}

impl RevertScheduler {
    /// Makes a scheduler for the pending reverts of `dispatcher`, with the default
    /// settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the dispatcher has no revert store. Refer to
    /// [`DispatcherBuilder::revert_store`](crate::DispatcherBuilder::revert_store).
    pub fn new(dispatcher: Arc<Dispatcher>) -> Result<Self> {
        Self::with_config(dispatcher, RevertSchedulerConfig::default())
    }

    /// Makes a scheduler for the pending reverts of `dispatcher`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the dispatcher has no revert store, if a delay is
    /// zero, or if `retry_max` is less than `retry_base`.
    pub fn with_config(dispatcher: Arc<Dispatcher>, config: RevertSchedulerConfig) -> Result<Self> {
        let Some(ledger) = dispatcher.ledger().cloned() else {
            return Err(Error::Config(
                "the dispatcher has no revert store; set DispatcherBuilder::revert_store"
                    .to_owned(),
            ));
        };
        if config.retry_base.is_zero() || config.approval_poll.is_zero() {
            return Err(Error::Config(
                "the delays of the revert scheduler must be more than zero".to_owned(),
            ));
        }
        if config.retry_max < config.retry_base {
            return Err(Error::Config(
                "retry_max of the revert scheduler must not be less than retry_base".to_owned(),
            ));
        }
        let started_at = ledger.clock.now();
        Ok(Self {
            inner: Arc::new(Inner {
                dispatcher,
                ledger,
                config,
                started_at,
                gate: tokio::sync::Mutex::new(()),
                deferred: Mutex::default(),
                stats: watch::Sender::new(RevertStats::default()),
            }),
        })
    }

    /// Returns the principal of the reverts that the scheduler requests.
    #[must_use]
    pub fn principal() -> Principal {
        Principal::new(
            SCHEDULER_PRINCIPAL_ID,
            PrincipalKind::System,
            &[SCHEDULER_PRINCIPAL_ID],
        )
    }

    /// Returns the time of the clock that the scheduler and its dispatcher use.
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.inner.ledger.clock.now()
    }

    /// Returns the counts of what the scheduler did since it started.
    #[must_use]
    pub fn stats(&self) -> RevertStats {
        *self.inner.stats.borrow()
    }

    /// Returns a receiver that shows each change of the counts.
    ///
    /// Use `wait_for` on the receiver to wait until the scheduler did an operation.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<RevertStats> {
        self.inner.stats.subscribe()
    }

    /// Lists the pending reverts. The pending revert with the earliest time is first.
    pub async fn pending(&self) -> Result<Vec<PendingRevert>> {
        self.inner.ledger.store.list().await
    }

    /// Reads the pending revert of one action.
    pub async fn get(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        self.inner.ledger.store.get(action_id).await
    }

    async fn entry(&self, action_id: ActionId) -> Result<PendingRevert> {
        self.get(action_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("the action {action_id} has no pending revert")))
    }

    fn count(&self, change: impl FnOnce(&mut RevertStats)) {
        self.inner.stats.send_modify(change);
    }

    /// Writes one audit record about a pending revert.
    async fn record(
        &self,
        event: &str,
        actor: &str,
        summary: String,
        pending: &PendingRevert,
        extra: Value,
    ) -> Result<()> {
        let mut payload = json!({
            "event": event,
            "action_id": pending.action_id,
            "kind": pending.kind,
            "target": pending.target,
            "requested_by": pending.requested_by,
            "revert_after_seconds": pending.revert_after_seconds,
            "due_at": pending.due_at,
            "attempts": pending.attempts,
        });
        if let (Some(fields), Value::Object(more)) = (payload.as_object_mut(), extra) {
            fields.extend(more);
        }
        let mut evidence = vec![EvidenceRef::new(EvidenceKind::Action, pending.action_id)];
        if let Some(incident_id) = pending.incident_id {
            evidence.push(EvidenceRef::new(EvidenceKind::Incident, incident_id));
        }
        self.inner
            .dispatcher
            .audit_log()
            .append(
                AuditEntry::new(AuditKind::Other, actor, summary)
                    .with_payload(payload)
                    .with_evidence(evidence),
            )
            .await
            .map(|_| ())
    }

    /// Removes a pending revert from the store after its audit record is written.
    async fn remove(&self, action_id: ActionId, what: &str) -> Result<()> {
        let ledger = &self.inner.ledger;
        ledger.store.remove(action_id).await.map_err(|error| {
            same_kind(
                &error,
                format!(
                    "the audit log has the {what} of the action {action_id}, but the revert store did not remove the pending revert; do the operation again: {error}"
                ),
            )
        })?;
        lock(&self.inner.deferred).remove(&action_id);
        ledger.changed.notify_one();
        Ok(())
    }

    /// Confirms an action. The containment stays, and the scheduler does not revert it.
    ///
    /// Only a person can confirm an action. The caller must authenticate the person and
    /// check the permission of the person before the call.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`]: the principal is not a person.
    /// - [`Error::NotFound`]: the action has no pending revert.
    /// - The error of the audit log or of the store. The pending revert then stays.
    pub async fn confirm(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<PendingRevert> {
        require_person(principal, "confirm")?;
        let _gate = self.inner.gate.lock().await;
        let pending = self.entry(action_id).await?;
        self.record(
            event::CONFIRMED,
            &principal.id,
            format!(
                "{} confirmed the action {}. The containment stays. The scheduler does not revert it.",
                principal.id,
                label(&pending)
            ),
            &pending,
            json!({ "principal": principal }),
        )
        .await?;
        self.remove(action_id, "confirmation").await?;
        self.count(|stats| stats.confirmed += 1);
        Ok(pending)
    }

    /// Moves the revert time of an action by `extension`.
    ///
    /// The new time is `extension` after the present revert time, or after the present
    /// time if the revert time is in the past. The new time can be 30 days from the
    /// present time at most. The count of failed attempts starts again at zero.
    ///
    /// Only a person can move the time. The caller must authenticate the person and check
    /// the permission of the person before the call.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`]: the principal is not a person.
    /// - [`Error::InvalidInput`]: `extension` is less than one second, or the new time is
    ///   more than 30 days from the present time.
    /// - [`Error::NotFound`]: the action has no pending revert.
    /// - The error of the audit log or of the store. The revert time then does not change.
    pub async fn extend(
        &self,
        action_id: ActionId,
        principal: &Principal,
        extension: Duration,
    ) -> Result<PendingRevert> {
        require_person(principal, "extend")?;
        if extension.as_secs() == 0 {
            return Err(Error::InvalidInput(
                "the extension of a timed revert must be one second or more".to_owned(),
            ));
        }
        let _gate = self.inner.gate.lock().await;
        let mut pending = self.entry(action_id).await?;
        let now = self.now();
        let previous = pending.due_at;
        let due_at = add_seconds(previous.max(now), extension.as_secs());
        if due_at > add_seconds(now, MAX_REVERT_AFTER_SECONDS) {
            return Err(Error::InvalidInput(format!(
                "the new revert time of the action {action_id} is more than {MAX_REVERT_AFTER_SECONDS} seconds from the present time"
            )));
        }
        pending.due_at = due_at;
        pending.attempts = 0;
        pending.next_attempt_at = None;
        pending.last_error = None;
        self.record(
            event::EXTENDED,
            &principal.id,
            format!(
                "{} moved the revert time of the action {} from {previous} to {due_at}.",
                principal.id,
                label(&pending)
            ),
            &pending,
            json!({ "principal": principal, "previous_due_at": previous }),
        )
        .await?;
        let ledger = &self.inner.ledger;
        ledger.store.put(pending.clone()).await.map_err(|error| {
            same_kind(
                &error,
                format!(
                    "the audit log has the new revert time of the action {action_id}, but the revert store did not save it; do the operation again: {error}"
                ),
            )
        })?;
        lock(&self.inner.deferred).remove(&action_id);
        ledger.changed.notify_one();
        self.count(|stats| stats.extended += 1);
        Ok(pending)
    }

    /// Reverts an action immediately, before its revert time.
    ///
    /// The revert goes through [`Dispatcher::revert`] with `principal`, so the policy
    /// applies. If the result is not a completed revert, for example a pending approval,
    /// the pending revert stays and the scheduler reverts the action at its time.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: the action has no pending revert.
    /// - The errors of [`Dispatcher::revert`].
    pub async fn cancel(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        let _gate = self.inner.gate.lock().await;
        let pending = self.entry(action_id).await?;
        let reason = format!(
            "{} cancelled the action {} before the revert time {}.",
            principal.id,
            label(&pending),
            pending.due_at
        );
        let disposition = self
            .inner
            .dispatcher
            .try_revert(action_id, principal, &reason, pending.audit_sequence)
            .await
            .map_err(|failure| failure.error)?;
        if let ActionDisposition::Executed(outcome) = &disposition
            && outcome.status == ActionStatus::Succeeded
        {
            self.record(
                event::CANCELLED,
                &principal.id,
                format!(
                    "{} reverted the action {} before the revert time.",
                    principal.id,
                    label(&pending)
                ),
                &pending,
                json!({ "principal": principal, "revert_action_id": outcome.action_id }),
            )
            .await?;
            self.forget(action_id).await;
            self.count(|stats| stats.cancelled += 1);
        }
        Ok(disposition)
    }

    /// Makes sure that the store has no pending revert for an action that is reverted.
    ///
    /// The dispatcher removes the pending revert when a revert succeeds. This function
    /// does the removal again if the dispatcher could not do it.
    async fn forget(&self, action_id: ActionId) {
        lock(&self.inner.deferred).remove(&action_id);
        if let Err(error) = self.inner.ledger.store.remove(action_id).await {
            tracing::warn!(
                %action_id,
                %error,
                "could not remove the pending revert of an action that is reverted"
            );
        }
    }

    /// Returns the time at which the scheduler examines a pending revert.
    fn wake_at(&self, pending: &PendingRevert) -> DateTime<Utc> {
        let stored = pending.wake_at();
        match lock(&self.inner.deferred).get(&pending.action_id) {
            Some(deferred) if *deferred > stored => *deferred,
            _ => stored,
        }
    }

    /// Returns the delay before the next attempt, after `attempts` attempts that failed.
    fn delay(&self, attempts: u32) -> Duration {
        let config = &self.inner.config;
        let doublings = attempts.saturating_sub(1).min(31);
        config
            .retry_base
            .saturating_mul(1_u32 << doublings)
            .min(config.retry_max)
    }

    /// Examines each pending revert that is due and reverts its action.
    ///
    /// [`run`](Self::run) calls this function. A caller that has its own timer can call it
    /// directly.
    ///
    /// Returns one line for each pending revert that was due.
    ///
    /// # Errors
    ///
    /// Returns the error of the store if the scheduler cannot read the pending reverts.
    /// A revert that fails is not an error: its line has [`RevertProgress::Failed`].
    pub async fn run_due(&self) -> Result<Vec<RevertAttempt>> {
        let mut report = Vec::new();
        let listed = self.pending().await?;
        // Forget the delay of a pending revert that is no longer in the store.
        lock(&self.inner.deferred)
            .retain(|action_id, _| listed.iter().any(|pending| pending.action_id == *action_id));
        for listed in listed {
            if self.wake_at(&listed) > self.now() {
                continue;
            }
            let _gate = self.inner.gate.lock().await;
            // Read the pending revert again. A person can confirm the action or move the
            // time while the scheduler does a different revert.
            let Some(pending) = self.get(listed.action_id).await? else {
                continue;
            };
            if self.wake_at(&pending) > self.now() {
                continue;
            }
            let action_id = pending.action_id;
            let progress = self.attempt(pending).await;
            report.push(RevertAttempt {
                action_id,
                progress,
            });
        }
        Ok(report)
    }

    /// Runs the scheduler until `shutdown` completes.
    ///
    /// The scheduler reads the pending reverts when it starts, so it continues the work
    /// from before a restart. It then sleeps until the next revert time or until the
    /// pending reverts change.
    pub async fn run(&self, shutdown: impl Future<Output = ()> + Send) {
        tokio::pin!(shutdown);
        loop {
            let wait = match self.pass().await {
                Ok(wait) => wait,
                Err(error) => {
                    tracing::error!(
                        %error,
                        "the revert scheduler could not read the pending reverts; it tries again"
                    );
                    Some(self.inner.config.retry_base)
                }
            };
            let sleep = async {
                match wait {
                    Some(wait) => tokio::time::sleep(wait.max(MIN_WAIT)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = self.inner.ledger.changed.notified() => {}
                () = sleep => {}
            }
        }
    }

    /// Does one pass and returns the time to the next pass. `None` if no revert waits.
    async fn pass(&self) -> Result<Option<Duration>> {
        self.run_due().await?;
        let now = self.now();
        let next = self
            .pending()
            .await?
            .iter()
            .map(|pending| self.wake_at(pending))
            .min();
        Ok(next.map(|next| (next - now).to_std().unwrap_or(Duration::ZERO)))
    }

    fn reason(&self, pending: &PendingRevert) -> String {
        let late = if pending.due_at < self.inner.started_at {
            " The scheduler started after this time, so the revert runs now."
        } else {
            ""
        };
        format!(
            "Nobody confirmed the action {} before {}. The timed revert of {} seconds is due.{late}",
            label(pending),
            pending.due_at,
            pending.revert_after_seconds
        )
    }

    /// Does one revert attempt for a pending revert that is due.
    async fn attempt(&self, pending: PendingRevert) -> RevertProgress {
        if let Some(approval_id) = pending.approval_id {
            return self.follow_approval(pending, approval_id).await;
        }
        let result = self
            .inner
            .dispatcher
            .try_revert(
                pending.action_id,
                &Self::principal(),
                &self.reason(&pending),
                pending.audit_sequence,
            )
            .await;
        match result {
            Ok(disposition) => self.after(pending, disposition).await,
            Err(failure) => match failure.refusal {
                Refusal::AlreadyReverted => {
                    self.close(
                        pending,
                        "A different request reverted the action before the revert time."
                            .to_owned(),
                    )
                    .await
                }
                Refusal::NothingToRevert => {
                    self.close(
                        pending,
                        format!("There is nothing to revert: {}.", failure.error),
                    )
                    .await
                }
                Refusal::NotFound if pending.state == PendingState::Armed => {
                    self.fail(
                        pending,
                        format!(
                            "the process stopped while the action ran, and the audit log has no result; examine the target, then confirm the action: {}",
                            failure.error
                        ),
                    )
                    .await
                }
                Refusal::NotFound | Refusal::Other => {
                    self.fail(pending, failure.error.to_string()).await
                }
            },
        }
    }

    /// Handles the result of a revert request.
    async fn after(
        &self,
        mut pending: PendingRevert,
        disposition: ActionDisposition,
    ) -> RevertProgress {
        match disposition {
            ActionDisposition::Executed(outcome) => match outcome.status {
                ActionStatus::Succeeded => self.complete(pending, outcome).await,
                ActionStatus::Skipped => {
                    self.close(
                        pending,
                        format!(
                            "The connector found that no change was necessary: {}",
                            truncate(&outcome.message, MAX_ERROR_LENGTH)
                        ),
                    )
                    .await
                }
                ActionStatus::Simulated | ActionStatus::Failed => {
                    self.fail(
                        pending,
                        format!(
                            "the revert has the status {} and changed nothing: {}",
                            snake_name(&outcome.status),
                            outcome.message
                        ),
                    )
                    .await
                }
            },
            ActionDisposition::PendingApproval { approval_id, .. } => {
                pending.approval_id = Some(approval_id);
                self.wait_for_approval(pending, approval_id, true).await
            }
            ActionDisposition::Denied(decision) => {
                self.fail(
                    pending,
                    format!("policy denied the revert: {}", decision.reasons.join(" ")),
                )
                .await
            }
        }
    }

    /// Saves that a revert waits for an approval request and sets the next examination.
    async fn wait_for_approval(
        &self,
        mut pending: PendingRevert,
        approval_id: ApprovalId,
        announce: bool,
    ) -> RevertProgress {
        let next = add_duration(self.now(), self.inner.config.approval_poll);
        pending.next_attempt_at = Some(next);
        lock(&self.inner.deferred).insert(pending.action_id, next);
        if let Err(error) = self.inner.ledger.store.put(pending.clone()).await {
            tracing::warn!(
                action_id = %pending.action_id,
                %error,
                "could not save that the timed revert waits for approval"
            );
        }
        if announce
            && let Err(error) = self
                .record(
                    event::AWAITING_APPROVAL,
                    SCHEDULER_ACTOR,
                    format!(
                        "Policy requires approval for the timed revert of the action {}. The containment stays until a person decides on the approval {approval_id}.",
                        label(&pending)
                    ),
                    &pending,
                    json!({ "approval_id": approval_id }),
                )
                .await
        {
            tracing::error!(
                action_id = %pending.action_id,
                %error,
                "could not record that the timed revert waits for approval"
            );
        }
        RevertProgress::AwaitingApproval(approval_id)
    }

    /// Examines the approval request that a revert waits for.
    async fn follow_approval(
        &self,
        mut pending: PendingRevert,
        approval_id: ApprovalId,
    ) -> RevertProgress {
        let approval = match self.inner.dispatcher.approval(approval_id).await {
            Ok(Some(approval)) => approval,
            Ok(None) => {
                pending.approval_id = None;
                return self
                    .fail(
                        pending,
                        format!("the approval request {approval_id} is not in the approval queue"),
                    )
                    .await;
            }
            Err(error) => {
                return self
                    .fail(
                        pending,
                        format!("cannot read the approval request {approval_id}: {error}"),
                    )
                    .await;
            }
        };
        match approval.status {
            ApprovalStatus::Pending => self.wait_for_approval(pending, approval_id, false).await,
            ApprovalStatus::Rejected => {
                let person = approval.decided_by.unwrap_or_else(|| "A person".to_owned());
                self.close(
                    pending,
                    format!(
                        "{person} rejected the approval {approval_id} of the revert. The containment stays."
                    ),
                )
                .await
            }
            ApprovalStatus::Approved => {
                pending.approval_id = None;
                match self.inner.dispatcher.resume(approval_id).await {
                    Ok(disposition) => self.after(pending, disposition).await,
                    Err(error) => {
                        self.fail(
                            pending,
                            format!("the approved revert {approval_id} did not run: {error}"),
                        )
                        .await
                    }
                }
            }
        }
    }

    /// Ends a pending revert after the connector undid the action.
    async fn complete(&self, pending: PendingRevert, outcome: ActionOutcome) -> RevertProgress {
        self.forget(pending.action_id).await;
        if let Err(error) = self
            .record(
                event::COMPLETED,
                SCHEDULER_ACTOR,
                format!(
                    "Nobody confirmed the action {} before {}. The scheduler reverted the action.",
                    label(&pending),
                    pending.due_at
                ),
                &pending,
                json!({ "revert_action_id": outcome.action_id, "connector": outcome.connector }),
            )
            .await
        {
            // The dispatcher wrote the audit records of the revert itself.
            tracing::error!(
                action_id = %pending.action_id,
                %error,
                "could not record the end of the timed revert"
            );
        }
        self.count(|stats| stats.reverted += 1);
        RevertProgress::Reverted(outcome)
    }

    /// Ends a pending revert with no revert by the scheduler.
    ///
    /// The audit record comes first. If the audit log fails, the pending revert stays.
    async fn close(&self, pending: PendingRevert, reason: String) -> RevertProgress {
        let recorded = self
            .record(
                event::CLOSED,
                SCHEDULER_ACTOR,
                format!(
                    "The timed revert of the action {} ended with no revert by the scheduler. {reason}",
                    label(&pending)
                ),
                &pending,
                json!({ "reason": reason }),
            )
            .await;
        if let Err(error) = recorded {
            return self
                .fail(
                    pending,
                    format!("could not record the end of the pending revert: {error}"),
                )
                .await;
        }
        if let Err(error) = self
            .remove(pending.action_id, "end of the pending revert")
            .await
        {
            return self.fail(pending, error.to_string()).await;
        }
        self.count(|stats| stats.closed += 1);
        RevertProgress::Closed { reason }
    }

    /// Keeps a pending revert after an attempt that failed, and sets the next attempt.
    async fn fail(&self, mut pending: PendingRevert, error: String) -> RevertProgress {
        let error = truncate(&error, MAX_ERROR_LENGTH);
        pending.attempts = pending.attempts.saturating_add(1);
        let next = add_duration(self.now(), self.delay(pending.attempts));
        pending.next_attempt_at = Some(next);
        pending.last_error = Some(error.clone());
        lock(&self.inner.deferred).insert(pending.action_id, next);
        tracing::warn!(
            action_id = %pending.action_id,
            attempts = pending.attempts,
            %error,
            "the timed revert failed; the containment stays"
        );
        if let Err(store_error) = self.inner.ledger.store.put(pending.clone()).await {
            tracing::error!(
                action_id = %pending.action_id,
                error = %store_error,
                "could not save the failed attempt of the timed revert"
            );
        }
        if let Err(audit_error) = self
            .record(
                event::FAILED,
                SCHEDULER_ACTOR,
                format!(
                    "The timed revert of the action {} failed. The containment stays. The scheduler tries again at {next}.",
                    label(&pending)
                ),
                &pending,
                json!({ "error": error, "next_attempt_at": next }),
            )
            .await
        {
            tracing::error!(
                action_id = %pending.action_id,
                error = %audit_error,
                "could not record the failed attempt of the timed revert"
            );
        }
        self.count(|stats| stats.failed_attempts += 1);
        RevertProgress::Failed {
            error,
            attempts: pending.attempts,
            next_attempt_at: next,
        }
    }
}
