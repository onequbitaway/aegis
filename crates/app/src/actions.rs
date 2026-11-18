//! The journal of action requests and the simulation connector.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionStatus,
};
use aegis_contracts::common::ActionId;
use aegis_contracts::policy::Principal;
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use aegis_respond::Dispatcher;
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::activity::Activity;

/// The largest number of records that the journal keeps.
pub const MAX_JOURNAL_RECORDS: usize = 10_000;

/// The name of the simulation connector.
pub const SIMULATION_CONNECTOR: &str = "simulation";

/// What the dispatcher did with one request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchResult {
    /// The dispatcher handled the request.
    Disposition(ActionDisposition),
    /// The dispatcher returned an error.
    Failed {
        /// The name of the error variant, for example `unsupported`.
        kind: String,
        /// The error text.
        message: String,
        /// `true` if a new request can succeed.
        retryable: bool,
    },
}

impl DispatchResult {
    /// Makes the result for an error of the dispatcher.
    #[must_use]
    pub fn from_error(error: &Error) -> Self {
        Self::Failed {
            kind: error_kind(error).to_owned(),
            message: error.to_string(),
            retryable: error.is_retryable(),
        }
    }

    /// Returns `true` if a connector changed the environment of the operator.
    #[must_use]
    pub fn changed_the_environment(&self) -> bool {
        matches!(
            self,
            Self::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Succeeded
        )
    }
}

/// Returns the name of an error variant in snake case.
#[must_use]
pub fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::InvalidInput(_) => "invalid_input",
        Error::NotFound(_) => "not_found",
        Error::Config(_) => "config",
        Error::Unauthorized(_) => "unauthorized",
        Error::Denied(_) => "denied",
        Error::Unsupported(_) => "unsupported",
        Error::Unavailable(_) => "unavailable",
        Error::RateLimited(_) => "rate_limited",
        Error::Timeout(_) => "timeout",
        Error::Refused(_) => "refused",
        Error::BudgetExceeded(_) => "budget_exceeded",
        Error::Serialization(_) => "serialization",
        Error::Integrity(_) => "integrity",
        Error::Other { .. } => "other",
    }
}

/// One request that went to the dispatcher, with its last known result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// The position of the request in the journal. The first request has the value 1.
    pub sequence: u64,
    /// The request, as the dispatcher handled it. `dry_run` includes the global switch.
    pub request: ActionRequest,
    /// The identity that made the request.
    pub principal: Principal,
    /// The last known result.
    pub result: DispatchResult,
}

#[derive(Default)]
struct Journal {
    records: VecDeque<ActionRecord>,
    total: u64,
}

/// The single action dispatcher of the process, with a journal of its requests.
///
/// The agents and the playbook engine send each request to this value. It gives the
/// request to the one [`Dispatcher`] and records the request and the result. The journal
/// keeps the last [`MAX_JOURNAL_RECORDS`] requests in memory. The audit log is the durable
/// record.
pub struct ActionJournal {
    dispatcher: Arc<Dispatcher>,
    activity: Arc<Activity>,
    journal: Mutex<Journal>,
}

impl ActionJournal {
    /// Makes the journal in front of `dispatcher`.
    #[must_use]
    pub fn new(dispatcher: Arc<Dispatcher>, activity: Arc<Activity>) -> Self {
        Self {
            dispatcher,
            activity,
            journal: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Journal> {
        self.journal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the number of requests since the process started.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.lock().total
    }

    /// Returns the records that the journal keeps, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<ActionRecord> {
        self.lock().records.iter().cloned().collect()
    }

    /// Returns the records with a sequence number larger than `sequence`, oldest first.
    #[must_use]
    pub fn since(&self, sequence: u64) -> Vec<ActionRecord> {
        self.lock()
            .records
            .iter()
            .filter(|record| record.sequence > sequence)
            .cloned()
            .collect()
    }

    /// Returns the record of one request.
    #[must_use]
    pub fn get(&self, action_id: ActionId) -> Option<ActionRecord> {
        self.lock()
            .records
            .iter()
            .rev()
            .find(|record| record.request.id == action_id)
            .cloned()
    }

    /// Sets the result of a request that the journal has, for example after an approval.
    ///
    /// Returns `false` if the journal does not have the request.
    pub fn set_result(&self, action_id: ActionId, result: DispatchResult) -> bool {
        let found = {
            let mut journal = self.lock();
            match journal
                .records
                .iter_mut()
                .rev()
                .find(|record| record.request.id == action_id)
            {
                Some(record) => {
                    record.result = result;
                    true
                }
                None => false,
            }
        };
        if found {
            self.activity.bump();
        }
        found
    }

    fn record(&self, request: ActionRequest, principal: Principal, result: DispatchResult) {
        {
            let mut journal = self.lock();
            journal.total += 1;
            let sequence = journal.total;
            if journal.records.len() >= MAX_JOURNAL_RECORDS {
                journal.records.pop_front();
            }
            journal.records.push_back(ActionRecord {
                sequence,
                request,
                principal,
                result,
            });
        }
        self.activity.bump();
    }
}

#[async_trait]
impl ActionDispatcher for ActionJournal {
    async fn dispatch(
        &self,
        request: ActionRequest,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        let mut recorded = request.clone();
        recorded.dry_run = recorded.dry_run || self.dispatcher.dry_run();
        let result = self.dispatcher.dispatch(request, principal).await;
        let entry = match &result {
            Ok(disposition) => DispatchResult::Disposition(disposition.clone()),
            Err(error) => DispatchResult::from_error(error),
        };
        self.record(recorded, principal.clone(), entry);
        result
    }
}

/// The built-in action types that the simulation connector accepts.
const SIMULATED_KINDS: [ActionKind; 14] = [
    ActionKind::Enrich,
    ActionKind::Tag,
    ActionKind::Notify,
    ActionKind::SnapshotEvidence,
    ActionKind::OpenTicket,
    ActionKind::RevokeCredential,
    ActionKind::RotateCredential,
    ActionKind::DisableServicePrincipal,
    ActionKind::DisableUser,
    ActionKind::KillSession,
    ActionKind::IsolateHost,
    ActionKind::BlockIp,
    ActionKind::RotateSecret,
    ActionKind::DeployHoneytoken,
];

/// A connector that reports what a dry run would do, for an action type that has no
/// configured connector.
///
/// The composition root adds this connector last, and only when the global dry-run switch
/// is on. A configured connector for an action type thus always has priority. The
/// connector does no network request and changes nothing. It refuses a request that is not
/// a dry run with [`Error::Unsupported`], so it can never stand in for a real change.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulationConnector;

fn kind_name(kind: &ActionKind) -> String {
    match serde_json::to_value(kind) {
        Ok(serde_json::Value::String(name)) => name,
        _ => match kind {
            ActionKind::Custom(name) => format!("custom:{name}"),
            other => format!("{other:?}"),
        },
    }
}

#[async_trait]
impl ActionConnector for SimulationConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: SIMULATION_CONNECTOR.to_owned(),
            vendor: "aegis".to_owned(),
            product: "simulation".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        SIMULATED_KINDS.to_vec()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        let kind = kind_name(&request.kind);
        if !request.dry_run {
            return Err(Error::Unsupported(format!(
                "no connector is configured for the action {kind}: the simulation connector \
                 does only dry runs"
            )));
        }
        Ok(ActionOutcome {
            action_id: request.id,
            status: ActionStatus::Simulated,
            connector: SIMULATION_CONNECTOR.to_owned(),
            message: format!(
                "Dry run: a connector for {kind} would act on {}. No connector is configured \
                 for this action. Nothing changed.",
                request.target.id
            ),
            details: json!({ "configured_connector": false }),
            reversible: false,
            completed_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::policy::PrincipalKind;
    use aegis_respond::ActionRegistry;
    use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};

    use super::*;

    fn request(kind: ActionKind, dry_run: bool) -> ActionRequest {
        let mut request = ActionRequest::new(
            kind,
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            "responder",
            "The attack came from this address.",
        );
        request.dry_run = dry_run;
        request
    }

    fn responder() -> Principal {
        Principal::new("responder", PrincipalKind::Agent, &["responder"])
    }

    struct Stack {
        journal: ActionJournal,
        firewall: Arc<RecordingConnector>,
        activity: Arc<Activity>,
    }

    fn stack(policy: StaticPolicy, dry_run: bool) -> Stack {
        let firewall = Arc::new(RecordingConnector::new(
            "firewall",
            vec![ActionKind::BlockIp],
        ));
        let mut registry = ActionRegistry::new();
        registry.register(firewall.clone()).unwrap();
        let dispatcher = Dispatcher::builder(
            Arc::new(registry),
            Arc::new(policy),
            Arc::new(MemoryApprovals::default()),
            Arc::new(MemoryAuditLog::default()),
        )
        .dry_run(dry_run)
        .build();
        let activity = Arc::new(Activity::new());
        Stack {
            journal: ActionJournal::new(Arc::new(dispatcher), activity.clone()),
            firewall,
            activity,
        }
    }

    #[tokio::test]
    async fn the_journal_gives_each_request_to_the_dispatcher_and_records_the_result() {
        let stack = stack(StaticPolicy::AllowAll, false);
        let action = request(ActionKind::BlockIp, false);

        let disposition = stack
            .journal
            .dispatch(action.clone(), &responder())
            .await
            .unwrap();

        assert_eq!(stack.firewall.executed(), std::slice::from_ref(&action));
        assert_eq!(
            stack.journal.records(),
            [ActionRecord {
                sequence: 1,
                request: action.clone(),
                principal: responder(),
                result: DispatchResult::Disposition(disposition.clone()),
            }]
        );
        assert!(stack.journal.records()[0].result.changed_the_environment());
        assert_eq!(stack.journal.total(), 1);
        assert_eq!(stack.journal.get(action.id).unwrap().sequence, 1);
        assert_eq!(stack.journal.since(1), []);
        assert_eq!(stack.activity.count(), 1);
    }

    #[tokio::test]
    async fn the_record_shows_the_dry_run_that_the_global_switch_forced() {
        let stack = stack(StaticPolicy::AllowAll, true);
        let action = request(ActionKind::BlockIp, false);

        stack
            .journal
            .dispatch(action.clone(), &responder())
            .await
            .unwrap();

        let records = stack.journal.records();
        assert_eq!(records.len(), 1);
        assert!(records[0].request.dry_run);
        assert!(!records[0].result.changed_the_environment());
        assert!(
            matches!(&records[0].result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated && outcome.action_id == action.id),
            "{:?}",
            records[0].result
        );
    }

    #[tokio::test]
    async fn a_dispatcher_error_is_in_the_journal_and_goes_to_the_caller() {
        let stack = stack(StaticPolicy::AllowAll, false);
        let action = request(ActionKind::IsolateHost, false);

        let error = stack
            .journal
            .dispatch(action.clone(), &responder())
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Unsupported(_)), "{error:?}");
        let records = stack.journal.records();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].result,
            DispatchResult::Failed {
                kind: "unsupported".to_owned(),
                message: error.to_string(),
                retryable: false,
            }
        );
    }

    #[tokio::test]
    async fn set_result_replaces_the_result_of_a_pending_request() {
        let stack = stack(StaticPolicy::ByTier, false);
        let action = request(ActionKind::BlockIp, false);
        let pending = stack
            .journal
            .dispatch(action.clone(), &responder())
            .await
            .unwrap();
        assert!(matches!(pending, ActionDisposition::PendingApproval { .. }));
        let count = stack.activity.count();

        let failed = DispatchResult::from_error(&Error::Timeout("no answer".to_owned()));
        assert!(stack.journal.set_result(action.id, failed.clone()));

        assert_eq!(stack.journal.get(action.id).unwrap().result, failed);
        assert_eq!(stack.activity.count(), count + 1);
        assert!(!stack.journal.set_result(ActionId::new(), failed));
        assert_eq!(stack.activity.count(), count + 1);
    }

    #[tokio::test]
    async fn the_journal_keeps_the_newest_records_and_counts_all() {
        let stack = stack(StaticPolicy::DenyAll, false);
        let total = MAX_JOURNAL_RECORDS + 3;
        let mut last = None;
        for _ in 0..total {
            let action = request(ActionKind::BlockIp, false);
            last = Some(action.id);
            stack.journal.dispatch(action, &responder()).await.unwrap();
        }

        let records = stack.journal.records();
        assert_eq!(records.len(), MAX_JOURNAL_RECORDS);
        assert_eq!(stack.journal.total(), total as u64);
        assert_eq!(records[0].sequence, 4);
        assert_eq!(records[MAX_JOURNAL_RECORDS - 1].sequence, total as u64);
        assert_eq!(records[MAX_JOURNAL_RECORDS - 1].request.id, last.unwrap());
        assert_eq!(stack.journal.since(total as u64 - 2).len(), 2);
    }

    #[tokio::test]
    async fn the_simulation_connector_does_only_dry_runs() {
        let connector = SimulationConnector;
        assert_eq!(connector.info().name, "simulation");
        assert_eq!(connector.supported_actions().len(), 14);

        let dry = request(ActionKind::DisableServicePrincipal, true);
        let outcome = connector.execute(&dry).await.unwrap();
        assert_eq!(outcome.action_id, dry.id);
        assert_eq!(outcome.status, ActionStatus::Simulated);
        assert_eq!(outcome.connector, "simulation");
        assert!(!outcome.reversible);
        assert_eq!(
            outcome.message,
            "Dry run: a connector for disable_service_principal would act on 203.0.113.50. No \
             connector is configured for this action. Nothing changed."
        );

        let live = request(ActionKind::DisableServicePrincipal, false);
        let error = connector.execute(&live).await.unwrap_err();
        assert!(
            matches!(&error, Error::Unsupported(message)
                if message == "no connector is configured for the action \
                    disable_service_principal: the simulation connector does only dry runs"),
            "{error:?}"
        );
        // The default `revert` of the contract also changes nothing.
        let revert = connector.revert(&live).await.unwrap_err();
        assert!(matches!(revert, Error::Unsupported(_)), "{revert:?}");
    }

    #[test]
    fn each_error_variant_has_a_name() {
        let errors = [
            (Error::InvalidInput(String::new()), "invalid_input"),
            (Error::NotFound(String::new()), "not_found"),
            (Error::Config(String::new()), "config"),
            (Error::Unauthorized(String::new()), "unauthorized"),
            (Error::Denied(String::new()), "denied"),
            (Error::Unsupported(String::new()), "unsupported"),
            (Error::Unavailable(String::new()), "unavailable"),
            (Error::RateLimited(String::new()), "rate_limited"),
            (Error::Timeout(String::new()), "timeout"),
            (Error::Refused(String::new()), "refused"),
            (Error::BudgetExceeded(String::new()), "budget_exceeded"),
            (Error::Serialization(String::new()), "serialization"),
            (Error::Integrity(String::new()), "integrity"),
            (Error::other("context", "cause"), "other"),
        ];
        for (error, name) in errors {
            assert_eq!(error_kind(&error), name);
        }
        assert_eq!(kind_name(&ActionKind::BlockIp), "block_ip");
        assert_eq!(
            kind_name(&ActionKind::Custom("quarantine_mailbox".to_owned())),
            "custom:quarantine_mailbox"
        );
    }
}
