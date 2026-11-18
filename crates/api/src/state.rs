//! The state of the API: the services that the API reads and drives.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use aegis_agents::AgentRuntime;
use aegis_contracts::action::ActionDisposition;
use aegis_contracts::audit::AuditLog;
use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::{ActionId, ApprovalId};
use aegis_contracts::graph::DefensiveGraph;
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{ApprovalQueue, ApprovalRequest, Principal};
use aegis_core::ModuleSet;
use aegis_policy::Rbac;
use aegis_respond::{PendingRevert, PlaybookEngine};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A function that returns the value of an environment variable.
///
/// The API reads each secret through this function. Use [`process_env`] in a program and a
/// closure in a test.
pub type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Reads one variable from the environment of the process.
///
/// A variable that is not set, or that is not valid Unicode, gives `None`.
#[must_use]
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The result of one approval decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// The approval request after the decision.
    pub request: ApprovalRequest,
    /// For an approval, what the dispatcher did with the action. For a rejection, `None`.
    #[serde(default)]
    pub disposition: Option<ActionDisposition>,
}

/// The path by which a person decides a gated action.
///
/// The composition root implements this trait. The implementation checks the approval
/// rules, writes the audit record, records the decision in the queue, and, for an
/// approval, runs the action. This crate only calls it.
///
/// The REST API, the gRPC API, and the ChatOps endpoints all call this trait after they
/// identify the principal and check [`Permission::ApproveActions`](aegis_policy::Permission).
#[async_trait]
pub trait ApprovalActions: Send + Sync {
    /// Records the decision of `principal` on the approval request `id`.
    ///
    /// With `approve` set to `true`, the implementation then runs the action and returns
    /// its disposition.
    ///
    /// # Errors
    ///
    /// An implementation returns [`Error::NotFound`](aegis_contracts::Error::NotFound) for
    /// an unknown request, [`Error::InvalidInput`](aegis_contracts::Error::InvalidInput)
    /// for a request that already has a decision, and
    /// [`Error::Unauthorized`](aegis_contracts::Error::Unauthorized) if an approval rule
    /// does not permit the principal.
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> aegis_contracts::Result<ApprovalDecision>;
}

/// The path by which a person decides a timed revert, and reverts an action.
///
/// The composition root implements this trait. The implementation checks the permission
/// of the principal again, writes each audit record with the principal, and sends each
/// revert through the dispatcher: the policy, the approval queue, and the audit log. This
/// crate only calls it, after it identified the principal and checked
/// [`Permission::ApproveActions`](aegis_policy::Permission).
///
/// A state with no implementation has no timed revert: the list is empty, and each other
/// route answers with the status 501.
#[async_trait]
pub trait RevertActions: Send + Sync {
    /// Returns `true` if the process holds timed reverts.
    fn enabled(&self) -> bool;

    /// Lists the timed reverts that wait. The revert with the earliest time is first.
    ///
    /// # Errors
    ///
    /// An implementation returns the error of its store.
    async fn pending(&self) -> aegis_contracts::Result<Vec<PendingRevert>>;

    /// Confirms the action `action_id`. The containment stays.
    ///
    /// # Errors
    ///
    /// An implementation returns [`Error::NotFound`](aegis_contracts::Error::NotFound) if
    /// the action has no pending revert, and
    /// [`Error::Unauthorized`](aegis_contracts::Error::Unauthorized) if the principal is
    /// not a person or has no permission.
    async fn confirm(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> aegis_contracts::Result<PendingRevert>;

    /// Moves the revert time of the action `action_id` by `extension`.
    ///
    /// # Errors
    ///
    /// The errors of [`RevertActions::confirm`], and
    /// [`Error::InvalidInput`](aegis_contracts::Error::InvalidInput) for an extension
    /// that is not permitted.
    async fn extend(
        &self,
        action_id: ActionId,
        principal: &Principal,
        extension: Duration,
    ) -> aegis_contracts::Result<PendingRevert>;

    /// Reverts the action `action_id` immediately, before its revert time.
    ///
    /// # Errors
    ///
    /// An implementation returns [`Error::NotFound`](aegis_contracts::Error::NotFound) if
    /// the action has no pending revert, and the error of the revert.
    async fn cancel(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> aegis_contracts::Result<ActionDisposition>;

    /// Reverts one action that a connector did before, with or without a timed revert.
    ///
    /// # Errors
    ///
    /// An implementation returns [`Error::NotFound`](aegis_contracts::Error::NotFound) if
    /// the audit log has no execution of the action, and
    /// [`Error::InvalidInput`](aegis_contracts::Error::InvalidInput) if the action cannot
    /// be reverted, for example because it was a dry run.
    async fn revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
    ) -> aegis_contracts::Result<ActionDisposition>;
}

/// The counts of the flood protection of the detection engine, for the status route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloodStatus {
    /// The rule and indicator matches that gave no detection.
    pub suppressed_matches: u64,
    /// The detections for a rule that matched many times for one key.
    pub repeat_detections: u64,
    /// The `suspicious` detections that got no model request.
    pub triage_quota_denials: u64,
    /// The incident states that a newer state of the same incident replaced.
    pub coalesced_incident_updates: u64,
}

/// The data of the composition root that the status route shows.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    /// The counts of the flood protection, from the start of the process.
    pub flood: FloodStatus,
    /// More fields of the status document: the name of the field and its value. A name
    /// that the status document already has is not used.
    #[serde(flatten)]
    pub sections: BTreeMap<String, serde_json::Value>,
}

/// Gives the status route the data that only the composition root has.
#[async_trait]
pub trait StatusSource: Send + Sync {
    /// Returns the data of this time.
    async fn status(&self) -> SystemStatus;
}

/// The services that make an [`ApiState`].
///
/// Tests fill this structure with the in-memory services of the test kit. The composition
/// root fills it with the real services.
#[derive(Clone)]
pub struct ApiParts {
    /// The incident store.
    pub incidents: Arc<dyn IncidentStore>,
    /// The Defensive Graph.
    pub graph: Arc<dyn DefensiveGraph>,
    /// The audit log.
    pub audit: Arc<dyn AuditLog>,
    /// The approval queue. The API only reads it.
    pub approvals: Arc<dyn ApprovalQueue>,
    /// The message bus. The live feed and the notification task subscribe to it.
    pub bus: Arc<dyn MessageBus>,
    /// The role-based access control check.
    pub rbac: Rbac,
    /// The agent runtime.
    pub agents: Arc<AgentRuntime>,
    /// The playbook engine.
    pub playbooks: Arc<PlaybookEngine>,
    /// The path for approval decisions.
    pub approval_actions: Arc<dyn ApprovalActions>,
    /// The modules that the process runs. The status route shows them.
    pub modules: ModuleSet,
}

/// The state of the API. A clone shares the services of the original.
#[derive(Clone)]
pub struct ApiState {
    parts: Arc<ApiParts>,
    env: EnvLookup,
    reverts: Option<Arc<dyn RevertActions>>,
    status: Option<Arc<dyn StatusSource>>,
}

impl ApiState {
    /// Makes the state from its parts. Secrets come from the environment of the process.
    #[must_use]
    pub fn new(parts: ApiParts) -> Self {
        Self {
            parts: Arc::new(parts),
            env: Arc::new(process_env),
            reverts: None,
            status: None,
        }
    }

    /// Sets the path for timed reverts and for the revert of an action.
    ///
    /// Without it, the API has no timed revert. Refer to [`RevertActions`].
    #[must_use]
    pub fn with_reverts(mut self, reverts: Arc<dyn RevertActions>) -> Self {
        self.reverts = Some(reverts);
        self
    }

    /// Sets the source of the data that only the composition root has. The status route
    /// then shows the flood counters.
    #[must_use]
    pub fn with_status(mut self, status: Arc<dyn StatusSource>) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the function that returns the value of an environment variable.
    ///
    /// The API calls it for each `*_env` name in the [`ApiConfig`](crate::ApiConfig).
    #[must_use]
    pub fn with_env(
        mut self,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.env = Arc::new(env);
        self
    }

    /// Returns the services.
    #[must_use]
    pub fn parts(&self) -> &ApiParts {
        &self.parts
    }

    /// Returns the function that reads an environment variable.
    pub(crate) fn env(&self) -> &EnvLookup {
        &self.env
    }

    /// Returns the path for timed reverts, if the state has one.
    pub(crate) fn reverts(&self) -> Option<&Arc<dyn RevertActions>> {
        self.reverts.as_ref()
    }

    /// Returns the source of the status data, if the state has one.
    pub(crate) fn status(&self) -> Option<&Arc<dyn StatusSource>> {
        self.status.as_ref()
    }
}

impl fmt::Debug for ApiState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiState")
            .field("modules", &self.parts.modules)
            .finish_non_exhaustive()
    }
}
