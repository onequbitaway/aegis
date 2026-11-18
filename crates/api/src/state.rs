//! The state of the API: the services that the API reads and drives.

use std::fmt;
use std::sync::Arc;

use aegis_agents::AgentRuntime;
use aegis_contracts::action::ActionDisposition;
use aegis_contracts::audit::AuditLog;
use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::ApprovalId;
use aegis_contracts::graph::DefensiveGraph;
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{ApprovalQueue, ApprovalRequest, Principal};
use aegis_core::ModuleSet;
use aegis_policy::Rbac;
use aegis_respond::PlaybookEngine;
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
}

impl ApiState {
    /// Makes the state from its parts. Secrets come from the environment of the process.
    #[must_use]
    pub fn new(parts: ApiParts) -> Self {
        Self {
            parts: Arc::new(parts),
            env: Arc::new(process_env),
        }
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
}

impl fmt::Debug for ApiState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiState")
            .field("modules", &self.parts.modules)
            .finish_non_exhaustive()
    }
}
