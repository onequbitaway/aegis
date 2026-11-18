//! The contract for policy, decisions, and approvals.
//!
//! The operator owns the policy. The policy sets which actions run automatically, which
//! actions must have approval, and which actions are not permitted.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::ActionRequest;
use crate::common::{ApprovalId, IncidentId, Severity};
use crate::error::Result;
use crate::incident::IncidentStatus;

/// The tier of an action. The operator assigns the tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTier {
    /// A safe and reversible action. No approval is necessary.
    Auto,
    /// A disruptive action. A policy check applies, and approval can be necessary.
    Gated,
}

/// The type of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// An AEGIS agent.
    Agent,
    /// A person.
    Human,
    /// An AEGIS component that is not an agent, for example the playbook engine.
    System,
}

/// The identity that requests or approves an operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    /// The identifier of the principal, for example `responder` or `alice@example.com`.
    pub id: String,
    /// The type of the principal.
    pub kind: PrincipalKind,
    /// The roles of the principal. Role-based access control uses them.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl Principal {
    /// Makes a principal.
    pub fn new(id: impl Into<String>, kind: PrincipalKind, roles: &[&str]) -> Self {
        Self {
            id: id.into(),
            kind,
            roles: roles.iter().map(ToString::to_string).collect(),
        }
    }

    /// Returns `true` if the principal has `role`.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|candidate| candidate == role)
    }
}

/// Data about the incident that an action responds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentContext {
    /// The identifier of the incident.
    pub id: IncidentId,
    /// The severity of the incident.
    pub severity: Severity,
    /// The state of the incident.
    pub status: IncidentStatus,
}

/// The input document for a policy evaluation.
///
/// The policy engine gives this value to the policy as its `input` document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyInput {
    /// The action to evaluate.
    pub action: ActionRequest,
    /// The default tier of the action. Refer to
    /// [`ActionKind::default_tier`](crate::action::ActionKind::default_tier).
    pub default_tier: ActionTier,
    /// The identity that requests the action.
    pub principal: Principal,
    /// The incident that the action responds to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident: Option<IncidentContext>,
    /// More data that the operator supplies, for example a maintenance window.
    #[serde(default)]
    pub environment: serde_json::Value,
}

impl PolicyInput {
    /// Makes an input with no incident and no environment data.
    #[must_use]
    pub fn new(action: ActionRequest, principal: Principal) -> Self {
        Self {
            default_tier: action.kind.default_tier(),
            action,
            principal,
            incident: None,
            environment: serde_json::Value::Null,
        }
    }
}

/// What the policy permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    /// The action can run immediately.
    Allow,
    /// The action can run only after a person approves it.
    RequireApproval,
    /// The action must not run.
    Deny,
}

/// The result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// What the policy permits.
    pub effect: PolicyEffect,
    /// The tier that the policy gives to the action.
    pub tier: ActionTier,
    /// The reasons that the policy gives. Each reason is one sentence.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// The policy rule that made the decision, for example `aegis.response.decision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// The time of the evaluation.
    pub evaluated_at: DateTime<Utc>,
}

/// A policy engine. It evaluates the policy of the operator for one action.
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluates the policy for `input`.
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision>;
}

/// The state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// No person has decided.
    #[default]
    Pending,
    /// A person approved the action.
    Approved,
    /// A person rejected the action.
    Rejected,
}

/// A gated action that waits for the decision of a person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The identifier of the approval request.
    pub id: ApprovalId,
    /// The action that waits for approval.
    pub action: ActionRequest,
    /// The identity that requested the action.
    pub requested_by: Principal,
    /// The policy decision that made approval necessary.
    pub decision: PolicyDecision,
    /// The state of the request.
    #[serde(default)]
    pub status: ApprovalStatus,
    /// The time at which the request entered the queue.
    pub requested_at: DateTime<Utc>,
    /// The identifier of the principal that decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// The time of the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// A note from the principal that decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The queue of gated actions that wait for approval.
#[async_trait]
pub trait ApprovalQueue: Send + Sync {
    /// Puts a request in the queue.
    async fn submit(&self, request: ApprovalRequest) -> Result<()>;

    /// Reads one request.
    async fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>>;

    /// Lists the requests that have no decision, oldest first.
    async fn pending(&self) -> Result<Vec<ApprovalRequest>>;

    /// Records the decision of `decided_by` and returns the changed request.
    ///
    /// An implementation must return an error if the request already has a decision.
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        decided_by: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalRequest>;
}
