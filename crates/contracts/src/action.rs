//! The contract for response actions.
//!
//! An agent or a playbook makes an [`ActionRequest`]. An [`ActionDispatcher`] sends the
//! request through policy, approval, an [`ActionConnector`], and the audit log.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{ActionId, ApprovalId, EntityRef, EvidenceRef, IncidentId};
use crate::error::{Error, Result};
use crate::policy::{ActionTier, PolicyDecision, Principal};
use crate::source::ConnectorInfo;

/// The type of a response action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Add context to an incident or an entity.
    Enrich,
    /// Put a label on an entity.
    Tag,
    /// Send a message to a person or a channel.
    Notify,
    /// Save a copy of evidence.
    SnapshotEvidence,
    /// Open a ticket in a ticket system.
    OpenTicket,
    /// Remove a credential from an application or a service principal.
    RevokeCredential,
    /// Replace a credential of an application or a service principal.
    RotateCredential,
    /// Disable a service principal.
    DisableServicePrincipal,
    /// Disable a user account.
    DisableUser,
    /// Stop the sessions of a principal.
    KillSession,
    /// Isolate a host from the network.
    IsolateHost,
    /// Block an IP address.
    BlockIp,
    /// Replace a secret in a vault.
    RotateSecret,
    /// Plant a honeytoken or a canary.
    DeployHoneytoken,
    /// An action that a plugin defines.
    Custom(String),
}

impl ActionKind {
    /// Returns the tier that this action has when the operator sets no tier.
    ///
    /// Safe and reversible actions are [`ActionTier::Auto`]. All other actions are
    /// [`ActionTier::Gated`]. The policy of the operator can change the tier.
    #[must_use]
    pub fn default_tier(&self) -> ActionTier {
        match self {
            Self::Enrich | Self::Tag | Self::Notify | Self::SnapshotEvidence | Self::OpenTicket => {
                ActionTier::Auto
            }
            Self::RevokeCredential
            | Self::RotateCredential
            | Self::DisableServicePrincipal
            | Self::DisableUser
            | Self::KillSession
            | Self::IsolateHost
            | Self::BlockIp
            | Self::RotateSecret
            | Self::DeployHoneytoken
            | Self::Custom(_) => ActionTier::Gated,
        }
    }
}

/// A request to do one response action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    /// The identifier of the request.
    pub id: ActionId,
    /// The type of the action.
    pub kind: ActionKind,
    /// The entity that the action changes.
    pub target: EntityRef,
    /// Parameters for the connector.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// The incident that the action responds to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<IncidentId>,
    /// The agent or the playbook that made the request.
    pub requested_by: String,
    /// Why the action is necessary.
    pub reason: String,
    /// The evidence for the action.
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    /// With `true`, the connector must not change the target. It only reports what it would do.
    #[serde(default)]
    pub dry_run: bool,
    /// The time of the request.
    pub requested_at: DateTime<Utc>,
}

impl ActionRequest {
    /// Makes a request with a new identifier and the present time. `dry_run` is `false`.
    pub fn new(
        kind: ActionKind,
        target: EntityRef,
        requested_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: ActionId::new(),
            kind,
            target,
            parameters: BTreeMap::new(),
            incident_id: None,
            requested_by: requested_by.into(),
            reason: reason.into(),
            evidence: Vec::new(),
            dry_run: false,
            requested_at: Utc::now(),
        }
    }
}

/// The result state of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// The connector changed the target.
    Succeeded,
    /// The connector could not change the target.
    Failed,
    /// The request was a dry run. The connector changed nothing.
    Simulated,
    /// The connector found that no change was necessary.
    Skipped,
}

/// The result of one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// The identifier of the request.
    pub action_id: ActionId,
    /// The result state.
    pub status: ActionStatus,
    /// The name of the connector that did the action.
    pub connector: String,
    /// What the connector did, or what it would do in a dry run.
    pub message: String,
    /// More data from the connector.
    #[serde(default)]
    pub details: serde_json::Value,
    /// `true` if [`ActionConnector::revert`] can undo the action.
    #[serde(default)]
    pub reversible: bool,
    /// The time at which the connector completed the action.
    pub completed_at: DateTime<Utc>,
}

/// A response output. An implementation does actions in one vendor system.
///
/// An implementation must obey [`ActionRequest::dry_run`]. It must be safe to share between
/// tasks.
#[async_trait]
pub trait ActionConnector: Send + Sync {
    /// Returns the data that identifies this connector.
    fn info(&self) -> ConnectorInfo;

    /// Returns the action types that this connector can do.
    fn supported_actions(&self) -> Vec<ActionKind>;

    /// Does one action.
    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome>;

    /// Undoes an action that this connector did before.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        Err(Error::Unsupported(format!(
            "connector {} cannot revert action {}",
            self.info().name,
            request.id
        )))
    }
}

/// What the dispatcher did with a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDisposition {
    /// Policy permitted the action and a connector did it.
    Executed(ActionOutcome),
    /// Policy requires approval. The request is in the approval queue.
    PendingApproval {
        /// The identifier of the approval request.
        approval_id: ApprovalId,
        /// The policy decision.
        decision: PolicyDecision,
    },
    /// Policy denied the action.
    Denied(PolicyDecision),
}

/// The single path from an action request to a change in the environment.
///
/// An implementation evaluates policy, puts gated actions in the approval queue, calls the
/// connector, and writes each step to the audit log.
#[async_trait]
pub trait ActionDispatcher: Send + Sync {
    /// Sends one request through policy, approval, and execution.
    async fn dispatch(
        &self,
        request: ActionRequest,
        principal: &Principal,
    ) -> Result<ActionDisposition>;
}
