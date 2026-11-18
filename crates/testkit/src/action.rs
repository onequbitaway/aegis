use std::sync::Mutex;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionStatus,
};
use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::{ActionTier, PolicyDecision, PolicyEffect, Principal};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;

use crate::lock;

/// An action connector that changes nothing and records each request.
pub struct RecordingConnector {
    name: String,
    supported: Vec<ActionKind>,
    failure: Option<String>,
    executed: Mutex<Vec<ActionRequest>>,
    reverted: Mutex<Vec<ActionRequest>>,
}

impl RecordingConnector {
    /// Makes a connector that supports `supported`.
    pub fn new(name: impl Into<String>, supported: Vec<ActionKind>) -> Self {
        Self {
            name: name.into(),
            supported,
            failure: None,
            executed: Mutex::default(),
            reverted: Mutex::default(),
        }
    }

    /// Makes each call fail with [`Error::Unavailable`] and this message.
    #[must_use]
    pub fn failing(mut self, message: impl Into<String>) -> Self {
        self.failure = Some(message.into());
        self
    }

    /// Returns the requests that [`execute`](ActionConnector::execute) received.
    #[must_use]
    pub fn executed(&self) -> Vec<ActionRequest> {
        lock(&self.executed).clone()
    }

    /// Returns the requests that [`revert`](ActionConnector::revert) received.
    #[must_use]
    pub fn reverted(&self) -> Vec<ActionRequest> {
        lock(&self.reverted).clone()
    }

    fn outcome(&self, request: &ActionRequest, verb: &str) -> Result<ActionOutcome> {
        if let Some(message) = &self.failure {
            return Err(Error::Unavailable(message.clone()));
        }
        if !self.supported.contains(&request.kind) {
            return Err(Error::Unsupported(format!(
                "connector {} does not support {:?}",
                self.name, request.kind
            )));
        }
        let (status, message) = if request.dry_run {
            (
                ActionStatus::Simulated,
                format!("Would {verb} {:?} on {}.", request.kind, request.target.id),
            )
        } else {
            (
                ActionStatus::Succeeded,
                format!("Did {verb} {:?} on {}.", request.kind, request.target.id),
            )
        };
        Ok(ActionOutcome {
            action_id: request.id,
            status,
            connector: self.name.clone(),
            message,
            details: serde_json::Value::Null,
            reversible: true,
            completed_at: Utc::now(),
        })
    }
}

#[async_trait]
impl ActionConnector for RecordingConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: "aegis".to_owned(),
            product: "recording".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        self.supported.clone()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        lock(&self.executed).push(request.clone());
        self.outcome(request, "execute")
    }

    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        lock(&self.reverted).push(request.clone());
        self.outcome(request, "revert")
    }
}

/// What a [`RecordingDispatcher`] returns for each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchMode {
    /// Return [`ActionDisposition::Executed`].
    Execute,
    /// Return [`ActionDisposition::PendingApproval`].
    RequireApproval,
    /// Return [`ActionDisposition::Denied`].
    Deny,
}

/// An action dispatcher that changes nothing and records each request.
pub struct RecordingDispatcher {
    mode: DispatchMode,
    requests: Mutex<Vec<(ActionRequest, Principal)>>,
}

impl RecordingDispatcher {
    /// Makes a dispatcher that answers each request as `mode` says.
    #[must_use]
    pub fn new(mode: DispatchMode) -> Self {
        Self {
            mode,
            requests: Mutex::default(),
        }
    }

    /// Returns the requests that the dispatcher received, with the principal of each.
    #[must_use]
    pub fn requests(&self) -> Vec<(ActionRequest, Principal)> {
        lock(&self.requests).clone()
    }
}

#[async_trait]
impl ActionDispatcher for RecordingDispatcher {
    async fn dispatch(
        &self,
        request: ActionRequest,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        lock(&self.requests).push((request.clone(), principal.clone()));
        let decision = |effect| PolicyDecision {
            effect,
            tier: request.kind.default_tier(),
            reasons: vec![format!("The test dispatcher is in {:?} mode.", self.mode)],
            policy: Some("testkit.dispatcher".to_owned()),
            evaluated_at: Utc::now(),
        };
        Ok(match self.mode {
            DispatchMode::Execute => ActionDisposition::Executed(ActionOutcome {
                action_id: request.id,
                status: if request.dry_run {
                    ActionStatus::Simulated
                } else {
                    ActionStatus::Succeeded
                },
                connector: "testkit".to_owned(),
                message: format!("Recorded {:?} on {}.", request.kind, request.target.id),
                details: serde_json::Value::Null,
                reversible: request.kind.default_tier() == ActionTier::Auto,
                completed_at: Utc::now(),
            }),
            DispatchMode::RequireApproval => ActionDisposition::PendingApproval {
                approval_id: ApprovalId::new(),
                decision: decision(PolicyEffect::RequireApproval),
            },
            DispatchMode::Deny => ActionDisposition::Denied(decision(PolicyEffect::Deny)),
        })
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::policy::PrincipalKind;

    use super::*;

    fn request(kind: ActionKind, dry_run: bool) -> ActionRequest {
        let mut request = ActionRequest::new(
            kind,
            EntityRef::new(EntityKind::ServicePrincipal, "sp-1"),
            "responder",
            "Test.",
        );
        request.dry_run = dry_run;
        request
    }

    #[tokio::test]
    async fn the_connector_records_requests_and_obeys_dry_run() {
        let connector = RecordingConnector::new("rec", vec![ActionKind::BlockIp]);
        let simulated = connector
            .execute(&request(ActionKind::BlockIp, true))
            .await
            .unwrap();
        assert_eq!(simulated.status, ActionStatus::Simulated);
        assert_eq!(simulated.connector, "rec");
        let live = request(ActionKind::BlockIp, false);
        let done = connector.execute(&live).await.unwrap();
        assert_eq!(done.status, ActionStatus::Succeeded);
        assert_eq!(done.action_id, live.id);
        connector.revert(&live).await.unwrap();

        assert_eq!(connector.executed().len(), 2);
        assert_eq!(connector.reverted(), vec![live]);
        assert_eq!(connector.supported_actions(), vec![ActionKind::BlockIp]);
        assert_eq!(connector.info().name, "rec");
    }

    #[tokio::test]
    async fn the_connector_rejects_unsupported_kinds_and_scripted_failures() {
        let connector = RecordingConnector::new("rec", vec![ActionKind::BlockIp]);
        let unsupported = connector
            .execute(&request(ActionKind::IsolateHost, false))
            .await
            .unwrap_err();
        assert!(matches!(unsupported, Error::Unsupported(_)));
        assert_eq!(connector.executed().len(), 1);

        let failing = RecordingConnector::new("rec", vec![ActionKind::BlockIp]).failing("down");
        let error = failing
            .execute(&request(ActionKind::BlockIp, false))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Unavailable(message) if message == "down"));
    }

    #[tokio::test]
    async fn the_dispatcher_answers_as_its_mode_says() {
        let principal = Principal::new("responder", PrincipalKind::Agent, &["agent"]);
        let execute = RecordingDispatcher::new(DispatchMode::Execute);
        let disposition = execute
            .dispatch(request(ActionKind::Notify, true), &principal)
            .await
            .unwrap();
        assert!(
            matches!(&disposition, ActionDisposition::Executed(outcome) if outcome.status == ActionStatus::Simulated),
            "{disposition:?}"
        );
        assert_eq!(execute.requests().len(), 1);
        assert_eq!(execute.requests()[0].1, principal);

        let approval = RecordingDispatcher::new(DispatchMode::RequireApproval)
            .dispatch(request(ActionKind::IsolateHost, false), &principal)
            .await
            .unwrap();
        assert!(
            matches!(&approval, ActionDisposition::PendingApproval { decision, .. } if decision.effect == PolicyEffect::RequireApproval && decision.tier == ActionTier::Gated),
            "{approval:?}"
        );

        let denied = RecordingDispatcher::new(DispatchMode::Deny)
            .dispatch(request(ActionKind::IsolateHost, false), &principal)
            .await
            .unwrap();
        assert!(
            matches!(&denied, ActionDisposition::Denied(decision) if decision.effect == PolicyEffect::Deny),
            "{denied:?}"
        );
    }
}
