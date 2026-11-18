use std::collections::BTreeMap;
use std::sync::Mutex;

use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    PolicyEngine, PolicyInput, Principal,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;

use crate::lock;

/// A policy engine with a fixed rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticPolicy {
    /// Permit each action.
    AllowAll,
    /// Deny each action.
    DenyAll,
    /// Permit actions in the auto tier. Require approval for actions in the gated tier.
    ByTier,
}

#[async_trait]
impl PolicyEngine for StaticPolicy {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision> {
        let (effect, reason) = match (self, input.default_tier) {
            (Self::AllowAll, _) => (PolicyEffect::Allow, "The test policy permits all actions."),
            (Self::DenyAll, _) => (PolicyEffect::Deny, "The test policy denies all actions."),
            (Self::ByTier, ActionTier::Auto) => {
                (PolicyEffect::Allow, "The action is in the auto tier.")
            }
            (Self::ByTier, ActionTier::Gated) => (
                PolicyEffect::RequireApproval,
                "The action is in the gated tier.",
            ),
        };
        Ok(PolicyDecision {
            effect,
            tier: input.default_tier,
            reasons: vec![reason.to_owned()],
            policy: Some("testkit.static".to_owned()),
            evaluated_at: Utc::now(),
        })
    }
}

/// An approval queue that keeps all requests in memory.
#[derive(Default)]
pub struct MemoryApprovals {
    requests: Mutex<BTreeMap<ApprovalId, ApprovalRequest>>,
}

#[async_trait]
impl ApprovalQueue for MemoryApprovals {
    async fn submit(&self, request: ApprovalRequest) -> Result<()> {
        lock(&self.requests).insert(request.id, request);
        Ok(())
    }

    async fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>> {
        Ok(lock(&self.requests).get(&id).cloned())
    }

    async fn pending(&self) -> Result<Vec<ApprovalRequest>> {
        let mut pending: Vec<ApprovalRequest> = lock(&self.requests)
            .values()
            .filter(|request| request.status == ApprovalStatus::Pending)
            .cloned()
            .collect();
        pending.sort_by_key(|request| request.requested_at);
        Ok(pending)
    }

    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        decided_by: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalRequest> {
        let mut requests = lock(&self.requests);
        let request = requests
            .get_mut(&id)
            .ok_or_else(|| Error::NotFound(format!("approval request {id}")))?;
        if request.status != ApprovalStatus::Pending {
            return Err(Error::InvalidInput(format!(
                "approval request {id} already has a decision"
            )));
        }
        request.status = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        request.decided_by = Some(decided_by.id.clone());
        request.decided_at = Some(Utc::now());
        request.note = note;
        Ok(request.clone())
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::{ActionKind, ActionRequest};
    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::policy::PrincipalKind;
    use chrono::Duration;

    use super::*;

    fn input(kind: ActionKind) -> PolicyInput {
        PolicyInput::new(
            ActionRequest::new(
                kind,
                EntityRef::new(EntityKind::Host, "host-1"),
                "responder",
                "Test.",
            ),
            Principal::new("responder", PrincipalKind::Agent, &["agent"]),
        )
    }

    fn approval(age_seconds: i64) -> ApprovalRequest {
        let input = input(ActionKind::IsolateHost);
        ApprovalRequest {
            id: ApprovalId::new(),
            action: input.action,
            requested_by: input.principal,
            decision: PolicyDecision {
                effect: PolicyEffect::RequireApproval,
                tier: ActionTier::Gated,
                reasons: Vec::new(),
                policy: None,
                evaluated_at: Utc::now(),
            },
            status: ApprovalStatus::Pending,
            requested_at: Utc::now() - Duration::seconds(age_seconds),
            decided_by: None,
            decided_at: None,
            note: None,
        }
    }

    #[tokio::test]
    async fn each_static_policy_gives_its_fixed_effect() {
        let cases = [
            (
                StaticPolicy::AllowAll,
                ActionKind::IsolateHost,
                PolicyEffect::Allow,
            ),
            (
                StaticPolicy::DenyAll,
                ActionKind::Notify,
                PolicyEffect::Deny,
            ),
            (
                StaticPolicy::ByTier,
                ActionKind::Notify,
                PolicyEffect::Allow,
            ),
            (
                StaticPolicy::ByTier,
                ActionKind::IsolateHost,
                PolicyEffect::RequireApproval,
            ),
        ];
        for (policy, kind, expected) in cases {
            let input = input(kind.clone());
            let decision = policy.evaluate(&input).await.unwrap();
            assert_eq!(decision.effect, expected, "{policy:?} {kind:?}");
            assert_eq!(decision.tier, input.default_tier);
            assert_eq!(decision.reasons.len(), 1);
        }
    }

    #[tokio::test]
    async fn the_queue_lists_pending_requests_oldest_first() {
        let queue = MemoryApprovals::default();
        let newer = approval(10);
        let older = approval(60);
        queue.submit(newer.clone()).await.unwrap();
        queue.submit(older.clone()).await.unwrap();
        let pending: Vec<ApprovalId> = queue
            .pending()
            .await
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(pending, [older.id, newer.id]);
        assert_eq!(queue.get(newer.id).await.unwrap(), Some(newer));
        assert_eq!(queue.get(ApprovalId::new()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_decision_is_recorded_one_time_only() {
        let queue = MemoryApprovals::default();
        let request = approval(1);
        queue.submit(request.clone()).await.unwrap();
        let approver = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);

        let decided = queue
            .decide(request.id, false, &approver, Some("Not now.".to_owned()))
            .await
            .unwrap();
        assert_eq!(decided.status, ApprovalStatus::Rejected);
        assert_eq!(decided.decided_by.as_deref(), Some("alice@example.com"));
        assert_eq!(decided.note.as_deref(), Some("Not now."));
        assert!(decided.decided_at.is_some());
        assert!(queue.pending().await.unwrap().is_empty());

        let again = queue
            .decide(request.id, true, &approver, None)
            .await
            .unwrap_err();
        assert!(matches!(again, Error::InvalidInput(message) if message.contains("already")));
        assert_eq!(
            queue.get(request.id).await.unwrap().map(|r| r.status),
            Some(ApprovalStatus::Rejected)
        );
        let missing = queue
            .decide(ApprovalId::new(), true, &approver, None)
            .await
            .unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)));
    }
}
