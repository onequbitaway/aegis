use aegis_contracts::Result;
use aegis_contracts::policy::{
    ActionTier, PolicyDecision, PolicyEffect, PolicyEngine, PolicyInput,
};
use async_trait::async_trait;
use chrono::Utc;

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

#[cfg(test)]
mod tests {
    use aegis_contracts::action::{ActionKind, ActionRequest};
    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::policy::{Principal, PrincipalKind};

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
}
