//! Friction actions: reversible changes that slow an attacker during a critical incident.
//!
//! A friction action changes a control of the operator, in the environment of the operator,
//! through the administrative API of the product. It does not act on the attacker. It makes
//! the next step of an attack more difficult while the security team examines the incident.
//!
//! | Action | Connector | Effect |
//! | --- | --- | --- |
//! | `{custom: restrict_user_consent}` | [`GraphActionConnector`](crate::GraphActionConnector) | Users of the tenant cannot consent to applications. |
//! | `{custom: raise_friction}` | [`WebhookConnector`](crate::WebhookConnector) | The automation of the operator raises a control, for example a strict conditional-access policy or a change freeze. |
//!
//! # Rules
//!
//! - **Reversible.** A friction action must have an inverse. Before a friction action
//!   changes the target, the dispatcher makes sure that the connector can undo it. A webhook
//!   endpoint for a friction action must have `reversible: true`.
//! - **Policy.** A friction action is a custom action, so its default tier is `gated`.
//! - **Not in a draft.** A response draft from a model cannot use a friction action, unless
//!   the operator adds the action to
//!   [`DraftOptions::allowed_actions`](crate::DraftOptions::allowed_actions). A friction
//!   step of a draft always has a timed revert.
//!
//! Use a timed revert with a friction action. Refer to [`revert`](crate::revert).

use aegis_contracts::action::ActionKind;

/// The name of the custom action that stops user consent to applications in a tenant.
///
/// The target is the tenant. [`GraphActionConnector`](crate::GraphActionConnector) does
/// this action.
pub const RESTRICT_USER_CONSENT: &str = "restrict_user_consent";

/// The name of the custom action that raises a control of the operator.
///
/// [`WebhookConnector`](crate::WebhookConnector) sends this action to the automation of the
/// operator. Refer to [`parameter`] for the parameters that the samples use.
pub const RAISE_FRICTION: &str = "raise_friction";

/// The names of the friction actions.
pub const FRICTION_ACTIONS: [&str; 2] = [RESTRICT_USER_CONSENT, RAISE_FRICTION];

/// The request parameters that the samples use for [`RAISE_FRICTION`].
///
/// The webhook connector sends each parameter to the receiver and does not read it. The
/// receiver of the operator gives the parameters their effect.
pub mod parameter {
    /// The name of the control that the receiver raises, for example
    /// `conditional_access_strict` or `change_freeze`.
    pub const CONTROL: &str = "control";
    /// The level of the control, for example `high`. This parameter is optional.
    pub const LEVEL: &str = "level";
}

/// Returns the action type [`RESTRICT_USER_CONSENT`].
#[must_use]
pub fn restrict_user_consent() -> ActionKind {
    ActionKind::Custom(RESTRICT_USER_CONSENT.to_owned())
}

/// Returns the action type [`RAISE_FRICTION`].
#[must_use]
pub fn raise_friction() -> ActionKind {
    ActionKind::Custom(RAISE_FRICTION.to_owned())
}

/// Returns `true` if `kind` is a friction action.
#[must_use]
pub fn is_friction(kind: &ActionKind) -> bool {
    matches!(kind, ActionKind::Custom(name) if FRICTION_ACTIONS.contains(&name.as_str()))
}

/// Returns the friction action with this name.
pub(crate) fn from_name(name: &str) -> Option<ActionKind> {
    FRICTION_ACTIONS
        .contains(&name)
        .then(|| ActionKind::Custom(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_custom_actions_are_friction_actions() {
        assert!(is_friction(&restrict_user_consent()));
        assert!(is_friction(&raise_friction()));
        assert!(!is_friction(&ActionKind::Custom(
            "quarantine_mailbox".to_owned()
        )));
        assert!(!is_friction(&ActionKind::DisableUser));
        assert_eq!(
            from_name("restrict_user_consent"),
            Some(restrict_user_consent())
        );
        assert_eq!(from_name("raise_friction"), Some(raise_friction()));
        assert_eq!(from_name("disable_user"), None);
        assert_eq!(from_name("Restrict_User_Consent"), None);
    }
}
