//! The privileged self-assignment detector.

use aegis_contracts::common::{EntityKind, Severity};
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::Finding;
use crate::attack::technique_in;
use crate::common::event_entities;

/// The rule identifier of a privileged self-assignment detection.
pub const PRIVILEGED_SELF_ASSIGNMENT_RULE_ID: &str = "aegis.velocity.privileged_self_assignment";

/// The settings of [`PrivilegedSelfAssignment`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivilegedSelfAssignmentConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// With `true`, only an event with the attribute `privileged: true` gives a detection.
    /// Set to `false` for a source that does not mark privileged roles. Each
    /// self-assignment then gives a detection.
    pub require_privileged: bool,
    /// The severity of the detection.
    pub severity: Severity,
}

impl Default for PrivilegedSelfAssignmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_privileged: true,
            severity: Severity::High,
        }
    }
}

/// Finds an application or a service principal that gives itself a privileged role or
/// permission.
///
/// The detector examines `role.assign` and `app.permission_grant` events that did not fail.
/// An event gives a detection when the actor is a service principal or an application, the
/// target is the actor, and the event has `privileged: true`. The technique is `T1098.003`.
///
/// The detector keeps no state.
pub struct PrivilegedSelfAssignment {
    config: PrivilegedSelfAssignmentConfig,
}

impl PrivilegedSelfAssignment {
    /// Makes the detector.
    #[must_use]
    pub fn new(config: PrivilegedSelfAssignmentConfig) -> Self {
        Self { config }
    }

    /// Examines one event. Returns a detection if the event is a privileged
    /// self-assignment.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        let is_assignment =
            event.action == action::ROLE_ASSIGN || event.action == action::APP_PERMISSION_GRANT;
        let is_workload = matches!(
            event.actor.kind,
            EntityKind::ServicePrincipal | EntityKind::Application
        );
        if !self.config.enabled
            || !is_assignment
            || !is_workload
            || event.outcome == Outcome::Failure
        {
            return None;
        }
        let target = event.target.as_ref()?;
        if target.id != event.actor.id {
            return None;
        }
        let privileged = event.attribute_bool(attr::PRIVILEGED) == Some(true);
        if self.config.require_privileged && !privileged {
            return None;
        }

        let role = event
            .attribute_str(attr::ROLE_NAME)
            .or_else(|| event.attribute_str(attr::ROLE_ID));
        let granted = match role {
            Some(role) => format!("the role or permission {role:?}"),
            None => "a role or permission".to_owned(),
        };
        let mut attributes = vec![
            ("action", json!(event.action)),
            ("privileged", json!(privileged)),
        ];
        for key in [attr::ROLE_ID, attr::ROLE_NAME] {
            if let Some(value) = event.attribute_str(key) {
                attributes.push((key, json!(value)));
            }
        }
        Some(
            Finding {
                rule_id: PRIVILEGED_SELF_ASSIGNMENT_RULE_ID,
                title: "Workload identity gave itself a privileged role",
                description: format!(
                    "The workload identity {} gave {granted} to itself.",
                    event.actor.id
                ),
                severity: self.config.severity,
                verdict: Verdict::Malicious,
                attack: vec![technique_in("privilege-escalation", "T1098.003")],
                time: event.time,
                event_ids: vec![event.id],
                entities: event_entities(event),
                attributes,
            }
            .into_detection(event),
        )
    }
}

#[async_trait]
impl Detector for PrivilegedSelfAssignment {
    fn id(&self) -> &str {
        PRIVILEGED_SELF_ASSIGNMENT_RULE_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        Ok(self.evaluate(event).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::AttackTechnique;
    use aegis_contracts::common::EntityRef;
    use aegis_contracts::event::EventClass;

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    /// A service principal assigns the Global Administrator role to itself.
    fn self_assignment() -> Event {
        event(
            1,
            at(0),
            EventClass::UserAccessManagement,
            action::ROLE_ASSIGN,
            actor(
                EntityKind::ServicePrincipal,
                "sp-sync-helper",
                "203.0.113.51",
            ),
        )
        .with_target(EntityRef::new(
            EntityKind::ServicePrincipal,
            "sp-sync-helper",
        ))
        .with_attribute(attr::ROLE_ID, "62e90394")
        .with_attribute(attr::ROLE_NAME, "Global Administrator")
        .with_attribute(attr::PRIVILEGED, true)
    }

    fn detect(event: &Event) -> Option<Detection> {
        PrivilegedSelfAssignment::new(PrivilegedSelfAssignmentConfig::default()).evaluate(event)
    }

    #[test]
    fn a_service_principal_that_gives_itself_a_privileged_role_is_detected() {
        let event = self_assignment();
        let found = detect(&event).unwrap();
        assert_eq!(found.rule_id, PRIVILEGED_SELF_ASSIGNMENT_RULE_ID);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "privilege-escalation",
                "T1098.003",
                "Additional Cloud Roles"
            )]
        );
        assert_eq!(found.time, event.time);
        assert_eq!(found.event_ids, [event.id]);
        assert_eq!(found.tenant.as_deref(), Some(TENANT));
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
            ]
        );
        assert_eq!(
            found.description,
            "The workload identity sp-sync-helper gave the role or permission \"Global Administrator\" to itself."
        );
        assert_eq!(found.attributes["role_name"], json!("Global Administrator"));
        assert_eq!(found.attributes["role_id"], json!("62e90394"));
        assert_eq!(found.attributes["action"], json!("role.assign"));
    }

    #[test]
    fn an_application_that_grants_itself_a_privileged_permission_is_detected() {
        let mut event = self_assignment();
        event.action = action::APP_PERMISSION_GRANT.to_owned();
        event.actor.kind = EntityKind::Application;
        event.attributes.remove(attr::ROLE_NAME);
        event.attributes.remove(attr::ROLE_ID);
        let found = detect(&event).unwrap();
        assert_eq!(found.attributes["action"], json!("app.permission_grant"));
        assert_eq!(
            found.description,
            "The workload identity sp-sync-helper gave a role or permission to itself."
        );
    }

    #[test]
    fn an_assignment_to_a_different_principal_is_not_detected() {
        let mut event = self_assignment();
        event.target = Some(EntityRef::new(EntityKind::ServicePrincipal, "sp-other"));
        assert_eq!(detect(&event), None);
        event.target = None;
        assert_eq!(detect(&event), None);
    }

    #[test]
    fn a_user_that_assigns_a_role_to_itself_is_not_detected() {
        let mut event = self_assignment();
        event.actor.kind = EntityKind::User;
        assert_eq!(detect(&event), None);
    }

    #[test]
    fn a_role_that_is_not_privileged_is_not_detected() {
        let mut event = self_assignment();
        event
            .attributes
            .insert(attr::PRIVILEGED.to_owned(), json!(false));
        assert_eq!(detect(&event), None);
        event.attributes.remove(attr::PRIVILEGED);
        assert_eq!(detect(&event), None);
        event
            .attributes
            .insert(attr::PRIVILEGED.to_owned(), json!("true"));
        assert_eq!(detect(&event), None);
    }

    #[test]
    fn other_actions_and_failed_assignments_are_not_detected() {
        let mut other_action = self_assignment();
        other_action.action = action::ROLE_REMOVE.to_owned();
        assert_eq!(detect(&other_action), None);

        let mut failed = self_assignment();
        failed.outcome = Outcome::Failure;
        assert_eq!(detect(&failed), None);

        let mut unknown = self_assignment();
        unknown.outcome = Outcome::Unknown;
        assert!(detect(&unknown).is_some());
    }

    #[test]
    fn the_settings_change_the_severity_and_the_privileged_test() {
        let detector = PrivilegedSelfAssignment::new(PrivilegedSelfAssignmentConfig {
            require_privileged: false,
            severity: Severity::Critical,
            ..PrivilegedSelfAssignmentConfig::default()
        });
        let mut event = self_assignment();
        event.attributes.remove(attr::PRIVILEGED);
        let found = detector.evaluate(&event).unwrap();
        assert_eq!(found.severity, Severity::Critical);
        assert_eq!(found.attributes["privileged"], json!(false));

        let stopped = PrivilegedSelfAssignment::new(PrivilegedSelfAssignmentConfig {
            enabled: false,
            ..PrivilegedSelfAssignmentConfig::default()
        });
        assert_eq!(stopped.evaluate(&self_assignment()), None);
    }

    #[tokio::test]
    async fn the_detector_contract_returns_the_detection() {
        let detector = PrivilegedSelfAssignment::new(PrivilegedSelfAssignmentConfig::default());
        assert_eq!(detector.id(), "aegis.velocity.privileged_self_assignment");
        assert_eq!(detector.tier(), DetectionTier::Deterministic);
        assert_eq!(detector.inspect(&self_assignment()).await.unwrap().len(), 1);
        let mut user = self_assignment();
        user.actor.kind = EntityKind::User;
        assert_eq!(detector.inspect(&user).await.unwrap(), []);
    }
}
