//! The detector for a credential change immediately after a grant.

use std::sync::Mutex;

use aegis_contracts::common::{EntityRef, EventId, Severity};
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Finding, Tracked, at_least, seconds, tenant_key};
use crate::attack::technique_in;
use crate::common::{event_app_id, event_entities, lock, push_entity};
use crate::error::DetectError;

/// The rule identifier of a credential-after-grant detection.
pub const CREDENTIAL_AFTER_GRANT_RULE_ID: &str = "aegis.velocity.credential_after_grant";

/// The settings of [`CredentialAfterGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialAfterGrantConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// The largest time in seconds between the grant and the new credential.
    pub window_seconds: u64,
    /// The largest number of applications for which the detector keeps state.
    pub max_tracked_applications: usize,
}

impl Default for CredentialAfterGrantConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 120,
            max_tracked_applications: 50_000,
        }
    }
}

/// The data that the detector keeps of one event.
#[derive(Clone)]
struct Seen {
    time: DateTime<Utc>,
    event_id: EventId,
    action: String,
    entities: Vec<EntityRef>,
}

impl Seen {
    fn of(event: &Event) -> Self {
        Self {
            time: event.time,
            event_id: event.id,
            action: event.action.clone(),
            entities: event_entities(event),
        }
    }
}

#[derive(Default)]
struct ApplicationState {
    /// The newest grant for the application.
    grant: Option<Seen>,
    /// The newest new credential that no detection used. A grant can arrive after it.
    credential: Option<Seen>,
}

/// Finds a new credential on an application immediately after a grant for the application.
///
/// The detector examines events that did not fail. It keeps the newest
/// `oauth.consent_grant` or `app.permission_grant` for each `app_id`. An
/// `app.credential_add` for the same `app_id` gives a detection when it follows the grant
/// by at most `window_seconds`. The technique is `T1098.001`.
///
/// The two events can arrive in the reverse order. The detector compares their event times.
pub struct CredentialAfterGrant {
    config: CredentialAfterGrantConfig,
    window: TimeDelta,
    state: Mutex<Tracked<(u64, String), ApplicationState>>,
}

impl CredentialAfterGrant {
    /// Makes the detector.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the window or `max_tracked_applications` is zero.
    pub fn new(config: CredentialAfterGrantConfig) -> std::result::Result<Self, DetectError> {
        let prefix = "credential_after_grant";
        at_least(
            &format!("{prefix}.window_seconds"),
            usize::try_from(config.window_seconds).unwrap_or(usize::MAX),
            1,
        )?;
        at_least(
            &format!("{prefix}.max_tracked_applications"),
            config.max_tracked_applications,
            1,
        )?;
        Ok(Self {
            window: seconds(&format!("{prefix}.window_seconds"), config.window_seconds)?,
            state: Mutex::new(Tracked::new(config.max_tracked_applications)),
            config,
        })
    }

    fn follows(&self, grant: &Seen, credential: &Seen) -> bool {
        let gap = credential.time - grant.time;
        gap >= TimeDelta::zero() && gap <= self.window
    }

    /// Examines one event. Returns a detection if the event completes the pattern.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        let is_grant = event.action == action::OAUTH_CONSENT_GRANT
            || event.action == action::APP_PERMISSION_GRANT;
        let is_credential = event.action == action::APP_CREDENTIAL_ADD;
        if !self.config.enabled || !(is_grant || is_credential) || event.outcome == Outcome::Failure
        {
            return None;
        }
        let app_id = event_app_id(event)?;
        let seen = Seen::of(event);

        let mut tracked = lock(&self.state);
        let state = tracked.upsert(
            (tenant_key(event), app_id.to_owned()),
            event.time,
            ApplicationState::default,
        );
        let (grant, credential) = if is_grant {
            if state
                .grant
                .as_ref()
                .is_none_or(|known| known.time <= seen.time)
            {
                state.grant = Some(seen.clone());
            }
            let credential = state
                .credential
                .take_if(|credential| self.follows(&seen, credential))?;
            (seen, credential)
        } else {
            match state
                .grant
                .clone()
                .filter(|grant| self.follows(grant, &seen))
            {
                Some(grant) => (grant, seen),
                None => {
                    state.credential = Some(seen);
                    return None;
                }
            }
        };
        drop(tracked);

        let gap = (credential.time - grant.time).num_milliseconds();
        let mut entities = grant.entities;
        for entity in credential.entities {
            push_entity(&mut entities, entity);
        }
        let mut attributes = vec![
            ("app_id", json!(app_id)),
            ("grant_action", json!(grant.action)),
            ("milliseconds_after_grant", json!(gap)),
            ("window_seconds", json!(self.config.window_seconds)),
        ];
        if let Some(credential_type) = event
            .attribute_str(attr::CREDENTIAL_TYPE)
            .filter(|_| is_credential)
        {
            attributes.push((attr::CREDENTIAL_TYPE, json!(credential_type)));
        }
        // A response action needs the identifier of the credential to remove it.
        if let Some(credential_id) = event
            .attribute_str(attr::CREDENTIAL_ID)
            .filter(|_| is_credential)
        {
            attributes.push((attr::CREDENTIAL_ID, json!(credential_id)));
        }
        Some(
            Finding {
                rule_id: CREDENTIAL_AFTER_GRANT_RULE_ID,
                title: "New application credential immediately after a grant",
                description: format!(
                    "The application {app_id} got a new credential {gap} milliseconds after a \
                     grant ({}).",
                    grant.action
                ),
                severity: Severity::High,
                verdict: Verdict::Malicious,
                attack: vec![technique_in("persistence", "T1098.001")],
                time: credential.time,
                event_ids: vec![grant.event_id, credential.event_id],
                entities,
                attributes,
            }
            .into_detection(event),
        )
    }
}

#[async_trait]
impl Detector for CredentialAfterGrant {
    fn id(&self) -> &str {
        CREDENTIAL_AFTER_GRANT_RULE_ID
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
    use aegis_contracts::common::EntityKind;
    use aegis_contracts::event::EventClass;

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    const APP: &str = "app-sync-helper";

    fn detector() -> CredentialAfterGrant {
        CredentialAfterGrant::new(CredentialAfterGrantConfig {
            window_seconds: 30,
            ..CredentialAfterGrantConfig::default()
        })
        .unwrap()
    }

    fn grant(sequence: u32, milliseconds: i64, app: &str) -> Event {
        event(
            sequence,
            at(milliseconds),
            EventClass::UserAccessManagement,
            action::OAUTH_CONSENT_GRANT,
            actor(EntityKind::User, "user-dana", "203.0.113.50"),
        )
        .with_target(EntityRef::new(EntityKind::Application, app))
        .with_attribute(attr::APP_ID, app)
    }

    fn credential(sequence: u32, milliseconds: i64, app: &str) -> Event {
        event(
            sequence,
            at(milliseconds),
            EventClass::AccountChange,
            action::APP_CREDENTIAL_ADD,
            actor(EntityKind::User, "user-dana", "203.0.113.50"),
        )
        .with_target(EntityRef::new(
            EntityKind::ServicePrincipal,
            "sp-sync-helper",
        ))
        .with_attribute(attr::APP_ID, app)
        .with_attribute(attr::CREDENTIAL_TYPE, "password")
    }

    #[test]
    fn a_credential_three_seconds_after_a_grant_is_detected() {
        let detector = detector();
        let first = grant(1, 0, APP);
        let second = credential(2, 3_000, APP);
        assert_eq!(detector.evaluate(&first), None);
        let found = detector.evaluate(&second).unwrap();
        assert_eq!(found.rule_id, CREDENTIAL_AFTER_GRANT_RULE_ID);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "persistence",
                "T1098.001",
                "Additional Cloud Credentials"
            )]
        );
        assert_eq!(found.time, second.time);
        assert_eq!(found.event_ids, [first.id, second.id]);
        assert_eq!(found.tenant.as_deref(), Some(TENANT));
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::User, "user-dana"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
                EntityRef::new(EntityKind::Application, APP),
                EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper"),
            ]
        );
        assert_eq!(found.attributes["app_id"], json!(APP));
        assert_eq!(found.attributes["milliseconds_after_grant"], json!(3_000));
        assert_eq!(
            found.attributes["grant_action"],
            json!("oauth.consent_grant")
        );
        assert_eq!(found.attributes["credential_type"], json!("password"));
        assert_eq!(
            found.description,
            "The application app-sync-helper got a new credential 3000 milliseconds after a grant (oauth.consent_grant)."
        );
    }

    #[test]
    fn an_application_permission_grant_also_starts_the_window() {
        let detector = detector();
        let mut first = grant(1, 0, APP);
        first.action = action::APP_PERMISSION_GRANT.to_owned();
        assert_eq!(detector.evaluate(&first), None);
        let found = detector.evaluate(&credential(2, 1_000, APP)).unwrap();
        assert_eq!(
            found.attributes["grant_action"],
            json!("app.permission_grant")
        );
    }

    #[test]
    fn the_window_includes_its_end_and_excludes_later_credentials() {
        let detector = detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        assert!(detector.evaluate(&credential(2, 30_000, APP)).is_some());
        assert_eq!(detector.evaluate(&credential(3, 30_001, APP)), None);
    }

    #[test]
    fn a_credential_with_no_grant_or_for_a_different_application_is_not_detected() {
        let detector = detector();
        assert_eq!(detector.evaluate(&credential(1, 0, APP)), None);
        assert_eq!(detector.evaluate(&grant(2, 1_000, "app-other")), None);
        assert_eq!(detector.evaluate(&credential(3, 2_000, APP)), None);
    }

    #[test]
    fn a_credential_before_the_grant_is_not_detected() {
        let detector = detector();
        assert_eq!(detector.evaluate(&credential(1, 0, APP)), None);
        assert_eq!(detector.evaluate(&grant(2, 5_000, APP)), None);
    }

    #[test]
    fn the_detection_keeps_the_identifier_of_the_new_credential() {
        let detector = detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        let event = credential(2, 3_000, APP).with_attribute(attr::CREDENTIAL_ID, "credential-1");
        let found = detector.evaluate(&event).unwrap();
        assert_eq!(found.attributes["credential_id"], json!("credential-1"));

        // An event with no identifier gives a detection with no identifier.
        let detector = self::detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        let found = detector.evaluate(&credential(2, 3_000, APP)).unwrap();
        assert_eq!(found.attributes.get("credential_id"), None);
    }

    #[test]
    fn events_in_the_reverse_arrival_order_are_detected_one_time() {
        let detector = detector();
        let late_credential = credential(2, 3_000, APP);
        let early_grant = grant(1, 0, APP);
        assert_eq!(detector.evaluate(&late_credential), None);
        let found = detector.evaluate(&early_grant).unwrap();
        assert_eq!(found.event_ids, [early_grant.id, late_credential.id]);
        assert_eq!(found.time, late_credential.time);
        assert_eq!(found.attributes.get("credential_type"), None);
        // A second copy of the grant finds no credential that is not used.
        assert_eq!(detector.evaluate(&grant(3, 0, APP)), None);
    }

    #[test]
    fn each_credential_in_the_window_gives_a_detection() {
        let detector = detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        let first = detector.evaluate(&credential(2, 1_000, APP)).unwrap();
        let second = detector.evaluate(&credential(3, 2_000, APP)).unwrap();
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn the_newest_grant_is_the_start_of_the_window() {
        let detector = detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        assert_eq!(detector.evaluate(&grant(2, 40_000, APP)), None);
        let found = detector.evaluate(&credential(3, 45_000, APP)).unwrap();
        assert_eq!(found.attributes["milliseconds_after_grant"], json!(5_000));
        // An older grant that arrives late does not replace the newer grant.
        assert_eq!(detector.evaluate(&grant(4, 10_000, APP)), None);
        let found = detector.evaluate(&credential(5, 50_000, APP)).unwrap();
        assert_eq!(found.attributes["milliseconds_after_grant"], json!(10_000));
    }

    #[test]
    fn failed_events_and_events_with_no_application_are_ignored() {
        let detector = detector();
        let mut failed_grant = grant(1, 0, APP);
        failed_grant.outcome = Outcome::Failure;
        assert_eq!(detector.evaluate(&failed_grant), None);
        assert_eq!(detector.evaluate(&credential(2, 1_000, APP)), None);

        let detector = self::detector();
        assert_eq!(detector.evaluate(&grant(3, 0, APP)), None);
        let mut failed_credential = credential(4, 1_000, APP);
        failed_credential.outcome = Outcome::Failure;
        assert_eq!(detector.evaluate(&failed_credential), None);
        let mut no_application = credential(5, 2_000, APP);
        no_application.attributes.remove(attr::APP_ID);
        assert_eq!(detector.evaluate(&no_application), None);
    }

    #[test]
    fn the_application_of_a_grant_can_be_its_target() {
        let detector = detector();
        let mut first = grant(1, 0, APP);
        first.attributes.remove(attr::APP_ID);
        assert_eq!(detector.evaluate(&first), None);
        assert!(detector.evaluate(&credential(2, 1_000, APP)).is_some());
    }

    #[test]
    fn each_tenant_has_its_own_state() {
        let detector = detector();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        let mut other_tenant = credential(2, 1_000, APP);
        other_tenant.source.tenant = Some("tenant-2".to_owned());
        assert_eq!(detector.evaluate(&other_tenant), None);
    }

    #[test]
    fn the_state_is_limited() {
        let detector = CredentialAfterGrant::new(CredentialAfterGrantConfig {
            max_tracked_applications: 4,
            ..CredentialAfterGrantConfig::default()
        })
        .unwrap();
        for index in 0..100_u32 {
            let app = format!("app-{index}");
            assert_eq!(
                detector.evaluate(&grant(index, i64::from(index), &app)),
                None
            );
        }
        assert!(lock(&detector.state).len() <= 4);
        // The grant for the first application is no longer in the state.
        assert_eq!(detector.evaluate(&credential(200, 200, "app-0")), None);
        // The newest grant is.
        assert!(detector.evaluate(&credential(201, 201, "app-99")).is_some());
    }

    #[test]
    fn a_detector_that_is_not_enabled_gives_no_detection() {
        let detector = CredentialAfterGrant::new(CredentialAfterGrantConfig {
            enabled: false,
            ..CredentialAfterGrantConfig::default()
        })
        .unwrap();
        assert_eq!(detector.evaluate(&grant(1, 0, APP)), None);
        assert_eq!(detector.evaluate(&credential(2, 1_000, APP)), None);
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        let error = CredentialAfterGrant::new(CredentialAfterGrantConfig {
            window_seconds: 0,
            ..CredentialAfterGrantConfig::default()
        })
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "detector configuration: credential_after_grant.window_seconds must be 1 or more, but it is 0"
        );
        let error = CredentialAfterGrant::new(CredentialAfterGrantConfig {
            max_tracked_applications: 0,
            ..CredentialAfterGrantConfig::default()
        })
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("max_tracked_applications must be 1 or more")
        );
    }

    #[tokio::test]
    async fn the_detector_contract_returns_the_detection() {
        let detector = detector();
        assert_eq!(detector.id(), "aegis.velocity.credential_after_grant");
        assert_eq!(detector.tier(), DetectionTier::Deterministic);
        assert_eq!(detector.inspect(&grant(1, 0, APP)).await.unwrap(), []);
        assert_eq!(
            detector
                .inspect(&credential(2, 1_000, APP))
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
