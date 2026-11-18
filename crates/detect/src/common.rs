//! Helpers that all detectors share: names, entities, and stable identifiers.

use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, EventId, IncidentId, Severity};
use aegis_contracts::event::{Event, EventClass, Outcome, attr};
use aegis_contracts::{DetectionTier, Verdict};
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Locks a mutex. A panic in a different thread does not make the state unavailable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Returns `time + delta`. A sum that is out of range gives the largest time.
///
/// The `+` operator of the time type panics when the sum is out of range. An event can
/// carry any time, so the detectors must not use the operator.
pub(crate) fn time_after(time: DateTime<Utc>, delta: TimeDelta) -> DateTime<Utc> {
    time.checked_add_signed(delta)
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Returns `time - delta`. A difference that is out of range gives the smallest time.
pub(crate) fn time_before(time: DateTime<Utc>, delta: TimeDelta) -> DateTime<Utc> {
    time.checked_sub_signed(delta)
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// Returns the name of a severity, as the contracts encode it.
#[must_use]
pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Returns the severity for a name, or `None` for a name that the contracts do not have.
#[must_use]
pub fn severity_from_name(name: &str) -> Option<Severity> {
    [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .find(|severity| severity_name(*severity).eq_ignore_ascii_case(name))
}

/// Returns the name of an outcome, as the contracts encode it.
#[must_use]
pub fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Unknown => "unknown",
    }
}

/// The event classes, each with the name that the contracts encode.
pub(crate) const EVENT_CLASSES: &[(EventClass, &str)] = &[
    (EventClass::Authentication, "authentication"),
    (EventClass::AccountChange, "account_change"),
    (EventClass::UserAccessManagement, "user_access_management"),
    (EventClass::EntityManagement, "entity_management"),
    (EventClass::ApiActivity, "api_activity"),
    (EventClass::NetworkActivity, "network_activity"),
    (EventClass::ProcessActivity, "process_activity"),
    (EventClass::FileActivity, "file_activity"),
    (EventClass::DetectionFinding, "detection_finding"),
    (EventClass::Other, "other"),
];

/// Returns the name of an event class, as the contracts encode it.
#[must_use]
pub fn class_name(class: EventClass) -> &'static str {
    match class {
        EventClass::Authentication => "authentication",
        EventClass::AccountChange => "account_change",
        EventClass::UserAccessManagement => "user_access_management",
        EventClass::EntityManagement => "entity_management",
        EventClass::ApiActivity => "api_activity",
        EventClass::NetworkActivity => "network_activity",
        EventClass::ProcessActivity => "process_activity",
        EventClass::FileActivity => "file_activity",
        EventClass::DetectionFinding => "detection_finding",
        EventClass::Other => "other",
    }
}

/// Returns the name of an entity kind, as the contracts encode it.
#[must_use]
pub fn kind_name(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::User => "user",
        EntityKind::ServicePrincipal => "service_principal",
        EntityKind::Application => "application",
        EntityKind::Device => "device",
        EntityKind::Host => "host",
        EntityKind::IpAddress => "ip_address",
        EntityKind::Domain => "domain",
        EntityKind::Tenant => "tenant",
        EntityKind::Session => "session",
        EntityKind::Secret => "secret",
        EntityKind::Role => "role",
        EntityKind::Resource => "resource",
        EntityKind::Other => "other",
    }
}

/// Returns the name of a verdict, as the contracts encode it.
#[must_use]
pub fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Malicious => "malicious",
        Verdict::Suspicious => "suspicious",
        Verdict::Benign => "benign",
    }
}

/// Returns the token of a tier for the bus subject `aegis.detections.{tier}`.
#[must_use]
pub fn tier_token(tier: DetectionTier) -> &'static str {
    match tier {
        DetectionTier::Deterministic => "deterministic",
        DetectionTier::Llm => "llm",
    }
}

/// Returns the default verdict for a severity.
///
/// A rule or an indicator with a `high` or `critical` severity is `malicious`. All others
/// are `suspicious`, so that tier 2 examines them.
#[must_use]
pub fn default_verdict(severity: Severity) -> Verdict {
    if severity >= Severity::High {
        Verdict::Malicious
    } else {
        Verdict::Suspicious
    }
}

/// Returns the canonical form of an address.
///
/// An IPv4 address in the IPv6-mapped form becomes an IPv4 address, so that the two forms
/// of one address are equal.
#[must_use]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Returns the entity for an IP address.
#[must_use]
pub fn ip_entity(ip: IpAddr) -> EntityRef {
    EntityRef::new(EntityKind::IpAddress, canonical_ip(ip).to_string())
}

/// Returns the tenant in which the activity of an event occurred.
///
/// This is the tenant that the connector reads. If the source has none, it is the home
/// tenant of the actor.
#[must_use]
pub fn event_tenant(event: &Event) -> Option<&str> {
    event
        .source
        .tenant
        .as_deref()
        .or(event.actor.tenant.as_deref())
}

/// Returns the application identifier that an event refers to.
///
/// This is the `app_id` attribute. If the event has none, it is the target, when the
/// target is an application.
#[must_use]
pub fn event_app_id(event: &Event) -> Option<&str> {
    event.attribute_str(attr::APP_ID).or_else(|| {
        event
            .target
            .as_ref()
            .filter(|target| target.kind == EntityKind::Application)
            .map(|target| target.id.as_str())
    })
}

/// Adds `entity` to `entities` if no entity with the same kind and identifier is there.
pub(crate) fn push_entity(entities: &mut Vec<EntityRef>, entity: EntityRef) {
    let known = entities
        .iter()
        .any(|found| found.kind == entity.kind && found.id == entity.id);
    if !known {
        entities.push(entity);
    }
}

/// Returns the entities that an event involves, with no duplicates.
///
/// The list has the actor, the address of the actor, the target, and the application of the
/// `app_id` attribute.
///
/// For an authentication event, the list has only the actor and the address. The target of
/// a sign-in is a resource that many principals share. It would link incidents that are not
/// related.
#[must_use]
pub fn event_entities(event: &Event) -> Vec<EntityRef> {
    let mut entities = Vec::with_capacity(4);
    entities.push(event.actor.entity());
    if let Some(ip) = event.actor.ip {
        push_entity(&mut entities, ip_entity(ip));
    }
    if event.class != EventClass::Authentication {
        if let Some(target) = &event.target {
            push_entity(&mut entities, target.clone());
        }
        if let Some(app_id) = event.attribute_str(attr::APP_ID) {
            let mut application = EntityRef::new(EntityKind::Application, app_id);
            application.name = event.attribute_str(attr::APP_NAME).map(str::to_owned);
            push_entity(&mut entities, application);
        }
    }
    entities
}

fn stable_uuid(parts: &[&[u8]]) -> Uuid {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    for (target, source) in bytes.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    // Mark the value as a version 8 (custom) UUID of the RFC 9562 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Makes the identifier of a detection from the rule and the events that caused it.
///
/// The same rule and the same events always give the same identifier. A replay of one
/// event log thus gives the same detections, and a consumer can drop a repeated detection.
#[must_use]
pub fn detection_id(rule_id: &str, event_ids: &[EventId]) -> DetectionId {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(event_ids.len() + 2);
    parts.push(b"aegis-detect/detection");
    parts.push(rule_id.as_bytes());
    for id in event_ids {
        parts.push(id.0.as_bytes());
    }
    DetectionId(stable_uuid(&parts))
}

/// Makes the identifier of a detection that a later stage derives from `source`.
pub(crate) fn derived_detection_id(source: DetectionId, stage: &str) -> DetectionId {
    DetectionId(stable_uuid(&[
        b"aegis-detect/derived",
        stage.as_bytes(),
        source.0.as_bytes(),
    ]))
}

/// Makes the identifier of the incident that starts with the detection `first`.
pub(crate) fn incident_id(first: DetectionId) -> IncidentId {
    IncidentId(stable_uuid(&[b"aegis-detect/incident", first.0.as_bytes()]))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use aegis_contracts::event::{Actor, EventSource, action};
    use serde::Serialize;

    use super::*;

    fn encoded<T: Serialize>(value: T) -> String {
        serde_json::to_value(value)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn the_names_are_the_names_that_the_contracts_encode() {
        for severity in [
            Severity::Informational,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(severity_name(severity), encoded(severity));
            assert_eq!(severity_from_name(&encoded(severity)), Some(severity));
        }
        for outcome in [Outcome::Success, Outcome::Failure, Outcome::Unknown] {
            assert_eq!(outcome_name(outcome), encoded(outcome));
        }
        assert_eq!(EVENT_CLASSES.len(), 10);
        for (class, name) in EVENT_CLASSES {
            assert_eq!(class_name(*class), encoded(class));
            assert_eq!(*name, encoded(class));
        }
        for kind in [
            EntityKind::User,
            EntityKind::ServicePrincipal,
            EntityKind::Application,
            EntityKind::Device,
            EntityKind::Host,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Tenant,
            EntityKind::Session,
            EntityKind::Secret,
            EntityKind::Role,
            EntityKind::Resource,
            EntityKind::Other,
        ] {
            assert_eq!(kind_name(kind), encoded(kind));
        }
        for verdict in [Verdict::Malicious, Verdict::Suspicious, Verdict::Benign] {
            assert_eq!(verdict_name(verdict), encoded(verdict));
        }
        for tier in [DetectionTier::Deterministic, DetectionTier::Llm] {
            assert_eq!(tier_token(tier), encoded(tier));
        }
    }

    #[test]
    fn time_arithmetic_stops_at_the_ends_of_the_range_and_does_not_panic() {
        let time = DateTime::from_timestamp(1_793_696_400, 0).unwrap();
        let minute = TimeDelta::seconds(60);
        assert_eq!(time_after(time, minute), time + minute);
        assert_eq!(time_before(time, minute), time - minute);
        assert_eq!(
            time_after(DateTime::<Utc>::MAX_UTC, minute),
            DateTime::<Utc>::MAX_UTC
        );
        assert_eq!(
            time_before(DateTime::<Utc>::MIN_UTC, minute),
            DateTime::<Utc>::MIN_UTC
        );
        assert_eq!(time_after(time, TimeDelta::MAX), DateTime::<Utc>::MAX_UTC);
        assert_eq!(time_before(time, TimeDelta::MAX), DateTime::<Utc>::MIN_UTC);
    }

    #[test]
    fn lock_gives_the_state_after_a_panic_in_a_different_thread() {
        let state = std::sync::Arc::new(Mutex::new(7));
        let other = state.clone();
        let result = std::thread::spawn(move || {
            let _guard = other.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        assert!(result.is_err());
        assert!(state.is_poisoned());
        assert_eq!(*lock(&state), 7);
    }

    #[test]
    fn severity_from_name_ignores_case_and_rejects_other_names() {
        assert_eq!(severity_from_name("HIGH"), Some(Severity::High));
        assert_eq!(severity_from_name("severe"), None);
        assert_eq!(severity_from_name(""), None);
    }

    #[test]
    fn the_default_verdict_is_malicious_only_for_high_and_critical() {
        assert_eq!(default_verdict(Severity::Critical), Verdict::Malicious);
        assert_eq!(default_verdict(Severity::High), Verdict::Malicious);
        assert_eq!(default_verdict(Severity::Medium), Verdict::Suspicious);
        assert_eq!(
            default_verdict(Severity::Informational),
            Verdict::Suspicious
        );
    }

    #[test]
    fn a_mapped_address_and_its_ipv4_form_give_one_entity() {
        let plain = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 50).to_ipv6_mapped());
        assert_eq!(ip_entity(mapped), ip_entity(plain));
        assert_eq!(ip_entity(plain).id, "203.0.113.50");
        assert_eq!(ip_entity(plain).kind, EntityKind::IpAddress);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ip_entity(v6).id, "2001:db8::1");
    }

    fn event(class: EventClass, action: &str) -> Event {
        let actor = Actor::new(EntityKind::User, "user-1")
            .with_tenant("home")
            .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        Event::new(
            DateTime::UNIX_EPOCH,
            EventSource::new("c", "v", "p"),
            class,
            action,
            actor,
        )
        .with_target(EntityRef::new(EntityKind::Application, "app-1"))
        .with_attribute(attr::APP_ID, "app-1")
        .with_attribute(attr::APP_NAME, "App One")
    }

    #[test]
    fn event_entities_has_the_actor_the_address_and_the_target_with_no_duplicates() {
        let entities = event_entities(&event(
            EventClass::UserAccessManagement,
            action::OAUTH_CONSENT_GRANT,
        ));
        let keys: Vec<(EntityKind, &str)> = entities
            .iter()
            .map(|entity| (entity.kind, entity.id.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                (EntityKind::User, "user-1"),
                (EntityKind::IpAddress, "203.0.113.9"),
                (EntityKind::Application, "app-1"),
            ]
        );
    }

    #[test]
    fn event_entities_adds_the_application_of_the_app_id_attribute() {
        let mut event = event(EventClass::AccountChange, action::APP_CREDENTIAL_ADD);
        event.target = Some(EntityRef::new(EntityKind::ServicePrincipal, "sp-1"));
        let entities = event_entities(&event);
        assert_eq!(entities.len(), 4);
        assert_eq!(
            entities[2],
            EntityRef::new(EntityKind::ServicePrincipal, "sp-1")
        );
        assert_eq!(
            entities[3],
            EntityRef::new(EntityKind::Application, "app-1").with_name("App One")
        );
    }

    #[test]
    fn event_entities_leaves_out_the_resource_of_a_sign_in() {
        let entities = event_entities(&event(EventClass::Authentication, action::SIGN_IN));
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].kind, EntityKind::User);
        assert_eq!(entities[1].kind, EntityKind::IpAddress);
    }

    #[test]
    fn the_tenant_is_the_source_tenant_and_then_the_actor_tenant() {
        let mut event = event(EventClass::Authentication, action::SIGN_IN);
        assert_eq!(event_tenant(&event), Some("home"));
        event.source.tenant = Some("resource".to_owned());
        assert_eq!(event_tenant(&event), Some("resource"));
        event.source.tenant = None;
        event.actor.tenant = None;
        assert_eq!(event_tenant(&event), None);
    }

    #[test]
    fn the_app_id_is_the_attribute_and_then_an_application_target() {
        let mut event = event(EventClass::AccountChange, action::APP_CREDENTIAL_ADD);
        event.target = Some(EntityRef::new(EntityKind::Application, "app-target"));
        assert_eq!(event_app_id(&event), Some("app-1"));
        event.attributes.remove(attr::APP_ID);
        assert_eq!(event_app_id(&event), Some("app-target"));
        event.target = Some(EntityRef::new(EntityKind::ServicePrincipal, "sp-1"));
        assert_eq!(event_app_id(&event), None);
    }

    #[test]
    fn detection_identifiers_are_stable_and_depend_on_the_rule_and_the_events() {
        let first = EventId(Uuid::from_u128(1));
        let second = EventId(Uuid::from_u128(2));
        let id = detection_id("rule-a", &[first, second]);
        assert_eq!(id, detection_id("rule-a", &[first, second]));
        assert_ne!(id, detection_id("rule-b", &[first, second]));
        assert_ne!(id, detection_id("rule-a", &[second, first]));
        assert_ne!(id, detection_id("rule-a", &[first]));
        assert_eq!(id.0.get_version_num(), 8);
        assert_eq!(id.0.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn derived_and_incident_identifiers_differ_from_their_source() {
        let source = detection_id("rule-a", &[EventId(Uuid::from_u128(1))]);
        let derived = derived_detection_id(source, "llm");
        assert_ne!(derived, source);
        assert_eq!(derived, derived_detection_id(source, "llm"));
        assert_ne!(derived, derived_detection_id(source, "other"));
        let incident = incident_id(source);
        assert_ne!(incident.0, source.0);
        assert_eq!(incident, incident_id(source));
    }
}
