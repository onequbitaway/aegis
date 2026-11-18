//! Tests of the rule pack that the project ships: `detections/aegis-identity`.
//!
//! Each rule gets events that it must match and events that it must not match.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::path::PathBuf;

use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, Verdict};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::ioc::IndicatorKind;
use aegis_detect::pack::RulePack;
use aegis_detect::sigma::SigmaRule;
use aegis_testkit::fixtures;
use ipnet::IpNet;
use serde_json::json;

const CONSENT: &str = "5b0f3c2e-8a41-4d6f-9c57-2e1a7b90d314";
const HONEYTOKEN: &str = "0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940";
const WORKLOAD_ROLE: &str = "a4d7e1b9-6c35-4f02-8e7a-1b9c0d5f2a63";
const PERMISSION_GRANT: &str = "e2f8a6c1-9d47-4b53-b0e6-3a5c8d7f1b02";
const USER_CREATED: &str = "3f6b9d2c-7e10-4a85-9b4c-5d8e2f0a7c16";
const LEGACY_MAIL: &str = "9a1c5e3f-4b82-4d07-a6f9-0e3b7c2d8a51";
const MFA_DENIED: &str = "6e2d8b4a-1f93-4c60-8d2e-9a7f3b5c0e47";
const MFA_METHOD: &str = "c7a3f0e5-5d28-4b91-9e6c-4f1a8d2b7e30";
const ACCOUNT_LOCKED: &str = "1d4f7a9c-8e26-4b3d-a5c0-6b9e2d1f8a75";
const DECOY_CONTACT: &str = "a7b8c02c-60bc-47ca-b31c-049f9d348159";
const DECOY_CONTACT_REPEATED: &str = "a7b8c02c-60bc-47ca-b31c-049f9d348159:repeated";
const DECOY_CANARY_HIT: &str = "ce68feda-b68d-4690-9d03-ba2f31cf87ac";

fn pack() -> RulePack {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity");
    RulePack::load(directory).unwrap()
}

fn event(class: EventClass, action: &str, kind: EntityKind) -> Event {
    let actor = Actor::new(kind, "principal-1")
        .with_ip("198.51.100.10".parse::<IpAddr>().unwrap())
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    Event::new(
        fixtures::base_time(),
        EventSource::new("entra-prod", "microsoft", "entra_id").with_tenant("tenant-1"),
        class,
        action,
        actor,
    )
    .with_outcome(Outcome::Success)
}

fn user(class: EventClass, action: &str) -> Event {
    event(class, action, EntityKind::User)
}

/// Returns the detections of the Sigma rules and of the indicators of the pack.
fn detect(pack: &RulePack, event: &Event) -> Vec<Detection> {
    let mut detections = pack.sigma().evaluate(event);
    detections.extend(pack.indicators().evaluate(event));
    detections
}

fn rule_ids(pack: &RulePack, event: &Event) -> Vec<String> {
    detect(pack, event)
        .into_iter()
        .map(|detection| detection.rule_id)
        .collect()
}

fn technique_ids(detection: &Detection) -> Vec<&str> {
    detection
        .attack
        .iter()
        .map(|technique| technique.technique_id.as_str())
        .collect()
}

const NONE: [&str; 0] = [];

#[test]
fn the_manifest_names_the_pack() {
    let pack = pack();
    assert_eq!(pack.manifest().name, "aegis-identity");
    assert!(!pack.manifest().version.is_empty());
    assert!(!pack.rules().is_empty());
    assert!(!pack.indicators().is_empty());
}

#[test]
fn the_pack_has_the_identity_rules_and_the_decoy_rules() {
    let pack = pack();
    let mut ids: Vec<&str> = pack.rules().iter().map(SigmaRule::id).collect();
    ids.sort_unstable();
    let mut expected = [
        CONSENT,
        HONEYTOKEN,
        WORKLOAD_ROLE,
        PERMISSION_GRANT,
        USER_CREATED,
        LEGACY_MAIL,
        MFA_DENIED,
        MFA_METHOD,
        ACCOUNT_LOCKED,
        DECOY_CONTACT,
        DECOY_CANARY_HIT,
    ];
    expected.sort_unstable();
    assert_eq!(ids, expected);
}

/// One event of a decoy service from a client.
fn decoy_event(sequence: u32, seconds: i64, name: &str, ip: &str, fingerprint: &str) -> Event {
    let actor = Actor::new(EntityKind::Other, "unknown")
        .with_ip(ip.parse::<IpAddr>().unwrap())
        .with_user_agent("scan-tool/3.1");
    Event::new(
        fixtures::base_time() + chrono::TimeDelta::seconds(seconds),
        EventSource::new("decoy-1", "aegis", "decoy").with_tenant("tenant-1"),
        EventClass::NetworkActivity,
        name,
        actor,
    )
    .with_id(aegis_contracts::common::EventId(uuid::Uuid::from_u128(
        u128::from(sequence) + 1,
    )))
    .with_outcome(Outcome::Success)
    .with_attribute(attr::DECOY_ID, "tarpit-1")
    .with_attribute(attr::DECOY_KIND, "tarpit")
    .with_attribute(attr::CLIENT_FINGERPRINT, fingerprint)
    .with_attribute(attr::HTTP_METHOD, "GET")
    .with_attribute(attr::HTTP_PATH, "/")
}

fn engine() -> DetectionEngine {
    DetectionEngine::new(EngineConfig::default(), pack()).unwrap()
}

#[tokio::test]
async fn one_contact_with_a_decoy_is_suspicious_and_names_the_address_and_the_fingerprint() {
    let engine = engine();
    let contact = decoy_event(1, 0, action::DECOY_CONTACT, "203.0.113.80", "FP-80");
    let output = engine.process(&contact).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    let found = &output.detections[0];
    assert_eq!(found.rule_id, DECOY_CONTACT);
    assert_eq!(found.title, "Client contacted a decoy");
    // A scanner also contacts a decoy, so one contact is not proof of an attack.
    assert_eq!(found.verdict, Verdict::Suspicious);
    assert_eq!(found.severity, Severity::Low);
    assert_eq!(technique_ids(found), ["T1595"]);
    assert_eq!(found.attack[0].tactic, "reconnaissance");
    assert_eq!(
        found.entities,
        [
            EntityRef::new(EntityKind::Other, "unknown"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.80"),
            EntityRef::new(EntityKind::Other, "client_fingerprint:fp-80"),
        ]
    );
    assert_eq!(found.attributes["decoy_id"], json!("tarpit-1"));
    assert_eq!(found.attributes["decoy_kind"], json!("tarpit"));
    assert_eq!(found.attributes["client_fingerprint"], json!("fp-80"));
    assert_eq!(found.attributes["user_agent"], json!("scan-tool/3.1"));

    // A different action of the same client is not this rule.
    let other = decoy_event(2, 1, action::NETWORK_CONNECT, "203.0.113.80", "FP-80");
    assert!(engine.process(&other).await.unwrap().is_empty());
}

#[tokio::test]
async fn repeated_contact_of_one_client_gives_one_malicious_detection() {
    let engine = engine();
    let mut rule_ids: Vec<Vec<String>> = Vec::new();
    for sequence in 0..40_u32 {
        let contact = decoy_event(
            sequence,
            i64::from(sequence),
            action::DECOY_CONTACT,
            "203.0.113.80",
            "fp-80",
        );
        let output = engine.process(&contact).await.unwrap();
        rule_ids.push(
            output
                .detections
                .iter()
                .map(|detection| detection.rule_id.clone())
                .collect(),
        );
        if sequence == 9 {
            // The tenth contact in ten minutes is the repeat detection.
            let repeated = &output.detections[0];
            assert_eq!(repeated.verdict, Verdict::Malicious);
            assert_eq!(repeated.severity, Severity::High);
            assert_eq!(repeated.title, "Client contacted a decoy: repeated");
            assert_eq!(repeated.attributes["matches"], json!(10));
            assert_eq!(repeated.attributes["window_seconds"], json!(600));
            assert_eq!(technique_ids(repeated), ["T1595"]);
            assert!(
                repeated
                    .entities
                    .contains(&EntityRef::new(EntityKind::IpAddress, "203.0.113.80"))
            );
            assert!(repeated.entities.contains(&EntityRef::new(
                EntityKind::Other,
                "client_fingerprint:fp-80"
            )));
            // The repeat detection is in the incident of the first contact.
            assert_eq!(output.incidents.len(), 1);
            assert_eq!(output.incidents[0].detections.len(), 2);
            assert_eq!(output.incidents[0].severity, Severity::High);
        }
    }
    // Forty contacts give two detections: the first contact and the tenth contact.
    for (sequence, found) in rule_ids.iter().enumerate() {
        let expected: &[&str] = match sequence {
            0 => &[DECOY_CONTACT],
            9 => &[DECOY_CONTACT_REPEATED],
            _ => &[],
        };
        assert_eq!(found, expected, "contact {sequence}");
    }
    assert_eq!(engine.flood_counters().suppressed_matches, 39);
    assert_eq!(engine.flood_counters().repeat_detections, 1);
    let summaries = engine.suppression_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].rule_id, DECOY_CONTACT);
    assert_eq!(summaries[0].key, "203.0.113.80, fp-80");
    assert_eq!(summaries[0].matches, 40);

    // Nine contacts of a different client stay below the count.
    let mut other = 0;
    for sequence in 100..109_u32 {
        let contact = decoy_event(
            sequence,
            i64::from(sequence),
            action::DECOY_CONTACT,
            "203.0.113.81",
            "fp-81",
        );
        other += engine.process(&contact).await.unwrap().detections.len();
    }
    assert_eq!(other, 1);
    // The same address with a different fingerprint is a different client.
    let changed = decoy_event(200, 200, action::DECOY_CONTACT, "203.0.113.80", "fp-other");
    let output = engine.process(&changed).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    assert_eq!(output.detections[0].rule_id, DECOY_CONTACT);
}

#[tokio::test]
async fn a_canary_hit_is_malicious_at_the_first_event() {
    let engine = engine();
    let hit = decoy_event(1, 0, action::DECOY_CANARY_HIT, "203.0.113.82", "fp-82")
        .with_attribute(attr::CANARY_ID, "canary-7");
    let output = engine.process(&hit).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    let found = &output.detections[0];
    assert_eq!(found.rule_id, DECOY_CANARY_HIT);
    assert_eq!(found.verdict, Verdict::Malicious);
    assert_eq!(found.severity, Severity::High);
    assert_eq!(technique_ids(found), ["T1595"]);
    assert_eq!(
        found.entities,
        [
            EntityRef::new(EntityKind::Other, "unknown"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.82"),
            EntityRef::new(EntityKind::Other, "client_fingerprint:fp-82"),
        ]
    );
    assert_eq!(output.incidents.len(), 1);
    assert_eq!(output.incidents[0].severity, Severity::High);

    // The same client and the same canary again give no second detection in ten minutes.
    let again = decoy_event(2, 30, action::DECOY_CANARY_HIT, "203.0.113.82", "fp-82")
        .with_attribute(attr::CANARY_ID, "canary-7");
    assert!(engine.process(&again).await.unwrap().is_empty());
    // A different canary is a new detection.
    let other = decoy_event(3, 60, action::DECOY_CANARY_HIT, "203.0.113.82", "fp-82")
        .with_attribute(attr::CANARY_ID, "canary-8");
    let output = engine.process(&other).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    assert_eq!(output.detections[0].rule_id, DECOY_CANARY_HIT);
    // A contact with a canary identifier is a contact, not a canary hit.
    let contact = decoy_event(4, 90, action::DECOY_CONTACT, "203.0.113.83", "fp-83")
        .with_attribute(attr::CANARY_ID, "canary-7");
    let output = engine.process(&contact).await.unwrap();
    assert_eq!(output.detections.len(), 1);
    assert_eq!(output.detections[0].rule_id, DECOY_CONTACT);
}

#[tokio::test]
async fn the_sign_in_rules_give_one_detection_for_one_account_in_their_window() {
    let engine = engine();
    let locked = |sequence: u32, seconds: i64, account: &str| {
        let mut event = user(EventClass::Authentication, action::SIGN_IN)
            .with_outcome(Outcome::Failure)
            .with_attribute(attr::ERROR_CODE, "50053");
        event.id = aegis_contracts::common::EventId(uuid::Uuid::from_u128(u128::from(sequence)));
        event.time = fixtures::base_time() + chrono::TimeDelta::seconds(seconds);
        event.actor.id = account.to_owned();
        event
    };
    let mut counts = Vec::new();
    for (sequence, seconds, account) in [
        (1, 0, "user-a"),
        (2, 10, "user-a"),
        (3, 899, "user-a"),
        (4, 20, "user-b"),
        (5, 900, "user-a"),
    ] {
        let output = engine
            .process(&locked(sequence, seconds, account))
            .await
            .unwrap();
        let ids: Vec<&str> = output
            .detections
            .iter()
            .map(|detection| detection.rule_id.as_str())
            .collect();
        assert!(ids.iter().all(|id| *id == ACCOUNT_LOCKED), "{ids:?}");
        counts.push(ids.len());
    }
    // The window of the rule is 15 minutes for one account.
    assert_eq!(counts, [1, 0, 0, 1, 1]);
}

#[test]
fn each_rule_is_active_and_has_a_description_and_a_technique() {
    let pack = pack();
    assert!(!pack.rules().is_empty());
    for rule in pack.rules() {
        assert!(rule.is_active(), "{}", rule.origin());
        assert!(!rule.description().is_empty(), "{}", rule.origin());
        assert!(!rule.attack().is_empty(), "{}", rule.origin());
        assert!(
            rule.attack()
                .iter()
                .all(|technique| technique.tactic != "unknown"
                    && technique.name != technique.technique_id),
            "{}: {:?}",
            rule.origin(),
            rule.attack()
        );
    }
}

#[test]
fn consent_to_privileged_permissions_is_malicious() {
    let pack = pack();
    let consent = || {
        user(
            EventClass::UserAccessManagement,
            action::OAUTH_CONSENT_GRANT,
        )
    };

    let flagged = consent().with_attribute(attr::PRIVILEGED, true);
    let detections = detect(&pack, &flagged);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, CONSENT);
    assert_eq!(detections[0].verdict, Verdict::Malicious);
    assert_eq!(detections[0].severity, Severity::High);
    assert_eq!(technique_ids(&detections[0]), ["T1528"]);

    // A privileged scope is sufficient when the source does not set the flag.
    for scope in [
        "Directory.ReadWrite.All",
        "rolemanagement.readwrite.directory",
        "Mail.Read",
        "full_access_as_app",
    ] {
        let by_scope = consent().with_attribute(attr::SCOPES, json!(["openid", scope]));
        assert_eq!(rule_ids(&pack, &by_scope), [CONSENT], "{scope}");
    }

    let ordinary = consent()
        .with_attribute(attr::PRIVILEGED, false)
        .with_attribute(
            attr::SCOPES,
            json!(["openid", "profile", "User.Read", "Mail.ReadBasic"]),
        );
    assert_eq!(rule_ids(&pack, &ordinary), NONE);
    assert_eq!(rule_ids(&pack, &consent()), NONE);
    let failed = consent()
        .with_attribute(attr::PRIVILEGED, true)
        .with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
    let other_action = user(EventClass::UserAccessManagement, action::ROLE_REMOVE)
        .with_attribute(attr::PRIVILEGED, true);
    assert_eq!(rule_ids(&pack, &other_action), NONE);
    // The log source of the rule is the class of access management events.
    let other_class =
        user(EventClass::Other, action::OAUTH_CONSENT_GRANT).with_attribute(attr::PRIVILEGED, true);
    assert_eq!(rule_ids(&pack, &other_class), NONE);
}

#[test]
fn a_honeytoken_use_is_critical() {
    let pack = pack();
    let trip = event(
        EventClass::ApiActivity,
        action::HONEYTOKEN_TRIP,
        EntityKind::ServicePrincipal,
    );
    let detections = detect(&pack, &trip);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, HONEYTOKEN);
    assert_eq!(detections[0].severity, Severity::Critical);
    assert_eq!(detections[0].verdict, Verdict::Malicious);
    assert_eq!(technique_ids(&detections[0]), ["T1552"]);

    // A different action on a resource that the source marks as a honeytoken also matches.
    let marked = user(EventClass::ApiActivity, action::SECRET_READ)
        .with_attribute(attr::HONEYTOKEN_ID, "honeytoken-1");
    assert_eq!(rule_ids(&pack, &marked), [HONEYTOKEN]);

    let ordinary_read = user(EventClass::ApiActivity, action::SECRET_READ);
    assert_eq!(rule_ids(&pack, &ordinary_read), NONE);
}

#[test]
fn a_privileged_role_from_a_workload_identity_is_malicious() {
    let pack = pack();
    let assignment = |kind: EntityKind, action: &str| {
        event(EventClass::UserAccessManagement, action, kind)
            .with_target(EntityRef::new(EntityKind::User, "user-2"))
            .with_attribute(attr::PRIVILEGED, true)
    };
    for kind in [EntityKind::ServicePrincipal, EntityKind::Application] {
        for name in [action::ROLE_ASSIGN, action::APP_PERMISSION_GRANT] {
            let detections = detect(&pack, &assignment(kind, name));
            assert_eq!(detections.len(), 1, "{kind:?} {name}");
            assert_eq!(detections[0].rule_id, WORKLOAD_ROLE);
            assert_eq!(detections[0].verdict, Verdict::Malicious);
            assert_eq!(technique_ids(&detections[0]), ["T1098.003"]);
        }
    }

    // A person who assigns a role is not this rule.
    assert_eq!(
        rule_ids(&pack, &assignment(EntityKind::User, action::ROLE_ASSIGN)),
        NONE
    );
    let not_privileged = assignment(EntityKind::ServicePrincipal, action::ROLE_ASSIGN)
        .with_attribute(attr::PRIVILEGED, false);
    assert_eq!(rule_ids(&pack, &not_privileged), NONE);
    let failed = assignment(EntityKind::ServicePrincipal, action::ROLE_ASSIGN)
        .with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
    let removal = assignment(EntityKind::ServicePrincipal, action::ROLE_REMOVE);
    assert_eq!(rule_ids(&pack, &removal), NONE);
}

#[test]
fn a_privileged_application_permission_from_a_person_is_suspicious() {
    let pack = pack();
    let grant = |kind: EntityKind| {
        event(
            EventClass::UserAccessManagement,
            action::APP_PERMISSION_GRANT,
            kind,
        )
        .with_attribute(attr::PRIVILEGED, true)
    };
    let detections = detect(&pack, &grant(EntityKind::User));
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, PERMISSION_GRANT);
    assert_eq!(detections[0].verdict, Verdict::Suspicious);
    assert_eq!(detections[0].severity, Severity::Medium);
    assert_eq!(technique_ids(&detections[0]), ["T1098.003"]);

    // The same grant from a workload identity is the malicious rule, and only that rule.
    assert_eq!(
        rule_ids(&pack, &grant(EntityKind::ServicePrincipal)),
        [WORKLOAD_ROLE]
    );
    let not_privileged = grant(EntityKind::User).with_attribute(attr::PRIVILEGED, false);
    assert_eq!(rule_ids(&pack, &not_privileged), NONE);
    let failed = grant(EntityKind::User).with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
}

#[test]
fn a_user_account_from_a_workload_identity_is_suspicious() {
    let pack = pack();
    let create = |kind: EntityKind| event(EventClass::AccountChange, action::USER_CREATE, kind);
    for kind in [EntityKind::ServicePrincipal, EntityKind::Application] {
        let detections = detect(&pack, &create(kind));
        assert_eq!(detections.len(), 1, "{kind:?}");
        assert_eq!(detections[0].rule_id, USER_CREATED);
        assert_eq!(detections[0].verdict, Verdict::Suspicious);
        assert_eq!(technique_ids(&detections[0]), ["T1136.003"]);
    }
    assert_eq!(rule_ids(&pack, &create(EntityKind::User)), NONE);
    let failed = create(EntityKind::ServicePrincipal).with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
    let update = event(
        EventClass::AccountChange,
        action::USER_UPDATE,
        EntityKind::ServicePrincipal,
    );
    assert_eq!(rule_ids(&pack, &update), NONE);
}

#[test]
fn a_successful_sign_in_with_a_legacy_mail_protocol_is_suspicious() {
    let pack = pack();
    let sign_in = |protocol: &str| {
        user(EventClass::Authentication, action::SIGN_IN)
            .with_attribute(attr::AUTH_PROTOCOL, protocol)
    };
    for protocol in [
        "imap",
        "IMAP4",
        "pop3",
        "Authenticated SMTP",
        "Exchange ActiveSync",
        // The values that the Entra ID source writes.
        "authenticated_smtp",
        "exchange_active_sync",
        "exchange_web_services",
        "mapi_over_http",
        "auto_discover",
        "autodiscover",
    ] {
        let detections = detect(&pack, &sign_in(protocol));
        assert_eq!(detections.len(), 1, "{protocol}");
        assert_eq!(detections[0].rule_id, LEGACY_MAIL);
        assert_eq!(detections[0].verdict, Verdict::Suspicious);
        assert_eq!(technique_ids(&detections[0]), ["T1078.004"]);
    }
    for protocol in [
        "browser",
        "client_credentials",
        "ropc",
        "mobile apps and desktop clients",
    ] {
        assert_eq!(rule_ids(&pack, &sign_in(protocol)), NONE, "{protocol}");
    }
    let failed = sign_in("imap").with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
    let no_protocol = user(EventClass::Authentication, action::SIGN_IN);
    assert_eq!(rule_ids(&pack, &no_protocol), NONE);
}

#[test]
fn a_denied_multi_factor_request_is_suspicious() {
    let pack = pack();
    let failed_sign_in =
        || user(EventClass::Authentication, action::SIGN_IN).with_outcome(Outcome::Failure);

    let by_code = failed_sign_in().with_attribute(attr::ERROR_CODE, "500121");
    let detections = detect(&pack, &by_code);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, MFA_DENIED);
    assert_eq!(detections[0].verdict, Verdict::Suspicious);
    assert_eq!(technique_ids(&detections[0]), ["T1621"]);
    let by_number = failed_sign_in().with_attribute(attr::ERROR_CODE, 500_121);
    assert_eq!(rule_ids(&pack, &by_number), [MFA_DENIED]);
    let by_text = failed_sign_in().with_attribute(
        attr::FAILURE_REASON,
        "The user DENIED the authentication request in the app.",
    );
    assert_eq!(rule_ids(&pack, &by_text), [MFA_DENIED]);

    // A wrong password is not this rule. This is the failure of the recorded spray.
    let wrong_password = failed_sign_in()
        .with_attribute(attr::ERROR_CODE, "50126")
        .with_attribute(attr::FAILURE_REASON, "Invalid username or password.");
    assert_eq!(rule_ids(&pack, &wrong_password), NONE);
    let success = by_code.with_outcome(Outcome::Success);
    assert_eq!(rule_ids(&pack, &success), NONE);
}

#[test]
fn a_multi_factor_method_change_from_a_script_client_is_suspicious() {
    let pack = pack();
    let change = |user_agent: &str| {
        let mut event = user(EventClass::AccountChange, action::MFA_METHOD_CHANGE);
        event.actor.user_agent = Some(user_agent.to_owned());
        event
    };
    for user_agent in ["python-httpx/0.27.0", "curl/8.6.0", "Go-http-client/2.0"] {
        let detections = detect(&pack, &change(user_agent));
        assert_eq!(detections.len(), 1, "{user_agent}");
        assert_eq!(detections[0].rule_id, MFA_METHOD);
        assert_eq!(detections[0].verdict, Verdict::Suspicious);
        assert_eq!(technique_ids(&detections[0]), ["T1556.006"]);
    }
    let browser = change("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    assert_eq!(rule_ids(&pack, &browser), NONE);
    let mut no_user_agent = change("x");
    no_user_agent.actor.user_agent = None;
    assert_eq!(rule_ids(&pack, &no_user_agent), NONE);
    let failed = change("curl/8.6.0").with_outcome(Outcome::Failure);
    assert_eq!(rule_ids(&pack, &failed), NONE);
    // A sign-in from a script client is not a method change.
    let mut sign_in = user(EventClass::Authentication, action::SIGN_IN);
    sign_in.actor.user_agent = Some("python-httpx/0.27.0".to_owned());
    assert_eq!(rule_ids(&pack, &sign_in), NONE);
}

#[test]
fn an_account_lock_is_a_low_suspicious_detection() {
    let pack = pack();
    let failed_sign_in =
        || user(EventClass::Authentication, action::SIGN_IN).with_outcome(Outcome::Failure);
    let by_code = failed_sign_in().with_attribute(attr::ERROR_CODE, "50053");
    let detections = detect(&pack, &by_code);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, ACCOUNT_LOCKED);
    assert_eq!(detections[0].severity, Severity::Low);
    assert_eq!(detections[0].verdict, Verdict::Suspicious);
    assert_eq!(technique_ids(&detections[0]), ["T1110"]);
    let by_text = failed_sign_in().with_attribute(
        attr::FAILURE_REASON,
        "The account is locked. Try again later.",
    );
    assert_eq!(rule_ids(&pack, &by_text), [ACCOUNT_LOCKED]);

    let wrong_password = failed_sign_in().with_attribute(attr::ERROR_CODE, "50126");
    assert_eq!(rule_ids(&pack, &wrong_password), NONE);
    assert_eq!(rule_ids(&pack, &failed_sign_in()), NONE);
}

#[test]
fn the_indicators_match_their_values_and_nothing_near_them() {
    let pack = pack();
    let from = |ip: &str| {
        let mut event = user(EventClass::Authentication, action::SIGN_IN);
        event.actor.ip = Some(ip.parse().unwrap());
        event
    };
    assert_eq!(
        rule_ids(&pack, &from("192.0.2.201")),
        ["ioc:ip:192.0.2.200/29"]
    );
    assert_eq!(rule_ids(&pack, &from("192.0.2.208")), NONE);
    assert_eq!(
        rule_ids(&pack, &from("203.0.113.230")),
        ["ioc:ip:203.0.113.224/28"]
    );
    assert_eq!(
        rule_ids(&pack, &from("2001:db8:bad:7::1")),
        ["ioc:ip:2001:db8:bad::/48"]
    );
    assert_eq!(rule_ids(&pack, &from("2001:db8:bae::1")), NONE);

    let connection = user(EventClass::NetworkActivity, action::NETWORK_CONNECT)
        .with_attribute(attr::DESTINATION_DOMAIN, "portal.sign-in-check.example");
    assert_eq!(
        rule_ids(&pack, &connection),
        ["ioc:domain:sign-in-check.example"]
    );
    let other_domain = user(EventClass::NetworkActivity, action::NETWORK_CONNECT)
        .with_attribute(attr::DESTINATION_DOMAIN, "sign-in-check.example.org");
    assert_eq!(rule_ids(&pack, &other_domain), NONE);

    let mut tool = user(EventClass::Authentication, action::SIGN_IN);
    tool.actor.user_agent = Some("Example-Password-Tester/2.1".to_owned());
    assert_eq!(
        rule_ids(&pack, &tool),
        ["ioc:user_agent:example-password-tester/"]
    );

    let consent = user(EventClass::Other, action::APP_CREATE)
        .with_attribute(attr::APP_ID, "app-example-consent-trap");
    assert_eq!(
        rule_ids(&pack, &consent),
        ["ioc:app_id:app-example-consent-trap"]
    );
}

#[test]
fn the_indicators_use_only_documentation_addresses_and_reserved_domains() {
    let documentation: Vec<IpNet> = [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    ]
    .iter()
    .map(|network| network.parse().unwrap())
    .collect();
    let pack = pack();
    let mut addresses = 0;
    let mut domains = 0;
    for indicator in pack.indicators().indicators() {
        match indicator.kind {
            IndicatorKind::Ip => {
                addresses += 1;
                let network: IpNet = indicator
                    .value
                    .parse()
                    .or_else(|_| indicator.value.parse::<IpAddr>().map(IpNet::from))
                    .unwrap();
                assert!(
                    documentation.iter().any(|range| range.contains(&network)),
                    "{} is not in a documentation range",
                    indicator.value
                );
            }
            IndicatorKind::Domain => {
                domains += 1;
                let reserved = [".example", ".test", ".invalid"];
                assert!(
                    reserved
                        .iter()
                        .any(|suffix| indicator.value.ends_with(suffix)),
                    "{} does not use a reserved top-level domain",
                    indicator.value
                );
            }
            IndicatorKind::UserAgent | IndicatorKind::AppId | IndicatorKind::ClientFingerprint => {
                assert!(
                    indicator.value.contains("example"),
                    "{} is not marked as an example",
                    indicator.value
                );
            }
        }
    }
    assert!(addresses > 0);
    assert!(domains > 0);
}

#[test]
fn no_indicator_matches_an_event_of_the_recorded_attack_log() {
    let pack = pack();
    let events = fixtures::artex_style_attack();
    assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
    let matches: usize = events
        .iter()
        .map(|event| pack.indicators().evaluate(event).len())
        .sum();
    assert_eq!(matches, 0);
}
