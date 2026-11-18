//! Tests of the rule pack that the project ships: `detections/aegis-identity`.
//!
//! Each rule gets events that it must match and events that it must not match.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::path::PathBuf;

use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{Detection, Verdict};
use aegis_detect::ioc::IndicatorKind;
use aegis_detect::pack::RulePack;
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
            IndicatorKind::UserAgent | IndicatorKind::AppId => {
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
