//! Tests of whole rules: Sigma YAML against events.

use std::net::{IpAddr, Ipv4Addr};

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
use aegis_contracts::{AttackTechnique, DetectionTier, Detector, Verdict};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::common::ip_entity;

fn time() -> DateTime<Utc> {
    DateTime::from_timestamp(1_793_696_400, 0).unwrap()
}

/// A consent grant by a user from a script, with a list attribute and a raw record.
fn event() -> Event {
    let actor = Actor::new(EntityKind::User, "user-dana")
        .with_name("dana@contoso.example")
        .with_tenant("tenant-contoso")
        .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)))
        .with_user_agent("python-httpx/0.27.0");
    Event::new(
        time(),
        EventSource::new("entra-prod", "microsoft", "entra_id").with_tenant("tenant-contoso"),
        EventClass::UserAccessManagement,
        action::OAUTH_CONSENT_GRANT,
        actor,
    )
    .with_id(EventId(Uuid::from_u128(7)))
    .with_outcome(Outcome::Success)
    .with_target(
        EntityRef::new(EntityKind::Application, "app-sync-helper").with_name("Sync Helper"),
    )
    .with_attribute(attr::APP_ID, "app-sync-helper")
    .with_attribute(attr::PRIVILEGED, true)
    .with_attribute(attr::ERROR_CODE, "50126")
    .with_attribute("risk_score", 72)
    .with_attribute(
        attr::SCOPES,
        json!([
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "offline_access"
        ]),
    )
    .with_raw(json!({ "operationName": "Consent to application", "result": { "code": 0 } }))
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}\n"))
        .collect::<String>()
}

/// Compiles a rule with the given `detection` section.
fn rule(detection: &str) -> SigmaRule {
    let text = format!("title: Test rule\ndetection:\n{}", indent(detection));
    SigmaRule::parse(&text, "test.yml").unwrap()
}

/// Returns `true` if a rule with the given `detection` section matches the event.
fn matches(detection: &str) -> bool {
    rule(detection).matches(&event())
}

/// Returns the reason that a rule text is not valid.
fn reason(text: &str) -> String {
    match SigmaRule::parse(text, "rules/broken.yml").unwrap_err() {
        DetectError::Rule { file, reason } => {
            assert_eq!(file, "rules/broken.yml");
            reason
        }
        other => panic!("unexpected error: {other}"),
    }
}

/// Returns the reason that a `detection` section is not valid.
fn detection_reason(detection: &str) -> String {
    reason(&format!(
        "title: Test rule\ndetection:\n{}",
        indent(detection)
    ))
}

const FULL_RULE: &str = r"
title: Consent to privileged scopes
id: 0f6a4a3e-5d1b-4c57-9f0e-3c8a5b7d9e21
status: stable
description: A principal consents to privileged scopes for an application.
author: AEGIS
references:
  - https://attack.mitre.org/techniques/T1528/
logsource:
  product: entra_id
  category: user_access_management
detection:
  selection:
    action: oauth.consent_grant
    privileged: true
  condition: selection
falsepositives:
  - An administrator who installs a known application.
level: high
tags:
  - attack.credential-access
  - attack.t1528
";

#[test]
fn a_rule_keeps_its_metadata() {
    let rule = SigmaRule::parse(FULL_RULE, "rules/consent.yml").unwrap();
    assert_eq!(rule.id(), "0f6a4a3e-5d1b-4c57-9f0e-3c8a5b7d9e21");
    assert_eq!(rule.title(), "Consent to privileged scopes");
    assert_eq!(
        rule.description(),
        "A principal consents to privileged scopes for an application."
    );
    assert_eq!(rule.status(), Some(SigmaStatus::Stable));
    assert_eq!(rule.level(), Severity::High);
    assert_eq!(rule.verdict(), Verdict::Malicious);
    assert_eq!(rule.tags(), ["attack.credential-access", "attack.t1528"]);
    assert_eq!(
        rule.attack(),
        [AttackTechnique::new(
            "credential-access",
            "T1528",
            "Steal Application Access Token"
        )]
    );
    assert_eq!(rule.origin(), "rules/consent.yml");
    assert!(rule.is_active());
    assert!(rule.matches(&event()));
}

#[test]
fn a_match_gives_a_detection_with_the_data_of_the_rule_and_the_event() {
    let rule = SigmaRule::parse(FULL_RULE, "rules/consent.yml").unwrap();
    let event = event();
    let detection = rule.detect(&event).unwrap();
    assert_eq!(detection.rule_id, "0f6a4a3e-5d1b-4c57-9f0e-3c8a5b7d9e21");
    assert_eq!(detection.title, "Consent to privileged scopes");
    assert_eq!(detection.severity, Severity::High);
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert_eq!(detection.tier, DetectionTier::Deterministic);
    assert_eq!(detection.time, event.time);
    assert_eq!(detection.event_ids, [event.id]);
    assert_eq!(detection.tenant.as_deref(), Some("tenant-contoso"));
    assert_eq!(detection.attack, rule.attack());
    assert_eq!(
        detection.entities,
        [
            event.actor.entity(),
            ip_entity(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))),
            EntityRef::new(EntityKind::Application, "app-sync-helper").with_name("Sync Helper"),
        ]
    );
    assert_eq!(detection.attributes["detector"], json!("aegis.sigma"));
    assert_eq!(detection.attributes["action"], json!("oauth.consent_grant"));
    assert_eq!(detection.id, rule.detect(&event).unwrap().id);

    let mut other = event.clone();
    other.action = action::SIGN_IN.to_owned();
    assert_eq!(rule.detect(&other), None);
}

#[test]
fn the_level_sets_the_severity_and_the_default_verdict() {
    for (level, severity, verdict) in [
        (
            "informational",
            Severity::Informational,
            Verdict::Suspicious,
        ),
        ("low", Severity::Low, Verdict::Suspicious),
        ("medium", Severity::Medium, Verdict::Suspicious),
        ("high", Severity::High, Verdict::Malicious),
        ("critical", Severity::Critical, Verdict::Malicious),
    ] {
        let text = format!(
            "title: T\nlevel: {level}\ndetection:\n  selection:\n    action: sign_in\n  condition: selection\n"
        );
        let rule = SigmaRule::parse(&text, "t.yml").unwrap();
        assert_eq!(rule.level(), severity, "{level}");
        assert_eq!(rule.verdict(), verdict, "{level}");
    }
    let rule = rule("selection:\n  action: sign_in\ncondition: selection");
    assert_eq!(rule.level(), Severity::Medium);
    assert_eq!(rule.verdict(), Verdict::Suspicious);
    assert_eq!(rule.status(), None);
    assert_eq!(rule.description(), "");
    assert_eq!(rule.attack(), []);
}

#[test]
fn aegis_verdict_replaces_the_default_verdict() {
    let body = "detection:\n  selection:\n    action: sign_in\n  condition: selection\n";
    let flat = format!("title: T\nlevel: high\naegis.verdict: suspicious\n{body}");
    assert_eq!(
        SigmaRule::parse(&flat, "t.yml").unwrap().verdict(),
        Verdict::Suspicious
    );
    let nested = format!("title: T\nlevel: low\naegis:\n  verdict: malicious\n{body}");
    let rule = SigmaRule::parse(&nested, "t.yml").unwrap();
    assert_eq!(rule.verdict(), Verdict::Malicious);
    assert_eq!(rule.level(), Severity::Low);

    let benign = format!("title: T\naegis.verdict: benign\n{body}");
    assert_eq!(
        reason(&benign),
        "aegis.verdict is \"benign\"; use malicious or suspicious"
    );
    let number = format!("title: T\naegis.verdict: 1\n{body}");
    assert_eq!(reason(&number), "aegis.verdict must be a string");
}

#[test]
fn a_rule_with_no_id_gets_an_identifier_from_its_title() {
    let text = "title: '  Sign-in: Burst (v2)!  '\ndetection:\n  selection:\n    action: sign_in\n  condition: selection\n";
    let rule = SigmaRule::parse(text, "t.yml").unwrap();
    assert_eq!(rule.id(), "sigma.sign-in-burst-v2");
    assert_eq!(rule.title(), "Sign-in: Burst (v2)!");
}

#[test]
fn a_deprecated_or_unsupported_rule_never_matches() {
    for (status, active) in [
        ("stable", true),
        ("test", true),
        ("experimental", true),
        ("deprecated", false),
        ("unsupported", false),
    ] {
        let text = format!(
            "title: T\nstatus: {status}\ndetection:\n  selection:\n    action: oauth.consent_grant\n  condition: selection\n"
        );
        let rule = SigmaRule::parse(&text, "t.yml").unwrap();
        assert_eq!(rule.is_active(), active, "{status}");
        assert_eq!(rule.matches(&event()), active, "{status}");
        assert_eq!(rule.detect(&event()).is_some(), active, "{status}");
    }
}

// ----- Log source -----

fn logsource_matches(logsource: &str) -> bool {
    let text = format!(
        "title: T\nlogsource:\n{}detection:\n  selection:\n    action: oauth.consent_grant\n  condition: selection\n",
        indent(logsource)
    );
    SigmaRule::parse(&text, "t.yml").unwrap().matches(&event())
}

#[test]
fn the_logsource_product_is_the_product_or_the_vendor_of_the_source() {
    assert!(logsource_matches("product: entra_id"));
    assert!(logsource_matches("product: Entra_ID"));
    assert!(logsource_matches("product: microsoft"));
    assert!(!logsource_matches("product: okta"));
    assert!(!logsource_matches("product: entra"));
}

#[test]
fn the_logsource_service_is_the_product_or_the_connector_of_the_source() {
    assert!(logsource_matches("service: entra_id"));
    assert!(logsource_matches("service: entra-prod"));
    assert!(!logsource_matches("service: microsoft"));
    assert!(!logsource_matches("service: signinlogs"));
}

#[test]
fn the_logsource_category_is_the_class_of_the_event() {
    assert!(logsource_matches("category: user_access_management"));
    assert!(!logsource_matches("category: authentication"));
    assert!(logsource_matches(
        "product: microsoft\nservice: entra_id\ncategory: user_access_management"
    ));
    assert!(!logsource_matches(
        "product: microsoft\nservice: entra_id\ncategory: api_activity"
    ));
    assert!(!logsource_matches(
        "product: okta\ncategory: user_access_management"
    ));
    assert!(logsource_matches(
        "definition: Free text that the engine ignores."
    ));
}

#[test]
fn a_sigma_category_alias_selects_the_matching_class() {
    let text = "title: T\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    action: process.start\n  condition: selection\n";
    let rule = SigmaRule::parse(text, "t.yml").unwrap();
    let mut event = event();
    event.action = action::PROCESS_START.to_owned();
    assert!(!rule.matches(&event));
    event.class = EventClass::ProcessActivity;
    assert!(rule.matches(&event));
}

#[test]
fn a_logsource_that_the_engine_cannot_apply_is_an_error() {
    let body = "detection:\n  selection:\n    action: sign_in\n  condition: selection\n";
    let unknown = reason(&format!("title: T\nlogsource:\n  category: dns\n{body}"));
    assert!(
        unknown.starts_with(
            "the logsource category \"dns\" is not known; the categories are authentication, "
        ),
        "{unknown}"
    );
    assert_eq!(
        reason(&format!("title: T\nlogsource:\n  product: 5\n{body}")),
        "logsource.product must be a string that is not empty"
    );
    assert_eq!(
        reason(&format!("title: T\nlogsource: entra\n{body}")),
        "logsource must be a map"
    );
}

// ----- Selections -----

#[test]
fn a_selection_map_needs_each_field() {
    assert!(matches(
        "selection:\n  action: oauth.consent_grant\n  outcome: success\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  action: oauth.consent_grant\n  outcome: failure\ncondition: selection"
    ));
}

#[test]
fn a_selection_list_of_maps_needs_one_map() {
    let second = "selection:\n  - action: sign_in\n  - action: oauth.consent_grant\n    outcome: success\ncondition: selection";
    assert!(matches(second));
    let none = "selection:\n  - action: sign_in\n  - action: oauth.consent_grant\n    outcome: failure\ncondition: selection";
    assert!(!matches(none));
}

#[test]
fn a_list_of_values_needs_one_value() {
    assert!(matches(
        "selection:\n  action:\n    - sign_in\n    - oauth.consent_grant\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  action:\n    - sign_in\n    - role.assign\ncondition: selection"
    ));
}

#[test]
fn string_values_ignore_case_and_accept_wildcards() {
    assert!(matches(
        "selection:\n  action: OAUTH.Consent_Grant\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  action: 'oauth.*'\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  actor.id: 'user-d?na'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  action: 'app.*'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.id: 'user-d?a'\ncondition: selection"
    ));
}

#[test]
fn a_list_attribute_matches_when_one_item_matches() {
    assert!(matches(
        "selection:\n  scopes: offline_access\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  scopes: '*.ReadWrite.All'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  scopes: Mail.Read\ncondition: selection"
    ));
}

#[test]
fn the_contains_modifier() {
    assert!(matches(
        "selection:\n  actor.user_agent|contains: HTTPX\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  scopes|contains: rolemanagement\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.user_agent|contains: curl\ncondition: selection"
    ));
}

#[test]
fn the_startswith_modifier() {
    assert!(matches(
        "selection:\n  actor.user_agent|startswith: python-\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.user_agent|startswith: httpx\ncondition: selection"
    ));
}

#[test]
fn the_endswith_modifier() {
    assert!(matches(
        "selection:\n  actor.name|endswith: '@contoso.example'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.name|endswith: '@fabrikam.example'\ncondition: selection"
    ));
}

#[test]
fn the_re_modifier() {
    assert!(matches(
        "selection:\n  actor.user_agent|re: '^python-[a-z]+/\\d'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.user_agent|re: '^Python-'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.user_agent|re: '^httpx'\ncondition: selection"
    ));
}

#[test]
fn the_cidr_modifier() {
    assert!(matches(
        "selection:\n  actor.ip|cidr: 203.0.113.0/24\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  actor.ip|cidr:\n    - 198.51.100.0/24\n    - 203.0.113.48/29\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.ip|cidr: 198.51.100.0/24\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.ip|cidr: 2001:db8::/32\ncondition: selection"
    ));
}

#[test]
fn the_all_modifier_needs_each_value() {
    let both = "selection:\n  scopes|contains|all:\n    - Directory.ReadWrite\n    - RoleManagement\ncondition: selection";
    assert!(matches(both));
    let one_absent = "selection:\n  scopes|contains|all:\n    - Directory.ReadWrite\n    - Mail.Send\ncondition: selection";
    assert!(!matches(one_absent));
    let any = "selection:\n  scopes|contains:\n    - Directory.ReadWrite\n    - Mail.Send\ncondition: selection";
    assert!(matches(any));
    let exact_all = "selection:\n  scopes|all:\n    - offline_access\n    - directory.readwrite.all\ncondition: selection";
    assert!(matches(exact_all));
}

#[test]
fn the_comparison_modifiers() {
    for (modifier, value, expected) in [
        ("gt", 71, true),
        ("gt", 72, false),
        ("gte", 72, true),
        ("gte", 73, false),
        ("lt", 73, true),
        ("lt", 72, false),
        ("lte", 72, true),
        ("lte", 71, false),
    ] {
        let detection =
            format!("selection:\n  risk_score|{modifier}: {value}\ncondition: selection");
        assert_eq!(matches(&detection), expected, "{modifier} {value}");
    }
    assert!(matches(
        "selection:\n  error_code|gt: 50000\ncondition: selection"
    ));
    assert!(!matches("selection:\n  action|gt: 1\ncondition: selection"));
    assert!(!matches(
        "selection:\n  missing|lt: 1\ncondition: selection"
    ));
}

#[test]
fn the_exists_modifier() {
    assert!(matches(
        "selection:\n  app_id|exists: true\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  app_id|exists: false\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  honeytoken_id|exists: false\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  honeytoken_id|exists: true\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  actor.ip|exists: true\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  actor.session_id|exists: true\ncondition: selection"
    ));
}

#[test]
fn a_null_value_matches_a_field_that_is_absent_or_null() {
    assert!(matches(
        "selection:\n  honeytoken_id: null\ncondition: selection"
    ));
    assert!(!matches("selection:\n  app_id: null\ncondition: selection"));
    assert!(matches(
        "selection:\n  actor.session_id: null\ncondition: selection"
    ));
    let rule = rule("selection:\n  note: null\ncondition: selection");
    let with_null = event().with_attribute("note", serde_json::Value::Null);
    assert!(rule.matches(&with_null));
    let with_text = event().with_attribute("note", "text");
    assert!(!rule.matches(&with_text));
    assert!(matches(
        "selection:\n  app_id:\n    - null\n    - app-sync-helper\ncondition: selection"
    ));
}

#[test]
fn numbers_and_booleans_match_typed_and_text_values() {
    assert!(matches(
        "selection:\n  privileged: true\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  privileged: false\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  risk_score: 72\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  risk_score: 73\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  error_code: 50126\ncondition: selection"
    ));
    assert!(matches(
        "selection:\n  error_code: '50126'\ncondition: selection"
    ));
    assert!(!matches(
        "selection:\n  error_code: 50127\ncondition: selection"
    ));
}

#[test]
fn field_names_reach_each_part_of_the_event() {
    for (field, value) in [
        ("action", "oauth.consent_grant"),
        ("outcome", "success"),
        ("severity", "informational"),
        ("class", "user_access_management"),
        ("actor.id", "user-dana"),
        ("actor.ip", "203.0.113.50"),
        ("actor.kind", "user"),
        ("actor.user_agent", "python-httpx/0.27.0"),
        ("target.id", "app-sync-helper"),
        ("target.kind", "application"),
        ("source.product", "entra_id"),
        ("attributes.app_id", "app-sync-helper"),
        ("app_id", "app-sync-helper"),
        ("raw.operationName", "Consent to application"),
        ("raw.result.code", "0"),
    ] {
        let hit = format!("selection:\n  {field}: '{value}'\ncondition: selection");
        assert!(matches(&hit), "{field}");
        let miss = format!("selection:\n  {field}: 'not-{value}'\ncondition: selection");
        assert!(!matches(&miss), "{field}");
    }
}

// ----- Conditions -----

const SELECTIONS: &str = "selection_action:\n  action: oauth.consent_grant\nselection_privileged:\n  privileged: true\nselection_failed:\n  outcome: failure\nfilter_office:\n  actor.ip|cidr: 198.51.100.0/24\n";

fn condition_matches(condition: &str) -> bool {
    matches(&format!("{SELECTIONS}condition: {condition}"))
}

#[test]
fn conditions_with_and_or_not_and_parentheses() {
    assert!(condition_matches(
        "selection_action and selection_privileged"
    ));
    assert!(!condition_matches("selection_action and selection_failed"));
    assert!(condition_matches("selection_failed or selection_action"));
    assert!(!condition_matches("selection_failed or filter_office"));
    assert!(condition_matches("selection_action and not filter_office"));
    assert!(!condition_matches(
        "selection_action and not selection_privileged"
    ));
    assert!(condition_matches(
        "(selection_failed or selection_action) and not filter_office"
    ));
    assert!(!condition_matches(
        "selection_failed or (selection_action and filter_office)"
    ));
}

#[test]
fn conditions_with_one_of_and_all_of_a_pattern() {
    assert!(condition_matches("1 of selection*"));
    assert!(!condition_matches("1 of filter*"));
    assert!(!condition_matches("all of selection*"));
    assert!(condition_matches("all of selection_a*"));
    assert!(!condition_matches("all of selection_*d"));
    assert!(!condition_matches("all of selection_a* and filter_office"));
    assert!(condition_matches("2 of selection*"));
    assert!(!condition_matches("3 of selection*"));
    assert!(condition_matches("1 of selection* and not 1 of filter*"));
}

#[test]
fn conditions_with_them() {
    assert!(condition_matches("1 of them"));
    assert!(!condition_matches("all of them"));
    let all = "a:\n  action: oauth.consent_grant\nb:\n  privileged: true\ncondition: all of them";
    assert!(matches(all));
    let none = "a:\n  action: sign_in\nb:\n  privileged: false\ncondition: 1 of them";
    assert!(!matches(none));
}

#[test]
fn a_list_of_conditions_needs_one_condition() {
    assert!(matches(&format!(
        "{SELECTIONS}condition:\n  - selection_failed\n  - selection_action and selection_privileged"
    )));
    assert!(!matches(&format!(
        "{SELECTIONS}condition:\n  - selection_failed\n  - filter_office"
    )));
}

// ----- Rules that are not valid -----

#[test]
fn text_that_is_not_a_rule_is_an_error_with_the_file_and_the_position() {
    let error = SigmaRule::parse("title: [unclosed\n", "rules/broken.yml").unwrap_err();
    let text = error.to_string();
    assert!(text.starts_with("rule rules/broken.yml: line "), "{text}");
    assert_eq!(reason("- a\n- b\n"), "the rule must be a YAML map");
    assert_eq!(reason(""), "the rule must be a YAML map");
    assert!(reason("title: A\n---\ntitle: B\n").contains("multiple YAML documents"));
    assert!(reason("title: A\ntitle: B\n").contains("duplicate mapping key"));
}

#[test]
fn a_rule_needs_a_title_a_detection_a_selection_and_a_condition() {
    let body = "detection:\n  selection:\n    action: sign_in\n  condition: selection\n";
    assert_eq!(reason(body), "the rule has no title");
    assert_eq!(
        reason(&format!("title: '  '\n{body}")),
        "the rule has no title"
    );
    assert_eq!(
        reason(&format!("title: 5\n{body}")),
        "title must be a string"
    );
    assert_eq!(
        reason(&format!("title: T\nid: ''\n{body}")),
        "the id is empty"
    );
    assert_eq!(reason("title: T\n"), "the rule has no detection map");
    assert_eq!(
        reason("title: T\ndetection: selection\n"),
        "the rule has no detection map"
    );
    assert_eq!(
        detection_reason("condition: selection"),
        "the detection has no selection"
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in"),
        "the detection has no condition"
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in\ncondition: 5"),
        "the condition must be a string or a list of strings"
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in\ncondition: []"),
        "the condition must be a string or a list of strings"
    );
}

#[test]
fn a_selection_that_would_match_all_events_is_an_error() {
    assert_eq!(
        detection_reason("selection: {}\ncondition: selection"),
        "the selection \"selection\" has an empty map, which would match all events"
    );
    assert_eq!(
        detection_reason("selection: []\ncondition: selection"),
        "the selection \"selection\" is an empty list"
    );
    assert_eq!(
        detection_reason("selection:\n  - {}\ncondition: selection"),
        "the selection \"selection\" has an empty map, which would match all events"
    );
    assert_eq!(
        detection_reason("selection:\n  action: []\ncondition: selection"),
        "the selection \"selection\": the field \"action\" has an empty list of values"
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in\ncondition: all of other*"),
        "the pattern \"other*\" in the condition matches no selection"
    );
}

#[test]
fn parts_of_sigma_that_the_engine_does_not_support_are_errors() {
    assert_eq!(
        detection_reason("keywords:\n  - mimikatz\n  - rubeus\ncondition: keywords"),
        "the selection \"keywords\" is a list of keywords; use a list of maps"
    );
    assert_eq!(
        detection_reason("selection: sign_in\ncondition: selection"),
        "the selection \"selection\" must be a map or a list of maps"
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in\ntimeframe: 5m\ncondition: selection"),
        "the detection has a timeframe; aggregation is not supported"
    );
    assert!(
        detection_reason("selection:\n  action: sign_in\ncondition: selection | count() > 5")
            .contains("aggregation is not supported")
    );
    let modifier = detection_reason("selection:\n  action|base64: sign_in\ncondition: selection");
    assert_eq!(
        modifier,
        "the selection \"selection\": the field \"action\" has the modifier \"base64\", which is \
         not supported; the modifiers are contains, startswith, endswith, re, cidr, all, gt, gte, \
         lt, lte, exists"
    );
}

#[test]
fn modifiers_that_do_not_fit_are_errors() {
    assert!(
        detection_reason("selection:\n  action|contains|re: a\ncondition: selection")
            .contains("more than one of the modifiers")
    );
    assert!(
        detection_reason("selection:\n  action|all|all: a\ncondition: selection")
            .contains("two times")
    );
    assert!(
        detection_reason("selection:\n  action|exists|all: true\ncondition: selection")
            .contains("exists with a different modifier")
    );
    assert_eq!(
        detection_reason("selection:\n  action|exists: yes please\ncondition: selection"),
        "the selection \"selection\": the field \"action\" with exists needs true or false"
    );
    assert_eq!(
        detection_reason("selection:\n  actor.ip|cidr: office\ncondition: selection"),
        "the selection \"selection\": the field \"actor.ip\": \"office\" is not a network in CIDR form"
    );
    assert!(
        detection_reason("selection:\n  action|re: '(unclosed'\ncondition: selection")
            .starts_with("the selection \"selection\": the field \"action\": the regular expression \"(unclosed\" is not valid")
    );
    assert_eq!(
        detection_reason("selection:\n  risk_score|gt: many\ncondition: selection"),
        "the selection \"selection\": the field \"risk_score\": a comparison modifier needs a number"
    );
    assert_eq!(
        detection_reason("selection:\n  action:\n    nested: map\ncondition: selection"),
        "the selection \"selection\": the field \"action\": a value must be a string, a number, a boolean, or null"
    );
}

#[test]
fn names_that_are_not_valid_are_errors() {
    assert!(
        detection_reason("selection:\n  actor.email: a\ncondition: selection")
            .starts_with("the selection \"selection\": the field \"actor.email\" is not known")
    );
    assert_eq!(
        detection_reason("selection:\n  action: sign_in\ncondition: selection and other"),
        "the condition names the selection \"other\", which the rule does not have"
    );
    for name in ["and", "not", "them", "'a b'", "'a|b'", "'sel*'"] {
        let message =
            detection_reason(&format!("{name}:\n  action: sign_in\ncondition: selection"));
        assert!(
            message.ends_with("is not a valid name for a selection"),
            "{name}: {message}"
        );
    }
}

#[test]
fn metadata_that_is_not_valid_is_an_error() {
    let body = "detection:\n  selection:\n    action: sign_in\n  condition: selection\n";
    assert_eq!(
        reason(&format!("title: T\nlevel: severe\n{body}")),
        "the level \"severe\" is not known; use informational, low, medium, high, or critical"
    );
    assert_eq!(
        reason(&format!("title: T\nstatus: retired\n{body}")),
        "the status \"retired\" is not known; use stable, test, experimental, deprecated, or unsupported"
    );
    assert_eq!(
        reason(&format!("title: T\ntags: attack.t1528\n{body}")),
        "tags must be a list of strings"
    );
    assert_eq!(
        reason(&format!("title: T\ntags:\n  - 5\n{body}")),
        "tags must be a list of strings"
    );
}

// ----- The detector -----

#[tokio::test]
async fn the_detector_returns_one_detection_for_each_rule_that_matches_in_rule_order() {
    let make = |id: &str, action: &str| {
        let text = format!(
            "title: Rule {id}\nid: {id}\nlevel: high\ndetection:\n  selection:\n    action: {action}\n  condition: selection\n"
        );
        SigmaRule::parse(&text, "t.yml").unwrap()
    };
    let detector = SigmaDetector::new(vec![
        make("first", "oauth.consent_grant"),
        make("second", "sign_in"),
        make("third", "oauth.*"),
    ]);
    assert_eq!(detector.id(), "aegis.sigma");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);
    assert_eq!(detector.rules().len(), 3);

    let detections = detector.inspect(&event()).await.unwrap();
    let ids: Vec<&str> = detections
        .iter()
        .map(|found| found.rule_id.as_str())
        .collect();
    assert_eq!(ids, ["first", "third"]);
    assert_ne!(detections[0].id, detections[1].id);

    let mut other = event();
    other.action = action::ROLE_ASSIGN.to_owned();
    assert_eq!(detector.inspect(&other).await.unwrap(), []);
    assert_eq!(
        SigmaDetector::default().inspect(&event()).await.unwrap(),
        []
    );
}

#[test]
fn load_reads_a_rule_file_and_names_the_file_in_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let good = directory.path().join("good.yml");
    std::fs::write(&good, FULL_RULE).unwrap();
    let rule = SigmaRule::load(&good).unwrap();
    assert_eq!(rule.title(), "Consent to privileged scopes");
    assert_eq!(rule.origin(), good.display().to_string());

    let bad = directory.path().join("bad.yml");
    std::fs::write(&bad, "title: T\n").unwrap();
    let error = SigmaRule::load(&bad).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("rule {}: the rule has no detection map", bad.display())
    );

    let absent = SigmaRule::load(&directory.path().join("none.yml")).unwrap_err();
    assert!(matches!(absent, DetectError::Io { .. }), "{absent}");

    let large = directory.path().join("large.yml");
    let size = usize::try_from(MAX_RULE_BYTES).unwrap() + 1;
    std::fs::write(&large, "#".repeat(size)).unwrap();
    let error = SigmaRule::load(&large).unwrap_err();
    assert!(
        matches!(&error, DetectError::Rule { reason, .. } if reason == "the file is larger than the limit of 1048576 bytes"),
        "{error}"
    );
}
