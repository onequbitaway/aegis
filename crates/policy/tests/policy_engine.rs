//! Tests for the Rego policy engine through its public interface.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::incident::IncidentStatus;
use aegis_contracts::policy::{
    ActionTier, IncidentContext, PolicyDecision, PolicyEffect, PolicyEngine, PolicyInput,
    Principal, PrincipalKind,
};
use aegis_policy::{
    DEFAULT_DECISION_RULE, DataFormat, EngineOptions, FAIL_CLOSED_POLICY, PolicySources,
    RegoPolicyEngine,
};
use chrono::Utc;
use serde_json::json;

const RULE_NAME: &str = "aegis.response.decision";

fn input(kind: ActionKind) -> PolicyInput {
    PolicyInput::new(
        ActionRequest::new(
            kind,
            EntityRef::new(EntityKind::ServicePrincipal, "sp-1"),
            "responder",
            "Test.",
        ),
        Principal::new("responder", PrincipalKind::Agent, &["agent", "responder"]),
    )
}

fn engine(policy: &str) -> RegoPolicyEngine {
    RegoPolicyEngine::load(PolicySources::new().policy_text("test.rego", policy)).unwrap()
}

fn policy(body: &str) -> String {
    format!("package aegis.response\n\nimport rego.v1\n\n{body}\n")
}

fn config_message(result: aegis_contracts::Result<impl Sized>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected a configuration error, found {other:?}"),
        Ok(_) => panic!("expected a configuration error, found success"),
    }
}

/// Asserts that the engine made the decision because the policy gave no valid decision.
fn assert_fail_closed(decision: &PolicyDecision, fragment: &str, case: &str) {
    assert_eq!(decision.effect, PolicyEffect::Deny, "{case}");
    assert_eq!(decision.tier, ActionTier::Gated, "{case}");
    assert_eq!(
        decision.policy.as_deref(),
        Some(FAIL_CLOSED_POLICY),
        "{case}"
    );
    assert_eq!(decision.reasons.len(), 2, "{case}: {:?}", decision.reasons);
    assert!(
        decision.reasons[0].contains(fragment),
        "{case}: the reason {:?} must show {fragment:?}",
        decision.reasons[0]
    );
}

#[test]
fn the_policy_gives_each_effect_with_its_reasons() {
    let engine = engine(&policy(
        r#"
        default decision := {"effect": "deny", "reasons": ["No rule matches."]}

        decision := {"effect": "allow", "reasons": ["A notification is safe."]} if {
            input.action.kind == "notify"
        }

        decision := {"effect": "require_approval", "reasons": ["A person must agree.", "The action is disruptive."]} if {
            input.action.kind == "disable_user"
        }
        "#,
    ));
    let cases = [
        (
            ActionKind::Notify,
            PolicyEffect::Allow,
            ActionTier::Auto,
            vec!["A notification is safe."],
        ),
        (
            ActionKind::DisableUser,
            PolicyEffect::RequireApproval,
            ActionTier::Gated,
            vec!["A person must agree.", "The action is disruptive."],
        ),
        (
            ActionKind::IsolateHost,
            PolicyEffect::Deny,
            ActionTier::Gated,
            vec!["No rule matches."],
        ),
    ];
    for (kind, effect, tier, reasons) in cases {
        let before = Utc::now();
        let decision = engine.decide(&input(kind.clone()));
        assert_eq!(decision.effect, effect, "{kind:?}");
        assert_eq!(decision.tier, tier, "{kind:?}: the default tier");
        assert_eq!(decision.reasons, reasons, "{kind:?}");
        assert_eq!(decision.policy.as_deref(), Some(RULE_NAME), "{kind:?}");
        assert!(
            before <= decision.evaluated_at && decision.evaluated_at <= Utc::now(),
            "{kind:?}"
        );
    }
}

#[test]
fn the_policy_can_change_the_tier() {
    let engine = engine(&policy(
        r#"
        decision := {"effect": "allow", "tier": "auto"} if input.action.kind == "block_ip"
        decision := {"effect": "require_approval", "tier": "gated"} if input.action.kind == "open_ticket"
        decision := {"effect": "allow"} if input.action.kind == "tag"
        decision := {"effect": "allow", "tier": "gated"} if input.action.kind == "enrich"
        "#,
    ));
    let cases = [
        // (kind, default tier, effect, tier of the decision)
        (
            ActionKind::BlockIp,
            ActionTier::Gated,
            PolicyEffect::Allow,
            ActionTier::Auto,
        ),
        (
            ActionKind::OpenTicket,
            ActionTier::Auto,
            PolicyEffect::RequireApproval,
            ActionTier::Gated,
        ),
        (
            ActionKind::Tag,
            ActionTier::Auto,
            PolicyEffect::Allow,
            ActionTier::Auto,
        ),
        (
            ActionKind::Enrich,
            ActionTier::Auto,
            PolicyEffect::Allow,
            ActionTier::Gated,
        ),
    ];
    for (kind, default_tier, effect, tier) in cases {
        let input = input(kind.clone());
        assert_eq!(input.default_tier, default_tier, "{kind:?}");
        let decision = engine.decide(&input);
        assert_eq!((decision.effect, decision.tier), (effect, tier), "{kind:?}");
        assert_eq!(decision.reasons, Vec::<String>::new(), "{kind:?}");
    }
}

#[test]
fn a_set_of_reasons_becomes_a_sorted_list() {
    let engine = engine(&policy(
        r#"
        decision := {"effect": "deny", "reasons": reasons}
        reasons contains "The target is protected." if input.action.target.id == "sp-1"
        reasons contains "The action is not a dry run." if not input.action.dry_run
        reasons contains "This reason does not apply." if input.action.kind == "tag"
        "#,
    ));
    let decision = engine.decide(&input(ActionKind::DisableServicePrincipal));
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(
        decision.reasons,
        ["The action is not a dry run.", "The target is protected."]
    );
}

#[test]
fn the_decision_follows_each_part_of_the_input() {
    let engine = engine(&policy(
        r#"
        default decision := {"effect": "require_approval", "reasons": ["default"]}

        decision := {"effect": "allow", "reasons": ["dry_run"]} if {
            input.action.dry_run
        } else := {"effect": "deny", "reasons": ["environment"]} if {
            input.environment.change_freeze == true
        } else := {"effect": "allow", "tier": "auto", "reasons": ["severity"]} if {
            input.incident.severity == "critical"
            input.action.kind == "disable_service_principal"
        } else := {"effect": "deny", "reasons": ["roles"]} if {
            input.action.kind == "isolate_host"
            not "responder" in input.principal.roles
        } else := {"effect": "allow", "reasons": ["kind"]} if {
            input.action.kind == "notify"
        }
        "#,
    ));
    let incident = |severity| {
        Some(IncidentContext {
            id: IncidentId::new(),
            severity,
            status: IncidentStatus::Investigating,
        })
    };
    type Change = Box<dyn Fn(&mut PolicyInput)>;
    let cases: Vec<(&str, ActionKind, Change, PolicyEffect, &str)> = vec![
        (
            "no rule matches",
            ActionKind::DisableServicePrincipal,
            Box::new(|_| {}),
            PolicyEffect::RequireApproval,
            "default",
        ),
        (
            "input.action.kind",
            ActionKind::Notify,
            Box::new(|_| {}),
            PolicyEffect::Allow,
            "kind",
        ),
        (
            "input.action.dry_run",
            ActionKind::DisableServicePrincipal,
            Box::new(|input| input.action.dry_run = true),
            PolicyEffect::Allow,
            "dry_run",
        ),
        (
            "input.incident.severity critical",
            ActionKind::DisableServicePrincipal,
            Box::new(move |input| input.incident = incident(Severity::Critical)),
            PolicyEffect::Allow,
            "severity",
        ),
        (
            "input.incident.severity high",
            ActionKind::DisableServicePrincipal,
            Box::new(move |input| input.incident = incident(Severity::High)),
            PolicyEffect::RequireApproval,
            "default",
        ),
        (
            "input.principal.roles with the role",
            ActionKind::IsolateHost,
            Box::new(|_| {}),
            PolicyEffect::RequireApproval,
            "default",
        ),
        (
            "input.principal.roles without the role",
            ActionKind::IsolateHost,
            Box::new(|input| input.principal.roles = vec!["agent".to_owned()]),
            PolicyEffect::Deny,
            "roles",
        ),
        (
            "input.environment freeze",
            ActionKind::Notify,
            Box::new(|input| input.environment = json!({ "change_freeze": true })),
            PolicyEffect::Deny,
            "environment",
        ),
        (
            "input.environment no freeze",
            ActionKind::Notify,
            Box::new(|input| input.environment = json!({ "change_freeze": false })),
            PolicyEffect::Allow,
            "kind",
        ),
    ];
    assert_eq!(cases.len(), 9);
    for (name, kind, change, effect, reason) in cases {
        let mut input = input(kind);
        change(&mut input);
        let decision = engine.decide(&input);
        assert_eq!(decision.effect, effect, "{name}");
        assert_eq!(decision.reasons, [reason], "{name}");
        assert_eq!(decision.policy.as_deref(), Some(RULE_NAME), "{name}");
    }
}

#[test]
fn a_result_that_is_not_a_valid_decision_denies_the_action() {
    let cases = [
        (
            "undefined result",
            r#"decision := {"effect": "allow"} if input.action.kind == "tag""#,
            DEFAULT_DECISION_RULE,
        ),
        ("result is a string", r#"decision := "allow""#, "a string"),
        ("result is a boolean", "decision := true", "a boolean"),
        (
            "no effect",
            r#"decision := {"tier": "auto", "reasons": ["Allowed."]}"#,
            "`effect`",
        ),
        (
            "unknown effect",
            r#"decision := {"effect": "permit"}"#,
            "`permit`",
        ),
        (
            "effect in the wrong letter case",
            r#"decision := {"effect": "ALLOW"}"#,
            "`ALLOW`",
        ),
        (
            "effect is not a string",
            r#"decision := {"effect": true}"#,
            "a boolean",
        ),
        (
            "unknown tier",
            r#"decision := {"effect": "allow", "tier": "automatic"}"#,
            "`automatic`",
        ),
        (
            "reasons is a string",
            r#"decision := {"effect": "allow", "reasons": "Allowed."}"#,
            "`reasons`",
        ),
        (
            "a reason is a number",
            r#"decision := {"effect": "allow", "reasons": ["Allowed.", 7]}"#,
            "`reasons`",
        ),
        (
            "unknown field",
            r#"decision := {"effect": "allow", "teir": "gated"}"#,
            "`teir`",
        ),
    ];
    assert_eq!(cases.len(), 11);
    for (case, body, fragment) in cases {
        let decision = engine(&policy(body)).decide(&input(ActionKind::Notify));
        assert_fail_closed(&decision, fragment, case);
    }
}

#[test]
fn an_evaluation_error_denies_the_action_and_names_the_location() {
    let cases = [
        (
            "division by zero",
            r#"decision := {"effect": "allow"} if 10 / count(input.action.evidence) > 1"#,
        ),
        (
            "two values for one rule",
            "decision := {\"effect\": \"allow\"} if true\n\ndecision := {\"effect\": \"deny\"} if true",
        ),
        (
            "built-in function error",
            r#"decision := {"effect": "allow"} if to_number(input.action.target.id) > 1"#,
        ),
        (
            "function that does not exist",
            r#"decision := {"effect": "allow"} if no_such_function(input.action.kind)"#,
        ),
    ];
    for (case, body) in cases {
        let decision = engine(&policy(body)).decide(&input(ActionKind::Notify));
        assert_fail_closed(&decision, DEFAULT_DECISION_RULE, case);
        assert!(
            decision.reasons[0].contains("test.rego:"),
            "{case}: the reason {:?} must give the file and the line",
            decision.reasons[0]
        );
    }
}

#[test]
fn a_policy_can_use_the_documented_built_in_functions() {
    // (function, rule body, target that matches, target that does not match)
    let cases = [
        (
            "regex.match",
            r#"decision := {"effect": "allow"} if regex.match("^sp-[0-9]+$", input.action.target.id)"#,
            "sp-42",
            "user-42",
        ),
        (
            "glob.match",
            r#"decision := {"effect": "allow"} if glob.match("*.example.com", ["."], input.action.target.id)"#,
            "host.example.com",
            "host.example.org",
        ),
        (
            "net.cidr_contains",
            r#"decision := {"effect": "allow"} if net.cidr_contains("10.0.0.0/8", input.action.target.id)"#,
            "10.20.30.40",
            "192.0.2.1",
        ),
        (
            "time.parse_rfc3339_ns",
            r#"decision := {"effect": "allow"} if time.parse_rfc3339_ns(input.action.target.id) < time.parse_rfc3339_ns(input.action.requested_at)"#,
            "2001-01-01T00:00:00Z",
            "2200-01-01T00:00:00Z",
        ),
    ];
    for (function, body, matching, other) in cases {
        let engine = engine(&policy(body));
        let mut request = input(ActionKind::Notify);
        request.action.target.id = matching.to_owned();
        let decision = engine.decide(&request);
        assert_eq!(decision.effect, PolicyEffect::Allow, "{function}");
        assert_eq!(decision.policy.as_deref(), Some(RULE_NAME), "{function}");

        request.action.target.id = other.to_owned();
        let decision = engine.decide(&request);
        assert_fail_closed(&decision, "gave no result", function);
    }
}

/// The engine has no function that opens a network connection or reads the environment of
/// the process. A policy that calls such a function gives no decision.
#[test]
fn a_policy_cannot_use_the_network_or_the_process_environment() {
    let cases = [
        (
            "http.send",
            r#"decision := {"effect": "allow"} if http.send({"method": "get", "url": "http://127.0.0.1:9/"}).status_code == 200"#,
        ),
        (
            "opa.runtime",
            r#"decision := {"effect": "allow"} if opa.runtime().env.HOME != """#,
        ),
        (
            "net.lookup_ip_addr",
            r#"decision := {"effect": "allow"} if count(net.lookup_ip_addr("localhost")) > 0"#,
        ),
    ];
    for (function, body) in cases {
        let decision = engine(&policy(body)).decide(&input(ActionKind::Notify));
        assert_fail_closed(&decision, DEFAULT_DECISION_RULE, function);
        assert!(
            decision.reasons[0].contains(function),
            "{function}: {:?}",
            decision.reasons[0]
        );
    }
}

/// With lenient built-in errors, the `deny` rule below would not match and the default
/// would permit the action.
#[test]
fn an_error_in_a_deny_rule_does_not_let_the_default_permit_the_action() {
    let engine = engine(&policy(
        r#"
        default decision := {"effect": "allow", "reasons": ["The risk is low."]}

        decision := {"effect": "deny", "reasons": ["The risk is high."]} if {
            to_number(input.environment.risk) > 5
        }
        "#,
    ));
    let mut low = input(ActionKind::Notify);
    low.environment = json!({ "risk": "2" });
    assert_eq!(engine.decide(&low).effect, PolicyEffect::Allow);

    let mut high = input(ActionKind::Notify);
    high.environment = json!({ "risk": "9" });
    let decision = engine.decide(&high);
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(RULE_NAME));

    let mut unreadable = input(ActionKind::Notify);
    unreadable.environment = json!({ "risk": "very high" });
    let decision = engine.decide(&unreadable);
    assert_fail_closed(&decision, DEFAULT_DECISION_RULE, "risk is not a number");
}

#[test]
fn an_evaluation_that_exceeds_the_time_limit_denies_the_action() {
    let slow = policy(
        r#"
        decision := {"effect": "allow"} if {
            count([1 |
                some a in numbers.range(1, 400)
                some b in numbers.range(1, 400)
                a == b
            ]) == 400
        }
        "#,
    );
    let sources = PolicySources::new().policy_text("slow.rego", slow);

    let no_limit = RegoPolicyEngine::load_with(
        sources.clone(),
        EngineOptions::default().with_evaluation_time_limit(None),
    )
    .unwrap();
    assert_eq!(
        no_limit.decide(&input(ActionKind::Notify)).effect,
        PolicyEffect::Allow,
        "the policy permits the action when it has the time to complete"
    );

    let limited = RegoPolicyEngine::load_with(
        sources,
        EngineOptions::default().with_evaluation_time_limit(Some(Duration::from_micros(200))),
    )
    .unwrap();
    let decision = limited.decide(&input(ActionKind::Notify));
    assert_fail_closed(&decision, "time limit", "time limit");
}

#[test]
fn a_file_that_does_not_compile_is_an_error_that_names_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let good = directory.path().join("good.rego");
    let broken = directory.path().join("broken.rego");
    fs::write(&good, policy(r#"decision := {"effect": "allow"}"#)).unwrap();
    fs::write(
        &broken,
        "package aegis.extra\n\nimport rego.v1\n\nhelper if {\n",
    )
    .unwrap();

    let message = config_message(RegoPolicyEngine::load(
        PolicySources::new().policy_file(&good).policy_file(&broken),
    ));
    assert!(message.contains("broken.rego"), "{message}");
    assert!(!message.contains("good.rego"), "{message}");

    let message = config_message(RegoPolicyEngine::load(
        PolicySources::new().policy_directory(directory.path()),
    ));
    assert!(message.contains("broken.rego"), "{message}");
}

#[test]
fn an_error_that_only_the_analysis_finds_names_the_file() {
    let sources = PolicySources::new()
        .policy_text("good.rego", policy(r#"decision := {"effect": "allow"}"#))
        .policy_text(
            "unsafe_variable.rego",
            "package aegis.extra\n\nimport rego.v1\n\nhelper if never_assigned > 1\n",
        );
    let message = config_message(RegoPolicyEngine::load(sources));
    assert!(message.contains("unsafe_variable.rego:5"), "{message}");
}

#[test]
fn a_policy_without_the_decision_rule_does_not_load() {
    let other_package = "package other\n\nimport rego.v1\n\ndecision := {\"effect\": \"allow\"}\n";
    let sources = PolicySources::new().policy_text("other.rego", other_package);
    let message = config_message(RegoPolicyEngine::load(sources.clone()));
    assert!(message.contains(DEFAULT_DECISION_RULE), "{message}");

    let custom = RegoPolicyEngine::load_with(
        sources.clone(),
        EngineOptions::default().with_rule("data.other.decision"),
    )
    .unwrap();
    assert_eq!(custom.rule(), "data.other.decision");
    let decision = custom.decide(&input(ActionKind::IsolateHost));
    assert_eq!(decision.effect, PolicyEffect::Allow);
    assert_eq!(decision.policy.as_deref(), Some("other.decision"));

    let message = config_message(RegoPolicyEngine::load_with(
        sources,
        EngineOptions::default().with_rule("other.decision"),
    ));
    assert!(message.contains("other.decision"), "{message}");
}

#[test]
fn sources_that_cannot_give_a_policy_do_not_load() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.rego");
    let message = config_message(RegoPolicyEngine::load(
        PolicySources::new().policy_file(&missing),
    ));
    assert!(message.contains("missing.rego"), "{message}");

    fs::write(directory.path().join("notes.txt"), "Not a policy.").unwrap();
    let message = config_message(RegoPolicyEngine::load(
        PolicySources::new().policy_directory(directory.path()),
    ));
    assert!(
        message.contains(&directory.path().display().to_string()),
        "{message}"
    );

    let message = config_message(RegoPolicyEngine::load(PolicySources::new()));
    assert!(message.contains("no policy file"), "{message}");
    let message = config_message(RegoPolicyEngine::load(PolicySources::new().data_text(
        "only-data.json",
        DataFormat::Json,
        "{}",
    )));
    assert!(message.contains("no policy file"), "{message}");
}

#[test]
fn a_directory_gives_its_rego_files_only() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("b_decision.rego"),
        policy(r#"decision := {"effect": "deny", "reasons": [data.aegis.helpers.reason]}"#),
    )
    .unwrap();
    fs::write(
        directory.path().join("a_helpers.rego"),
        "package aegis.helpers\n\nimport rego.v1\n\nreason := \"From the helper file.\"\n",
    )
    .unwrap();
    fs::write(directory.path().join("readme.md"), "package is not rego {").unwrap();
    let nested = directory.path().join("examples");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("broken.rego"), "package aegis.response {{{").unwrap();

    let engine =
        RegoPolicyEngine::load(PolicySources::new().policy_directory(directory.path())).unwrap();
    let names: Vec<String> = engine
        .version()
        .policies
        .iter()
        .map(|path| {
            std::path::Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["a_helpers.rego", "b_decision.rego"]);
    let decision = engine.decide(&input(ActionKind::Notify));
    assert_eq!(decision.reasons, ["From the helper file."]);
}

#[test]
fn the_policy_reads_json_and_yaml_data() {
    let directory = tempfile::tempdir().unwrap();
    let yaml = directory.path().join("limits.yaml");
    fs::write(
        &yaml,
        "aegis:\n  limits:\n    approval_kinds:\n      - block_ip\n",
    )
    .unwrap();
    let sources = PolicySources::new()
        .policy_text(
            "data.rego",
            policy(
                r#"
                default decision := {"effect": "allow"}

                decision := {"effect": "deny", "reasons": ["The target is protected."]} if {
                    input.action.target.id in data.aegis.protected
                } else := {"effect": "require_approval"} if {
                    input.action.kind in data.aegis.limits.approval_kinds
                }
                "#,
            ),
        )
        .data_text(
            "protected.json",
            DataFormat::Json,
            r#"{"aegis": {"protected": ["sp-1"]}}"#,
        )
        .data_file(&yaml);
    let engine = RegoPolicyEngine::load(sources).unwrap();
    assert_eq!(engine.version().data.len(), 2);

    let protected = engine.decide(&input(ActionKind::BlockIp));
    assert_eq!(protected.effect, PolicyEffect::Deny);
    assert_eq!(protected.reasons, ["The target is protected."]);

    let mut other_target = input(ActionKind::BlockIp);
    other_target.action.target.id = "sp-2".to_owned();
    assert_eq!(
        engine.decide(&other_target).effect,
        PolicyEffect::RequireApproval
    );
    other_target.action.kind = ActionKind::Notify;
    assert_eq!(engine.decide(&other_target).effect, PolicyEffect::Allow);

    fs::write(
        &yaml,
        "aegis:\n  limits:\n    approval_kinds:\n      - notify\n",
    )
    .unwrap();
    engine.reload().unwrap();
    assert_eq!(
        engine.decide(&other_target).effect,
        PolicyEffect::RequireApproval,
        "a reload reads the data file again"
    );
}

#[test]
fn a_data_document_that_is_not_valid_does_not_load() {
    let base =
        || PolicySources::new().policy_text("p.rego", policy(r#"decision := {"effect": "allow"}"#));
    let cases = [
        (
            "syntax.json",
            base().data_text("syntax.json", DataFormat::Json, r#"{"a": "#),
        ),
        (
            "list.json",
            base().data_text("list.json", DataFormat::Json, "[1, 2]"),
        ),
        (
            "syntax.yaml",
            base().data_text("syntax.yaml", DataFormat::Yaml, "a: [1, 2\nb: {"),
        ),
        (
            "scalar.yaml",
            base().data_text("scalar.yaml", DataFormat::Yaml, "just text"),
        ),
        (
            "second.json",
            base()
                .data_text("first.json", DataFormat::Json, r#"{"limit": 1}"#)
                .data_text("second.json", DataFormat::Json, r#"{"limit": 2}"#),
        ),
        ("data.toml", base().data_file("data.toml")),
        ("missing.json", base().data_file("missing.json")),
    ];
    assert_eq!(cases.len(), 7);
    for (name, sources) in cases {
        let message = config_message(RegoPolicyEngine::load(sources));
        assert!(message.contains(name), "{name}: {message}");
    }
}

#[test]
fn reload_puts_a_changed_file_in_use() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("response.rego");
    fs::write(
        &file,
        policy(r#"decision := {"effect": "allow", "reasons": ["first"]}"#),
    )
    .unwrap();
    let engine = RegoPolicyEngine::load(PolicySources::new().policy_file(&file)).unwrap();
    let first = engine.version();
    assert_eq!(engine.decide(&input(ActionKind::Notify)).reasons, ["first"]);

    fs::write(
        &file,
        policy(r#"decision := {"effect": "deny", "reasons": ["second"]}"#),
    )
    .unwrap();
    assert_eq!(
        engine.decide(&input(ActionKind::Notify)).reasons,
        ["first"],
        "a changed file has no effect before the reload"
    );
    let second = engine.reload().unwrap();
    assert_ne!(second.digest, first.digest);
    assert_eq!(second, engine.version());
    let decision = engine.decide(&input(ActionKind::Notify));
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.reasons, ["second"]);
}

#[test]
fn a_reload_of_a_broken_policy_keeps_the_old_policy() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("response.rego");
    let good = policy(r#"decision := {"effect": "require_approval", "reasons": ["good"]}"#);
    fs::write(&file, &good).unwrap();
    let engine = RegoPolicyEngine::load(PolicySources::new().policy_file(&file)).unwrap();
    let loaded = engine.version();

    // (text of the broken policy, what the error must name)
    let broken_texts = [
        // The parser rejects this text.
        (
            "package aegis.response\n\ndecision := {\"effect\": \"allow\"".to_owned(),
            "response.rego",
        ),
        // The analysis rejects this text.
        (
            policy(r#"decision := {"effect": "allow"} if never_assigned > 1"#),
            "response.rego",
        ),
        // This text compiles, but it does not have the decision rule.
        (
            "package aegis.response\n\nimport rego.v1\n\nother := 1\n".to_owned(),
            DEFAULT_DECISION_RULE,
        ),
    ];
    for (broken, named) in broken_texts {
        fs::write(&file, &broken).unwrap();
        let message = config_message(engine.reload());
        assert!(message.contains(named), "{message}");
        assert_eq!(engine.version(), loaded, "the version must not change");
        let decision = engine.decide(&input(ActionKind::Notify));
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        assert_eq!(decision.reasons, ["good"]);
        assert_eq!(decision.policy.as_deref(), Some(RULE_NAME));
    }

    fs::write(
        &file,
        policy(r#"decision := {"effect": "allow", "reasons": ["fixed"]}"#),
    )
    .unwrap();
    engine.reload().unwrap();
    assert_eq!(engine.decide(&input(ActionKind::Notify)).reasons, ["fixed"]);
}

#[test]
fn replace_puts_new_sources_in_use_and_rejects_broken_sources() {
    let engine = engine(&policy(
        r#"decision := {"effect": "allow", "reasons": ["first"]}"#,
    ));

    let message = config_message(engine.replace(
        PolicySources::new().policy_text("broken.rego", "package aegis.response\n\ndecision := {"),
    ));
    assert!(message.contains("broken.rego"), "{message}");
    assert_eq!(engine.decide(&input(ActionKind::Notify)).reasons, ["first"]);

    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("second.rego");
    fs::write(
        &file,
        policy(r#"decision := {"effect": "deny", "reasons": ["second"]}"#),
    )
    .unwrap();
    let version = engine
        .replace(PolicySources::new().policy_file(&file))
        .unwrap();
    assert_eq!(version.policies, [file.display().to_string()]);
    assert_eq!(
        engine.decide(&input(ActionKind::Notify)).reasons,
        ["second"]
    );

    fs::write(
        &file,
        policy(r#"decision := {"effect": "deny", "reasons": ["third"]}"#),
    )
    .unwrap();
    engine.reload().unwrap();
    assert_eq!(
        engine.decide(&input(ActionKind::Notify)).reasons,
        ["third"],
        "a reload reads the sources of the last replace"
    );
}

#[test]
fn the_digest_identifies_the_policy_text_and_the_data() {
    let text = policy(r#"decision := {"effect": "allow"}"#);
    let load = |sources: PolicySources| RegoPolicyEngine::load(sources).unwrap().version();
    let first = load(PolicySources::new().policy_text("a.rego", text.clone()));
    let same_text = load(PolicySources::new().policy_text("b.rego", text.clone()));
    let other_text =
        load(PolicySources::new().policy_text("a.rego", format!("{text}\n# Changed.\n")));
    let with_data = load(PolicySources::new().policy_text("a.rego", text).data_text(
        "d.json",
        DataFormat::Json,
        r#"{"x": 1}"#,
    ));
    assert_eq!(first.digest.len(), 64);
    assert_eq!(first.digest, same_text.digest);
    assert_ne!(first.digest, other_text.digest);
    assert_ne!(first.digest, with_data.digest);
    assert_eq!(first.rule, DEFAULT_DECISION_RULE);
    assert_eq!(first.policies, ["a.rego"]);
    assert_eq!(with_data.data, ["d.json"]);
}

#[tokio::test]
async fn the_engine_works_as_a_policy_engine_trait_object() {
    let engine: Arc<dyn PolicyEngine> = Arc::new(engine(&policy(
        r#"decision := {"effect": "require_approval", "reasons": ["A person must agree."]}"#,
    )));
    let decision = engine
        .evaluate(&input(ActionKind::RotateSecret))
        .await
        .unwrap();
    assert_eq!(decision.effect, PolicyEffect::RequireApproval);
    assert_eq!(decision.tier, ActionTier::Gated);
    assert_eq!(decision.reasons, ["A person must agree."]);
}

/// A log subscriber that keeps the level and the fields of each event.
#[derive(Clone, Default)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<String>>>);

struct EventText(String);

impl tracing::field::Visit for EventText {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for CapturedLog {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut text = EventText(event.metadata().level().to_string());
        event.record(&mut text);
        self.0.lock().unwrap().push(text.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[test]
fn a_print_call_in_a_policy_goes_to_the_log_at_the_debug_level() {
    let log = CapturedLog::default();
    let request = input(ActionKind::Notify);
    let decision = tracing::subscriber::with_default(log.clone(), || {
        let engine = RegoPolicyEngine::load(PolicySources::new().policy_text(
            "print.rego",
            "package aegis.response\n\nimport rego.v1\n\ndecision := {\"effect\": \"deny\"} if print(\"The kind is\", input.action.kind)\n",
        ))
        .unwrap();
        engine.decide(&request)
    });
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(RULE_NAME));

    let events = log.0.lock().unwrap().clone();
    let prints: Vec<&String> = events
        .iter()
        .filter(|event| event.contains("the policy printed a message"))
        .collect();
    assert_eq!(prints.len(), 1, "{events:?}");
    assert!(prints[0].starts_with("DEBUG "), "{}", prints[0]);
    assert!(
        prints[0].contains("output=print.rego:5: The kind is notify"),
        "{}",
        prints[0]
    );
    assert!(
        prints[0].contains(&format!("action={}", request.action.id)),
        "{}",
        prints[0]
    );
}

/// The contract function gives a decision, not an error, when the policy gives no valid
/// decision.
#[tokio::test]
async fn the_contract_function_gives_a_deny_decision_when_the_policy_gives_none() {
    let cases = [
        (
            "undefined result",
            r#"decision := {"effect": "allow"} if input.action.kind == "tag""#,
        ),
        ("unknown effect", r#"decision := {"effect": "permit"}"#),
        (
            "evaluation error",
            r#"decision := {"effect": "allow"} if to_number(input.action.target.id) > 1"#,
        ),
    ];
    for (case, body) in cases {
        let engine: Arc<dyn PolicyEngine> = Arc::new(engine(&policy(body)));
        let decision = engine.evaluate(&input(ActionKind::Notify)).await.unwrap();
        assert_eq!(decision.effect, PolicyEffect::Deny, "{case}");
        assert_eq!(
            decision.policy.as_deref(),
            Some(FAIL_CLOSED_POLICY),
            "{case}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluations_from_many_tasks_see_one_complete_policy_during_reloads() {
    const TASKS: usize = 8;
    const EVALUATIONS: usize = 150;
    let allow = policy(r#"decision := {"effect": "allow", "reasons": ["first"]}"#);
    let deny = policy(r#"decision := {"effect": "deny", "reasons": ["second"]}"#);
    let engine = Arc::new(engine(&allow));

    let mut workers = Vec::new();
    for _ in 0..TASKS {
        let engine = Arc::clone(&engine);
        workers.push(tokio::spawn(async move {
            let mut seen = Vec::with_capacity(EVALUATIONS);
            for _ in 0..EVALUATIONS {
                let decision = engine.evaluate(&input(ActionKind::Notify)).await.unwrap();
                seen.push((decision.effect, decision.reasons, decision.policy));
                tokio::task::yield_now().await;
            }
            seen
        }));
    }
    for round in 0..40 {
        let text = if round % 2 == 0 { &deny } else { &allow };
        engine
            .replace(PolicySources::new().policy_text("test.rego", text.clone()))
            .unwrap();
        tokio::task::yield_now().await;
    }
    engine
        .replace(PolicySources::new().policy_text("test.rego", deny))
        .unwrap();

    let first = (
        PolicyEffect::Allow,
        vec!["first".to_owned()],
        Some(RULE_NAME.to_owned()),
    );
    let second = (
        PolicyEffect::Deny,
        vec!["second".to_owned()],
        Some(RULE_NAME.to_owned()),
    );
    let mut total = 0;
    for worker in workers {
        let seen = tokio::time::timeout(Duration::from_secs(60), worker)
            .await
            .unwrap()
            .unwrap();
        for decision in seen {
            assert!(
                decision == first || decision == second,
                "a decision must come from one complete policy: {decision:?}"
            );
            total += 1;
        }
    }
    assert_eq!(total, TASKS * EVALUATIONS);
    let last = engine.evaluate(&input(ActionKind::Notify)).await.unwrap();
    assert_eq!(last.effect, PolicyEffect::Deny);
}
