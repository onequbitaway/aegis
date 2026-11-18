//! Tests for the behavior of the policy files in the `policies` directory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::incident::IncidentStatus;
use aegis_contracts::policy::{
    ActionTier, IncidentContext, PolicyDecision, PolicyEffect, PolicyInput, Principal,
    PrincipalKind,
};
use aegis_policy::{FAIL_CLOSED_POLICY, PolicySources, RegoPolicyEngine};
use chrono::{DateTime, Utc};
use serde_json::json;

const RULE_NAME: &str = "aegis.response.decision";

fn policies() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies")
}

fn example(name: &str) -> PathBuf {
    policies().join("examples").join(name)
}

fn load(file: PathBuf) -> RegoPolicyEngine {
    RegoPolicyEngine::load(PolicySources::new().policy_file(file)).unwrap()
}

fn agent() -> Principal {
    Principal::new("responder", PrincipalKind::Agent, &["agent"])
}

fn input(kind: ActionKind, target: EntityRef) -> PolicyInput {
    PolicyInput::new(
        ActionRequest::new(kind, target, "responder", "Test."),
        agent(),
    )
}

fn service_principal() -> EntityRef {
    EntityRef::new(EntityKind::ServicePrincipal, "sp-1")
}

fn incident(severity: Severity) -> Option<IncidentContext> {
    Some(IncidentContext {
        id: IncidentId::new(),
        severity,
        status: IncidentStatus::Investigating,
    })
}

fn all_kinds() -> Vec<ActionKind> {
    vec![
        ActionKind::Enrich,
        ActionKind::Tag,
        ActionKind::Notify,
        ActionKind::SnapshotEvidence,
        ActionKind::OpenTicket,
        ActionKind::RevokeCredential,
        ActionKind::RotateCredential,
        ActionKind::DisableServicePrincipal,
        ActionKind::DisableUser,
        ActionKind::KillSession,
        ActionKind::IsolateHost,
        ActionKind::BlockIp,
        ActionKind::RotateSecret,
        ActionKind::DeployHoneytoken,
        ActionKind::Custom("quarantine_mail".to_owned()),
    ]
}

/// Asserts that the policy made the decision, with the effect and the tier.
fn assert_decision(decision: &PolicyDecision, effect: PolicyEffect, tier: ActionTier, case: &str) {
    assert_eq!(
        decision.policy.as_deref(),
        Some(RULE_NAME),
        "{case}: {decision:?}"
    );
    assert_eq!(
        (decision.effect, decision.tier),
        (effect, tier),
        "{case}: {decision:?}"
    );
    assert_eq!(decision.reasons.len(), 1, "{case}: {decision:?}");
}

/// Asserts that the policy gives the decisions of the default policy for each action kind.
fn assert_default_behavior(
    engine: &RegoPolicyEngine,
    change: impl Fn(&mut PolicyInput),
    case: &str,
) {
    let kinds = all_kinds();
    assert_eq!(kinds.len(), 15);
    for kind in kinds {
        let mut input = input(kind.clone(), service_principal());
        change(&mut input);
        let decision = engine.decide(&input);
        let (effect, tier) = match input.default_tier {
            ActionTier::Auto => (PolicyEffect::Allow, ActionTier::Auto),
            ActionTier::Gated => (PolicyEffect::RequireApproval, ActionTier::Gated),
        };
        assert_decision(&decision, effect, tier, &format!("{case}, {kind:?}"));
    }
}

#[test]
fn the_default_policy_permits_auto_actions_and_gates_the_other_actions() {
    let engine = RegoPolicyEngine::load(PolicySources::new().policy_directory(policies())).unwrap();
    assert_default_behavior(&engine, |_| {}, "default");
    assert_default_behavior(
        &engine,
        |input| {
            input.incident = incident(Severity::Critical);
            input.environment = json!({ "maintenance_window": { "start": "x", "end": "y" } });
            input.principal = Principal::new("alice@example.com", PrincipalKind::Human, &["admin"]);
        },
        "default with data that the policy does not read",
    );
}

#[test]
fn the_default_policy_permits_each_dry_run() {
    let engine = load(policies().join("default.rego"));
    let kinds = all_kinds();
    assert_eq!(kinds.len(), 15);
    for kind in kinds {
        let mut input = input(kind.clone(), service_principal());
        input.action.dry_run = true;
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::Allow,
            input.default_tier,
            &format!("{kind:?}"),
        );
    }
}

#[test]
fn the_default_policy_denies_a_request_that_no_rule_matches() {
    // The contract type cannot hold a tier that the policy does not know. Thus a second
    // policy gives the default policy an input document with such a tier.
    let mut document =
        serde_json::to_value(input(ActionKind::Notify, service_principal())).unwrap();
    document["default_tier"] = json!("unknown");
    let wrapper = format!(
        "package wrapper\n\nimport rego.v1\n\ndecision := result if {{\n\tresult := data.aegis.response.decision with input as {document}\n}}\n"
    );
    let engine = RegoPolicyEngine::load_with(
        PolicySources::new()
            .policy_file(policies().join("default.rego"))
            .policy_text("wrapper.rego", wrapper),
        aegis_policy::EngineOptions::default().with_rule("data.wrapper.decision"),
    )
    .unwrap();
    let decision = engine.decide(&input(ActionKind::Notify, service_principal()));
    assert_eq!(decision.policy.as_deref(), Some("wrapper.decision"));
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.tier, ActionTier::Gated);
    assert_eq!(decision.reasons.len(), 1);
}

/// Loads the default policy with the two sets that its comments tell the operator to
/// change.
fn default_policy_with(always_gated: &str, always_auto: &str) -> RegoPolicyEngine {
    let shipped = std::fs::read_to_string(policies().join("default.rego")).unwrap();
    let mut changed = shipped;
    for (name, value) in [("always_gated", always_gated), ("always_auto", always_auto)] {
        let empty = format!("{name} := set()");
        assert_eq!(
            changed.matches(&empty).count(),
            1,
            "the default policy must have one empty set with the name {name}"
        );
        changed = changed.replace(&empty, &format!("{name} := {value}"));
    }
    RegoPolicyEngine::load(PolicySources::new().policy_text("default.rego", changed)).unwrap()
}

#[test]
fn the_default_policy_gates_the_kinds_that_the_operator_adds_to_always_gated() {
    let engine = default_policy_with(r#"{"open_ticket", "tag"}"#, "set()");
    for kind in [ActionKind::OpenTicket, ActionKind::Tag] {
        let input = input(kind.clone(), service_principal());
        assert_eq!(input.default_tier, ActionTier::Auto, "{kind:?}");
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::RequireApproval,
            ActionTier::Gated,
            &format!("{kind:?}"),
        );

        let mut dry_run = input;
        dry_run.action.dry_run = true;
        let decision = engine.decide(&dry_run);
        assert_decision(
            &decision,
            PolicyEffect::Allow,
            ActionTier::Gated,
            &format!("dry run of {kind:?}"),
        );
    }
    // The other kinds keep their default tier.
    let notify = engine.decide(&input(ActionKind::Notify, service_principal()));
    assert_decision(&notify, PolicyEffect::Allow, ActionTier::Auto, "notify");
    let isolate = engine.decide(&input(ActionKind::IsolateHost, service_principal()));
    assert_decision(
        &isolate,
        PolicyEffect::RequireApproval,
        ActionTier::Gated,
        "isolate_host",
    );
}

#[test]
fn the_default_policy_permits_the_kinds_that_the_operator_adds_to_always_auto() {
    let engine = default_policy_with(
        r#"{"block_ip"}"#,
        r#"{"kill_session", "block_ip", {"custom": "quarantine_mail"}}"#,
    );
    for kind in [
        ActionKind::KillSession,
        ActionKind::Custom("quarantine_mail".to_owned()),
    ] {
        let input = input(kind.clone(), service_principal());
        assert_eq!(input.default_tier, ActionTier::Gated, "{kind:?}");
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::Allow,
            ActionTier::Auto,
            &format!("{kind:?}"),
        );
    }
    // A kind in the two sets needs approval: `always_gated` has priority.
    let block_ip = engine.decide(&input(ActionKind::BlockIp, service_principal()));
    assert_decision(
        &block_ip,
        PolicyEffect::RequireApproval,
        ActionTier::Gated,
        "block_ip",
    );
    // A plugin action with a different name stays in the gated tier.
    let other_custom = engine.decide(&input(
        ActionKind::Custom("wipe_device".to_owned()),
        service_principal(),
    ));
    assert_decision(
        &other_custom,
        PolicyEffect::RequireApproval,
        ActionTier::Gated,
        "a different plugin action",
    );
}

#[test]
fn each_example_policy_loads_alone() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(policies().join("examples"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rego")
        })
        .collect();
    files.sort();
    assert!(
        files.len() >= 2,
        "the examples directory has {} policies",
        files.len()
    );
    for file in files {
        let engine = load(file.clone());
        let mut dry_run = input(
            ActionKind::IsolateHost,
            EntityRef::new(EntityKind::Host, "host-1"),
        );
        dry_run.action.dry_run = true;
        let decision = engine.decide(&dry_run);
        assert_decision(
            &decision,
            PolicyEffect::Allow,
            ActionTier::Gated,
            &file.display().to_string(),
        );
    }
}

#[test]
fn the_containment_example_runs_containment_of_a_service_principal_in_a_critical_incident() {
    let engine = load(example("auto_contain_service_principals.rego"));
    for kind in [
        ActionKind::DisableServicePrincipal,
        ActionKind::RevokeCredential,
        ActionKind::KillSession,
    ] {
        let mut input = input(kind.clone(), service_principal());
        assert_eq!(input.default_tier, ActionTier::Gated);
        input.incident = incident(Severity::Critical);
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::Allow,
            ActionTier::Auto,
            &format!("{kind:?}"),
        );
    }
}

#[test]
fn the_containment_example_gates_all_other_gated_requests() {
    let engine = load(example("auto_contain_service_principals.rego"));
    type Change = Box<dyn Fn(&mut PolicyInput)>;
    let cases: Vec<(&str, Change)> = vec![
        ("no incident", Box::new(|input| input.incident = None)),
        (
            "high severity",
            Box::new(|input| input.incident = incident(Severity::High)),
        ),
        (
            "the target is a user",
            Box::new(|input| input.action.target = EntityRef::new(EntityKind::User, "user-1")),
        ),
        (
            "the action is not a containment action",
            Box::new(|input| input.action.kind = ActionKind::RotateSecret),
        ),
    ];
    assert_eq!(cases.len(), 4);
    for (case, change) in cases {
        let mut input = input(ActionKind::DisableServicePrincipal, service_principal());
        input.incident = incident(Severity::Critical);
        change(&mut input);
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::RequireApproval,
            ActionTier::Gated,
            case,
        );
    }
    assert_default_behavior(&engine, |_| {}, "containment example with no incident");
    assert_default_behavior(
        &engine,
        |input| {
            input.incident = incident(Severity::Critical);
            input.action.target = EntityRef::new(EntityKind::Host, "host-1");
        },
        "containment example with a host target",
    );
}

fn at(time: &str) -> DateTime<Utc> {
    time.parse().unwrap()
}

fn window() -> serde_json::Value {
    json!({ "maintenance_window": { "start": "2026-03-01T22:00:00Z", "end": "2026-03-02T02:00:00Z" } })
}

#[test]
fn the_maintenance_example_denies_each_change_in_the_window() {
    let engine = load(example("maintenance_window.rego"));
    for time in [
        "2026-03-01T22:00:00Z",
        "2026-03-02T00:30:00.250Z",
        "2026-03-02T01:59:59.999999Z",
    ] {
        let kinds = all_kinds();
        assert_eq!(kinds.len(), 15);
        for kind in kinds {
            let mut input = input(kind.clone(), service_principal());
            input.environment = window();
            input.action.requested_at = at(time);
            let decision = engine.decide(&input);
            assert_decision(
                &decision,
                PolicyEffect::Deny,
                input.default_tier,
                &format!("{kind:?} at {time}"),
            );
        }
    }
}

#[test]
fn the_maintenance_example_follows_the_default_policy_out_of_the_window() {
    let engine = load(example("maintenance_window.rego"));
    for time in [
        "2026-03-01T21:59:59.999Z",
        "2026-03-02T02:00:00Z",
        "2026-03-05T00:00:00Z",
    ] {
        assert_default_behavior(
            &engine,
            |input| {
                input.environment = window();
                input.action.requested_at = at(time);
            },
            &format!("maintenance example at {time}"),
        );
    }
    for environment in [json!(null), json!({}), json!({ "region": "eu" })] {
        assert_default_behavior(
            &engine,
            |input| {
                input.environment = environment.clone();
                input.action.requested_at = at("2026-03-02T00:30:00Z");
            },
            &format!("maintenance example with environment {environment}"),
        );
    }
}

#[test]
fn the_maintenance_example_permits_a_dry_run_in_the_window() {
    let engine = load(example("maintenance_window.rego"));
    let mut input = input(
        ActionKind::IsolateHost,
        EntityRef::new(EntityKind::Host, "host-1"),
    );
    input.environment = window();
    input.action.requested_at = at("2026-03-02T00:30:00Z");
    input.action.dry_run = true;
    let decision = engine.decide(&input);
    assert_decision(&decision, PolicyEffect::Allow, ActionTier::Gated, "dry run");
}

#[test]
fn the_maintenance_example_denies_changes_when_the_window_cannot_be_read() {
    let engine = load(example("maintenance_window.rego"));
    for environment in [
        json!({ "maintenance_window": { "start": "tonight", "end": "2026-03-02T02:00:00Z" } }),
        json!({ "maintenance_window": { "start": "2026-03-01T22:00:00Z", "end": 7 } }),
    ] {
        let mut input = input(ActionKind::Notify, service_principal());
        input.environment = environment.clone();
        input.action.requested_at = at("2026-03-02T00:30:00Z");
        let decision = engine.decide(&input);
        assert_eq!(decision.effect, PolicyEffect::Deny, "{environment}");
        assert_eq!(
            decision.policy.as_deref(),
            Some(FAIL_CLOSED_POLICY),
            "{environment}"
        );
    }
}

/// The comments in the files tell the operator to load one complete policy. If two of them
/// are loaded together, a request on which they do not agree gets no valid decision.
#[test]
fn two_complete_policies_together_deny_a_request_on_which_they_do_not_agree() {
    let together = |name: &str| {
        RegoPolicyEngine::load(
            PolicySources::new()
                .policy_file(policies().join("default.rego"))
                .policy_file(example(name)),
        )
        .unwrap()
    };

    // The default policy permits the notification. The example denies it in the window.
    let engine = together("maintenance_window.rego");
    let mut in_window = input(ActionKind::Notify, service_principal());
    in_window.environment = window();
    in_window.action.requested_at = at("2026-03-02T00:30:00Z");
    let decision = engine.decide(&in_window);
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(FAIL_CLOSED_POLICY));
    assert!(
        decision.reasons[0].contains("conflicts"),
        "{:?}",
        decision.reasons
    );

    // The default policy requires approval. The example permits the containment.
    let engine = together("auto_contain_service_principals.rego");
    let mut containment = input(ActionKind::DisableServicePrincipal, service_principal());
    containment.incident = incident(Severity::Critical);
    let decision = engine.decide(&containment);
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(FAIL_CLOSED_POLICY));

    // The two policies agree on this request, so the decision is the decision of each.
    let agreed = engine.decide(&input(ActionKind::IsolateHost, service_principal()));
    assert_decision(
        &agreed,
        PolicyEffect::RequireApproval,
        ActionTier::Gated,
        "a request on which the two policies agree",
    );
}

fn protected_engine() -> RegoPolicyEngine {
    RegoPolicyEngine::load(
        PolicySources::new()
            .policy_file(example("protected_entities.rego"))
            .data_file(example("protected_entities.yaml")),
    )
    .unwrap()
}

fn protected_user() -> EntityRef {
    EntityRef::new(EntityKind::User, "emergency-access@example.com")
}

#[test]
fn the_protection_example_denies_automatic_changes_to_a_protected_entity() {
    let engine = protected_engine();
    let principals = [
        agent(),
        Principal::new("playbooks", PrincipalKind::System, &["incident_commander"]),
        Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]),
    ];
    for principal in principals {
        for kind in [ActionKind::DisableUser, ActionKind::Notify] {
            let mut input = input(kind.clone(), protected_user());
            input.principal = principal.clone();
            let decision = engine.decide(&input);
            assert_decision(
                &decision,
                PolicyEffect::Deny,
                input.default_tier,
                &format!("{kind:?} by {}", principal.id),
            );
        }
    }
    let protected_service_principal = input(
        ActionKind::DisableServicePrincipal,
        EntityRef::new(EntityKind::ServicePrincipal, "sp-backup-operator"),
    );
    assert_eq!(
        engine.decide(&protected_service_principal).effect,
        PolicyEffect::Deny
    );
}

#[test]
fn the_protection_example_lets_an_incident_commander_ask_for_approval() {
    let engine = protected_engine();
    for kind in [ActionKind::DisableUser, ActionKind::Notify] {
        let mut input = input(kind.clone(), protected_user());
        input.principal = Principal::new(
            "bob@example.com",
            PrincipalKind::Human,
            &["analyst", "incident_commander"],
        );
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::RequireApproval,
            ActionTier::Gated,
            &format!("{kind:?}"),
        );
    }
}

#[test]
fn the_protection_example_follows_the_default_policy_for_other_entities() {
    let engine = protected_engine();
    assert_default_behavior(&engine, |_| {}, "protection example, other entity");
    assert_default_behavior(
        &engine,
        // The identifier is in the list, but with a different kind.
        |input| {
            input.action.target = EntityRef::new(EntityKind::Host, "emergency-access@example.com")
        },
        "protection example, same identifier with a different kind",
    );
    let mut dry_run = input(ActionKind::DisableUser, protected_user());
    dry_run.action.dry_run = true;
    let decision = engine.decide(&dry_run);
    assert_decision(
        &decision,
        PolicyEffect::Allow,
        ActionTier::Gated,
        "dry run on a protected entity",
    );
}

#[test]
fn the_protection_example_denies_changes_when_the_list_is_not_loaded() {
    let engine = load(example("protected_entities.rego"));
    let kinds = all_kinds();
    assert_eq!(kinds.len(), 15);
    for kind in kinds {
        let input = input(kind.clone(), service_principal());
        let decision = engine.decide(&input);
        assert_decision(
            &decision,
            PolicyEffect::Deny,
            input.default_tier,
            &format!("{kind:?}"),
        );
    }
}
