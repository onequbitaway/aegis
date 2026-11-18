//! Tests for the configuration types with a TOML configuration file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use aegis_contracts::Error;
use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::policy::{PolicyEffect, PolicyInput, Principal, PrincipalKind};
use aegis_policy::{
    ApprovalRules, DEFAULT_DECISION_RULE, FAIL_CLOSED_POLICY, FileAuditLog, FileAuditLogConfig,
    Permission, PolicyConfig, Rbac, RbacConfig, RegoPolicyEngine,
};
use serde::Deserialize;

/// The tables that this crate reads from the configuration file.
#[derive(Debug, Deserialize)]
struct Tables {
    policy: PolicyConfig,
    rbac: RbacConfig,
    approval: ApprovalRules,
    audit_file: FileAuditLogConfig,
}

fn policies() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies")
}

fn input(kind: ActionKind, target: EntityRef) -> PolicyInput {
    PolicyInput::new(
        ActionRequest::new(kind, target, "responder", "Test."),
        Principal::new("responder", PrincipalKind::Agent, &["agent"]),
    )
}

fn host() -> EntityRef {
    EntityRef::new(EntityKind::Host, "host-1")
}

fn effect(engine: &RegoPolicyEngine, kind: ActionKind, target: EntityRef) -> PolicyEffect {
    engine.decide(&input(kind, target)).effect
}

/// Reads the `[policy]` table of `text`.
fn policy_table(text: &str) -> Result<PolicyConfig, toml::de::Error> {
    #[derive(Deserialize)]
    struct File {
        policy: PolicyConfig,
    }
    toml::from_str::<File>(text).map(|file| file.policy)
}

fn config_message(result: aegis_contracts::Result<RegoPolicyEngine>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected a configuration error, found {other:?}"),
        Ok(_) => panic!("expected a configuration error, found an engine"),
    }
}

#[tokio::test]
async fn a_configuration_file_builds_each_service() {
    let directory = tempfile::tempdir().unwrap();
    let audit_path = directory.path().join("audit.jsonl");
    let text = format!(
        r#"
[policy]
paths = ['{policies}']

[rbac.roles]
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]

[approval]
four_eyes = false

[audit_file]
path = '{audit}'
"#,
        policies = policies().display(),
        audit = audit_path.display(),
    );
    let tables: Tables = toml::from_str(&text).unwrap();

    // The policy directory holds the default policy. The engine does not read the examples.
    let engine = RegoPolicyEngine::from_config(&tables.policy).unwrap();
    assert_eq!(engine.rule(), DEFAULT_DECISION_RULE);
    assert_eq!(engine.version().policies.len(), 1);
    assert_eq!(
        effect(&engine, ActionKind::Notify, host()),
        PolicyEffect::Allow
    );
    assert_eq!(
        effect(&engine, ActionKind::IsolateHost, host()),
        PolicyEffect::RequireApproval
    );

    let rbac = Rbac::new(tables.rbac);
    let approver = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);
    let analyst = Principal::new("bob@example.com", PrincipalKind::Human, &["analyst"]);
    rbac.check(&approver, Permission::ApproveActions).unwrap();
    rbac.check(&analyst, Permission::ViewAudit).unwrap();
    assert!(matches!(
        rbac.check(&analyst, Permission::ApproveActions),
        Err(Error::Unauthorized(_))
    ));

    assert_eq!(
        tables.approval,
        ApprovalRules {
            four_eyes: false,
            humans_only: true
        }
    );

    let log = FileAuditLog::from_config(&tables.audit_file).unwrap();
    assert_eq!(log.path(), fs::canonicalize(&audit_path).unwrap());
    let record = log
        .append(AuditEntry::new(
            AuditKind::ConfigChange,
            "test",
            "Loaded the configuration.",
        ))
        .await
        .unwrap();
    assert_eq!(record.sequence, 1);
    assert_eq!(fs::read_to_string(&audit_path).unwrap().lines().count(), 1);
}

#[test]
fn the_policy_table_names_files_data_and_the_rule() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("verdict.rego");
    fs::write(
        &policy,
        "package custom\n\nimport rego.v1\n\ndefault verdict := {\"effect\": \"allow\"}\n\nverdict := {\"effect\": \"deny\"} if input.action.target.id in data.blocked\n",
    )
    .unwrap();
    let data = directory.path().join("blocked.json");
    fs::write(&data, r#"{"blocked": ["host-1"]}"#).unwrap();
    let text = format!(
        "[policy]\npaths = ['{}']\ndata = ['{}']\nrule = \"data.custom.verdict\"\n",
        policy.display(),
        data.display()
    );
    let config = policy_table(&text).unwrap();
    assert_eq!(config.paths, std::slice::from_ref(&policy));
    assert_eq!(config.data, std::slice::from_ref(&data));
    assert_eq!(config.evaluation_time_limit_ms, 1000);

    let engine = RegoPolicyEngine::from_config(&config).unwrap();
    assert_eq!(engine.rule(), "data.custom.verdict");
    let version = engine.version();
    assert_eq!(version.policies, [policy.display().to_string()]);
    assert_eq!(version.data, [data.display().to_string()]);
    assert_eq!(
        effect(&engine, ActionKind::Notify, host()),
        PolicyEffect::Deny
    );
    assert_eq!(
        effect(
            &engine,
            ActionKind::Notify,
            EntityRef::new(EntityKind::Host, "host-2")
        ),
        PolicyEffect::Allow
    );
}

#[test]
fn the_time_limit_of_the_policy_table_stops_a_slow_evaluation() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("slow.rego");
    fs::write(
        &policy,
        "package aegis.response\n\nimport rego.v1\n\ndecision := {\"effect\": \"allow\"} if {\n\tcount([1 |\n\t\tsome a in numbers.range(1, 400)\n\t\tsome b in numbers.range(1, 400)\n\t\ta == b\n\t]) == 400\n}\n",
    )
    .unwrap();
    let table = |limit: u64| {
        policy_table(&format!(
            "[policy]\npaths = ['{}']\nevaluation_time_limit_ms = {limit}\n",
            policy.display()
        ))
        .unwrap()
    };

    let generous = RegoPolicyEngine::from_config(&table(600_000)).unwrap();
    let decision = generous.decide(&input(ActionKind::Notify, host()));
    assert_eq!(decision.effect, PolicyEffect::Allow);

    let short = RegoPolicyEngine::from_config(&table(1)).unwrap();
    let decision = short.decide(&input(ActionKind::Notify, host()));
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(FAIL_CLOSED_POLICY));
    assert!(
        decision.reasons[0].contains("time limit"),
        "{:?}",
        decision.reasons
    );

    let message = config_message(RegoPolicyEngine::from_config(&table(0)));
    assert!(message.contains("evaluation_time_limit_ms"), "{message}");
}

#[test]
fn a_policy_table_with_no_usable_path_does_not_load() {
    let no_paths = policy_table("[policy]\npaths = []\n").unwrap();
    let message = config_message(RegoPolicyEngine::from_config(&no_paths));
    assert!(message.contains("no policy file"), "{message}");

    let missing = PolicyConfig::new([Path::new("/no/such/directory/response.rego")]);
    let message = config_message(RegoPolicyEngine::from_config(&missing));
    assert!(
        message.contains("/no/such/directory/response.rego"),
        "{message}"
    );

    let error = policy_table("[policy]\nrule = \"data.x.y\"\n").unwrap_err();
    assert!(
        error.to_string().contains("missing field `paths`"),
        "{error}"
    );
}

#[test]
fn each_table_rejects_a_key_that_it_does_not_know() {
    let error = policy_table("[policy]\npaths = []\npath = 'x.rego'\n").unwrap_err();
    assert!(
        error.to_string().contains("unknown field `path`"),
        "{error}"
    );

    let error = toml::from_str::<RbacConfig>("[role]\nadmin = [\"administer\"]\n").unwrap_err();
    assert!(
        error.to_string().contains("unknown field `role`"),
        "{error}"
    );

    let error = toml::from_str::<RbacConfig>("[roles]\nadmin = [\"everything\"]\n").unwrap_err();
    assert!(
        error.to_string().contains("unknown variant `everything`"),
        "{error}"
    );

    let error = toml::from_str::<ApprovalRules>("four_eye = false\n").unwrap_err();
    assert!(
        error.to_string().contains("unknown field `four_eye`"),
        "{error}"
    );

    let error =
        toml::from_str::<FileAuditLogConfig>("path = 'a.jsonl'\nsync = false\n").unwrap_err();
    assert!(
        error.to_string().contains("unknown field `sync`"),
        "{error}"
    );
}

#[test]
fn an_approval_table_with_no_keys_has_each_rule_on() {
    let rules: ApprovalRules = toml::from_str("").unwrap();
    assert_eq!(
        rules,
        ApprovalRules {
            four_eyes: true,
            humans_only: true
        }
    );
    let rules: ApprovalRules = toml::from_str("humans_only = false\n").unwrap();
    assert_eq!(
        rules,
        ApprovalRules {
            four_eyes: true,
            humans_only: false
        }
    );
}

/// The configuration example of the README file must be a valid configuration.
#[test]
fn the_configuration_example_of_the_readme_file_is_valid() {
    let readme =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    let (_, after_start) = readme
        .split_once("```toml\n")
        .expect("the README file has a TOML example");
    let (example, _) = after_start
        .split_once("```")
        .expect("the TOML example has an end");
    let tables: Tables = toml::from_str(example).unwrap();

    let options = tables.policy.options().unwrap();
    assert_eq!(options, aegis_policy::EngineOptions::default());
    assert_eq!(tables.policy.paths.len(), 1);
    assert_eq!(tables.approval, ApprovalRules::default());
    assert!(tables.audit_file.path.is_absolute());

    let rbac = Rbac::new(tables.rbac);
    let principal = |role: &str| Principal::new("p", PrincipalKind::Human, &[role]);
    assert!(rbac.allows(&principal("approver"), Permission::ApproveActions));
    assert!(rbac.allows(&principal("analyst"), Permission::ViewAudit));
    assert!(rbac.allows(&principal("admin"), Permission::ManagePolicy));
    assert!(!rbac.allows(&principal("admin"), Permission::ApproveActions));
}
