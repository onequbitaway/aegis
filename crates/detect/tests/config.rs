//! Tests of the engine settings as an operator writes them: a TOML table.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_contracts::common::{EntityKind, Severity};
use aegis_detect::engine::{BusRunnerConfig, DetectionEngine, EngineConfig};
use aegis_detect::pack::RulePack;

/// Returns the text of the first TOML block of the README of the crate.
fn readme_example() -> &'static str {
    let readme = include_str!("../README.md");
    let marker = "```toml\n";
    let start = readme.find(marker).expect("the README has a TOML block") + marker.len();
    let length = readme[start..]
        .find("```")
        .expect("the TOML block has an end");
    &readme[start..start + length]
}

#[test]
fn the_configuration_example_of_the_readme_is_the_default_configuration() {
    let config: EngineConfig = toml::from_str(readme_example()).unwrap();
    assert_eq!(config, EngineConfig::default());
    // The engine accepts the documented settings.
    assert!(DetectionEngine::new(config, RulePack::empty()).is_ok());
}

#[test]
fn a_toml_table_changes_the_keys_that_it_names_and_keeps_the_other_defaults() {
    let text = r#"
[velocity.sign_in_burst]
distinct_user_threshold = 25

[velocity.privileged_self_assignment]
severity = "critical"

[velocity.impossible_speed]
max_speed_kmh = 900

[correlator]
window_seconds = 600
unlinked_kinds = ["tenant", "role", "application"]

[triage]
model = "fast-model"
benign_min_confidence = 0.95
"#;
    let config: EngineConfig = toml::from_str(text).unwrap();
    let defaults = EngineConfig::default();
    assert_eq!(config.velocity.sign_in_burst.distinct_user_threshold, 25);
    assert_eq!(config.velocity.sign_in_burst.failure_threshold, 20);
    assert_eq!(
        config.velocity.privileged_self_assignment.severity,
        Severity::Critical
    );
    assert!((config.velocity.impossible_speed.max_speed_kmh - 900.0).abs() < f64::EPSILON);
    assert_eq!(
        config.velocity.credential_after_grant,
        defaults.velocity.credential_after_grant
    );
    assert_eq!(config.correlator.window_seconds, 600);
    assert_eq!(
        config.correlator.unlinked_kinds,
        [
            EntityKind::Tenant,
            EntityKind::Role,
            EntityKind::Application
        ]
    );
    assert_eq!(config.correlator.max_incidents, 10_000);
    assert_eq!(config.triage.model.as_deref(), Some("fast-model"));
    assert!((config.triage.benign_min_confidence - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.triage.timeout_seconds, 60);

    let empty: EngineConfig = toml::from_str("").unwrap();
    assert_eq!(empty, defaults);
}

#[test]
fn the_readme_example_names_each_key_of_the_new_detectors_and_of_the_quota() {
    // The example is the default configuration. This test also needs each new key to be
    // in the text, so that the README shows the operator all the settings.
    let example = readme_example();
    for key in [
        "[velocity.machine_cadence]",
        "min_actions = ",
        "max_median_gap_milliseconds = ",
        "max_coefficient_of_variation = ",
        "sensitive_actions = ",
        "supporting_actions = ",
        "follow_addresses = ",
        "ignored_principals = ",
        "max_tracked_keys = ",
        "[velocity.endpoint_probe]",
        "distinct_path_threshold = ",
        "missing_statuses = ",
        "decoy_paths = ",
        "decoy_path_severity = ",
        "max_tracked_clients = ",
        "quota_window_seconds = ",
        "max_requests_per_source = ",
        "max_requests_per_tenant = ",
    ] {
        assert!(example.contains(key), "the README example has no {key:?}");
    }
}

#[test]
fn a_toml_table_changes_the_new_detectors_and_the_quota() {
    let text = r#"
[velocity.machine_cadence]
min_actions = 6
max_median_gap_milliseconds = 2000
max_coefficient_of_variation = 0.05
supporting_actions = []
follow_addresses = false
ignored_principals = ["sp-provisioning"]

[velocity.endpoint_probe]
window_seconds = 30
distinct_path_threshold = 40
missing_statuses = [404]
decoy_paths = ["/.env", "/admin/backup/*"]
decoy_path_severity = "high"

[triage]
quota_window_seconds = 600
max_requests_per_source = 10
max_requests_per_tenant = 30
"#;
    let config: EngineConfig = toml::from_str(text).unwrap();
    let defaults = EngineConfig::default();
    let cadence = &config.velocity.machine_cadence;
    assert_eq!(cadence.min_actions, 6);
    assert_eq!(cadence.max_median_gap_milliseconds, 2_000);
    assert!((cadence.max_coefficient_of_variation - 0.05).abs() < f64::EPSILON);
    assert_eq!(cadence.supporting_actions, Vec::<String>::new());
    assert!(!cadence.follow_addresses);
    assert_eq!(cadence.ignored_principals, ["sp-provisioning"]);
    // The keys that the table does not name keep their defaults.
    assert_eq!(cadence.window_seconds, 300);
    assert_eq!(
        cadence.sensitive_actions,
        defaults.velocity.machine_cadence.sensitive_actions
    );
    assert_eq!(cadence.sensitive_actions.len(), 15);
    assert_eq!(
        defaults.velocity.machine_cadence.supporting_actions,
        ["sign_in", "api.call"]
    );

    let probe = &config.velocity.endpoint_probe;
    assert_eq!(probe.window_seconds, 30);
    assert_eq!(probe.distinct_path_threshold, 40);
    assert_eq!(probe.missing_statuses, [404]);
    assert_eq!(probe.decoy_paths, ["/.env", "/admin/backup/*"]);
    assert_eq!(probe.decoy_path_severity, Severity::High);
    assert_eq!(probe.cooldown_seconds, 900);
    assert_eq!(
        defaults.velocity.endpoint_probe.missing_statuses,
        [404, 410]
    );
    assert_eq!(
        defaults.velocity.endpoint_probe.decoy_paths,
        Vec::<String>::new()
    );

    assert_eq!(config.triage.quota_window_seconds, 600);
    assert_eq!(config.triage.max_requests_per_source, 10);
    assert_eq!(config.triage.max_requests_per_tenant, 30);
    assert_eq!(defaults.triage.quota_window_seconds, 3_600);
    assert_eq!(defaults.triage.max_requests_per_source, 120);
    assert_eq!(defaults.triage.max_requests_per_tenant, 240);
    assert!(DetectionEngine::new(config, RulePack::empty()).is_ok());
}

#[test]
fn a_key_that_the_settings_do_not_have_is_an_error_that_names_the_key() {
    for (text, key) in [
        ("[velocity.sign_in_burst]\ntreshold = 5\n", "treshold"),
        ("[velocity.machine_cadence]\nmin_action = 5\n", "min_action"),
        ("[velocity.endpoint_probe]\ndecoys = []\n", "decoys"),
        ("[triage]\nquota = 5\n", "quota"),
        ("[correlator]\nwindow = 5\n", "window"),
        ("[sigma]\nenabled = true\n", "sigma"),
    ] {
        let error = toml::from_str::<EngineConfig>(text)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("unknown field `{key}`")),
            "{text}: {error}"
        );
    }
}

#[test]
fn the_runner_settings_read_from_a_toml_table() {
    let config: BusRunnerConfig =
        toml::from_str("durable_name = \"detect-eu\"\npublish_attempts = 3\n").unwrap();
    assert_eq!(config.durable_name, "detect-eu");
    assert_eq!(config.publish_attempts, 3);
    assert_eq!(config.publish_backoff_milliseconds, 50);
    assert_eq!(
        toml::from_str::<BusRunnerConfig>("").unwrap(),
        BusRunnerConfig::default()
    );
    // The bound on the published states of one incident.
    assert_eq!(config.max_incident_updates, 20);
    assert_eq!(config.incident_update_window_seconds, 60);
    let bound: BusRunnerConfig =
        toml::from_str("max_incident_updates = 5\nincident_update_window_seconds = 300\n").unwrap();
    assert_eq!(bound.max_incident_updates, 5);
    assert_eq!(bound.incident_update_window_seconds, 300);
    assert_eq!(bound.durable_name, "aegis-detect");
    assert!(toml::from_str::<BusRunnerConfig>("max_updates = 5\n").is_err());
}
