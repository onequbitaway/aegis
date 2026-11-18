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
fn a_key_that_the_settings_do_not_have_is_an_error_that_names_the_key() {
    for (text, key) in [
        ("[velocity.sign_in_burst]\ntreshold = 5\n", "treshold"),
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
}
