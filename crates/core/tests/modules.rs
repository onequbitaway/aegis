//! Tests for the module set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_contracts::Error;
use aegis_core::modules::{RULE_NOT_EMPTY, RULE_RESPONDER_NEEDS_DETECTION};
use aegis_core::{Config, Module, ModuleSet};

fn config_error(result: aegis_contracts::Result<ModuleSet>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

fn from_toml(text: &str) -> aegis_contracts::Result<ModuleSet> {
    ModuleSet::from_config(&Config::from_toml_str(text).unwrap())
}

#[test]
fn the_configuration_selects_the_modules() {
    let modules =
        from_toml("[modules]\nenabled = [\"ingest\", \"detection\", \"monitor\"]\n").unwrap();
    let enabled: Vec<Module> = modules.iter().collect();
    assert_eq!(
        enabled,
        [Module::Ingest, Module::Detection, Module::Monitor]
    );
    assert_eq!(modules, ModuleSet::monitoring_only());
    assert_eq!(modules.iter().count(), 3);
}

#[test]
fn each_module_name_in_the_configuration_selects_one_module() {
    let modules = from_toml(
        "[modules]\nenabled = [\"api\", \"reporter\", \"deception\", \"responder\", \"analyst\", \
         \"hunter\", \"monitor\", \"detection\", \"ingest\"]\n",
    )
    .unwrap();
    assert_eq!(modules, ModuleSet::all());
    let names: Vec<&str> = modules.iter().map(Module::name).collect();
    assert_eq!(
        names,
        [
            "ingest",
            "detection",
            "monitor",
            "hunter",
            "analyst",
            "responder",
            "deception",
            "reporter",
            "api"
        ]
    );
}

#[test]
fn all_contains_each_module() {
    let modules = ModuleSet::all();
    assert_eq!(modules.iter().count(), Module::ALL.len());
    assert_eq!(Module::ALL.len(), 9);
    for module in Module::ALL {
        assert!(modules.contains(module), "{module}");
    }
}

#[test]
fn monitoring_only_contains_no_module_that_changes_the_environment() {
    let modules = ModuleSet::monitoring_only();
    assert!(modules.contains(Module::Ingest));
    assert!(modules.contains(Module::Detection));
    assert!(modules.contains(Module::Monitor));
    for module in [
        Module::Hunter,
        Module::Analyst,
        Module::Responder,
        Module::Deception,
        Module::Reporter,
        Module::Api,
    ] {
        assert!(!modules.contains(module), "{module}");
    }
}

#[test]
fn a_missing_section_or_a_missing_key_gives_monitoring_only() {
    assert_eq!(from_toml("").unwrap(), ModuleSet::monitoring_only());
    assert_eq!(
        from_toml("[modules]\n").unwrap(),
        ModuleSet::monitoring_only()
    );
}

#[test]
fn responder_without_detection_breaks_a_named_rule() {
    let expected = format!(
        "the module set breaks the rule `{RULE_RESPONDER_NEEDS_DETECTION}`: enable `detection`, \
         or remove `responder`"
    );
    assert_eq!(
        config_error(from_toml(
            "[modules]\nenabled = [\"ingest\", \"responder\"]\n"
        )),
        expected
    );
    assert_eq!(config_error(ModuleSet::new([Module::Responder])), expected);
    assert_eq!(
        RULE_RESPONDER_NEEDS_DETECTION,
        "responder-requires-detection"
    );
}

#[test]
fn responder_with_detection_is_valid() {
    let modules = ModuleSet::new([Module::Responder, Module::Detection]).unwrap();
    assert!(modules.contains(Module::Responder));
    assert!(modules.contains(Module::Detection));
    assert!(!modules.contains(Module::Ingest));
    assert_eq!(modules.iter().count(), 2);
}

#[test]
fn an_empty_set_breaks_a_named_rule() {
    let expected =
        format!("the module set breaks the rule `{RULE_NOT_EMPTY}`: enable one module or more");
    assert_eq!(
        config_error(from_toml("[modules]\nenabled = []\n")),
        expected
    );
    assert_eq!(config_error(ModuleSet::new([])), expected);
}

#[test]
fn a_module_that_occurs_two_times_counts_one_time() {
    let modules = ModuleSet::new([Module::Api, Module::Api, Module::Ingest]).unwrap();
    assert_eq!(modules.iter().count(), 2);
    assert_eq!(modules.to_string(), "ingest, api");
}

#[test]
fn an_unknown_module_name_is_an_error_that_lists_the_names() {
    assert_eq!(
        config_error(from_toml(
            "[modules]\nenabled = [\"ingest\", \"offense\"]\n"
        )),
        "the section `modules` is not valid: key `enabled[1]`: unknown variant, expected one of \
         `ingest`, `detection`, `monitor`, `hunter`, `analyst`, `responder`, `deception`, \
         `reporter`, `api`"
    );
}

#[test]
fn an_unknown_key_in_the_section_is_an_error() {
    assert_eq!(
        config_error(from_toml("[modules]\nenable = [\"ingest\"]\n")),
        "the section `modules` is not valid: unknown field `enable`, expected `enabled`"
    );
}

#[test]
fn an_environment_override_selects_the_modules() {
    let config = Config::from_toml_str("[modules]\nenabled = [\"ingest\"]\n")
        .unwrap()
        .with_overrides([(
            "AEGIS__MODULES__ENABLED".to_owned(),
            "[\"detection\", \"responder\"]".to_owned(),
        )])
        .unwrap();
    let modules = ModuleSet::from_config(&config).unwrap();
    let enabled: Vec<Module> = modules.iter().collect();
    assert_eq!(enabled, [Module::Detection, Module::Responder]);
}

#[test]
fn a_module_serializes_as_its_configuration_name() {
    let names: Vec<String> = Module::ALL
        .iter()
        .map(|module| {
            serde_json::to_value(module)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        names,
        [
            "ingest",
            "detection",
            "monitor",
            "hunter",
            "analyst",
            "responder",
            "deception",
            "reporter",
            "api"
        ]
    );
    let decoded: Vec<Module> = serde_json::from_value(serde_json::json!(names)).unwrap();
    assert_eq!(decoded, Module::ALL);
}

#[test]
fn a_module_name_parses_and_prints_as_the_configuration_name() {
    for module in Module::ALL {
        assert_eq!(module.name().parse::<Module>().unwrap(), module);
        assert_eq!(module.to_string(), module.name());
    }
    match "Ingest".parse::<Module>() {
        Err(Error::InvalidInput(message)) => assert_eq!(
            message,
            "`Ingest` is not a module name; use one of: ingest, detection, monitor, hunter, \
             analyst, responder, deception, reporter, api"
        ),
        other => panic!("expected Error::InvalidInput, got {other:?}"),
    }
}
