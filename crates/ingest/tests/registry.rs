//! Integration tests for [`SourceRegistry`] and [`SourceConfig`].
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Result};
use aegis_ingest::{
    CheckpointStore, FileSource, FileSourceConfig, MemoryCheckpointStore, RetryPolicy, RunOutcome,
    SourceConfig, SourceRegistry,
};
use aegis_testkit::{MemoryBus, StaticSource, fixtures};
use async_trait::async_trait;
use common::{FaultySource, fixture_path, published_events};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

/// The longest time that a test waits for a runner.
const LIMIT: Duration = Duration::from_secs(60);

/// The shape of a configuration file that holds a list of sources.
#[derive(Debug, Deserialize)]
struct Settings {
    sources: Vec<SourceConfig>,
}

fn settings(text: &str) -> Settings {
    toml::from_str(text).unwrap()
}

/// A TOML string for a file path. A literal string keeps the `\` of a Windows path.
fn toml_path(path: &std::path::Path) -> String {
    format!("'{}'", path.display())
}

/// A source whose check fails with a fixed error.
struct BrokenSource(&'static str);

#[async_trait]
impl SourceConnector for BrokenSource {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.0.to_owned(),
            vendor: "aegis".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    async fn check(&self) -> Result<()> {
        Err(Error::Unauthorized(format!("{}: no permission", self.0)))
    }

    async fn stream(&self, _cursor: Option<String>) -> Result<EventStream> {
        Err(Error::Unsupported("stream".to_owned()))
    }

    async fn fetch(&self, _range: TimeRange, _cursor: Option<String>) -> Result<EventBatch> {
        Err(Error::Unsupported("fetch".to_owned()))
    }
}

fn static_source(name: &str) -> Arc<dyn SourceConnector> {
    Arc::new(StaticSource::new(name, Vec::new()))
}

#[test]
fn an_empty_registry_has_no_connectors() {
    let registry = SourceRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert_eq!(registry.names(), Vec::<String>::new());
    assert!(registry.get("static").is_none());
}

#[test]
fn the_registry_holds_each_connector_by_the_name_in_its_info() {
    let mut registry = SourceRegistry::new();
    registry.register(static_source("zulu")).unwrap();
    registry.register(static_source("alpha")).unwrap();
    registry.register(static_source("mike-2")).unwrap();

    assert!(!registry.is_empty());
    assert_eq!(registry.len(), 3);
    assert_eq!(registry.names(), ["alpha", "mike-2", "zulu"]);
    assert_eq!(registry.get("mike-2").unwrap().info().name, "mike-2");
    assert!(registry.get("mike").is_none());
}

#[test]
fn a_second_connector_with_the_same_name_or_a_name_that_is_not_valid_is_rejected() {
    let mut registry = SourceRegistry::new();
    registry.register(static_source("entra")).unwrap();

    let error = registry.register(static_source("entra")).unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("entra") && message.contains("already")),
        "{error}"
    );
    for name in ["entra.prod", "", "a b", ">"] {
        let error = registry.register(static_source(name)).unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)), "{name:?}");
    }
    assert_eq!(registry.names(), ["entra"]);
}

#[tokio::test]
async fn check_gives_the_result_of_each_connector_in_name_order() {
    let directory = tempfile::tempdir().unwrap();
    let missing = FileSource::new(FileSourceConfig::new(
        "missing-file",
        directory.path().join("none.jsonl"),
    ))
    .unwrap();
    let mut registry = SourceRegistry::new();
    registry.register(static_source("static")).unwrap();
    registry.register(Arc::new(missing)).unwrap();
    registry.register(Arc::new(BrokenSource("denied"))).unwrap();
    registry
        .register(Arc::new(
            FileSource::new(FileSourceConfig::new("fixture", fixture_path())).unwrap(),
        ))
        .unwrap();

    let checks = registry.check().await;

    let names: Vec<&str> = checks.iter().map(|check| check.name.as_str()).collect();
    assert_eq!(names, ["denied", "fixture", "missing-file", "static"]);
    assert!(
        matches!(&checks[0].result, Err(Error::Unauthorized(message)) if message == "denied: no permission"),
        "{:?}",
        checks[0].result
    );
    assert!(matches!(checks[1].result, Ok(())), "{:?}", checks[1].result);
    assert!(
        matches!(&checks[2].result, Err(Error::NotFound(message)) if message.contains("none.jsonl")),
        "{:?}",
        checks[2].result
    );
    assert!(matches!(checks[3].result, Ok(())), "{:?}", checks[3].result);
    assert_eq!(SourceRegistry::new().check().await.len(), 0);
}

#[tokio::test]
async fn runner_builds_the_runner_of_one_connector_and_fails_for_an_unknown_name() {
    let events = fixtures::artex_style_attack();
    let mut registry = SourceRegistry::new();
    registry
        .register(Arc::new(StaticSource::new("static", events.clone())))
        .unwrap();
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());

    let runner = registry
        .runner(
            "static",
            bus.clone(),
            store.clone(),
            CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(runner.name(), "static");
    assert_eq!(runner.subject(), "aegis.events.static");
    let outcome = tokio::time::timeout(LIMIT, runner.run()).await.unwrap();
    assert_eq!(outcome.unwrap(), RunOutcome::Completed);
    assert_eq!(published_events(&bus, "aegis.events.static"), events);

    let result = registry.runner("other", bus, store, CancellationToken::new());
    assert!(
        matches!(&result, Err(Error::NotFound(message)) if message == "connector other"),
        "{:?}",
        result.err()
    );
}

#[tokio::test(start_paused = true)]
async fn runners_builds_one_runner_for_each_connector_with_the_shared_parts() {
    let events = fixtures::artex_style_attack();
    let mut registry = SourceRegistry::new();
    registry
        .register(Arc::new(StaticSource::new(
            "second",
            events[100..200].to_vec(),
        )))
        .unwrap();
    // This connector fails two times. Only the shared retry rules let its runner complete.
    registry
        .register(Arc::new(
            FaultySource::new("first", events[..100].to_vec(), 50).fail_open([
                Error::Unavailable("down".to_owned()),
                Error::Unavailable("down".to_owned()),
            ]),
        ))
        .unwrap();
    let memory_bus = Arc::new(MemoryBus::default());
    let bus: Arc<dyn MessageBus> = memory_bus.clone();
    let memory_store = Arc::new(MemoryCheckpointStore::new());
    let store: Arc<dyn CheckpointStore> = memory_store.clone();
    let cancel = CancellationToken::new();
    let retry = RetryPolicy {
        max_retries: 2,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
    };

    let runners = registry.runners(&bus, &store, &cancel, retry).unwrap();

    let names: Vec<&str> = runners.iter().map(|runner| runner.name()).collect();
    assert_eq!(names, ["first", "second"]);
    for runner in &runners {
        let outcome = tokio::time::timeout(LIMIT, runner.run()).await.unwrap();
        assert_eq!(outcome.unwrap(), RunOutcome::Completed, "{}", runner.name());
    }
    assert_eq!(runners[0].stats().retries, 2);
    assert_eq!(
        published_events(&memory_bus, "aegis.events.first"),
        events[..100]
    );
    assert_eq!(
        published_events(&memory_bus, "aegis.events.second"),
        events[100..200]
    );
    assert_eq!(memory_bus.published().len(), 200);
    assert_eq!(
        memory_store.load("first").await.unwrap().as_deref(),
        Some("100")
    );
    assert_eq!(
        memory_store.load("second").await.unwrap().as_deref(),
        Some("100")
    );

    // The shared token stops all runners.
    cancel.cancel();
    for runner in &runners {
        let outcome = tokio::time::timeout(LIMIT, runner.run()).await.unwrap();
        assert_eq!(outcome.unwrap(), RunOutcome::Cancelled, "{}", runner.name());
    }
}

#[tokio::test]
async fn a_registry_from_a_configuration_file_runs_the_file_source() {
    let settings = settings(&format!(
        r#"
        [[sources]]
        type = "file"
        name = "replay"
        path = {path}
        batch_size = 200

        [[sources]]
        type = "entra"
        name = "entra-prod"
        tenant_id = "00000000-0000-0000-0000-000000000000"
        client_id = "11111111-1111-1111-1111-111111111111"
        client_secret = "example-secret"
        poll_interval = "45s"
        service_principal_sign_ins = true
        "#,
        path = toml_path(&fixture_path())
    ));
    let names: Vec<&str> = settings.sources.iter().map(SourceConfig::name).collect();
    assert_eq!(names, ["replay", "entra-prod"]);
    assert!(matches!(&settings.sources[0], SourceConfig::File(config) if config.batch_size == 200));
    assert!(matches!(
        &settings.sources[1],
        SourceConfig::Entra(config)
            if config.poll_interval == Duration::from_secs(45) && config.service_principal_sign_ins
    ));
    assert!(
        !format!("{settings:?}").contains("example-secret"),
        "the debug output must not show the secret"
    );

    let registry = SourceRegistry::from_configs(&settings.sources).unwrap();
    assert_eq!(registry.names(), ["entra-prod", "replay"]);
    let entra = registry.get("entra-prod").unwrap().info();
    assert_eq!(
        (entra.vendor.as_str(), entra.product.as_str()),
        ("microsoft", "entra_id")
    );

    let bus = Arc::new(MemoryBus::default());
    let runner = registry
        .runner(
            "replay",
            bus.clone(),
            Arc::new(MemoryCheckpointStore::new()),
            CancellationToken::new(),
        )
        .unwrap();
    let outcome = tokio::time::timeout(LIMIT, runner.run()).await.unwrap();
    assert_eq!(outcome.unwrap(), RunOutcome::Completed);
    let published = published_events(&bus, "aegis.events.replay");
    assert_eq!(published.len(), fixtures::ATTACK_LOG_EVENTS);
    assert_eq!(published, fixtures::artex_style_attack());
    assert_eq!(runner.stats().batches, 4);
}

#[test]
fn a_configuration_that_is_not_valid_is_a_configuration_error() {
    let duplicate = settings(
        r#"
        [[sources]]
        type = "file"
        name = "replay"
        path = "a.jsonl"

        [[sources]]
        type = "file"
        name = "replay"
        path = "b.jsonl"
        "#,
    );
    let error = SourceRegistry::from_configs(&duplicate.sources)
        .err()
        .unwrap();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("replay") && message.contains("already")),
        "{error}"
    );

    let zero_batch = settings(
        r#"
        [[sources]]
        type = "file"
        name = "replay"
        path = "a.jsonl"
        batch_size = 0
        "#,
    );
    let error = zero_batch.sources[0].build().err().unwrap();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("batch_size")),
        "{error}"
    );

    // The variable name is an example. No process sets it.
    let no_secret = settings(
        r#"
        [[sources]]
        type = "entra"
        name = "entra-prod"
        tenant_id = "contoso.example"
        client_id = "11111111-1111-1111-1111-111111111111"
        client_secret_env = "AEGIS_INGEST_TEST_SECRET_THAT_IS_NOT_SET"
        "#,
    );
    let error = SourceRegistry::from_configs(&no_secret.sources)
        .err()
        .unwrap();
    assert!(
        matches!(&error, Error::Config(message)
            if message == "entra source entra-prod: the environment variable AEGIS_INGEST_TEST_SECRET_THAT_IS_NOT_SET is not set"),
        "{error}"
    );
}

#[test]
fn a_source_with_an_unknown_type_or_an_unknown_field_does_not_parse() {
    let unknown_type = toml::from_str::<Settings>(
        r#"
        [[sources]]
        type = "syslog"
        name = "replay"
        "#,
    )
    .unwrap_err();
    assert!(
        unknown_type
            .to_string()
            .contains("unknown variant `syslog`"),
        "{unknown_type}"
    );

    let unknown_field = toml::from_str::<Settings>(
        r#"
        [[sources]]
        type = "file"
        name = "replay"
        path = "a.jsonl"
        tenant_id = "contoso.example"
        "#,
    )
    .unwrap_err();
    assert!(
        unknown_field
            .to_string()
            .contains("unknown field `tenant_id`"),
        "{unknown_field}"
    );

    let no_type = toml::from_str::<Settings>(
        r#"
        [[sources]]
        name = "replay"
        path = "a.jsonl"
        "#,
    )
    .unwrap_err();
    assert!(no_type.to_string().contains("type"), "{no_type}");
}
