//! The set of named source connectors.

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_contracts::bus::MessageBus;
use aegis_contracts::source::SourceConnector;
use aegis_contracts::{Error, Result};
use tokio_util::sync::CancellationToken;

use crate::check_connector_name;
use crate::checkpoint::CheckpointStore;
use crate::config::SourceConfig;
use crate::runner::{IngestRunner, RetryPolicy};

/// The result of [`SourceConnector::check`] for one connector.
#[derive(Debug)]
pub struct SourceCheck {
    /// The name of the connector.
    pub name: String,
    /// The result of the check.
    pub result: Result<()>,
}

/// Holds source connectors by name and builds their runners.
#[derive(Default)]
pub struct SourceRegistry {
    sources: BTreeMap<String, Arc<dyn SourceConnector>>,
}

impl SourceRegistry {
    /// Makes an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes a registry with one connector for each configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a configuration is not valid or if two connectors have
    /// the same name.
    pub fn from_configs(configs: &[SourceConfig]) -> Result<Self> {
        let mut registry = Self::new();
        for config in configs {
            registry
                .register(config.build()?)
                .map_err(|error| match error {
                    Error::InvalidInput(message) => Error::Config(message),
                    other => other,
                })?;
        }
        Ok(registry)
    }

    /// Adds a connector. The registry uses the name in [`SourceConnector::info`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if the name is not valid or if the registry already
    /// has a connector with this name.
    pub fn register(&mut self, source: Arc<dyn SourceConnector>) -> Result<()> {
        let name = source.info().name;
        check_connector_name(&name)?;
        if self.sources.contains_key(&name) {
            return Err(Error::InvalidInput(format!(
                "a connector with the name {name} is already in the registry"
            )));
        }
        self.sources.insert(name, source);
        Ok(())
    }

    /// Returns the connector with the name `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn SourceConnector>> {
        self.sources.get(name).cloned()
    }

    /// Returns the names of all connectors, in alphabetical order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }

    /// Returns the number of connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Returns `true` if the registry has no connectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Runs [`SourceConnector::check`] on all connectors at the same time.
    ///
    /// Returns one result for each connector, in alphabetical order of the names.
    pub async fn check(&self) -> Vec<SourceCheck> {
        let checks = self.sources.iter().map(|(name, source)| async move {
            SourceCheck {
                name: name.clone(),
                result: source.check().await,
            }
        });
        futures::future::join_all(checks).await
    }

    /// Builds the runner for the connector with the name `name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the registry has no connector with this name.
    pub fn runner(
        &self,
        name: &str,
        bus: Arc<dyn MessageBus>,
        checkpoints: Arc<dyn CheckpointStore>,
        cancel: CancellationToken,
    ) -> Result<IngestRunner> {
        let source = self
            .get(name)
            .ok_or_else(|| Error::NotFound(format!("connector {name}")))?;
        IngestRunner::new(source, bus, checkpoints, cancel)
    }

    /// Builds one runner for each connector, in alphabetical order of the names.
    ///
    /// All runners share the bus, the checkpoint store, the cancellation signal, and the
    /// retry rules.
    pub fn runners(
        &self,
        bus: &Arc<dyn MessageBus>,
        checkpoints: &Arc<dyn CheckpointStore>,
        cancel: &CancellationToken,
        retry: RetryPolicy,
    ) -> Result<Vec<IngestRunner>> {
        self.sources
            .values()
            .map(|source| {
                IngestRunner::new(
                    source.clone(),
                    bus.clone(),
                    checkpoints.clone(),
                    cancel.clone(),
                )
                .map(|runner| runner.with_retry(retry))
            })
            .collect()
    }
}
