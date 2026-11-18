//! The configuration of one source connector.

use std::sync::Arc;

use aegis_contracts::Result;
use aegis_contracts::source::SourceConnector;
use serde::Deserialize;

use crate::entra::{EntraConfig, EntraSource};
use crate::file::{FileSource, FileSourceConfig};

/// The configuration of one source connector. The `type` field selects the connector.
///
/// ```toml
/// [[sources]]
/// type = "file"
/// name = "replay"
/// path = "fixtures/artex_style_attack.jsonl"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceConfig {
    /// A [`FileSource`].
    File(FileSourceConfig),
    /// An [`EntraSource`].
    Entra(Box<EntraConfig>),
}

impl SourceConfig {
    /// Returns the name of the connector instance.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::File(config) => &config.name,
            Self::Entra(config) => &config.name,
        }
    }

    /// Builds the connector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](aegis_contracts::Error::Config) if the configuration is
    /// not valid.
    pub fn build(&self) -> Result<Arc<dyn SourceConnector>> {
        Ok(match self {
            Self::File(config) => Arc::new(FileSource::new(config.clone())?),
            Self::Entra(config) => Arc::new(EntraSource::new(config.as_ref().clone())?),
        })
    }
}
