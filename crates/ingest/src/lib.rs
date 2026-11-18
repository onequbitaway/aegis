//! Source connectors and the ingestion runner of AEGIS.
//!
//! A source connector reads the telemetry of the operator and converts it to the normalized
//! [`Event`](aegis_contracts::Event). The [`IngestRunner`] publishes these events on the
//! message bus. Detection reads them from the bus.
//!
//! This crate only reads telemetry. It does not change the source system.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`IngestRunner`] | Drives one connector: publish, checkpoint, retry, backfill. |
//! | [`SourceRegistry`] | Holds named connectors and builds their runners. |
//! | [`CheckpointStore`] | Keeps the cursor of each connector between restarts. |
//! | [`FileSource`] | Replays normalized events from a JSON Lines file. |
//! | [`EntraSource`] | Reads Microsoft Entra ID sign-in and audit logs through Microsoft Graph. |
//! | [`SourceConfig`] | The serde configuration of one connector. |
//!
//! # Delivery guarantee
//!
//! The runner publishes a batch before it saves the cursor of the batch. A stop between the
//! two steps repeats the batch after the restart. The runner can repeat an event. It does
//! not lose an event.
//!
//! # Example
//!
//! This example replays the recorded attack log from a file to a bus in memory.
//!
//! ```
//! use std::sync::Arc;
//!
//! use aegis_ingest::{
//!     FileSource, FileSourceConfig, IngestRunner, MemoryCheckpointStore, RunOutcome,
//! };
//! use aegis_testkit::MemoryBus;
//! use tokio_util::sync::CancellationToken;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> aegis_contracts::Result<()> {
//! # let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/artex_style_attack.jsonl");
//! let source = Arc::new(FileSource::new(FileSourceConfig::new("replay", path))?);
//! let bus = Arc::new(MemoryBus::default());
//! let checkpoints = Arc::new(MemoryCheckpointStore::new());
//! let runner = IngestRunner::new(source, bus.clone(), checkpoints, CancellationToken::new())?;
//!
//! assert_eq!(runner.run().await?, RunOutcome::Completed);
//! assert_eq!(runner.stats().events_published, 648);
//! assert_eq!(bus.published_to("aegis.events.replay").len(), 648);
//! # Ok(())
//! # }
//! ```

mod checkpoint;
mod config;
pub mod entra;
mod file;
mod registry;
mod runner;

use aegis_contracts::Error;

pub use checkpoint::{CheckpointStore, FileCheckpointStore, MemoryCheckpointStore};
pub use config::SourceConfig;
pub use entra::{EntraConfig, EntraSource};
pub use file::{FileSource, FileSourceConfig, ReplayPace};
pub use registry::{SourceCheck, SourceRegistry};
pub use runner::{IngestRunner, IngestStats, RetryPolicy, RunOutcome};

/// The largest number of characters in a connector name.
const MAX_NAME_LENGTH: usize = 64;

/// Returns the reason why `name` is not a valid connector name, if it is not valid.
///
/// The name becomes one token of a bus subject and a part of a checkpoint file name. Thus
/// only ASCII letters, digits, `-`, and `_` are permitted.
fn connector_name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("the connector name is empty".to_owned());
    }
    if name.len() > MAX_NAME_LENGTH {
        return Some(format!(
            "the connector name is longer than {MAX_NAME_LENGTH} characters"
        ));
    }
    let permitted =
        |character: char| character.is_ascii_alphanumeric() || character == '-' || character == '_';
    if name.chars().all(permitted) {
        None
    } else {
        Some(format!(
            "the connector name {name:?} has a character that is not a letter, a digit, '-', or '_'"
        ))
    }
}

/// Checks a connector name that comes from a caller.
pub(crate) fn check_connector_name(name: &str) -> Result<(), Error> {
    connector_name_problem(name).map_or(Ok(()), |problem| Err(Error::InvalidInput(problem)))
}

/// Checks a connector name that comes from the configuration.
pub(crate) fn check_configured_name(name: &str) -> Result<(), Error> {
    connector_name_problem(name).map_or(Ok(()), |problem| Err(Error::Config(problem)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_of_letters_digits_hyphens_and_underscores_is_valid() {
        for name in ["entra-prod", "file_1", "A", &"x".repeat(MAX_NAME_LENGTH)] {
            assert_eq!(connector_name_problem(name), None, "{name}");
        }
    }

    #[test]
    fn a_name_that_changes_the_subject_or_the_file_path_is_not_valid() {
        let too_long = "x".repeat(MAX_NAME_LENGTH + 1);
        for name in [
            "",
            "entra.prod",
            "entra prod",
            "*",
            ">",
            "../etc",
            "a/b",
            "é",
            &too_long,
        ] {
            assert!(connector_name_problem(name).is_some(), "{name:?}");
            assert!(
                matches!(check_connector_name(name), Err(Error::InvalidInput(_))),
                "{name:?}"
            );
            assert!(
                matches!(check_configured_name(name), Err(Error::Config(_))),
                "{name:?}"
            );
        }
    }
}
