//! The AEGIS message bus.
//!
//! This crate has two implementations of [`MessageBus`]:
//!
//! - [`NatsBus`] stores messages in a NATS JetStream stream. Use it in production.
//! - [`InProcessBus`] keeps messages in the memory of the process. Use it for a
//!   deployment that is one binary with no NATS server.
//!
//! The two implementations obey the same rules. [`connect`] makes the implementation that
//! [`BusConfig::kind`] selects.
//!
//! ```no_run
//! # async fn example() -> aegis_contracts::Result<()> {
//! use aegis_bus::{BusConfig, BusKind};
//! use aegis_contracts::bus::{publish_json, subject};
//! use futures::StreamExt;
//!
//! let config = BusConfig {
//!     kind: BusKind::Memory,
//!     ..BusConfig::default()
//! };
//! let bus = aegis_bus::connect(&config).await?;
//! let mut audit = bus.subscribe("aegis.audit", Some("archive")).await?;
//! publish_json(bus.as_ref(), subject::AUDIT, &"record").await?;
//! if let Some(message) = audit.next().await {
//!     let record: String = message?.decode()?;
//!     assert_eq!(record, "record");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Delivery rules
//!
//! - `publish` returns `Ok` only after the bus stored the message.
//! - A subscription with no durable name gets the messages that the bus stores after the
//!   subscription starts. It gets each message one time, in the sequence of the stream.
//! - A subscription with a durable name gets each message one time or more (at least once).
//!   The bus acknowledges a message when the caller polls the stream for the next message.
//!   If the caller drops the stream before that poll, the bus delivers the message again.
//! - After an error item, poll the stream again. When a stream cannot continue, it gives
//!   one last error item and then ends.
//! - A subscription stream of [`NatsBus`] continues after a restart of the NATS server.
//!
//! The README of the crate has the full rules, the configuration, and the error mapping.

mod config;
mod memory;
mod nats;
mod subject;

use std::sync::Arc;

use aegis_contracts::{MessageBus, Result};

pub use config::{
    BusConfig, BusKind, ConsumerConfig, NatsAuth, NatsConfig, StorageKind, StreamConfig, TlsConfig,
};
pub use memory::InProcessBus;
pub use nats::{NatsBus, StreamStatus};
/// The type of the passwords and the tokens in [`NatsAuth`]. Its `Debug` output hides the
/// value.
pub use secrecy::SecretString;

/// Compiles and runs the examples of the README as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;

/// Makes the message bus that the configuration selects.
///
/// For [`BusKind::Nats`], the function connects to the servers and then calls
/// [`NatsBus::ensure_stream`]. For [`BusKind::Memory`], the function makes an
/// [`InProcessBus`] and uses no network.
///
/// # Errors
///
/// Returns the errors of [`NatsBus::connect`], [`NatsBus::ensure_stream`], and
/// [`InProcessBus::new`].
pub async fn connect(config: &BusConfig) -> Result<Arc<dyn MessageBus>> {
    match config.kind {
        BusKind::Memory => Ok(Arc::new(InProcessBus::new(config)?)),
        BusKind::Nats => {
            let bus = NatsBus::connect(config).await?;
            bus.ensure_stream().await?;
            Ok(Arc::new(bus))
        }
    }
}
