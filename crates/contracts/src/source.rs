//! The contract for telemetry inputs.

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::common::TimeRange;
use crate::error::Result;
use crate::event::Event;

/// Data that identifies a connector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectorInfo {
    /// The name of the connector instance, for example `entra-prod`.
    pub name: String,
    /// The vendor of the product that the connector talks to.
    pub vendor: String,
    /// The product that the connector talks to.
    pub product: String,
    /// The version of the connector.
    pub version: String,
}

/// A stream of normalized events from a source connector.
pub type EventStream = BoxStream<'static, Result<Event>>;

/// One page of events from a batch read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBatch {
    /// The events in this page, in time order.
    pub events: Vec<Event>,
    /// The cursor for the next page. `None` means that the read is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A telemetry input. An implementation reads one vendor system and emits normalized events.
///
/// An implementation must be safe to share between tasks.
#[async_trait]
pub trait SourceConnector: Send + Sync {
    /// Returns the data that identifies this connector.
    fn info(&self) -> ConnectorInfo;

    /// Checks that the connector can reach its source system.
    async fn check(&self) -> Result<()>;

    /// Opens a live stream of events.
    ///
    /// `cursor` is the value of a previous checkpoint. With `None`, the stream starts at
    /// the present time. The stream stays open until the caller drops it or the source ends.
    async fn stream(&self, cursor: Option<String>) -> Result<EventStream>;

    /// Reads one page of past events in `range`.
    ///
    /// Send `None` as `cursor` for the first page. Then send
    /// [`EventBatch::next_cursor`] until it is `None`.
    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch>;
}
