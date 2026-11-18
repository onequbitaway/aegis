//! A source connector that runs in a plugin.

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::SecondsFormat;

use crate::bindings::SourceConnectorPre;
use crate::sandbox::{HostState, Sandbox};

/// A [`SourceConnector`] whose code is a WebAssembly component.
pub(crate) struct PluginSource {
    inner: Arc<Inner>,
}

struct Inner {
    sandbox: Sandbox,
    component: SourceConnectorPre<HostState>,
    info: ConnectorInfo,
    poll_interval: Duration,
}

impl PluginSource {
    /// Asks the plugin for its identity and makes the connector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if `info` does not return the JSON form of
    /// `ConnectorInfo`, and the error of the sandbox if the call fails.
    pub(crate) async fn load(
        sandbox: Sandbox,
        component: SourceConnectorPre<HostState>,
        poll_interval: Duration,
    ) -> Result<Self> {
        let pre = component.clone();
        let text = sandbox
            .call("info", move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    plugin.aegis_plugin_source().call_info(store).await
                })
            })
            .await?;
        let info = sandbox.connector_info(text).await?;
        Ok(Self {
            inner: Arc::new(Inner {
                sandbox,
                component,
                info,
                poll_interval,
            }),
        })
    }
}

impl Inner {
    /// Calls `poll` one time and checks the batch.
    async fn poll(&self, cursor: Option<String>) -> Result<EventBatch> {
        let pre = self.component.clone();
        let reply = self
            .sandbox
            .call("poll", move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    plugin
                        .aegis_plugin_source()
                        .call_poll(store, cursor.as_deref())
                        .await
                })
            })
            .await?;
        self.batch("poll", reply).await
    }

    /// Decodes a batch and makes the host the authority for the connector name.
    ///
    /// A plugin cannot emit an event that claims to come from a different connector.
    async fn batch(
        &self,
        operation: &str,
        reply: Result<String, crate::bindings::GuestError>,
    ) -> Result<EventBatch> {
        let text = reply.map_err(|error| self.sandbox.guest_error(error))?;
        let mut batch: EventBatch = self.sandbox.decode(operation, "EventBatch", text).await?;
        for event in &mut batch.events {
            event.source.connector.clone_from(&self.info.name);
        }
        Ok(batch)
    }
}

#[async_trait]
impl SourceConnector for PluginSource {
    fn info(&self) -> ConnectorInfo {
        self.inner.info.clone()
    }

    async fn check(&self) -> Result<()> {
        let pre = self.inner.component.clone();
        self.inner
            .sandbox
            .call("check", move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    plugin.aegis_plugin_source().call_check(store).await
                })
            })
            .await?
            .map_err(|error| self.inner.sandbox.guest_error(error))
    }

    /// Opens a stream that calls `poll` of the plugin again and again.
    ///
    /// The first call is immediate. Then the host waits for the poll interval of the
    /// manifest between two calls. The host sends the last cursor that the plugin
    /// returned. An error is one item of the stream, and the stream continues after it.
    /// The stream ends only when the caller drops it.
    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        let state = (Arc::clone(&self.inner), cursor, true);
        Ok(Box::pin(futures::stream::unfold(
            state,
            |(inner, cursor, first)| async move {
                if !first {
                    tokio::time::sleep(inner.poll_interval).await;
                }
                let result = inner.poll(cursor.clone()).await;
                let cursor = match &result {
                    Ok(batch) => batch.next_cursor.clone().or(cursor),
                    Err(_) => cursor,
                };
                Some((result, (inner, cursor, false)))
            },
        )))
    }

    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        if range.end < range.start {
            return Err(Error::InvalidInput(format!(
                "plugin {}: the time range ends before it starts",
                self.inner.info.name
            )));
        }
        let start = range.start.to_rfc3339_opts(SecondsFormat::AutoSi, true);
        let end = range.end.to_rfc3339_opts(SecondsFormat::AutoSi, true);
        let pre = self.inner.component.clone();
        let reply = self
            .inner
            .sandbox
            .call("fetch", move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    plugin
                        .aegis_plugin_source()
                        .call_fetch(store, &start, &end, cursor.as_deref())
                        .await
                })
            })
            .await?;
        self.inner.batch("fetch", reply).await
    }
}
