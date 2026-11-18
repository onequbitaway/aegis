//! Telemetry initialization.
//!
//! [`init`] installs the global `tracing` subscriber of the process. The subscriber writes
//! formatted log lines to the standard error stream. With the Cargo feature `otlp` and an
//! endpoint in the configuration, it also sends spans to an OpenTelemetry collector.
//!
//! `tracing` permits only one global subscriber in a process. [`subscriber`] builds the same
//! subscriber and does not install it. Use [`subscriber`] in tests.
//!
//! With no endpoint, this module does not use the network.

#[cfg(feature = "otlp")]
mod otlp;

use std::fmt;

use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};
use tracing::Dispatch;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};

use crate::config::Config;

/// One layer of the subscriber, with its type hidden.
type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// The format of the log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One line of text for each event. A person reads this format.
    #[default]
    Text,
    /// One JSON object for each event. A log collector reads this format.
    Json,
}

/// The lowest severity that the subscriber records.
///
/// The variants are in order. `Trace` records the most events. `Off` records no events.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Records all events.
    Trace,
    /// Records debug events and all events that are more severe.
    Debug,
    /// Records informational events and all events that are more severe.
    #[default]
    Info,
    /// Records warnings and errors.
    Warn,
    /// Records only errors.
    Error,
    /// Records no events.
    Off,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Self::TRACE,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Info => Self::INFO,
            LogLevel::Warn => Self::WARN,
            LogLevel::Error => Self::ERROR,
            LogLevel::Off => Self::OFF,
        }
    }
}

/// The `[telemetry]` section of the configuration.
///
/// All keys are optional. An unknown key is an error.
///
/// ```toml
/// [telemetry]
/// service_name = "aegis"
/// log_format = "json"
/// log_level = "info"
/// otlp_endpoint = "http://localhost:4318"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// The name of this process in the trace data. It must not be empty. The default is
    /// `aegis`.
    pub service_name: String,
    /// The format of the log lines. The default is [`LogFormat::Text`].
    pub log_format: LogFormat,
    /// The lowest severity that the subscriber records. The default is [`LogLevel::Info`].
    pub log_level: LogLevel,
    /// The base URL of an OpenTelemetry collector that accepts OTLP over HTTP, for example
    /// `http://localhost:4318`. The exporter sends spans to the path `/v1/traces` below it.
    ///
    /// The URL must start with `http://` or `https://`. It must not contain credentials, a
    /// query, or a fragment. To authenticate, set the standard environment variable
    /// `OTEL_EXPORTER_OTLP_HEADERS`.
    ///
    /// With `None`, the process sends no trace data. A build without the Cargo feature
    /// `otlp` rejects a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "aegis".to_owned(),
            log_format: LogFormat::default(),
            log_level: LogLevel::default(),
            otlp_endpoint: None,
        }
    }
}

impl TelemetryConfig {
    /// The name of the configuration section.
    pub const SECTION: &'static str = "telemetry";

    /// Reads the `[telemetry]` section. A missing section gives the default values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the section is not valid.
    pub fn from_config(config: &Config) -> Result<Self> {
        config.section_or_default(Self::SECTION)
    }

    fn validate(&self) -> Result<()> {
        if self.service_name.trim().is_empty() {
            return Err(Error::Config(
                "telemetry.service_name must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Keeps the trace exporter in operation.
///
/// Keep the guard until the process stops. When the guard is dropped, it sends the spans
/// that remain and stops the exporter. A failure at that time goes to the log as a warning.
/// Call [`TelemetryGuard::shutdown`] to get the failure as an error.
///
/// This operation blocks the thread until the exporter stops or its time limit expires.
#[must_use = "the trace exporter stops when the guard is dropped"]
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Returns `true` if this guard holds a trace exporter.
    #[must_use]
    pub fn exports_traces(&self) -> bool {
        #[cfg(feature = "otlp")]
        return self.provider.is_some();
        #[cfg(not(feature = "otlp"))]
        return false;
    }

    /// Sends the spans that remain and stops the exporter.
    ///
    /// A collector that is not available is not an error of this function. The exporter
    /// tries again, then writes the failure to the log as an error event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the exporter does not stop in its time limit. Returns
    /// [`Error::Unavailable`] if the exporter reports a failure of the stop operation.
    pub fn shutdown(mut self) -> Result<()> {
        self.stop()
    }

    fn stop(&mut self) -> Result<()> {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.provider.take() {
            return otlp::shutdown(&provider);
        }
        Ok(())
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            tracing::warn!(%error, "the trace exporter did not stop correctly");
        }
    }
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryGuard")
            .field("exports_traces", &self.exports_traces())
            .finish()
    }
}

/// Builds the subscriber and installs it as the global `tracing` subscriber.
///
/// The log lines go to the standard error stream. Call this function one time, at the start
/// of the process. Keep the guard until the process stops.
///
/// # Errors
///
/// Returns the errors of [`subscriber`]. Returns [`Error::Other`] if the process already
/// has a global subscriber.
pub fn init(config: &TelemetryConfig) -> Result<TelemetryGuard> {
    let (dispatch, guard) = subscriber(config, std::io::stderr)?;
    tracing::dispatcher::set_global_default(dispatch)
        .map_err(|error| Error::other("install the global tracing subscriber", error))?;
    Ok(guard)
}

/// Builds the subscriber and does not install it.
///
/// `writer` receives the log lines. Use the result with
/// [`tracing::dispatcher::with_default`] in a test, or with
/// [`tracing::dispatcher::set_global_default`].
///
/// # Errors
///
/// Returns [`Error::Config`] in these conditions:
///
/// - `service_name` is empty.
/// - `otlp_endpoint` has a value and the build does not have the Cargo feature `otlp`.
/// - `otlp_endpoint` is not a valid collector URL.
///
/// The message does not contain the endpoint.
pub fn subscriber<W>(config: &TelemetryConfig, writer: W) -> Result<(Dispatch, TelemetryGuard)>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    config.validate()?;
    let (trace_layer, guard) = trace_export(config)?;
    let log_layer: BoxedLayer = match config.log_format {
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .boxed(),
    };
    let mut layers = vec![log_layer];
    layers.extend(trace_layer);
    // The level filter must be a layer of its own, outside the list. A filter in the list
    // has no effect, because a list accepts an event if one of its layers accepts it.
    let subscriber = Registry::default()
        .with(layers)
        .with(LevelFilter::from(config.log_level));
    Ok((Dispatch::new(subscriber), guard))
}

/// Builds the trace export layer if the configuration has an endpoint.
#[cfg(feature = "otlp")]
fn trace_export(config: &TelemetryConfig) -> Result<(Option<BoxedLayer>, TelemetryGuard)> {
    let Some(endpoint) = &config.otlp_endpoint else {
        return Ok((None, TelemetryGuard { provider: None }));
    };
    let (layer, provider) = otlp::layer(&config.service_name, endpoint)?;
    Ok((
        Some(layer),
        TelemetryGuard {
            provider: Some(provider),
        },
    ))
}

/// Rejects an endpoint, because this build cannot export traces.
#[cfg(not(feature = "otlp"))]
fn trace_export(config: &TelemetryConfig) -> Result<(Option<BoxedLayer>, TelemetryGuard)> {
    if config.otlp_endpoint.is_some() {
        return Err(Error::Config(
            "telemetry.otlp_endpoint has a value, but this build cannot export traces: build \
             with the Cargo feature `otlp`, or remove the key"
                .to_owned(),
        ));
    }
    Ok((None, TelemetryGuard {}))
}
