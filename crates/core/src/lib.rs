//! Shared runtime services for each AEGIS process.
//!
//! All AEGIS subsystems run in one binary. This crate gives the binary and the subsystem
//! crates the services that they all use.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`config`] | [`Config`]: a TOML document with environment overrides. Each subsystem reads its section. |
//! | [`telemetry`] | [`telemetry::init`]: the `tracing` subscriber, with an optional OTLP trace exporter. |
//! | [`modules`] | [`ModuleSet`]: the subsystems that the process runs. |
//! | [`shutdown`] | [`Shutdown`]: the signal that stops long-running loops. |
//!
//! # Example
//!
//! ```
//! use aegis_core::{Config, Module, ModuleSet, Shutdown, TelemetryConfig};
//!
//! # fn main() -> aegis_contracts::Result<()> {
//! let config = Config::from_toml_str(
//!     r#"
//!     [telemetry]
//!     log_format = "json"
//!
//!     [modules]
//!     enabled = ["ingest", "detection", "monitor"]
//!     "#,
//! )?;
//!
//! let telemetry = TelemetryConfig::from_config(&config)?;
//! assert_eq!(telemetry.service_name, "aegis");
//!
//! let modules = ModuleSet::from_config(&config)?;
//! assert!(modules.contains(Module::Detection));
//! assert!(!modules.contains(Module::Responder));
//!
//! let shutdown = Shutdown::new();
//! assert!(!shutdown.is_triggered());
//! # Ok(())
//! # }
//! ```
//!
//! # Cargo features
//!
//! | Feature | Effect |
//! | --- | --- |
//! | `otlp` | Adds the OpenTelemetry OTLP trace exporter to [`telemetry`]. |

pub mod config;
pub mod modules;
pub mod shutdown;
pub mod telemetry;

pub use config::Config;
pub use modules::{Module, ModuleSet};
pub use shutdown::Shutdown;
pub use telemetry::{LogFormat, LogLevel, TelemetryConfig, TelemetryGuard};

/// Compiles the examples in `README.md` as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
