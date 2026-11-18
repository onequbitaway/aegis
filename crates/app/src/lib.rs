//! The composition root of AEGIS.
//!
//! This crate builds all subsystems of one AEGIS process from one configuration document,
//! connects them, and runs them. Each subsystem crate knows only the contracts of
//! `aegis-contracts`. The connections between the subsystems are in this crate.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`App`] | All subsystems of one process. [`App::build`] makes it from a [`Config`](aegis_core::Config). |
//! | [`App::run`] | The service: ingestion, detection, the agents, and the playbooks, until shutdown. |
//! | [`App::replay`] | A run on a list of events in the process, with a [`ReplayReport`](report::ReplayReport). |
//! | [`App::decide_approval`] | The decision of a person on a gated action. |
//! | [`App::reload`] | A new load of the rule pack, the policy, and the playbooks. |
//! | [`preflight`] | All problems of a configuration, with no connection and no file write. |
//! | `api` | The operator API of the application: REST, the web console, and ChatOps. Cargo feature `api`. |
//! | [`settings`] | The sections of the configuration document. |
//! | [`starter`] | The starter directory and the recorded attack log, embedded in the crate. |
//!
//! # The connections
//!
//! - **Engine output to the store.** [`incidents::SharedIncidents`] writes each incident
//!   state of the detection engine. It keeps the state, the summary, and the timeline that
//!   the agents wrote.
//! - **Incidents and events to the agents.** The agents get each new and changed incident.
//!   The Monitor agent gets the events that caused a detection.
//! - **Playbooks.** Each matching playbook runs one time for one incident.
//! - **One dispatcher.** The agents and the playbooks send each action through
//!   [`actions::ActionJournal`], which is in front of the one
//!   [`Dispatcher`](aegis_respond::Dispatcher).
//! - **Live audit feed.** [`audit::PublishingAuditLog`] publishes each sealed audit record
//!   on `aegis.audit`.
//! - **Honeytokens.** The honeytoken connector and the honeytoken detector use one
//!   registry.
//! - **Operator API.** With the Cargo feature `api`, the module `api` gives the services
//!   of the application to `aegis-api`. A decision of a person through the API runs the
//!   approved action one time, also when the HTTP request goes away.
//!
//! # Safe defaults
//!
//! With the default settings, the application changes nothing in the environment of the
//! operator. The dispatcher makes each action a dry run, the agents propose dry runs, and
//! the playbooks run as dry runs. With no `[model]` section, the application uses no model
//! and no network for a model.
//!
//! # Example
//!
//! ```no_run
//! use aegis_app::{App, starter};
//! use aegis_core::Config;
//!
//! # async fn example() -> aegis_contracts::Result<()> {
//! let directory = std::path::Path::new("/var/lib/aegis-starter");
//! starter::write(directory)?;
//! let config = Config::load(directory.join(starter::CONFIG_FILE))?;
//! let app = App::builder(&config).base_dir(directory).build().await?;
//!
//! let report = app.replay(starter::attack_events()?).await?;
//! assert!(report.audit.verification.valid);
//! assert!(!report.changed_the_environment());
//! # Ok(())
//! # }
//! ```
//!
//! # Cargo features
//!
//! | Feature | Effect |
//! | --- | --- |
//! | `postgres` | `storage.kind = "postgres"` and `audit.kind = "postgres"`. |
//! | `plugins` | The `[plugins]` section: WebAssembly connector plugins. |
//! | `otlp` | The OpenTelemetry trace exporter of `aegis-core`. |
//! | `api` | The `[api]` section and the module `api`: the operator API. |
//! | `grpc` | The gRPC services of the operator API. Not a default feature. |
//!
//! `postgres`, `plugins`, `otlp`, and `api` are default features. Without them, the crate
//! builds a light process for monitoring with the in-memory storage and no HTTP server.

pub mod actions;
pub mod activity;
#[cfg(feature = "api")]
pub mod api;
mod app;
pub mod audit;
mod bridge;
#[cfg(feature = "decoy")]
pub mod decoy;
pub mod evidence;
pub mod incidents;
pub mod offline;
pub mod playbooks;
mod preflight;
pub mod report;
pub mod settings;
pub mod sharing;
pub mod starter;

pub use app::{
    APP_ACTOR, APPROVAL_REJECTED_POLICY, App, AppBuilder, HONEYTOKEN_CONNECTOR, RunOptions, Service,
};
pub use bridge::{CORRELATOR_ACTOR, DETECTION_ACTOR, PLAYBOOK_ACTOR, Progress};
pub use preflight::preflight;

/// Compiles the Rust example of the README file as a documentation test.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
