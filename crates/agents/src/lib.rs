//! The autonomous multi-agent runtime of AEGIS.
//!
//! A supervisor and six specialized agents work on tasks. They share the Defensive Graph.
//! They reason with a model through the [`ModelProvider`](aegis_contracts::ModelProvider)
//! contract. They propose response actions. They never change the environment of the
//! operator: only the [`ActionDispatcher`](aegis_contracts::ActionDispatcher) can do that,
//! under the policy of the operator.
//!
//! This crate is defensive only. No agent scans, probes, or attacks a system.
//!
//! # Modules
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`runtime`] | The [`AgentRuntime`]: the task queue, the guard rails, and the output path. |
//! | [`agents`] | The Supervisor, Monitor, Hunter, Analyst, Responder, Deception, and Reporter agents. |
//! | [`config`] | The configuration structures. |
//! | [`llm`] | Model helpers: JSON answers with validation, and a tool loop with a step limit. |
//! | [`prompt`] | Prompts that keep instructions and untrusted data apart. |
//! | [`tools`] | Read-only tools for the Defensive Graph and the incident store. |
//! | [`ledger`] | The record of proposed actions in the timeline of an incident. |
//! | [`report`] | The incident report as a structure, as JSON, and as Markdown. |
//! | [`graph_ops`] | The property names that the agents use on graph nodes. |
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use aegis_agents::{AgentRuntime, RuntimeConfig};
//! use aegis_contracts::AuditLog;
//! use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
//! // The model has no script, so each agent uses its deterministic path.
//! let harness = Harness::new(ScriptedModel::new("local"));
//! let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
//! let runtime = AgentRuntime::builder(harness.context("Keep this tenant safe."), dispatcher)
//!     .config(RuntimeConfig::default())
//!     .with_default_agents()
//!     .build()?;
//!
//! runtime.submit_goal("Keep this tenant safe.")?;
//! let report = runtime.run_until_idle().await?;
//!
//! // The Supervisor made one task for the Monitor, the Hunter, and the Deception agent.
//! assert_eq!(report.tasks_completed, 4);
//! assert_eq!(report.tasks_failed, 0);
//! assert!(runtime.is_idle());
//! assert!(harness.audit.verify().await?.valid);
//! # Ok(())
//! # })
//! # }
//! ```

pub mod agents;
pub mod config;
pub mod error;
pub mod graph_ops;
pub mod ledger;
pub mod llm;
pub mod prompt;
pub mod report;
pub mod runtime;
mod support;
pub mod tools;

pub use agents::Roster;
pub use config::{
    AnalystConfig, BUILT_IN_ROLES, DeceptionConfig, HunterConfig, MAX_SECONDS, MonitorConfig,
    ResponderConfig, RuntimeConfig, RuntimeLimits,
};
pub use error::ModelCallError;
pub use report::IncidentReport;
pub use runtime::{
    AgentRuntime, AgentRuntimeBuilder, RunReport, RuntimeState, TaskRecord, TaskState,
};
/// The token that stops [`AgentRuntime::run`].
pub use tokio_util::sync::CancellationToken;

/// Runs the example of `README.md` as a documentation test.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
