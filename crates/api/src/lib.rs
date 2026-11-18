//! The HTTP API, the embedded web console, and the ChatOps endpoints of AEGIS.
//!
//! The crate has no composition logic. [`ApiState`] holds the services that the API reads
//! and drives. A test fills it with the in-memory services of the test kit. The
//! composition root fills it with the real services.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`ApiState`], [`ApiParts`] | The services of the API. |
//! | [`ApprovalActions`], [`ApprovalDecision`] | The path for approval decisions. The composition root implements it. |
//! | [`ApiConfig`] | The configuration: the address, the principals, the limits, and ChatOps. |
//! | [`router`] | Builds the `axum` router. |
//! | [`serve`], [`serve_on`] | Run the server until a shutdown signal. |
//! | [`route_permissions`] | The permission that each REST route needs. |
//! | [`chatops`] | The Slack and Teams endpoints, and the notification task. |
//!
//! # Security
//!
//! - **Fail closed.** Each REST route but `GET /healthz` needs a bearer token of a
//!   configured principal and a permission. With no principals, each such route answers
//!   401. A ChatOps request needs a valid signature.
//! - **One access check.** [`aegis_policy::Rbac`] decides each permission, for REST, for
//!   gRPC, and for ChatOps.
//! - **Untrusted data.** Incident text, event text, and audit text can come from an
//!   attacker. The console shows it as text only. The chat formats escape it.
//! - **No secrets in the configuration.** The configuration names environment variables.
//!
//! This crate is defensive only. It reads the state of AEGIS and sends the decisions of
//! the operator to the action path. It has no function that acts on a system that the
//! operator does not own.
//!
//! # Example
//!
//! ```
//! use aegis_api::{ApiConfig, PrincipalConfig};
//!
//! let config: ApiConfig = serde_json::from_value(serde_json::json!({
//!     "bind": "127.0.0.1:8080",
//!     "principals": [
//!         { "id": "alice@example.com", "roles": ["approver"], "token_env": "AEGIS_TOKEN_ALICE" }
//!     ]
//! }))?;
//! assert_eq!(
//!     config.principals,
//!     [PrincipalConfig::human("alice@example.com", &["approver"], "AEGIS_TOKEN_ALICE")]
//! );
//! config.validate()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod auth;
pub mod chatops;
pub mod config;
mod console;
mod error;
mod extract;
#[cfg(feature = "grpc")]
pub mod grpc;
mod ops;
mod routes;
mod security;
mod server;
mod state;
mod text;

pub use auth::MIN_TOKEN_CHARACTERS;
pub use config::{
    ApiConfig, ChatOpsConfig, LimitsConfig, NotificationConfig, PrincipalConfig, SlackConfig,
    TeamsConfig,
};
pub use console::{ConsoleAsset, console_assets};
pub use routes::{API_BASE, RoutePermission, route_permissions};
pub use security::{API_CONTENT_SECURITY_POLICY, CONSOLE_CONTENT_SECURITY_POLICY};
pub use server::{router, serve, serve_on};
pub use state::{
    ApiParts, ApiState, ApprovalActions, ApprovalDecision, EnvLookup, FloodStatus, RevertActions,
    StatusSource, SystemStatus, process_env,
};

/// Compiles the examples of the README file when the documentation tests run.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
