//! Model provider adapters and the model router for AEGIS.
//!
//! This crate puts each LLM behind the [`ModelProvider`](aegis_contracts::ModelProvider)
//! contract. Agents and detectors write a request one time. The router selects a provider
//! and a model for the task kind of the request.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`OpenAiCompatibleProvider`] | The adapter for the OpenAI chat-completions format. It covers hosted APIs, gateways, Ollama, and vLLM. |
//! | [`AnthropicProvider`] | The adapter for the Anthropic Messages API. |
//! | [`Router`] | Route selection for each task kind, fallback, token budgets, and usage counters. |
//! | [`ModelConfig`] and [`build_router`] | The configuration section and the function that builds the router from it. |
//!
//! # Example
//!
//! This example builds a router for one local server. It does not use the network.
//!
//! ```
//! use std::sync::Arc;
//!
//! use aegis_contracts::model::{ModelProvider, TaskKind};
//! use aegis_model::{OLLAMA_BASE_URL, OpenAiCompatibleProvider, Route, Router};
//!
//! # fn main() -> aegis_contracts::Result<()> {
//! let local = OpenAiCompatibleProvider::local(OLLAMA_BASE_URL, "llama3.1")?;
//! let router = Router::builder()
//!     .provider(Arc::new(local))
//!     .default_routes(vec![Route::new("local")])
//!     .route(TaskKind::Triage, vec![Route::new("local").with_model("llama3.1:8b")])
//!     .build()?;
//!
//! assert_eq!(router.name(), "router");
//! assert_eq!(router.routes(TaskKind::Analysis), [Route::new("local")]);
//! # Ok(())
//! # }
//! ```
//!
//! # Errors and secrets
//!
//! Each adapter maps a provider failure to one [`aegis_contracts::Error`] variant. An
//! error message has the provider name, the HTTP status, and the error identifiers of the
//! provider. It never has an API key, a prompt, or the message text of the provider.

use std::time::Duration;

mod anthropic;
mod config;
mod convert;
mod http;
mod openai;
mod router;
mod sse;

pub use anthropic::{
    ANTHROPIC_BASE_URL, ANTHROPIC_VERSION, AnthropicConfig, AnthropicProvider,
    DEFAULT_MAX_OUTPUT_TOKENS,
};
pub use config::{ModelConfig, ProviderConfig, RoutesConfig, build_router, process_env};
pub use openai::{
    MaxTokensField, OLLAMA_BASE_URL, OpenAiCompatibleConfig, OpenAiCompatibleProvider,
};
pub use router::{
    Budget, DEFAULT_BUDGET_WINDOW, DEFAULT_ROUTER_NAME, Route, Router, RouterBuilder, RouterUsage,
    TASK_KINDS, UsageCounters, task_name,
};
pub use secrecy::SecretString;

/// The default timeout of one request to a provider.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
