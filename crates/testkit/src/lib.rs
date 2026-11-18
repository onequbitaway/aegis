//! In-memory implementations of the AEGIS contracts and shared test data.
//!
//! Each workstream tests against these implementations. The implementations obey the rules
//! in the contract documentation, so a test that passes here also describes the real
//! subsystem.
//!
//! | Item | Contract |
//! | --- | --- |
//! | [`MemoryBus`] | [`MessageBus`](aegis_contracts::MessageBus) |
//! | [`ScriptedModel`] | [`ModelProvider`](aegis_contracts::ModelProvider) |
//! | [`StaticSource`] | [`SourceConnector`](aegis_contracts::SourceConnector) |
//! | [`RecordingConnector`] | [`ActionConnector`](aegis_contracts::ActionConnector) |
//! | [`RecordingDispatcher`] | [`ActionDispatcher`](aegis_contracts::ActionDispatcher) |
//! | [`StaticPolicy`] | [`PolicyEngine`](aegis_contracts::PolicyEngine) |
//! | [`MemoryApprovals`] | [`ApprovalQueue`](aegis_contracts::ApprovalQueue) |
//! | [`MemoryAuditLog`] | [`AuditLog`](aegis_contracts::AuditLog) |
//! | [`MemoryGraph`] | [`DefensiveGraph`](aegis_contracts::DefensiveGraph) |
//! | [`MemoryVectors`] | [`VectorStore`](aegis_contracts::VectorStore) |
//! | [`MemoryIncidents`] | [`IncidentStore`](aegis_contracts::IncidentStore) |
//!
//! The [`fixtures`] module holds the recorded attack log that the detection tests and the
//! demonstration replay.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aegis_contracts::AgentContext;

mod action;
mod audit;
mod bus;
pub mod fixtures;
mod model;
mod policy;
mod source;
mod store;

pub use action::{DispatchMode, RecordingConnector, RecordingDispatcher};
pub use audit::MemoryAuditLog;
pub use bus::MemoryBus;
pub use model::{EMBEDDING_DIMENSIONS, ScriptedModel, embed_text};
pub use policy::{MemoryApprovals, StaticPolicy};
pub use source::StaticSource;
pub use store::{MemoryGraph, MemoryIncidents, MemoryVectors};

/// Locks a mutex. A panic in a different thread does not make the data unavailable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One set of in-memory services for an agent test.
pub struct Harness {
    /// The scripted model.
    pub model: Arc<ScriptedModel>,
    /// The Defensive Graph.
    pub graph: Arc<MemoryGraph>,
    /// The incident store.
    pub incidents: Arc<MemoryIncidents>,
    /// The audit log.
    pub audit: Arc<MemoryAuditLog>,
    /// The message bus.
    pub bus: Arc<MemoryBus>,
}

impl Harness {
    /// Makes a set of empty services around `model`.
    #[must_use]
    pub fn new(model: ScriptedModel) -> Self {
        Self {
            model: Arc::new(model),
            graph: Arc::new(MemoryGraph::default()),
            incidents: Arc::new(MemoryIncidents::default()),
            audit: Arc::new(MemoryAuditLog::default()),
            bus: Arc::new(MemoryBus::default()),
        }
    }

    /// Returns an agent context that uses these services.
    #[must_use]
    pub fn context(&self, goal: &str) -> AgentContext {
        AgentContext {
            goal: goal.to_owned(),
            models: self.model.clone(),
            graph: self.graph.clone(),
            incidents: self.incidents.clone(),
            audit: self.audit.clone(),
            bus: self.bus.clone(),
        }
    }
}
