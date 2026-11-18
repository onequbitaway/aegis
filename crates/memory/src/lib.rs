//! In-memory implementations of the AEGIS storage contracts.
//!
//! Use these implementations for a deployment with no database, for example a
//! monitor-only installation or a demonstration. All data is lost when the process stops.
//! For durable storage, use the PostgreSQL implementations.
//!
//! | Item | Contract |
//! | --- | --- |
//! | [`MemoryGraph`] | [`DefensiveGraph`](aegis_contracts::DefensiveGraph) |
//! | [`MemoryVectors`] | [`VectorStore`](aegis_contracts::VectorStore) |
//! | [`MemoryIncidents`] | [`IncidentStore`](aegis_contracts::IncidentStore) |
//! | [`MemoryApprovals`] | [`ApprovalQueue`](aegis_contracts::ApprovalQueue) |

use std::sync::{Mutex, MutexGuard, PoisonError};

mod approvals;
mod store;

pub use approvals::MemoryApprovals;
pub use store::{MemoryGraph, MemoryIncidents, MemoryVectors};

/// Locks a mutex. A panic in a different thread does not make the data unavailable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
