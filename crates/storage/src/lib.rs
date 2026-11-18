//! PostgreSQL storage for AEGIS.
//!
//! One PostgreSQL database holds all durable AEGIS state. [`PgStore`] owns the connection
//! pool and gives one repository for each storage contract.
//!
//! | Repository | Contract | Storage |
//! | --- | --- | --- |
//! | [`PgGraph`] | [`DefensiveGraph`](aegis_contracts::DefensiveGraph) | Apache AGE graph `aegis_graph` |
//! | [`PgVectors`] | [`VectorStore`](aegis_contracts::VectorStore) | pgvector table `aegis.vectors` |
//! | [`PgIncidents`] | [`IncidentStore`](aegis_contracts::IncidentStore) | Table `aegis.incidents` |
//! | [`PgAuditLog`] | [`AuditLog`](aegis_contracts::AuditLog) | Table `aegis.audit_log` |
//! | [`PgApprovals`] | [`ApprovalQueue`](aegis_contracts::ApprovalQueue) | Table `aegis.approvals` |
//!
//! # Use
//!
//! ```no_run
//! use aegis_storage::{PgStore, StorageConfig};
//!
//! # async fn example() -> aegis_contracts::Result<()> {
//! let config = StorageConfig::new("postgres://aegis:secret@localhost/aegis?sslmode=verify-full");
//! let store = PgStore::connect(&config).await?;
//! store.migrate().await?;
//! let graph = store.graph();
//! let audit = store.audit();
//! # Ok(())
//! # }
//! ```
//!
//! # Security rules
//!
//! - Each value goes to the database as a bound parameter. No statement contains a value.
//! - A relation name becomes an edge label, and a label cannot be a parameter. The graph
//!   accepts only names that match `^[a-z][a-z0-9_]*$`.
//! - The database URL is a secret. No error and no log line contains it.
//! - The audit table is append-only. Triggers reject each change and each record that does
//!   not continue the hash chain. The application role needs only `INSERT` and `SELECT` on
//!   that table.
//! - An approval request gets one decision. One statement checks the state and changes it.
//!
//! # Several processes
//!
//! Several processes can use one database at the same time. Advisory locks in the database
//! put the appends to the audit log in one order, and the writes to one graph node or one
//! graph relation in one order.
//!
//! The README of the crate gives the configuration, the privileges of the application role,
//! and the instructions for the tests.

mod agtype;
mod approvals;
mod audit;
mod config;
mod error;
mod graph;
mod incidents;
mod json;
mod migrations;
mod store;
mod vectors;

pub use approvals::PgApprovals;
pub use audit::PgAuditLog;
pub use config::StorageConfig;
pub use graph::{MAX_NODE_ID_BYTES, MAX_RELATION_NAME_BYTES, PgGraph};
pub use incidents::PgIncidents;
pub use store::PgStore;
pub use vectors::{MAX_DIMENSIONS, PgVectors};
