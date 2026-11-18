//! Response and actuation for AEGIS.
//!
//! This crate is the only path from a proposed action to a change in the environment of
//! the operator. Each action goes through policy, approval, a connector, and the audit log.
//!
//! All actions are defensive. A connector changes only the environment of the operator,
//! through the administrative API of the product: it disables an account, revokes a
//! credential, blocks an address in the firewall of the operator, or opens a ticket.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`registry`] | [`ActionRegistry`]: the named connectors and the routing table. |
//! | [`dispatcher`] | [`Dispatcher`]: policy, approval, execution, revert, and audit for each request. |
//! | [`revert`] | [`RevertScheduler`] and [`RevertStore`]: contain first, with a timed revert. |
//! | [`friction`] | The friction actions: reversible changes that slow an attacker. |
//! | [`connectors`] | [`GraphActionConnector`] for Microsoft Entra ID and [`WebhookConnector`]. |
//! | [`playbook`] | [`PlaybookEngine`], the YAML playbook format, and [`draft_response`]. |
//! | [`deception`] | [`HoneytokenRegistry`], [`HoneytokenTripDetector`], and [`HoneytokenConnector`]. |
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use aegis_contracts::action::{ActionDispatcher, ActionDisposition, ActionKind, ActionRequest};
//! use aegis_contracts::common::{EntityKind, EntityRef};
//! use aegis_contracts::policy::{Principal, PrincipalKind};
//! use aegis_respond::{ActionRegistry, Dispatcher, HoneytokenConnector, HoneytokenRegistry};
//! use aegis_respond::deception::MemoryHoneytokenStore;
//! use aegis_testkit::{MemoryApprovals, MemoryAuditLog, StaticPolicy};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> aegis_contracts::Result<()> {
//! let honeytokens =
//!     Arc::new(HoneytokenRegistry::open(Arc::new(MemoryHoneytokenStore::default())).await?);
//! let mut registry = ActionRegistry::new();
//! registry.register(Arc::new(HoneytokenConnector::new("deception", honeytokens)))?;
//!
//! let audit = Arc::new(MemoryAuditLog::default());
//! let dispatcher = Dispatcher::builder(
//!     Arc::new(registry),
//!     Arc::new(StaticPolicy::AllowAll),
//!     Arc::new(MemoryApprovals::default()),
//!     audit.clone(),
//! )
//! .dry_run(true)
//! .build();
//!
//! let request = ActionRequest::new(
//!     ActionKind::DeployHoneytoken,
//!     EntityRef::new(EntityKind::Secret, "kv-prod/legacy-admin-password"),
//!     "deception",
//!     "Plant a decoy secret in the production vault.",
//! );
//! let principal = Principal::new("deception", PrincipalKind::Agent, &["agent"]);
//! let disposition = dispatcher.dispatch(request, &principal).await?;
//!
//! assert!(matches!(disposition, ActionDisposition::Executed(_)));
//! assert_eq!(audit.records().len(), 3);
//! # Ok(())
//! # }
//! ```

use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod connectors;
pub mod deception;
pub mod dispatcher;
pub mod friction;
mod names;
pub mod playbook;
pub mod registry;
pub mod revert;

pub use connectors::{
    GraphActionConnector, GraphConfig, MemorySecretSink, RotatedSecret, SecretSink, WebhookConfig,
    WebhookConnector, WebhookEndpoint,
};
pub use deception::{
    Honeytoken, HoneytokenConnector, HoneytokenKind, HoneytokenRegistry, HoneytokenRequest,
    HoneytokenStore, HoneytokenTripDetector, MemoryHoneytokenStore,
};
pub use dispatcher::{Dispatcher, DispatcherBuilder};
pub use playbook::{
    DraftError, DraftOptions, Playbook, PlaybookEngine, PlaybookError, PlaybookRun, RunMode,
    StepResult, StepRun, draft_response,
};
pub use registry::{ActionRegistry, Route};
pub use revert::{
    FileRevertStore, MemoryRevertStore, PendingRevert, PendingState, RevertAttempt, RevertClock,
    RevertProgress, RevertScheduler, RevertSchedulerConfig, RevertStats, RevertStore,
};

/// Compiles and runs the examples of the crate `README.md` as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_examples {}

/// Locks a mutex. A panic in a different thread does not make the data unavailable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
