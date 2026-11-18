//! Policy, access control, approvals, and the file audit log of AEGIS.
//!
//! Each response action goes through the policy of the operator, an optional approval by a
//! person, and the audit log. This crate has the implementations of those steps.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`RegoPolicyEngine`] | Implements [`PolicyEngine`](aegis_contracts::PolicyEngine). Evaluates the Rego policy of the operator in the process. |
//! | [`Rbac`] | Checks that a principal has a [`Permission`]. |
//! | [`ApprovalService`] | Lists approval requests and records the decisions of persons. |
//! | [`FileAuditLog`] | Implements [`AuditLog`](aegis_contracts::AuditLog). Keeps the hash chain in one JSON Lines file. |
//! | [`explain`](mod@explain) | Returns the audit records that explain one action or one incident. |
//!
//! # Fail closed
//!
//! - The policy engine denies an action when the policy gives no valid decision.
//! - Role-based access control gives no permission to a role that it does not know.
//! - The approval service records no decision without an audit record.
//! - The file audit log does not append to a file that does not verify.
//!
//! # Example
//!
//! ```
//! use aegis_contracts::action::{ActionKind, ActionRequest};
//! use aegis_contracts::common::{EntityKind, EntityRef};
//! use aegis_contracts::policy::{PolicyEffect, PolicyInput, Principal, PrincipalKind};
//! use aegis_policy::{PolicySources, RegoPolicyEngine};
//!
//! # fn main() -> aegis_contracts::Result<()> {
//! let policy = r#"
//!     package aegis.response
//!
//!     default decision := {"effect": "require_approval", "reasons": ["A person must approve."]}
//!
//!     decision := {"effect": "allow", "reasons": ["A notification is safe."]} if {
//!         input.action.kind == "notify"
//!     }
//! "#;
//! let engine = RegoPolicyEngine::load(PolicySources::new().policy_text("response.rego", policy))?;
//!
//! let request = ActionRequest::new(
//!     ActionKind::Notify,
//!     EntityRef::new(EntityKind::User, "user-1"),
//!     "responder",
//!     "Tell the owner of the account.",
//! );
//! let principal = Principal::new("responder", PrincipalKind::Agent, &["agent"]);
//! let decision = engine.decide(&PolicyInput::new(request, principal));
//! assert_eq!(decision.effect, PolicyEffect::Allow);
//! # Ok(())
//! # }
//! ```

/// Compiles the Rust examples of the README file when the documentation tests run.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;

pub mod approval;
pub mod explain;
pub mod file_log;
pub mod rbac;
pub mod rego;

pub use approval::{ApprovalRules, ApprovalService};
pub use explain::{Explanation, Subject, explain_action, explain_incident};
pub use file_log::{FileAuditLog, FileAuditLogConfig};
pub use rbac::{Permission, Rbac, RbacConfig};
pub use rego::{
    DEFAULT_DECISION_RULE, DEFAULT_EVALUATION_TIME_LIMIT, DataFormat, EngineOptions,
    FAIL_CLOSED_POLICY, PolicyConfig, PolicySources, PolicyVersion, RegoPolicyEngine,
};
