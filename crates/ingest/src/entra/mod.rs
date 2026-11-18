//! The source connector for Microsoft Entra ID.
//!
//! [`EntraSource`] reads the sign-in logs and the directory audit log of one tenant through
//! Microsoft Graph. The [`normalize`] module converts the records to normalized events.
//!
//! The connector only reads. It needs the application permission `AuditLog.Read.All`.

mod client;
mod config;
pub mod normalize;
mod source;

pub use config::EntraConfig;
pub use source::EntraSource;
