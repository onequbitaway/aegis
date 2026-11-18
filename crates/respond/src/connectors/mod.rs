//! Action connectors. Each connector does response actions in one system of the operator.
//!
//! | Connector | System |
//! | --- | --- |
//! | [`GraphActionConnector`] | Microsoft Entra ID, through Microsoft Graph. |
//! | [`WebhookConnector`] | An HTTPS endpoint of the operator: chat, tickets, firewall, EDR, vault. |
//!
//! Each connector obeys [`ActionRequest::dry_run`](aegis_contracts::ActionRequest). A dry
//! run sends no HTTP request.
//!
//! Each connector maps HTTP failures to contract errors in the same way:
//!
//! | HTTP status | Error |
//! | --- | --- |
//! | 401, 403 | [`Error::Unauthorized`](aegis_contracts::Error::Unauthorized) |
//! | 404 | [`Error::NotFound`](aegis_contracts::Error::NotFound) |
//! | 408 | [`Error::Timeout`](aegis_contracts::Error::Timeout) |
//! | 429 | [`Error::RateLimited`](aegis_contracts::Error::RateLimited) |
//! | Other 4xx | [`Error::InvalidInput`](aegis_contracts::Error::InvalidInput) |
//! | 5xx | [`Error::Unavailable`](aegis_contracts::Error::Unavailable) |

pub mod graph;
mod http;
pub mod webhook;

pub use graph::{GraphActionConnector, GraphConfig, MemorySecretSink, RotatedSecret, SecretSink};
pub use webhook::{
    WebhookConfig, WebhookConnector, WebhookEndpoint, WebhookOperation, WebhookPayload, sign,
    verify_signature,
};
