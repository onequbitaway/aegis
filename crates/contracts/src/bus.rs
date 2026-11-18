//! The message bus between subsystems.
//!
//! Subjects use the NATS format: tokens with `.` between them. A subscription pattern can
//! use `*` for one token and `>` for all remaining tokens.

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::Result;

/// The subjects that AEGIS subsystems use. Payloads are JSON.
pub mod subject {
    /// Normalized events. Publish to `aegis.events.{connector}`. Payload: `Event`.
    pub const EVENTS: &str = "aegis.events";
    /// Detections. Publish to `aegis.detections.{tier}`. Payload: `Detection`.
    pub const DETECTIONS: &str = "aegis.detections";
    /// New and changed incidents. Payload: `Incident`.
    pub const INCIDENTS: &str = "aegis.incidents";
    /// Tasks for agents. Publish to `aegis.agents.tasks.{role}`. Payload: `AgentTask`.
    pub const AGENT_TASKS: &str = "aegis.agents.tasks";
    /// Action requests from agents and playbooks. Payload: `ActionRequest`.
    pub const ACTION_REQUESTS: &str = "aegis.actions.requests";
    /// Action results. Payload: `ActionDisposition`.
    pub const ACTION_RESULTS: &str = "aegis.actions.results";
    /// New and decided approval requests. Payload: `ApprovalRequest`.
    pub const APPROVALS: &str = "aegis.approvals";
    /// New audit records. Payload: `AuditRecord`.
    pub const AUDIT: &str = "aegis.audit";
}

/// One message from the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusMessage {
    /// The subject of the message.
    pub subject: String,
    /// The payload of the message.
    pub payload: Vec<u8>,
}

impl BusMessage {
    /// Decodes the JSON payload.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.payload)?)
    }
}

/// A stream of messages from a subscription.
pub type BusStream = BoxStream<'static, Result<BusMessage>>;

/// A publish and subscribe bus.
#[async_trait]
pub trait MessageBus: Send + Sync {
    /// Publishes one message.
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()>;

    /// Subscribes to the subjects that match `pattern`.
    ///
    /// With `durable` set to `None`, the subscription gets only new messages.
    ///
    /// With a durable name, the bus keeps the position of the consumer. A new durable name
    /// starts at the first message that the bus holds. A consumer that starts again with
    /// the same name continues after its last message. Consumers that share one durable
    /// name share the messages: each message goes to one of them.
    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream>;
}

/// Encodes a value as a JSON payload.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

/// Encodes a value as JSON and publishes it.
pub async fn publish_json<T: Serialize + Sync + ?Sized>(
    bus: &dyn MessageBus,
    subject: &str,
    value: &T,
) -> Result<()> {
    bus.publish(subject, encode(value)?).await
}

/// Returns `true` if `subject` matches the subscription `pattern`.
///
/// `*` matches one token. `>` matches one or more remaining tokens and must be the last
/// token of the pattern.
#[must_use]
pub fn subject_matches(pattern: &str, subject: &str) -> bool {
    let mut pattern_tokens = pattern.split('.');
    let mut subject_tokens = subject.split('.');
    loop {
        match (pattern_tokens.next(), subject_tokens.next()) {
            (Some(">"), Some(_)) => return pattern_tokens.next().is_none(),
            (Some("*"), Some(_)) => {}
            (Some(expected), Some(found)) if expected == found => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}
