//! The webhook action connector.
//!
//! The connector sends one signed JSON document to an HTTPS endpoint of the operator. The
//! operator points each action type at the automation that does it: a chat channel, a ticket
//! system, a firewall, an EDR product, or a vault.
//!
//! # Signature
//!
//! Each request has three headers:
//!
//! | Header | Contents |
//! | --- | --- |
//! | [`TIMESTAMP_HEADER`] | The send time, in seconds since the Unix epoch. |
//! | [`SIGNATURE_HEADER`] | `sha256=` and the HMAC-SHA256 of `{timestamp}.{body}`, in hexadecimal. |
//! | [`DELIVERY_HEADER`] | The identifier of the action request. |
//!
//! The receiver must compute the same HMAC with the shared secret and compare the values in
//! constant time. The receiver must also refuse a timestamp that is too old. Use
//! [`verify_signature`] in a receiver that you write in Rust.
//!
//! # Revert
//!
//! `revert` sends the same document with the operation `revert` to an endpoint that the
//! configuration marks `reversible`. When the dispatcher reverts an action, the action in
//! the document has one more parameter, `execution_details`: the details of the outcome of
//! the execution. `execution_details.external_reference` is the `id` and the `url` that the
//! receiver returned for the execution, so the receiver can find its own work item.
//!
//! # Friction: `raise_friction`
//!
//! The custom action [`RAISE_FRICTION`](crate::friction::RAISE_FRICTION) is a friction
//! action for the controls of the operator. Refer to [`friction`]. Point
//! its endpoint at an automation that you own, for example an automation that turns on a
//! strict conditional-access policy or a change freeze.
//!
//! - On the operation `execute`, the receiver raises the control.
//! - On the operation `revert`, the receiver puts the control in its earlier state.
//!
//! The connector sends the parameters of the request and does not read them. The samples
//! use `control` for the name of the control and `level` for its level. Refer to
//! [`friction::parameter`].
//!
//! A friction action must be reversible. The connector refuses a configuration with an
//! endpoint for a friction action that does not have `reversible: true`.

use std::fmt;
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use url::Url;

use super::http;
use crate::friction;
use crate::names::{entity_label, snake_name, truncate};

/// The header that holds the signature of the request.
pub const SIGNATURE_HEADER: &str = "x-aegis-signature";
/// The header that holds the send time, in seconds since the Unix epoch.
pub const TIMESTAMP_HEADER: &str = "x-aegis-timestamp";
/// The header that holds the identifier of the action request.
pub const DELIVERY_HEADER: &str = "x-aegis-delivery";
/// The value of [`WebhookPayload::schema`].
pub const PAYLOAD_SCHEMA: &str = "aegis.webhook.v1";
/// The minimum length of the shared secret, in bytes.
pub const MIN_SECRET_BYTES: usize = 16;

const SIGNATURE_PREFIX: &str = "sha256=";
const VENDOR: &str = "aegis";
const PRODUCT: &str = "webhook";
const DEFAULT_NAME: &str = "webhook";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const RESPONSE_LIMIT: usize = 64 * 1024;
const REFERENCE_LIMIT: usize = 256;

fn default_name() -> String {
    DEFAULT_NAME.to_owned()
}

fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

/// The endpoint for one action type.
///
/// The `Debug` output does not show the URL, because a webhook URL can hold a secret.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpoint {
    /// The action type that this endpoint does.
    pub kind: ActionKind,
    /// The URL of the endpoint. It must use `https`, or `http` with a loopback host.
    pub url: String,
    /// `true` if the endpoint can undo the action when it receives the operation `revert`.
    #[serde(default)]
    pub reversible: bool,
}

impl fmt::Debug for WebhookEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookEndpoint")
            .field("kind", &self.kind)
            .field("url", &"[REDACTED]")
            .field("reversible", &self.reversible)
            .finish()
    }
}

/// The configuration of a [`WebhookConnector`].
///
/// The `Debug` output does not show the secret or the URLs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// The name of the connector instance. The default is `webhook`.
    #[serde(default = "default_name")]
    pub name: String,
    /// The shared secret for the HMAC-SHA256 signature. It has 16 bytes or more.
    pub secret: SecretString,
    /// One endpoint for each action type that the connector does.
    pub endpoints: Vec<WebhookEndpoint>,
    /// The maximum time for one HTTP request, in seconds. The default is 30.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl WebhookConfig {
    /// Makes a configuration with no endpoints and the default settings.
    pub fn new(name: impl Into<String>, secret: SecretString) -> Self {
        Self {
            name: name.into(),
            secret,
            endpoints: Vec::new(),
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    /// Adds the endpoint for one action type.
    #[must_use]
    pub fn endpoint(mut self, kind: ActionKind, url: impl Into<String>, reversible: bool) -> Self {
        self.endpoints.push(WebhookEndpoint {
            kind,
            url: url.into(),
            reversible,
        });
        self
    }
}

/// What the receiver must do with the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookOperation {
    /// Do the action.
    Execute,
    /// Undo the action.
    Revert,
}

/// The JSON document that the connector sends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// The version of the document format. Refer to [`PAYLOAD_SCHEMA`].
    pub schema: String,
    /// What the receiver must do with the action.
    pub operation: WebhookOperation,
    /// The action request.
    pub action: ActionRequest,
    /// The time at which the connector sent the document.
    pub sent_at: DateTime<Utc>,
}

fn mac(secret: &SecretString, timestamp: i64, body: &[u8]) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| Error::Config("the webhook secret is not a valid HMAC key".to_owned()))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(mac)
}

/// Returns the value of [`SIGNATURE_HEADER`] for a request body and a send time.
///
/// The value is `sha256=` and the HMAC-SHA256 of `{timestamp}.{body}`, in hexadecimal.
pub fn sign(secret: &SecretString, timestamp: i64, body: &[u8]) -> Result<String> {
    let digest = mac(secret, timestamp, body)?.finalize().into_bytes();
    Ok(format!("{SIGNATURE_PREFIX}{}", hex::encode(digest)))
}

/// Returns `true` if `signature` is the correct [`SIGNATURE_HEADER`] value.
///
/// The comparison takes the same time for each wrong value. The caller must also examine
/// the age of `timestamp`.
#[must_use]
pub fn verify_signature(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
    signature: &str,
) -> bool {
    let Some(digest) = signature
        .strip_prefix(SIGNATURE_PREFIX)
        .and_then(|text| hex::decode(text).ok())
    else {
        return false;
    };
    mac(secret, timestamp, body).is_ok_and(|mac| mac.verify_slice(&digest).is_ok())
}

struct Endpoint {
    kind: ActionKind,
    url: Url,
    reversible: bool,
}

/// An action connector that sends signed JSON documents to endpoints of the operator.
pub struct WebhookConnector {
    name: String,
    secret: SecretString,
    endpoints: Vec<Endpoint>,
    client: Client,
}

impl WebhookConnector {
    /// Makes a connector.
    ///
    /// Returns [`Error::Config`] if the name is empty, the secret is too short, no endpoint
    /// is set, an action type has two endpoints, a URL is not safe, or the endpoint of a
    /// friction action is not reversible. A URL must use `https`. Plain `http` is permitted
    /// only for a loopback host.
    pub fn new(config: WebhookConfig) -> Result<Self> {
        let name = config.name.trim();
        if name.is_empty() {
            return Err(Error::Config(
                "a webhook connector must have a name".to_owned(),
            ));
        }
        if config.secret.expose_secret().len() < MIN_SECRET_BYTES {
            return Err(Error::Config(format!(
                "the secret of webhook connector {name} must have {MIN_SECRET_BYTES} bytes or more"
            )));
        }
        if config.endpoints.is_empty() {
            return Err(Error::Config(format!(
                "webhook connector {name} must have one endpoint or more"
            )));
        }
        let mut endpoints: Vec<Endpoint> = Vec::with_capacity(config.endpoints.len());
        for endpoint in config.endpoints {
            let kind = snake_name(&endpoint.kind);
            if matches!(&endpoint.kind, ActionKind::Custom(custom) if custom.trim().is_empty()) {
                return Err(Error::Config(format!(
                    "webhook connector {name} has a custom action with no name"
                )));
            }
            if endpoints.iter().any(|known| known.kind == endpoint.kind) {
                return Err(Error::Config(format!(
                    "webhook connector {name} has two endpoints for the action {kind}"
                )));
            }
            if friction::is_friction(&endpoint.kind) && !endpoint.reversible {
                return Err(Error::Config(format!(
                    "the endpoint of webhook connector {name} for the friction action {kind} must have reversible = true; a friction action must have an inverse"
                )));
            }
            let what = format!("the endpoint of webhook connector {name} for the action {kind}");
            endpoints.push(Endpoint {
                url: http::secure_url(&endpoint.url, &what)?,
                kind: endpoint.kind,
                reversible: endpoint.reversible,
            });
        }
        Ok(Self {
            name: name.to_owned(),
            secret: config.secret,
            endpoints,
            client: http::client(Duration::from_secs(config.timeout_seconds))?,
        })
    }

    fn endpoint(&self, kind: &ActionKind) -> Result<&Endpoint> {
        self.endpoints
            .iter()
            .find(|endpoint| &endpoint.kind == kind)
            .ok_or_else(|| {
                Error::Unsupported(format!(
                    "webhook connector {} has no endpoint for the action {}",
                    self.name,
                    snake_name(kind)
                ))
            })
    }

    async fn deliver(
        &self,
        request: &ActionRequest,
        operation: WebhookOperation,
    ) -> Result<ActionOutcome> {
        let endpoint = self.endpoint(&request.kind)?;
        if operation == WebhookOperation::Revert && !endpoint.reversible {
            return Err(Error::Unsupported(format!(
                "the endpoint of webhook connector {} for the action {} cannot undo an action",
                self.name,
                snake_name(&request.kind)
            )));
        }
        let host = http::host_label(&endpoint.url);
        let kind = snake_name(&request.kind);
        let label = entity_label(&request.target);
        let operation_name = snake_name(&operation);
        let outcome = |status, message, details| ActionOutcome {
            action_id: request.id,
            status,
            connector: self.name.clone(),
            message,
            details,
            reversible: endpoint.reversible,
            completed_at: Utc::now(),
        };
        if request.dry_run {
            return Ok(outcome(
                ActionStatus::Simulated,
                format!(
                    "Would send the operation {operation_name} of the action {kind} for {label} to {host}. This was a dry run. Nothing changed."
                ),
                json!({ "endpoint_host": host, "operation": operation }),
            ));
        }

        let sent_at = Utc::now();
        let body = serde_json::to_vec(&WebhookPayload {
            schema: PAYLOAD_SCHEMA.to_owned(),
            operation,
            action: request.clone(),
            sent_at,
        })?;
        let timestamp = sent_at.timestamp();
        let signature = sign(&self.secret, timestamp, &body)?;
        let what = format!("webhook {} to {host} for the action {kind}", self.name);
        let response = self
            .client
            .post(endpoint.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(SIGNATURE_HEADER, signature)
            .header(DELIVERY_HEADER, request.id.to_string())
            .body(body)
            .send()
            .await
            .map_err(|error| http::transport_error(error, &what))?;
        let status = response.status();
        if !status.is_success() {
            return Err(http::status_error(status, &what, None));
        }
        let reply = http::read_limited(response, RESPONSE_LIMIT, &what).await?;
        Ok(outcome(
            ActionStatus::Succeeded,
            format!(
                "Sent the operation {operation_name} of the action {kind} for {label} to {host}."
            ),
            json!({
                "endpoint_host": host,
                "operation": operation,
                "http_status": status.as_u16(),
                "external_reference": external_reference(&reply),
            }),
        ))
    }
}

/// Reads the reference that the receiver gives to its work item, for example a ticket.
///
/// The connector reads only the fields `id` and `url` of a JSON object. No other part of
/// the response goes into the outcome.
fn external_reference(reply: &[u8]) -> Value {
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(reply) else {
        return Value::Null;
    };
    let read = |name: &str| match fields.get(name) {
        Some(Value::String(text)) => Some(truncate(text, REFERENCE_LIMIT)),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => None,
    };
    match (read("id"), read("url")) {
        (None, None) => Value::Null,
        (id, url) => json!({ "id": id, "url": url }),
    }
}

#[async_trait]
impl ActionConnector for WebhookConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: VENDOR.to_owned(),
            product: PRODUCT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.kind.clone())
            .collect()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.deliver(request, WebhookOperation::Execute).await
    }

    /// Sends the operation `revert` to an endpoint that the configuration marks reversible.
    ///
    /// Returns [`Error::Unsupported`] for an endpoint that is not reversible.
    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.deliver(request, WebhookOperation::Revert).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretString {
        SecretString::from("0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn a_signature_verifies_only_for_the_same_secret_time_and_body() {
        let signature = sign(&secret(), 1_800_000_000, b"{\"a\":1}").unwrap();
        assert!(signature.starts_with("sha256="), "{signature}");
        assert_eq!(signature.len(), "sha256=".len() + 64);
        assert!(verify_signature(
            &secret(),
            1_800_000_000,
            b"{\"a\":1}",
            &signature
        ));

        assert!(!verify_signature(
            &secret(),
            1_800_000_001,
            b"{\"a\":1}",
            &signature
        ));
        assert!(!verify_signature(
            &secret(),
            1_800_000_000,
            b"{\"a\":2}",
            &signature
        ));
        let other = SecretString::from("ffffffffffffffffffffffffffffffff");
        assert!(!verify_signature(
            &other,
            1_800_000_000,
            b"{\"a\":1}",
            &signature
        ));
        assert!(!verify_signature(
            &secret(),
            1_800_000_000,
            b"{\"a\":1}",
            &signature[7..]
        ));
        assert!(!verify_signature(
            &secret(),
            1_800_000_000,
            b"{\"a\":1}",
            "sha256=zz"
        ));
    }

    #[test]
    fn the_signature_is_the_documented_hmac() {
        // The expected value comes from a different HMAC-SHA256 implementation:
        // printf '1800000000.{"a":1}' | openssl dgst -sha256 -hmac 0123456789abcdef0123456789abcdef
        assert_eq!(
            sign(&secret(), 1_800_000_000, b"{\"a\":1}").unwrap(),
            "sha256=d40e555bc2c1dae21953757b24b165a171698880732ac310a5c8cf0ab751abf2"
        );
    }

    #[test]
    fn the_reference_reads_only_the_id_and_the_url() {
        assert_eq!(
            external_reference(
                br#"{"id":"TICKET-42","url":"https://tickets.example.com/42","token":"x"}"#
            ),
            json!({ "id": "TICKET-42", "url": "https://tickets.example.com/42" })
        );
        assert_eq!(
            external_reference(br#"{"id":42}"#),
            json!({ "id": "42", "url": null })
        );
        assert_eq!(external_reference(b"ok"), Value::Null);
        assert_eq!(external_reference(br#"{"status":"queued"}"#), Value::Null);
        assert_eq!(external_reference(br#"["id"]"#), Value::Null);
    }

    #[test]
    fn the_debug_output_hides_the_secret_and_the_urls() {
        let config = WebhookConfig::new("soc", secret()).endpoint(
            ActionKind::Notify,
            "https://hooks.example.com/services/T0/path-token",
            false,
        );
        let text = format!("{config:?}");
        assert!(text.contains("Notify"), "{text}");
        assert!(!text.contains("path-token"), "{text}");
        assert!(!text.contains("0123456789abcdef"), "{text}");
    }
}
