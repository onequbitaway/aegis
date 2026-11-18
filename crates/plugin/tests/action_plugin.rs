//! Tests that load the example action plugin through the host.
//!
//! A `wiremock` server on a loopback address is the webhook. No request leaves the
//! computer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{EntityKind, EntityRef, Error};
use aegis_plugin::{HostLimits, PluginHost, PluginKind, PluginManifest};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The name that the operator gives to the connector instance in these tests.
const NAME: &str = "webhook-notify";

/// Makes a manifest that sends notifications to `server` and permits that destination.
fn manifest(server: &MockServer) -> PluginManifest {
    let mut manifest = common::manifest(NAME, PluginKind::Action, "example-action");
    manifest.allowed_hosts = vec![server.address().to_string()];
    manifest
        .config
        .insert("webhook_url".to_owned(), format!("{}/hook", server.uri()));
    manifest
}

async fn load(manifest: &PluginManifest) -> Arc<dyn ActionConnector> {
    let host = PluginHost::new(HostLimits::default()).unwrap();
    host.load_action(manifest).await.unwrap()
}

fn notify() -> ActionRequest {
    ActionRequest::new(
        ActionKind::Notify,
        EntityRef::new(EntityKind::User, "bob@example.com"),
        "responder",
        "Many failed sign-ins for one account.",
    )
}

/// Starts a webhook that answers each `POST /hook` with `status`.
async fn webhook(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

async fn request_count(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

#[tokio::test]
async fn info_and_supported_actions_come_from_the_plugin() {
    let server = webhook(200).await;
    let action = load(&manifest(&server)).await;
    assert_eq!(
        action.info(),
        ConnectorInfo {
            name: NAME.to_owned(),
            vendor: "aegis".to_owned(),
            product: "webhook".to_owned(),
            version: "0.1.0".to_owned(),
        }
    );
    assert_eq!(action.supported_actions(), [ActionKind::Notify]);
    // To load a plugin does not send a request.
    assert_eq!(request_count(&server).await, 0);
}

#[tokio::test]
async fn a_dry_run_makes_no_http_request() {
    let server = webhook(200).await;
    let action = load(&manifest(&server)).await;
    let mut request = notify();
    request.dry_run = true;

    let outcome = action.execute(&request).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(outcome.action_id, request.id);
    assert_eq!(outcome.connector, NAME);
    assert_eq!(
        outcome.message,
        "Would send a notification about bob@example.com to the webhook."
    );
    assert!(!outcome.reversible);
    assert_eq!(request_count(&server).await, 0);
}

#[tokio::test]
async fn a_live_execute_reaches_the_server_through_the_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let action = load(&manifest(&server)).await;
    let request = notify();
    let before = chrono::Utc::now();

    let outcome: ActionOutcome = action.execute(&request).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, request.id);
    assert_eq!(outcome.connector, NAME);
    assert_eq!(
        outcome.message,
        "Sent a notification about bob@example.com to the webhook."
    );
    assert_eq!(outcome.details, json!({ "http_status": 200 }));
    // The plugin reads the clock of the host through WASI.
    assert!(outcome.completed_at >= before - chrono::Duration::seconds(1));
    assert!(outcome.completed_at <= chrono::Utc::now() + chrono::Duration::seconds(1));

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: Value = received[0].body_json().unwrap();
    assert_eq!(
        body,
        json!({
            "text": "Many failed sign-ins for one account.",
            "action_id": request.id.to_string(),
            "target": { "kind": "user", "id": "bob@example.com" },
            "incident_id": null,
            "requested_by": "responder",
        })
    );
}

#[tokio::test]
async fn the_message_parameter_replaces_the_reason_in_the_notification() {
    let server = webhook(204).await;
    let action = load(&manifest(&server)).await;
    let mut request = notify();
    request
        .parameters
        .insert("message".to_owned(), json!("Check the account of Bob."));

    let outcome = action.execute(&request).await.unwrap();

    assert_eq!(outcome.details, json!({ "http_status": 204 }));
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: Value = received[0].body_json().unwrap();
    assert_eq!(body["text"], "Check the account of Bob.");
}

#[tokio::test]
async fn a_host_that_is_not_in_allowed_hosts_is_refused_and_no_request_leaves() {
    let server = webhook(200).await;
    let permitted = MockServer::start().await;
    // The webhook URL points to `server`, but the manifest permits a different port.
    let mut manifest = manifest(&server);
    manifest.allowed_hosts = vec![permitted.address().to_string()];
    let action = load(&manifest).await;

    let error = action.execute(&notify()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message)
        if *message == format!(
            "plugin webhook-notify: the destination {} is not in allowed_hosts",
            server.address()
        )),
        "{error:?}"
    );
    assert!(!error.is_retryable());
    assert_eq!(request_count(&server).await, 0);
    assert_eq!(request_count(&permitted).await, 0);
}

#[tokio::test]
async fn a_plugin_with_no_allowed_hosts_has_no_network() {
    let server = webhook(200).await;
    let mut manifest = manifest(&server);
    manifest.allowed_hosts.clear();
    let action = load(&manifest).await;

    let error = action.execute(&notify()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message) if message.contains("is not in allowed_hosts")),
        "{error:?}"
    );
    assert_eq!(request_count(&server).await, 0);
}

#[tokio::test]
async fn plain_http_to_a_host_that_is_not_loopback_is_refused() {
    // The destination is in the list, but plain HTTP is not permitted for it. The host
    // refuses before it resolves the name, thus the test uses no network.
    let mut manifest = common::manifest(NAME, PluginKind::Action, "example-action");
    manifest.allowed_hosts = vec!["hooks.example.com:80".to_owned()];
    manifest.config.insert(
        "webhook_url".to_owned(),
        "http://hooks.example.com/services/secret-path".to_owned(),
    );
    let action = load(&manifest).await;

    let error = action.execute(&notify()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message)
            if message.contains("plain http is permitted only for a loopback address")),
        "{error:?}"
    );
    // The error does not show the path of the webhook URL, which can be a secret.
    assert!(!error.to_string().contains("secret-path"), "{error}");
}

#[tokio::test]
async fn the_host_refuses_an_action_type_that_the_plugin_did_not_declare() {
    let server = webhook(200).await;
    let action = load(&manifest(&server)).await;
    let request = ActionRequest::new(
        ActionKind::DisableUser,
        EntityRef::new(EntityKind::User, "bob@example.com"),
        "responder",
        "Test.",
    );

    let error = action.execute(&request).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unsupported(message)
            if message == "plugin webhook-notify does not support DisableUser"),
        "{error:?}"
    );
    assert_eq!(request_count(&server).await, 0);
}

#[tokio::test]
async fn revert_is_unsupported_for_a_notification() {
    let server = webhook(200).await;
    let action = load(&manifest(&server)).await;

    let error = action.revert(&notify()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unsupported(message)
            if message == "plugin webhook-notify: A notification cannot be undone."),
        "{error:?}"
    );
    assert_eq!(request_count(&server).await, 0);
}

#[tokio::test]
async fn a_failed_webhook_maps_to_the_contract_error_of_the_same_kind() {
    let unavailable = webhook(503).await;
    let error = load(&manifest(&unavailable))
        .await
        .execute(&notify())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("HTTP 503")),
        "{error:?}"
    );
    assert!(error.is_retryable());

    let limited = webhook(429).await;
    let error = load(&manifest(&limited))
        .await
        .execute(&notify())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::RateLimited(message) if message.contains("HTTP 429")),
        "{error:?}"
    );

    let refused = webhook(401).await;
    let error = load(&manifest(&refused))
        .await
        .execute(&notify())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message.contains("HTTP 401")),
        "{error:?}"
    );
    assert!(!error.is_retryable());
    assert_eq!(request_count(&refused).await, 1);
}

#[tokio::test]
async fn a_missing_webhook_url_is_invalid_input() {
    let manifest = common::manifest(NAME, PluginKind::Action, "example-action");
    let action = load(&manifest).await;

    let error = action.execute(&notify()).await.unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("webhook_url")),
        "{error:?}"
    );
}
