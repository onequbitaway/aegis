//! Integration tests for the webhook action connector, against a mock HTTP server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use aegis_contracts::Error;
use aegis_contracts::action::{ActionConnector, ActionKind, ActionRequest, ActionStatus};
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId};
use aegis_respond::connectors::webhook::{
    DELIVERY_HEADER, PAYLOAD_SCHEMA, SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookOperation,
    WebhookPayload, verify_signature,
};
use aegis_respond::{WebhookConfig, WebhookConnector};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::Sha256;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use common::{request, spray_address};

const SECRET: &str = "webhook-secret-0123456789abcdef";

/// Returns `true` if the error has the expected variant.
type ErrorCheck = fn(&Error) -> bool;

fn secret() -> SecretString {
    SecretString::from(SECRET)
}

fn config(server: &MockServer) -> WebhookConfig {
    WebhookConfig::new("soc-bridge", secret())
        .endpoint(
            ActionKind::Notify,
            format!("{}/hooks/chat", server.uri()),
            false,
        )
        .endpoint(
            ActionKind::OpenTicket,
            format!("{}/hooks/tickets", server.uri()),
            false,
        )
        .endpoint(
            ActionKind::BlockIp,
            format!("{}/hooks/firewall", server.uri()),
            true,
        )
        .endpoint(
            ActionKind::Custom("quarantine_mailbox".to_owned()),
            format!("{}/hooks/mail", server.uri()),
            false,
        )
}

fn connector(server: &MockServer) -> WebhookConnector {
    WebhookConnector::new(config(server)).unwrap()
}

fn notify_request() -> ActionRequest {
    let mut action = request(
        ActionKind::Notify,
        EntityRef::new(EntityKind::Other, "security-operations"),
    );
    action.incident_id = Some(IncidentId::new());
    action
        .parameters
        .insert("severity".to_owned(), json!("critical"));
    action
}

async fn mount_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202).set_body_string("accepted"))
        .mount(server)
        .await;
}

fn header<'a>(request: &'a Request, name: &str) -> &'a str {
    request.headers[name].to_str().unwrap()
}

#[tokio::test]
async fn notify_posts_the_signed_request_document() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let action = notify_request();
    let before = Utc::now().timestamp();

    let outcome = connector(&server).execute(&action).await.unwrap();

    let after = Utc::now().timestamp();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(outcome.connector, "soc-bridge");
    assert!(!outcome.reversible);
    assert_eq!(outcome.details["http_status"], 202);
    assert_eq!(outcome.details["operation"], "execute");
    assert_eq!(outcome.details["external_reference"], Value::Null);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let received = &requests[0];
    assert_eq!(received.method.as_str(), "POST");
    assert_eq!(received.url.path(), "/hooks/chat");
    assert_eq!(header(received, "content-type"), "application/json");
    assert_eq!(header(received, DELIVERY_HEADER), action.id.to_string());

    let payload: WebhookPayload = serde_json::from_slice(&received.body).unwrap();
    assert_eq!(payload.schema, PAYLOAD_SCHEMA);
    assert_eq!(payload.operation, WebhookOperation::Execute);
    assert_eq!(payload.action, action);
    let document: Value = serde_json::from_slice(&received.body).unwrap();
    assert_eq!(document["schema"], "aegis.webhook.v1");
    assert_eq!(document["operation"], "execute");
    assert_eq!(document["action"]["kind"], "notify");
    assert_eq!(document["action"]["target"]["id"], "security-operations");
    assert_eq!(document["action"]["parameters"]["severity"], "critical");
    assert_eq!(
        document["action"]["reason"],
        "Contain the rogue service principal."
    );

    let timestamp: i64 = header(received, TIMESTAMP_HEADER).parse().unwrap();
    assert!((before..=after).contains(&timestamp), "{timestamp}");
    assert_eq!(payload.sent_at.timestamp(), timestamp);
}

#[tokio::test]
async fn the_signature_verifies_with_the_shared_secret() {
    let server = MockServer::start().await;
    mount_ok(&server).await;

    connector(&server).execute(&notify_request()).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let received = &requests[0];
    let timestamp: i64 = header(received, TIMESTAMP_HEADER).parse().unwrap();
    let signature = header(received, SIGNATURE_HEADER);

    // The receiver computes HMAC-SHA256 of "{timestamp}.{body}" with the shared secret.
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(&received.body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(signature, expected);

    assert!(verify_signature(
        &secret(),
        timestamp,
        &received.body,
        signature
    ));
    let mut changed = received.body.clone();
    changed[0] ^= 1;
    assert!(!verify_signature(&secret(), timestamp, &changed, signature));
    assert!(!verify_signature(
        &secret(),
        timestamp + 1,
        &received.body,
        signature
    ));
    let other = SecretString::from("a-different-secret-0123456789");
    assert!(!verify_signature(
        &other,
        timestamp,
        &received.body,
        signature
    ));
}

#[tokio::test]
async fn each_action_type_goes_to_its_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/tickets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "IR-1042",
            "url": "https://tickets.example.com/IR-1042",
            "internal_note": "do not copy this field",
        })))
        .mount(&server)
        .await;
    mount_ok(&server).await;
    let connector = connector(&server);
    let ticket = request(
        ActionKind::OpenTicket,
        EntityRef::new(EntityKind::Other, "incident-response"),
    );
    let block = request(ActionKind::BlockIp, spray_address());
    let quarantine = request(
        ActionKind::Custom("quarantine_mailbox".to_owned()),
        EntityRef::new(EntityKind::User, "user-dana"),
    );

    let ticket_outcome = connector.execute(&ticket).await.unwrap();
    let block_outcome = connector.execute(&block).await.unwrap();
    connector.execute(&quarantine).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    let seen: Vec<(String, String)> = requests
        .iter()
        .map(|received| {
            let document: Value = serde_json::from_slice(&received.body).unwrap();
            (
                received.url.path().to_owned(),
                document["action"]["kind"].to_string(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("/hooks/tickets".to_owned(), "\"open_ticket\"".to_owned()),
            ("/hooks/firewall".to_owned(), "\"block_ip\"".to_owned()),
            (
                "/hooks/mail".to_owned(),
                "{\"custom\":\"quarantine_mailbox\"}".to_owned()
            ),
        ]
    );
    assert_eq!(
        ticket_outcome.details["external_reference"],
        json!({ "id": "IR-1042", "url": "https://tickets.example.com/IR-1042" })
    );
    assert!(
        !serde_json::to_string(&ticket_outcome)
            .unwrap()
            .contains("do not copy")
    );
    assert!(block_outcome.reversible);
    assert_eq!(
        block_outcome.message,
        format!(
            "Sent the operation execute of the action block_ip for ip_address 203.0.113.50 to {}.",
            server.address()
        )
    );
    assert_eq!(
        connector.supported_actions(),
        [
            ActionKind::Notify,
            ActionKind::OpenTicket,
            ActionKind::BlockIp,
            ActionKind::Custom("quarantine_mailbox".to_owned()),
        ]
    );
    let info = connector.info();
    assert_eq!(
        (info.name.as_str(), info.product.as_str()),
        ("soc-bridge", "webhook")
    );
}

#[tokio::test]
async fn a_dry_run_sends_no_request() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let connector = connector(&server);
    let mut block = request(ActionKind::BlockIp, spray_address());
    block.dry_run = true;

    let outcome = connector.execute(&block).await.unwrap();
    let reverted = connector.revert(&block).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert!(outcome.reversible);
    assert_eq!(
        outcome.message,
        format!(
            "Would send the operation execute of the action block_ip for ip_address 203.0.113.50 to {}. This was a dry run. Nothing changed.",
            server.address()
        )
    );
    assert_eq!(reverted.status, ActionStatus::Simulated);
    assert_eq!(reverted.details["operation"], "revert");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn revert_goes_only_to_an_endpoint_that_is_reversible() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let connector = connector(&server);
    let block = request(ActionKind::BlockIp, spray_address());

    let outcome = connector.revert(&block).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/hooks/firewall");
    let payload: WebhookPayload = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload.operation, WebhookOperation::Revert);
    assert_eq!(payload.action, block);

    let error = connector.revert(&notify_request()).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unsupported(message) if message == "the endpoint of webhook connector soc-bridge for the action notify cannot undo an action"),
        "{error:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_action_type_with_no_endpoint_is_unsupported() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let connector = connector(&server);

    let isolate = connector
        .execute(&request(
            ActionKind::IsolateHost,
            EntityRef::new(EntityKind::Host, "host-1"),
        ))
        .await
        .unwrap_err();
    let other_custom = connector
        .execute(&request(
            ActionKind::Custom("purge_mailbox".to_owned()),
            EntityRef::new(EntityKind::User, "user-dana"),
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(&isolate, Error::Unsupported(message) if message == "webhook connector soc-bridge has no endpoint for the action isolate_host"),
        "{isolate:?}"
    );
    assert!(
        matches!(other_custom, Error::Unsupported(_)),
        "{other_custom:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn each_http_status_maps_to_its_contract_error() {
    let cases: [(u16, ErrorCheck); 7] = [
        (401, |error| matches!(error, Error::Unauthorized(_))),
        (403, |error| matches!(error, Error::Unauthorized(_))),
        (404, |error| matches!(error, Error::NotFound(_))),
        (429, |error| matches!(error, Error::RateLimited(_))),
        (500, |error| matches!(error, Error::Unavailable(_))),
        (502, |error| matches!(error, Error::Unavailable(_))),
        (422, |error| matches!(error, Error::InvalidInput(_))),
    ];
    for (status, is_expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string("response detail"))
            .mount(&server)
            .await;

        let error = connector(&server)
            .execute(&notify_request())
            .await
            .unwrap_err();

        assert!(is_expected(&error), "{status}: {error:?}");
        let text = error.to_string();
        assert!(
            text.ends_with(&format!(
                "webhook soc-bridge to {} for the action notify: HTTP {status}",
                server.address()
            )),
            "{text}"
        );
        assert!(!text.contains("/hooks/chat"), "{text}");
        assert!(!text.contains("response detail"), "{text}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/chat"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/elsewhere", server.uri())),
        )
        .mount(&server)
        .await;
    mount_ok(&server).await;

    let error = connector(&server)
        .execute(&notify_request())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Config(message) if message.contains("the server sent a redirect")),
        "{error:?}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/hooks/chat");
}

#[tokio::test]
async fn a_configuration_that_is_not_safe_is_rejected() {
    let config_error = |config: WebhookConfig| match WebhookConnector::new(config) {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected a configuration error, found {other:?}"),
        Ok(_) => panic!("expected a configuration error"),
    };
    let base = || WebhookConfig::new("soc-bridge", secret());

    assert_eq!(
        config_error(base().endpoint(
            ActionKind::Notify,
            "http://hooks.example.com/services/T0/path-token",
            false
        )),
        "the endpoint of webhook connector soc-bridge for the action notify must use https; plain http is permitted only for a loopback host"
    );
    assert_eq!(
        config_error(base().endpoint(ActionKind::BlockIp, "http://192.0.2.10/block", true)),
        "the endpoint of webhook connector soc-bridge for the action block_ip must use https; plain http is permitted only for a loopback host"
    );
    assert!(
        WebhookConnector::new(base().endpoint(
            ActionKind::Notify,
            "https://hooks.example.com/services/T0/path-token",
            false
        ))
        .is_ok()
    );
    assert!(
        WebhookConnector::new(base().endpoint(
            ActionKind::Notify,
            "http://localhost:9000/hook",
            false
        ))
        .is_ok()
    );

    assert_eq!(
        config_error(
            WebhookConfig::new("soc-bridge", SecretString::from("short")).endpoint(
                ActionKind::Notify,
                "https://hooks.example.com/x",
                false
            )
        ),
        "the secret of webhook connector soc-bridge must have 16 bytes or more"
    );
    assert_eq!(
        config_error(base()),
        "webhook connector soc-bridge must have one endpoint or more"
    );
    assert_eq!(
        config_error(
            base()
                .endpoint(ActionKind::Notify, "https://hooks.example.com/a", false)
                .endpoint(ActionKind::Notify, "https://hooks.example.com/b", false)
        ),
        "webhook connector soc-bridge has two endpoints for the action notify"
    );
    assert_eq!(
        config_error(WebhookConfig::new(" ", secret()).endpoint(
            ActionKind::Notify,
            "https://hooks.example.com/a",
            false
        )),
        "a webhook connector must have a name"
    );
    assert_eq!(
        config_error(base().endpoint(
            ActionKind::Custom(" ".to_owned()),
            "https://hooks.example.com/a",
            false
        )),
        "webhook connector soc-bridge has a custom action with no name"
    );
}

#[tokio::test]
async fn the_configuration_reads_from_text() {
    let config: WebhookConfig = serde_json::from_value(json!({
        "secret": SECRET,
        "endpoints": [
            { "kind": "notify", "url": "https://hooks.example.com/chat" },
            { "kind": "block_ip", "url": "https://firewall.example.com/block", "reversible": true },
            { "kind": { "custom": "quarantine_mailbox" }, "url": "https://mail.example.com/q" },
        ],
    }))
    .unwrap();

    assert_eq!(config.name, "webhook");
    assert_eq!(config.timeout_seconds, 30);
    assert_eq!(config.endpoints.len(), 3);
    assert_eq!(config.endpoints[1].kind, ActionKind::BlockIp);
    assert!(config.endpoints[1].reversible);
    assert!(!config.endpoints[0].reversible);
    let connector = WebhookConnector::new(config).unwrap();
    assert_eq!(
        connector.supported_actions(),
        [
            ActionKind::Notify,
            ActionKind::BlockIp,
            ActionKind::Custom("quarantine_mailbox".to_owned()),
        ]
    );
}
