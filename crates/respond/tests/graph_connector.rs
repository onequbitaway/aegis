//! Integration tests for the Microsoft Graph action connector, against a mock HTTP server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::AuditLog;
use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::{Error, Result};
use aegis_respond::connectors::graph::parameter;
use aegis_respond::{
    ActionRegistry, Dispatcher, GraphActionConnector, GraphConfig, MemorySecretSink, RotatedSecret,
    SecretSink,
};
use aegis_testkit::fixtures::{
    OTHER_TENANT, ROGUE_APP_ID, ROGUE_PRINCIPAL_ID, TENANT, VICTIM_USER_ID,
};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, MemoryBus, StaticPolicy};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use wiremock::matchers::{bearer_token, body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{request, responder, rogue_principal, victim_user};

const CLIENT_ID: &str = "client-aegis";
const CLIENT_SECRET: &str = "client-secret-Zq8rT1";
const ACCESS_TOKEN: &str = "access-token-Kp4mX9";
const NEW_SECRET: &str = "new-password-Hd7~wQ2vLx";
const NEW_KEY_ID: &str = "key-new";
const OLD_KEY_ID: &str = "credential-1";
const TOKEN_PATH: &str = "/tenant-contoso/oauth2/v2.0/token";

/// Returns `true` if the error has the expected variant.
type ErrorCheck = fn(&Error) -> bool;

fn config(server: &MockServer) -> GraphConfig {
    let mut config = GraphConfig::new(TENANT, CLIENT_ID, SecretString::from(CLIENT_SECRET));
    config.graph_base_url = format!("{}/v1.0", server.uri());
    config.login_base_url = server.uri();
    config
}

fn connector(server: &MockServer) -> GraphActionConnector {
    GraphActionConnector::new(config(server), Arc::new(MemorySecretSink::default())).unwrap()
}

fn token_response(expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "token_type": "Bearer",
        "expires_in": expires_in,
        "access_token": ACCESS_TOKEN,
    }))
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response(3600))
        .mount(server)
        .await;
}

/// One request that the mock server received: the method, the path, and the JSON body.
#[derive(Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    body: Value,
}

fn seen(method: &str, path: &str, body: Value) -> Seen {
    Seen {
        method: method.to_owned(),
        path: path.to_owned(),
        body,
    }
}

/// Returns the requests to Microsoft Graph, without the token requests.
async fn graph_requests(server: &MockServer) -> Vec<Seen> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() != TOKEN_PATH)
        .map(|request| Seen {
            method: request.method.to_string(),
            path: request.url.path().to_owned(),
            body: if request.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&request.body).unwrap()
            },
        })
        .collect()
}

async fn token_request_count(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == TOKEN_PATH)
        .count()
}

fn with_key(mut request: ActionRequest, key_id: &str) -> ActionRequest {
    request
        .parameters
        .insert(parameter::KEY_ID.to_owned(), json!(key_id));
    request
}

fn dry(mut request: ActionRequest) -> ActionRequest {
    request.dry_run = true;
    request
}

#[tokio::test]
async fn the_token_request_uses_the_client_credentials_flow() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    connector(&server)
        .execute(&request(
            ActionKind::DisableServicePrincipal,
            rogue_principal(),
        ))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let token = &requests[0];
    assert_eq!(token.method.as_str(), "POST");
    assert_eq!(token.url.path(), TOKEN_PATH);
    assert_eq!(
        token.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&token.body)
        .into_owned()
        .collect();
    assert_eq!(
        form,
        BTreeMap::from([
            ("client_id".to_owned(), CLIENT_ID.to_owned()),
            ("client_secret".to_owned(), CLIENT_SECRET.to_owned()),
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            (
                "scope".to_owned(),
                "https://graph.microsoft.com/.default".to_owned()
            ),
        ])
    );
    assert_eq!(
        requests[1].headers["authorization"],
        format!("Bearer {ACCESS_TOKEN}")
    );
}

#[tokio::test]
async fn disable_service_principal_patches_account_enabled_and_revert_sets_it_again() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .and(path("/v1.0/servicePrincipals/sp-sync-helper"))
        .and(bearer_token(ACCESS_TOKEN))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;
    let connector = connector(&server);
    let action = request(ActionKind::DisableServicePrincipal, rogue_principal());

    let outcome = connector.execute(&action).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(outcome.connector, "entra-graph");
    assert!(outcome.reversible);
    assert_eq!(
        outcome.message,
        "Did disable the account of service_principal sp-sync-helper."
    );
    assert_eq!(
        graph_requests(&server).await,
        [seen(
            "PATCH",
            "/v1.0/servicePrincipals/sp-sync-helper",
            json!({ "accountEnabled": false })
        )]
    );

    let reverted = connector.revert(&action).await.unwrap();

    assert_eq!(reverted.status, ActionStatus::Succeeded);
    assert_eq!(
        reverted.message,
        "Did enable the account of service_principal sp-sync-helper."
    );
    assert_eq!(
        graph_requests(&server).await[1],
        seen(
            "PATCH",
            "/v1.0/servicePrincipals/sp-sync-helper",
            json!({ "accountEnabled": true })
        )
    );
}

#[tokio::test]
async fn disable_user_patches_the_user() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .and(path("/v1.0/users/user-dana"))
        .and(body_json(json!({ "accountEnabled": false })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = connector(&server)
        .execute(&request(ActionKind::DisableUser, victim_user()))
        .await
        .unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert!(outcome.reversible);
    assert_eq!(
        graph_requests(&server).await,
        [seen(
            "PATCH",
            "/v1.0/users/user-dana",
            json!({ "accountEnabled": false })
        )]
    );
}

#[tokio::test]
async fn kill_session_revokes_the_sign_in_sessions_of_the_user() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1.0/users/user-dana/revokeSignInSessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": true })))
        .expect(1)
        .mount(&server)
        .await;
    let connector = connector(&server);
    let action = request(ActionKind::KillSession, victim_user());

    let outcome = connector.execute(&action).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert!(!outcome.reversible);
    assert_eq!(
        graph_requests(&server).await,
        [seen(
            "POST",
            "/v1.0/users/user-dana/revokeSignInSessions",
            Value::Null
        )]
    );

    let error = connector.revert(&action).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unsupported(message) if message == "the action kill_session has no inverse in Microsoft Graph"),
        "{error:?}"
    );
    assert_eq!(graph_requests(&server).await.len(), 1);
}

#[tokio::test]
async fn revoke_credential_reads_the_key_from_the_credential_id_parameter_of_the_responder() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let connector = connector(&server);

    // The Responder agent names the parameter with the shared attribute name.
    let mut from_responder = request(ActionKind::RevokeCredential, rogue_principal());
    from_responder
        .parameters
        .insert("credential_id".to_owned(), json!(OLD_KEY_ID));
    let outcome = connector.execute(&from_responder).await.unwrap();
    assert_eq!(outcome.status, ActionStatus::Succeeded);

    // `key_id` has priority when a request has the two names.
    let mut both = with_key(
        request(ActionKind::RevokeCredential, rogue_principal()),
        "key-2",
    );
    both.parameters
        .insert("credential_id".to_owned(), json!(OLD_KEY_ID));
    connector.execute(&both).await.unwrap();

    assert_eq!(
        graph_requests(&server).await,
        [
            seen(
                "POST",
                "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
                json!({ "keyId": OLD_KEY_ID })
            ),
            seen(
                "POST",
                "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
                json!({ "keyId": "key-2" })
            ),
        ]
    );

    // A request with none of the two names stays an error.
    let neither = request(ActionKind::RevokeCredential, rogue_principal());
    let error = connector.execute(&neither).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message == "the action revoke_credential needs the parameter key_id"),
        "{error:?}"
    );
}

#[tokio::test]
async fn revoke_credential_removes_the_password_with_the_key_id() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let connector = connector(&server);

    let on_principal = connector
        .execute(&with_key(
            request(ActionKind::RevokeCredential, rogue_principal()),
            OLD_KEY_ID,
        ))
        .await
        .unwrap();
    let application = EntityRef::new(EntityKind::Application, ROGUE_APP_ID);
    connector
        .execute(&with_key(
            request(ActionKind::RevokeCredential, application),
            "key-2",
        ))
        .await
        .unwrap();

    assert_eq!(on_principal.status, ActionStatus::Succeeded);
    assert!(!on_principal.reversible);
    assert_eq!(
        graph_requests(&server).await,
        [
            seen(
                "POST",
                "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
                json!({ "keyId": OLD_KEY_ID })
            ),
            seen(
                "POST",
                "/v1.0/applications/app-sync-helper/removePassword",
                json!({ "keyId": "key-2" })
            ),
        ]
    );
}

async fn mount_rotation(server: &MockServer) {
    mount_token(server).await;
    Mock::given(method("POST"))
        .and(path("/v1.0/servicePrincipals/sp-sync-helper/addPassword"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keyId": NEW_KEY_ID,
            "secretText": NEW_SECRET,
            "displayName": "rotated",
            "hint": "new",
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

#[tokio::test]
async fn rotate_credential_adds_a_password_stores_it_and_removes_the_old_one() {
    let server = MockServer::start().await;
    mount_rotation(&server).await;
    let sink = Arc::new(MemorySecretSink::default());
    let connector = GraphActionConnector::new(config(&server), sink.clone()).unwrap();
    let mut action = with_key(
        request(ActionKind::RotateCredential, rogue_principal()),
        OLD_KEY_ID,
    );
    action.parameters.insert(
        parameter::DISPLAY_NAME.to_owned(),
        json!("rotated by AEGIS"),
    );

    let outcome = connector.execute(&action).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert!(!outcome.reversible);
    assert_eq!(
        graph_requests(&server).await,
        [
            seen(
                "POST",
                "/v1.0/servicePrincipals/sp-sync-helper/addPassword",
                json!({ "passwordCredential": { "displayName": "rotated by AEGIS" } })
            ),
            seen(
                "POST",
                "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
                json!({ "keyId": OLD_KEY_ID })
            ),
        ]
    );
    assert_eq!(
        outcome.details["rotation"],
        json!({
            "new_key_id": NEW_KEY_ID,
            "removed_key_id": OLD_KEY_ID,
            "secret_reference": "memory:key-new",
        })
    );

    let stored = sink.stored();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].value.expose_secret(), NEW_SECRET);
    assert_eq!(stored[0].key_id, NEW_KEY_ID);
    assert_eq!(stored[0].owner, rogue_principal());
    assert_eq!(stored[0].action_id, action.id);

    let outcome_text = serde_json::to_string(&outcome).unwrap();
    assert!(!outcome_text.contains(NEW_SECRET), "{outcome_text}");
    assert!(!format!("{outcome:?}").contains(NEW_SECRET));
    assert!(!format!("{stored:?}").contains(NEW_SECRET));
}

#[tokio::test]
async fn the_rotated_secret_is_in_no_audit_record_and_no_bus_message() {
    let server = MockServer::start().await;
    mount_rotation(&server).await;
    let sink = Arc::new(MemorySecretSink::default());
    let mut registry = ActionRegistry::new();
    registry
        .register(Arc::new(
            GraphActionConnector::new(config(&server), sink.clone()).unwrap(),
        ))
        .unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let bus = Arc::new(MemoryBus::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .bus(bus.clone())
    .build();
    let action = with_key(
        request(ActionKind::RotateCredential, rogue_principal()),
        OLD_KEY_ID,
    );

    let disposition = dispatcher.dispatch(action, &responder()).await.unwrap();

    assert!(
        matches!(&disposition, ActionDisposition::Executed(outcome) if outcome.status == ActionStatus::Succeeded),
        "{disposition:?}"
    );
    assert_eq!(sink.stored().len(), 1);
    assert_eq!(sink.stored()[0].value.expose_secret(), NEW_SECRET);

    let records = audit.records();
    assert_eq!(records.len(), 3);
    let audit_text = serde_json::to_string(&records).unwrap();
    assert!(audit_text.contains(NEW_KEY_ID), "{audit_text}");
    assert!(!audit_text.contains(NEW_SECRET), "{audit_text}");
    assert!(!audit_text.contains(ACCESS_TOKEN), "{audit_text}");
    assert!(!audit_text.contains(CLIENT_SECRET), "{audit_text}");
    let messages = bus.published();
    assert_eq!(messages.len(), 1);
    let bus_text = String::from_utf8(messages[0].payload.clone()).unwrap();
    assert!(bus_text.contains(NEW_KEY_ID), "{bus_text}");
    assert!(!bus_text.contains(NEW_SECRET), "{bus_text}");
    assert!(audit.verify().await.unwrap().valid);
}

/// A sink that fails and, against its contract, puts the secret in the error text.
struct LeakySink;

#[async_trait]
impl SecretSink for LeakySink {
    async fn store(&self, secret: RotatedSecret) -> Result<String> {
        Err(Error::Unauthorized(format!(
            "the vault refused the value {}",
            secret.value.expose_secret()
        )))
    }
}

#[tokio::test]
async fn a_sink_failure_removes_the_new_credential_and_keeps_the_old_one() {
    let server = MockServer::start().await;
    mount_rotation(&server).await;
    let connector = GraphActionConnector::new(config(&server), Arc::new(LeakySink)).unwrap();
    let action = with_key(
        request(ActionKind::RotateCredential, rogue_principal()),
        OLD_KEY_ID,
    );

    let error = connector.execute(&action).await.unwrap_err();

    let text = error.to_string();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message.contains("nothing changed") && message.contains(NEW_KEY_ID)),
        "{error:?}"
    );
    assert!(text.contains("[REDACTED]"), "{text}");
    assert!(!text.contains(NEW_SECRET), "{text}");
    assert!(!format!("{error:?}").contains(NEW_SECRET));
    let requests = graph_requests(&server).await;
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].path,
        "/v1.0/servicePrincipals/sp-sync-helper/addPassword"
    );
    assert_eq!(
        requests[1],
        seen(
            "POST",
            "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
            json!({ "keyId": NEW_KEY_ID })
        )
    );
}

#[tokio::test]
async fn a_failure_to_remove_the_old_credential_names_the_new_key_and_not_the_secret() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1.0/servicePrincipals/sp-sync-helper/addPassword"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "keyId": NEW_KEY_ID, "secretText": NEW_SECRET })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1.0/servicePrincipals/sp-sync-helper/removePassword",
        ))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let sink = Arc::new(MemorySecretSink::default());
    let connector = GraphActionConnector::new(config(&server), sink.clone()).unwrap();
    let action = with_key(
        request(ActionKind::RotateCredential, rogue_principal()),
        OLD_KEY_ID,
    );

    let error = connector.execute(&action).await.unwrap_err();

    let text = error.to_string();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("the new credential key-new") && message.contains("the old credential was not removed")),
        "{error:?}"
    );
    assert!(text.contains("memory:key-new"), "{text}");
    assert!(!text.contains(NEW_SECRET), "{text}");
    assert_eq!(sink.stored().len(), 1);
}

#[tokio::test]
async fn a_dry_run_sends_no_request() {
    let server = MockServer::start().await;
    let sink = Arc::new(MemorySecretSink::default());
    let connector = GraphActionConnector::new(config(&server), sink.clone()).unwrap();
    let principal = rogue_principal;
    let cases = [
        (
            dry(request(ActionKind::DisableServicePrincipal, principal())),
            true,
            json!([{ "method": "PATCH", "path": "/servicePrincipals/sp-sync-helper", "body": { "accountEnabled": false } }]),
        ),
        (
            dry(request(ActionKind::DisableUser, victim_user())),
            true,
            json!([{ "method": "PATCH", "path": "/users/user-dana", "body": { "accountEnabled": false } }]),
        ),
        (
            dry(request(ActionKind::KillSession, victim_user())),
            false,
            json!([{ "method": "POST", "path": "/users/user-dana/revokeSignInSessions", "body": null }]),
        ),
        (
            dry(with_key(
                request(ActionKind::RevokeCredential, principal()),
                OLD_KEY_ID,
            )),
            false,
            json!([{ "method": "POST", "path": "/servicePrincipals/sp-sync-helper/removePassword", "body": { "keyId": OLD_KEY_ID } }]),
        ),
    ];
    for (action, reversible, planned) in cases {
        let outcome = connector.execute(&action).await.unwrap();
        assert_eq!(outcome.status, ActionStatus::Simulated, "{:?}", action.kind);
        assert_eq!(outcome.reversible, reversible, "{:?}", action.kind);
        assert_eq!(
            outcome.details["planned_requests"], planned,
            "{:?}",
            action.kind
        );
        assert!(
            outcome
                .message
                .ends_with("This was a dry run. Nothing changed.")
        );
    }

    let rotate = dry(with_key(
        request(ActionKind::RotateCredential, principal()),
        OLD_KEY_ID,
    ));
    let outcome = connector.execute(&rotate).await.unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);
    let planned = outcome.details["planned_requests"].as_array().unwrap();
    assert_eq!(planned.len(), 2);
    assert_eq!(
        planned[0]["path"],
        "/servicePrincipals/sp-sync-helper/addPassword"
    );
    assert_eq!(planned[1]["body"], json!({ "keyId": OLD_KEY_ID }));

    let reverted = connector
        .revert(&dry(request(ActionKind::DisableUser, victim_user())))
        .await
        .unwrap();
    assert_eq!(reverted.status, ActionStatus::Simulated);
    assert_eq!(
        reverted.details["planned_requests"][0]["body"],
        json!({ "accountEnabled": true })
    );

    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    assert_eq!(sink.stored().len(), 0);
}

#[tokio::test]
async fn each_http_status_maps_to_its_contract_error() {
    let cases: [(u16, ErrorCheck); 7] = [
        (403, |error| matches!(error, Error::Unauthorized(_))),
        (404, |error| matches!(error, Error::NotFound(_))),
        (429, |error| matches!(error, Error::RateLimited(_))),
        (500, |error| matches!(error, Error::Unavailable(_))),
        (503, |error| matches!(error, Error::Unavailable(_))),
        (400, |error| matches!(error, Error::InvalidInput(_))),
        (302, |error| matches!(error, Error::Config(_))),
    ];
    for (status, is_expected) in cases {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": { "code": "Request_Failure", "message": "internal detail" }
            })))
            .mount(&server)
            .await;

        let error = connector(&server)
            .execute(&request(
                ActionKind::DisableServicePrincipal,
                rogue_principal(),
            ))
            .await
            .unwrap_err();

        assert!(is_expected(&error), "{status}: {error:?}");
        let text = error.to_string();
        assert!(
            text.contains(&format!(
                "Microsoft Graph PATCH /servicePrincipals/sp-sync-helper: HTTP {status} (Request_Failure)"
            )),
            "{status}: {text}"
        );
        assert!(!text.contains("internal detail"), "{status}: {text}");
        assert!(!text.contains(ACCESS_TOKEN), "{status}: {text}");
        assert_eq!(graph_requests(&server).await.len(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_401_from_graph_gets_a_new_token_and_one_more_attempt() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(2)
        .mount(&server)
        .await;

    let outcome = connector(&server)
        .execute(&request(
            ActionKind::DisableServicePrincipal,
            rogue_principal(),
        ))
        .await
        .unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(graph_requests(&server).await.len(), 2);
    assert_eq!(token_request_count(&server).await, 2);
}

#[tokio::test]
async fn a_second_401_from_graph_is_unauthorized() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let error = connector(&server)
        .execute(&request(
            ActionKind::DisableServicePrincipal,
            rogue_principal(),
        ))
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    assert_eq!(graph_requests(&server).await.len(), 2);
    assert_eq!(token_request_count(&server).await, 2);
}

#[tokio::test]
async fn a_valid_token_is_used_again_and_an_old_token_is_not() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let cached = connector(&server);
    for _ in 0..3 {
        cached
            .execute(&request(ActionKind::DisableUser, victim_user()))
            .await
            .unwrap();
    }
    assert_eq!(graph_requests(&server).await.len(), 3);
    assert_eq!(token_request_count(&server).await, 1);

    let short = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response(30))
        .mount(&short)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&short)
        .await;
    let expiring = connector(&short);
    for _ in 0..2 {
        expiring
            .execute(&request(ActionKind::DisableUser, victim_user()))
            .await
            .unwrap();
    }
    assert_eq!(token_request_count(&short).await, 2);
}

#[tokio::test]
async fn a_token_failure_maps_to_unauthorized_or_configuration() {
    let cases: [(u16, &str, ErrorCheck); 5] = [
        (401, "invalid_client", |error| {
            matches!(error, Error::Unauthorized(_))
        }),
        (400, "invalid_client", |error| {
            matches!(error, Error::Unauthorized(_))
        }),
        (400, "unauthorized_client", |error| {
            matches!(error, Error::Unauthorized(_))
        }),
        (400, "invalid_scope", |error| {
            matches!(error, Error::Config(_))
        }),
        (503, "temporarily_unavailable", |error| {
            matches!(error, Error::Unavailable(_))
        }),
    ];
    for (status, code, is_expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": code,
                "error_description": format!("AADSTS7000215: the secret {CLIENT_SECRET} is not valid"),
            })))
            .mount(&server)
            .await;

        let error = connector(&server)
            .execute(&request(ActionKind::DisableUser, victim_user()))
            .await
            .unwrap_err();

        assert!(is_expected(&error), "{status} {code}: {error:?}");
        let text = error.to_string();
        assert!(text.contains(code), "{text}");
        assert!(text.contains("Microsoft Entra ID token request"), "{text}");
        assert!(!text.contains(CLIENT_SECRET), "{text}");
        assert_eq!(graph_requests(&server).await.len(), 0);
    }
}

#[tokio::test]
async fn a_token_document_that_is_not_valid_is_a_serialization_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>sign in</html>"))
        .mount(&server)
        .await;

    let error = connector(&server)
        .execute(&request(ActionKind::DisableUser, victim_user()))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Serialization(message) if message == "Microsoft Entra ID token request: the response is not a valid token document"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_target_in_a_different_tenant_is_refused() {
    let server = MockServer::start().await;
    let foreign =
        EntityRef::new(EntityKind::ServicePrincipal, ROGUE_PRINCIPAL_ID).with_tenant(OTHER_TENANT);

    let error = connector(&server)
        .execute(&request(
            ActionKind::DisableServicePrincipal,
            foreign.clone(),
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::InvalidInput(message) if message == "the target service_principal sp-sync-helper is in the tenant tenant-fabrikam; connector entra-graph manages the tenant tenant-contoso only"),
        "{error:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);

    let mut with_alias = config(&server);
    with_alias.tenant_aliases = vec!["Tenant-Fabrikam".to_owned()];
    let connector =
        GraphActionConnector::new(with_alias, Arc::new(MemorySecretSink::default())).unwrap();
    let outcome = connector
        .execute(&dry(request(ActionKind::DisableServicePrincipal, foreign)))
        .await
        .unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);

    let no_tenant = EntityRef::new(EntityKind::User, VICTIM_USER_ID);
    let outcome = connector
        .execute(&dry(request(ActionKind::DisableUser, no_tenant)))
        .await
        .unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);
}

#[tokio::test]
async fn a_request_that_is_not_valid_sends_nothing() {
    let server = MockServer::start().await;
    let connector = connector(&server);

    let no_key = connector
        .execute(&request(ActionKind::RevokeCredential, rogue_principal()))
        .await
        .unwrap_err();
    assert!(
        matches!(&no_key, Error::InvalidInput(message) if message == "the action revoke_credential needs the parameter key_id"),
        "{no_key:?}"
    );

    let mut bad_key = request(ActionKind::RotateCredential, rogue_principal());
    bad_key
        .parameters
        .insert(parameter::KEY_ID.to_owned(), json!(17));
    let bad_key = connector.execute(&bad_key).await.unwrap_err();
    assert!(
        matches!(&bad_key, Error::InvalidInput(message) if message == "the parameter key_id must be a string"),
        "{bad_key:?}"
    );

    let wrong_type = connector
        .execute(&request(ActionKind::DisableUser, rogue_principal()))
        .await
        .unwrap_err();
    assert!(
        matches!(&wrong_type, Error::InvalidInput(message) if message == "the action disable_user needs a target of the type user, not service_principal"),
        "{wrong_type:?}"
    );

    let session_of_principal = connector
        .execute(&request(ActionKind::KillSession, rogue_principal()))
        .await
        .unwrap_err();
    assert!(matches!(session_of_principal, Error::InvalidInput(_)));

    let traversal = EntityRef::new(EntityKind::User, "../servicePrincipals/sp-sync-helper");
    let traversal = connector
        .execute(&request(ActionKind::DisableUser, traversal))
        .await
        .unwrap_err();
    assert!(
        matches!(&traversal, Error::InvalidInput(message) if message.contains("target identifier")),
        "{traversal:?}"
    );

    let unsupported = connector
        .execute(&request(
            ActionKind::BlockIp,
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(&unsupported, Error::Unsupported(message) if message == "the Microsoft Graph connector does not support the action block_ip"),
        "{unsupported:?}"
    );

    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn the_connector_reports_its_identity_and_its_actions() {
    let server = MockServer::start().await;
    let mut named = config(&server);
    named.name = "entra-prod".to_owned();
    let connector =
        GraphActionConnector::new(named, Arc::new(MemorySecretSink::default())).unwrap();

    let info = connector.info();
    assert_eq!(info.name, "entra-prod");
    assert_eq!(info.vendor, "microsoft");
    assert_eq!(info.product, "entra_id");
    assert_eq!(
        connector.supported_actions(),
        [
            ActionKind::DisableServicePrincipal,
            ActionKind::DisableUser,
            ActionKind::KillSession,
            ActionKind::RevokeCredential,
            ActionKind::RotateCredential,
        ]
    );
}

#[tokio::test]
async fn a_configuration_that_is_not_safe_is_rejected() {
    let sink = || -> Arc<dyn SecretSink> { Arc::new(MemorySecretSink::default()) };
    let base = || GraphConfig::new(TENANT, CLIENT_ID, SecretString::from(CLIENT_SECRET));
    let config_error = |config: GraphConfig| match GraphActionConnector::new(config, sink()) {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected a configuration error, found {other:?}"),
        Ok(_) => panic!("expected a configuration error"),
    };

    assert!(GraphActionConnector::new(base(), sink()).is_ok());

    let mut plain_graph = base();
    plain_graph.graph_base_url = "http://graph.example.com/v1.0".to_owned();
    assert_eq!(
        config_error(plain_graph),
        "graph_base_url must use https; plain http is permitted only for a loopback host"
    );
    let mut plain_login = base();
    plain_login.login_base_url = "http://login.example.com".to_owned();
    assert_eq!(
        config_error(plain_login),
        "login_base_url must use https; plain http is permitted only for a loopback host"
    );
    let empty_secret = GraphConfig::new(TENANT, CLIENT_ID, SecretString::from(""));
    assert_eq!(
        config_error(empty_secret),
        "the Microsoft Graph setting client_secret must not be empty"
    );
    let empty_client = GraphConfig::new(TENANT, " ", SecretString::from(CLIENT_SECRET));
    assert_eq!(
        config_error(empty_client),
        "the Microsoft Graph setting client_id must not be empty"
    );
    let bad_tenant = GraphConfig::new("../common", CLIENT_ID, SecretString::from(CLIENT_SECRET));
    assert_eq!(
        config_error(bad_tenant),
        "the Microsoft Graph setting tenant_id must be a tenant identifier or a domain name"
    );
    let mut no_timeout = base();
    no_timeout.timeout_seconds = 0;
    assert_eq!(
        config_error(no_timeout),
        "the HTTP timeout must be more than zero"
    );
}

#[tokio::test]
async fn the_configuration_reads_from_text_with_defaults() {
    let config: GraphConfig = serde_json::from_value(json!({
        "tenant_id": TENANT,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }))
    .unwrap();

    assert_eq!(config.name, "entra-graph");
    assert_eq!(config.graph_base_url, "https://graph.microsoft.com/v1.0");
    assert_eq!(config.login_base_url, "https://login.microsoftonline.com");
    assert_eq!(config.scope, "https://graph.microsoft.com/.default");
    assert_eq!(config.timeout_seconds, 30);
    assert_eq!(config.tenant_aliases, Vec::<String>::new());
    assert_eq!(config.client_secret.expose_secret(), CLIENT_SECRET);

    let unknown = serde_json::from_value::<GraphConfig>(json!({
        "tenant_id": TENANT,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_secert": "typo",
    }));
    assert!(unknown.is_err());
}

#[tokio::test]
async fn a_server_that_does_not_answer_in_time_is_a_timeout() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let mut quick = config(&server);
    quick.timeout_seconds = 1;
    let connector =
        GraphActionConnector::new(quick, Arc::new(MemorySecretSink::default())).unwrap();

    let error = connector
        .execute(&request(ActionKind::DisableUser, victim_user()))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Timeout(message) if message == "Microsoft Graph PATCH /users/user-dana: the request timed out"),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

/// Returns the URL of a loopback port that no server listens on.
fn closed_port_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}")
}

#[tokio::test]
async fn a_server_that_is_down_is_unavailable() {
    let url = closed_port_url();
    let mut config = GraphConfig::new(TENANT, CLIENT_ID, SecretString::from(CLIENT_SECRET));
    config.graph_base_url = format!("{url}/v1.0");
    config.login_base_url = url;
    let connector =
        GraphActionConnector::new(config, Arc::new(MemorySecretSink::default())).unwrap();

    let error = connector
        .execute(&request(ActionKind::DisableUser, victim_user()))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message) if message == "Microsoft Entra ID token request: cannot connect to the server"),
        "{error:?}"
    );
    assert!(error.is_retryable());
}
