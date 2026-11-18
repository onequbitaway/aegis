//! The Microsoft Teams endpoint.

use aegis_contracts::common::{ApprovalId, Severity};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{ApprovalQueue, ApprovalStatus, Principal, PrincipalKind};
use axum::http::StatusCode;
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::json;

use crate::chat::{
    TEAMS_ALICE, TEAMS_VERA, chat_config, chat_env, signed_teams_request, teams_authorization,
    teams_body, teams_now, teams_request, teams_secret,
};
use crate::support::{DecideCall, TestApi, incident, send};

fn chat_api() -> TestApi {
    let env = chat_env();
    let env: Vec<(&str, &str)> = env
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    TestApi::with_env(&env)
}

fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

fn message(text: &str) -> serde_json::Value {
    json!({ "type": "message", "text": text })
}

#[tokio::test]
async fn a_request_with_the_correct_hmac_runs_the_command() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());

    let body = teams_body(
        Some(TEAMS_ALICE),
        "29:1alice",
        "<at>AEGIS</at> approvals",
        teams_now(),
    );
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        message(&format!(
            "Actions that wait for approval: 1. This message shows 1.<br>\
             {} | Action: disable\\_user | Target: user victim\\@example\\.com \\(user\\-1\\) | \
             Reason: The account signed in from the spray address\\. | Requested by: responder | \
             Policy: The action is in the gated tier\\.",
            request.id
        ))
    );

    let text = format!(
        "<at>AEGIS</at>&nbsp;approve {} verified by phone",
        request.id
    );
    let body = teams_body(Some(TEAMS_ALICE), "29:1alice", &text, teams_now());
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: request.id,
            approve: true,
            principal: alice(),
            note: Some("verified by phone".to_owned()),
        }]
    );
    assert_eq!(
        reply.json(),
        message(
            "alice\\@example\\.com approved the action disable\\_user on user \
             victim\\@example\\.com \\(user\\-1\\)\\.<br>\
             The action ran\\: The connector did the action\\."
        )
    );
}

/// Sends a request that must be refused, and checks that nothing changed.
async fn assert_refused_with_401(
    api: &TestApi,
    request: axum::http::Request<axum::body::Body>,
    id: ApprovalId,
) {
    let router = api.router_with(&chat_config());
    let reply = send(&router, request).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "unauthorized",
            "message": "The request signature is not valid."
        } })
    );
    assert!(api.actions.calls().is_empty());
    let stored = api.approvals.get(id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
}

#[tokio::test]
async fn a_request_with_a_wrong_hmac_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let text = format!("approve {}", request.id);
    let body = teams_body(Some(TEAMS_ALICE), "29:1alice", &text, teams_now());

    let mut other_secret = teams_secret();
    other_secret[0] ^= 0xff;
    let other_body = body.replace("approve", "reject");
    let correct = teams_authorization(&teams_secret(), &body);
    let cases = [
        Some(teams_authorization(&other_secret, &body)),
        Some(teams_authorization(&teams_secret(), &other_body)),
        Some(correct.replacen("HMAC ", "Bearer ", 1)),
        Some(correct.trim_start_matches("HMAC ").to_owned()),
        Some("HMAC AAAA".to_owned()),
        None,
    ];
    for authorization in cases {
        let refused = teams_request(&body, authorization.as_deref());
        assert_refused_with_401(&api, refused, request.id).await;
    }

    // The same body with the correct value is accepted.
    let router = api.router_with(&chat_config());
    let reply = send(&router, teams_request(&body, Some(&correct))).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(api.actions.calls().len(), 1);
}

#[tokio::test]
async fn a_request_with_an_old_timestamp_or_no_timestamp_is_refused() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let text = format!("approve {}", request.id);
    let at = |age: Duration| Some((Utc::now() - age).to_rfc3339_opts(SecondsFormat::Millis, true));

    // A time in the future has a margin, because the server reads the clock after the test.
    for timestamp in [
        None,
        at(Duration::seconds(301)),
        at(Duration::hours(2)),
        at(Duration::seconds(-330)),
    ] {
        // The HMAC is correct. Only the time of the message is wrong.
        let body = teams_body(Some(TEAMS_ALICE), "29:1alice", &text, timestamp);
        assert_refused_with_401(&api, signed_teams_request(&body), request.id).await;
    }

    // An operator can switch the time check off for a client that sends no timestamp.
    let mut config = chat_config();
    config.chatops.teams.as_mut().unwrap().require_timestamp = false;
    let router = api.router_with(&config);
    let body = teams_body(Some(TEAMS_ALICE), "29:1alice", &text, None);
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(api.actions.calls().len(), 1);
}

#[tokio::test]
async fn an_unknown_sender_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());
    let text = format!("approve {}", request.id);

    for (aad_object_id, id) in [
        (Some("9f0e1d2c-mallory"), "29:1mallory"),
        (None, "29:1mallory"),
        (None, ""),
    ] {
        let body = teams_body(aad_object_id, id, &text, teams_now());
        let reply = send(&router, signed_teams_request(&body)).await;
        assert_eq!(reply.status, StatusCode::OK, "{aad_object_id:?} {id}");
        assert_eq!(
            reply.json(),
            message("You are not permitted to use AEGIS from this chat\\."),
            "{aad_object_id:?} {id}"
        );
    }
    assert!(api.actions.calls().is_empty());
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
}

#[tokio::test]
async fn the_sender_maps_to_a_principal_and_the_access_rules_apply() {
    let api = chat_api();
    let request = api.seed_approval().await;
    api.seed_incident("Password spray", Severity::High).await;
    let router = api.router_with(&chat_config());

    // This sender has no Entra object identifier. The Teams identifier maps to the principal.
    let text = format!("approve {}", request.id);
    let body = teams_body(None, TEAMS_VERA, &text, teams_now());
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(
        reply.json(),
        message("The principal does not have the permission approve\\_actions\\.")
    );
    assert!(api.actions.calls().is_empty());

    let body = teams_body(None, TEAMS_VERA, "incidents", teams_now());
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    let text = reply.json()["text"].as_str().unwrap().to_owned();
    assert!(
        text.starts_with("The newest incidents: 1<br>high | open | Password spray | "),
        "{text}"
    );

    let body = teams_body(
        Some(TEAMS_ALICE),
        "29:1alice",
        &format!("reject {}", request.id),
        teams_now(),
    );
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: request.id,
            approve: false,
            principal: alice(),
            note: None,
        }]
    );
}

#[tokio::test]
async fn incident_text_with_markup_characters_is_escaped() {
    let api = chat_api();
    let hostile = incident(
        "[Sign in](https://evil.example) <at>General</at> **now** <img src=x>",
        Severity::Critical,
    );
    api.incidents.save(&hostile).await.unwrap();
    let router = api.router_with(&chat_config());

    let body = teams_body(None, TEAMS_VERA, "incidents", teams_now());
    let reply = send(&router, signed_teams_request(&body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        message(&format!(
            "The newest incidents: 1<br>critical | open | \
             \\[Sign in\\]\\(https\\:\\/\\/evil\\.example\\) &lt;at&gt;General&lt;\\/at&gt; \
             \\*\\*now\\*\\* &lt;img src\\=x&gt; | {}",
            hostile.id
        ))
    );
}

#[tokio::test]
async fn a_body_that_is_not_a_message_is_a_400() {
    let api = chat_api();
    let router = api.router_with(&chat_config());
    let invoke = json!({ "type": "invoke", "timestamp": teams_now() }).to_string();
    let no_time_format = json!({ "type": "message", "timestamp": "yesterday" }).to_string();
    for body in [
        "not json",
        "[]",
        "null",
        "\"approvals\"",
        &invoke,
        &no_time_format,
    ] {
        let reply = send(&router, signed_teams_request(body)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), "invalid_input", "{body}");
    }
    assert!(api.actions.calls().is_empty());
}
