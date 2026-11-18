//! Helpers for the ChatOps tests: the configuration, the secrets, and signed requests.

use std::collections::BTreeMap;

use aegis_api::{ApiConfig, SlackConfig, TeamsConfig};
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method, Request};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::support::config;

/// The signing secret of the Slack application in the tests.
pub const SLACK_SECRET: &str = "slack-signing-secret-0123456789abcdef";
/// The identifier of the Slack workspace in the tests.
pub const SLACK_TEAM: &str = "T0AEGIS";
/// The Slack user of `alice@example.com`, who can approve actions.
pub const SLACK_ALICE: &str = "U0ALICE";
/// The Slack user of `vera@example.com`, who can only read incidents.
pub const SLACK_VERA: &str = "U0VERA";
/// The Microsoft Entra object identifier of `alice@example.com`.
pub const TEAMS_ALICE: &str = "9f0e1d2c-alice";
/// The Teams identifier of `vera@example.com`.
pub const TEAMS_VERA: &str = "29:1vera";

/// Returns the shared secret of the Teams outgoing webhook, before base64 encoding.
pub fn teams_secret() -> Vec<u8> {
    (100..132).collect()
}

/// Returns the environment variables of the ChatOps secrets.
pub fn chat_env() -> Vec<(&'static str, String)> {
    vec![
        ("SLACK_SIGNING_SECRET", SLACK_SECRET.to_owned()),
        ("TEAMS_SECRET", STANDARD.encode(teams_secret())),
    ]
}

/// Returns a configuration with the Slack endpoints and the Teams endpoint.
pub fn chat_config() -> ApiConfig {
    let mut config = config();
    config.chatops.slack = Some(SlackConfig {
        signing_secret_env: Some("SLACK_SIGNING_SECRET".to_owned()),
        team_id: Some(SLACK_TEAM.to_owned()),
        users: BTreeMap::from([
            (SLACK_ALICE.to_owned(), "alice@example.com".to_owned()),
            (SLACK_VERA.to_owned(), "vera@example.com".to_owned()),
        ]),
        ..SlackConfig::default()
    });
    config.chatops.teams = Some(TeamsConfig {
        shared_secret_env: Some("TEAMS_SECRET".to_owned()),
        users: BTreeMap::from([
            (TEAMS_ALICE.to_owned(), "alice@example.com".to_owned()),
            (TEAMS_VERA.to_owned(), "vera@example.com".to_owned()),
        ]),
        ..TeamsConfig::default()
    });
    config
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Computes the Slack signature as the Slack documentation describes it. This function
/// does not use the code under test.
pub fn slack_signature(secret: &str, timestamp: i64, body: &str) -> String {
    let base = format!("v0:{timestamp}:{body}");
    format!(
        "v0={}",
        hex::encode(hmac_sha256(secret.as_bytes(), base.as_bytes()))
    )
}

/// Returns the present time in seconds since the Unix epoch.
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Builds a Slack request with the given timestamp and signature headers.
pub fn slack_request(
    path: &str,
    body: &str,
    timestamp: Option<&str>,
    signature: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(timestamp) = timestamp {
        builder = builder.header("x-slack-request-timestamp", timestamp);
    }
    if let Some(signature) = signature {
        builder = builder.header("x-slack-signature", signature);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

/// Builds a Slack request with a correct signature for the present time.
pub fn signed_slack_request(path: &str, body: &str) -> Request<Body> {
    let timestamp = now();
    let signature = slack_signature(SLACK_SECRET, timestamp, body);
    slack_request(path, body, Some(&timestamp.to_string()), Some(&signature))
}

/// Returns the form body of a slash command.
pub fn command_body(team: &str, user: &str, text: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", "legacy-verification-token")
        .append_pair("team_id", team)
        .append_pair("team_domain", "aegis")
        .append_pair("channel_id", "C0SECOPS")
        .append_pair("user_id", user)
        .append_pair("user_name", "someone")
        .append_pair("command", "/aegis")
        .append_pair("text", text)
        .append_pair("trigger_id", "13345224609.738474920.8088930838d88f008e0")
        .finish()
}

/// Returns the form body of a button interaction.
pub fn interaction_body(
    team: &str,
    user: &str,
    action_id: &str,
    value: &str,
    response_url: Option<&str>,
) -> String {
    let mut payload = json!({
        "type": "block_actions",
        "user": { "id": user, "username": "someone", "team_id": team },
        "team": { "id": team, "domain": "aegis" },
        "api_app_id": "A0AEGIS",
        "container": { "type": "message", "message_ts": "1730624700.000100" },
        "actions": [{
            "type": "button",
            "action_id": action_id,
            "block_id": format!("aegis_approval_{value}"),
            "value": value,
            "action_ts": "1730624705.000200"
        }]
    });
    if let Some(url) = response_url {
        payload["response_url"] = json!(url);
    }
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("payload", &payload.to_string())
        .finish()
}

/// Computes the `Authorization` header of a Teams outgoing webhook request as the Teams
/// documentation describes it. This function does not use the code under test.
pub fn teams_authorization(secret: &[u8], body: &str) -> String {
    format!(
        "HMAC {}",
        STANDARD.encode(hmac_sha256(secret, body.as_bytes()))
    )
}

/// Returns the JSON body of a Teams message. `sender` sets `from.aadObjectId` and
/// `from.id`.
pub fn teams_body(
    aad_object_id: Option<&str>,
    id: &str,
    text: &str,
    timestamp: Option<String>,
) -> String {
    let mut activity: Value = json!({
        "type": "message",
        "id": "1730624700123",
        "serviceUrl": "https://smba.trafficmanager.net/amer/",
        "channelId": "msteams",
        "from": { "id": id, "name": "Someone" },
        "conversation": { "id": "19:channel@thread.tacv2" },
        "text": text,
        "textFormat": "plain"
    });
    if let Some(aad_object_id) = aad_object_id {
        activity["from"]["aadObjectId"] = json!(aad_object_id);
    }
    if let Some(timestamp) = timestamp {
        activity["timestamp"] = json!(timestamp);
    }
    activity.to_string()
}

/// Builds a Teams request with an optional `Authorization` header.
pub fn teams_request(body: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/chatops/teams/messages")
        .header(CONTENT_TYPE, "application/json; charset=utf-8");
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

/// Builds a Teams request with a correct `Authorization` header.
pub fn signed_teams_request(body: &str) -> Request<Body> {
    teams_request(body, Some(&teams_authorization(&teams_secret(), body)))
}

/// Returns the present time in the form that Teams writes.
pub fn teams_now() -> Option<String> {
    Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}
