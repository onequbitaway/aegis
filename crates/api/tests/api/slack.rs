//! The Slack endpoints.

use aegis_contracts::common::{ApprovalId, Severity};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{ApprovalQueue, ApprovalStatus, Principal, PrincipalKind};
use axum::http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::chat::{
    SLACK_ALICE, SLACK_SECRET, SLACK_TEAM, SLACK_VERA, chat_config, chat_env, command_body,
    interaction_body, now, signed_slack_request, slack_request, slack_signature,
};
use crate::support::{DecideCall, TestApi, VIEWER, config, get, incident, send};

const COMMANDS: &str = "/chatops/slack/commands";
const INTERACTIONS: &str = "/chatops/slack/interactions";

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

fn plain(text: &str) -> Value {
    json!({ "type": "plain_text", "text": text, "emoji": false })
}

fn section(text: &str) -> Value {
    json!({ "type": "section", "text": plain(text) })
}

fn buttons(id: ApprovalId) -> Value {
    json!({
        "type": "actions",
        "block_id": format!("aegis_approval_{id}"),
        "elements": [
            {
                "type": "button",
                "action_id": "aegis_approve",
                "style": "primary",
                "text": plain("Approve"),
                "value": id.to_string(),
                "confirm": {
                    "title": plain("Approve the action?"),
                    "text": plain("AEGIS runs the action after the approval."),
                    "confirm": plain("Approve"),
                    "deny": plain("Cancel")
                }
            },
            {
                "type": "button",
                "action_id": "aegis_reject",
                "style": "danger",
                "text": plain("Reject"),
                "value": id.to_string()
            }
        ]
    })
}

#[tokio::test]
async fn a_signed_command_lists_the_pending_approvals_with_buttons() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());

    let body = command_body(SLACK_TEAM, SLACK_ALICE, "approvals");
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    let summary = "Actions that wait for approval: 1. This message shows 1.";
    assert_eq!(
        reply.json(),
        json!({
            "response_type": "ephemeral",
            "text": summary,
            "blocks": [
                section(summary),
                section(
                    "Action: disable_user\n\
                     Target: user victim@example.com (user-1)\n\
                     Reason: The account signed in from the spray address.\n\
                     Requested by: responder\n\
                     Policy: The action is in the gated tier."
                ),
                { "type": "context", "elements": [plain(&format!("Approval {}", request.id))] },
                buttons(request.id)
            ]
        })
    );
    assert!(api.actions.calls().is_empty());
}

#[tokio::test]
async fn a_signed_approve_command_reaches_the_approval_path_with_the_mapped_principal() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());

    let text = format!("approve {} checked with the owner", request.id);
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &text);
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: request.id,
            approve: true,
            principal: alice(),
            note: Some("checked with the owner".to_owned()),
        }]
    );
    assert_eq!(
        reply.json(),
        json!({
            "response_type": "ephemeral",
            "text": "alice@example.com approved the action disable_user on user \
                     victim@example.com (user-1).\n\
                     The action ran: The connector did the action."
        })
    );

    // A second decision is refused with the reason, and it does not reach the approval path.
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("reject {}", request.id));
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "response_type": "ephemeral",
            "text": "The approval request already has a decision."
        })
    );
    assert_eq!(api.actions.calls().len(), 1);
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
async fn a_wrong_signature_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {}", request.id));
    let timestamp = now();

    let other_secret = slack_signature("a-different-secret-0123456789abcdef", timestamp, &body);
    let other_body = slack_signature(SLACK_SECRET, timestamp, &body.replace("approve", "reject"));
    let other_time = slack_signature(SLACK_SECRET, timestamp - 1, &body);
    let correct = slack_signature(SLACK_SECRET, timestamp, &body);
    let no_version = correct.trim_start_matches("v0=").to_owned();
    for signature in [
        other_secret,
        other_body,
        other_time,
        no_version,
        "v0=00".to_owned(),
    ] {
        let refused = slack_request(
            COMMANDS,
            &body,
            Some(&timestamp.to_string()),
            Some(&signature),
        );
        assert_refused_with_401(&api, refused, request.id).await;
    }

    // The same request with the correct signature is accepted, so the refusals above come
    // from the signature only.
    let router = api.router_with(&chat_config());
    let accepted = slack_request(
        COMMANDS,
        &body,
        Some(&timestamp.to_string()),
        Some(&correct),
    );
    assert_eq!(send(&router, accepted).await.status, StatusCode::OK);
    assert_eq!(api.actions.calls().len(), 1);
}

#[tokio::test]
async fn a_missing_signature_header_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {}", request.id));
    let timestamp = now().to_string();
    let signature = slack_signature(SLACK_SECRET, now(), &body);

    for (timestamp, signature) in [
        (None, Some(signature.as_str())),
        (Some(timestamp.as_str()), None),
        (None, None),
    ] {
        let refused = slack_request(COMMANDS, &body, timestamp, signature);
        assert_refused_with_401(&api, refused, request.id).await;
    }
    for path in [COMMANDS, INTERACTIONS] {
        let refused = slack_request(path, &body, None, None);
        assert_refused_with_401(&api, refused, request.id).await;
    }
}

#[tokio::test]
async fn an_old_timestamp_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {}", request.id));

    // The signature is correct for the timestamp. Only the age of the request is wrong.
    // A time in the future has a margin, because the server reads the clock after the test.
    for age in [301, 3_600, -330] {
        let timestamp = now() - age;
        let signature = slack_signature(SLACK_SECRET, timestamp, &body);
        let refused = slack_request(
            COMMANDS,
            &body,
            Some(&timestamp.to_string()),
            Some(&signature),
        );
        assert_refused_with_401(&api, refused, request.id).await;
    }

    let router = api.router_with(&chat_config());
    let timestamp = now() - 200;
    let signature = slack_signature(SLACK_SECRET, timestamp, &body);
    let recent = slack_request(
        COMMANDS,
        &body,
        Some(&timestamp.to_string()),
        Some(&signature),
    );
    assert_eq!(send(&router, recent).await.status, StatusCode::OK);
    assert_eq!(api.actions.calls().len(), 1);
}

#[tokio::test]
async fn an_unknown_user_is_refused_with_no_side_effect() {
    let api = chat_api();
    let request = api.seed_approval().await;
    api.seed_incident("Password spray", Severity::High).await;
    let router = api.router_with(&chat_config());
    let refusal = json!({
        "response_type": "ephemeral",
        "text": "You are not permitted to use AEGIS from this chat."
    });

    let approve = format!("approve {}", request.id);
    for (team, user, text) in [
        (SLACK_TEAM, "U0MALLORY", approve.as_str()),
        (SLACK_TEAM, "U0MALLORY", "incidents"),
        (SLACK_TEAM, "U0MALLORY", "approvals"),
        // A known user identifier in a different workspace is a different person.
        ("T0OTHER", SLACK_ALICE, approve.as_str()),
        (SLACK_TEAM, "", approve.as_str()),
    ] {
        let body = command_body(team, user, text);
        let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
        assert_eq!(reply.status, StatusCode::OK, "{team} {user} {text}");
        assert_eq!(reply.json(), refusal, "{team} {user} {text}");
    }
    assert!(api.actions.calls().is_empty());
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
}

#[tokio::test]
async fn a_user_without_the_permission_cannot_decide() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());

    let body = command_body(SLACK_TEAM, SLACK_VERA, &format!("approve {}", request.id));
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "response_type": "ephemeral",
            "text": "The principal does not have the permission approve_actions."
        })
    );
    assert!(api.actions.calls().is_empty());

    // The same user can read: the access rules are the rules of the REST API.
    let body = command_body(SLACK_TEAM, SLACK_VERA, "approvals");
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(
        reply.json()["text"],
        "Actions that wait for approval: 1. This message shows 1."
    );
    // A user who can approve but cannot read incidents does not get the incident list.
    let body = command_body(SLACK_TEAM, SLACK_ALICE, "incidents");
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(
        reply.json()["text"],
        "The principal does not have the permission view_incidents."
    );
}

#[tokio::test]
async fn incident_text_with_markup_characters_is_escaped() {
    let api = chat_api();
    let mut hostile = incident(
        "<!channel> *urgent* <https://evil.example|click here> & <@U0ALICE>\nSeverity: low",
        Severity::Critical,
    );
    hostile.summary = "<script>alert(1)</script>".to_owned();
    api.incidents.save(&hostile).await.unwrap();
    let router = api.router_with(&chat_config());

    let body = command_body(SLACK_TEAM, SLACK_VERA, "incidents");
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "response_type": "ephemeral",
            "text": "The newest incidents: 1",
            "blocks": [
                section("The newest incidents: 1"),
                section(&format!(
                    "critical | open | &lt;!channel&gt; *urgent* \
                     &lt;https://evil.example|click here&gt; &amp; &lt;@U0ALICE&gt; \
                     Severity: low\n{}",
                    hostile.id
                ))
            ]
        })
    );
    // No control character of Slack is in the answer, in any field.
    let text = reply.text();
    assert!(!text.contains('<'), "{text}");
    assert!(!text.contains('>'), "{text}");
}

#[tokio::test]
async fn a_command_that_is_not_valid_gives_a_message_and_help_lists_the_commands() {
    let api = chat_api();
    let router = api.router_with(&chat_config());
    for (text, expected) in [
        (
            "approve",
            "Give the identifier of the approval request: approve &lt;id&gt; [note].",
        ),
        (
            "approve 42",
            "The identifier of the approval request is not a valid UUID.",
        ),
        (
            "delete everything",
            "The command is not known. Send help to see the commands.",
        ),
        (
            "",
            "AEGIS commands:\n\
             incidents - show the newest incidents\n\
             approvals - show the actions that wait for approval\n\
             approve &lt;id&gt; [note] - approve one action\n\
             reject &lt;id&gt; [note] - reject one action",
        ),
    ] {
        let body = command_body(SLACK_TEAM, SLACK_ALICE, text);
        let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
        assert_eq!(reply.status, StatusCode::OK, "{text}");
        assert_eq!(
            reply.json(),
            json!({ "response_type": "ephemeral", "text": expected }),
            "{text}"
        );
    }
    let unknown = ApprovalId::new();
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {unknown}"));
    let reply = send(&router, signed_slack_request(COMMANDS, &body)).await;
    assert_eq!(reply.json()["text"], "The approval request does not exist.");
    assert!(api.actions.calls().is_empty());
}

/// Starts a server that takes the answers to buttons, and a configuration that permits it.
async fn response_server() -> (MockServer, aegis_api::ApiConfig) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/actions/respond"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut config = chat_config();
    let host = server.address().ip().to_string();
    config.chatops.slack.as_mut().unwrap().response_hosts = vec![host];
    (server, config)
}

async fn posted(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .collect()
}

#[tokio::test]
async fn an_approve_button_reaches_the_approval_path_and_replaces_the_message() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let (server, config) = response_server().await;
    let router = api.router_with(&config);
    let response_url = format!("{}/actions/respond", server.uri());

    let body = interaction_body(
        SLACK_TEAM,
        SLACK_ALICE,
        "aegis_approve",
        &request.id.to_string(),
        Some(&response_url),
    );
    let reply = send(&router, signed_slack_request(INTERACTIONS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: request.id,
            approve: true,
            principal: alice(),
            note: None,
        }]
    );
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Approved);

    // The handler sends the answer before it returns, so the server has it now.
    let expected = json!({
        "replace_original": true,
        "text": "alice@example.com approved the action disable_user on user \
                 victim@example.com (user-1).\n\
                 The action ran: The connector did the action."
    });
    assert_eq!(reply.json(), expected);
    assert_eq!(posted(&server).await, [expected]);
}

#[tokio::test]
async fn a_reject_button_records_a_rejection() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let (server, config) = response_server().await;
    let router = api.router_with(&config);
    let response_url = format!("{}/actions/respond", server.uri());

    let body = interaction_body(
        SLACK_TEAM,
        SLACK_ALICE,
        "aegis_reject",
        &request.id.to_string(),
        Some(&response_url),
    );
    let reply = send(&router, signed_slack_request(INTERACTIONS, &body)).await;
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
    assert_eq!(
        posted(&server).await,
        [json!({
            "replace_original": true,
            "text": "alice@example.com rejected the action disable_user on user \
                     victim@example.com (user-1)."
        })]
    );
}

#[tokio::test]
async fn a_button_of_a_person_who_cannot_decide_changes_nothing_and_keeps_the_message() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let (server, config) = response_server().await;
    let router = api.router_with(&config);
    let response_url = format!("{}/actions/respond", server.uri());
    let id = request.id.to_string();

    let cases = [
        (
            SLACK_TEAM,
            "U0MALLORY",
            "You are not permitted to use AEGIS from this chat.",
        ),
        (
            "T0OTHER",
            SLACK_ALICE,
            "You are not permitted to use AEGIS from this chat.",
        ),
        (
            SLACK_TEAM,
            SLACK_VERA,
            "The principal does not have the permission approve_actions.",
        ),
    ];
    for (team, user, text) in cases {
        let body = interaction_body(team, user, "aegis_approve", &id, Some(&response_url));
        let reply = send(&router, signed_slack_request(INTERACTIONS, &body)).await;
        assert_eq!(reply.status, StatusCode::OK, "{team} {user}");
        assert_eq!(
            reply.json(),
            json!({ "response_type": "ephemeral", "replace_original": false, "text": text }),
            "{team} {user}"
        );
    }
    assert!(api.actions.calls().is_empty());
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
    let answers = posted(&server).await;
    assert_eq!(answers.len(), 3);
    for answer in answers {
        assert_eq!(answer["replace_original"], false);
    }
}

#[tokio::test]
async fn the_answer_to_a_button_goes_only_to_a_permitted_host() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    // The default configuration permits only hooks.slack.com.
    let router = api.router_with(&chat_config());
    let response_url = format!("{}/actions/respond", server.uri());

    let body = interaction_body(
        SLACK_TEAM,
        SLACK_ALICE,
        "aegis_approve",
        &request.id.to_string(),
        Some(&response_url),
    );
    let reply = send(&router, signed_slack_request(INTERACTIONS, &body)).await;
    assert_eq!(reply.status, StatusCode::OK);
    // The decision is recorded. The server did not call the URL of the request.
    assert_eq!(api.actions.calls().len(), 1);
    assert_eq!(posted(&server).await, Vec::<Value>::new());
}

#[tokio::test]
async fn an_interaction_that_is_not_a_button_of_aegis_is_a_400() {
    let api = chat_api();
    let request = api.seed_approval().await;
    let router = api.router_with(&chat_config());
    let id = request.id.to_string();

    let other_button = interaction_body(SLACK_TEAM, SLACK_ALICE, "other_app_button", &id, None);
    let bad_value = interaction_body(SLACK_TEAM, SLACK_ALICE, "aegis_approve", "42", None);
    let view = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "payload",
            &json!({ "type": "view_submission", "user": { "id": SLACK_ALICE } }).to_string(),
        )
        .finish();
    let not_json = "payload=%7Bnot+json".to_owned();
    let no_payload = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {id}"));
    for body in [other_button, bad_value, view, not_json, no_payload] {
        let reply = send(&router, signed_slack_request(INTERACTIONS, &body)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            reply.json(),
            json!({ "error": {
                "code": "invalid_input",
                "message": "The interaction is not valid."
            } })
        );
    }
    assert!(api.actions.calls().is_empty());
}

#[tokio::test]
async fn the_slack_endpoints_do_not_exist_without_a_signing_secret() {
    let api = chat_api();
    let request = api.seed_approval().await;
    // The configuration has no ChatOps section.
    let router = api.router_with(&config());
    let body = command_body(SLACK_TEAM, SLACK_ALICE, &format!("approve {}", request.id));
    for path in [COMMANDS, INTERACTIONS, "/chatops/teams/messages"] {
        let reply = send(&router, signed_slack_request(path, &body)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.error_code(), "not_found");
    }
    assert!(api.actions.calls().is_empty());
    // The REST API is not affected.
    assert_eq!(
        get(&router, "/api/v1/session", VIEWER).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_signed_request_must_be_a_form() {
    let api = chat_api();
    let router = api.router_with(&chat_config());
    let body = command_body(SLACK_TEAM, SLACK_ALICE, "approvals");
    let timestamp = now();
    let signature = slack_signature(SLACK_SECRET, timestamp, &body);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(COMMANDS)
        .header("content-type", "application/json")
        .header("x-slack-request-timestamp", timestamp.to_string())
        .header("x-slack-signature", signature)
        .body(axum::body::Body::from(body))
        .unwrap();
    let reply = send(&router, request).await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(reply.error_code(), "unsupported_media_type");
}
