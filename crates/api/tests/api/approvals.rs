//! The approval routes.

use aegis_contracts::Error;
use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::{ApprovalQueue, ApprovalStatus, Principal, PrincipalKind};
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;

use crate::support::{
    APPROVER, DecideCall, TestApi, VIEWER, approval_request, executed_outcome, get, post, send,
    to_json,
};

fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

fn decision_path(id: ApprovalId) -> String {
    format!("/api/v1/approvals/{id}/decision")
}

#[tokio::test]
async fn the_list_has_the_pending_requests_oldest_first() {
    let api = TestApi::new();
    let first = api.seed_approval().await;
    let mut second = approval_request();
    second.requested_at = first.requested_at + chrono::Duration::minutes(1);
    api.approvals.submit(second.clone()).await.unwrap();
    let mut decided = approval_request();
    decided.status = ApprovalStatus::Rejected;
    api.approvals.submit(decided.clone()).await.unwrap();
    let router = api.router();

    for token in [VIEWER, APPROVER] {
        let reply = get(&router, "/api/v1/approvals", token).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json(),
            json!({ "items": [to_json(&first), to_json(&second)], "total": 2 })
        );
    }

    let reply = get(&router, "/api/v1/approvals?limit=1", VIEWER).await;
    assert_eq!(
        reply.json(),
        json!({ "items": [to_json(&first)], "total": 2 })
    );

    let reply = get(&router, "/api/v1/approvals?limit=none", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), "invalid_input");

    // One request by its identifier, with or without a decision.
    let reply = get(
        &router,
        &format!("/api/v1/approvals/{}", decided.id),
        VIEWER,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), to_json(&decided));
    let body = get(
        &router,
        &format!("/api/v1/approvals/{}", first.id),
        APPROVER,
    )
    .await
    .json();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["action"]["kind"], "disable_user");
    assert_eq!(body["requested_by"]["id"], "responder");
}

#[tokio::test]
async fn an_unknown_request_is_a_404_and_a_bad_identifier_is_a_400() {
    let api = TestApi::new();
    api.seed_approval().await;
    let router = api.router();

    let reply = get(
        &router,
        &format!("/api/v1/approvals/{}", ApprovalId::new()),
        VIEWER,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "not_found",
            "message": "The approval request does not exist."
        } })
    );
    let reply = get(&router, "/api/v1/approvals/not-a-uuid", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.error_message(),
        "The approval identifier is not a valid UUID."
    );

    let body = json!({ "approve": true });
    let reply = post(&router, &decision_path(ApprovalId::new()), APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.error_message(),
        "The approval request does not exist."
    );
    let reply = post(&router, "/api/v1/approvals/7/decision", APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(api.actions.calls().is_empty());
}

#[tokio::test]
async fn an_approval_calls_the_approval_path_with_the_principal_of_the_token() {
    let api = TestApi::new();
    let request = api.seed_approval().await;
    let router = api.router();

    let body = json!({ "approve": true, "note": "  Looks right. " });
    let reply = post(&router, &decision_path(request.id), APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::OK);

    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: request.id,
            approve: true,
            principal: alice(),
            note: Some("Looks right.".to_owned()),
        }]
    );
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Approved);
    assert_eq!(stored.decided_by.as_deref(), Some("alice@example.com"));
    assert_eq!(
        reply.json(),
        json!({
            "request": to_json(&stored),
            "disposition": { "executed": to_json(&executed_outcome(&request)) }
        })
    );
    let disposition = &reply.json()["disposition"]["executed"];
    assert_eq!(disposition["status"], "succeeded");
    assert_eq!(disposition["action_id"], to_json(&request.action.id));
}

#[tokio::test]
async fn a_rejection_has_no_disposition() {
    let api = TestApi::new();
    let request = api.seed_approval().await;
    let router = api.router();

    let reply = post(
        &router,
        &decision_path(request.id),
        APPROVER,
        &json!({ "approve": false }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["request"]["status"], "rejected");
    assert_eq!(body["request"]["decided_by"], "alice@example.com");
    assert_eq!(body["disposition"], json!(null));
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
async fn a_second_decision_is_a_409_and_does_not_reach_the_approval_path() {
    let api = TestApi::new();
    let request = api.seed_approval().await;
    let router = api.router();
    let path = decision_path(request.id);

    let first = post(&router, &path, APPROVER, &json!({ "approve": false })).await;
    assert_eq!(first.status, StatusCode::OK);

    for approve in [true, false] {
        let second = post(&router, &path, APPROVER, &json!({ "approve": approve })).await;
        assert_eq!(second.status, StatusCode::CONFLICT);
        assert_eq!(
            second.json(),
            json!({ "error": {
                "code": "conflict",
                "message": "The approval request already has a decision."
            } })
        );
    }
    assert_eq!(api.actions.calls().len(), 1);
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Rejected);
}

#[tokio::test]
async fn a_decision_body_that_is_not_valid_is_refused_before_the_approval_path() {
    let api = TestApi::new();
    let request = api.seed_approval().await;
    let router = api.router();
    let path = decision_path(request.id);

    let cases = [
        (
            json!({}),
            "The request body is not valid: missing field `approve`.",
        ),
        (
            json!({ "approve": "yes" }),
            "The request body is not valid: invalid type: string \"yes\", expected a boolean.",
        ),
        (
            json!({ "approve": true, "force": true }),
            "The request body is not valid: unknown field `force`, expected `approve` or `note`.",
        ),
        (
            json!({ "approve": true, "note": "x".repeat(1001) }),
            "The note must have 1000 characters or fewer.",
        ),
        // An array is not a decision, also when its items have the types of the fields.
        (
            json!([true, "a note"]),
            "The request body must be a JSON object.",
        ),
        (json!(true), "The request body must be a JSON object."),
    ];
    for (body, message) in cases {
        let reply = post(&router, &path, APPROVER, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            reply.json(),
            json!({ "error": { "code": "invalid_input", "message": message } }),
            "{body}"
        );
    }

    let not_json = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(AUTHORIZATION, format!("Bearer {APPROVER}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("approve=true"))
        .unwrap();
    let reply = send(&router, not_json).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "invalid_input",
            "message": "The request body is not valid: expected value at line 1 column 1."
        } })
    );

    let wrong_type = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(AUTHORIZATION, format!("Bearer {APPROVER}"))
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"approve":true}"#))
        .unwrap();
    let reply = send(&router, wrong_type).await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "unsupported_media_type",
            "message": "The request body must have the content type application/json."
        } })
    );

    assert!(api.actions.calls().is_empty());
    let stored = api.approvals.get(request.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
}

#[tokio::test]
async fn an_error_of_the_approval_path_has_its_status_and_no_internal_detail() {
    let api = TestApi::new();
    let request = api.seed_approval().await;
    let router = api.router();
    let path = decision_path(request.id);
    let body = json!({ "approve": true });

    api.actions.fail_next(Error::Unauthorized(
        "the principal that requested the action cannot approve it".to_owned(),
    ));
    let reply = post(&router, &path, APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "forbidden",
            "message": "the principal that requested the action cannot approve it"
        } })
    );

    api.actions.fail_next(Error::InvalidInput(format!(
        "approval request {} already has a decision",
        request.id
    )));
    let reply = post(&router, &path, APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.error_message(),
        format!("approval request {} already has a decision", request.id)
    );

    api.actions.fail_next(Error::Unavailable(
        "postgres://aegis:hunter2@db.internal:5432 refused the connection".to_owned(),
    ));
    let reply = post(&router, &path, APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "unavailable",
            "message": "A service is not available. Try again later."
        } })
    );
    assert!(!reply.text().contains("hunter2"));

    api.actions.fail_next(Error::other(
        "resume the action",
        std::io::Error::other("/var/lib/aegis"),
    ));
    let reply = post(&router, &path, APPROVER, &body).await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.error_code(), "internal");
    assert!(!reply.text().contains("/var/lib"));
    assert_eq!(api.actions.calls().len(), 4);
}
