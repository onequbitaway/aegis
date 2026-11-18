//! The routes of the timed reverts, and the revert of one action.

use std::time::Duration;

use aegis_api::{ApiState, route_permissions};
use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditRecord};
use aegis_contracts::common::{ActionId, EntityKind, EntityRef, EvidenceKind};
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_respond::revert::event;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::support::{APPROVER, AUDITOR, TestApi, VIEWER, config, env, get, post, to_json};

fn responder() -> Principal {
    Principal::new("responder", PrincipalKind::Agent, &["responder"])
}

/// Blocks one address through the dispatcher of the test API. With `revert_after`, the
/// request has a timed revert.
async fn block(api: &TestApi, address: &str, revert_after: Option<u64>) -> ActionId {
    let mut request = ActionRequest::new(
        ActionKind::BlockIp,
        EntityRef::new(EntityKind::IpAddress, address),
        "responder",
        "The attack came from this address.",
    );
    if let Some(seconds) = revert_after {
        request
            .parameters
            .insert("revert_after_seconds".to_owned(), seconds.into());
    }
    let id = request.id;
    let disposition = api
        .dispatcher
        .dispatch(request, &responder())
        .await
        .unwrap();
    assert!(
        matches!(&disposition, ActionDisposition::Executed(outcome)
            if outcome.status == ActionStatus::Succeeded),
        "{disposition:?}"
    );
    id
}

/// Returns the audit records of the scheduler with the field `event` set to `name`.
fn scheduler_records(api: &TestApi, name: &str) -> Vec<AuditRecord> {
    api.audit
        .records()
        .into_iter()
        .filter(|record| record.kind == AuditKind::Other && record.payload["event"] == name)
        .collect()
}

fn path(action_id: ActionId, operation: &str) -> String {
    format!("/api/v1/reverts/{action_id}/{operation}")
}

#[tokio::test]
async fn the_list_has_the_pending_reverts_with_the_earliest_time_first() {
    let api = TestApi::new();
    let later = block(&api, "203.0.113.50", Some(7200)).await;
    let sooner = block(&api, "203.0.113.51", Some(600)).await;
    // An action with no revert time has no pending revert.
    block(&api, "203.0.113.52", None).await;
    let pending = api.scheduler.pending().await.unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|revert| revert.action_id)
            .collect::<Vec<_>>(),
        [sooner, later]
    );
    let router = api.router();

    for token in [VIEWER, APPROVER] {
        let reply = get(&router, "/api/v1/reverts", token).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json(),
            json!({ "enabled": true, "items": to_json(&pending), "total": 2 })
        );
    }
    let first = &get(&router, "/api/v1/reverts", VIEWER).await.json()["items"][0];
    assert_eq!(first["action_id"], json!(sooner));
    assert_eq!(first["kind"], "block_ip");
    assert_eq!(first["target"]["id"], "203.0.113.51");
    assert_eq!(first["revert_after_seconds"], 600);
    assert_eq!(first["state"], "waiting");
    assert_eq!(first["requested_by"], "responder");

    let reply = get(&router, "/api/v1/reverts?limit=1", VIEWER).await;
    assert_eq!(
        reply.json(),
        json!({ "enabled": true, "items": [to_json(&pending[0])], "total": 2 })
    );
    let reply = get(&router, "/api/v1/reverts?state=waiting", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), "invalid_input");
}

#[tokio::test(start_paused = true)]
async fn a_confirmation_keeps_the_action_and_the_audit_record_names_the_principal() {
    let api = TestApi::new();
    let confirmed = block(&api, "203.0.113.50", Some(3600)).await;
    let not_confirmed = block(&api, "203.0.113.51", Some(3600)).await;
    let router = api.router();

    let reply = post(&router, &path(confirmed, "confirm"), APPROVER, &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    assert_eq!(body["revert"]["action_id"], json!(confirmed));
    assert_eq!(body["revert"]["target"]["id"], "203.0.113.50");

    // The audit record has the principal of the token and a link to the action.
    let records = scheduler_records(&api, event::CONFIRMED);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].actor, "alice@example.com");
    assert_eq!(records[0].payload["principal"]["id"], "alice@example.com");
    assert_eq!(records[0].payload["principal"]["kind"], "human");
    assert_eq!(records[0].payload["action_id"], json!(confirmed));
    assert!(
        records[0]
            .evidence
            .iter()
            .any(|link| link.kind == EvidenceKind::Action && link.id == confirmed.to_string())
    );

    // After the revert time, the scheduler reverts only the action that nobody confirmed.
    tokio::time::advance(Duration::from_secs(3601)).await;
    let attempts = api.scheduler.run_due().await.unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].action_id, not_confirmed);
    let reverted = api.firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, not_confirmed);
    let reply = get(&router, "/api/v1/reverts", VIEWER).await;
    assert_eq!(
        reply.json(),
        json!({ "enabled": true, "items": [], "total": 0 })
    );

    // A second confirmation finds no pending revert.
    let reply = post(&router, &path(confirmed, "confirm"), APPROVER, &json!({})).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.error_code(), "not_found");
}

#[tokio::test(start_paused = true)]
async fn an_extension_moves_the_revert_time() {
    let api = TestApi::new();
    let action = block(&api, "203.0.113.50", Some(600)).await;
    let before = api.scheduler.get(action).await.unwrap().unwrap();
    let router = api.router();

    let reply = post(
        &router,
        &path(action, "extend"),
        APPROVER,
        &json!({ "seconds": 1800 }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let after = api.scheduler.get(action).await.unwrap().unwrap();
    assert_eq!(
        after.due_at,
        before.due_at + chrono::Duration::seconds(1800)
    );
    assert_eq!(reply.json(), json!({ "revert": to_json(&after) }));
    let records = scheduler_records(&api, event::EXTENDED);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].actor, "alice@example.com");
    assert_eq!(
        records[0].payload["previous_due_at"],
        to_json(&before.due_at)
    );

    // The action is not reverted at the first revert time.
    tokio::time::advance(Duration::from_secs(601)).await;
    assert_eq!(api.scheduler.run_due().await.unwrap(), []);
    assert_eq!(api.firewall.reverted().len(), 0);
    tokio::time::advance(Duration::from_secs(1800)).await;
    assert_eq!(api.scheduler.run_due().await.unwrap().len(), 1);
    assert_eq!(api.firewall.reverted().len(), 1);

    for body in [
        json!({ "seconds": 0 }),
        json!({ "seconds": -5 }),
        json!({ "seconds": "600" }),
        json!({}),
        json!({ "seconds": 600, "reason": "x" }),
    ] {
        let reply = post(&router, &path(action, "extend"), APPROVER, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), "invalid_input", "{body}");
    }
}

#[tokio::test]
async fn a_cancel_reverts_the_action_now_through_the_dispatcher() {
    let api = TestApi::new();
    let action = block(&api, "203.0.113.50", Some(3600)).await;
    let router = api.router();

    let reply = post(&router, &path(action, "cancel"), APPROVER, &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    assert_eq!(body["disposition"]["executed"]["status"], "succeeded");
    assert_eq!(body["disposition"]["executed"]["connector"], "firewall");
    let reverted = api.firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action);
    assert_eq!(api.scheduler.pending().await.unwrap(), []);

    // The revert is a request of its own. Its proposal names the principal of the token.
    let records = api.audit.records();
    let proposals: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| {
            record.kind == AuditKind::ActionProposed && record.payload["operation"] == "revert"
        })
        .collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].actor, "alice@example.com");
    assert_eq!(proposals[0].payload["principal"]["id"], "alice@example.com");
    assert_eq!(proposals[0].payload["reverts"]["action_id"], json!(action));
    let cancelled = scheduler_records(&api, event::CANCELLED);
    assert_eq!(cancelled.len(), 1);
    assert_eq!(cancelled[0].actor, "alice@example.com");
}

#[tokio::test]
async fn one_action_is_reverted_with_a_reason_and_only_one_time() {
    let api = TestApi::new();
    // The action has no revert time.
    let action = block(&api, "203.0.113.50", None).await;
    let router = api.router();
    let revert_path = format!("/api/v1/actions/{action}/revert");

    for body in [
        json!({}),
        json!({ "reason": " \n " }),
        json!({ "reason": "x".repeat(1001) }),
        json!({ "reason": "A wrong block.", "force": true }),
    ] {
        let reply = post(&router, &revert_path, APPROVER, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(api.firewall.reverted().len(), 0);

    let reply = post(
        &router,
        &revert_path,
        APPROVER,
        &json!({ "reason": "The address is the proxy\n of a partner." }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.json()["disposition"]["executed"]["status"],
        "succeeded"
    );
    let reverted = api.firewall.reverted();
    assert_eq!(reverted.len(), 1);
    assert_eq!(reverted[0].id, action);
    let records = api.audit.records();
    let proposal = records
        .iter()
        .find(|record| {
            record.kind == AuditKind::ActionProposed && record.payload["operation"] == "revert"
        })
        .unwrap();
    assert_eq!(proposal.actor, "alice@example.com");
    // The reason is one line in the audit log.
    assert_eq!(
        proposal.payload["action"]["reason"],
        "The address is the proxy of a partner."
    );

    // One execution can be reverted one time.
    let reply = post(
        &router,
        &revert_path,
        APPROVER,
        &json!({ "reason": "Again." }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), "invalid_input");
    assert_eq!(api.firewall.reverted().len(), 1);

    // An action that the audit log does not have.
    let unknown = format!("/api/v1/actions/{}/revert", ActionId::new());
    let reply = post(&router, &unknown, APPROVER, &json!({ "reason": "Test." })).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unknown_action_is_a_404_and_a_bad_identifier_is_a_400() {
    let api = TestApi::new();
    block(&api, "203.0.113.50", Some(3600)).await;
    let router = api.router();

    for operation in ["confirm", "cancel"] {
        let reply = post(
            &router,
            &path(ActionId::new(), operation),
            APPROVER,
            &json!({}),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{operation}");
        assert_eq!(reply.error_code(), "not_found", "{operation}");

        let bad = format!("/api/v1/reverts/not-a-uuid/{operation}");
        let reply = post(&router, &bad, APPROVER, &json!({})).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{operation}");
        assert_eq!(
            reply.error_message(),
            "The action identifier is not a valid UUID."
        );

        // A body with a field that the route does not know.
        let action = api.scheduler.pending().await.unwrap()[0].action_id;
        let reply = post(
            &router,
            &path(action, operation),
            APPROVER,
            &json!({ "note": "x" }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{operation}");
    }
    let reply = post(
        &router,
        &path(ActionId::new(), "extend"),
        APPROVER,
        &json!({ "seconds": 60 }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    // Nothing changed.
    assert_eq!(api.scheduler.pending().await.unwrap().len(), 1);
    assert_eq!(api.firewall.reverted().len(), 0);
}

#[tokio::test]
async fn a_principal_without_the_permission_changes_nothing() {
    let api = TestApi::new();
    let action = block(&api, "203.0.113.50", Some(3600)).await;
    let records_before = api.audit.records().len();
    let router = api.router();

    let routes: Vec<_> = route_permissions()
        .into_iter()
        .filter(|route| route.method == "POST" && route.path.contains("revert"))
        .collect();
    assert_eq!(routes.len(), 4);
    for route in routes {
        let concrete = format!(
            "/api/v1{}",
            route
                .path
                .replace("{action_id}", &action.to_string())
                .replace("{id}", &action.to_string())
        );
        let body = json!({ "seconds": 60, "reason": "Test." });
        // No token, and tokens of principals that cannot approve.
        let reply = crate::support::send(
            &router,
            crate::support::request(axum::http::Method::POST, &concrete, None, Some(&body)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{concrete}");
        for token in [VIEWER, AUDITOR] {
            let reply = post(&router, &concrete, token, &body).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{concrete}");
            assert_eq!(
                reply.error_message(),
                "The principal does not have the permission approve_actions."
            );
        }
    }
    // The audit reader cannot list the pending reverts.
    let reply = get(&router, "/api/v1/reverts", AUDITOR).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    assert_eq!(api.scheduler.pending().await.unwrap().len(), 1);
    assert_eq!(api.firewall.reverted().len(), 0);
    assert_eq!(api.audit.records().len(), records_before);
}

#[tokio::test]
async fn a_state_with_no_revert_path_has_an_empty_list_and_refuses_each_change() {
    let api = TestApi::new();
    let action = block(&api, "203.0.113.50", Some(3600)).await;
    // The state has the same services, and no revert path.
    let state = ApiState::new(api.state.parts().clone()).with_env(env(&[]));
    let router = aegis_api::router(state, &config()).unwrap();

    let reply = get(&router, "/api/v1/reverts", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({ "enabled": false, "items": [], "total": 0 })
    );
    let requests: [(String, Value); 4] = [
        (path(action, "confirm"), json!({})),
        (path(action, "extend"), json!({ "seconds": 60 })),
        (path(action, "cancel"), json!({})),
        (
            format!("/api/v1/actions/{action}/revert"),
            json!({ "reason": "Test." }),
        ),
    ];
    for (request_path, body) in requests {
        let reply = post(&router, &request_path, APPROVER, &body).await;
        assert_eq!(reply.status, StatusCode::NOT_IMPLEMENTED, "{request_path}");
        assert_eq!(reply.error_code(), "unsupported", "{request_path}");
    }
    assert_eq!(api.scheduler.pending().await.unwrap().len(), 1);
    assert_eq!(api.firewall.reverted().len(), 0);
}
