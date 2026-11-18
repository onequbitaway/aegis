//! The limits of the server, and the absence of cross-origin access.

use std::sync::Arc;

use aegis_api::{ApiParts, ApiState};
use aegis_contracts::Result;
use aegis_contracts::common::IncidentId;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;

use crate::support::{ADMIN, TestApi, VIEWER, config, env, get, post, send};

#[tokio::test]
async fn a_body_that_is_larger_than_the_limit_is_a_413() {
    let api = TestApi::new();
    let mut config = config();
    config.limits.max_body_bytes = 256;
    let router = api.router_with(&config);

    let reply = post(
        &router,
        "/api/v1/goal",
        ADMIN,
        &json!({ "text": "x".repeat(300) }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "payload_too_large",
            "message": "The request body is too large."
        } })
    );
    assert_eq!(api.agents.queued(), 0);
    assert!(api.audit.records().is_empty());

    // A body below the limit passes.
    let reply = post(
        &router,
        "/api/v1/goal",
        ADMIN,
        &json!({ "text": "x".repeat(100) }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

/// An incident store that never answers.
struct StalledIncidents;

#[async_trait]
impl IncidentStore for StalledIncidents {
    async fn save(&self, _incident: &Incident) -> Result<()> {
        std::future::pending().await
    }

    async fn get(&self, _id: IncidentId) -> Result<Option<Incident>> {
        std::future::pending().await
    }

    async fn list(&self, _status: Option<IncidentStatus>, _limit: usize) -> Result<Vec<Incident>> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_that_takes_more_time_than_the_limit_is_a_504() {
    let api = TestApi::new();
    let parts = ApiParts {
        incidents: Arc::new(StalledIncidents),
        ..api.state.parts().clone()
    };
    let state = ApiState::new(parts).with_env(env(&[]));
    let mut config = config();
    config.limits.request_timeout_seconds = 2;
    let router = aegis_api::router(state, &config).unwrap();

    let started = tokio::time::Instant::now();
    let reply = get(&router, "/api/v1/incidents", VIEWER).await;
    assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "timeout",
            "message": "The request took more time than the limit."
        } })
    );
    assert_eq!(started.elapsed().as_secs(), 2);
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));

    // A route that does not use the stalled store still answers.
    let reply = get(&router, "/api/v1/session", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn the_server_gives_no_cross_origin_access() {
    let api = TestApi::new();
    let router = api.router();

    let cross_origin = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/session")
        .header(AUTHORIZATION, format!("Bearer {VIEWER}"))
        .header(ORIGIN, "https://other.example")
        .body(Body::empty())
        .unwrap();
    let reply = send(&router, cross_origin).await;
    assert_eq!(reply.status, StatusCode::OK);
    let cors_headers: Vec<&str> = reply
        .headers
        .keys()
        .map(|name| name.as_str())
        .filter(|name| name.starts_with("access-control-"))
        .collect();
    assert_eq!(cors_headers, Vec::<&str>::new());

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/goal")
        .header(ORIGIN, "https://other.example")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .body(Body::empty())
        .unwrap();
    let reply = send(&router, preflight).await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(reply.header("access-control-allow-origin").is_none());
    assert!(reply.header("access-control-allow-headers").is_none());
}

#[tokio::test]
async fn two_authorization_headers_are_refused() {
    let api = TestApi::new();
    let router = api.router();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/session")
        .header(AUTHORIZATION, format!("Bearer {VIEWER}"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();
    let reply = send(&router, request).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}
