//! The live feed.

use std::time::Duration;

use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::Severity;
use axum::Router;
use axum::body::BodyDataStream;
use axum::http::{Method, StatusCode};
use futures::StreamExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::support::{
    ANALYST, APPROVER, TestApi, VIEWER, approval_request, config, incident, request, send, to_json,
};

/// An open live feed: the body of the response and the text that is not parsed yet.
pub struct Feed {
    body: BodyDataStream,
    buffer: String,
}

impl Feed {
    /// Opens the live feed with a bearer token. The response must be a 200.
    pub async fn open(router: &Router, token: &str) -> Self {
        let response = router
            .clone()
            .oneshot(request(Method::GET, "/api/v1/stream", Some(token), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        Self {
            body: response.into_body().into_data_stream(),
            buffer: String::new(),
        }
    }

    /// Reads the next event: its type and its JSON data. Comments are skipped.
    pub async fn next(&mut self) -> (String, Value) {
        tokio::time::timeout(Duration::from_secs(10), self.read_event())
            .await
            .expect("the live feed gave no event in time")
            .expect("the live feed ended")
    }

    async fn read_event(&mut self) -> Option<(String, Value)> {
        loop {
            while let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                let mut event = String::new();
                let mut data = String::new();
                for line in block.lines() {
                    if let Some(value) = line.strip_prefix("event: ") {
                        event = value.to_owned();
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        data.push_str(value);
                    }
                }
                if !data.is_empty() {
                    return Some((event, serde_json::from_str(&data).unwrap()));
                }
            }
            let chunk = self.body.next().await?.unwrap();
            self.buffer.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }
}

#[tokio::test]
async fn a_bus_message_arrives_as_a_typed_event() {
    let api = TestApi::new();
    let router = api.router();
    let mut feed = Feed::open(&router, VIEWER).await;

    assert_eq!(
        feed.next().await,
        (
            "ready".to_owned(),
            json!({ "feeds": ["detection", "incident", "action_result", "approval"] })
        )
    );

    let incident = incident("Password spray", Severity::High);
    publish_json(api.bus.as_ref(), subject::INCIDENTS, &incident)
        .await
        .unwrap();
    assert_eq!(
        feed.next().await,
        (
            "incident".to_owned(),
            json!({ "subject": "aegis.incidents", "payload": to_json(&incident) })
        )
    );

    let detection = &incident.detections[0];
    publish_json(
        api.bus.as_ref(),
        "aegis.detections.deterministic",
        detection,
    )
    .await
    .unwrap();
    assert_eq!(
        feed.next().await,
        (
            "detection".to_owned(),
            json!({ "subject": "aegis.detections.deterministic", "payload": to_json(detection) })
        )
    );

    let approval = approval_request();
    publish_json(api.bus.as_ref(), subject::APPROVALS, &approval)
        .await
        .unwrap();
    assert_eq!(
        feed.next().await,
        (
            "approval".to_owned(),
            json!({ "subject": "aegis.approvals", "payload": to_json(&approval) })
        )
    );

    let result = json!({ "denied": to_json(&approval.decision) });
    publish_json(api.bus.as_ref(), subject::ACTION_RESULTS, &result)
        .await
        .unwrap();
    assert_eq!(
        feed.next().await,
        (
            "action_result".to_owned(),
            json!({ "subject": "aegis.actions.results", "payload": result })
        )
    );
}

#[tokio::test]
async fn the_feed_gives_audit_records_only_to_a_principal_that_can_read_the_audit_log() {
    let api = TestApi::new();
    let router = api.router();
    let mut viewer = Feed::open(&router, VIEWER).await;
    let mut analyst = Feed::open(&router, ANALYST).await;
    assert_eq!(viewer.next().await.0, "ready");
    assert_eq!(
        analyst.next().await,
        (
            "ready".to_owned(),
            json!({ "feeds": ["detection", "incident", "action_result", "approval", "audit"] })
        )
    );

    let record = api
        .audit
        .append(AuditEntry::new(
            AuditKind::AgentDecision,
            "analyst",
            "A decision.",
        ))
        .await
        .unwrap();
    publish_json(api.bus.as_ref(), subject::AUDIT, &record)
        .await
        .unwrap();
    assert_eq!(
        analyst.next().await,
        (
            "audit".to_owned(),
            json!({ "subject": "aegis.audit", "payload": to_json(&record) })
        )
    );

    // The bus got the audit record before the incident. The viewer gets only the incident.
    let incident = incident("Password spray", Severity::High);
    publish_json(api.bus.as_ref(), subject::INCIDENTS, &incident)
        .await
        .unwrap();
    assert_eq!(analyst.next().await.0, "incident");
    assert_eq!(viewer.next().await.0, "incident");
}

#[tokio::test]
async fn a_message_that_is_not_json_and_a_message_of_a_different_subject_are_not_in_the_feed() {
    let api = TestApi::new();
    let router = api.router();
    let mut feed = Feed::open(&router, VIEWER).await;
    assert_eq!(feed.next().await.0, "ready");

    api.bus
        .publish(subject::INCIDENTS, b"<not json>".to_vec())
        .await
        .unwrap();
    publish_json(api.bus.as_ref(), "aegis.events.entra", &json!({ "a": 1 }))
        .await
        .unwrap();
    publish_json(
        api.bus.as_ref(),
        "aegis.agents.tasks.analyst",
        &json!({ "a": 2 }),
    )
    .await
    .unwrap();
    publish_json(
        api.bus.as_ref(),
        "aegis.detections.llm",
        &json!({ "marker": true }),
    )
    .await
    .unwrap();
    assert_eq!(
        feed.next().await,
        (
            "detection".to_owned(),
            json!({ "subject": "aegis.detections.llm", "payload": { "marker": true } })
        )
    );
}

#[tokio::test]
async fn a_message_from_before_the_feed_opened_is_not_in_the_feed() {
    let api = TestApi::new();
    publish_json(
        api.bus.as_ref(),
        subject::INCIDENTS,
        &json!({ "old": true }),
    )
    .await
    .unwrap();
    let router = api.router();
    let mut feed = Feed::open(&router, VIEWER).await;
    assert_eq!(feed.next().await.0, "ready");
    publish_json(
        api.bus.as_ref(),
        subject::INCIDENTS,
        &json!({ "new": true }),
    )
    .await
    .unwrap();
    assert_eq!(
        feed.next().await.1,
        json!({ "subject": "aegis.incidents", "payload": { "new": true } })
    );
}

#[tokio::test]
async fn the_number_of_open_feeds_has_a_limit() {
    let api = TestApi::new();
    let mut config = config();
    config.limits.max_streams = 1;
    let router = api.router_with(&config);

    let mut first = Feed::open(&router, VIEWER).await;
    assert_eq!(first.next().await.0, "ready");

    let refused = send(
        &router,
        request(Method::GET, "/api/v1/stream", Some(VIEWER), None),
    )
    .await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.json(),
        json!({ "error": {
            "code": "rate_limited",
            "message": "Too many live feeds are open. Close one and try again."
        } })
    );

    // A closed feed gives its place back.
    drop(first);
    let mut second = Feed::open(&router, VIEWER).await;
    assert_eq!(second.next().await.0, "ready");
}

#[tokio::test]
async fn the_feed_needs_the_permission_to_read_incidents_and_takes_no_parameters() {
    let api = TestApi::new();
    let router = api.router();
    let reply = send(
        &router,
        request(Method::GET, "/api/v1/stream", Some(APPROVER), None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = send(
        &router,
        request(Method::GET, "/api/v1/stream?token=abc", Some(VIEWER), None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.error_code(), "invalid_input");
}
