//! The incident routes and the explanation routes.

use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::common::{ActionId, EvidenceKind, EvidenceRef, IncidentId, Severity};
use aegis_contracts::incident::{IncidentStatus, IncidentStore};
use axum::http::StatusCode;
use chrono::Duration;
use serde_json::json;

use crate::support::{AUDITOR, TestApi, VIEWER, get, incident, to_json};

#[tokio::test]
async fn the_list_has_the_incidents_newest_first() {
    let api = TestApi::new();
    let older = api.seed_incident("Password spray", Severity::High).await;
    let mut newer = incident("Rogue application", Severity::Critical);
    newer.created_at = older.created_at + Duration::minutes(5);
    newer.status = IncidentStatus::Contained;
    api.incidents.save(&newer).await.unwrap();
    let router = api.router();

    let reply = get(&router, "/api/v1/incidents", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(
        reply.json(),
        json!({ "items": [to_json(&newer), to_json(&older)] })
    );

    let reply = get(&router, "/api/v1/incidents?status=contained", VIEWER).await;
    assert_eq!(reply.json(), json!({ "items": [to_json(&newer)] }));

    let reply = get(&router, "/api/v1/incidents?status=&limit=1", VIEWER).await;
    assert_eq!(reply.json(), json!({ "items": [to_json(&newer)] }));

    let reply = get(&router, "/api/v1/incidents?status=resolved", VIEWER).await;
    assert_eq!(reply.json(), json!({ "items": [] }));
}

#[tokio::test]
async fn a_list_query_that_is_not_valid_is_a_400() {
    let api = TestApi::new();
    api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();
    let cases = [
        (
            "status=closed",
            "The query parameter status must be one of: open, investigating, contained, \
             resolved, false_positive.",
        ),
        (
            "limit=0",
            "The query parameter limit must be from 1 to 200.",
        ),
        (
            "limit=201",
            "The query parameter limit must be from 1 to 200.",
        ),
        (
            "limit=ten",
            "The query parameter limit must be a whole number that is not negative.",
        ),
        (
            "offset=5",
            "The query has a parameter that this route does not know. The known parameters \
             are: status, limit.",
        ),
        (
            "limit=1&limit=2",
            "The query parameter limit occurs more than one time.",
        ),
    ];
    for (query, message) in cases {
        let reply = get(&router, &format!("/api/v1/incidents?{query}"), VIEWER).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(
            reply.json(),
            json!({ "error": { "code": "invalid_input", "message": message } }),
            "{query}"
        );
    }
}

#[tokio::test]
async fn one_incident_has_the_full_incident_document() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let reply = get(
        &router,
        &format!("/api/v1/incidents/{}", incident.id),
        VIEWER,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body, to_json(&incident));
    // The fields that the console reads.
    assert_eq!(body["title"], "Password spray");
    assert_eq!(body["severity"], "high");
    assert_eq!(body["status"], "open");
    assert_eq!(body["attack"][0]["technique_id"], "T1110.003");
    assert_eq!(
        body["entities"][0],
        json!({ "kind": "ip_address", "id": "203.0.113.50" })
    );
    assert_eq!(body["timeline"][0]["author"], "correlator");
}

#[tokio::test]
async fn an_unknown_incident_is_a_404_and_a_bad_identifier_is_a_400() {
    let api = TestApi::new();
    api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let reply = get(
        &router,
        &format!("/api/v1/incidents/{}", IncidentId::new()),
        VIEWER,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({ "error": { "code": "not_found", "message": "The incident does not exist." } })
    );

    let reply = get(&router, "/api/v1/incidents/42", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json(),
        json!({ "error": {
            "code": "invalid_input",
            "message": "The incident identifier is not a valid UUID."
        } })
    );
}

#[tokio::test]
async fn the_incident_explanation_has_the_audit_records_of_the_incident_and_its_actions() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let action = ActionId::new();
    let incident_link = EvidenceRef::new(EvidenceKind::Incident, incident.id);
    let action_link = EvidenceRef::new(EvidenceKind::Action, action);
    let proposed = api
        .audit
        .append(
            AuditEntry::new(AuditKind::ActionProposed, "responder", "Proposed block_ip.")
                .with_evidence(vec![action_link.clone(), incident_link]),
        )
        .await
        .unwrap();
    api.audit
        .append(AuditEntry::new(
            AuditKind::Other,
            "monitor",
            "A record of a different subject.",
        ))
        .await
        .unwrap();
    let executed = api
        .audit
        .append(
            AuditEntry::new(AuditKind::ActionExecuted, "dispatcher", "Did block_ip.")
                .with_evidence(vec![action_link]),
        )
        .await
        .unwrap();
    let router = api.router();

    let reply = get(
        &router,
        &format!("/api/v1/incidents/{}/explanation", incident.id),
        AUDITOR,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "subject": { "incident": incident.id },
            "records": [to_json(&proposed), to_json(&executed)]
        })
    );

    let reply = get(
        &router,
        &format!("/api/v1/actions/{action}/explanation"),
        AUDITOR,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "subject": { "action": action },
            "records": [to_json(&proposed), to_json(&executed)]
        })
    );
}

#[tokio::test]
async fn an_explanation_with_no_audit_record_is_a_404() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let path = format!("/api/v1/incidents/{}/explanation", incident.id);
    let reply = get(&router, &path, AUDITOR).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.error_code(), "not_found");
    assert_eq!(
        reply.error_message(),
        format!("no audit record links to incident {}", incident.id)
    );

    let action = ActionId::new();
    let reply = get(
        &router,
        &format!("/api/v1/actions/{action}/explanation"),
        AUDITOR,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.error_message(),
        format!("no audit record links to action {action}")
    );

    for path in [
        "/api/v1/incidents/x/explanation",
        "/api/v1/actions/x/explanation",
    ] {
        let reply = get(&router, path, AUDITOR).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(reply.error_code(), "invalid_input");
    }
}
