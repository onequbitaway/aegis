//! The audit, status, agent, goal, and playbook routes.

use aegis_agents::TaskState;
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::common::{EvidenceKind, IncidentId, Severity, TaskId};
use aegis_contracts::incident::IncidentStore;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::support::{
    ADMIN, AUDITOR, FLOOD, OPERATOR, PLAYBOOK_NAME, SPRAY_ADDRESS, TestApi, TestStatus, VIEWER,
    config, get, incident, post, to_json,
};

async fn append(api: &TestApi, count: usize) {
    for index in 0..count {
        api.audit
            .append(AuditEntry::new(
                AuditKind::AgentDecision,
                "analyst",
                format!("Decision {index}."),
            ))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn the_audit_list_has_the_records_in_sequence_order() {
    let api = TestApi::new();
    append(&api, 3).await;
    let records = api.audit.records();
    let router = api.router();

    let reply = get(&router, "/api/v1/audit", AUDITOR).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({ "items": to_json(&records), "next_sequence": null })
    );
    let first = &reply.json()["items"][0];
    assert_eq!(first["sequence"], 1);
    assert_eq!(first["kind"], "agent_decision");
    assert_eq!(first["hash"].as_str().map(str::len), Some(64));

    let reply = get(&router, "/api/v1/audit?from_sequence=2&limit=1", AUDITOR).await;
    assert_eq!(
        reply.json(),
        json!({ "items": [to_json(&records[1])], "next_sequence": 3 })
    );
    let reply = get(&router, "/api/v1/audit?from_sequence=4", AUDITOR).await;
    assert_eq!(reply.json(), json!({ "items": [], "next_sequence": null }));

    for query in [
        "from_sequence=-1",
        "from_sequence=one",
        "limit=500",
        "before=3",
    ] {
        let reply = get(&router, &format!("/api/v1/audit?{query}"), AUDITOR).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(reply.error_code(), "invalid_input", "{query}");
    }
}

#[tokio::test]
async fn the_audit_verification_finds_a_changed_record() {
    let api = TestApi::new();
    append(&api, 3).await;
    let router = api.router();

    let reply = get(&router, "/api/v1/audit/verification", AUDITOR).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), json!({ "valid": true, "checked": 3 }));

    api.audit
        .tamper(|records| records[1].summary = "Changed.".to_owned());
    let reply = get(&router, "/api/v1/audit/verification", AUDITOR).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "valid": false,
            "checked": 1,
            "first_invalid_sequence": 2,
            "reason": "hash does not match the record contents"
        })
    );
}

fn zero_stats() -> Value {
    json!({
        "tasks_completed": 0,
        "tasks_failed": 0,
        "tasks_rejected": 0,
        "actions_dispatched": 0,
        "actions_rejected": 0,
        "dispatch_failures": 0,
        "audit_failures": 0
    })
}

#[tokio::test]
async fn the_status_has_the_modules_the_agent_runtime_and_the_audit_head() {
    let api = TestApi::new();
    let router = api.router();

    let reply = get(&router, "/api/v1/status", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "modules": ["detection", "responder", "api"],
            "agents": {
                "state": "idle",
                "idle": true,
                "queued": 0,
                "dry_run": true,
                "stats": zero_stats()
            },
            "audit": { "head": null }
        })
    );

    append(&api, 5).await;
    let last = api.audit.records().pop().unwrap();
    let reply = get(&router, "/api/v1/status", VIEWER).await;
    assert_eq!(
        reply.json()["audit"],
        json!({ "head": { "sequence": 5, "hash": last.hash, "time": last.time } })
    );

    // The next request starts at the known head and finds the new records.
    append(&api, 2).await;
    let last = api.audit.records().pop().unwrap();
    let reply = get(&router, "/api/v1/status", VIEWER).await;
    assert_eq!(reply.json()["audit"]["head"]["sequence"], 7);
    assert_eq!(reply.json()["audit"]["head"]["hash"], json!(last.hash));

    let reply = get(&router, "/api/v1/status?verbose=1", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_status_has_the_flood_counters_and_the_fields_of_the_composition_root() {
    let api = TestApi::new();
    let state = api
        .state
        .clone()
        .with_status(std::sync::Arc::new(TestStatus));
    let router = aegis_api::router(state, &config()).unwrap();

    let reply = get(&router, "/api/v1/status", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(
        body["flood"],
        json!({
            "suppressed_matches": 41,
            "repeat_detections": 2,
            "triage_quota_denials": 7,
            "coalesced_incident_updates": 13
        })
    );
    assert_eq!(body["flood"], to_json(&FLOOD));
    assert_eq!(body["decoy"], json!({ "requests": 5 }));
    // A field of the composition root does not replace a field of the route.
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["modules"], json!(["detection", "responder", "api"]));
    // The order of the fields depends on a Cargo feature of `serde_json`. The test thus
    // compares the set of the fields.
    let fields: std::collections::BTreeSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        std::collections::BTreeSet::from([
            "agents", "audit", "decoy", "flood", "modules", "version"
        ])
    );
}

#[tokio::test]
async fn the_agents_route_has_the_roster_the_state_and_the_recent_tasks() {
    let api = TestApi::new();
    let router = api.router();

    let reply = get(&router, "/api/v1/agents", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "state": "idle",
            "idle": true,
            "queued": 0,
            "dry_run": true,
            "stats": zero_stats(),
            "roster": [
                "supervisor", "monitor", "hunter", "analyst", "responder", "deception", "reporter"
            ],
            "recent_tasks": []
        })
    );

    api.agents.submit_goal("Keep this tenant safe.").unwrap();
    let report = api.agents.run_until_idle().await.unwrap();
    assert!(report.tasks_completed >= 2, "{report:?}");
    let recent = api.agents.recent_tasks();

    let body = get(&router, "/api/v1/agents", VIEWER).await.json();
    assert_eq!(
        body["stats"]["tasks_completed"],
        json!(report.tasks_completed)
    );
    assert_eq!(body["recent_tasks"], to_json(&recent));
    assert_eq!(body["recent_tasks"][0]["role"], "supervisor");
    assert_eq!(body["recent_tasks"][0]["state"], "completed");

    // The limit keeps the newest tasks.
    let body = get(&router, "/api/v1/agents?limit=1", VIEWER).await.json();
    assert_eq!(
        body["recent_tasks"],
        json!([to_json(recent.last().unwrap())])
    );

    let reply = get(&router, "/api/v1/agents?limit=0", VIEWER).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_goal_goes_to_the_agent_runtime_with_an_audit_record_of_the_principal() {
    let api = TestApi::new();
    let router = api.router();

    let reply = post(
        &router,
        "/api/v1/goal",
        ADMIN,
        &json!({ "text": "  Keep this tenant safe.  " }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    let body = reply.json();
    let task_id: TaskId = serde_json::from_value(body["task_id"].clone()).unwrap();
    assert_eq!(body, json!({ "task_id": task_id }));
    assert_eq!(api.agents.task_state(task_id), Some(TaskState::Queued));
    assert_eq!(api.agents.queued(), 1);

    let records = api.audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::Other);
    assert_eq!(records[0].actor, "adam@example.com");
    assert_eq!(
        records[0].payload,
        json!({ "operation": "submit_goal", "goal": "Keep this tenant safe." })
    );
}

#[tokio::test]
async fn a_goal_that_is_not_valid_is_a_400_with_no_side_effect() {
    let api = TestApi::new();
    let router = api.router();
    let cases = [
        (json!({ "text": "   " }), "The goal has no text."),
        (
            json!({ "text": "x".repeat(4001) }),
            "The goal must have 4000 characters or fewer.",
        ),
        (
            json!({}),
            "The request body is not valid: missing field `text`.",
        ),
        (
            json!({ "text": "a", "role": "hunter" }),
            "The request body is not valid: unknown field `role`, expected `text`.",
        ),
    ];
    for (body, message) in cases {
        let reply = post(&router, "/api/v1/goal", ADMIN, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            reply.json(),
            json!({ "error": { "code": "invalid_input", "message": message } }),
            "{body}"
        );
    }
    assert_eq!(api.agents.queued(), 0);
    assert!(api.audit.records().is_empty());
}

#[tokio::test]
async fn the_playbook_list_has_each_playbook() {
    let api = TestApi::new();
    let router = api.router();
    for token in [VIEWER, OPERATOR] {
        let reply = get(&router, "/api/v1/playbooks", token).await;
        assert_eq!(reply.status, StatusCode::OK);
        let body = reply.json();
        assert_eq!(
            body,
            json!({ "items": to_json(&api.state.parts().playbooks.playbooks()) })
        );
        assert_eq!(body["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["items"][0]["name"], PLAYBOOK_NAME);
        assert_eq!(body["items"][0]["steps"][0]["action"], "block_ip");
    }
}

fn runs_path() -> String {
    format!("/api/v1/playbooks/{PLAYBOOK_NAME}/runs")
}

#[tokio::test]
async fn a_playbook_run_is_a_dry_run_by_default() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let reply = post(
        &router,
        &runs_path(),
        OPERATOR,
        &json!({ "incident_id": incident.id }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["trigger_matched"], true);
    assert_eq!(body["run"]["playbook"], PLAYBOOK_NAME);
    assert_eq!(body["run"]["incident_id"], json!(incident.id));
    assert_eq!(body["run"]["mode"], "dry_run");
    let steps = body["run"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["step"], "block-address");
    assert_eq!(
        steps[0]["target"],
        json!({ "kind": "ip_address", "id": SPRAY_ADDRESS })
    );
    assert_eq!(
        steps[0]["result"]["dispatched"]["executed"]["status"],
        "simulated"
    );

    let calls = api.firewall.executed();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].dry_run);
    assert_eq!(calls[0].target.id, SPRAY_ADDRESS);

    // The first audit record names the principal that started the run.
    let records = api.audit.records();
    assert_eq!(records[0].kind, AuditKind::Other);
    assert_eq!(records[0].actor, "oscar@example.com");
    assert_eq!(
        records[0].payload,
        json!({
            "operation": "run_playbook",
            "playbook": PLAYBOOK_NAME,
            "incident_id": incident.id,
            "mode": "dry_run",
            "trigger_matched": true
        })
    );
    assert_eq!(records[0].evidence.len(), 1);
    assert_eq!(records[0].evidence[0].kind, EvidenceKind::Incident);
    assert_eq!(records[0].evidence[0].id, incident.id.to_string());
}

#[tokio::test]
async fn a_live_playbook_run_lets_the_connector_change_the_target() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let reply = post(
        &router,
        &runs_path(),
        OPERATOR,
        &json!({ "incident_id": incident.id, "mode": "live" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["run"]["mode"], "live");
    assert_eq!(
        body["run"]["steps"][0]["result"]["dispatched"]["executed"]["status"],
        "succeeded"
    );
    let calls = api.firewall.executed();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].dry_run);
    assert_eq!(api.audit.records()[0].payload["mode"], "live");
}

#[tokio::test]
async fn a_run_for_an_incident_that_the_trigger_does_not_match_says_so() {
    let api = TestApi::new();
    let mut low = incident("Low noise", Severity::Low);
    low.attack.clear();
    api.incidents.save(&low).await.unwrap();
    let router = api.router();

    let reply = post(
        &router,
        &runs_path(),
        OPERATOR,
        &json!({ "incident_id": low.id }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["trigger_matched"], false);
    assert_eq!(reply.json()["run"]["mode"], "dry_run");
}

#[tokio::test]
async fn a_run_request_that_is_not_valid_changes_nothing() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let reply = post(
        &router,
        "/api/v1/playbooks/no-such-playbook/runs",
        OPERATOR,
        &json!({ "incident_id": incident.id }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({ "error": { "code": "not_found", "message": "The playbook does not exist." } })
    );

    let reply = post(
        &router,
        &runs_path(),
        OPERATOR,
        &json!({ "incident_id": IncidentId::new() }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.error_message(), "The incident does not exist.");

    let bodies = [
        json!({}),
        json!({ "incident_id": "42" }),
        json!({ "incident_id": incident.id, "mode": "force" }),
        json!({ "incident_id": incident.id, "dry_run": false }),
    ];
    for body in bodies {
        let reply = post(&router, &runs_path(), OPERATOR, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), "invalid_input", "{body}");
    }

    assert!(api.firewall.executed().is_empty());
    assert!(api.audit.records().is_empty());
}
