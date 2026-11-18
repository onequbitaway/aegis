//! The model path: a replay with a local OpenAI-compatible server, and a replay with a
//! server that fails.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_app::actions::DispatchResult;
use aegis_contracts::action::{ActionDisposition, ActionStatus};
use aegis_contracts::common::Severity;
use aegis_contracts::incident::IncidentStatus;
use aegis_policy::FileAuditLog;
use aegis_testkit::fixtures;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::Starter;

const MODEL_SUMMARY: &str =
    "A password spray gave access to one account. A rogue application got a privileged role.";

fn model_section(server: &MockServer) -> String {
    format!(
        r#"
[model.providers.local]
kind = "openai_compatible"
base_url = "{}/v1"
chat_model = "local-test-model"
timeout = "10s"

[model.routes]
default = [{{ provider = "local" }}]
"#,
        server.uri()
    )
}

/// An answer in the OpenAI chat-completions format that holds `content`.
fn completion(content: &Value) -> Value {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "local-test-model",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content.to_string() },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120 }
    })
}

async fn chat_requests(server: &MockServer) -> Vec<Value> {
    let requests = server.received_requests().await.unwrap();
    requests
        .iter()
        .map(|request| {
            assert_eq!(request.method.as_str(), "POST");
            assert_eq!(request.url.path(), "/v1/chat/completions");
            serde_json::from_slice(&request.body).unwrap()
        })
        .collect()
}

#[tokio::test]
async fn a_replay_with_a_local_model_sends_chat_requests_and_completes() {
    let server = MockServer::start().await;
    // The answer is a valid assessment of the Analyst. For each other agent, it has the
    // wrong shape, and that agent then uses its deterministic path.
    let assessment = json!({
        "verdict": "true_positive",
        "confidence": 0.93,
        "summary": MODEL_SUMMARY,
        "recommended_containment": ["Disable the service principal."]
    });
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(&assessment)))
        .mount(&server)
        .await;
    let starter = Starter::new();
    let config = starter.config_with(|text| text + &model_section(&server));
    let app = starter.build(&config, |builder| builder).await;
    assert!(app.has_model());
    assert_eq!(app.models().name(), "router");

    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();

    let requests = chat_requests(&server).await;
    assert!(
        requests.len() >= 7,
        "the agents must ask the model for each state of the incident: {}",
        requests.len()
    );
    for request in &requests {
        assert_eq!(request["model"], "local-test-model");
        assert_eq!(request["messages"][0]["role"], "system");
    }

    // The run completes with the same detections and one incident.
    assert!(report.model);
    assert_eq!(report.detections.len(), 9);
    assert_eq!(report.incidents.len(), 1);
    let incident = &report.incidents[0];
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.status, IncidentStatus::Investigating);
    // The Analyst took the summary of the model. Each later state of the detection engine
    // has a new summary, and the summary of the Analyst stays.
    assert_eq!(incident.summary, MODEL_SUMMARY);
    assert!(
        incident
            .timeline
            .iter()
            .any(|entry| entry.author == "analyst"
                && entry
                    .description
                    .starts_with("The analyst assessed a true positive. Model confidence: 0.93.")),
        "{:?}",
        incident.timeline
    );

    // The model cannot switch the dry run off, and it cannot remove a baseline action.
    assert!(!report.changed_the_environment());
    let responder: Vec<_> = report
        .actions
        .iter()
        .filter(|action| action.request.requested_by == "responder")
        .collect();
    assert_eq!(responder.len(), 6);
    for action in &report.actions {
        assert!(
            matches!(&action.result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated),
            "{:?}",
            action.result
        );
    }
    assert_eq!(report.agents.unwrap().tasks_failed, 0);
    assert!(report.audit.verification.valid);
    assert!(
        FileAuditLog::verify_file(starter.audit_file())
            .unwrap()
            .valid
    );
}

#[tokio::test]
async fn a_replay_with_a_model_server_that_fails_completes_on_the_deterministic_paths() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("the model server is down"))
        .mount(&server)
        .await;
    let starter = Starter::new();
    let config = starter.config_with(|text| text + &model_section(&server));
    let app = starter.build(&config, |builder| builder).await;

    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();

    // The agents asked the model, and each request failed.
    let requests = chat_requests(&server).await;
    assert!(requests.len() >= 7, "{}", requests.len());

    // The result is the result of a run with no model.
    let offline = Starter::new();
    let offline_report = offline
        .app()
        .await
        .replay(fixtures::artex_style_attack())
        .await
        .unwrap();
    assert_eq!(report.detections, offline_report.detections);
    assert_eq!(report.incidents.len(), 1);
    let incident = &report.incidents[0];
    let offline_incident = &offline_report.incidents[0];
    assert_eq!(incident.id, offline_incident.id);
    assert_eq!(incident.status, IncidentStatus::Investigating);
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.detections, offline_incident.detections);
    assert_eq!(incident.entities, offline_incident.entities);
    // No agent wrote a summary, so the incident has the summary of the detection engine.
    assert_eq!(incident.summary, offline_incident.summary);
    assert!(
        incident
            .timeline
            .iter()
            .any(|entry| entry.author == "analyst"
                && entry.description.contains("Deterministic triage:")),
        "{:?}",
        incident.timeline
    );
    let summary = |report: &aegis_app::report::ReplayReport| -> Vec<(String, String, String)> {
        report
            .actions
            .iter()
            .map(|action| {
                (
                    action.request.requested_by.clone(),
                    serde_json::to_value(&action.request.kind)
                        .unwrap()
                        .to_string(),
                    action.request.target.id.clone(),
                )
            })
            .collect()
    };
    assert_eq!(summary(&report), summary(&offline_report));
    assert_eq!(report.actions.len(), 23);
    assert!(!report.changed_the_environment());
    assert_eq!(report.agents.unwrap().tasks_failed, 0);
    assert!(report.audit.verification.valid);
}
