//! Tests for the wire formats and the pure functions of the contracts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionStatus,
};
use aegis_contracts::agent::{Agent, AgentInput, AgentOutput, AgentRole, AgentTask};
use aegis_contracts::audit::{
    AuditEntry, AuditKind, AuditLog, AuditRecord, GENESIS_HASH, canonical_json, seal, verify_chain,
};
use aegis_contracts::bus::{BusMessage, MessageBus, subject_matches};
use aegis_contracts::common::{
    ActionId, AuditId, DetectionId, EntityKind, EntityRef, EventId, EvidenceKind, EvidenceRef,
    IncidentId, Severity, TimeRange,
};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
use aegis_contracts::event::{self, Actor, Event, EventClass, EventSource, Outcome};
use aegis_contracts::graph::{
    DefensiveGraph, Direction, GraphEdge, GraphNode, NodeId, NodeKind, VectorMatch, VectorRecord,
    VectorStore, relation,
};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry};
use aegis_contracts::model::{
    ChatChunk, ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse, FinishReason,
    Message, ModelCapabilities, ModelProvider, ResponseFormat, Role, TaskKind, ToolCall,
    ToolChoice, ToolSpec, Usage,
};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, IncidentContext, PolicyDecision,
    PolicyEffect, PolicyEngine, PolicyInput, Principal, PrincipalKind,
};
use aegis_contracts::source::{ConnectorInfo, EventBatch, SourceConnector};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const KNOWN_CANONICAL_RECORD: &str = r#"{"actor":"responder","evidence":[{"id":"inc-1","kind":"incident"}],"id":"018f0000-0000-7000-8000-000000000001","kind":"action_executed","payload":{"a":[true,null,"x"],"b":1},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","sequence":1,"summary":"Disabled a service principal.","time":"2026-01-02T03:04:05.123456Z"}"#;
const KNOWN_RECORD_HASH: &str = "789a0573e1a04fc22a1af8e51bad8f826907271dc6e936c27da6443405e621d1";

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: &T) -> Value {
    let text = serde_json::to_string(value).unwrap();
    let decoded: T = serde_json::from_str(&text).unwrap();
    assert_eq!(&decoded, value);
    serde_json::from_str(&text).unwrap()
}

fn sorted_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn instant(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, second).unwrap()
}

fn sample_event() -> Event {
    Event::new(
        instant(5),
        EventSource::new("entra-prod", "microsoft", "entra_id").with_tenant("tenant-a"),
        EventClass::Authentication,
        event::action::SIGN_IN,
        Actor::new(EntityKind::User, "user-1")
            .with_name("alice@example.com")
            .with_tenant("tenant-a")
            .with_ip("203.0.113.7".parse().unwrap())
            .with_user_agent("python-requests/2.32")
            .with_session_id("session-1"),
    )
    .with_outcome(Outcome::Failure)
    .with_severity(Severity::Low)
    .with_target(EntityRef::new(EntityKind::Application, "app-1").with_name("Portal"))
    .with_attribute(event::attr::COUNTRY, "NL")
    .with_attribute(event::attr::MFA_SATISFIED, false)
    .with_raw(json!({ "vendorField": 1 }))
}

fn sample_detection() -> Detection {
    Detection {
        id: DetectionId::new(),
        rule_id: "aegis.velocity.sign_in_burst".to_owned(),
        title: "Sign-in burst".to_owned(),
        description: "One address made 900 sign-ins in one minute.".to_owned(),
        severity: Severity::High,
        verdict: Verdict::Malicious,
        tier: DetectionTier::Deterministic,
        time: instant(6),
        attack: vec![AttackTechnique::new(
            "credential-access",
            "T1110.003",
            "Password Spraying",
        )],
        event_ids: vec![EventId::new()],
        entities: vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.7")],
        tenant: Some("tenant-a".to_owned()),
        attributes: BTreeMap::from([("count".to_owned(), json!(900))]),
    }
}

fn sample_incident() -> Incident {
    let detection = sample_detection();
    Incident {
        id: IncidentId::new(),
        title: "Agent attack on tenant-a".to_owned(),
        summary: "A sign-in burst preceded a privileged role assignment.".to_owned(),
        severity: Severity::Critical,
        status: IncidentStatus::Investigating,
        created_at: instant(7),
        updated_at: instant(8),
        tenant: Some("tenant-a".to_owned()),
        entities: detection.entities.clone(),
        attack: detection.attack.clone(),
        timeline: vec![TimelineEntry {
            time: instant(7),
            author: "correlator".to_owned(),
            description: "The correlator opened the incident.".to_owned(),
            evidence: vec![EvidenceRef::new(EvidenceKind::Detection, detection.id)],
        }],
        detections: vec![detection],
    }
}

fn sample_action() -> ActionRequest {
    let mut request = ActionRequest::new(
        ActionKind::DisableServicePrincipal,
        EntityRef::new(EntityKind::ServicePrincipal, "sp-1"),
        "responder",
        "The service principal assigned a privileged role to itself.",
    );
    request.incident_id = Some(IncidentId::new());
    request.dry_run = true;
    request.requested_at = instant(9);
    request
        .parameters
        .insert("ticket".to_owned(), json!("SEC-1"));
    request.evidence = vec![EvidenceRef::new(EvidenceKind::Incident, "inc-1").with_note("cause")];
    request
}

fn sample_decision(effect: PolicyEffect) -> PolicyDecision {
    PolicyDecision {
        effect,
        tier: ActionTier::Gated,
        reasons: vec!["The action is disruptive.".to_owned()],
        policy: Some("aegis.response.decision".to_owned()),
        evaluated_at: instant(10),
    }
}

fn sample_outcome(action_id: ActionId) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::Simulated,
        connector: "graph".to_owned(),
        message: "Would disable service principal sp-1.".to_owned(),
        details: json!({ "enabled": true }),
        reversible: true,
        completed_at: instant(11),
    }
}

fn entry(summary: &str) -> AuditEntry {
    AuditEntry::new(AuditKind::ActionExecuted, "responder", summary)
        .with_payload(json!({ "b": 1, "a": [true, null, "x"] }))
        .with_evidence(vec![EvidenceRef::new(EvidenceKind::Incident, "inc-1")])
}

fn chain(length: usize) -> Vec<AuditRecord> {
    let mut records: Vec<AuditRecord> = Vec::new();
    for index in 0..length {
        let record = seal(
            records.last(),
            entry(&format!("Step {index}.")),
            instant(12),
        )
        .unwrap();
        records.push(record);
    }
    records
}

#[test]
fn event_round_trips_and_uses_the_documented_wire_names() {
    let value = round_trip(&sample_event());
    assert_eq!(value["class"], "authentication");
    assert_eq!(value["action"], "sign_in");
    assert_eq!(value["outcome"], "failure");
    assert_eq!(value["severity"], "low");
    assert_eq!(value["actor"]["kind"], "user");
    assert_eq!(value["actor"]["ip"], "203.0.113.7");
    assert_eq!(value["target"]["kind"], "application");
    assert_eq!(value["attributes"]["country"], "NL");
    assert_eq!(value["time"], "2026-01-02T03:04:05Z");
}

#[test]
fn event_decodes_a_minimal_record_with_defaults() {
    let id = EventId::new();
    let minimal = json!({
        "id": id,
        "time": "2026-01-02T03:04:05Z",
        "source": { "connector": "file", "vendor": "aegis", "product": "mock" },
        "class": "api_activity",
        "action": "api.call",
        "actor": { "kind": "service_principal", "id": "sp-1" }
    });
    let event: Event = serde_json::from_value(minimal).unwrap();
    assert_eq!(event.id, id);
    assert_eq!(event.outcome, Outcome::Unknown);
    assert_eq!(event.severity, Severity::Informational);
    assert_eq!(event.target, None);
    assert!(event.attributes.is_empty());
    assert_eq!(event.raw, None);
    assert_eq!(event.actor.ip, None);
}

#[test]
fn event_omits_empty_optional_fields() {
    let event = Event::new(
        instant(5),
        EventSource::new("file", "aegis", "mock"),
        EventClass::Other,
        "custom.action",
        Actor::new(EntityKind::Other, "x"),
    );
    let value = round_trip(&event);
    assert_eq!(
        sorted_keys(&value),
        [
            "action", "actor", "class", "id", "outcome", "severity", "source", "time"
        ]
    );
    assert_eq!(sorted_keys(&value["actor"]), ["id", "kind"]);
}

#[test]
fn event_attribute_helpers_return_only_the_matching_type() {
    let event = sample_event();
    assert_eq!(event.attribute_str(event::attr::COUNTRY), Some("NL"));
    assert_eq!(
        event.attribute_bool(event::attr::MFA_SATISFIED),
        Some(false)
    );
    assert_eq!(event.attribute_str(event::attr::MFA_SATISFIED), None);
    assert_eq!(event.attribute_bool(event::attr::COUNTRY), None);
    assert_eq!(event.attribute_str("absent"), None);
}

#[test]
fn actor_entity_keeps_the_identity_fields() {
    let actor = sample_event().actor;
    assert_eq!(
        actor.entity(),
        EntityRef::new(EntityKind::User, "user-1")
            .with_name("alice@example.com")
            .with_tenant("tenant-a")
    );
}

#[test]
fn detection_and_incident_round_trip() {
    let detection = round_trip(&sample_detection());
    assert_eq!(detection["verdict"], "malicious");
    assert_eq!(detection["tier"], "deterministic");
    assert_eq!(detection["attack"][0]["technique_id"], "T1110.003");
    let incident = round_trip(&sample_incident());
    assert_eq!(incident["status"], "investigating");
    assert_eq!(incident["severity"], "critical");
    assert_eq!(incident["timeline"][0]["evidence"][0]["kind"], "detection");
}

#[test]
fn severity_orders_from_informational_to_critical() {
    let mut values = vec![
        Severity::High,
        Severity::Informational,
        Severity::Critical,
        Severity::Low,
        Severity::Medium,
    ];
    values.sort();
    assert_eq!(
        values,
        [
            Severity::Informational,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical
        ]
    );
}

#[test]
fn identifiers_parse_their_display_form_and_reject_other_text() {
    let id = IncidentId::new();
    assert_eq!(id.to_string().parse::<IncidentId>().unwrap(), id);
    assert_eq!(round_trip(&id), json!(id.to_string()));
    let error = "not-a-uuid".parse::<IncidentId>().unwrap_err();
    assert!(matches!(error, Error::InvalidInput(message) if message.contains("not-a-uuid")));
}

#[test]
fn time_range_includes_the_start_and_excludes_the_end() {
    let range = TimeRange {
        start: instant(10),
        end: instant(20),
    };
    assert!(range.contains(instant(10)));
    assert!(range.contains(instant(19)));
    assert!(!range.contains(instant(20)));
    assert!(!range.contains(instant(9)));
    round_trip(&range);
}

#[test]
fn only_transient_errors_are_retryable() {
    let retryable = [
        Error::Unavailable("x".into()),
        Error::RateLimited("x".into()),
        Error::Timeout("x".into()),
    ];
    let permanent = [
        Error::InvalidInput("x".into()),
        Error::NotFound("x".into()),
        Error::Config("x".into()),
        Error::Unauthorized("x".into()),
        Error::Denied("x".into()),
        Error::Unsupported("x".into()),
        Error::Refused("x".into()),
        Error::BudgetExceeded("x".into()),
        Error::Serialization("x".into()),
        Error::Integrity("x".into()),
        Error::other("read file", std::io::Error::other("disk")),
    ];
    assert!(retryable.iter().all(Error::is_retryable));
    assert!(!permanent.iter().any(Error::is_retryable));
}

#[test]
fn other_error_shows_the_context_and_keeps_the_source() {
    let error = Error::other("read rule pack", std::io::Error::other("disk failure"));
    assert_eq!(error.to_string(), "read rule pack: disk failure");
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(source.to_string(), "disk failure");
}

#[test]
fn json_errors_convert_to_serialization_errors() {
    let message = BusMessage {
        subject: "aegis.events.file".to_owned(),
        payload: b"{not json".to_vec(),
    };
    let error = message.decode::<Event>().unwrap_err();
    assert!(matches!(error, Error::Serialization(_)));
}

#[test]
fn model_types_round_trip() {
    let request = ChatRequest {
        task: TaskKind::Triage,
        model: Some("local-small".to_owned()),
        messages: vec![
            Message::system("You are a security analyst."),
            Message::user("Triage this alert."),
            Message {
                role: Role::Assistant,
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: "call-1".to_owned(),
                    name: "lookup_ip".to_owned(),
                    arguments: json!({ "ip": "203.0.113.7" }),
                }],
                tool_call_id: None,
            },
            Message::tool("call-1", "{\"reputation\":\"bad\"}"),
        ],
        tools: vec![ToolSpec {
            name: "lookup_ip".to_owned(),
            description: "Returns the reputation of an IP address.".to_owned(),
            parameters: json!({ "type": "object", "properties": { "ip": { "type": "string" } } }),
        }],
        tool_choice: ToolChoice::Tool("lookup_ip".to_owned()),
        response_format: ResponseFormat::Json,
        temperature: Some(0.0),
        max_output_tokens: Some(512),
    };
    let value = round_trip(&request);
    assert_eq!(value["task"], "triage");
    assert_eq!(value["messages"][3]["role"], "tool");
    assert_eq!(value["messages"][3]["tool_call_id"], "call-1");
    assert_eq!(value["tool_choice"], json!({ "tool": "lookup_ip" }));
    assert_eq!(value["response_format"], "json");

    let response = ChatResponse {
        provider: "openai-compatible".to_owned(),
        model: "local-small".to_owned(),
        message: Message::assistant("True positive."),
        finish_reason: FinishReason::Stop,
        usage: Usage {
            input_tokens: 120,
            output_tokens: 4,
        },
    };
    assert_eq!(round_trip(&response)["finish_reason"], "stop");
    round_trip(&ChatChunk {
        delta: "True".to_owned(),
        tool_calls: Vec::new(),
        finish_reason: Some(FinishReason::ToolCalls),
        usage: Some(Usage::default()),
    });
    round_trip(&EmbeddingRequest {
        model: None,
        input: vec!["sign-in burst".to_owned()],
    });
    round_trip(&EmbeddingResponse {
        provider: "local".to_owned(),
        model: "embed-small".to_owned(),
        embeddings: vec![vec![0.25, -0.5]],
        usage: Usage::default(),
    });
    round_trip(&ModelCapabilities {
        tools: true,
        streaming: true,
        embeddings: false,
    });
}

#[test]
fn chat_request_new_uses_default_settings() {
    let request = ChatRequest::new(TaskKind::Planning, vec![Message::user("Plan.")]);
    assert_eq!(request.task, TaskKind::Planning);
    assert_eq!(request.model, None);
    assert_eq!(request.tool_choice, ToolChoice::Auto);
    assert_eq!(request.response_format, ResponseFormat::Text);
    assert!(request.tools.is_empty());
    let decoded: ChatRequest =
        serde_json::from_value(json!({ "messages": [{ "role": "user", "content": "Hi" }] }))
            .unwrap();
    assert_eq!(decoded.task, TaskKind::Analysis);
    assert_eq!(decoded.messages, vec![Message::user("Hi")]);
}

#[test]
fn action_kinds_use_snake_case_wire_names() {
    assert_eq!(round_trip(&ActionKind::IsolateHost), json!("isolate_host"));
    assert_eq!(
        round_trip(&ActionKind::DisableServicePrincipal),
        json!("disable_service_principal")
    );
    assert_eq!(
        round_trip(&ActionKind::Custom("quarantine_mailbox".to_owned())),
        json!({ "custom": "quarantine_mailbox" })
    );
}

#[test]
fn only_safe_and_reversible_actions_default_to_the_auto_tier() {
    let auto = [
        ActionKind::Enrich,
        ActionKind::Tag,
        ActionKind::Notify,
        ActionKind::SnapshotEvidence,
        ActionKind::OpenTicket,
    ];
    let gated = [
        ActionKind::RevokeCredential,
        ActionKind::RotateCredential,
        ActionKind::DisableServicePrincipal,
        ActionKind::DisableUser,
        ActionKind::KillSession,
        ActionKind::IsolateHost,
        ActionKind::BlockIp,
        ActionKind::RotateSecret,
        ActionKind::DeployHoneytoken,
        ActionKind::Custom("x".to_owned()),
    ];
    for kind in auto {
        assert_eq!(kind.default_tier(), ActionTier::Auto, "{kind:?}");
    }
    for kind in gated {
        assert_eq!(kind.default_tier(), ActionTier::Gated, "{kind:?}");
    }
}

#[test]
fn action_types_round_trip() {
    let request = sample_action();
    let value = round_trip(&request);
    assert_eq!(value["kind"], "disable_service_principal");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["target"]["kind"], "service_principal");

    let outcome = sample_outcome(request.id);
    assert_eq!(round_trip(&outcome)["status"], "simulated");
    let executed = round_trip(&ActionDisposition::Executed(outcome));
    assert_eq!(executed["executed"]["connector"], "graph");
    let denied = round_trip(&ActionDisposition::Denied(sample_decision(
        PolicyEffect::Deny,
    )));
    assert_eq!(denied["denied"]["effect"], "deny");
    let pending = round_trip(&ActionDisposition::PendingApproval {
        approval_id: aegis_contracts::ApprovalId::new(),
        decision: sample_decision(PolicyEffect::RequireApproval),
    });
    assert_eq!(
        pending["pending_approval"]["decision"]["effect"],
        "require_approval"
    );
}

#[test]
fn new_action_request_is_not_a_dry_run_and_has_no_incident() {
    let request = ActionRequest::new(
        ActionKind::Notify,
        EntityRef::new(EntityKind::User, "user-1"),
        "playbook:burst",
        "Tell the owner.",
    );
    assert!(!request.dry_run);
    assert_eq!(request.incident_id, None);
    assert_eq!(request.requested_by, "playbook:burst");
    assert!(request.parameters.is_empty());
    assert!(request.evidence.is_empty());
}

#[test]
fn policy_input_takes_the_default_tier_from_the_action_kind() {
    let principal = Principal::new("responder", PrincipalKind::Agent, &["agent", "responder"]);
    assert!(principal.has_role("responder"));
    assert!(!principal.has_role("approver"));

    let gated = PolicyInput::new(sample_action(), principal.clone());
    assert_eq!(gated.default_tier, ActionTier::Gated);
    assert_eq!(gated.incident, None);
    assert_eq!(gated.environment, Value::Null);

    let mut notify = sample_action();
    notify.kind = ActionKind::Notify;
    let mut auto = PolicyInput::new(notify, principal);
    assert_eq!(auto.default_tier, ActionTier::Auto);
    auto.incident = Some(IncidentContext {
        id: IncidentId::new(),
        severity: Severity::High,
        status: IncidentStatus::Open,
    });
    auto.environment = json!({ "maintenance_window": false });
    let value = round_trip(&auto);
    assert_eq!(value["default_tier"], "auto");
    assert_eq!(value["principal"]["kind"], "agent");
    assert_eq!(value["principal"]["roles"], json!(["agent", "responder"]));
    assert_eq!(value["incident"]["severity"], "high");
    assert_eq!(value["action"]["kind"], "notify");
}

#[test]
fn approval_request_round_trips() {
    let request = ApprovalRequest {
        id: aegis_contracts::ApprovalId::new(),
        action: sample_action(),
        requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent"]),
        decision: sample_decision(PolicyEffect::RequireApproval),
        status: ApprovalStatus::Approved,
        requested_at: instant(12),
        decided_by: Some("alice@example.com".to_owned()),
        decided_at: Some(instant(13)),
        note: Some("Confirmed with the owner.".to_owned()),
    };
    let value = round_trip(&request);
    assert_eq!(value["status"], "approved");
    assert_eq!(value["decision"]["tier"], "gated");
}

#[test]
fn canonical_json_does_not_depend_on_key_order() {
    let first: Value =
        serde_json::from_str(r#"{"b":{"y":1,"x":[2,{"q":null,"p":"é"}]},"a":true}"#).unwrap();
    let second: Value = serde_json::from_str(
        r#"{ "a": true, "b": { "x": [2, { "p": "é", "q": null }], "y": 1 } }"#,
    )
    .unwrap();
    let expected = r#"{"a":true,"b":{"x":[2,{"p":"é","q":null}],"y":1}}"#;
    assert_eq!(canonical_json(&first), expected);
    assert_eq!(canonical_json(&second), expected);
}

#[test]
fn canonical_json_escapes_keys_and_strings() {
    let value = json!({ "quote\"key": "line\nbreak" });
    assert_eq!(canonical_json(&value), r#"{"quote\"key":"line\nbreak"}"#);
}

#[test]
fn record_hash_matches_an_independent_sha256_of_the_canonical_form() {
    let record = AuditRecord {
        sequence: 1,
        id: "018f0000-0000-7000-8000-000000000001"
            .parse::<AuditId>()
            .unwrap(),
        time: "2026-01-02T03:04:05.123456Z".parse().unwrap(),
        kind: AuditKind::ActionExecuted,
        actor: "responder".to_owned(),
        summary: "Disabled a service principal.".to_owned(),
        payload: json!({ "b": 1, "a": [true, null, "x"] }),
        evidence: vec![EvidenceRef::new(EvidenceKind::Incident, "inc-1")],
        prev_hash: GENESIS_HASH.to_owned(),
        hash: "ignored".to_owned(),
    };
    let mut value = serde_json::to_value(&record).unwrap();
    value.as_object_mut().unwrap().remove("hash");
    assert_eq!(canonical_json(&value), KNOWN_CANONICAL_RECORD);
    assert_eq!(record.compute_hash().unwrap(), KNOWN_RECORD_HASH);
}

#[test]
fn seal_builds_a_chain_that_verifies() {
    let records = chain(3);
    assert_eq!(records[0].sequence, 1);
    assert_eq!(records[0].prev_hash, GENESIS_HASH);
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[2].prev_hash, records[1].hash);
    assert_eq!(records[2].sequence, 3);
    assert_eq!(records[0].hash.len(), 64);
    assert_ne!(records[0].hash, records[1].hash);

    let report = verify_chain(None, &records).unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 3);
    assert_eq!(report.first_invalid_sequence, None);
    round_trip(&records[2]);
    round_trip(&report);
}

#[test]
fn seal_rounds_the_time_down_to_microseconds() {
    let time = "2026-01-02T03:04:05.123456789Z".parse().unwrap();
    let record = seal(None, entry("Step."), time).unwrap();
    assert_eq!(
        record.time,
        "2026-01-02T03:04:05.123456Z"
            .parse::<DateTime<Utc>>()
            .unwrap()
    );
}

#[test]
fn a_change_to_any_field_breaks_the_chain_at_that_record() {
    type Tamper = fn(&mut AuditRecord);
    let tampers: [(&str, Tamper); 8] = [
        ("summary", |record| record.summary.push('!')),
        ("actor", |record| record.actor = "attacker".to_owned()),
        ("kind", |record| record.kind = AuditKind::Other),
        ("payload", |record| record.payload = json!({ "b": 2 })),
        ("evidence", |record| record.evidence.clear()),
        ("time", |record| record.time = instant(59)),
        ("id", |record| record.id = AuditId::new()),
        ("hash", |record| record.hash = GENESIS_HASH.to_owned()),
    ];
    for (field, tamper) in tampers {
        let mut records = chain(3);
        tamper(&mut records[1]);
        let report = verify_chain(None, &records).unwrap();
        assert!(!report.valid, "a change to {field} must break the chain");
        assert_eq!(report.checked, 1, "{field}");
        assert_eq!(report.first_invalid_sequence, Some(2), "{field}");
        assert!(report.reason.is_some(), "{field}");
    }
}

#[test]
fn a_recomputed_hash_after_a_change_breaks_the_next_record() {
    let mut records = chain(3);
    records[1].summary = "Changed.".to_owned();
    records[1].hash = records[1].compute_hash().unwrap();
    let report = verify_chain(None, &records).unwrap();
    assert!(!report.valid);
    assert_eq!(report.checked, 2);
    assert_eq!(report.first_invalid_sequence, Some(3));
}

#[test]
fn a_removed_or_reordered_record_breaks_the_chain() {
    let mut removed = chain(3);
    removed.remove(1);
    let report = verify_chain(None, &removed).unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_invalid_sequence, Some(3));
    assert_eq!(report.checked, 1);

    let mut reordered = chain(3);
    reordered.swap(1, 2);
    let report = verify_chain(None, &reordered).unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_invalid_sequence, Some(3));

    let mut truncated_start = chain(3);
    truncated_start.remove(0);
    let report = verify_chain(None, &truncated_start).unwrap();
    assert!(!report.valid);
    assert_eq!(report.checked, 0);
    assert_eq!(report.first_invalid_sequence, Some(2));
}

#[test]
fn a_segment_verifies_against_its_anchor_only() {
    let records = chain(4);
    let report = verify_chain(Some(&records[1]), &records[2..]).unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 2);

    let wrong_anchor = verify_chain(Some(&records[0]), &records[2..]).unwrap();
    assert!(!wrong_anchor.valid);
    assert_eq!(wrong_anchor.first_invalid_sequence, Some(3));
}

#[test]
fn an_empty_chain_is_valid() {
    let report = verify_chain(None, &[]).unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 0);
}

#[test]
fn node_identifiers_use_the_entity_kind_and_the_entity_identifier() {
    let principal = EntityRef::new(EntityKind::ServicePrincipal, "sp-1").with_tenant("tenant-a");
    assert_eq!(NodeId::for_entity(&principal).0, "service_principal:sp-1");
    assert_eq!(
        NodeId::for_entity(&EntityRef::new(EntityKind::IpAddress, "203.0.113.7")).0,
        "ip_address:203.0.113.7"
    );
    let incident = IncidentId::new();
    assert_eq!(
        NodeId::for_incident(incident).0,
        format!("incident:{incident}")
    );
    let detection = DetectionId::new();
    assert_eq!(
        NodeId::for_detection(detection).to_string(),
        format!("alert:{detection}")
    );

    let node = GraphNode::from_entity(&principal);
    assert_eq!(node.kind, NodeKind::Identity);
    assert_eq!(node.label, "sp-1");
    assert_eq!(node.properties["tenant"], "tenant-a");
    assert_eq!(node.properties["entity_kind"], "service_principal");
    assert_eq!(
        GraphNode::from_entity(&principal.with_name("Deploy bot")).label,
        "Deploy bot"
    );
}

#[test]
fn identities_and_assets_map_to_the_correct_node_kind() {
    let identities = [
        EntityKind::User,
        EntityKind::ServicePrincipal,
        EntityKind::Application,
    ];
    let assets = [
        EntityKind::Device,
        EntityKind::Host,
        EntityKind::IpAddress,
        EntityKind::Domain,
        EntityKind::Tenant,
        EntityKind::Session,
        EntityKind::Secret,
        EntityKind::Role,
        EntityKind::Resource,
        EntityKind::Other,
    ];
    for kind in identities {
        assert_eq!(NodeKind::from(kind), NodeKind::Identity, "{kind:?}");
    }
    for kind in assets {
        assert_eq!(NodeKind::from(kind), NodeKind::Asset, "{kind:?}");
    }
}

#[test]
fn graph_types_round_trip() {
    let from = NodeId::for_entity(&EntityRef::new(EntityKind::User, "user-1"));
    let to = NodeId::for_entity(&EntityRef::new(EntityKind::Role, "global-admin"));
    let edge = round_trip(&GraphEdge::new(from, relation::HAS_ROLE, to));
    assert_eq!(edge["from"], "user:user-1");
    assert_eq!(edge["relation"], "has_role");
    assert_eq!(round_trip(&Direction::Both), json!("both"));
    round_trip(&VectorMatch {
        record: VectorRecord {
            id: "note-1".to_owned(),
            embedding: vec![0.5, 0.25],
            text: "Sign-in burst from one address.".to_owned(),
            metadata: json!({ "incident": "inc-1" }),
        },
        score: 0.75,
    });
}

#[test]
fn subject_patterns_follow_nats_wildcard_rules() {
    let cases = [
        ("aegis.events.entra", "aegis.events.entra", true),
        ("aegis.events.*", "aegis.events.entra", true),
        ("aegis.*.entra", "aegis.events.entra", true),
        ("aegis.>", "aegis.events.entra", true),
        ("aegis.events.>", "aegis.events.entra", true),
        (">", "aegis", true),
        ("aegis.events.*", "aegis.events", false),
        ("aegis.events.*", "aegis.events.entra.extra", false),
        ("aegis.events.>", "aegis.events", false),
        ("aegis.events", "aegis.events.entra", false),
        ("aegis.events.entra", "aegis.events", false),
        ("aegis.>.entra", "aegis.events.entra", false),
        ("aegis.events.okta", "aegis.events.entra", false),
    ];
    for (pattern, subject, expected) in cases {
        assert_eq!(
            subject_matches(pattern, subject),
            expected,
            "{pattern} vs {subject}"
        );
    }
}

#[test]
fn agent_types_round_trip() {
    assert_eq!(AgentRole::Analyst.token(), "analyst");
    assert_eq!(
        AgentRole::Custom("forensics".to_owned()).token(),
        "forensics"
    );
    let incident = sample_incident();
    let task = AgentTask::new(
        AgentRole::Analyst,
        AgentInput::Incident(Box::new(incident.clone())),
    )
    .from_role(AgentRole::Monitor)
    .for_incident(incident.id);
    let value = round_trip(&task);
    assert_eq!(value["to"], "analyst");
    assert_eq!(value["from"], "monitor");
    assert_eq!(value["input"]["incident"]["id"], json!(incident.id));
    assert_eq!(round_trip(&AgentInput::Tick), json!("tick"));
    assert_eq!(
        round_trip(&AgentInput::Goal("Keep tenant-a safe.".to_owned()))["goal"],
        "Keep tenant-a safe."
    );
    round_trip(&AgentInput::Event(Box::new(sample_event())));
    round_trip(&AgentInput::Detection(Box::new(sample_detection())));
    round_trip(&AgentInput::ActionResult(Box::new(
        ActionDisposition::Executed(sample_outcome(ActionId::new())),
    )));
    round_trip(&AgentOutput {
        tasks: vec![task],
        actions: vec![sample_action()],
        incidents: vec![incident],
        notes: vec!["The burst came from one address.".to_owned()],
    });
    let empty: AgentOutput = serde_json::from_value(json!({})).unwrap();
    assert_eq!(empty, AgentOutput::default());
}

#[test]
fn source_types_round_trip() {
    round_trip(&ConnectorInfo {
        name: "entra-prod".to_owned(),
        vendor: "microsoft".to_owned(),
        product: "entra_id".to_owned(),
        version: "0.1.0".to_owned(),
    });
    let batch = round_trip(&EventBatch {
        events: vec![sample_event()],
        next_cursor: None,
    });
    assert_eq!(sorted_keys(&batch), ["events"]);
}

struct MinimalConnector;

#[async_trait]
impl ActionConnector for MinimalConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "minimal".to_owned(),
            vendor: "aegis".to_owned(),
            product: "test".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::Notify]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        Ok(sample_outcome(request.id))
    }
}

#[tokio::test]
async fn a_connector_without_revert_reports_unsupported() {
    let connector: Arc<dyn ActionConnector> = Arc::new(MinimalConnector);
    let request = sample_action();
    let error = connector.revert(&request).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unsupported(message) if message.contains("minimal") && message.contains(&request.id.to_string())),
        "{error}"
    );
    assert_eq!(
        connector.execute(&request).await.unwrap().action_id,
        request.id
    );
}

/// Fails to compile if a contract trait cannot be used as a trait object.
#[allow(dead_code, clippy::too_many_arguments)]
fn contract_traits_are_object_safe(
    _: &dyn SourceConnector,
    _: &dyn Detector,
    _: &dyn ModelProvider,
    _: &dyn Agent,
    _: &dyn ActionConnector,
    _: &dyn ActionDispatcher,
    _: &dyn PolicyEngine,
    _: &dyn ApprovalQueue,
    _: &dyn AuditLog,
    _: &dyn DefensiveGraph,
    _: &dyn VectorStore,
    _: &dyn IncidentStore,
    _: &dyn MessageBus,
) {
}
