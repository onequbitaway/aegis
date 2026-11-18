//! Helpers that the integration tests share: the in-memory services, the principals, and
//! the request functions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_agents::AgentRuntime;
use aegis_api::{
    ApiConfig, ApiParts, ApiState, ApprovalActions, ApprovalDecision, FloodStatus, PrincipalConfig,
    RevertActions, StatusSource, SystemStatus,
};
use aegis_contracts::action::{
    ActionDisposition, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::agent::AgentContext;
use aegis_contracts::common::{ActionId, ApprovalId, EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    Principal, PrincipalKind,
};
use aegis_contracts::{Error, Result};
use aegis_core::{Module, ModuleSet};
use aegis_policy::{Permission, Rbac, RbacConfig};
use aegis_respond::{
    ActionRegistry, Dispatcher, MemoryRevertStore, PendingRevert, Playbook, PlaybookEngine,
    RevertScheduler,
};
use aegis_testkit::{
    DispatchMode, MemoryApprovals, MemoryAuditLog, MemoryBus, MemoryGraph, MemoryIncidents,
    RecordingConnector, RecordingDispatcher, ScriptedModel, StaticPolicy,
};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use chrono::{TimeZone, Utc};
use serde_json::Value;
use tower::ServiceExt;

/// A principal with the permission to read incidents.
pub const VIEWER: &str = "viewer-token-0123456789abcdef0123456789";
/// A principal with the permission to read the audit log.
pub const AUDITOR: &str = "auditor-token-0123456789abcdef012345678";
/// A principal with the permission to approve actions.
pub const APPROVER: &str = "approver-token-0123456789abcdef01234567";
/// A principal with the permission to run playbooks.
pub const OPERATOR: &str = "operator-token-0123456789abcdef01234567";
/// A principal with the permission to administer.
pub const ADMIN: &str = "admin-token-0123456789abcdef0123456789ab";
/// A principal with a valid token and a role that gives no permission.
pub const GUEST: &str = "guest-token-0123456789abcdef0123456789ab";
/// A principal with the permissions to read incidents and to read the audit log.
pub const ANALYST: &str = "analyst-token-0123456789abcdef012345678";
/// A token that no principal has.
pub const UNKNOWN: &str = "unknown-token-0123456789abcdef0123456789";

/// The name of the sample playbook.
pub const PLAYBOOK_NAME: &str = "block-spray-source";

const PLAYBOOK: &str = r#"
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
  entity_kinds: [ip_address]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
"#;

/// The principals of the test configuration: the identifier, the role, the token variable,
/// and the token. The role `analyst` has two permissions. Each other role has one.
pub const PRINCIPALS: [(&str, &str, &str, &str); 7] = [
    ("vera@example.com", "viewer", "TOKEN_VIEWER", VIEWER),
    ("audrey@example.com", "auditor", "TOKEN_AUDITOR", AUDITOR),
    ("alice@example.com", "approver", "TOKEN_APPROVER", APPROVER),
    ("oscar@example.com", "operator", "TOKEN_OPERATOR", OPERATOR),
    ("adam@example.com", "admin", "TOKEN_ADMIN", ADMIN),
    ("gus@example.com", "guest", "TOKEN_GUEST", GUEST),
    ("sam@example.com", "analyst", "TOKEN_ANALYST", ANALYST),
];

/// Returns the environment of the tests: one token for each principal, and `extra`.
pub fn env(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static {
    let mut variables: BTreeMap<String, String> = PRINCIPALS
        .iter()
        .map(|(_, _, variable, token)| ((*variable).to_owned(), (*token).to_owned()))
        .collect();
    for (name, value) in extra {
        variables.insert((*name).to_owned(), (*value).to_owned());
    }
    move |name: &str| variables.get(name).cloned()
}

/// Returns the access rules of the tests.
pub fn rbac() -> Rbac {
    Rbac::new(
        RbacConfig::default()
            .with_role("viewer", &[Permission::ViewIncidents])
            .with_role("auditor", &[Permission::ViewAudit])
            .with_role("approver", &[Permission::ApproveActions])
            .with_role("operator", &[Permission::RunPlaybooks])
            .with_role("admin", &[Permission::Administer])
            .with_role(
                "analyst",
                &[Permission::ViewIncidents, Permission::ViewAudit],
            ),
    )
}

/// Returns a configuration with the test principals.
pub fn config() -> ApiConfig {
    ApiConfig {
        principals: PRINCIPALS
            .iter()
            .map(|(id, role, variable, _)| PrincipalConfig::human(*id, &[*role], *variable))
            .collect(),
        ..ApiConfig::default()
    }
}

/// One call of [`ApprovalActions::decide`].
#[derive(Debug, Clone, PartialEq)]
pub struct DecideCall {
    pub id: ApprovalId,
    pub approve: bool,
    pub principal: Principal,
    pub note: Option<String>,
}

/// An approval path that records each call and changes only the in-memory queue.
pub struct FakeApprovalActions {
    queue: Arc<MemoryApprovals>,
    calls: Mutex<Vec<DecideCall>>,
    failure: Mutex<Option<Error>>,
}

impl FakeApprovalActions {
    pub fn new(queue: Arc<MemoryApprovals>) -> Self {
        Self {
            queue,
            calls: Mutex::default(),
            failure: Mutex::default(),
        }
    }

    /// Returns the calls, in order.
    pub fn calls(&self) -> Vec<DecideCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Makes the next call fail with `error`.
    pub fn fail_next(&self, error: Error) {
        *self.failure.lock().unwrap() = Some(error);
    }
}

/// The outcome that the fake approval path returns for an approval.
pub fn executed_outcome(request: &ApprovalRequest) -> ActionOutcome {
    ActionOutcome {
        action_id: request.action.id,
        status: ActionStatus::Succeeded,
        connector: "test-connector".to_owned(),
        message: "The connector did the action.".to_owned(),
        details: Value::Null,
        reversible: true,
        completed_at: Utc.with_ymd_and_hms(2026, 11, 3, 9, 30, 0).unwrap(),
    }
}

#[async_trait]
impl ApprovalActions for FakeApprovalActions {
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalDecision> {
        self.calls.lock().unwrap().push(DecideCall {
            id,
            approve,
            principal: principal.clone(),
            note: note.clone(),
        });
        if let Some(error) = self.failure.lock().unwrap().take() {
            return Err(error);
        }
        let request = self.queue.decide(id, approve, principal, note).await?;
        let disposition = approve.then(|| ActionDisposition::Executed(executed_outcome(&request)));
        Ok(ApprovalDecision {
            request,
            disposition,
        })
    }
}

/// The revert path of the tests: the real scheduler and the real dispatcher, with the
/// in-memory services. The composition root has the same calls, and it also checks the
/// permission of the principal.
pub struct TestReverts {
    pub scheduler: RevertScheduler,
    pub dispatcher: Arc<Dispatcher>,
}

#[async_trait]
impl RevertActions for TestReverts {
    fn enabled(&self) -> bool {
        true
    }

    async fn pending(&self) -> Result<Vec<PendingRevert>> {
        self.scheduler.pending().await
    }

    async fn confirm(&self, action_id: ActionId, principal: &Principal) -> Result<PendingRevert> {
        self.scheduler.confirm(action_id, principal).await
    }

    async fn extend(
        &self,
        action_id: ActionId,
        principal: &Principal,
        extension: Duration,
    ) -> Result<PendingRevert> {
        self.scheduler.extend(action_id, principal, extension).await
    }

    async fn cancel(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        self.scheduler.cancel(action_id, principal).await
    }

    async fn revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
    ) -> Result<ActionDisposition> {
        self.dispatcher.revert(action_id, principal, reason).await
    }
}

/// The status data of the tests: fixed counts, and one more field.
pub struct TestStatus;

/// The flood counts that [`TestStatus`] gives.
pub const FLOOD: FloodStatus = FloodStatus {
    suppressed_matches: 41,
    repeat_detections: 2,
    triage_quota_denials: 7,
    coalesced_incident_updates: 13,
};

#[async_trait]
impl StatusSource for TestStatus {
    async fn status(&self) -> SystemStatus {
        let mut sections = BTreeMap::new();
        sections.insert("decoy".to_owned(), serde_json::json!({ "requests": 5 }));
        // A field of the route itself. The route keeps its own value.
        sections.insert("version".to_owned(), serde_json::json!("not-the-version"));
        SystemStatus {
            flood: FLOOD,
            sections,
        }
    }
}

/// The in-memory services behind one API under test.
pub struct TestApi {
    pub incidents: Arc<MemoryIncidents>,
    pub graph: Arc<MemoryGraph>,
    pub audit: Arc<MemoryAuditLog>,
    pub approvals: Arc<MemoryApprovals>,
    pub bus: Arc<MemoryBus>,
    pub agents: Arc<AgentRuntime>,
    pub actions: Arc<FakeApprovalActions>,
    pub firewall: Arc<RecordingConnector>,
    /// The dispatcher of the playbooks and of the reverts. Its policy permits each action.
    pub dispatcher: Arc<Dispatcher>,
    /// The scheduler of the timed reverts of `dispatcher`. No task runs it: a test calls
    /// `run_due`.
    pub scheduler: RevertScheduler,
    pub state: ApiState,
}

impl TestApi {
    /// Makes empty services and an API state around them.
    pub fn new() -> Self {
        Self::with_env(&[])
    }

    /// Makes the services. The environment has the tokens and the `extra` variables.
    pub fn with_env(extra: &[(&str, &str)]) -> Self {
        let incidents = Arc::new(MemoryIncidents::default());
        let graph = Arc::new(MemoryGraph::default());
        let audit = Arc::new(MemoryAuditLog::default());
        let approvals = Arc::new(MemoryApprovals::default());
        let bus = Arc::new(MemoryBus::default());

        let context = AgentContext {
            goal: "Keep this tenant safe.".to_owned(),
            models: Arc::new(ScriptedModel::new("local")),
            graph: graph.clone(),
            incidents: incidents.clone(),
            audit: audit.clone(),
            bus: bus.clone(),
        };
        let agents = Arc::new(
            AgentRuntime::builder(
                context,
                Arc::new(RecordingDispatcher::new(DispatchMode::Execute)),
            )
            .with_default_agents()
            .build()
            .unwrap(),
        );

        let firewall = Arc::new(RecordingConnector::new(
            "firewall",
            vec![ActionKind::BlockIp],
        ));
        let mut registry = ActionRegistry::new();
        registry.register(firewall.clone()).unwrap();
        let dispatcher = Arc::new(
            Dispatcher::builder(
                Arc::new(registry),
                Arc::new(StaticPolicy::AllowAll),
                approvals.clone(),
                audit.clone(),
            )
            .revert_store(Arc::new(MemoryRevertStore::default()))
            .build(),
        );
        let scheduler = RevertScheduler::new(dispatcher.clone()).unwrap();
        let mut playbooks = PlaybookEngine::new(dispatcher.clone());
        playbooks
            .add(Playbook::from_yaml("block-spray-source.yaml", PLAYBOOK).unwrap())
            .unwrap();

        let actions = Arc::new(FakeApprovalActions::new(approvals.clone()));
        let state = ApiState::new(ApiParts {
            incidents: incidents.clone(),
            graph: graph.clone(),
            audit: audit.clone(),
            approvals: approvals.clone(),
            bus: bus.clone(),
            rbac: rbac(),
            agents: agents.clone(),
            playbooks: Arc::new(playbooks),
            approval_actions: actions.clone(),
            modules: ModuleSet::new([Module::Detection, Module::Responder, Module::Api]).unwrap(),
        })
        .with_reverts(Arc::new(TestReverts {
            scheduler: scheduler.clone(),
            dispatcher: dispatcher.clone(),
        }))
        .with_env(env(extra));
        Self {
            incidents,
            graph,
            audit,
            approvals,
            bus,
            agents,
            actions,
            firewall,
            dispatcher,
            scheduler,
            state,
        }
    }

    /// Builds the router with the test configuration.
    pub fn router(&self) -> Router {
        self.router_with(&config())
    }

    /// Builds the router with `config`.
    pub fn router_with(&self, config: &ApiConfig) -> Router {
        aegis_api::router(self.state.clone(), config).unwrap()
    }

    /// Saves a sample incident and returns it.
    pub async fn seed_incident(&self, title: &str, severity: Severity) -> Incident {
        let incident = incident(title, severity);
        self.incidents.save(&incident).await.unwrap();
        incident
    }

    /// Puts a sample approval request in the queue and returns it.
    pub async fn seed_approval(&self) -> ApprovalRequest {
        let request = approval_request();
        self.approvals.submit(request.clone()).await.unwrap();
        request
    }
}

/// The address of the password spray in the sample incident.
pub const SPRAY_ADDRESS: &str = "203.0.113.50";

/// Makes an open incident with one detection, three entities, and one timeline entry.
pub fn incident(title: &str, severity: Severity) -> Incident {
    let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 0).unwrap();
    let technique = AttackTechnique::new("credential-access", "T1110.003", "Password Spraying");
    let entities = vec![
        EntityRef::new(EntityKind::IpAddress, SPRAY_ADDRESS),
        EntityRef::new(EntityKind::User, "user-1").with_name("victim@example.com"),
        EntityRef::new(EntityKind::ServicePrincipal, "sp-1").with_name("sync-helper"),
    ];
    Incident {
        id: IncidentId::new(),
        title: title.to_owned(),
        summary: "Many failed sign-ins from one address.".to_owned(),
        severity,
        status: IncidentStatus::Open,
        created_at: time,
        updated_at: time,
        tenant: Some("tenant-contoso".to_owned()),
        detections: vec![Detection {
            id: aegis_contracts::common::DetectionId::new(),
            rule_id: "aegis.signin.burst".to_owned(),
            title: "Password spray".to_owned(),
            description: "One address failed to sign in to many accounts.".to_owned(),
            severity,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time,
            attack: vec![technique.clone()],
            event_ids: Vec::new(),
            entities: entities.clone(),
            tenant: Some("tenant-contoso".to_owned()),
            attributes: BTreeMap::new(),
        }],
        entities,
        attack: vec![technique],
        timeline: vec![TimelineEntry {
            time,
            author: "correlator".to_owned(),
            description: "The correlator made the incident.".to_owned(),
            evidence: Vec::new(),
        }],
    }
}

/// Makes a pending approval request for a `disable_user` action of the Responder.
pub fn approval_request() -> ApprovalRequest {
    let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 5, 0).unwrap();
    let mut action = ActionRequest::new(
        ActionKind::DisableUser,
        EntityRef::new(EntityKind::User, "user-1").with_name("victim@example.com"),
        "responder",
        "The account signed in from the spray address.",
    );
    action.requested_at = time;
    ApprovalRequest {
        id: ApprovalId::new(),
        action,
        requested_by: Principal::new("responder", PrincipalKind::Agent, &["responder"]),
        decision: PolicyDecision {
            effect: PolicyEffect::RequireApproval,
            tier: ActionTier::Gated,
            reasons: vec!["The action is in the gated tier.".to_owned()],
            policy: Some("aegis.response.decision".to_owned()),
            evaluated_at: time,
        },
        status: ApprovalStatus::Pending,
        requested_at: time,
        decided_by: None,
        decided_at: None,
        note: None,
    }
}

/// One response: the status, the headers, and the body.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    /// Returns the body as a JSON document.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("the body is not JSON ({error}): {:?}", self.text()))
    }

    /// Returns the body as text.
    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    /// Returns one header as text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Returns the `code` of the error body.
    pub fn error_code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap().to_owned()
    }

    /// Returns the `message` of the error body.
    pub fn error_message(&self) -> String {
        self.json()["error"]["message"].as_str().unwrap().to_owned()
    }
}

/// Sends one request to the router and reads the full response.
pub async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    // A live feed has no end. The tests of the feed read its events one at a time.
    let is_feed = headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/event-stream"));
    let body = if is_feed {
        Vec::new()
    } else {
        let read = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024);
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("the response body did not end")
            .unwrap()
            .to_vec()
    };
    Reply {
        status,
        headers,
        body,
    }
}

/// Builds a request with an optional bearer token and an optional JSON body.
pub fn request(
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    match body {
        Some(body) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Sends a GET request with a bearer token.
pub async fn get(router: &Router, path: &str, token: &str) -> Reply {
    send(router, request(Method::GET, path, Some(token), None)).await
}

/// Sends a POST request with a bearer token and a JSON body.
pub async fn post(router: &Router, path: &str, token: &str, body: &Value) -> Reply {
    send(router, request(Method::POST, path, Some(token), Some(body))).await
}

/// Returns a value in its JSON form.
pub fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}
