//! The operator API in the running application: REST with bearer tokens, the approval
//! path, the live feed, the console, and shutdown.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aegis_agents::RuntimeState;
use aegis_agents::ledger::{ActionState, tracked_actions};
use aegis_app::actions::DispatchResult;
use aegis_app::api::OperatorApi;
use aegis_app::report::RunSummary;
use aegis_app::{App, RunOptions, starter};
use aegis_contracts::action::{
    ActionConnector, ActionDisposition, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::common::{ActionId, ApprovalId, EvidenceKind, TimeRange};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus, Principal, PrincipalKind};
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Result};
use aegis_core::{Config, Shutdown};
use aegis_ingest::{FileSource, FileSourceConfig};
use aegis_policy::FileAuditLog;
use aegis_testkit::{RecordingConnector, fixtures};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use support::{Starter, WAIT, live, replace_once, spray_events, with_modules};

const ALICE_TOKEN: &str = "alice-0123456789abcdef0123456789abcdef";
const VERA_TOKEN: &str = "vera-0123456789abcdef0123456789abcdef0";
const ROOT_TOKEN: &str = "root-0123456789abcdef0123456789abcdef0";

/// The modules of the tests: detection, the agents that propose actions, and the API.
const MODULES: [&str; 6] = [
    "ingest",
    "detection",
    "monitor",
    "analyst",
    "responder",
    "api",
];

/// The `[api]` section of the tests. Alice can approve. Vera can only read. Root has the
/// role `admin`, which can run playbooks and cannot approve.
const API_SECTION: &str = r#"
[api]
bind = "127.0.0.1:9443"

[[api.principals]]
id = "alice@example.com"
roles = ["approver"]
token_env = "AEGIS_TEST_TOKEN_ALICE"

[[api.principals]]
id = "vera@example.com"
roles = ["analyst"]
token_env = "AEGIS_TEST_TOKEN_VERA"

[[api.principals]]
id = "root@example.com"
roles = ["admin"]
token_env = "AEGIS_TEST_TOKEN_ROOT"
"#;

/// The environment of the tests. The tests do not change the environment of the process.
fn env(name: &str) -> Option<String> {
    match name {
        "AEGIS_TEST_TOKEN_ALICE" => Some(ALICE_TOKEN.to_owned()),
        "AEGIS_TEST_TOKEN_VERA" => Some(VERA_TOKEN.to_owned()),
        "AEGIS_TEST_TOKEN_ROOT" => Some(ROOT_TOKEN.to_owned()),
        _ => None,
    }
}

fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

/// A live configuration with the API: the dispatcher and the agents make no dry run, the
/// playbooks are off, and the default policy gates each containment action.
fn live_config(starter: &Starter, change: impl FnOnce(String) -> String) -> Config {
    starter.config_with(|text| change(with_modules(&live(&text), &MODULES) + API_SECTION))
}

/// A recording connector that can hold each call until the test releases it.
struct TestConnector {
    record: RecordingConnector,
    entered: watch::Sender<usize>,
    held: watch::Sender<bool>,
}

impl TestConnector {
    fn with(record: RecordingConnector) -> Arc<Self> {
        Arc::new(Self {
            record,
            entered: watch::Sender::new(0),
            held: watch::Sender::new(false),
        })
    }

    /// A connector for the actions of the Responder and of the sample playbooks.
    fn new() -> Arc<Self> {
        Self::with(Self::recorder())
    }

    fn recorder() -> RecordingConnector {
        RecordingConnector::new(
            "recorder",
            vec![
                ActionKind::BlockIp,
                ActionKind::KillSession,
                ActionKind::DisableServicePrincipal,
                ActionKind::RevokeCredential,
                ActionKind::Notify,
            ],
        )
    }

    /// Makes each later call wait in `execute`.
    fn hold(&self) {
        self.held.send_replace(true);
    }

    /// Lets each call that waits continue.
    fn release(&self) {
        self.held.send_replace(false);
    }

    /// Waits until `count` calls started.
    async fn entered(&self, count: usize) {
        let mut entered = self.entered.subscribe();
        tokio::time::timeout(WAIT, entered.wait_for(|calls| *calls >= count))
            .await
            .expect("the connector did not get the call in time")
            .unwrap();
    }

    fn calls(&self) -> usize {
        *self.entered.borrow()
    }

    /// Returns the requests of the calls that completed.
    fn executed(&self) -> Vec<ActionRequest> {
        self.record.executed()
    }
}

#[async_trait]
impl ActionConnector for TestConnector {
    fn info(&self) -> ConnectorInfo {
        self.record.info()
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        self.record.supported_actions()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.entered.send_modify(|calls| *calls += 1);
        let mut held = self.held.subscribe();
        held.wait_for(|held| !*held)
            .await
            .map_err(|_| Error::Unavailable("the test dropped the connector".to_owned()))?;
        self.record.execute(request).await
    }
}

/// The file source of the recorded attack log. It opens its stream when the test opens
/// the gate, so that a test can prepare before the first event.
struct GatedSource {
    inner: FileSource,
    gate: watch::Receiver<bool>,
}

#[async_trait]
impl SourceConnector for GatedSource {
    fn info(&self) -> ConnectorInfo {
        self.inner.info()
    }

    async fn check(&self) -> Result<()> {
        self.inner.check().await
    }

    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        let mut gate = self.gate.clone();
        gate.wait_for(|open| *open)
            .await
            .map_err(|_| Error::Unavailable("the test dropped the gate".to_owned()))?;
        self.inner.stream(cursor).await
    }

    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        self.inner.fetch(range, cursor).await
    }
}

/// An HTTP client for one server on a loopback address.
struct Http {
    address: SocketAddr,
    client: reqwest::Client,
}

impl Http {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            // A proxy of the environment must not get the requests of the test.
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    async fn send(request: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::Response {
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        tokio::time::timeout(WAIT, request.send())
            .await
            .expect("the server gave no answer in time")
            .unwrap()
    }

    async fn get(&self, path: &str, token: Option<&str>) -> reqwest::Response {
        Self::send(self.client.get(self.url(path)), token).await
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> reqwest::Response {
        Self::send(self.client.post(self.url(path)).json(body), token).await
    }

    /// Sends a GET request that must succeed, and returns the JSON document.
    async fn json(&self, path: &str, token: &str) -> Value {
        let response = self.get(path, Some(token)).await;
        assert_eq!(response.status(), 200, "GET {path}");
        response.json().await.unwrap()
    }

    /// Sends a request that the server must refuse. Returns the code of the error.
    async fn refused(response: reqwest::Response, status: u16) -> String {
        assert_eq!(response.status(), status);
        let body: Value = response.json().await.unwrap();
        body["error"]["code"].as_str().unwrap().to_owned()
    }
}

/// The program logic of `aegis run`: the application with the recorded attack log as a
/// file source, and its operator API on a loopback port that the operating system
/// selects.
struct Program {
    starter: Starter,
    app: Arc<App>,
    http: Http,
    shutdown: Shutdown,
    run: JoinHandle<Result<RunSummary>>,
    connector: Arc<TestConnector>,
    gate: watch::Sender<bool>,
}

impl Program {
    async fn start() -> Self {
        Self::start_with(|text| text).await
    }

    /// Starts the application after `change` changed the text of the live configuration.
    async fn start_with(change: impl FnOnce(String) -> String) -> Self {
        let starter = Starter::new();
        let events = starter.path().join("events.jsonl");
        std::fs::write(&events, starter::attack_log()).unwrap();
        let config = live_config(&starter, change);
        let connector = TestConnector::new();
        let (gate, gate_receiver) = watch::channel(false);
        let source = GatedSource {
            inner: FileSource::new(FileSourceConfig::new("recorded", events)).unwrap(),
            gate: gate_receiver,
        };
        let app = Arc::new(
            starter
                .build(&config, |builder| {
                    builder
                        .action_connector(connector.clone())
                        .source(Arc::new(source))
                })
                .await,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = OperatorApi::new(&app)
            .unwrap()
            .with_env(env)
            .on_listener(listener)
            .unwrap();
        let http = Http::new(api.local_addr());
        let shutdown = Shutdown::new();
        let options = RunOptions {
            stop_when_sources_end: false,
            services: vec![api.into_service()],
        };
        let run = tokio::spawn({
            let (app, shutdown) = (app.clone(), shutdown.clone());
            async move { app.run_with(shutdown, options).await }
        });
        Self {
            starter,
            app,
            http,
            shutdown,
            run,
            connector,
            gate,
        }
    }

    /// Lets the file source read the recorded attack log.
    fn open_the_source(&self) {
        self.gate.send(true).unwrap();
    }

    /// Waits until the application examined the full attack log and the Responder
    /// proposed its six containment actions. Each one waits for approval.
    async fn wait_for_the_attack(&self) {
        let reached = self
            .app
            .wait_until(WAIT, || {
                let app = self.app.clone();
                async move {
                    app.progress().events_processed == fixtures::ATTACK_LOG_EVENTS as u64
                        && app.approvals().pending().await.unwrap().len() == 6
                }
            })
            .await;
        assert!(
            reached.is_ok(),
            "progress {:?}, {} pending approvals",
            self.app.progress(),
            self.app.approvals().pending().await.unwrap().len()
        );
    }

    async fn the_incident(&self) -> Incident {
        let mut incidents = self.app.incidents().list(None, 10).await.unwrap();
        assert_eq!(incidents.len(), 1);
        incidents.remove(0)
    }

    /// Returns the pending approval request for the block of the spray address, as the
    /// API shows it.
    async fn the_block_request(&self) -> Value {
        let page = self.http.json("/api/v1/approvals", VERA_TOKEN).await;
        assert_eq!(page["total"], 6);
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 6);
        let spray_address = fixtures::SPRAY_IP.to_string();
        let found: Vec<&Value> = items
            .iter()
            .filter(|item| {
                item["action"]["kind"] == "block_ip"
                    && item["action"]["target"]["id"] == spray_address.as_str()
            })
            .collect();
        assert_eq!(found.len(), 1);
        found[0].clone()
    }

    /// Triggers the shutdown and returns the result of the run.
    async fn stop(&mut self) -> Result<RunSummary> {
        self.shutdown.trigger();
        tokio::time::timeout(WAIT, &mut self.run)
            .await
            .expect("the application did not stop in time")
            .unwrap()
    }
}

fn id_of<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

/// Returns the state of one action in the timeline of an incident.
fn tracked_state(incident: &Incident, action: ActionId) -> Option<ActionState> {
    tracked_actions(incident)
        .iter()
        .find(|tracked| tracked.action_id == action.to_string())
        .map(|tracked| tracked.state)
}

/// Returns the audit records of one kind that have `approval` in their payload.
async fn records_of(app: &App, kind: AuditKind, approval: ApprovalId) -> Vec<AuditRecord> {
    let wanted = json!(approval);
    app.audit()
        .read(1, 100_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|record| {
            record.kind == kind
                && (record.payload["approval"]["id"] == wanted
                    || record.payload["approval_id"] == wanted)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_sees_the_incident_and_approves_a_gated_action_through_http() {
    let mut program = Program::start().await;
    program.open_the_source();
    program.wait_for_the_attack().await;
    let http = &program.http;

    // No token and a token that no principal has: 401.
    let code = Http::refused(http.get("/api/v1/incidents", None).await, 401).await;
    assert_eq!(code, "unauthorized");
    let unknown = "mallory-0123456789abcdef0123456789abc";
    let code = Http::refused(http.get("/api/v1/incidents", Some(unknown)).await, 401).await;
    assert_eq!(code, "unauthorized");

    // The incident of the store is in the list.
    let incident = program.the_incident().await;
    let page = http.json("/api/v1/incidents", VERA_TOKEN).await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(id_of::<Incident>(&items[0]).id, incident.id);
    assert_eq!(items[0]["severity"], "critical");
    assert_eq!(items[0]["detections"].as_array().unwrap().len(), 8);

    // The pending request is in the list, with the action of the Responder.
    let request = program.the_block_request().await;
    assert_eq!(request["status"], "pending");
    assert_eq!(request["requested_by"]["id"], "responder");
    assert_eq!(request["action"]["dry_run"], false);
    let approval: ApprovalId = id_of(&request["id"]);
    let action: ActionId = id_of(&request["action"]["id"]);
    assert_eq!(
        tracked_state(&incident, action),
        Some(ActionState::PendingApproval)
    );
    let path = format!("/api/v1/approvals/{approval}/decision");
    let approve = json!({ "approve": true, "note": "Confirmed with the network team." });

    // No token: 401. A token without the permission `approve_actions`: 403.
    let code = Http::refused(http.post(&path, None, &approve).await, 401).await;
    assert_eq!(code, "unauthorized");
    let code = Http::refused(http.post(&path, Some(VERA_TOKEN), &approve).await, 403).await;
    assert_eq!(code, "forbidden");
    let code = Http::refused(http.post(&path, Some(ROOT_TOKEN), &approve).await, 403).await;
    assert_eq!(code, "forbidden");
    assert_eq!(program.connector.calls(), 0);
    assert_eq!(program.app.approvals().pending().await.unwrap().len(), 6);

    // Alice approves. The answer has the decided request and the result of the action.
    let response = http.post(&path, Some(ALICE_TOKEN), &approve).await;
    assert_eq!(response.status(), 200);
    let decision: Value = response.json().await.unwrap();
    assert_eq!(decision["request"]["status"], "approved");
    assert_eq!(decision["request"]["decided_by"], "alice@example.com");
    assert_eq!(
        decision["request"]["note"],
        "Confirmed with the network team."
    );
    assert_eq!(decision["disposition"]["executed"]["status"], "succeeded");
    assert_eq!(decision["disposition"]["executed"]["connector"], "recorder");
    assert_eq!(
        id_of::<ActionId>(&decision["disposition"]["executed"]["action_id"]),
        action
    );

    // The action ran exactly one time, and it was not a dry run.
    let executed = program.connector.executed();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].id, action);
    assert_eq!(executed[0].kind, ActionKind::BlockIp);
    assert_eq!(executed[0].target.id, fixtures::SPRAY_IP.to_string());
    assert!(!executed[0].dry_run);

    // A second decision is refused, for an approval and for a rejection.
    for approve in [true, false] {
        let again = json!({ "approve": approve });
        let code = Http::refused(http.post(&path, Some(ALICE_TOKEN), &again).await, 409).await;
        assert_eq!(code, "conflict");
    }
    assert_eq!(program.connector.calls(), 1);
    let page = http.json("/api/v1/approvals", ALICE_TOKEN).await;
    assert_eq!(page["total"], 5);
    let one = http
        .json(&format!("/api/v1/approvals/{approval}"), ALICE_TOKEN)
        .await;
    assert_eq!(one["status"], "approved");

    // The Responder got the result: the incident store has the new state of the action.
    let reached = program
        .app
        .wait_until(WAIT, || {
            let app = program.app.clone();
            async move {
                let stored = app.incidents().get(incident.id).await.unwrap().unwrap();
                tracked_state(&stored, action) == Some(ActionState::Succeeded)
            }
        })
        .await;
    assert!(reached.is_ok(), "the Responder did not record the result");
    let shown: Incident = id_of(
        &http
            .json(&format!("/api/v1/incidents/{}", incident.id), VERA_TOKEN)
            .await,
    );
    assert_eq!(tracked_state(&shown, action), Some(ActionState::Succeeded));

    // The audit log has one decision of Alice and one run for this approval, and the
    // chain verifies.
    let decided = records_of(&program.app, AuditKind::ApprovalDecided, approval).await;
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].actor, "alice@example.com");
    let ran = records_of(&program.app, AuditKind::ActionExecuted, approval).await;
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].payload["outcome"]["status"], "succeeded");
    let verification = http.json("/api/v1/audit/verification", VERA_TOKEN).await;
    assert_eq!(verification["valid"], true);
    assert_eq!(
        verification["checked"].as_u64().unwrap(),
        program.app.audit().read(1, 100_000).await.unwrap().len() as u64
    );

    let summary = program.stop().await.unwrap();
    assert_eq!(
        summary.progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    let from_file = FileAuditLog::verify_file(program.starter.audit_file()).unwrap();
    assert!(from_file.valid, "{from_file:?}");
}

/// Reads the live feed until `done` accepts the events. Each event is its type and its
/// data.
///
/// The time limit is for all events together: a feed that sends only other events, or
/// only its keep-alive comments, does not keep the test waiting.
async fn read_feed(
    feed: &mut reqwest::Response,
    buffer: &mut String,
    events: &mut Vec<(String, Value)>,
    done: impl Fn(&[(String, Value)]) -> bool,
) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer.drain(..end + 2).collect();
            let field = |name: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .map(str::to_owned)
            };
            if let (Some(event), Some(data)) = (field("event: "), field("data: ")) {
                events.push((event, serde_json::from_str(&data).unwrap()));
            }
        }
        if done(events) {
            return;
        }
        let chunk = tokio::time::timeout_at(deadline, feed.chunk())
            .await
            .expect("the live feed did not give the expected events in time")
            .unwrap()
            .expect("the live feed ended");
        buffer.push_str(std::str::from_utf8(&chunk).unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_feed_delivers_the_audit_records_and_the_incidents_of_the_application() {
    let mut program = Program::start().await;

    // The feed opens before the source gives its first event.
    let mut feed = program.http.get("/api/v1/stream", Some(VERA_TOKEN)).await;
    assert_eq!(feed.status(), 200);
    let (mut buffer, mut events) = (String::new(), Vec::new());
    read_feed(&mut feed, &mut buffer, &mut events, |events| {
        !events.is_empty()
    })
    .await;
    assert_eq!(events[0].0, "ready");
    assert_eq!(
        events[0].1,
        json!({ "feeds": ["detection", "incident", "action_result", "approval", "audit"] })
    );

    program.open_the_source();
    let is_detection_record = |(event, data): &(String, Value)| {
        event == "audit" && data["payload"]["kind"] == "detection"
    };
    read_feed(&mut feed, &mut buffer, &mut events, |events| {
        events.iter().any(|(event, _)| event == "incident")
            && events.iter().any(is_detection_record)
    })
    .await;
    program.wait_for_the_attack().await;

    // The incident event is the first state of the incident of the store.
    let incident = program.the_incident().await;
    let (_, first_state) = events
        .iter()
        .find(|(event, _)| event == "incident")
        .unwrap();
    assert_eq!(first_state["subject"], "aegis.incidents");
    assert_eq!(id_of::<Incident>(&first_state["payload"]).id, incident.id);
    assert_eq!(
        first_state["payload"]["detections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The audit event is the sealed record of the audit log, with the same hash.
    let (_, sealed) = events
        .iter()
        .find(|event| is_detection_record(event))
        .unwrap();
    assert_eq!(sealed["subject"], "aegis.audit");
    let from_feed: AuditRecord = id_of(&sealed["payload"]);
    let stored = program
        .app
        .audit()
        .read(from_feed.sequence, 1)
        .await
        .unwrap();
    assert_eq!(stored, std::slice::from_ref(&from_feed));
    assert_eq!(from_feed.kind, AuditKind::Detection);
    assert_eq!(from_feed.actor, aegis_app::DETECTION_ACTOR);

    // The shutdown ends the feed.
    program.stop().await.unwrap();
    let ended = tokio::time::timeout(WAIT, async {
        while feed.chunk().await.unwrap().is_some() {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the live feed stayed open after the shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_console_loads_and_the_shutdown_stops_the_server_and_the_application() {
    let mut program = Program::start().await;
    let http = &program.http;

    // The page and each file that it uses come from the running program, with no token.
    let assets = aegis_api::console_assets();
    assert!(assets.len() > 1, "{}", assets.len());
    for asset in assets {
        let path = match asset.path {
            "index.html" => "/".to_owned(),
            path => format!("/assets/{path}"),
        };
        let response = http.get(&path, None).await;
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(
            response.headers()["content-type"].to_str().unwrap(),
            asset.content_type,
            "{path}"
        );
        assert_eq!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap(),
            aegis_api::CONSOLE_CONTENT_SECURITY_POLICY,
            "{path}"
        );
        assert_eq!(response.text().await.unwrap(), asset.body, "{path}");
    }
    let health = http.get("/healthz", None).await;
    assert_eq!(health.status(), 200);
    assert_eq!(
        health.json::<Value>().await.unwrap(),
        json!({ "status": "ok" })
    );

    // The status route shows the module set and the agent runtime of the application.
    // The runtime drives its queue when it works on the goal of the operator.
    let runtime = program.app.agents().unwrap();
    program
        .app
        .wait_until(WAIT, || {
            let runtime = runtime.clone();
            async move { runtime.state() == RuntimeState::Running }
        })
        .await
        .unwrap();
    let status = http.json("/api/v1/status", VERA_TOKEN).await;
    assert_eq!(status["modules"], json!(MODULES));
    assert_eq!(status["agents"]["state"], "running");
    assert_eq!(status["agents"]["dry_run"], false);
    let agents = http.json("/api/v1/agents", VERA_TOKEN).await;
    assert_eq!(
        agents["roster"],
        json!(["supervisor", "monitor", "analyst", "responder"])
    );
    let session = http.json("/api/v1/session", ALICE_TOKEN).await;
    assert_eq!(session["principal"]["id"], "alice@example.com");
    assert_eq!(
        session["permissions"],
        json!(["view_incidents", "approve_actions"])
    );

    // The shutdown stops the application and the server. Each component returns.
    program.open_the_source();
    program.wait_for_the_attack().await;
    let address = program.http.address;
    let summary = program.stop().await.unwrap();
    assert_eq!(summary.sources.len(), 1);
    assert_eq!(
        summary.progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(runtime.state(), RuntimeState::Idle);

    // The server does not listen, and no task of the server holds the application.
    let refused = tokio::net::TcpStream::connect(address).await.unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    drop(runtime);
    let Program { app, starter, .. } = program;
    let app = Arc::try_unwrap(app)
        .ok()
        .expect("a task still holds the application after the shutdown");
    app.close().await;
    drop(app);

    // The audit file is free: a new application opens it and continues the chain.
    let config = live_config(&starter, |text| text);
    let again = starter.build(&config, |builder| builder).await;
    let verification = again.audit().verify().await.unwrap();
    assert!(verification.valid, "{verification:?}");
    assert!(verification.checked > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_the_time_limit_drops_leaves_no_half_applied_approval() {
    // The API drops the work of a request after one second.
    let mut program =
        Program::start_with(|text| text + "\n[api.limits]\nrequest_timeout_seconds = 1\n").await;
    program.open_the_source();
    program.wait_for_the_attack().await;
    // The test reads the queue directly: only the decisions go through the short limit.
    let spray_address = fixtures::SPRAY_IP.to_string();
    let requests: Vec<ApprovalRequest> = program
        .app
        .approvals()
        .pending()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| {
            request.action.kind == ActionKind::BlockIp && request.action.target.id == spray_address
        })
        .collect();
    assert_eq!(requests.len(), 1);
    let (approval, action) = (requests[0].id, requests[0].action.id);
    let path = format!("/api/v1/approvals/{approval}/decision");

    // The connector does not answer. The request ends at the time limit.
    program.connector.hold();
    let response = program
        .http
        .post(&path, Some(ALICE_TOKEN), &json!({ "approve": true }))
        .await;
    let code = Http::refused(response, 504).await;
    assert_eq!(code, "timeout");

    // The decision is recorded, and the action is in progress: the connector has the
    // call, and the audit log has no result.
    program.connector.entered(1).await;
    let decided = program
        .app
        .approvals()
        .get(approval)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(decided.decided_by.as_deref(), Some("alice@example.com"));
    assert_eq!(program.connector.executed(), []);
    assert_eq!(
        records_of(&program.app, AuditKind::ActionExecuted, approval)
            .await
            .len(),
        0
    );
    // The API refuses a second decision while the first one is in progress.
    let again = program
        .http
        .post(&path, Some(ALICE_TOKEN), &json!({ "approve": true }))
        .await;
    assert_eq!(Http::refused(again, 409).await, "conflict");

    // The shutdown waits for the decision that is in progress.
    program.shutdown.trigger();
    let early = tokio::time::timeout(Duration::from_millis(500), &mut program.run).await;
    assert!(
        early.is_err(),
        "the application stopped before the approved action completed"
    );

    // The connector answers. The decision completes with no request: the action ran one
    // time, the journal and the audit log have its result, and the chain verifies.
    program.connector.release();
    tokio::time::timeout(WAIT, &mut program.run)
        .await
        .expect("the application did not stop in time")
        .unwrap()
        .unwrap();
    let executed = program.connector.executed();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].id, action);
    assert!(!executed[0].dry_run);
    assert_eq!(program.connector.calls(), 1);
    let record = program.app.actions().get(action).unwrap();
    let DispatchResult::Disposition(ActionDisposition::Executed(outcome)) = &record.result else {
        panic!("the journal must have the result: {:?}", record.result);
    };
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    let ran = records_of(&program.app, AuditKind::ActionExecuted, approval).await;
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].payload["outcome"]["status"], "succeeded");
    let from_file = FileAuditLog::verify_file(program.starter.audit_file()).unwrap();
    assert!(from_file.valid, "{from_file:?}");
}

/// An application after the password spray, with no service. One action of the Responder
/// waits for approval: the block of the spray address.
struct Desk {
    _starter: Starter,
    app: Arc<App>,
    connector: Arc<TestConnector>,
    incident: Incident,
    approval: ApprovalRequest,
}

impl Desk {
    async fn new(connector: Arc<TestConnector>, change: impl FnOnce(String) -> String) -> Self {
        let starter = Starter::new();
        let config = live_config(&starter, change);
        let app = Arc::new(
            starter
                .build(&config, |builder| {
                    builder.action_connector(connector.clone())
                })
                .await,
        );
        let report = app.replay(spray_events()).await.unwrap();
        assert_eq!(report.incidents.len(), 1);
        let responder: Vec<ApprovalRequest> = app
            .approvals()
            .pending()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.requested_by.id == "responder")
            .collect();
        assert_eq!(responder.len(), 1);
        assert_eq!(responder[0].action.kind, ActionKind::BlockIp);
        Self {
            _starter: starter,
            app,
            connector,
            incident: report.incidents[0].clone(),
            approval: responder[0].clone(),
        }
    }

    /// Starts the operator API of the application on a loopback port, with no service.
    async fn serve(&self) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = OperatorApi::new(&self.app)
            .unwrap()
            .with_env(env)
            .on_listener(listener)
            .unwrap();
        let http = Http::new(api.local_addr());
        let shutdown = Shutdown::new();
        let task = tokio::spawn(api.serve(shutdown.clone()));
        Server {
            http,
            shutdown,
            task,
        }
    }

    async fn stored(&self) -> Incident {
        self.app
            .incidents()
            .get(self.incident.id)
            .await
            .unwrap()
            .unwrap()
    }
}

struct Server {
    http: Http,
    shutdown: Shutdown,
    task: JoinHandle<Result<()>>,
}

impl Server {
    async fn stop(self) {
        self.shutdown.trigger();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("the server did not stop in time")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decision_completes_when_its_caller_goes_away() {
    let desk = Desk::new(TestConnector::new(), |text| text).await;
    let api = OperatorApi::new(&desk.app).unwrap();
    let approvals = api.state().parts().approval_actions.clone();
    let id = desk.approval.id;
    let alice = alice();

    // The caller goes away when the connector has the call and did not answer.
    desk.connector.hold();
    tokio::select! {
        biased;
        decision = approvals.decide(id, true, &alice, None) => {
            panic!("the decision must wait for the connector: {decision:?}");
        }
        () = desk.connector.entered(1) => {}
    }
    let decided = desk.app.approvals().get(id).await.unwrap().unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(desk.connector.executed(), []);

    // The work continues with no caller. After the connector answers, each step is done.
    desk.connector.release();
    tokio::time::timeout(WAIT, api.settle())
        .await
        .expect("the decision did not complete in time");
    let executed = desk.connector.executed();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].id, desk.approval.action.id);
    assert_eq!(desk.connector.calls(), 1);
    let stored = desk.stored().await;
    assert_eq!(stored.status, IncidentStatus::Contained);
    assert_eq!(
        tracked_state(&stored, desk.approval.action.id),
        Some(ActionState::Succeeded)
    );
    assert_eq!(
        records_of(&desk.app, AuditKind::ActionExecuted, id)
            .await
            .len(),
        1
    );
    assert!(desk.app.audit().verify().await.unwrap().valid);

    // One approval permits one action, also for a caller that did not see the result.
    let again = approvals.decide(id, true, &alice, None).await.unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(message) if message.contains("already has a decision")),
        "{again:?}"
    );
    assert_eq!(desk.connector.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_action_that_fails_after_the_approval_is_in_the_answer() {
    let connector = TestConnector::with(TestConnector::recorder().failing("the firewall is down"));
    let desk = Desk::new(connector, |text| text).await;
    let server = desk.serve().await;
    let id = desk.approval.id;
    let path = format!("/api/v1/approvals/{id}/decision");

    let response = server
        .http
        .post(&path, Some(ALICE_TOKEN), &json!({ "approve": true }))
        .await;

    // The decision took effect, so the answer is the decided request. The failure of the
    // action is the disposition.
    assert_eq!(response.status(), 200);
    let decision: Value = response.json().await.unwrap();
    assert_eq!(decision["request"]["status"], "approved");
    assert_eq!(decision["request"]["decided_by"], "alice@example.com");
    assert_eq!(decision["disposition"]["executed"]["status"], "failed");
    assert_eq!(
        decision["disposition"]["executed"]["message"],
        "unavailable: the firewall is down"
    );
    assert_eq!(desk.connector.calls(), 1);

    // The Responder got the failure, and the journal has it.
    let stored = desk.stored().await;
    assert_eq!(stored.status, IncidentStatus::Investigating);
    assert_eq!(
        tracked_state(&stored, desk.approval.action.id),
        Some(ActionState::Failed)
    );
    let record = desk.app.actions().get(desk.approval.action.id).unwrap();
    assert_eq!(
        record.result,
        DispatchResult::Failed {
            kind: "unavailable".to_owned(),
            message: "unavailable: the firewall is down".to_owned(),
            retryable: true,
        }
    );

    // One approval permits one attempt.
    let again = server
        .http
        .post(&path, Some(ALICE_TOKEN), &json!({ "approve": true }))
        .await;
    assert_eq!(Http::refused(again, 409).await, "conflict");
    assert_eq!(desk.connector.calls(), 1);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_through_http_runs_no_action_and_tells_the_agent() {
    let desk = Desk::new(TestConnector::new(), |text| text).await;
    let server = desk.serve().await;
    let id = desk.approval.id;

    let response = server
        .http
        .post(
            &format!("/api/v1/approvals/{id}/decision"),
            Some(ALICE_TOKEN),
            &json!({ "approve": false, "note": "This address is our scanner." }),
        )
        .await;

    assert_eq!(response.status(), 200);
    let decision: Value = response.json().await.unwrap();
    assert_eq!(decision["request"]["status"], "rejected");
    assert_eq!(decision["request"]["decided_by"], "alice@example.com");
    assert_eq!(decision["disposition"], Value::Null);
    assert_eq!(desk.connector.calls(), 0);
    let stored = desk.stored().await;
    assert_eq!(
        tracked_state(&stored, desk.approval.action.id),
        Some(ActionState::Denied)
    );
    let page = server.http.json("/api/v1/approvals", ALICE_TOKEN).await;
    assert_eq!(page["total"], 0);
    server.stop().await;
}

/// The names of the playbooks, as the API lists them.
async fn playbook_names(http: &Http) -> Vec<String> {
    let page = http.json("/api/v1/playbooks", ROOT_TOKEN).await;
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|playbook| playbook["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The sample playbook that matches the password spray. It has two steps: it blocks the
/// spray address, and it sends a notification.
const SPRAY_PLAYBOOK: &str = "block-password-spray-source";

fn playbook_mode(text: &str, mode: &str) -> String {
    replace_once(
        text,
        "playbooks = \"off\"",
        &format!("playbooks = \"{mode}\""),
    )
}

/// Returns the requests that the playbook of the test sent to the dispatcher.
fn playbook_requests(app: &App) -> Vec<ActionRequest> {
    app.actions()
        .records()
        .into_iter()
        .map(|record| record.request)
        .filter(|request| request.requested_by == format!("playbook:{SPRAY_PLAYBOOK}"))
        .collect()
}

/// Starts the playbook of the test through the API, as the principal of `token`.
async fn start_playbook(
    http: &Http,
    incident: &Incident,
    mode: &str,
    token: &str,
) -> reqwest::Response {
    http.post(
        &format!("/api/v1/playbooks/{SPRAY_PLAYBOOK}/runs"),
        Some(token),
        &json!({ "incident_id": incident.id, "mode": mode }),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_has_no_playbook_when_the_playbooks_are_off() {
    let desk = Desk::new(TestConnector::new(), |text| text).await;
    assert_eq!(desk.app.playbooks().names().len(), 5);
    let server = desk.serve().await;

    assert_eq!(playbook_names(&server.http).await, Vec::<String>::new());
    let response = start_playbook(&server.http, &desk.incident, "live", ROOT_TOKEN).await;
    assert_eq!(Http::refused(response, 404).await, "not_found");
    let response = start_playbook(&server.http, &desk.incident, "dry_run", ROOT_TOKEN).await;
    assert_eq!(Http::refused(response, 404).await, "not_found");

    assert_eq!(playbook_requests(&desk.app), []);
    assert_eq!(desk.connector.calls(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_run_through_the_api_is_a_dry_run_when_the_playbooks_are_dry_runs() {
    // The dispatcher is live. Only the playbook mode makes the dry runs.
    let desk = Desk::new(TestConnector::new(), |text| playbook_mode(&text, "dry_run")).await;
    assert!(!desk.app.dispatcher().dry_run());
    // The application ran the playbook for the incident: two dry runs.
    let before = playbook_requests(&desk.app).len();
    assert_eq!(before, 2);
    let server = desk.serve().await;
    let names = playbook_names(&server.http).await;
    assert_eq!(names, desk.app.playbooks().names());
    assert!(names.contains(&SPRAY_PLAYBOOK.to_owned()), "{names:?}");

    // A principal without the permission `run_playbooks` cannot start a playbook.
    let response = start_playbook(&server.http, &desk.incident, "live", ALICE_TOKEN).await;
    assert_eq!(Http::refused(response, 403).await, "forbidden");
    assert_eq!(playbook_requests(&desk.app).len(), before);

    let response = start_playbook(&server.http, &desk.incident, "live", ROOT_TOKEN).await;

    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    let steps = report["run"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 2);
    for step in steps {
        assert_eq!(
            step["result"]["dispatched"]["executed"]["status"], "simulated",
            "{step}"
        );
    }
    let requests = playbook_requests(&desk.app);
    assert_eq!(requests.len(), before + 2);
    assert!(requests.iter().all(|request| request.dry_run));
    let executed = desk.connector.executed();
    assert_eq!(executed.len(), before + 2);
    assert!(executed.iter().all(|request| request.dry_run));
    // No playbook request waits for approval: nothing was gated.
    let pending = desk.app.approvals().pending().await.unwrap();
    assert_eq!(pending, std::slice::from_ref(&desk.approval));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_request_selects_the_mode_when_the_playbooks_are_live() {
    let desk = Desk::new(TestConnector::new(), |text| playbook_mode(&text, "live")).await;
    // The application ran the playbook for the incident: the policy gated the block, and
    // the notification ran.
    let before = playbook_requests(&desk.app).len();
    assert_eq!(before, 2);
    assert_eq!(desk.connector.calls(), 1);
    assert_eq!(desk.app.approvals().pending().await.unwrap().len(), 2);
    let server = desk.serve().await;

    let response = start_playbook(&server.http, &desk.incident, "live", ROOT_TOKEN).await;

    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    let steps = report["run"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0]["action"], "block_ip");
    assert!(
        steps[0]["result"]["dispatched"]["pending_approval"].is_object(),
        "{}",
        steps[0]
    );
    assert_eq!(steps[1]["action"], "notify");
    assert_eq!(
        steps[1]["result"]["dispatched"]["executed"]["status"],
        "succeeded"
    );
    let requests = playbook_requests(&desk.app);
    assert_eq!(requests.len(), before + 2);
    assert!(requests[before..].iter().all(|request| !request.dry_run));
    assert_eq!(desk.app.approvals().pending().await.unwrap().len(), 3);
    let executed = desk.connector.executed();
    assert_eq!(executed.len(), 2);
    assert_eq!(executed[1].kind, ActionKind::Notify);
    assert!(!executed[1].dry_run);

    // With the mode `dry_run` in the request, the same playbook changes nothing.
    let response = start_playbook(&server.http, &desk.incident, "dry_run", ROOT_TOKEN).await;
    assert_eq!(response.status(), 200);
    let requests = playbook_requests(&desk.app);
    assert_eq!(requests.len(), before + 4);
    assert!(requests[before + 2..].iter().all(|request| request.dry_run));
    assert_eq!(desk.app.approvals().pending().await.unwrap().len(), 3);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_request_does_not_stop_a_playbook_action_in_the_middle() {
    let desk = Desk::new(TestConnector::new(), |text| {
        playbook_mode(&text, "dry_run") + "\n[api.limits]\nrequest_timeout_seconds = 1\n"
    })
    .await;
    // The application ran the playbook for the incident before: two dry runs.
    let before = playbook_requests(&desk.app).len();
    assert_eq!(before, 2);
    assert_eq!(desk.connector.calls(), 2);
    let server = desk.serve().await;

    // The connector does not answer the first action. The request ends at the time limit.
    desk.connector.hold();
    let response = start_playbook(&server.http, &desk.incident, "dry_run", ROOT_TOKEN).await;
    assert_eq!(Http::refused(response, 504).await, "timeout");
    desk.connector.entered(3).await;
    assert_eq!(playbook_requests(&desk.app).len(), before);

    // The connector answers. The action that was in progress completes with its records.
    // The playbook does not continue with its second step.
    desk.connector.release();
    let reached = desk
        .app
        .wait_until(WAIT, || {
            let app = desk.app.clone();
            async move { playbook_requests(&app).len() > before }
        })
        .await;
    assert!(reached.is_ok(), "the action did not complete");
    server.stop().await;
    let requests = playbook_requests(&desk.app);
    assert_eq!(requests.len(), before + 1);
    let request = &requests[before];
    assert_eq!(request.kind, ActionKind::BlockIp);
    assert!(request.dry_run);
    let record = desk.app.actions().get(request.id).unwrap();
    let DispatchResult::Disposition(ActionDisposition::Executed(outcome)) = &record.result else {
        panic!("the journal must have the result: {:?}", record.result);
    };
    assert_eq!(outcome.status, ActionStatus::Simulated);
    // Each record of the dispatcher for one request links to the request.
    let wanted = request.id.to_string();
    let kinds: Vec<AuditKind> = desk
        .app
        .audit()
        .read(1, 100_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|record| {
            record
                .evidence
                .iter()
                .any(|link| link.kind == EvidenceKind::Action && link.id == wanted)
        })
        .map(|record| record.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            AuditKind::ActionProposed,
            AuditKind::PolicyDecision,
            AuditKind::ActionExecuted
        ]
    );
    assert_eq!(desk.connector.calls(), 3);
    assert!(desk.app.audit().verify().await.unwrap().valid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_service_stops_with_the_error_of_a_server_that_fails() {
    let starter = Starter::new();
    let config = live_config(&starter, |text| text);
    let app = Arc::new(starter.build(&config, |builder| builder).await);

    // The secrets are there for the check, and they are gone when the server starts.
    let present = Arc::new(AtomicBool::new(true));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = OperatorApi::new(&app)
        .unwrap()
        .with_env({
            let present = present.clone();
            move |name| present.load(Ordering::SeqCst).then(|| env(name)).flatten()
        })
        .on_listener(listener)
        .unwrap();
    present.store(false, Ordering::SeqCst);

    let shutdown = Shutdown::new();
    let options = RunOptions {
        stop_when_sources_end: false,
        services: vec![api.into_service()],
    };
    let error = tokio::time::timeout(WAIT, app.run_with(shutdown.clone(), options))
        .await
        .expect("the application did not stop after the server failed")
        .unwrap_err();

    assert!(
        matches!(&error, Error::Config(message)
            if message == "the section `api` is not valid: principal alice@example.com: the \
                environment variable AEGIS_TEST_TOKEN_ALICE is not set"),
        "{error:?}"
    );
    // Each other component stopped. The signal of the caller is not changed.
    assert_eq!(app.agents().unwrap().state(), RuntimeState::Idle);
    assert!(!shutdown.is_triggered());
}

#[tokio::test]
async fn the_operator_api_needs_its_section_its_secrets_and_an_agent() {
    // No `[api]` section.
    let starter = Starter::new();
    let app = Arc::new(starter.app().await);
    let error = OperatorApi::new(&app).err().unwrap();
    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with("the section `api` is missing: the operator API needs it.")),
        "{error:?}"
    );
    drop(app);

    // No agent: the module set has only the detection and the API.
    let starter = Starter::new();
    let config = starter
        .config_with(|text| with_modules(&text, &["ingest", "detection", "api"]) + API_SECTION);
    let app = Arc::new(starter.build(&config, |builder| builder).await);
    assert!(app.agents().is_none());
    let error = OperatorApi::new(&app).err().unwrap();
    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with("the section `modules` is not valid: the module `api` needs \
                the agent runtime, and no agent is enabled.")),
        "{error:?}"
    );
    assert_eq!(
        app.settings().check_api_module().unwrap_err().to_string(),
        error.to_string()
    );
    drop(app);

    // A secret that is not set, and a secret that is too short. No message has a token.
    let starter = Starter::new();
    let app = Arc::new(
        starter
            .build(&live_config(&starter, |text| text), |b| b)
            .await,
    );
    assert!(app.settings().check_api_module().is_ok());
    let unset = OperatorApi::new(&app).unwrap().with_env(|_| None);
    let error = unset.check().unwrap_err();
    assert!(
        matches!(&error, Error::Config(message)
            if message == "the section `api` is not valid: principal alice@example.com: the \
                environment variable AEGIS_TEST_TOKEN_ALICE is not set"),
        "{error:?}"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(matches!(
        unset.on_listener(listener).err(),
        Some(Error::Config(_))
    ));
    let short = OperatorApi::new(&app)
        .unwrap()
        .with_env(|name| env(name).map(|token| token[..12].to_owned()));
    let error = short.check().unwrap_err();
    assert!(
        matches!(&error, Error::Config(message)
            if message == "the section `api` is not valid: principal alice@example.com: the \
                token in AEGIS_TEST_TOKEN_ALICE must have 32 characters or more"),
        "{error:?}"
    );
    assert!(
        OperatorApi::new(&app)
            .unwrap()
            .with_env(env)
            .check()
            .is_ok()
    );
}

#[tokio::test]
async fn bind_opens_the_address_of_the_section_and_reports_an_address_in_use() {
    // The operating system selects a free port for `api.bind`.
    let starter = Starter::new();
    let any_port = |text: String| replace_once(&text, "127.0.0.1:9443", "127.0.0.1:0");
    let app = Arc::new(starter.build(&live_config(&starter, any_port), |b| b).await);
    let bound = OperatorApi::new(&app)
        .unwrap()
        .with_env(env)
        .bind()
        .await
        .unwrap();
    let address = bound.local_addr();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let shutdown = Shutdown::new();
    let server = tokio::spawn(bound.serve(shutdown.clone()));
    let http = Http::new(address);
    assert_eq!(http.get("/healthz", None).await.status(), 200);

    // A second server on the same address cannot start.
    let second = Starter::new();
    let same_port = |text: String| replace_once(&text, "127.0.0.1:9443", &address.to_string());
    let other = Arc::new(second.build(&live_config(&second, same_port), |b| b).await);
    let error = OperatorApi::new(&other)
        .unwrap()
        .with_env(env)
        .bind()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.starts_with(&format!("[api] the operator API cannot listen on {address}: "))),
        "{error:?}"
    );

    shutdown.trigger();
    tokio::time::timeout(WAIT, server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn the_example_of_the_starter_configuration_gives_a_working_api() {
    // Remove the comment mark from the `[api]` example, and add the module.
    let starter = Starter::new();
    let config = starter.config_with(|text| {
        let (before, example) = text.split_once("# [api]\n").unwrap();
        let example: String = std::iter::once("[api]")
            .chain(example.lines().map(|line| {
                line.strip_prefix("# ")
                    .or_else(|| line.strip_prefix('#'))
                    .expect("each line of the example is a comment")
            }))
            .flat_map(|line| [line, "\n"])
            .collect();
        replace_once(
            &format!("{before}{example}"),
            "\"reporter\"]",
            "\"reporter\", \"api\"]",
        )
    });
    let app = Arc::new(starter.build(&config, |builder| builder).await);
    let section = app.settings().api.clone().unwrap();
    assert_eq!(section.bind.to_string(), "127.0.0.1:8080");
    assert_eq!(section.principals.len(), 1);
    let principal = &section.principals[0];
    let variable = principal.token_env.clone().unwrap();
    // Each role of the example is a role of the `[rbac]` section.
    assert!(!principal.roles.is_empty());
    for role in &principal.roles {
        assert!(app.settings().rbac.roles.contains_key(role), "{role}");
    }
    assert!(app.settings().check_api_module().is_ok());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = OperatorApi::new(&app)
        .unwrap()
        .with_env(move |name| (name == variable).then(|| ALICE_TOKEN.to_owned()))
        .on_listener(listener)
        .unwrap();
    let http = Http::new(api.local_addr());
    let shutdown = Shutdown::new();
    let server = tokio::spawn(api.serve(shutdown.clone()));

    let session = http.json("/api/v1/session", ALICE_TOKEN).await;
    assert_eq!(session["principal"]["id"], principal.id.as_str());
    assert_eq!(
        session["permissions"],
        json!(["view_incidents", "view_audit", "approve_actions"])
    );
    let refused = http.get("/api/v1/session", None).await;
    assert_eq!(refused.status(), 401);

    shutdown.trigger();
    tokio::time::timeout(WAIT, server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

/// The path of the gRPC call that decides an approval request.
const GRPC_DECIDE: &str = "/aegis.v1.ApprovalService/Decide";

#[cfg(not(feature = "grpc"))]
#[tokio::test]
async fn a_build_without_the_grpc_feature_has_no_grpc_service() {
    let desk = Desk::new(TestConnector::new(), |text| text).await;
    let server = desk.serve().await;

    let response = server
        .http
        .post(GRPC_DECIDE, Some(ALICE_TOKEN), &json!({}))
        .await;

    assert_eq!(Http::refused(response, 404).await, "not_found");
    assert_eq!(desk.connector.calls(), 0);
    server.stop().await;
}

#[cfg(feature = "grpc")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_through_grpc_runs_the_action_one_time() {
    use aegis_api::grpc::proto;
    use prost::Message as _;

    /// The gRPC status codes of the test.
    const FAILED_PRECONDITION: &str = "9";
    const UNAUTHENTICATED: &str = "16";

    let desk = Desk::new(TestConnector::new(), |text| text).await;
    let server = desk.serve().await;
    // gRPC with no TLS uses HTTP/2 from the first byte.
    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let decide = |token: Option<&'static str>| {
        let message = proto::DecideRequest {
            id: desk.approval.id.to_string(),
            approve: true,
            note: None,
        }
        .encode_to_vec();
        // One gRPC frame: no compression, the length, and the message.
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&message);
        let request = client
            .post(server.http.url(GRPC_DECIDE))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(frame);
        Http::send(request, token)
    };
    // The status of a refused call is in the headers.
    let status = |response: &reqwest::Response| {
        response
            .headers()
            .get("grpc-status")
            .map(|value| value.to_str().unwrap().to_owned())
    };

    // No token: the call is refused, and nothing runs.
    let refused = decide(None).await;
    assert_eq!(status(&refused).as_deref(), Some(UNAUTHENTICATED));
    assert_eq!(desk.connector.calls(), 0);

    let response = decide(Some(ALICE_TOKEN)).await;

    assert_eq!(response.status(), 200);
    assert_eq!(status(&response), None);
    let body = response.bytes().await.unwrap();
    assert!(body.len() > 5, "{}", body.len());
    let answer = proto::DecideResponse::decode(&body[5..]).unwrap();
    let request = answer.request.unwrap();
    assert_eq!(request.id, desk.approval.id.to_string());
    assert_eq!(request.decided_by.as_deref(), Some("alice@example.com"));
    let Some(proto::action_disposition::Result::Executed(outcome)) = answer
        .disposition
        .and_then(|disposition| disposition.result)
    else {
        panic!("the action must run");
    };
    assert_eq!(outcome.action_id, desk.approval.action.id.to_string());
    assert_eq!(outcome.connector, "recorder");

    // The action ran one time through the dispatcher, and the Responder got the result.
    let executed = desk.connector.executed();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].id, desk.approval.action.id);
    assert!(!executed[0].dry_run);
    assert_eq!(desk.stored().await.status, IncidentStatus::Contained);

    // A second decision is refused.
    let again = decide(Some(ALICE_TOKEN)).await;
    assert_eq!(status(&again).as_deref(), Some(FAILED_PRECONDITION));
    assert_eq!(desk.connector.calls(), 1);
    server.stop().await;
}
