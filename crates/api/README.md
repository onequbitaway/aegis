# aegis-api

`aegis-api` is the operator interface of AEGIS. It has four parts:

- **REST API.** JSON under `/api/v1`, with a live feed as server-sent events.
- **Web console.** Plain HTML, CSS, and JavaScript in the binary, at `/`.
- **ChatOps.** Slack and Microsoft Teams commands, buttons, and notifications.
- **gRPC.** Two services, with the Cargo feature `grpc`.

This crate is defensive only. It reads the state of AEGIS and sends the decisions of the
operator to the action path. It has no function that acts on a system that the operator
does not own.

The crate has no composition logic. `ApiState` holds the services. A test fills it with the
in-memory services of `aegis-testkit`. The composition root fills it with the real services.

## Contents

- [Public API](#public-api)
- [Use the crate](#use-the-crate)
- [Security](#security)
- [Configuration](#configuration)
- [REST routes](#rest-routes)
- [Errors](#errors)
- [Live feed](#live-feed)
- [Web console](#web-console)
- [ChatOps](#chatops)
- [gRPC](#grpc)
- [Test the crate](#test-the-crate)
- [Limits](#limits)

## Public API

| Item | Function |
| --- | --- |
| `ApiParts` | The services that make the state. All fields are public. |
| `ApiState::new(parts)` | Makes the state. Secrets come from the environment of the process. |
| `ApiState::with_env(lookup)` | Sets the function that reads an environment variable. Use it in a test. |
| `ApprovalActions`, `ApprovalDecision` | The path for approval decisions. The composition root implements the trait. |
| `RevertActions`, `ApiState::with_reverts(path)` | The path for timed reverts and for the revert of an action. The composition root implements the trait. |
| `StatusSource`, `SystemStatus`, `FloodStatus`, `ApiState::with_status(source)` | The data of the composition root for the status route: the flood counters and more fields. |
| `ApiConfig`, `PrincipalConfig`, `LimitsConfig` | The configuration. `ApiConfig::validate()` checks it. |
| `ChatOpsConfig`, `SlackConfig`, `TeamsConfig`, `NotificationConfig` | The ChatOps configuration. |
| `router(state, &config)` | Builds the `axum::Router`. Returns `Result`, because it reads the secrets. |
| `serve(state, config, shutdown)` | Listens on `config.bind` until the shutdown signal. |
| `serve_on(listener, state, config, shutdown)` | The same, on a listener that the caller made. |
| `route_permissions()` | Each REST route with the permissions that it needs. |
| `console_assets()` | The files of the web console. |
| `chatops::Notifier` | The notification task. `serve` runs it. A caller of `router` runs it itself. |
| `chatops::signature` | The signature functions of Slack and Teams. |
| `chatops::slack`, `chatops::teams` | The message formats. |
| `grpc::proto` | The generated gRPC types (feature `grpc`). |

### The approval path

The API never changes the approval queue. It calls this trait:

```rust
use aegis_api::ApprovalDecision;
use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::Principal;

#[async_trait::async_trait]
pub trait ApprovalActions: Send + Sync {
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> aegis_contracts::Result<ApprovalDecision>;
}
```

The implementation checks the approval rules, writes the audit record, records the
decision, and, for an approval, runs the action. `ApprovalDecision` holds the changed
`ApprovalRequest` and, for an approval, the `ActionDisposition` of the action. The REST
API, the gRPC API, and the ChatOps endpoints all use this one path.

### The revert path

The API never changes a pending revert itself. It calls the trait `RevertActions`:
`enabled`, `pending`, `confirm`, `extend`, `cancel`, and `revert`. The implementation
checks the permission again, writes each audit record with the principal, and sends each
revert through the dispatcher: the policy, the approval queue, and the audit log.

A state with no revert path has no timed revert. `GET /reverts` then answers with
`"enabled": false` and an empty list, and each other revert route answers with the status
501.

## Use the crate

This example runs. It uses the in-memory services of the test kit and sends one request to
the router.

```rust
use std::sync::Arc;

use aegis_agents::AgentRuntime;
use aegis_api::{ApiConfig, ApiParts, ApiState, ApprovalActions, ApprovalDecision, PrincipalConfig};
use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::{ApprovalQueue, Principal};
use aegis_core::ModuleSet;
use aegis_policy::{Permission, Rbac, RbacConfig};
use aegis_respond::PlaybookEngine;
use aegis_testkit::{DispatchMode, Harness, MemoryApprovals, RecordingDispatcher, ScriptedModel};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// The composition root has the real approval path. This one only records the decision.
struct RecordOnly(Arc<MemoryApprovals>);

#[async_trait::async_trait]
impl ApprovalActions for RecordOnly {
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> aegis_contracts::Result<ApprovalDecision> {
        let request = self.0.decide(id, approve, principal, note).await?;
        Ok(ApprovalDecision { request, disposition: None })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let harness = Harness::new(ScriptedModel::new("local"));
    let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
    let agents = AgentRuntime::builder(harness.context("Keep this tenant safe."), dispatcher.clone())
        .with_default_agents()
        .build()?;
    let approvals = Arc::new(MemoryApprovals::default());

    let state = ApiState::new(ApiParts {
        incidents: harness.incidents.clone(),
        graph: harness.graph.clone(),
        audit: harness.audit.clone(),
        approvals: approvals.clone(),
        bus: harness.bus.clone(),
        rbac: Rbac::new(RbacConfig::default().with_role("viewer", &[Permission::ViewIncidents])),
        agents: Arc::new(agents),
        playbooks: Arc::new(PlaybookEngine::new(dispatcher)),
        approval_actions: Arc::new(RecordOnly(approvals)),
        modules: ModuleSet::monitoring_only(),
    })
    // A program reads the real environment. A test gives the values.
    .with_env(|name| (name == "AEGIS_TOKEN_VERA").then(|| "0123456789abcdef0123456789abcdef".to_owned()));

    let config = ApiConfig {
        principals: vec![PrincipalConfig::human("vera@example.com", &["viewer"], "AEGIS_TOKEN_VERA")],
        ..ApiConfig::default()
    };
    let router = aegis_api::router(state, &config)?;

    let request = Request::get("/api/v1/incidents")
        .header("authorization", "Bearer 0123456789abcdef0123456789abcdef")
        .body(Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    // A request with no token is refused.
    let request = Request::get("/api/v1/incidents").body(Body::empty())?;
    assert_eq!(router.oneshot(request).await?.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
```

To run a server, call `serve`:

```rust,no_run
use aegis_api::{ApiConfig, ApiState};
use aegis_core::Shutdown;

async fn run(state: ApiState, config: ApiConfig) -> aegis_contracts::Result<()> {
    let shutdown = Shutdown::new();
    shutdown.listen_for_signals()?;
    aegis_api::serve(state, config, shutdown).await
}
```

On the shutdown signal, the server stops to accept connections, ends each live feed, lets
each open request complete, and stops the notification task.

## Security

- **Fail closed.** Each REST route but `GET /healthz` needs a bearer token of a configured
  principal and a permission. With no principals, each such route answers 401. There is no
  open mode.
- **Tokens.** A token has 32 visible ASCII characters or more. The server keeps only the
  SHA-256 digest of each token. It compares digests in constant time. Two principals cannot
  have the same token.
- **One access check.** `aegis_policy::Rbac` decides each permission, for REST, gRPC, and
  ChatOps. No permission includes a different permission.
- **The principal of a decision.** The principal of the token, or of the chat user, is the
  `Principal` that `ApprovalActions::decide` gets.
- **Signatures.** Each ChatOps request needs a valid HMAC-SHA256 signature. The server
  compares signatures in constant time and refuses a request that is older than five
  minutes.
- **Untrusted data.** Incident text, event text, and audit text can come from an attacker.
  The console shows it as text only. Each chat format escapes it.
- **Secrets.** The configuration holds the names of environment variables, never a secret.
  An error message names the variable and never shows its value. A webhook URL is a secret
  too: no error and no log line shows it.
- **Limits.** The request body size, the request time, the page size, and the number of
  live feeds have limits.
- **Headers.** Each response has `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, a
  `Content-Security-Policy`, and `Cache-Control: no-store` (console files: `no-cache`).
- **No CORS.** The server sends no `Access-Control-*` header. A page of a different origin
  cannot read the API.
- **No TLS in the server.** The default address is a loopback address. The server refuses a
  different address, unless you set `allow_non_loopback`. Then put a proxy with TLS before
  the server.

## Configuration

`ApiConfig` implements `serde::Deserialize`. Read it from one table of the AEGIS
configuration file. This example uses the table `api`. An unknown key is an error. All keys
are optional.

```rust
use aegis_api::ApiConfig;
use aegis_core::Config;

const FILE: &str = r#"
[api]
bind = "127.0.0.1:8080"          # The default.
allow_non_loopback = false       # Set true only behind a proxy with TLS.
console = true                   # Serve the web console at "/".

[[api.principals]]
id = "alice@example.com"
kind = "human"                   # "human" (default), "agent", or "system".
roles = ["approver"]             # The role names of the RBAC configuration.
token_env = "AEGIS_TOKEN_ALICE"  # The NAME of the variable that holds the token.

[[api.principals]]
id = "vera@example.com"          # No token: this person uses only the chat.
roles = ["viewer"]

[api.limits]
max_body_bytes = 65536           # 1 to 1048576.
request_timeout_seconds = 30     # 1 to 300.
default_page_size = 50
max_page_size = 200              # 1 to 1000.
max_streams = 32                 # Live feeds at the same time. 1 to 1024.
stream_keep_alive_seconds = 15

[api.chatops.slack]
signing_secret_env = "AEGIS_SLACK_SIGNING_SECRET"   # Turns the Slack endpoints on.
webhook_url_env = "AEGIS_SLACK_WEBHOOK_URL"         # Turns the Slack notifications on.
team_id = "T0123456"                                # Optional: only this workspace.
response_hosts = ["hooks.slack.com"]                # The default.

[api.chatops.slack.users]
U0ALICE = "alice@example.com"    # Slack user identifier = principal id.
U0VERA = "vera@example.com"

[api.chatops.teams]
shared_secret_env = "AEGIS_TEAMS_SECRET"            # Turns the Teams endpoint on.
webhook_url_env = "AEGIS_TEAMS_WEBHOOK_URL"         # Turns the Teams notifications on.
require_timestamp = true                            # The default.

[api.chatops.teams.users]
"9f0e1d2c-0000-4000-8000-000000000001" = "alice@example.com"   # from.aadObjectId or from.id.

[api.chatops.notifications]
min_severity = "medium"          # The default. Approval requests are always sent.
request_timeout_seconds = 10     # 1 to 60.
max_attempts = 3                 # 1 to 10.
retry_backoff_ms = 500           # 0 to 60000. Each later attempt waits two times longer.
"#;

fn main() -> aegis_contracts::Result<()> {
    let config: ApiConfig = Config::from_toml_str(FILE)?.section("api")?;
    config.validate()?;
    assert_eq!(config.principals.len(), 2);
    Ok(())
}
```

Rules:

- A principal `id` occurs one time only.
- A principal with `token_env` must have that variable set when the server starts. If not,
  `router` and `serve` return `Error::Config`.
- A chat user must map to a principal in `api.principals`.
- A webhook URL must use HTTPS. Only a loopback address can use HTTP.
- `durable_consumer` in `[api.chatops.notifications]` gives the notification task a durable
  bus consumer. Then the task continues after its last message when the process starts
  again. With no name, the task gets only new messages.

Make a token with a random generator, for example `openssl rand -hex 32`.

## REST routes

All paths but `/healthz` start with `/api/v1`. `route_permissions()` returns this table. One
of the listed permissions is sufficient.

| Method and path | Permission | Answer |
| --- | --- | --- |
| `GET /healthz` | None | `{"status":"ok"}` |
| `GET /session` | A valid token | `{"principal", "permissions"}` |
| `GET /status` | `view_incidents` | `{"version", "modules", "agents", "audit": {"head"}, "flood"}`, and the fields of the composition root |
| `GET /incidents?status=&limit=` | `view_incidents` | `{"items": [Incident]}`, newest first |
| `GET /incidents/{id}` | `view_incidents` | `Incident` |
| `GET /incidents/{id}/explanation` | `view_audit` | `{"subject", "records"}` from `aegis_policy::explain_incident` |
| `GET /actions/{id}/explanation` | `view_audit` | `{"subject", "records"}` from `aegis_policy::explain_action` |
| `GET /approvals?limit=` | `view_incidents` or `approve_actions` | `{"items": [ApprovalRequest], "total"}`, pending only, oldest first |
| `GET /approvals/{id}` | `view_incidents` or `approve_actions` | `ApprovalRequest` |
| `POST /approvals/{id}/decision` | `approve_actions` | `{"request", "disposition"}` |
| `GET /reverts?limit=` | `view_incidents` or `approve_actions` | `{"enabled", "items": [PendingRevert], "total"}`, earliest revert time first |
| `POST /reverts/{action_id}/confirm` | `approve_actions` | `{"revert": PendingRevert}`. The containment stays. |
| `POST /reverts/{action_id}/extend` | `approve_actions` | `{"revert": PendingRevert}` with the new revert time |
| `POST /reverts/{action_id}/cancel` | `approve_actions` | `{"disposition"}`. The revert runs now, through the policy. |
| `POST /actions/{id}/revert` | `approve_actions` | `{"disposition"}`. The revert of one action, with or without a revert time. |
| `GET /graph/nodes?kind=&limit=` | `view_incidents` | `{"items": [GraphNode]}`. `kind` is mandatory. |
| `GET /graph/nodes/{id}` | `view_incidents` | `GraphNode` |
| `GET /graph/nodes/{id}/neighbors?direction=&relation=&limit=` | `view_incidents` | `{"node", "items", "total"}`. The default direction is `both`. |
| `GET /audit?from_sequence=&limit=` | `view_audit` | `{"items": [AuditRecord], "next_sequence"}` |
| `GET /audit/verification` | `view_audit` | `ChainVerification` |
| `GET /agents?limit=` | `view_incidents` | The state, the counts, `roster`, and `recent_tasks` |
| `POST /goal` | `administer` | 202 and `{"task_id"}` |
| `GET /playbooks` | `view_incidents` or `run_playbooks` | `{"items": [Playbook]}` |
| `POST /playbooks/{name}/runs` | `run_playbooks` | `{"trigger_matched", "run"}` |
| `GET /stream` | `view_incidents` | Server-sent events |

Request bodies:

| Route | Body |
| --- | --- |
| `POST /approvals/{id}/decision` | `{"approve": true, "note": "optional text"}`. The note has 1000 characters or fewer. |
| `POST /reverts/{action_id}/confirm`, `POST /reverts/{action_id}/cancel` | `{}` |
| `POST /reverts/{action_id}/extend` | `{"seconds": 3600}`. The value is 1 or more. |
| `POST /actions/{id}/revert` | `{"reason": "text"}`. The reason has 1 to 1000 characters. |
| `POST /goal` | `{"text": "Keep this tenant safe."}`. The text has 4000 characters or fewer. |
| `POST /playbooks/{name}/runs` | `{"incident_id": "<uuid>", "mode": "dry_run"}`. `mode` is `dry_run` (default) or `live`. |

Notes:

- The types are the types of `aegis-contracts` in their JSON form.
- A body is one JSON object with the content type `application/json`. An unknown field is
  an error.
- A query parameter that the route does not know is an error. A parameter with no text is
  the same as no parameter. `limit` is from 1 to `max_page_size`.
- A node identifier in a path must be one path segment. Encode it, for example
  `ip_address%3A203.0.113.50`.
- `POST /goal` and `POST /playbooks/{name}/runs` write an audit record with the principal
  before they start the operation. If the audit log does not take the record, the
  operation does not start.
- A second decision on one approval request is a 409.
- `disposition` is `null` for a rejection.
- `GET /status` finds the last audit record with a small number of one-record reads. The
  `AuditLog` contract has no function for the last record.
- `GET /status` has the field `flood` only if the state has a `StatusSource`. The field
  holds `suppressed_matches`, `repeat_detections`, `triage_quota_denials`, and
  `coalesced_incident_updates`. The source can add more fields, for example `reverts`,
  `evidence`, and `decoy`. It cannot replace a field of the route.
- A revert route writes no audit record itself. The revert path writes each record with
  the principal before the change. If the audit log does not take the record, nothing
  changes.
- A revert is a request of its own. With a policy that requires approval, the answer of
  `cancel` or `revert` is a disposition with `pending_approval`. The action is not
  reverted until a second person approves.
- An action with no pending revert is a 404 for `confirm`, `extend`, and `cancel`.

## Errors

Each error is a JSON document:

```json
{ "error": { "code": "not_found", "message": "The incident does not exist." } }
```

| Status | `code` | Cause |
| --- | --- | --- |
| 400 | `invalid_input` | A bad identifier, query, or body. `Error::InvalidInput`. |
| 401 | `unauthorized` | No token, an unknown token, or a bad ChatOps signature. |
| 403 | `forbidden`, `denied` | The principal does not have the permission. `Error::Unauthorized`, `Error::Denied`. |
| 404 | `not_found` | An unknown identifier or path. `Error::NotFound`. |
| 405 | `method_not_allowed` | The method is not valid for the path. |
| 409 | `conflict` | The approval request already has a decision. |
| 413 | `payload_too_large` | The body is larger than `max_body_bytes`. |
| 415 | `unsupported_media_type` | The body has a different content type. |
| 429 | `rate_limited`, `budget_exceeded` | Too many live feeds. `Error::RateLimited`, `Error::BudgetExceeded`. |
| 500 | `internal`, `configuration`, `integrity` | `Error::Other`, `Error::Serialization`, `Error::Config`, `Error::Integrity`. |
| 501 | `unsupported` | `Error::Unsupported`. |
| 502 | `model_refused` | `Error::Refused`. |
| 503 | `unavailable` | `Error::Unavailable`. |
| 504 | `timeout` | The request took more time than the limit. `Error::Timeout`. |

The message of a server fault (500 and larger, and `rate_limited`) is fixed text. The cause
goes to the log only. The message of a caller fault from a different subsystem is one line
of 300 characters or fewer.

## Live feed

`GET /api/v1/stream` is a stream of server-sent events. The server subscribes to the bus
before it answers. The first event has the type `ready`.

| Event type | Bus subject | Also needs |
| --- | --- | --- |
| `detection` | `aegis.detections.>` | |
| `incident` | `aegis.incidents` | |
| `action_result` | `aegis.actions.results` | |
| `approval` | `aegis.approvals` | |
| `audit` | `aegis.audit` | `view_audit` |
| `ready` | None | The data lists the event types of this feed. |
| `error` | None | A bus subscription failed. The data is `{"code", "message"}`. |

The data of a bus event is `{"subject": "...", "payload": ...}`. The payload is the bus
payload. A bus message that is not JSON is not in the feed. The feed has only messages that
the bus gets after the feed opens. The sequence of two events with different types is not
always the sequence on the bus.

A browser `EventSource` cannot send the `Authorization` header. Read the feed with `fetch`.

## Web console

The console is at `/`. Its files are in the binary (`assets/`). It has no build step and it
makes no request to a different origin, so it works on a network with no internet.

| View | Contents |
| --- | --- |
| Incidents | The list with a state filter. The detail: the timeline, the entities, the ATT&CK techniques, the detections, and the audit records of the actions. |
| Activity | The agent runtime (state, counts, roster, last tasks) and the live feed. |
| Approvals | The pending requests. Approve or reject with a note. The pending timed reverts, with the buttons **Confirm the action** and **Revert now**. |
| Graph | Start at an incident, an entity, or a node identifier. Walk the neighbors in a list or in an SVG drawing. |
| Audit | The records, newest first, and the state of the hash chain. |

- Enter an API token at the top of the page. The console keeps it in `sessionStorage`. It
  is gone when the tab closes. The console uses no cookie.
- The console builds each element with `createElement` and sets each text with
  `textContent`. It never reads markup from a string.
- The policy is `default-src 'self'` with no inline script and no inline style.
- Each control works with the keyboard. The graph nodes take the focus, and Enter opens a
  node. The layout works at a width of 360 pixels.
- Set `console = false` to switch the console off.

To look at the console with sample data and no other service:

```sh
AEGIS_DEMO_TOKEN="$(openssl rand -hex 32)" cargo run -p aegis-api --example console_demo
```

## ChatOps

All parts are off until the configuration names their secret.

### Commands

| Command | Permission |
| --- | --- |
| `incidents` | `view_incidents` |
| `approvals` | `view_incidents` or `approve_actions` |
| `approve <id> [note]` | `approve_actions` |
| `reject <id> [note]` | `approve_actions` |
| `help` | None |

The configuration maps each chat user to a principal. An unknown user gets a refusal and
nothing changes. A known user then has the permissions of its principal. A decision uses
`ApprovalActions`, as the REST API does.

### Slack

| Endpoint | Slack setting |
| --- | --- |
| `POST /chatops/slack/commands` | The request URL of the slash command, for example `/aegis`. |
| `POST /chatops/slack/interactions` | The request URL of Interactivity. |

- The server checks `X-Slack-Signature` on each request: HMAC-SHA256 of
  `v0:{timestamp}:{body}` with the signing secret. A timestamp that is more than five
  minutes from the present time is refused. A refused request gets a 401.
- With `team_id`, a request from a different workspace is refused.
- The answer to a command is visible only to the person who sent it.
- A button sends its answer to the `response_url` of the interaction. The server calls
  only a host in `response_hosts`, and only with HTTPS.
- Slack waits three seconds for an answer. A slow action can show a timeout in Slack. The
  decision is recorded all the same. Send `approvals` to see the state.

### Microsoft Teams

`POST /chatops/teams/messages` is the URL of a Teams outgoing webhook.

- The server checks `Authorization: HMAC <base64>`: HMAC-SHA256 of the body with the
  security token of the webhook. Put the token, as Teams shows it, in the variable.
- The server refuses a message with no `timestamp`, or a `timestamp` that is more than five
  minutes from the present time. Set `require_timestamp = false` only if your client sends
  no timestamp.
- The sender is `from.aadObjectId` (the first choice) or `from.id`.
- The mention of the webhook (`<at>name</at>`) is not a part of the command.

### Notifications

`Notifier` subscribes to `aegis.approvals` and `aegis.incidents`. `serve` runs it when the
configuration has a webhook URL.

- A new approval request and each decision give one message.
- An incident gives one message when it is new, and one more when its state or its severity
  changes. An incident below `min_severity` gives no message.
- Slack gets a Block Kit message. A pending request has an approve button and a reject
  button, if the server has the Slack endpoints.
- Teams gets an Adaptive Card. A pending request shows the commands that decide it.
- A webhook fault (a network error, a 5xx, or a 429) is tried again, `max_attempts` times.
  A different refusal is not tried again. A message that is not delivered goes to the log.

### Untrusted text in chat

Text from an incident or an action goes into a message on one line with a length limit.

- **Slack:** only in `plain_text` objects, with `&`, `<`, and `>` as entities. The text
  cannot make a mention, a link, or a channel notification.
- **Teams:** `&`, `<`, and `>` as entities, and a backslash before each other ASCII
  punctuation character. The text cannot make a link, an image, a mention, or a tag.

## gRPC

Build with the feature `grpc`. The build needs no `protoc` program: `build.rs` compiles
`proto/aegis/v1/aegis.proto` with `protox`.

| Service | Calls |
| --- | --- |
| `aegis.v1.IncidentService` | `ListIncidents`, `GetIncident` |
| `aegis.v1.ApprovalService` | `ListPending`, `Decide` |

- `router` and `serve` serve gRPC on the same port as REST. A client uses HTTP/2 with prior
  knowledge on a connection with no TLS.
- Send the token in the metadata key `authorization`: `Bearer <token>`.
- The access rules and the approval path are those of the REST API.
- The module documentation of `grpc` shows the gRPC status for each REST error.

## Test the crate

Run these commands from the root of the repository:

```sh
cargo test -p aegis-api --all-features
cargo test -p aegis-api
cargo clippy -p aegis-api --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p aegis-api --no-deps
```

All tests are hermetic. They use the in-memory services of `aegis-testkit`. A test sends a
request to the router with `tower::ServiceExt::oneshot`, or it starts the server on a
loopback address. Chat webhooks are `wiremock` servers. No test uses a real Slack, a real
Teams, or Docker.

| Test file | Subject |
| --- | --- |
| `tests/api/access.rs` | 401 and 403 for each route of `route_permissions()`, and the session route. |
| `tests/api/incidents.rs`, `approvals.rs`, `graph.rs`, `system.rs` | Each route: the JSON form, 404, and 400. |
| `tests/api/reverts.rs` | The revert routes with the real scheduler and a paused clock: the list, confirm, extend, cancel, the revert of one action, 401, 403, and a state with no revert path. |
| `tests/api/stream.rs` | The live feed. |
| `tests/api/limits.rs` | The body limit, the time limit, and no CORS. |
| `tests/api/console.rs` | The page, the files, the policy, and no reference to a different origin. |
| `tests/api/slack.rs`, `teams.rs` | Signatures, users, commands, buttons, and escapes. |
| `tests/api/notifications.rs` | The JSON that the webhooks get. |
| `tests/api/serve.rs` | The server on a loopback address, and shutdown. |
| `tests/api/grpc.rs` | The gRPC services (feature `grpc`). |

The examples in this file are documentation tests. `cargo test` compiles and runs them.

## Limits

- The server has no TLS and no limit on the time that a client takes to send its request
  headers. Use it on a loopback address, or behind a proxy.
- The server has no rate limit for failed tokens. A token is long and random, so a search
  is not practical. A proxy can add a rate limit.
- A Slack request can be sent again in the five-minute window. A decision takes effect one
  time only, and the answer to a read command goes to the sender of the copy.
- The Teams card has no buttons. A button in Teams needs a bot registration. Use the
  commands.
- The live feed and the notification task do not get messages from before they started,
  unless the notification task has a `durable_consumer`.
- `GET /graph/nodes/{id}/neighbors` returns nodes. The `DefensiveGraph` contract does not
  return the relations, so the drawing shows no relation names.
