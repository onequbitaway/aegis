# aegis-app

`aegis-app` is the composition root of AEGIS. It builds all subsystems of one process from
one configuration document, connects them, and runs them.

Each subsystem crate knows only the contracts of `aegis-contracts`. The connections between
the subsystems are in this crate. The crate has no detection logic, no agent logic, and no
connector for a vendor system. It is defensive only: it has no function that acts on a
system that the operator does not own.

## Contents

- [Public API](#public-api)
- [Use the crate](#use-the-crate)
- [The two run modes](#the-two-run-modes)
- [The connections between the subsystems](#the-connections-between-the-subsystems)
- [The operator API](#the-operator-api)
- [Configuration](#configuration)
- [Safe defaults](#safe-defaults)
- [Cargo features](#cargo-features)
- [Test the crate](#test-the-crate)
- [Limits](#limits)

## Public API

| Item | Function |
| --- | --- |
| `App::build(&Config)` | Builds all subsystems. A relative path starts at the working directory. |
| `App::builder(&Config)` | The same, with the options of `AppBuilder`. |
| `App::run(shutdown)`, `App::run_with(shutdown, RunOptions)` | The service. It runs until the shutdown signal. |
| `App::replay(events)` | Examines a list of events in the process. Returns a `ReplayReport`. |
| `App::decide_approval(id, approve, &principal, note)` | Records the decision of a person. Runs an approved action one time. |
| `App::reload()`, `App::reload_by(&principal)` | Loads the rule pack, the policy, and the playbooks again. |
| `App::wait_until(limit, condition)` | Waits for a state of the application. It uses no sleep. |
| `App::progress()` | The counts of the bridges: events, detections, incident changes, playbook runs. |
| `App::close()` | Closes the database connections. |
| `preflight(&Config, base_dir, extra_sections)` | Returns all problems of a configuration. Opens no connection and writes no file. |
| `settings::Settings` | The sections of the configuration document. `Settings::read` returns all problems. |
| `Settings::check_api_module()` | Checks that the build and the settings can run the module `api`. |
| `api::service(&app)` | Makes the `Service` of the operator API for `run_with`. Cargo feature `api`. |
| `api::OperatorApi`, `api::BoundApi` | The operator API of one application, before and after it has a listener. |
| `api::AppApprovals` | The approval path of the API: an `aegis_api::ApprovalActions` that calls the application. |
| `starter::write(dir)`, `starter::attack_events()` | The starter directory and the recorded attack log. The crate embeds them at compile time. |
| `incidents::SharedIncidents` | The incident store for the detection engine and the agents. |
| `actions::ActionJournal`, `actions::ActionRecord` | The single dispatcher of the process, with a journal of its requests. |
| `actions::SimulationConnector` | Reports a dry run for an action type that has no configured connector. |
| `audit::PublishingAuditLog` | Publishes each sealed audit record on `aegis.audit`. |
| `offline::OfflineModel` | The model provider of a process that has no model. |
| `playbooks::Playbooks` | The active playbooks and their reload. |
| `activity::Activity` | A signal that changes at each change of the state of the application. |
| `report::{ReplayReport, RunSummary, ApprovalOutcome, ReloadReport}` | The reports. Each implements `serde::Serialize`. |
| `Service`, `RunOptions` | One more long-running component for `run_with`, for example an operator API. |

`App` gives each service through an accessor: `bus`, `graph`, `vectors`, `incidents`,
`audit`, `approvals`, `models`, `policy`, `rbac`, `approval_service`, `dispatcher`,
`actions`, `action_registry`, `playbooks`, `engine`, `agents`, `sources`, `honeytokens`,
`rotated_secrets`, `modules`, and `settings`.

`AppBuilder` has these options:

| Option | Effect |
| --- | --- |
| `base_dir(dir)` | The directory that relative paths of the configuration start at. |
| `allow_section(name)` | Permits a section that a different component reads. With `api`, the application does not read `[api]`. |
| `modules(set)` | Replaces the module set of the configuration. |
| `model(provider)` | Replaces the model of the configuration. |
| `action_connector(connector)` | Adds an action connector. It has priority over the configured connectors. |
| `source(connector)`, `without_configured_sources()` | Adds a source connector. Ignores the `[[sources]]` of the configuration. |
| `force_dry_run()` | Makes each action a dry run, also when the configuration permits changes. |
| `audit_file(path)` | Writes the audit log to a different file. |
| `local_session(audit_file)` | Uses the in-process bus, the in-memory storage, and an audit file of the session. |

## Use the crate

```rust,no_run
use aegis_app::{App, starter};
use aegis_core::{Config, Shutdown};

# async fn example() -> aegis_contracts::Result<()> {
// Write a working starter directory, and build the application from it.
let directory = std::path::Path::new("/var/lib/aegis-starter");
starter::write(directory)?;
let config = Config::load_with_env(directory.join(starter::CONFIG_FILE))?;
let app = App::builder(&config).base_dir(directory).build().await?;

// Run the service until SIGINT or SIGTERM.
let shutdown = Shutdown::new();
shutdown.listen_for_signals()?;
app.run(shutdown).await?;
app.close().await;
# Ok(())
# }
```

## The two run modes

### `App::run`: the service

`run` starts these components for the modules in the module set:

| Module | Component |
| --- | --- |
| `ingest` | One `IngestRunner` for each source. |
| `detection` | The bus runner of the detection engine, with the bridges. |
| `monitor`, `hunter`, `analyst`, `responder`, `deception`, `reporter` | The agent runtime. It reads incidents and tasks from the bus. |
| `responder` | The playbook worker, if `response.playbooks` is not `off`. |
| `api` | The operator API. `run_with` gets its `Service` from `api::service`. |

- At the start, `run` writes one `config_change` audit record and gives the goal of the
  operator to the Supervisor agent.
- After the shutdown signal, each component completes the work that is in progress.
- If one component fails, `run` stops all components and returns the error of the component
  that failed first. The shutdown signal of the caller stays as it is.
- One run or one replay is possible at a time. A second call is `Error::InvalidInput`.
- The module `api` needs a `Service` in the options of `run_with`. Make it with
  `api::service(&app)`. Without that service, a module set with `api` is `Error::Config`.
  Refer to [The operator API](#the-operator-api).

`RunOptions::stop_when_sources_end` stops the run when all sources are at their end and the
detection engine completed their events. Use it for a session on recorded events.

### `App::replay`: a run in the process

`replay` examines a list of events with no source connector. The result is the same each
time for the same events and the same configuration. For each event, the steps are:

1. The detection engine examines the event.
2. The bridge records each detection and writes each incident state to the store.
3. The agents work until their queue is empty.
4. The matching playbooks run.

The `ReplayReport` has the detections, the incidents in their last state from the store,
each action request with its result, each playbook run, and the result of the check of the
audit chain.

## The connections between the subsystems

**Engine output to the store.** The correlator makes each incident with the state `open`,
and it sends the full incident again for each new detection. `SharedIncidents::merge_engine`
writes that state with these rules:

- The stored state stays. One exception: the correlator sets `resolved` when it merges an
  incident into a different one, and an incident that is not closed then becomes
  `resolved`.
- The stored summary stays if an agent wrote it.
- The timeline entries, the detections, the entities, and the techniques that only the
  store has stay. The larger severity stays.
- The detections, the entities, the techniques, the title, and the times come from the
  engine.

A save of an agent also never removes a detection, an entity, a technique, or a timeline
entry that the store has. Thus an agent that saves an old copy does not remove a detection
that came during its work. Writes run one at a time.

When an incident becomes `resolved` or `false_positive`, the store calls
`DetectionEngine::forget_incident`. A later detection then starts a new incident.

**The bus has the stored state.** The bridge publishes the stored state of an incident on
`aegis.incidents`, not the state of the engine. A subscriber thus never sees a state that
moves an incident back to `open`.

**Incidents to the agents.** In `replay`, the bridge calls `AgentRuntime::submit_incident`.
In `run`, the agent runtime reads the stored state from `aegis.incidents`.

The Monitor agent gives an incident to the Analyst when the incident store did not have the
data before, or when the incident is `open`. The bridge writes the store first, so the
Monitor finds no new data. For an incident that is not `open` and has a new detection, the
bridge thus gives the incident directly to the Analyst.

**Events to the Monitor.** The events that caused a detection go to the Monitor agent as
`AgentInput::Event` tasks. The Monitor writes the identities and the addresses to the
Defensive Graph. The bridge keeps the last 1024 events for this, and sends at most 16
events for one detection. `agents.monitor_events` selects `detected`, `all`, or `none`.

**Playbooks.** For an incident that is `open` or `investigating` and has a new detection,
each matching playbook runs one time. The playbooks and the agents send each action through
one `Dispatcher`.

**Approvals.** `decide_approval` calls the `ApprovalService`. For an approval, it calls
`Dispatcher::resume`. Then the agent that proposed the action gets the result as an
`AgentInput::ActionResult` task with the identifier of the action. For a rejection, the
agent gets a denial with the policy name `aegis.approval.rejected`, so that the agent does
not wait and does not propose the action again.

**Live audit feed.** `PublishingAuditLog` appends a record and then publishes the sealed
record on `aegis.audit`. A publish failure does not fail the append and does not remove the
record.

**Audit records of the bridge.** The bridge writes one `detection` record for each
detection, one `incident` record for each change of an incident, and one record for each
playbook run.

**Honeytokens.** The `HoneytokenConnector` of the action registry and the
`HoneytokenTripDetector` of the detection engine use one `HoneytokenRegistry`.

**Durable names.** Each bus subscriber has its own durable name: the detection runner
(`detection.runner.durable_name`), the two subscriptions of the agent runtime
(`agents.bus_consumer` with `-tasks` and `-incidents`), and the two subscriptions of the
notification task of the operator API (`api.chatops.notifications.durable_consumer` with
`-approvals` and `-incidents`). A configuration that gives two of them one name is an
error. The bridges and the live feed of the API use no durable name.

**Simulation connector.** A dispatcher needs a connector also for a dry run. With
`response.dry_run = true`, the action registry gets the `simulation` connector last. It
reports what a dry run would do for an action type that has no configured connector. It
refuses each request that is not a dry run.

## The operator API

The module `api` (Cargo feature `api`) joins `aegis-api` to the services of the
application: the REST API, the web console, ChatOps, and, with the Cargo feature `grpc`,
the gRPC services. Refer to the README of `aegis-api` for the routes and for the keys of
the `[api]` section.

```rust,no_run
# #[cfg(feature = "api")]
# async fn example() -> aegis_contracts::Result<()> {
use std::sync::Arc;

use aegis_app::{App, RunOptions, api};
use aegis_core::{Config, Shutdown};

let config = Config::load_with_env("aegis.toml")?;
let app = Arc::new(App::build(&config).await?);

let shutdown = Shutdown::new();
shutdown.listen_for_signals()?;
let options = RunOptions {
    stop_when_sources_end: false,
    // The function reads the secrets and opens the listener on `api.bind`.
    services: vec![api::service(&app).await?],
};
app.run_with(shutdown, options).await?;
# Ok(())
# }
```

The server runs as one component of `run_with`. It stops on the shutdown signal of the
run. If the server fails, the run stops all components and returns the error.

### The services of the API

| Part of `aegis_api::ApiParts` | Service of the application |
| --- | --- |
| `incidents`, `graph`, `audit`, `approvals`, `bus` | `App::incidents`, `graph`, `audit`, `approvals`, `bus` |
| `rbac` | The `[rbac]` section. The roles of an API principal are roles of this section. |
| `agents` | `App::agents` |
| `playbooks` | A copy of the active playbooks. Refer to [Playbooks through the API](#playbooks-through-the-api). |
| `approval_actions` | `api::AppApprovals` |
| `modules` | `App::modules` |

### Rules at the start

The API fails closed. Each of these conditions is an `Error::Config` before the server
starts. `Settings::check_api_module`, `preflight`, and `api::OperatorApi` check them.

- The module `api` is in the module set, and the build does not have the Cargo feature
  `api`.
- The configuration has no `[api]` section. The API has no default principal and no open
  mode.
- A value of the `[api]` section is not valid. For example, the address is not a loopback
  address, and `allow_non_loopback` is not `true`.
- `api.chatops.notifications.durable_consumer` gives a durable name that the agent runtime
  or the detection runner has. Each bus subscriber has its own durable name.
- An environment variable that the section names is not set, or its token is not usable.
  `OperatorApi::check` reads the secrets. The message names the variable and never shows a
  secret.
- The process runs no agent. The API shows and drives the agent runtime, so a module set
  with `api` needs one agent module or more, for example `monitor`.

`OperatorApi::bind` opens the listener before the run starts. An address that is in use is
thus an `Error::Unavailable` before the application starts its sources.

### Decisions through the API

A decision from REST, the console, Slack, Teams, or gRPC goes to `api::AppApprovals`. It
does the steps of `App::decide_approval`: the approval service checks the permission and
the approval rules, writes the audit record, and records the decision. For an approval,
the dispatcher runs the action one time, and the agent that proposed the action gets the
result.

- **The steps run in a task of their own.** The API has a time limit for each request, and
  a client can close its connection. The task completes also when the request is gone, so
  a decision is never half-applied. The audit log and the incident have the result.
- **After the record of the decision, the answer is the decided request.** If the approved
  action does not run, the answer has a disposition with the status `failed` and the
  cause. The API does not answer with an error for a decision that took effect. One
  approval permits one attempt.
- **The shutdown waits.** The server stops only when each decision that started is
  complete. The time limit of one connector call is `response.execution_timeout_seconds`.

### Playbooks through the API

`response.playbooks` is the limit for a playbook that a principal starts through the API:

| `response.playbooks` | The API |
| --- | --- |
| `off` | Has no playbook. A run is a 404. |
| `dry_run` | Lists the playbooks. Each run is a dry run, also when the request asks for `live`. |
| `live` | Lists the playbooks. The request selects `dry_run` or `live`. |

- `response.dry_run` makes each action a dry run in all three modes.
- Each action of a run goes through the dispatcher in a task of its own. A request that
  goes away stops the playbook between two actions, never in the middle of one.
- A run through the API does not use the rule "one playbook runs one time for one
  incident". The principal selects the playbook and the incident.

## Configuration

One TOML document holds the sections of all subsystems. Each subsystem crate defines the
type of its section. Refer to the README of that crate for the keys.

| Section | Type | Necessary |
| --- | --- | --- |
| `[modules]` | `aegis_core::ModuleSet` | No |
| `[telemetry]` | `aegis_core::TelemetryConfig` | No |
| `[bus]` | `aegis_bus::BusConfig` | Yes |
| `[storage]` | `kind = "memory"`, or `kind = "postgres"` with the keys of `aegis_storage::StorageConfig` | Yes |
| `[audit]` | `kind = "file"` (the default) with `path`, or `kind = "postgres"` | Yes |
| `[model]` | `aegis_model::ModelConfig` | No |
| `[policy]` | `aegis_policy::PolicyConfig` | Yes |
| `[rbac]` | `aegis_policy::RbacConfig` | No |
| `[approval]` | `aegis_policy::ApprovalRules` | No |
| `[detection]` | `pack`, the keys of `aegis_detect::EngineConfig`, and `runner` (`BusRunnerConfig`) | Yes |
| `[agents]` | `goal`, `monitor_events`, and the keys of `aegis_agents::RuntimeConfig` | No |
| `[response]` | The keys in the table below | No |
| `[[sources]]` | A list of `aegis_ingest::SourceConfig` | No |
| `[ingest]` | `checkpoint_dir` and `retry` (`aegis_ingest::RetryPolicy`) | No |
| `[plugins]` | `dir` and `limits` | No |
| `[api]` | `aegis_api::ApiConfig` | Only with the module `api` |

A section name that is not in this table is an error. Each section rejects a key that it
does not know. A section that is missing or not valid is an `Error::Config` that names the
section, and the build stops. No error message contains a value of a section.

A relative path starts at the base directory. `App::build` uses the working directory of
the process. The command-line program uses the directory of the configuration file.

### `[response]`

| Key | Default | Meaning |
| --- | --- | --- |
| `dry_run` | `true` | The dispatcher sets `dry_run` on each request. No connector changes anything. |
| `simulate_missing_connectors` | `true` | With `dry_run`, an action type that has no connector goes to the simulation connector. |
| `playbooks` | `"dry_run"` | How the playbooks run: `off`, `dry_run`, or `live`. |
| `playbook_dir` | Not set | The directory of the playbooks. |
| `graph` | Not set | `aegis_respond::GraphConfig`: the Microsoft Graph connector. |
| `webhook` | Not set | `aegis_respond::WebhookConfig`: the webhook connector. |
| `routes` | Empty | A list of `aegis_respond::Route`: the connector for an action type. |
| `environment` | Not set | A table that the policy reads as `input.environment`. |
| `execution_timeout_seconds` | `120` | The maximum time for one connector call. |

A connector that comes first has priority for an action type with no route. The order is:
the connectors of `AppBuilder::action_connector`, `graph`, `webhook`, the action plugins,
the honeytoken connector, and the simulation connector.

### `[agents]`

| Key | Default | Meaning |
| --- | --- | --- |
| `goal` | `Keep the environment of the operator safe.` | The goal of the operator, in natural language. |
| `monitor_events` | `"detected"` | The events that the Monitor agent gets: `detected`, `all`, or `none`. |

All other keys are the keys of `aegis_agents::RuntimeConfig`, for example `dry_run`. The
module set selects the agent roles: a role runs only if its module is in `[modules]`. The
Supervisor runs when one agent module or more is in the set.

### `[plugins]`

| Key | Meaning |
| --- | --- |
| `dir` | The directory of the plugin manifests. |
| `limits.max_memory_bytes`, `limits.call_timeout_seconds`, `limits.max_concurrent_calls`, `limits.http_timeout_seconds`, `limits.require_sha256` | Limits of the sandbox. The defaults are the defaults of `aegis_plugin::HostLimits`. |

A source plugin goes to the source registry. An action plugin goes to the action registry.

### Example

```toml
[modules]
enabled = ["ingest", "detection", "monitor", "analyst", "responder", "reporter"]

[bus]
kind = "memory"

[storage]
kind = "memory"

[audit]
kind = "file"
path = "data/audit.jsonl"

[policy]
paths = ["policies/default.rego"]

[detection]
pack = "detections/aegis-identity"

[response]
dry_run = true
playbooks = "dry_run"
playbook_dir = "playbooks"

[[sources]]
type = "file"
name = "replay"
path = "events.jsonl"
```

`starter::CONFIG` is a full starter configuration with comments. It has the `[api]`
section as a comment: the bind address and one principal with the name of its token
variable. The roles of that principal are roles of the `[rbac.roles]` table of the same
file.

## Safe defaults

- `response.dry_run`, `agents.dry_run`, and `response.playbooks = "dry_run"` are the
  defaults. With them, no action changes the environment of the operator.
- With no `[modules]` section, the process runs `ingest`, `detection`, and `monitor`.
- With no `[model]` section, the process uses `OfflineModel`. Each call returns
  `Error::Unavailable`, and the agents use their deterministic paths. Tier 2 of the
  detection engine does not run.
- With the default policy, a dry run is permitted and a gated action needs the approval of
  a person.
- With no `api` in `[modules]`, the process opens no listener. The starter configuration
  does not have the module.

## Cargo features

| Feature | Effect |
| --- | --- |
| `postgres` | `storage.kind = "postgres"` and `audit.kind = "postgres"` (`aegis-storage`). The build runs the migrations. |
| `plugins` | The `[plugins]` section (`aegis-plugin`). |
| `otlp` | The OpenTelemetry trace exporter of `aegis-core`. |
| `api` | The `[api]` section and the module `api` of this crate (`aegis-api`). |
| `grpc` | The gRPC services of the operator API. It includes `api`. It is not a default feature. |
| `docker-tests` | The tests that need Docker. |

`postgres`, `plugins`, `otlp`, and `api` are default features. With
`--no-default-features`, the crate builds a light process for monitoring, with no HTTP
server. A section or a module that needs a feature that the build does not have is an
`Error::Config`.

## Test the crate

Run these commands from the root of the repository:

```sh
cargo test -p aegis-app
cargo test -p aegis-app --no-default-features
cargo test -p aegis-app --all-features
```

The tests use no network outside the loopback address and no credentials. The model server
and the webhook receiver are `wiremock` servers. The tests of the operator API give the
tokens through `OperatorApi::with_env`. They do not change the environment of the process.

| Test file | Subject |
| --- | --- |
| `tests/replay.rs` | The end-to-end replay of the recorded attack log from the starter configuration. |
| `tests/model.rs` | A replay with a local OpenAI-compatible server, and with a server that fails. |
| `tests/approval.rs` | A gated action: approval, rejection, permissions, the webhook connector, a connector failure. |
| `tests/bridges.rs` | The state of an incident stays, closed incidents, events to the Monitor, the audit feed, action results, honeytokens. |
| `tests/service.rs` | `App::run` with a file source on the in-process bus, a monitoring session, a failed component. |
| `tests/api.rs` | The operator API of the running application on a loopback port: the tokens, the approval path, a request that goes away, the playbook modes, the live feed, the console, and the shutdown. |
| `tests/build.rs` | The build from a configuration, the builder options, and the reload. |
| `tests/plugins.rs` | The example plugins of the repository in the two registries. This test builds the plugins. |
| `tests/docker.rs` | A replay and a service run with PostgreSQL storage, the PostgreSQL audit log, and a NATS bus. The operator API then reads the same database and the same bus. |

The feature `docker-tests` needs Docker. `tests/docker.rs` builds the image
`aegis-test-postgres:test` from `deploy/docker/postgres`, and starts one PostgreSQL
container and one NATS container on free ports of the local host. Each container name
starts with `aegis-test-app-`. The test removes the containers.

## Limits

- The honeytoken registry and the receiver of rotated secrets are in memory. A honeytoken
  and a rotated secret do not continue after a restart. Move each rotated secret to your
  vault before the process stops.
- The bridge remembers in memory which playbook ran for which incident, and which engine
  summary it wrote. After a restart, a playbook can run a second time for an old incident,
  and the bridge keeps a stored summary that it cannot explain.
- The state of the detection engine is in memory. After a restart, the correlator starts
  an incident again with only the new detections. The store keeps the old detections.
- In `run`, the Analyst can get an incident with a new detection before the Monitor wrote
  that detection to the Defensive Graph. The tasks of one incident still run one at a time.
- `PublishingAuditLog` publishes each record before `append` returns. With a bus that does
  not answer, each append waits for the request timeout of the bus.
- If the audit log does not take the `config_change` record of a reload, `reload` returns
  the error, and the new rule pack, policy, and playbooks are active.
- The action journal keeps the last 10,000 requests in memory. The audit log is the durable
  record.
- The operator API needs the agent runtime. A process with no agent module cannot have
  the module `api`.
- The operator API has the playbook set of the time when `api::OperatorApi::new` ran. After
  `App::reload`, the API lists and runs the old set until the process starts again. The
  command-line program does not call `reload`.
- A principal cannot start a decision again through the API when its approved action did
  not run. The request then has a decision, and the API refuses a second one.
- When the shutdown waits for a decision, the agent runtime is possibly stopped. The
  result task of that decision then stays in the queue of the agents.
- `App::build` connects to the bus and to the database, runs the migrations, and opens the
  audit log. One process writes one audit file, so a second build with the same audit file
  is `Error::Unavailable` while the first application lives.
