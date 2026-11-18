# aegis-agents

`aegis-agents` is the autonomous multi-agent runtime of AEGIS. A supervisor and six
specialized agents work on tasks. They share the Defensive Graph. They reason with a model
through the `ModelProvider` contract. They propose response actions.

This crate is defensive only. An agent analyzes data that AEGIS already has. An agent never
changes the environment of the operator. Only the `ActionDispatcher` can do that, under the
policy of the operator. No agent scans, probes, or attacks a system.

## Contents

- [The agents](#the-agents)
- [How an incident moves through the agents](#how-an-incident-moves-through-the-agents)
- [Use the runtime](#use-the-runtime)
- [Public API](#public-api)
- [Configuration](#configuration)
- [Guard rails](#guard-rails)
- [What the model can and cannot do](#what-the-model-can-and-cannot-do)
- [Bus subjects](#bus-subjects)
- [Graph data](#graph-data)
- [Test the crate](#test-the-crate)

## The agents

Each agent implements `aegis_contracts::Agent`.

| Agent | What it does | Model task | Without a model |
| --- | --- | --- | --- |
| Supervisor | Turns the goal of the operator into tasks. Gives new incidents to the Monitor. | `Planning` | The default plan: one task for the Monitor, the Hunter, and the Deception agent. |
| Monitor | Writes incidents, alerts, entities, and their relations to the Defensive Graph. Gives incidents to the Analyst. | None | Always deterministic. |
| Hunter | Hunts in the graph and the incident store. Records `Finding` nodes. | `Analysis`, with read-only tools | The deterministic hunts: shared address, privileged role, external exposure. |
| Analyst | Triages an incident. Sets the state, the summary, and the timeline. Gives true positives to the Responder. | `Analysis` | A deterministic detection with the verdict `malicious`, or a honeytoken trip, confirms the incident. Each other incident stays open. |
| Responder | Proposes containment actions. Records each result. Sets `Contained` when each action ran. | `ResponseDraft` | The baseline actions for each entity type. |
| Deception | Proposes `DeployHoneytoken` actions. Escalates an incident when a honeytoken is used. | None | Always deterministic. |
| Reporter | Writes the incident report as JSON and as Markdown. | `Reporting` | A deterministic template. |

The Responder maps the entities of an incident to actions:

| Entity | Baseline action | Optional action (the model can add it) |
| --- | --- | --- |
| Service principal | `DisableServicePrincipal`, `RevokeCredential` | `RotateCredential` |
| User | `KillSession` | `DisableUser` |
| Session | `KillSession` | |
| Host | `IsolateHost` | |
| IP address that is not internal | `BlockIp` | |
| Application | | `RevokeCredential` |
| Device | | `IsolateHost` |
| Secret | | `RotateSecret` |

## How an incident moves through the agents

```text
incident ─> Supervisor ─> Monitor ─> Analyst ─┬─> Responder ─> ActionDispatcher
                          (graph)   (triage)  │       │  ^            │
                                              │       │  └── result ──┘
                                              │       └─> Reporter (after the last result)
                                              ├─> Hunter (findings)
                                              └─> Deception (honeytoken)
```

1. The Monitor writes the incident to the Defensive Graph.
2. The Analyst assesses the incident. A false positive stops here.
3. The Responder proposes containment actions. The runtime sends each action to the
   dispatcher and gives the result back to the Responder.
4. The Responder records each result in the timeline of the incident. It sets the state
   `Contained` only when each action ran. A dry run, a denial, a pending approval, and a
   failure do not contain an incident.
5. The Reporter writes the report.

## Use the runtime

This example runs. The model has no script, so each agent uses its deterministic path.

```rust
use std::sync::Arc;

use aegis_agents::{AgentRuntime, CancellationToken, RuntimeConfig};
use aegis_contracts::AuditLog;
use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio.block_on(async {
        // A configuration file gives only the values that it changes.
        let config: RuntimeConfig = serde_json::from_value(json!({
            "dry_run": true,
            "tick_interval_seconds": 60,
            "limits": { "max_steps_per_incident": 64, "max_concurrency": 4 },
            "responder": { "refine_with_model": false }
        }))?;

        // Use your model router, stores, bus, and dispatcher in place of the test kit.
        let harness = Harness::new(ScriptedModel::new("local"));
        let dispatcher = Arc::new(RecordingDispatcher::new(DispatchMode::Execute));
        let runtime = Arc::new(
            AgentRuntime::builder(harness.context("Keep this tenant safe."), dispatcher)
                .config(config)
                .with_default_agents()
                .build()?,
        );

        // Batch use: put work in the queue and run until the queue is empty.
        runtime.submit_goal("Keep this tenant safe.")?;
        let report = runtime.run_until_idle().await?;
        assert_eq!(report.tasks_completed, 4);
        assert_eq!(report.tasks_failed, 0);
        assert!(harness.audit.verify().await?.valid);

        // Service use: run until the token is cancelled. The runtime takes tasks and
        // incidents from the bus and sends `Tick` tasks.
        let stop = CancellationToken::new();
        let service = tokio::spawn({
            let runtime = runtime.clone();
            let stop = stop.clone();
            async move { runtime.run(stop).await }
        });
        stop.cancel();
        service.await??;
        Ok(())
    })
}
```

To give an incident to the agents, call `runtime.submit_incident(incident)` or publish the
incident on the bus subject `aegis.incidents`.

## Public API

| Item | Function |
| --- | --- |
| `AgentRuntime::builder(context, dispatcher)` | Starts an `AgentRuntimeBuilder`. |
| `AgentRuntimeBuilder::config`, `with_default_agents`, `agent`, `build` | Sets the configuration, adds the built-in agents, adds or replaces an agent, and makes the runtime. |
| `AgentRuntime::submit`, `submit_goal`, `submit_incident` | Puts external work in the queue. |
| `AgentRuntime::run_until_idle` | Runs tasks until the queue is empty. Returns a `RunReport`. |
| `AgentRuntime::run(CancellationToken)` | Runs until the cancellation. Takes work from the bus and sends `Tick` tasks. |
| `AgentRuntime::state`, `is_idle`, `queued`, `stats`, `task_state`, `recent_tasks`, `roster`, `config` | Read the state of the runtime. |
| `RuntimeState`, `TaskState`, `TaskRecord`, `RunReport` | The state machine and the counts. |
| `RuntimeConfig`, `RuntimeLimits`, `MonitorConfig`, `HunterConfig`, `AnalystConfig`, `ResponderConfig`, `DeceptionConfig` | The configuration structures. |
| `agents::{Supervisor, Monitor, Hunter, Analyst, Responder, Deception, Reporter}` | The agents. Use them with a different runtime if necessary. |
| `agents::containment_candidates(&incident)` | The deterministic containment plan for an incident. |
| `agents::{ReportDocument, REPORT_SUBJECT}`, `IncidentReport` | The report in its two forms, and the bus subject of the reports. |
| `llm::{chat_json, run_tool_loop, run_tool_loop_json, parse_json_output, ModelOutput, ToolSet}` | Model helpers: a JSON answer with validation and one repair request, and a tool loop with a step limit. |
| `prompt::{Prompt, DATA_START, DATA_END, data_sections, outside_data_sections}` | Prompts that keep instructions and untrusted data apart. |
| `tools::GraphTools` | Read-only tools for the Defensive Graph and the incident store. |
| `ledger::{tracked_actions, TrackedAction, ActionState}` | The proposed actions of an incident and their last known states. |
| `graph_ops::prop` | The property names that the agents use on graph nodes. |
| `ModelCallError` | Why a model call gave no usable answer. |

A custom agent implements `aegis_contracts::Agent`. Add it with `AgentRuntimeBuilder::agent`
and put its role in `enabled_roles`. An agent with a built-in role replaces the built-in
agent.

## Configuration

All structures implement `serde::Deserialize` and `serde::Serialize`. Each key has a default.
An unknown key is an error. Call `RuntimeConfig::validate` to check the values;
`AgentRuntimeBuilder::build` calls it for you.

| Key | Default | Function |
| --- | --- | --- |
| `dry_run` | `true` | The runtime sets `dry_run` on each proposed action. A new installation changes nothing. |
| `enabled_roles` | All seven roles | The roles that can receive tasks. |
| `tick_interval_seconds` | `60` | The time between two `Tick` tasks. The value 0 stops the `Tick` tasks. The largest value is 31536000 (365 days). |
| `bus_consumer` | `"aegis-agents"` | The durable consumer name for the bus subscriptions. `null` gives only new messages. |
| `limits.max_steps_per_incident` | `64` | The maximum number of tasks for one incident that one external input can cause. |
| `limits.max_task_depth` | `16` | The maximum length of a chain of tasks. |
| `limits.max_concurrency` | `4` | The maximum number of tasks that run at the same time. |
| `limits.max_queued_tasks` | `10000` | The maximum number of tasks that wait in the queue. |
| `limits.max_actions_per_task` | `16` | The maximum number of actions that the runtime dispatches for one task. |
| `limits.task_timeout_seconds` | `120` | The maximum time for one task, and for one answer of the dispatcher. The largest value is 31536000. |
| `monitor.sweep_limit` | `50` | The maximum number of open incidents that one sweep gives to the Analyst. |
| `hunter.model_guided` | `true` | A hunt request in natural language uses the model and the read-only tools. |
| `hunter.max_tool_steps` | `6` | The maximum number of model calls in one model-guided hunt. |
| `hunter.scan_limit` | `500` | The maximum number of graph nodes that one hunt reads for each node type. |
| `hunter.max_findings` | `25` | The maximum number of new findings that one task records. |
| `hunter.management_ports` | 13 ports, for example 22 and 3389 | The ports that make an internet-exposed asset a finding. |
| `analyst.false_positive_min_confidence` | `0.8` | The minimum model confidence that can close an incident as a false positive. |
| `analyst.max_context_entities` | `20` | The maximum number of entities for which the Analyst reads graph context. |
| `responder.refine_with_model` | `true` | The Responder asks the model which optional actions to add. |
| `responder.max_actions_per_incident` | `12` | The maximum number of actions that the Responder proposes for one task. |
| `deception.max_honeytokens_per_task` | `3` | The maximum number of honeytokens that one task proposes. |
| `deception.scan_limit` | `500` | The maximum number of graph nodes and incidents that one task reads. |

A role in `enabled_roles` is a lower-case name, for example `"responder"`. A custom role is
`{ "custom": "name" }`.

## Guard rails

- **Steps and depth.** One external input can cause only `max_steps_per_incident` tasks for
  one incident. A chain of tasks can have only `max_task_depth` links. A loop of agents
  stops, and the audit log gets the reason.
- **One incident, one task at a time.** The tasks of one incident run in the order of the
  queue. At most `max_concurrency` tasks run at the same time.
- **Errors.** An agent error, a panic, or a timeout goes to the audit log. The runtime
  continues with the next task.
- **Fail closed.** The runtime does not dispatch an action if the audit log does not take
  the decision record. It does not dispatch the actions of a task if the incident store does
  not take the incidents of that task.
- **Dry run.** With `dry_run`, the runtime sets `ActionRequest::dry_run` on each action. An
  agent cannot switch the dry run off. An agent cannot name a different requester.
- **Identity.** The runtime dispatches each action with a `Principal` of the type `Agent`.
  The identifier and the single role of the principal are the role name of the agent.

## What the model can and cannot do

Event text, incident text, and graph text can come from an attacker. The crate treats all of
it as untrusted data.

- A prompt puts untrusted text only in data sections. A data section starts with
  `<<<AEGIS_UNTRUSTED_DATA` and ends with `AEGIS_UNTRUSTED_DATA>>>`. The text in a section
  cannot close the section. The system message holds the instructions and no untrusted text.
- The code validates each model answer against a structure. One repair request is permitted.
- The model cannot make an action. The Responder proposes the baseline actions always. The
  model can only add optional actions from a list that the code made.
- The model cannot close an incident that has deterministic evidence of an attack. A model
  failure or an answer that is not valid never makes an incident a false positive. The
  incident stays open, and the timeline gets the reason.
- The model writes only the summary and the recommendations of a report. The code makes the
  facts. The Markdown form escapes all text from the incident.
- The tools of the Hunter are read-only. The tool loop has a step limit.

## Bus subjects

| Subject | Direction | Payload |
| --- | --- | --- |
| `aegis.agents.tasks.{role}` | In (`run`) | `AgentTask`. The subject must name the role in the task. |
| `aegis.incidents` | In (`run`) | `Incident` |
| `aegis.actions.requests` | Out | `ActionRequest`, before the dispatch |
| `aegis.reports.{incident identifier}` | Out | `agents::ReportDocument`: the report as a structure and as Markdown |

`aegis.reports` is not in `aegis_contracts::bus::subject`. It is the constant
`agents::REPORT_SUBJECT` of this crate.

The runtime does not publish on `aegis.actions.results` and does not read that subject. The
action dispatcher is the single publisher of the results (`aegis_contracts::ActionResult`).

The runtime gives the result of each dispatch to the agent that proposed the action. The
task with the result has the same UUID as the action request.

An action that waits for approval can run later. The component that runs it must then
publish the result as a task for the proposing agent, for example on
`aegis.agents.tasks.responder`. The input of the task is
`AgentInput::ActionResult(ActionDisposition::Executed(outcome))`. The Responder finds the
incident from the action identifier in the outcome. Set `AgentTask::incident_id` if you know
the incident.

## Graph data

The Monitor writes these relations: `involves`, `part_of`, `member_of`,
`authenticated_from`, `acted_on`, `owns`, and `has_role`. The Responder writes
`contained_by` when an action ran.

The module `graph_ops::prop` holds the property names. An inventory connector that writes
asset nodes must use two of them, so that the Hunter can review the external exposure of the
assets of the operator:

| Property | Value |
| --- | --- |
| `internet_exposed` | `true` if the inventory says that the internet can reach the asset |
| `open_ports` | The open ports from the inventory, as an array of numbers |

The Hunter compares these values with `hunter.management_ports`. It connects to no asset.

## Test the crate

All tests are hermetic. They use the in-memory services of `aegis-testkit` and a scripted
model. They use no network and no credentials.

```sh
cargo test -p aegis-agents --all-features
cargo clippy -p aegis-agents --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p aegis-agents --no-deps
```

- The unit tests are next to the code in `src/`.
- The integration tests are in `tests/integration/`. `acceptance.rs` sends an incident like
  the one in the recorded attack log through the agents. `output_path.rs`, `guard_rails.rs`,
  and `bus_loop.rs` test the runtime with small test agents.
- The example in this file runs as a documentation test.
