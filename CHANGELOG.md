# Changelog

This file records all notable changes to this project.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: the Cargo workspace, lint rules, and CI.
- Project documents: README, contribution guide, security policy, and code of conduct.
- `aegis-contracts`: the frozen contracts between the subsystems. They cover events,
  connectors, detectors, incidents, models, agents, actions, policy, approvals, the audit
  log, the Defensive Graph, and the message bus.
- `aegis-testkit`: in-memory implementations of all contracts.
- `fixtures/artex_style_attack.jsonl`: a recorded log of an agent attack on an identity tenant.
- `aegis-core`: the configuration file with environment overrides, the log, an OpenTelemetry
  trace exporter, the module set, and the shutdown signal.
- `aegis-model`: provider adapters for the OpenAI chat-completions format and for the
  Anthropic Messages API, and a model router with routes, fallback, and token budgets.
- `aegis-ingest`: the ingestion runner with checkpoints and retries, a JSON Lines file
  source, and a Microsoft Entra ID source.
- `aegis-bus`: the message bus on NATS JetStream, and a bus in the process.
- `aegis-detect`: detection tier 1 (a subset of Sigma, indicators, and four velocity
  detectors), detection tier 2 (model triage), the correlator, and rule packs.
- `detections/aegis-identity`: a detection pack with nine Sigma rules for attacks on identity
  systems.
- `aegis-agents`: the agent runtime with the Supervisor, Monitor, Hunter, Analyst, Responder,
  Deception, and Reporter agents. Each agent works with no model.
- `aegis-respond`: the action dispatcher (policy, approval, connector, audit), the Microsoft
  Graph and webhook action connectors, the playbook engine, and honeytokens.
- `playbooks/`: five sample playbooks.
- `aegis-policy`: the Rego policy engine, role-based access control, the approval service
  with the four-eyes rule, the file audit log, and explanations.
- `policies/`: the default response policy and three example policies.
- `aegis-memory` and `aegis-storage`: stores in memory, and PostgreSQL stores with Apache AGE
  and pgvector for the graph, embeddings, incidents, the audit log, and approvals.
- `deploy/docker/postgres`: a database image with PostgreSQL, Apache AGE, and pgvector.
- `aegis-plugin`, `wit/plugin.wit`, and `plugins/`: a sandbox for WebAssembly connector
  plugins, the plugin interface, and two example plugins.
- `aegis-api`: the REST API, the web console, Slack and Teams commands and notifications, and
  optional gRPC services.
- `aegis-app`: the composition root that builds all subsystems from one configuration.
- `aegis-cli`: the `aegis` program with the commands `demo`, `init`, `run`, `replay`,
  `monitor`, `audit verify`, `audit show`, and `config check`.
- `docs/`: the quickstart, the demonstration, the architecture with the threat model, and
  the configuration reference.
- `docs/`: the guides for connectors, detection packs, playbooks, policy, operations, and
  security.
- `examples/`: configuration sets for an offline service, a local model, and Microsoft Entra
  ID, and a detection pack with a playbook for device code phishing.
- `aegis-decoy`: a decoy service with a tarpit, a maze, a decoy model API, and a canary
  instruction for automated agents. It only answers a client that connects to it.
- `aegis-detect`: the velocity detectors `machine_cadence` and `endpoint_probe`, and flood
  protection: suppression for each rule and each indicator, a quota for tier 2, and a limit
  on the states of one incident.
- `detections/aegis-identity`: two rules for contact with a decoy. The pack has 11 rules.
- `aegis-respond`: the revert of an action through the dispatcher, the timed revert with a
  scheduler and a store file, and the friction actions `restrict_user_consent` and
  `raise_friction`.
- `playbooks/`: the field `revert_after` of a step, and a sixth sample playbook,
  `raise-friction-critical-identity-incident`.
- `policies/examples/contain_first_with_timed_revert.rego`: an example policy that lets a
  reversible action with a short revert time run first.
- `aegis-share`: abuse reports with an evidence manifest, and indicators as STIX 2.1 and as
  CSV. The crate makes documents only.
- `aegis-app`: the `[decoy]` section starts the decoy service, and each decoy key is a
  honeytoken. The `[response.revert]` table starts the revert scheduler. The `[evidence]`
  section writes an evidence archive. The `[share]` section gives the networks of the
  operator to the sharing functions. The Cargo feature `decoy` is a default feature.
- `aegis-api`: the routes `GET /reverts`, `POST /reverts/{action_id}/confirm`, `extend`, and
  `cancel`, and `POST /actions/{id}/revert`. The status route shows the counts of the flood
  protection, the timed reverts, the evidence archive, and the decoy. The console shows the
  pending timed reverts.
- `aegis-cli`: the commands `reverts list`, `reverts confirm`, `reverts extend`,
  `reverts cancel`, `report abuse`, and `indicators export`.
- `docs/`: the guides for deception, for the revert and the timed revert, and for sharing.

### Changed

- `README.md` describes the state of the code: what works, and what is not done.
- The recorded attack log gives nine detections with eight ATT&CK techniques. The new
  detector for machine cadence adds one detection.
- The reversible containment steps of the sample playbooks have a revert time of 4 hours.
- The starter configuration has the tables `[response.revert]` and `[evidence]`, and the
  `[decoy]` and `[share]` sections as comments.
- The simulation connector reports `reversible: true` for an action type that has an
  inverse, and it takes the two friction actions as dry runs.
- `aegis replay` uses the limit on the states of one incident. With the default limit, the
  result for the recorded attack log is the same.

### Security

- With the default settings, each response action is a dry run.
- The operator API listens on a loopback address and refuses each request with no valid
  token.
- Each revert goes through the policy, the approval queue, and the audit log. Only a person
  with the permission `approve_actions` can confirm, move, or request a revert.
- With no `[response.revert]` table, an action with a revert time runs only as a dry run.
- A decoy with no seed does not start. A decoy on the address of the operator API is
  refused.
- The sharing commands send nothing. With no `operator_networks`, they write no document.
  They refuse an audit log with a hash chain that does not verify.
