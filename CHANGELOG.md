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

### Changed

- `README.md` describes the state of the code: what works, and what is not done.

### Security

- With the default settings, each response action is a dry run.
- The operator API listens on a loopback address and refuses each request with no valid
  token.
