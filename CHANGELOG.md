# Changelog

This file records all notable changes to this project.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: the Cargo workspace, the empty `aegis-contracts` crate, lint rules, and
  CI.
- Project documents: README, contribution guide, security policy, and code of conduct.
- `aegis-contracts`: the frozen contracts for events, source connectors, detectors, incidents,
  model providers, agents, response actions, policy, approvals, the audit log, the Defensive
  Graph, and the message bus.
- `aegis-testkit`: in-memory implementations of all contracts.
- `fixtures/artex_style_attack.jsonl`: a recorded log of an agent attack on an identity tenant.
