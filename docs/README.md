# AEGIS documentation

AEGIS is an open-source framework for autonomous cyber defense. It is defensive only.
Use it only in an environment that you own or have authorization to defend.

These documents describe the code in this repository. The output blocks in them are
output of real runs, and each configuration example was loaded with the program. A
section with the name "Limits" says what is not built and what was not tested.

## Start here

| Document | Contents |
| --- | --- |
| [quickstart.md](quickstart.md) | From a clean checkout to a service that you operate: build, the demonstration, the console, an approval, and the audit log. |
| [demo.md](demo.md) | The recorded agent attack, step by step: each detection, the incident, the proposed containment, and the audit trail. |

## Understand

| Document | Contents |
| --- | --- |
| [architecture.md](architecture.md) | The components, the data flow, the bus subjects, the two detection tiers, the agents, the dispatch path, the storage options, and the threat model of AEGIS. |
| [security.md](security.md) | The hardening checklist, and the security properties with the tests that prove them. |

## Configure and operate

| Document | Contents |
| --- | --- |
| [configuration.md](configuration.md) | Each section and each key of `aegis.toml`, the environment overrides, and the secrets. |
| [operations.md](operations.md) | The audit log, approvals, a change of the rules or the policy, restarts, upgrades, backup, logs, and troubleshooting. |
| [policy.md](policy.md) | The response policy: the input, the decision, fail closed, tiers, approvals, and role-based access control. |
| [response.md](response.md) | The revert of an action, the timed revert, the decisions of a person, and the friction actions. |
| [deception.md](deception.md) | The decoy service: its personas, the canary instruction, decoy keys, placement, safety rules, and limits. |
| [sharing.md](sharing.md) | Abuse reports and indicators for other defenders, and the evidence archive. AEGIS sends nothing. |

## Extend

| Document | Contents |
| --- | --- |
| [connectors.md](connectors.md) | A source connector and an action connector, as native Rust code and as a WebAssembly plugin. |
| [detection-packs.md](detection-packs.md) | The pack layout, the supported part of Sigma, the event vocabulary, indicators, and how to test a rule. |
| [playbooks.md](playbooks.md) | The playbook format, triggers, target selectors, templates, the dry run, and how the policy applies. |

## Examples

The directory [`examples`](../examples/README.md) has configuration sets that you can
run.

| Example | Contents |
| --- | --- |
| [`offline-demo`](../examples/offline-demo/README.md) | The service with the web console, with no model, no database, and no network. |
| [`local-model`](../examples/local-model/README.md) | A local model behind an OpenAI-compatible server. |
| [`entra`](../examples/entra/README.md) | Microsoft Entra ID as the source, and Microsoft Graph for the identity actions. |
| [`device-code-phishing`](../examples/device-code-phishing/README.md) | One more detection pack and playbook pair, with sample events. |

## Reference in the repository

| Subject | Location |
| --- | --- |
| The `aegis` program and its commands | [`crates/cli/README.md`](../crates/cli/README.md) |
| The REST routes, the web console, and ChatOps | [`crates/api/README.md`](../crates/api/README.md) |
| The composition of the subsystems | [`crates/app/README.md`](../crates/app/README.md) |
| The contracts between the subsystems | [`crates/contracts/src`](../crates/contracts/src) |
| The source connectors | [`crates/ingest/README.md`](../crates/ingest/README.md) |
| Detection | [`crates/detect/README.md`](../crates/detect/README.md) |
| The decoy service | [`crates/decoy/README.md`](../crates/decoy/README.md) |
| Abuse reports and indicator export | [`crates/share/README.md`](../crates/share/README.md) |
| The agents | [`crates/agents/README.md`](../crates/agents/README.md) |
| Response and the action connectors | [`crates/respond/README.md`](../crates/respond/README.md) |
| Policy, access control, and the file audit log | [`crates/policy/README.md`](../crates/policy/README.md) |
| The model layer | [`crates/model/README.md`](../crates/model/README.md) |
| The message bus | [`crates/bus/README.md`](../crates/bus/README.md) |
| PostgreSQL storage | [`crates/storage/README.md`](../crates/storage/README.md) |
| The plugin host | [`crates/plugin/README.md`](../crates/plugin/README.md) |
| Plugin authoring | [`plugins/README.md`](../plugins/README.md) |
| The shipped policies | [`policies/README.md`](../policies/README.md) |
| The sample playbooks | [`playbooks/README.md`](../playbooks/README.md) |
| Deployment in containers | [`deploy/README.md`](../deploy/README.md) |

## Conventions of these documents

- A command runs in the root of the repository, with the `aegis` program in the path.
  The quickstart tells you how to build the program.
- A block of output is the real output of the command. The identifiers, the times, and
  the paths of temporary directories are different in your run.
- All identifiers are examples: `example.com` names, documentation addresses, and
  placeholder tenant identifiers.
- The documents use ASD Simplified Technical English style.
