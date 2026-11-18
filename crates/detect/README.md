# aegis-detect

`aegis-detect` is the detection and correlation subsystem of AEGIS. It reads normalized
events, finds attacks, and folds the findings into incidents. It has no offensive function.

Detection has two tiers:

- **Tier 1** is deterministic. It uses Sigma rules, indicator matches, and velocity
  detectors. It uses no model.
- **Tier 2** asks a model about the detections that tier 1 marks as `suspicious`. A
  `malicious` detection and an event with no detection never reach the model.

A correlator then puts related detections into one incident.

```text
Event -> tier 1 (Sigma, indicators, velocity) -> suspicious? -> tier 2 (model) -> correlator -> Incident
                                              -> malicious  ------------------->
```

The crate talks to other subsystems only through `aegis-contracts`: `Event`, `Detector`,
`Detection`, `Incident`, `ModelProvider`, and `MessageBus`.

## Public API

| Item | Function |
| --- | --- |
| `DetectionEngine` | The two tiers and the correlator as one unit. `process(&Event)` returns the new detections and the new or changed incidents. `run(bus, config, cancel)` connects the engine to the message bus. `reload(pack)` changes the rules with no restart. |
| `EngineConfig`, `EngineOutput`, `BusRunnerConfig`, `RunSummary` | The settings and the results of the engine and of the bus runner. |
| `RulePack`, `PackManifest` | A directory of Sigma rules and indicators that the engine loads as one unit. `RulePack::load(dir)` reads and validates it. |
| `SigmaRule`, `SigmaDetector` | The Sigma rule engine. `SigmaRule::parse(text, origin)` compiles one rule. |
| `IocStore`, `Indicator`, `IndicatorKind` | The indicator store: addresses, networks, domains, user agents, application identifiers. |
| `SignInBurst`, `PrivilegedSelfAssignment`, `CredentialAfterGrant`, `ImpossibleSpeed`, `VelocityConfig` | The velocity and behavior detectors, and their settings. |
| `LlmTriage`, `LlmTriageConfig` | Tier 2. `triage(&detection, &events)` returns a detection with the tier `llm`. |
| `Correlator`, `CorrelatorConfig` | Detections to incidents. |
| `DetectError` | The error of rules, indicator files, packs, and settings. It converts to `aegis_contracts::Error`. |

`SigmaDetector`, `IocStore`, and the four velocity detectors implement the `Detector`
contract with the tier `deterministic`.

## Use the engine

```rust,no_run
use std::sync::Arc;

use aegis_detect::{BusRunnerConfig, DetectionEngine, EngineConfig, RulePack};
use tokio_util::sync::CancellationToken;

# async fn example(
#     model: Arc<dyn aegis_contracts::ModelProvider>,
#     bus: Arc<dyn aegis_contracts::MessageBus>,
#     event: aegis_contracts::Event,
# ) -> Result<(), Box<dyn std::error::Error>> {
let pack = RulePack::load("detections/aegis-identity")?;
let engine = DetectionEngine::new(EngineConfig::default(), pack)?.with_triage(model)?;

// One event at a time.
let output = engine.process(&event).await?;
println!("{} detections, {} incidents", output.detections.len(), output.incidents.len());

// Or from the message bus, until the token is cancelled.
let cancel = CancellationToken::new();
let summary = engine.run(bus.as_ref(), &BusRunnerConfig::default(), cancel).await?;
println!("{} events", summary.events);
# Ok(())
# }
```

The bus runner does these steps:

1. It subscribes to `aegis.events.>` with a durable name. The default name is
   `aegis-detect`.
2. For each event, it calls `process`.
3. It publishes each detection to `aegis.detections.deterministic` or to
   `aegis.detections.llm`.
4. It publishes each new or changed incident to `aegis.incidents`.

Use one runner for each durable name. The velocity detectors must see all events of a
stream, in the order of the stream.

## Tier 1

### Sigma rules

The `sigma` module documentation lists the supported parts of Sigma. In short:

- Metadata: `title`, `id`, `status`, `description`, `level`, `tags`, `logsource`.
- Selections: maps and lists of maps, with the modifiers `contains`, `startswith`,
  `endswith`, `re`, `cidr`, `all`, `gt`, `gte`, `lt`, `lte`, and `exists`. Text comparison
  ignores case. `*` and `?` are wildcards.
- Conditions: `and`, `or`, `not`, parentheses, `1 of selection*`, `all of selection*`,
  `1 of them`, `all of them`.
- Fields: `action`, `outcome`, `severity`, `class`, `actor.*`, `target.*`, `source.*`,
  `attributes.<key>`, and `raw.<path>`. All other names are attribute keys.

A rule with the level `high` or `critical` gives `malicious` detections. All other rules
give `suspicious` detections. The top-level key `aegis.verdict` replaces this default:

```yaml
aegis.verdict: suspicious
```

A rule that is not valid is an error that names the file and the cause. The engine does
not ignore the parts of Sigma that it does not support, for example keyword lists and
aggregation.

### Indicators

An indicator file is YAML or JSON:

```yaml
indicators:
  - type: ip              # ip, domain, user_agent, or app_id
    value: 192.0.2.200/29 # an address or a network in CIDR form
    description: Example network.
    severity: high        # informational, low, medium, high, or critical
    tags: [attack.command-and-control, attack.t1090.003]
    verdict: malicious    # optional; the default comes from the severity
    id: feed-1            # optional; the default is ioc:{type}:{value}
```

Each lookup is a hash lookup or a prefix lookup. The cost for one event does not grow
with the number of indicators.

### Velocity detectors

| Detector | Pattern | Technique |
| --- | --- | --- |
| `SignInBurst` | Many failed sign-ins from one address in a short time. One detection for each burst, then a cooldown. A sign-in that succeeds from the address in the cooldown gives a second detection (`T1078`). | `T1110.003` |
| `PrivilegedSelfAssignment` | A service principal or an application gives a privileged role or permission to itself. | `T1098.003` |
| `CredentialAfterGrant` | A new application credential a short time after a consent or a permission grant for the same application. The detection keeps the attribute `credential_id` of the credential event, so that a response action can remove that credential. | `T1098.001` |
| `ImpossibleSpeed` | One principal acts from two places at a speed that is not possible, or in two resource tenants from two places in seconds. | `T1078.004` |

The detectors use the time of the events and not the clock of the host. Each detector
keeps state for a limited number of keys and drops the keys that it saw least recently.

## Tier 2

`LlmTriage` sends one `suspicious` detection and its event to the model with
`TaskKind::Triage` and the JSON response format. The model output is not trusted:

| Model output | Result |
| --- | --- |
| `malicious`, valid | `malicious`, tier `llm` |
| `benign`, valid, confidence at or above `benign_min_confidence` | `benign`, tier `llm` |
| `suspicious`, valid | `suspicious`, tier `llm` |
| Not JSON, an unknown verdict, no reasons, or `benign` with too little confidence | `suspicious`, tier `llm`. The attribute `triage` records the cause. |
| The model fails or gives no answer in time | The tier 1 detection stays `suspicious`. The attribute `triage` records the failure. |

A failure of tier 2 never removes a detection and never makes it `benign`.

## Correlator

Two detections are in one incident when they are in the same tenant, share an entity
(the same kind and identifier, including the address of the actor), and are in one time
window. A chain of entities also links. A detection that links two incidents merges them
into the older one. The other incident gets the status `resolved` and a timeline entry
that names the incident that replaces it.

The severity of an incident is the largest severity of its detections. An incident with
three or more different ATT&CK techniques is `critical`.

Entities of the kinds in `unlinked_kinds` do not link detections. The default is `tenant`
and `role`, because many principals share them. If many users share one address in your
environment, for example behind a proxy, add `ip_address` to the list.

The correlator makes each incident with the status `open`. It does not know about a
status change that an agent makes later. Before you write a published incident to the
incident store, keep the status that the store has. When an incident is complete, call
`DetectionEngine::forget_incident`, so that later detections start a new incident.

## Rule packs

```text
detections/aegis-identity/
  pack.yml                 name, version, description
  rules/*.yml              Sigma rules, one rule in each file
  indicators/*.yml         indicator files (YAML or JSON)
```

`RulePack::load` validates the full directory. One file that is not valid rejects the
pack. Two rules with one identifier, or one indicator in two files, also reject it.

To change the rules of an engine that operates:

```rust,no_run
# fn example(engine: &aegis_detect::DetectionEngine) -> Result<(), aegis_detect::DetectError> {
engine.reload_from_dir("detections/aegis-identity")?;
# Ok(())
# }
```

The change is atomic. Each event uses one pack from start to end, and no event is lost.
If the new pack is not valid, the call returns the error and the old pack stays active.
The state of the velocity detectors and the incidents stay.

The project ships one pack, `detections/aegis-identity`, with rules for attacks on
identity systems. Its indicator file holds examples only. All its addresses are in the
documentation ranges, and all its domains use a reserved top-level domain.

## Configuration

`EngineConfig` has three sections. Each section and each key is optional. An unknown key
is an error.

```toml
[velocity.sign_in_burst]
enabled = true
window_seconds = 60
failure_threshold = 20        # failed sign-ins from one address
distinct_user_threshold = 10  # different users from one address: a password spray
cooldown_seconds = 900
report_success_after_burst = true
max_tracked_addresses = 100000

[velocity.privileged_self_assignment]
enabled = true
require_privileged = true
severity = "high"

[velocity.credential_after_grant]
enabled = true
window_seconds = 120
max_tracked_applications = 50000

[velocity.impossible_speed]
enabled = true
max_speed_kmh = 1000.0
min_distance_km = 500.0
country_window_seconds = 1800
cross_tenant_window_seconds = 60
cooldown_seconds = 900
max_tracked_principals = 100000

[correlator]
window_seconds = 3600
critical_technique_count = 3
max_incidents = 10000
max_detections_per_incident = 200
unlinked_kinds = ["tenant", "role"]

[triage]
max_events = 20
max_event_bytes = 49152
max_output_tokens = 512
benign_min_confidence = 0.8
timeout_seconds = 60
# model = "name"  # optional; the model router selects the model if you omit it
```

`BusRunnerConfig` has the keys `durable_name`, `publish_attempts`, and
`publish_backoff_milliseconds`.

## Test

```sh
cargo test -p aegis-detect --all-features
```

The tests use no network and no credentials. The integration tests are in `tests/`:

| File | Content |
| --- | --- |
| `acceptance.rs` | A replay of the recorded attack log with the shipped pack. |
| `bus_runner.rs` | The bus runner with the in-memory bus. |
| `hot_reload.rs` | A change of the rule pack while the engine operates. |
| `detectors.rs` | Each `Detector` implementation through the contract. |
| `shipped_pack.rs` | Each rule and each indicator of `detections/aegis-identity`. |

## Limits

- Sigma keyword lists, aggregation, and correlation rules are not supported.
- A Sigma rule gives one detection for each event that matches. The engine has no
  suppression for a rule that matches many events.
- Tier 2 runs in `process`. An event with a `suspicious` detection waits for the model,
  for at most `timeout_seconds`.
- Tier 2 gets the event that completed the detection. It does not get older events.
- The state of the velocity detectors and of the correlator is in memory. It does not
  continue after a restart.
