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
| `IocStore`, `Indicator`, `IndicatorKind` | The indicator store: addresses, networks, domains, user agents, application identifiers, client fingerprints. |
| `SignInBurst`, `PrivilegedSelfAssignment`, `CredentialAfterGrant`, `ImpossibleSpeed`, `MachineCadence`, `EndpointProbe`, `VelocityConfig` | The velocity and behavior detectors, and their settings. |
| `LlmTriage`, `LlmTriageConfig` | Tier 2. `triage(&detection, &events)` returns a detection with the tier `llm`. |
| `Correlator`, `CorrelatorConfig` | Detections to incidents. |
| `FloodCounters`, `SuppressionSummary`, `IncidentCoalescer` | The flood protection of the engine. `DetectionEngine::flood_counters()` and `DetectionEngine::suppression_summaries()` return the counts. |
| `export_decoy_indicators`, `ExportOptions`, `export::merge_indicators` | The detections of decoys as indicators for a rule pack. `ioc::indicators_to_yaml` writes the file. |
| `DetectError` | The error of rules, indicator files, packs, and settings. It converts to `aegis_contracts::Error`. |

`SigmaDetector`, `IocStore`, and the six velocity detectors implement the `Detector`
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

A rule gives one detection for each event that matches. The top-level key
`aegis.suppress` changes this: the rule and one key then give ONE detection in a window.
Refer to [Flood protection](#flood-protection).

A rule that is not valid is an error that names the file and the cause. The engine does
not ignore the parts of Sigma that it does not support, for example keyword lists and
aggregation.

### Indicators

An indicator file is YAML or JSON:

```yaml
indicators:
  - type: ip              # ip, domain, user_agent, app_id, or client_fingerprint
    value: 192.0.2.200/29 # an address or a network in CIDR form
    description: Example network.
    severity: high        # informational, low, medium, high, or critical
    tags: [attack.command-and-control, attack.t1090.003]
    verdict: malicious    # optional; the default comes from the severity
    id: feed-1            # optional; the default is ioc:{type}:{value}
    first_seen: "2026-01-05T08:00:00Z"  # optional; when the source saw the value first
    last_seen: "2026-01-06T17:30:00Z"   # optional; when the source saw the value last
    source: example feed                # optional; where the indicator comes from
    suppress_seconds: 3600              # optional; refer to "Flood protection"
```

Each lookup is a hash lookup or a prefix lookup. The cost for one event does not grow
with the number of indicators.

A `client_fingerprint` indicator matches the attribute `client_fingerprint` of an event.
The comparison ignores ASCII case. A fingerprint with more than 128 characters, or with
characters that are not visible ASCII, is compared through its SHA-256 digest.

### Velocity detectors

| Detector | Pattern | Technique |
| --- | --- | --- |
| `SignInBurst` | Many failed sign-ins from one address in a short time. One detection for each burst, then a cooldown. A sign-in that succeeds from the address in the cooldown gives a second detection (`T1078`). | `T1110.003` |
| `PrivilegedSelfAssignment` | A service principal or an application gives a privileged role or permission to itself. | `T1098.003` |
| `CredentialAfterGrant` | A new application credential a short time after a consent or a permission grant for the same application. The detection keeps the attribute `credential_id` of the credential event, so that a response action can remove that credential. | `T1098.001` |
| `ImpossibleSpeed` | One principal acts from two places at a speed that is not possible, or in two resource tenants from two places in seconds. | `T1078.004` |
| `MachineCadence` | One principal or one address does a chain of different sensitive actions with gaps that are too short or too regular for a person. | `T1059.009` |
| `EndpointProbe` | One client asks a web or API endpoint for many different paths that do not exist, or for one decoy path. | `T1595.003`, `T1595` |

The detectors use the time of the events and not the clock of the host. Each detector
keeps state for a limited number of keys and drops the keys that it saw least recently.

#### Machine cadence

A **step** is an event that did not fail and whose action is in `sensitive_actions` or in
`supporting_actions`. The detector keeps the first event of each different action in a
window of `window_seconds`. Two `api.call` events with different `operation` attributes are
different actions. A job that does one action again and again thus makes no chain.

The detector reports a chain when the newest `min_actions` steps have one or more
sensitive actions, and one of these is true:

- The median gap is at most `max_median_gap_milliseconds`. The gaps are too short.
- The newest six steps (or `min_actions` steps, if that is more) have a coefficient of
  variation of at most `max_coefficient_of_variation`. The gaps are too regular. The
  coefficient is the standard deviation of the gaps divided by their mean. Fewer than
  five gaps do not show regularity, so the test needs six steps.

The detection is `suspicious`. It is `malicious` when the chain of a principal includes a
privileged change: a sensitive action with the attribute `privileged: true`.

The detector follows each user, service principal, and application. With
`follow_addresses`, it also follows each address, and it reports a chain that two or more
principals made from one address. An actor that is not a principal has only the chain of
its address. A chain of an address is always `suspicious`, because principals can share
an address.

The technique is `T1059.009` (Command and Scripting Interpreter: Cloud API). ATT&CK has
no technique for automated activity as such. A chain of control-plane actions at machine
speed shows a script or an agent that uses the cloud API, which is this technique.

An approved automation also works at machine speed. Put the identifier of each such
principal in `ignored_principals`, for example a provisioning service. If many principals
share one address, for example behind a proxy, set `follow_addresses` to `false`.

#### Endpoint probe

The detector examines `http.request` events. The client is the address of the actor. If
the event has no address, the client is the attribute `client_fingerprint`.

- **Probe**: one client asks for `distinct_path_threshold` different paths in
  `window_seconds`, and each answer has a status of `missing_statuses`. The detection is
  `suspicious` with the technique `T1595.003` (Wordlist Scanning). One path that the
  client asks for again and again is one path.
- **Decoy path**: one client asks for a path of `decoy_paths`. One request is sufficient,
  with any status. The technique is `T1595` (Active Scanning). The severity is
  `decoy_path_severity`. The severities `high` and `critical` make the detection
  `malicious`.

A decoy path is a path that no approved client asks for. A path that ends with `*`
matches each path that starts with the text before the `*`. The comparison ignores ASCII
case, the query, and a `/` at the end. It does not decode percent-encoded characters, so
the source connector must give the decoded path.

The detector makes ONE detection of each type for one client. It then makes no more
detections of that type for the client until `cooldown_seconds` end.

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

| The quota of the source or of the tenant has no request left | The tier 1 detection stays `suspicious`. The attribute `triage` records the status `quota`. The engine sends no request. |

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

## Flood protection

An attacker can send events only to make AEGIS work: to use the model budget, and to fill
the queue of incidents. The engine has three limits. Each limit uses the time of the
events and keeps a limited amount of state.

### Suppression

A Sigma rule with the top-level key `aegis.suppress` gives ONE detection for one key in a
window. The engine counts each other match in the window and makes no detection for it.

```yaml
aegis.suppress:
  window_seconds: 600             # necessary; the window starts with the first match
  fields:                         # optional; the event fields that make the key
    - actor.ip
    - client_fingerprint
  repeat:                         # optional; one more detection for many matches
    count: 10                     # the number of matches in the window
    level: high                   # optional; the default is high
    verdict: malicious            # optional; the default comes from the level
```

- `fields` use the field names of selections. Without `fields`, the key is the entities
  of the detection: the actor, the address, the client fingerprint, the target, and the
  application. A key always includes the rule and the tenant.
- `repeat` gives one more detection when the count of matches in one window reaches
  `count`. Its rule identifier is the identifier of the rule and `:repeated`. Use it for
  a rule where one match is `suspicious` and many matches are an attack.
- The first detection of a new window has the attribute `previous_window_matches`, if
  the window before had more than one match.

An indicator with the key `suppress_seconds` gives one detection for one matched value
and one actor in that time.

`DetectionEngine::suppression_summaries()` returns one summary for each window with more
than one match: the rule, the key, the times, and the number of matches. The engine keeps
at most 100,000 windows and drops those that it used least recently.

Suppression is a decision for each rule. A rule with no `aegis.suppress` key gives one
detection for each event that matches, as before. The velocity detectors have their own
windows and cooldowns. Use suppression for a rule that an attacker with no access can
match in any number, for example a rule for failed sign-ins or for decoy contact. Be
careful with a rule for changes: a suppressed match gives no detection, so its target is
not in an incident. Put the target in `fields` if each target must give a detection.

The `SigmaDetector` and the `IocStore` alone keep no state and do not suppress. The
engine applies the suppression.

### Tier 2 quota

Tier 2 sends at most `max_requests_per_source` model requests for the events of one source
connector, and at most `max_requests_per_tenant` for one tenant, in a window of
`quota_window_seconds`. A window starts with the first request of the source or the
tenant. When a quota has no request left:

- The engine sends no request to the model.
- The tier 1 detection stays `suspicious`. Its attribute `triage` has the status `quota`,
  the scope (`source` or `tenant`), the limit, and the window.
- The detection goes to the correlator, so it is in an incident.

A `malicious` tier 1 detection needs no model, so the quota does not change it. A
request that fails also uses one request of the quota.

### Incident coalescing

Each change of an incident gives a new state of the full incident. The bus runner
publishes at most `max_incident_updates` states of one incident in a window of
`incident_update_window_seconds`. It holds the newest state over the limit and drops the
states that this state replaces. The held state goes to the bus when one of these occurs:

- An event shows that the window is over.
- The same time passed on the clock of the host, and no event showed the end of the
  window.
- The runner stops.

These states are never held: the first state of an incident, a state with a higher
severity than the last published state, and the last state of an incident that a merge
replaced.

`DetectionEngine::process` returns each state and does not coalesce. A caller that
publishes the states itself can use `IncidentCoalescer`.

### Counters

`DetectionEngine::flood_counters()` returns the counts from the start of the engine:

| Counter | Meaning |
| --- | --- |
| `suppressed_matches` | Rule and indicator matches that gave no detection. |
| `repeat_detections` | Detections for a rule that matched many times for one key. |
| `triage_quota_denials` | `suspicious` detections that got no model request. |
| `coalesced_incident_updates` | Incident states that the bus runner did not publish. |

## Indicator export

A client that contacts a decoy shows its address, its user agent, and its fingerprint.
`export_decoy_indicators` makes indicators from the detections of decoys:

```rust,no_run
use aegis_detect::export::{ExportOptions, export_decoy_indicators, merge_indicators};
use aegis_detect::ioc::{indicators_to_yaml, load_indicators};

# fn example(detections: &[aegis_contracts::Detection]) -> Result<(), Box<dyn std::error::Error>> {
let path = std::path::Path::new("detections/aegis-identity/indicators/decoy.yml");
let new = export_decoy_indicators(detections, &ExportOptions::default())?;
// Keep the indicators of an earlier export. A pack must not have one indicator two times.
let all = if path.exists() {
    merge_indicators(load_indicators(path)?, new)
} else {
    new
};
std::fs::write(path, indicators_to_yaml(&all, "decoy.yml")?)?;
# Ok(())
# }
```

The function uses only the detections of decoys. The engine marks them: a detection for
an event with the attribute `decoy_id` gets the attributes `decoy_id`, `decoy_kind`,
`client_fingerprint`, and `user_agent`. A detection of the `EndpointProbe` for a decoy
path has the attribute `decoy_path`. You can thus give the function all detections of an
incident.

| Value | Source in the detection | Indicator type |
| --- | --- | --- |
| Address | Each entity of the kind `ip_address` | `ip` |
| Client fingerprint | The entity or the attribute `client_fingerprint` | `client_fingerprint` |
| User agent | The attribute `user_agent` | `user_agent` |

Each indicator has `first_seen` and `last_seen` from the times of its detections, and
the source note of the options. `merge_indicators` adds a new export to the indicators of
an existing file and keeps the oldest `first_seen` and the newest `last_seen`.

Examine the file before you add it to a pack. A decoy shows what a client did. It does
not show who the client is: many clients can share one address or one user agent. The
export is thus careful by default:

- No indicator has a severity above `medium` (`max_severity`). A match is then
  `suspicious`, and tier 2 examines it.
- A user agent indicator has the severity `low` (`max_user_agent_severity`).
- A user agent that starts with `Mozilla/` is not exported (`browser_user_agents`).
- `excluded_networks` names the addresses that the export never has, for example an
  approved scanner.
- Each indicator has a `suppress_seconds` of one hour.

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
identity systems and for contact with decoys. Its indicator file holds examples only. All
its addresses are in the documentation ranges, and all its domains use a reserved
top-level domain.

The decoy rules are in this pack and not in a pack of their own, because the engine
loads one pack. A second pack would not run with the configuration that the project
ships.

| Rule | Event | Result |
| --- | --- | --- |
| `decoy_contact.yml` | `decoy.contact` | `suspicious`, `low`: a scanner also contacts a decoy. One client (address and fingerprint) gives one detection in 10 minutes. |
| `decoy_contact.yml`, repeat | The tenth `decoy.contact` of one client in 10 minutes | `malicious`, `high`, with the rule identifier of the rule and `:repeated`. |
| `decoy_canary_hit.yml` | `decoy.canary_hit` | `malicious`, `high`: only an automated agent follows the hidden instruction. |

Each detection of a decoy event has the address of the client and its fingerprint as
entities. The fingerprint entity has the kind `other` and the identifier
`client_fingerprint:` and the fingerprint. The kind `other` selects no response action.

The rules for failed sign-ins and for legacy mail protocols (`account_locked_after_failed_sign_ins.yml`,
`mfa_request_denied.yml`, `legacy_mail_protocol_sign_in.yml`) have an `aegis.suppress`
key. An attacker with no access can match them in any number.

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

[velocity.machine_cadence]
enabled = true
window_seconds = 300
min_actions = 4                     # different actions in one chain
max_median_gap_milliseconds = 5000  # a median gap up to this value is too short
max_coefficient_of_variation = 0.1  # a variation up to this value is too regular
sensitive_actions = [
    "oauth.consent_grant", "app.create", "app.credential_add", "app.credential_remove",
    "app.permission_grant", "service_principal.create", "service_principal.disable",
    "role.assign", "role.remove", "user.create", "user.update", "user.password_reset",
    "mfa.method_change", "secret.read", "honeytoken.trip",
]
supporting_actions = ["sign_in", "api.call"]
follow_addresses = true
ignored_principals = []             # the identifiers of approved automations
cooldown_seconds = 900
max_tracked_keys = 100000

[velocity.endpoint_probe]
enabled = true
window_seconds = 60
distinct_path_threshold = 20        # different missing paths from one client
missing_statuses = [404, 410]
decoy_paths = []                    # for example ["/.env", "/admin/backup/*"]
decoy_path_severity = "medium"
cooldown_seconds = 900
max_tracked_clients = 100000

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
quota_window_seconds = 3600
max_requests_per_source = 120       # model requests for one source connector in a window
max_requests_per_tenant = 240       # model requests for one tenant in a window
# model = "name"  # optional; the model router selects the model if you omit it
```

`BusRunnerConfig` has these keys:

```toml
durable_name = "aegis-detect"
publish_attempts = 5
publish_backoff_milliseconds = 50
max_incident_updates = 20           # published states of one incident in a window
incident_update_window_seconds = 60
```

## Test

```sh
cargo test -p aegis-detect --all-features
```

The tests use no network and no credentials. The integration tests are in `tests/`:

| File | Content |
| --- | --- |
| `acceptance.rs` | A replay of the recorded attack log with the shipped pack. |
| `bus_runner.rs` | The bus runner with the in-memory bus. |
| `cadence.rs` | The machine-cadence detector with the recorded attack log. |
| `config.rs` | The settings as a TOML table, and the example of this file. |
| `detectors.rs` | Each `Detector` implementation through the contract. |
| `export.rs` | The indicator export: detections to a file, to a pack, to a match. |
| `flood.rs` | Suppression, the tier 2 quota, and the bound on incident states. |
| `hot_reload.rs` | A change of the rule pack while the engine operates. |
| `probe.rs` | The endpoint-probe detector through the engine. |
| `shipped_pack.rs` | Each rule and each indicator of `detections/aegis-identity`. |

## Limits

- Sigma keyword lists, aggregation, and correlation rules are not supported.
- A Sigma rule with no `aegis.suppress` key gives one detection for each event that
  matches. The detections of a detector that `with_detector` added are not suppressed.
- The limits of the flood protection use the time of the events. A source that sends
  events with wrong times can start a new window early.
- The machine-cadence detector cannot tell an approved automation from an attack. Use
  `ignored_principals`. One action of a person can give many events at one instant in
  some sources, and four such events are a chain.
- `DetectionEngine::process` does not coalesce incident states. Only the bus runner does.
- Tier 2 runs in `process`. An event with a `suspicious` detection waits for the model,
  for at most `timeout_seconds`.
- Tier 2 gets the event that completed the detection. It does not get older events.
- The state of the velocity detectors and of the correlator is in memory. It does not
  continue after a restart.
