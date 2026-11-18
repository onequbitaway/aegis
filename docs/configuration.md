# Configuration

One TOML file holds the configuration of one AEGIS process. This document describes each
section and each key of that file, the environment overrides, and the secrets.

`aegis init --dir <directory>` writes a starter file, `aegis.toml`, with comments.

## Contents

- [Rules of the file](#rules-of-the-file)
- [Check a configuration](#check-a-configuration)
- [Environment overrides](#environment-overrides)
- [Secrets](#secrets)
- [Sections](#sections)
- [Safe defaults](#safe-defaults)
- [Limits](#limits)

## Rules of the file

- Each top-level key is a section. The table in [Sections](#sections) lists all sections.
- A section name that AEGIS does not know is an error. A key that a section does not
  know is an error. A wrong name thus never passes with no effect.
- A relative path starts at the directory of the configuration file.
- A duration is text with a unit, for example `"30s"`, `"5m"`, `"1h"`, or `"7days"`. A key
  with a name that ends in `_seconds` or `_ms` is a number.
- An error message names the section and the key. It does not show a value.

## Check a configuration

```sh
aegis config check --config /tmp/aegis-quickstart/aegis.toml
```

The command does two steps:

1. It reads all sections and reports each section that is not valid. If all sections are
   valid, it reads the files that they name: the rule pack, the policy, and the playbooks.
2. If step 1 finds no problem, it builds the application. This step connects to the bus
   and to the database, runs the database migrations, and opens the audit log. With the
   module `api`, it also reads each token. With the `[decoy]` section, it also reads the
   seed and each decoy key. It opens no listener.

The command starts no source, no detection, no agent, and no server. The exit status is
1 if the configuration has a problem.

For a valid configuration, the command prints a summary:

| Line | Meaning |
| --- | --- |
| `agents_dry_run` | The value of `agents.dry_run`. |
| `api` | The address of the operator API, or `off`. |
| `bus` | `memory` or `nats`. |
| `connectors` | The action connectors, in priority order. |
| `decoy` | The address of the decoy service, or `off`. |
| `dispatcher_dry_run` | The value of `response.dry_run`. |
| `evidence_archive` | The file of the evidence archive, or `off`. |
| `model` | `true` if the configuration has a model. |
| `modules` | The modules that the process runs. |
| `playbook_mode` | The value of `response.playbooks`. |
| `playbooks` | The names of the loaded playbooks. |
| `rule_pack`, `rules` | The name of the detection pack and the number of its Sigma rules. |
| `sources` | The names of the source connectors. |
| `storage` | `memory` or `postgres`. |
| `timed_revert` | The store file of the timed reverts, or `off`. |

## Environment overrides

An environment variable can set one key. An override has priority over the value in the
file.

1. Start the name with `AEGIS__`.
2. Add the section name and the key name, with `__` between the parts of the key path.
3. Use upper case or lower case. The name is not case-sensitive.

| Variable | Key |
| --- | --- |
| `AEGIS__TELEMETRY__LOG_LEVEL=debug` | `telemetry.log_level` |
| `AEGIS__RESPONSE__DRY_RUN=true` | `response.dry_run` |
| `AEGIS__MODULES__ENABLED='["ingest", "detection", "monitor"]'` | `modules.enabled` |
| `AEGIS__STORAGE__URL='postgres://...'` | `storage.url` |

The text of the variable becomes a TOML value:

| Text | Result |
| --- | --- |
| `true` or `false` | A Boolean. |
| A TOML integer or a finite TOML float, for example `42` or `0.5` | A number. |
| A TOML string in quotation marks, for example `"42"` | The string in the quotation marks. |
| A TOML array, for example `["a", "b"]` | An array. |
| All other text | A string with the same text. |

- An override cannot set one element of an array. Set the full array.
- An override cannot change one table of `[[sources]]` or `[[api.principals]]`.
- Put quotation marks around digits that must stay a string. For example, a NATS
  password of only digits is `AEGIS__BUS__NATS__AUTH__PASSWORD='"123456"'` in a shell.
- `aegis run`, `aegis replay`, `aegis config check`, and `aegis monitor --config` read the
  overrides. `aegis demo` does not read them.

Example: this command examines an event file with the log level `error`.

```sh
AEGIS__TELEMETRY__LOG_LEVEL=error aegis replay \
    --config /tmp/aegis-quickstart/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run \
    --audit-file /tmp/aegis-quickstart/data/replay-audit.jsonl
```

## Secrets

Do not put a secret in the configuration file. Each secret has one of two paths.

**Path 1: the file names an environment variable.** The key holds the NAME of the
variable. AEGIS reads the variable at the start.

| Secret | Key that names the variable |
| --- | --- |
| The token of an API principal | `token_env` in `[[api.principals]]` |
| The client secret of the Entra ID source | `client_secret_env` in `[[sources]]` |
| The API key of a model provider | `api_key_env` in `[model.providers.<name>]` |
| The Slack signing secret and webhook URL | `signing_secret_env`, `webhook_url_env` in `[api.chatops.slack]` |
| The Teams secret and webhook URL | `shared_secret_env`, `webhook_url_env` in `[api.chatops.teams]` |
| The seed of the decoy service | `seed_env` in `[decoy]` |
| A decoy key of the decoy model API | `value_env` in `[[decoy.model_api.keys]]` |

**Path 2: an environment override sets the key.** These keys hold the secret itself.
Leave the key out of the file, and set it with an override.

| Secret | Override |
| --- | --- |
| The database URL | `AEGIS__STORAGE__URL` |
| The client secret of the Microsoft Graph action connector | `AEGIS__RESPONSE__GRAPH__CLIENT_SECRET` |
| The shared secret of the webhook action connector | `AEGIS__RESPONSE__WEBHOOK__SECRET` |
| The NATS password or token | `AEGIS__BUS__NATS__AUTH__PASSWORD`, `AEGIS__BUS__NATS__AUTH__TOKEN` |

For NATS, a credentials file is a third path: `method = "credentials_file"` with `path`.

A secret that is missing stops the start. The message names the key or the variable and
never shows a value:

```text
configuration error: the section `api` is not valid: principal alice@example.com: the environment variable AEGIS_TOKEN_ALICE is not set
configuration error: the section `response` is not valid: key `graph`: missing field `client_secret`
```

## Sections

| Section | Necessary | Contents |
| --- | --- | --- |
| [`[modules]`](#modules) | No | The subsystems that the process runs. |
| [`[telemetry]`](#telemetry) | No | The log and the trace exporter. |
| [`[bus]`](#bus) | Yes | The message bus. |
| [`[storage]`](#storage) | Yes | The incidents, the Defensive Graph, the embeddings, and the approvals. |
| [`[audit]`](#audit) | Yes | The audit log. |
| [`[model]`](#model) | No | The model providers, the routes, and the token budget. |
| [`[policy]`](#policy) | Yes | The response policy. |
| [`[rbac]`](#rbac) | No | The permissions of each role. |
| [`[approval]`](#approval) | No | The rules for approval decisions. |
| [`[detection]`](#detection) | Yes | The detection pack and the engine settings. |
| [`[agents]`](#agents) | No | The goal and the agent runtime. |
| [`[response]`](#response) | No | The dry-run switches, the playbooks, and the action connectors. |
| [`[[sources]]`](#sources) | No | The source connectors. |
| [`[ingest]`](#ingest) | No | The checkpoints and the retry rules of the sources. |
| [`[plugins]`](#plugins) | No | The WebAssembly connector plugins. |
| [`[decoy]`](#decoy) | No | The decoy service. |
| [`[evidence]`](#evidence) | No | The evidence archive for the sharing commands. |
| [`[share]`](#share) | Only for the sharing commands | The networks of the operator, and the receivers. |
| [`[api]`](#api) | Only with the module `api` | The operator API. |

### `[modules]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | List of names | `["ingest", "detection", "monitor"]` | The subsystems that the process starts. |

The names are `ingest`, `detection`, `monitor`, `hunter`, `analyst`, `responder`,
`deception`, `reporter`, and `api`.

- The default set cannot change your environment. Add each module that can.
- The list must have one module or more.
- `responder` needs `detection`.
- `api` needs the `[api]` section and one agent module or more, for example `monitor`.

```toml
[modules]
enabled = ["ingest", "detection", "monitor", "hunter", "analyst", "responder", "deception", "reporter"]
```

### `[telemetry]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `service_name` | Text | `"aegis"` | The name of the service in the trace data. |
| `log_format` | `"text"` or `"json"` | `"text"` | The format of the log lines. |
| `log_level` | `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"off"` | `"info"` | The level of the log and of the trace data. |
| `otlp_endpoint` | URL | Not set | The base URL of an OTLP/HTTP collector for trace data. |

The log goes to the standard error stream. With no `otlp_endpoint`, AEGIS exports no
trace data and uses no network for it.

```toml
[telemetry]
service_name = "aegis"
log_format = "json"
log_level = "info"
```

### `[bus]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kind` | `"nats"` or `"memory"` | `"nats"` | NATS JetStream, or a bus in the memory of the process. |
| `nats.urls` | List of URLs | `["nats://127.0.0.1:4222"]` | The NATS servers. Use `nats://` or `tls://`. |
| `nats.connection_name` | Text | `"aegis"` | The name of the connection on the server. |
| `nats.connect_timeout` | Duration | `"5s"` | The time limit for the first connection. |
| `nats.request_timeout` | Duration | `"5s"` | The time limit for one request. |
| `nats.auth.method` | `"none"`, `"user_password"`, `"token"`, `"credentials_file"` | `"none"` | The credentials. Refer to the list below. |
| `nats.tls.required` | Boolean | `false` | Refuse a connection that has no TLS. |
| `nats.tls.ca_file` | Path | Not set | Trust only the certificate authorities of this file. |
| `nats.tls.client_cert_file`, `nats.tls.client_key_file` | Path | Not set | The client certificate and key for mutual TLS. Set the two together. |
| `stream.name` | Text | `"AEGIS"` | The JetStream stream. |
| `stream.subjects` | List | `["aegis.>"]` | The subjects that the stream stores. |
| `stream.max_age` | Duration | `"7days"` | The retention time. `"0s"` sets no limit. |
| `stream.max_bytes` | Number | `1073741824` | The retention size. `0` sets no limit. |
| `stream.storage` | `"file"` or `"memory"` | `"file"` | The storage of the stream on the server. |
| `stream.replicas` | 1 to 5 | `1` | The number of copies of the stream. |
| `stream.manage` | Boolean | `true` | Let AEGIS create and update the stream. |
| `consumer.ack_wait` | Duration | `"30s"` | The server sends a message again after this time with no acknowledgement. |
| `consumer.pull_batch` | Number | `1` | The messages that a durable subscriber takes in one request. |
| `consumer.pull_expires` | Duration | `"10s"` | The life of one pull request. |

Credentials, by `nats.auth.method`:

- `user_password`: the keys `user` and `password`.
- `token`: the key `token`.
- `credentials_file`: the key `path` of a NATS credentials file.

The bus in the memory of the process uses only `stream.subjects`, `stream.max_age`, and
`stream.max_bytes`.

The starter configuration:

```toml
[bus]
kind = "memory"
```

NATS JetStream with a retention of two days:

```toml
[bus]
kind = "nats"

[bus.nats]
urls = ["nats://127.0.0.1:4222"]
connection_name = "aegis"
connect_timeout = "5s"
request_timeout = "5s"

[bus.nats.auth]
method = "none"

[bus.nats.tls]
required = false

[bus.stream]
name = "AEGIS"
subjects = ["aegis.>"]
max_age = "2days"
max_bytes = 1073741824
storage = "file"
replicas = 1
manage = true

[bus.consumer]
ack_wait = "30s"
pull_batch = 1
pull_expires = "10s"
```

### `[storage]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kind` | `"memory"` or `"postgres"` | None. The key is necessary. | Where the incidents, the graph, the embeddings, and the approvals are. |
| `url` | Text | None. Necessary for `postgres`. | The database URL. The URL is a secret. |
| `max_connections` | Number | `10` | The largest number of open connections. |
| `min_connections` | Number | `0` | The connections that the pool keeps open. |
| `acquire_timeout_seconds` | Number | `10` | The time to wait for a connection. |
| `statement_timeout_seconds` | Number | `30` | The time limit of one statement. `0` sets no limit. |

`kind = "memory"` takes no other key. The data is gone when the process stops.

`kind = "postgres"` needs PostgreSQL with the Apache AGE and pgvector extensions. At the
start, AEGIS runs its database migrations. The URL has the form
`postgres://user:password@host:port/database?sslmode=verify-full`. Use `verify-full` for
each server that is not on the same host.

The starter configuration:

```toml
[storage]
kind = "memory"
```

PostgreSQL. Set the URL with the override `AEGIS__STORAGE__URL`:

```toml
[storage]
kind = "postgres"
max_connections = 10
min_connections = 0
acquire_timeout_seconds = 10
statement_timeout_seconds = 30
```

### `[audit]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kind` | `"file"` or `"postgres"` | `"file"` | Where the audit log is. |
| `path` | Path | None. Necessary for `file`. | The audit file. The directory must exist. |

- `kind = "file"` is one append-only JSON Lines file. One process writes one file.
- `kind = "postgres"` uses the audit table of the database. It needs
  `storage.kind = "postgres"`, and it takes no `path`.

```toml
[audit]
kind = "file"
path = "data/audit.jsonl"
```

### `[model]`

With no `[model]` section, AEGIS uses no model. Detection tier 2 does not run, and the
agents use their deterministic paths.

Keys of one provider, `[model.providers.<name>]`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kind` | `"openai_compatible"` or `"anthropic"` | None. The key is necessary. | The format of the API. |
| `base_url` | URL | `https://api.anthropic.com` for `anthropic`. None for `openai_compatible`. | The base URL of the API. |
| `api_key_env` | Name of a variable | Not set | The variable that holds the API key. `anthropic` needs it. |
| `api_key_header` | Text | Not set | A header for the key, for example `api-key`. The default is `Authorization: Bearer`. |
| `chat_model` | Text | Not set | The chat model for a request and a route that name no model. |
| `embedding_model` | Text | Not set | The embedding model. Only `openai_compatible`. |
| `timeout` | Duration | `"60s"` | The time limit of one request. |
| `headers` | Table | Not set | Headers for each request. Put no secret here. |
| `max_tokens_field` | `"max_tokens"` or `"max_completion_tokens"` | `"max_tokens"` | The field for the output limit. Only `openai_compatible`. |
| `max_output_tokens` | Number | `4096` | The output limit for a request that sets no limit. Only `anthropic`. |

Keys of the routes and the budget:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `routes.default` | List of routes | Not set | The routes for a task type that has no list of its own. |
| `routes.<task>` | List of routes | Not set | The routes for `triage`, `analysis`, `planning`, `response_draft`, `reporting`, or `embedding`. |
| `provider` (in a route) | Text | None. The key is necessary. | The name of a provider. |
| `model` (in a route) | Text | Not set | The model of the route. |
| `budget.window` | Duration | `"1h"` | The length of the budget window. |
| `budget.total_tokens` | Number | Not set: no limit | The token limit for all task types together. |
| `budget.tasks.<task>` | Number | Not set: no limit | The token limit for one task type. |

The router uses the first route of a list. It uses the next route after an error that a
retry can correct, a refusal, or an operation that the provider does not support.

A local model for all task types:

```toml
[model.providers.local]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
chat_model = "qwen2.5:1.5b"
timeout = "60s"

[model.routes]
default = [{ provider = "local" }]

[model.budget]
window = "1h"
total_tokens = 2000000
```

A local model for triage, and a hosted gateway with a local fallback for the other task
types. This example needs the variable `AEGIS_GATEWAY_API_KEY`:

```toml
[model.providers.local]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
chat_model = "qwen2.5:1.5b"

[model.providers.gateway]
kind = "openai_compatible"
base_url = "https://llm-gateway.example.com/v1"
api_key_env = "AEGIS_GATEWAY_API_KEY"
chat_model = "gateway-large"
max_tokens_field = "max_completion_tokens"
headers = { "x-team" = "soc" }

[model.routes]
default = [{ provider = "gateway" }, { provider = "local" }]
triage = [{ provider = "local" }, { provider = "gateway", model = "gateway-small" }]

[model.budget]
window = "1h"
total_tokens = 2000000

[model.budget.tasks]
triage = 500000
```

### `[policy]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `paths` | List of paths | None. The key is necessary. | The policy files and directories. |
| `data` | List of paths | `[]` | Data files for the policy, in JSON or YAML. |
| `rule` | Text | `"data.aegis.response.decision"` | The decision rule. |
| `evaluation_time_limit_ms` | Number | `1000` | The time limit of one evaluation. Must be larger than 0. |

Load one complete policy. Refer to [policy.md](policy.md).

```toml
[policy]
paths = ["policies/examples/protected_entities.rego"]
data = ["policies/examples/protected_entities.yaml"]
rule = "data.aegis.response.decision"
evaluation_time_limit_ms = 1000
```

### `[rbac]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `roles` | Table: role name to a list of permissions | Empty | The permissions of each role. |

The permissions are `view_incidents`, `view_audit`, `approve_actions`, `manage_policy`,
`manage_connectors`, `run_playbooks`, and `administer`.

- No permission includes a different permission. Give each role each permission that it
  needs.
- A role that this table does not name gives no permission. `aegis config check` does not
  report a principal with such a role.
- Role names are case-sensitive.

```toml
[rbac.roles]
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]
admin = ["view_incidents", "view_audit", "manage_policy", "manage_connectors", "run_playbooks", "administer"]
```

### `[approval]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `four_eyes` | Boolean | `true` | The principal that requested an action cannot approve it. |
| `humans_only` | Boolean | `true` | Only a principal of the type `human` can decide. |

```toml
[approval]
four_eyes = true
humans_only = true
```

### `[detection]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pack` | Path | None. The key is necessary. | The directory of the detection pack. |
| `velocity.sign_in_burst.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.sign_in_burst.window_seconds` | Number | `60` | The time window of the count. |
| `velocity.sign_in_burst.failure_threshold` | Number | `20` | Failed sign-ins from one address that give a detection. |
| `velocity.sign_in_burst.distinct_user_threshold` | Number | `10` | Different users from one address that give a detection. |
| `velocity.sign_in_burst.cooldown_seconds` | Number | `900` | The time with no second detection for the same address. |
| `velocity.sign_in_burst.report_success_after_burst` | Boolean | `true` | Report a sign-in that succeeds in the cooldown. |
| `velocity.sign_in_burst.max_tracked_addresses` | Number | `100000` | The largest number of addresses in the state. |
| `velocity.privileged_self_assignment.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.privileged_self_assignment.require_privileged` | Boolean | `true` | Report only a role or permission that is privileged. |
| `velocity.privileged_self_assignment.severity` | Severity | `"high"` | The severity of the detection. |
| `velocity.credential_after_grant.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.credential_after_grant.window_seconds` | Number | `120` | The time after a grant in which a new credential gives a detection. |
| `velocity.credential_after_grant.max_tracked_applications` | Number | `50000` | The largest number of applications in the state. |
| `velocity.impossible_speed.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.impossible_speed.max_speed_kmh` | Number | `1000.0` | The largest speed that is possible. |
| `velocity.impossible_speed.min_distance_km` | Number | `500.0` | The smallest distance that the detector examines. |
| `velocity.impossible_speed.country_window_seconds` | Number | `1800` | The time window for two countries, for events with no coordinates. |
| `velocity.impossible_speed.cross_tenant_window_seconds` | Number | `60` | The time window for two resource tenants from two places. |
| `velocity.impossible_speed.cooldown_seconds` | Number | `900` | The time with no second detection for the same principal. |
| `velocity.impossible_speed.max_tracked_principals` | Number | `100000` | The largest number of principals in the state. |
| `velocity.machine_cadence.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.machine_cadence.window_seconds` | Number | `300` | The time window of one chain. |
| `velocity.machine_cadence.min_actions` | Number | `4` | The number of different actions in one chain. |
| `velocity.machine_cadence.max_median_gap_milliseconds` | Number | `5000` | A median gap up to this value is too short for a person. |
| `velocity.machine_cadence.max_coefficient_of_variation` | Number | `0.1` | A variation of the gaps up to this value is too regular for a person. |
| `velocity.machine_cadence.sensitive_actions` | List | Refer to the README of `aegis-detect` | The actions that make a chain sensitive. |
| `velocity.machine_cadence.supporting_actions` | List | `["sign_in", "api.call"]` | The other actions that are steps of a chain. |
| `velocity.machine_cadence.follow_addresses` | Boolean | `true` | Also follow each address, for a chain of two or more principals. |
| `velocity.machine_cadence.ignored_principals` | List | Empty | The identifiers of approved automations. |
| `velocity.machine_cadence.cooldown_seconds` | Number | `900` | The time with no second detection for the same key. |
| `velocity.machine_cadence.max_tracked_keys` | Number | `100000` | The largest number of keys in the state. |
| `velocity.endpoint_probe.enabled` | Boolean | `true` | Switch the detector on or off. |
| `velocity.endpoint_probe.window_seconds` | Number | `60` | The time window of the count. |
| `velocity.endpoint_probe.distinct_path_threshold` | Number | `20` | Different missing paths from one client that give a detection. |
| `velocity.endpoint_probe.missing_statuses` | List of numbers | `[404, 410]` | The HTTP statuses of a path that does not exist. |
| `velocity.endpoint_probe.decoy_paths` | List | Empty | Paths that no approved client asks for. One request gives a detection. |
| `velocity.endpoint_probe.decoy_path_severity` | Severity | `"medium"` | The severity of a decoy path detection. |
| `velocity.endpoint_probe.cooldown_seconds` | Number | `900` | The time with no second detection for the same client. |
| `velocity.endpoint_probe.max_tracked_clients` | Number | `100000` | The largest number of clients in the state. |
| `correlator.window_seconds` | Number | `3600` | The time window that links two detections. |
| `correlator.critical_technique_count` | Number | `3` | The number of ATT&CK techniques that makes an incident `critical`. |
| `correlator.max_incidents` | Number | `10000` | The largest number of incidents in the state. |
| `correlator.max_detections_per_incident` | Number | `200` | The largest number of detections in one incident. |
| `correlator.unlinked_kinds` | List of entity types | `["tenant", "role"]` | Entity types that do not link detections. |
| `triage.max_events` | Number | `20` | The largest number of events in one model request. |
| `triage.max_event_bytes` | Number | `49152` | The largest size of the events in one model request. |
| `triage.max_output_tokens` | Number | `512` | The output limit of one model request. |
| `triage.benign_min_confidence` | Number | `0.8` | The smallest confidence with which the model can give `benign`. |
| `triage.timeout_seconds` | Number | `60` | The time limit for one answer of the model. |
| `triage.quota_window_seconds` | Number | `3600` | The time window of the tier 2 quota. |
| `triage.max_requests_per_source` | Number | `120` | Model requests for the events of one source connector in one window. |
| `triage.max_requests_per_tenant` | Number | `240` | Model requests for one tenant in one window. |
| `triage.model` | Text | Not set | The model of tier 2. With no value, the router selects the model. |
| `runner.durable_name` | Text | `"aegis-detect"` | The durable name of the event subscription. |
| `runner.publish_attempts` | Number | `5` | The attempts to publish one message. |
| `runner.publish_backoff_milliseconds` | Number | `50` | The wait before the second attempt. It doubles after that. |
| `runner.max_incident_updates` | Number | `20` | The states of one incident that leave the engine in one window. Must be 1 or more. |
| `runner.incident_update_window_seconds` | Number | `60` | The window of `max_incident_updates`, in event time. Must be 1 or more. |

If many users share one address, for example behind a proxy, add `ip_address` to
`correlator.unlinked_kinds`.

**Flood protection.** An attacker can send events only to make AEGIS work. Three limits
stop this:

- A rule with the key `aegis.suppress` gives one detection for one key in a window. Refer
  to [detection-packs.md](detection-packs.md#suppression).
- `triage.max_requests_per_source` and `triage.max_requests_per_tenant` limit the model
  requests of tier 2. Above the quota, a detection stays `suspicious`, and the engine
  sends no request.
- `runner.max_incident_updates` limits the states of one incident. The engine holds the
  newest state over the limit until the window ends. The first state of an incident and
  a state with a higher severity always leave immediately. `aegis run` and
  `aegis replay` use this limit.

`GET /api/v1/status` shows the counts of the three limits in the field `flood`.

```toml
[detection]
pack = "detections/aegis-identity"

[detection.velocity.sign_in_burst]
enabled = true
window_seconds = 60
failure_threshold = 20
distinct_user_threshold = 10
cooldown_seconds = 900
report_success_after_burst = true
max_tracked_addresses = 100000

[detection.velocity.privileged_self_assignment]
enabled = true
require_privileged = true
severity = "high"

[detection.velocity.credential_after_grant]
enabled = true
window_seconds = 120
max_tracked_applications = 50000

[detection.velocity.impossible_speed]
enabled = true
max_speed_kmh = 1000.0
min_distance_km = 500.0
country_window_seconds = 1800
cross_tenant_window_seconds = 60
cooldown_seconds = 900
max_tracked_principals = 100000

[detection.velocity.machine_cadence]
enabled = true
window_seconds = 300
min_actions = 4
max_median_gap_milliseconds = 5000
max_coefficient_of_variation = 0.1
follow_addresses = true
ignored_principals = []
cooldown_seconds = 900
max_tracked_keys = 100000

[detection.velocity.endpoint_probe]
enabled = true
window_seconds = 60
distinct_path_threshold = 20
missing_statuses = [404, 410]
decoy_paths = []
decoy_path_severity = "medium"
cooldown_seconds = 900
max_tracked_clients = 100000

[detection.correlator]
window_seconds = 3600
critical_technique_count = 3
max_incidents = 10000
max_detections_per_incident = 200
unlinked_kinds = ["tenant", "role"]

[detection.triage]
max_events = 20
max_event_bytes = 49152
max_output_tokens = 512
benign_min_confidence = 0.8
timeout_seconds = 60
quota_window_seconds = 3600
max_requests_per_source = 120
max_requests_per_tenant = 240

[detection.runner]
durable_name = "aegis-detect"
publish_attempts = 5
publish_backoff_milliseconds = 50
max_incident_updates = 20
incident_update_window_seconds = 60
```

### `[agents]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `goal` | Text | `"Keep the environment of the operator safe."` | The goal of the operator, in natural language. |
| `monitor_events` | `"detected"`, `"all"`, `"none"` | `"detected"` | The events that the Monitor agent writes to the Defensive Graph. |
| `dry_run` | Boolean | `true` | The runtime sets `dry_run` on each action that an agent proposes. |
| `enabled_roles` | List of roles | All seven roles | The roles that can get tasks. The module set also limits the roles. |
| `tick_interval_seconds` | Number | `60` | The time between two periodic tasks. `0` stops them. |
| `bus_consumer` | Text | `"aegis-agents"` | The durable name of the bus subscriptions of the agents. |
| `limits.max_steps_per_incident` | Number | `64` | The tasks for one incident that one external input can cause. |
| `limits.max_task_depth` | Number | `16` | The largest length of a chain of tasks. |
| `limits.max_concurrency` | Number | `4` | The tasks that run at the same time. |
| `limits.max_queued_tasks` | Number | `10000` | The tasks that can wait in the queue. |
| `limits.max_actions_per_task` | Number | `16` | The actions that the runtime dispatches for one task. |
| `limits.task_timeout_seconds` | Number | `120` | The time limit for one task and for one answer of the dispatcher. |
| `monitor.sweep_limit` | Number | `50` | The open incidents that one sweep gives to the Analyst. |
| `hunter.model_guided` | Boolean | `true` | A hunt request in natural language uses the model and read-only tools. |
| `hunter.max_tool_steps` | Number | `6` | The model calls in one model-guided hunt. |
| `hunter.scan_limit` | Number | `500` | The graph nodes that one hunt reads for each node type. |
| `hunter.max_findings` | Number | `25` | The new findings that one task records. |
| `hunter.management_ports` | List of ports | 13 ports, for example `22` and `3389` | The ports that make an internet-exposed asset a finding. |
| `analyst.false_positive_min_confidence` | Number | `0.8` | The smallest model confidence that can close an incident as a false positive. |
| `analyst.max_context_entities` | Number | `20` | The entities for which the Analyst reads graph context. |
| `responder.refine_with_model` | Boolean | `true` | The Responder asks the model which optional actions to add. |
| `responder.max_actions_per_incident` | Number | `12` | The actions that the Responder proposes for one task. |
| `deception.max_honeytokens_per_task` | Number | `3` | The honeytokens that one task proposes. |
| `deception.scan_limit` | Number | `500` | The graph nodes and incidents that one task reads. |

```toml
[agents]
goal = "Keep the identities of this tenant safe."
monitor_events = "detected"
dry_run = true
enabled_roles = ["supervisor", "monitor", "hunter", "analyst", "responder", "deception", "reporter"]
tick_interval_seconds = 60
bus_consumer = "aegis-agents"

[agents.limits]
max_steps_per_incident = 64
max_task_depth = 16
max_concurrency = 4
max_queued_tasks = 10000
max_actions_per_task = 16
task_timeout_seconds = 120

[agents.monitor]
sweep_limit = 50

[agents.hunter]
model_guided = true
max_tool_steps = 6
scan_limit = 500
max_findings = 25
management_ports = [22, 23, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017]

[agents.analyst]
false_positive_min_confidence = 0.8
max_context_entities = 20

[agents.responder]
refine_with_model = true
max_actions_per_incident = 12

[agents.deception]
max_honeytokens_per_task = 3
scan_limit = 500
```

### `[response]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `dry_run` | Boolean | `true` | The dispatcher sets `dry_run` on each request. No connector changes anything. |
| `simulate_missing_connectors` | Boolean | `true` | With `dry_run`, an action type with no connector goes to the simulation connector. |
| `playbooks` | `"off"`, `"dry_run"`, `"live"` | `"dry_run"` | How the playbooks run. |
| `playbook_dir` | Path | Not set | The directory of the playbooks. |
| `execution_timeout_seconds` | Number | `120` | The time limit for one connector call. Must be larger than 0. |
| `environment` | Table | Not set | Data that the policy reads as `input.environment`. |
| `routes` | List of `{ kind, connector }` | Empty | The connector for an action type. |
| `graph` | Table | Not set | The Microsoft Graph action connector. |
| `webhook` | Table | Not set | The webhook action connector. |
| `revert` | Table | Not set | The timed revert. Refer to [`[response.revert]`](#responserevert). |

Keys of `[response.graph]`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | Text | `"entra-graph"` | The name of the connector. |
| `tenant_id` | Text | None. The key is necessary. | The tenant that the connector manages. |
| `tenant_aliases` | List | Empty | Other names that the telemetry uses for the same tenant. |
| `client_id` | Text | None. The key is necessary. | The client identifier of the application registration. |
| `client_secret` | Text | None. The key is necessary. | The client secret. Set it with an override. |
| `graph_base_url` | URL | `"https://graph.microsoft.com/v1.0"` | The base URL of Microsoft Graph. |
| `login_base_url` | URL | `"https://login.microsoftonline.com"` | The base URL of the sign-in service. |
| `scope` | Text | `"https://graph.microsoft.com/.default"` | The OAuth scope. |
| `timeout_seconds` | Number | `30` | The time limit for one HTTP request. |

Keys of `[response.webhook]`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | Text | `"webhook"` | The name of the connector. |
| `secret` | Text | None. The key is necessary. | The shared secret of the signature, 16 bytes or more. Set it with an override. |
| `endpoints` | List of `{ kind, url, reversible }` | None. The key is necessary. | One HTTPS endpoint for each action type. |
| `timeout_seconds` | Number | `30` | The time limit for one HTTP request. |

An action type is a name, for example `"block_ip"`. A custom action type is
`{ custom = "name" }`.

The starter configuration:

```toml
[response]
dry_run = true
playbooks = "dry_run"
playbook_dir = "playbooks"
```

A webhook connector, a route, and environment data for the policy. This example needs
the override `AEGIS__RESPONSE__WEBHOOK__SECRET`:

```toml
[response]
dry_run = true
simulate_missing_connectors = true
playbooks = "dry_run"
playbook_dir = "playbooks"
execution_timeout_seconds = 120

[response.webhook]
name = "soc-bridge"
timeout_seconds = 30

[[response.webhook.endpoints]]
kind = "notify"
url = "https://hooks.example.com/aegis/chat"

[[response.webhook.endpoints]]
kind = "open_ticket"
url = "https://tickets.example.com/aegis"

[[response.webhook.endpoints]]
kind = "block_ip"
url = "https://firewall.example.com/aegis/block"
reversible = true

[[response.webhook.endpoints]]
kind = { custom = "quarantine_mailbox" }
url = "https://mail.example.com/aegis"

[[response.routes]]
kind = "notify"
connector = "soc-bridge"

[response.environment]
maintenance_window = { start = "2026-03-01T22:00:00Z", end = "2026-03-02T02:00:00Z" }
```

The Microsoft Graph connector. This example needs the override
`AEGIS__RESPONSE__GRAPH__CLIENT_SECRET`:

```toml
[response]
dry_run = true
playbooks = "dry_run"
playbook_dir = "playbooks"

[response.graph]
name = "entra-graph"
tenant_id = "00000000-0000-0000-0000-000000000000"
tenant_aliases = ["contoso.example"]
client_id = "22222222-2222-2222-2222-222222222222"
graph_base_url = "https://graph.microsoft.com/v1.0"
login_base_url = "https://login.microsoftonline.com"
scope = "https://graph.microsoft.com/.default"
timeout_seconds = 30
```

The priority of the connectors for an action type with no route is: `graph`, `webhook`,
the action plugins, the honeytoken connector, and the simulation connector.

The simulation connector takes the built-in action types and the two friction actions,
`{custom: restrict_user_consent}` and `{custom: raise_friction}`, as dry runs. Its
outcome has `reversible: true` for an action type that has an inverse.

#### `[response.revert]`

The timed revert: a containment action with a revert time runs first, and AEGIS reverts
it at that time unless a person confirms it. Refer to [response.md](response.md).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | Boolean | `true` | With `false`, the table has no effect. |
| `store` | Path | None. The key is necessary. | The file that holds the pending reverts. One process uses one file. |
| `retry_base_seconds` | Number | `30` | The delay after the first revert attempt that fails. It doubles after each failure. |
| `retry_max_seconds` | Number | `1800` | The longest delay between two attempts. |
| `approval_poll_seconds` | Number | `60` | The time between two examinations of an approval that a revert waits for. |

```toml
[response.revert]
store = "data/pending-reverts.json"
retry_base_seconds = 30
retry_max_seconds = 1800
approval_poll_seconds = 60
```

- With no table, the timed revert is off. A request with a revert time that is not a dry
  run then does not run.
- A store file that is not valid stops the start.
- On Unix, only the owner can read the store file.

### `[[sources]]`

Each `[[sources]]` table is one source connector. The key `type` selects the connector.

Keys of `type = "file"`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | Text | None. The key is necessary. | The name of the connector. Events go to `aegis.events.{name}`. |
| `path` | Path | None. The key is necessary. | A JSON Lines file with one normalized event in each line. |
| `pace` | Table | `{ mode = "fast" }` | `fast`, or `{ mode = "timed", speed = 60.0 }` to keep the recorded time gaps, divided by `speed`. |
| `batch_size` | Number | `100` | The largest number of events in one batch. |

Keys of `type = "entra"`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | Text | None. The key is necessary. | The name of the connector. |
| `tenant_id` | Text | None. The key is necessary. | The tenant identifier or a verified domain name. |
| `client_id` | Text | None. The key is necessary. | The client identifier of the application registration. |
| `client_secret_env` | Name of a variable | Not set | The variable that holds the client secret. |
| `client_secret` | Text | Not set | The client secret. Use `client_secret_env`. Set only one of the two. |
| `login_base` | URL | `"https://login.microsoftonline.com"` | The base URL of the token service. |
| `graph_base` | URL | `"https://graph.microsoft.com"` | The base URL of Microsoft Graph. |
| `scope` | Text | `{graph_base}/.default` | The OAuth scope. |
| `poll_interval` | Duration | `"30s"` | The time between two reads. |
| `lookback` | Duration | `"5m"` | How far before the newest record each read starts. |
| `max_window` | Duration | `"1h"` | The longest time range of one read after a long stop. |
| `request_timeout` | Duration | `"30s"` | The time limit of one HTTP request. |
| `max_retry_after` | Duration | `"5m"` | The longest `Retry-After` delay that the connector waits for. |
| `rate_limit_retries` | Number | `3` | The times that the connector waits for `Retry-After` for one request. |
| `page_size` | 1 to 1000 | `500` | The records in one page. |
| `sign_ins` | Boolean | `true` | Read the user sign-in log. |
| `service_principal_sign_ins` | Boolean | `false` | Read the service principal sign-in log, a beta endpoint. |
| `directory_audits` | Boolean | `true` | Read the directory audit log. |

A connector name has ASCII letters, digits, `-`, and `_`, and 64 characters or fewer.

A file source:

```toml
[[sources]]
type = "file"
name = "replay"
path = "events.jsonl"
pace = { mode = "fast" }
batch_size = 100
```

An Entra ID source. This example needs the variable `AEGIS_ENTRA_CLIENT_SECRET`:

```toml
[[sources]]
type = "entra"
name = "entra-prod"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
client_secret_env = "AEGIS_ENTRA_CLIENT_SECRET"
login_base = "https://login.microsoftonline.com"
graph_base = "https://graph.microsoft.com"
poll_interval = "30s"
lookback = "5m"
max_window = "1h"
request_timeout = "30s"
max_retry_after = "5m"
rate_limit_retries = 3
page_size = 500
sign_ins = true
service_principal_sign_ins = false
directory_audits = true
```

### `[ingest]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `checkpoint_dir` | Path | Not set | The directory of the checkpoint files. With no value, the cursors are in memory. |
| `retry.max_retries` | Number | `5` | The retries in sequence before a source stops with its error. |
| `retry.initial_delay` | Duration | `"500ms"` | The delay before the first retry. It doubles after that. |
| `retry.max_delay` | Duration | `"30s"` | The longest delay before a retry. |

With a checkpoint directory, a source continues at its last position after a restart.

```toml
[ingest]
checkpoint_dir = "data/checkpoints"

[ingest.retry]
max_retries = 5
initial_delay = "500ms"
max_delay = "30s"
```

### `[plugins]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `dir` | Path | None. The key is necessary. | The directory of the plugin manifests. |
| `limits.max_memory_bytes` | Number | `67108864` | The memory of one plugin instance. |
| `limits.call_timeout_seconds` | Number | `30` | The time of one call into a plugin. |
| `limits.max_concurrent_calls` | Number | `4` | The calls that run in one plugin at the same time. |
| `limits.http_timeout_seconds` | Number | `10` | The time of one HTTP request of a plugin. |
| `limits.require_sha256` | Boolean | `false` | With `true`, a manifest with no `sha256` does not load. |

Refer to [connectors.md](connectors.md) for the manifest of a plugin.

```toml
[plugins]
dir = "plugins"

[plugins.limits]
max_memory_bytes = 67108864
call_timeout_seconds = 30
max_concurrent_calls = 4
http_timeout_seconds = 10
require_sha256 = true
```

### `[decoy]`

The decoy service: a tarpit, a maze, and a decoy model API for clients that have no
permission. It runs in `aegis run` with the module `ingest`. Refer to
[deception.md](deception.md). The README of
[`aegis-decoy`](../crates/decoy/README.md#configuration) lists all keys with their
ranges.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | Text | None. The key is necessary. | The connector name of the decoy, and `decoy_id` in its events. |
| `bind` | Address | None. The key is necessary. | The address of the listener. It must not be the address of `api.bind`. |
| `personas` | List | None. The key is necessary. | `tarpit`, `maze`, `model_api`: one persona or more. |
| `seed_env` | Text | None. The key is necessary. | The NAME of the variable that holds the seed: 32 to 1024 bytes. |
| `limits` | Table | Refer to the README | The connection, size, and time limits. |
| `tarpit`, `maze`, `model_api` | Table | Refer to the README | The settings of each persona. |
| `model_api.keys` | List of `{ id, value_env }` | Empty | The decoy keys. `value_env` is the NAME of the variable that holds the key. |
| `canary` | Table | `enabled = true`, `path_prefix = "/ref"` | The canary instruction. |
| `events` | Table | Refer to the README | The limits of the event queue. |

```toml
[decoy]
id = "decoy-lab"
bind = "127.0.0.1:8081"
personas = ["tarpit", "maze", "model_api"]
seed_env = "AEGIS_DECOY_SEED"

[[decoy.model_api.keys]]
id = "ht-decoy-model-key"
value_env = "AEGIS_DECOY_MODEL_KEY"
```

- Never use the address of a production endpoint.
- `id` must not be the name of a source in `[[sources]]`.
- Each decoy key is a honeytoken in the registry of AEGIS, with the `id` of the key.
- A build without the Cargo feature `decoy` refuses the section.

### `[evidence]`

The evidence archive: each detection, the events that caused it, and each state of an
incident, as JSON Lines. The sharing commands read it. Refer to
[sharing.md](sharing.md#the-evidence-archive).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | Boolean | `true` | With `false`, the section has no effect. |
| `path` | Path | None. The key is necessary. | The archive file. An older file has the same name and `.1`. |
| `max_bytes` | Number | `67108864` | The largest number of bytes on the disk. The smallest value is `65536`. |

```toml
[evidence]
path = "data/evidence.jsonl"
max_bytes = 67108864
```

With no section, the process writes no archive.

### `[share]`

The rules of `aegis report abuse` and `aegis indicators export`. Refer to
[sharing.md](sharing.md). The service does not use this section.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator_networks` | List of networks in CIDR form | Empty | All public networks of your organization. No document names an address in them. The commands refuse to run with an empty list. |
| `operator_domains` | List | Empty | The domains of your organization. No export gives them or their subdomains. |
| `permit_documentation_ranges` | Boolean | `false` | Permit the documentation ranges. Use it only with the recorded attack log. |
| `reporter.name`, `reporter.contact` | Text | Not set | The organization that sends a report, and how the receiver can reply. |
| `networks` | List of `{ prefix, name, abuse_contact }` | Empty | The hosting networks that you know. A report package then has one more report for each network. |

```toml
[share]
operator_networks = ["198.51.100.0/24"]
operator_domains = ["operator.example.org"]

[share.reporter]
name = "Example Security Team"
contact = "soc@operator.example.org"

[[share.networks]]
prefix = "203.0.113.0/24"
name = "AS64500 Example Hosting"
abuse_contact = "abuse@hosting.example"
```

### `[api]`

The operator API runs only with `"api"` in `modules.enabled`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `bind` | Address | `"127.0.0.1:8080"` | The listen address. The server has no TLS. |
| `allow_non_loopback` | Boolean | `false` | Permit an address that is not a loopback address. Set `true` only behind a proxy with TLS. |
| `console` | Boolean | `true` | Serve the web console at `/`. |
| `principals` | List of tables | Empty | The identities that can use the API. With no principal, each request is refused. |
| `limits.max_body_bytes` | 1 to 1048576 | `65536` | The largest request body. |
| `limits.request_timeout_seconds` | 1 to 300 | `30` | The time limit of one request. |
| `limits.default_page_size` | Number | `50` | The page size of a list with no `limit`. |
| `limits.max_page_size` | 1 to 1000 | `200` | The largest `limit`. |
| `limits.max_streams` | 1 to 1024 | `32` | The live feeds at the same time. |
| `limits.stream_keep_alive_seconds` | Number | `15` | The time between two keep-alive lines of a live feed. |

Keys of one principal, `[[api.principals]]`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | Text | None. The key is necessary. | The identifier of the principal, for example `alice@example.com`. |
| `kind` | `"human"`, `"agent"`, `"system"` | `"human"` | The type of the principal. |
| `roles` | List of role names | Empty | Names of `[rbac.roles]`. |
| `token_env` | Name of a variable | Not set | The variable that holds the token. A principal with no token uses only the chat. |

A token has 32 visible ASCII characters or more. Make one with `openssl rand -hex 32`.

Keys of ChatOps:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `chatops.slack.signing_secret_env` | Name of a variable | Not set | Switches the Slack endpoints on. |
| `chatops.slack.webhook_url_env` | Name of a variable | Not set | Switches the Slack notifications on. |
| `chatops.slack.team_id` | Text | Not set | Accept only this workspace. |
| `chatops.slack.response_hosts` | List | `["hooks.slack.com"]` | The hosts that the server sends button answers to. |
| `chatops.slack.users` | Table | Empty | Slack user identifier to principal `id`. |
| `chatops.teams.shared_secret_env` | Name of a variable | Not set | Switches the Teams endpoint on. |
| `chatops.teams.webhook_url_env` | Name of a variable | Not set | Switches the Teams notifications on. |
| `chatops.teams.require_timestamp` | Boolean | `true` | Refuse a message with no timestamp. |
| `chatops.teams.users` | Table | Empty | Teams user identifier to principal `id`. |
| `chatops.notifications.min_severity` | Severity | `"medium"` | The smallest incident severity that gives a message. |
| `chatops.notifications.request_timeout_seconds` | 1 to 60 | `10` | The time limit of one webhook request. |
| `chatops.notifications.max_attempts` | 1 to 10 | `3` | The attempts for one message. |
| `chatops.notifications.retry_backoff_ms` | 0 to 60000 | `500` | The wait before the second attempt. It doubles after that. |
| `chatops.notifications.durable_consumer` | Text | Not set | A durable name for the notification task. |

One principal with a token. This example needs the variable `AEGIS_TOKEN_ALICE`:

```toml
[modules]
enabled = ["ingest", "detection", "monitor", "analyst", "api"]

[rbac.roles]
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]

[api]
bind = "127.0.0.1:8080"
allow_non_loopback = false
console = true

[[api.principals]]
id = "alice@example.com"
kind = "human"
roles = ["analyst", "approver"]
token_env = "AEGIS_TOKEN_ALICE"

[api.limits]
max_body_bytes = 65536
request_timeout_seconds = 30
default_page_size = 50
max_page_size = 200
max_streams = 32
stream_keep_alive_seconds = 15
```

Slack and Teams. This example needs the variables `AEGIS_TOKEN_ALICE`,
`AEGIS_SLACK_SIGNING_SECRET`, `AEGIS_SLACK_WEBHOOK_URL`, `AEGIS_TEAMS_SECRET`, and
`AEGIS_TEAMS_WEBHOOK_URL`:

```toml
[modules]
enabled = ["ingest", "detection", "monitor", "analyst", "api"]

[rbac.roles]
viewer = ["view_incidents"]
approver = ["view_incidents", "approve_actions"]

[api]
bind = "127.0.0.1:8080"

[[api.principals]]
id = "alice@example.com"
roles = ["approver"]
token_env = "AEGIS_TOKEN_ALICE"

[[api.principals]]
id = "vera@example.com"
roles = ["viewer"]

[api.chatops.slack]
signing_secret_env = "AEGIS_SLACK_SIGNING_SECRET"
webhook_url_env = "AEGIS_SLACK_WEBHOOK_URL"
team_id = "T0123456"
response_hosts = ["hooks.slack.com"]

[api.chatops.slack.users]
U0ALICE = "alice@example.com"
U0VERA = "vera@example.com"

[api.chatops.teams]
shared_secret_env = "AEGIS_TEAMS_SECRET"
webhook_url_env = "AEGIS_TEAMS_WEBHOOK_URL"
require_timestamp = true

[api.chatops.teams.users]
"9f0e1d2c-0000-4000-8000-000000000001" = "alice@example.com"

[api.chatops.notifications]
min_severity = "medium"
request_timeout_seconds = 10
max_attempts = 3
retry_backoff_ms = 500
```

Refer to the README of [`aegis-api`](../crates/api/README.md) for the REST routes and
the ChatOps setup.

## Safe defaults

- `response.dry_run`, `agents.dry_run`, and `response.playbooks = "dry_run"` are the
  defaults. With them, no action changes your environment.
- With no `[modules]` section, the process runs `ingest`, `detection`, and `monitor`.
- With no `[model]` section, the process uses no model.
- With the default policy, a dry run is permitted, and a gated action needs the approval
  of a person.
- With no `api` in `[modules]`, the process opens no listener. With no `[decoy]` section,
  the process runs no decoy.
- With no `[response.revert]` table, an action with a revert time runs only as a dry run.
- With no `operator_networks` in `[share]`, the sharing commands write no document.

To permit changes, you must set all of these values:

| Key | Value |
| --- | --- |
| `response.dry_run` | `false` |
| `agents.dry_run` | `false` for the actions of the agents |
| `response.playbooks` | `"live"` for the actions of the playbooks |

The policy then decides each request. Read [policy.md](policy.md) before you set them.

## Limits

- The `aegis` program reads the configuration at the start only. To apply a change, stop
  the service and start it again.
- `[response.graph]`, `[response.webhook]`, `[storage]`, and `[bus.nats.auth]` have no key
  for the name of a secret variable. Use an environment override.
- One process loads one detection pack and one playbook directory. One process runs one
  decoy.
- The revert store and the evidence archive are files. They have no PostgreSQL form.
- `aegis config check` builds the application. It thus creates the audit file and runs
  the database migrations.
- The keys of `[plugins.limits]` are a part of the limits of the sandbox. The other limits
  have fixed values. Refer to [connectors.md](connectors.md#the-sandbox).
