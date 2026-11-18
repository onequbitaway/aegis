# aegis-ingest

Source connectors and the ingestion runner of AEGIS.

A source connector reads the telemetry of the operator and converts it to the normalized
`aegis_contracts::Event`. The ingestion runner publishes the events on the message bus.
Detection reads the events from the bus.

This crate only reads telemetry. It does not change the source system.

## Public API

| Item | Function |
| --- | --- |
| `IngestRunner` | Drives one `SourceConnector`: publish, checkpoint, retry, backfill. |
| `RetryPolicy` | The retry limit and the backoff delays of a runner. |
| `IngestStats` | A snapshot of the counters of a runner. |
| `RunOutcome` | Why a runner stopped without an error: `Completed` or `Cancelled`. |
| `SourceRegistry` | Holds named connectors, checks them, and builds their runners. |
| `SourceCheck` | The result of the check of one connector. |
| `CheckpointStore` | The trait for the cursor store: `load(name)` and `save(name, cursor)`. |
| `MemoryCheckpointStore` | A cursor store in memory. |
| `FileCheckpointStore` | A cursor store with one file for each connector. |
| `FileSource`, `FileSourceConfig`, `ReplayPace` | A connector that replays a JSON Lines file. |
| `EntraSource`, `EntraConfig` | A connector for Microsoft Entra ID through Microsoft Graph. |
| `entra::normalize` | Pure functions that convert Microsoft Graph records to events. |
| `SourceConfig` | The serde configuration of one connector. The `type` field selects it. |

## The runner

```rust
use std::sync::Arc;

use aegis_ingest::{FileCheckpointStore, FileSource, FileSourceConfig, IngestRunner};
use tokio_util::sync::CancellationToken;

let source = Arc::new(FileSource::new(FileSourceConfig::new(
    "replay",
    "fixtures/artex_style_attack.jsonl",
))?);
let checkpoints = Arc::new(FileCheckpointStore::new("/var/lib/aegis/checkpoints"));
let cancel = CancellationToken::new();
let runner = IngestRunner::new(source, bus, checkpoints, cancel.clone())?;

let outcome = runner.run().await?;
let stats = runner.stats();
```

`run` does these steps:

1. It loads the cursor of the connector from the checkpoint store.
2. It opens `SourceConnector::stream` at this cursor.
3. For each batch, it publishes each event as JSON to `aegis.events.{connector name}`.
4. Then it saves `EventBatch::next_cursor` to the checkpoint store.

The runner publishes a batch before it saves the cursor. A stop between the two steps
repeats the batch after the restart. The runner can repeat an event. It does not lose an
event. Each event has a stable identifier, so a consumer can remove a repeated event.

`backfill(range)` reads all pages of `SourceConnector::fetch` for a time range and
publishes them. A backfill does not read or change the checkpoint.

### Errors and retries

The runner retries after an error for which `Error::is_retryable` is `true`
(`Unavailable`, `RateLimited`, `Timeout`). The delay doubles with each retry, from
`initial_delay` up to `max_delay`. After `max_retries` retries in sequence, the runner
stops and returns the error. A batch that the runner delivers sets the count back to zero.

After an error in a stream, the runner opens the stream again at the last cursor.

The runner stops immediately and returns the error if the error is permanent, for example
`Unauthorized` or `Serialization`.

The defaults of `RetryPolicy` are 5 retries, from 500 ms to 30 s. Set other values with
`IngestRunner::with_retry`.

### Stop

Fire the `CancellationToken` to stop the runner. The runner completes the batch that is in
progress, saves its cursor, and returns `RunOutcome::Cancelled`. The token also stops a
wait before a retry.

### Connector names

A connector name is one token of the bus subject and a part of the checkpoint file name.
Use only ASCII letters, digits, `-`, and `_`, and not more than 64 characters. The runner,
the registry, and the stores reject all other names.

## Checkpoint stores

`FileCheckpointStore` keeps the file `{name}.checkpoint.json` for each connector in one
directory. For each save, it writes a temporary file, syncs it, and renames it. A crash
during a save leaves the old cursor in place. A checkpoint file that is damaged is an
`Error::Integrity`. The runner then stops. It does not start again from the beginning.

`MemoryCheckpointStore` loses the cursors when the process stops. Use it for tests and for
replays that must start at the beginning.

To use a different store, for example a database, implement `CheckpointStore`.

## The registry

```rust
let registry = SourceRegistry::from_configs(&settings.sources)?;
for check in registry.check().await {
    println!("{}: {:?}", check.name, check.result);
}
let runners = registry.runners(&bus, &checkpoints, &cancel, RetryPolicy::default())?;
```

`check` runs `SourceConnector::check` on all connectors and returns one result for each
connector. `runner(name, ...)` builds the runner of one connector.

## Configuration

`SourceConfig` reads one connector from a configuration file. The `type` field selects the
connector. An unknown field is an error.

```toml
[[sources]]
type = "file"
name = "replay"
path = "fixtures/artex_style_attack.jsonl"

[[sources]]
type = "entra"
name = "entra-prod"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
client_secret_env = "AEGIS_ENTRA_CLIENT_SECRET"
```

### File source

`FileSource` reads normalized events from a JSON Lines file: one `Event` in each line. It
needs no credentials and no network. Use it to run AEGIS offline.

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | | The name of the connector instance. |
| `path` | | The path of the JSON Lines file. |
| `pace` | `{ mode = "fast" }` | `fast` emits the events as fast as possible. `{ mode = "timed", speed = 60.0 }` keeps the recorded time gaps, divided by `speed`. |
| `batch_size` | `100` | The largest number of events in one batch. |

- The cursor is the number of lines that the caller already has.
- The connector ignores empty lines.
- A line that is not a valid event is `Error::Serialization` with the line number. The
  events before this line arrive first.
- The stream ends at the end of the file.

### Entra ID source

`EntraSource` reads these logs of one tenant through Microsoft Graph:

- User sign-ins: `GET {graph_base}/v1.0/auditLogs/signIns`.
- Service principal sign-ins (optional): `GET {graph_base}/beta/auditLogs/signIns` with the
  filter `signInEventTypes/any(t: t eq 'servicePrincipal')`.
- Directory audits: `GET {graph_base}/v1.0/auditLogs/directoryAudits`.

Give the application registration the Microsoft Graph application permission
`AuditLog.Read.All`. The connector needs no other permission. It sends only `GET` requests
to these endpoints and one `POST` request to the token endpoint.

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | | The name of the connector instance. |
| `tenant_id` | | The tenant GUID or a verified domain name. |
| `client_id` | | The application (client) identifier. |
| `client_secret_env` | | The name of the environment variable that holds the client secret. |
| `client_secret` | | The client secret. Prefer `client_secret_env`. Set only one of the two. |
| `login_base` | `https://login.microsoftonline.com` | The base URL of the token service. |
| `graph_base` | `https://graph.microsoft.com` | The base URL of Microsoft Graph. |
| `scope` | `{graph_base}/.default` | The OAuth scope of the token. |
| `poll_interval` | `30s` | The time between two reads of the live stream. |
| `lookback` | `5m` | How far before the newest record each read starts. |
| `max_window` | `1h` | The longest time range of one read after a long stop. |
| `request_timeout` | `30s` | The time limit of one HTTP request. |
| `max_retry_after` | `5m` | The longest `Retry-After` delay that the connector waits for. |
| `rate_limit_retries` | `3` | How many times the connector waits for `Retry-After` for one request. |
| `page_size` | `500` | The number of records in one page, from 1 to 1000. |
| `sign_ins` | `true` | Read the user sign-in log. |
| `service_principal_sign_ins` | `false` | Read the service principal sign-in log (a beta endpoint). |
| `directory_audits` | `true` | Read the directory audit log. |

For a national cloud, set `login_base` and `graph_base`. For example, use
`https://login.microsoftonline.us` and `https://graph.microsoft.us`.

**Token.** The connector gets a token with the OAuth 2.0 client credentials grant from
`{login_base}/{tenant_id}/oauth2/v2.0/token`. It keeps the token until 60 seconds before
the expiry. The client secret is in a `secrecy::SecretString`. `Debug` output, log lines,
and error messages do not contain the secret or the token.

**Transport.** The base URLs must use HTTPS. Plain HTTP is permitted only for a loopback
address, for local tests. The connector does not follow a redirect. It rejects an
`@odata.nextLink` that addresses a different host. Thus the token stays on the configured
host.

**Live stream.** The stream reads all enabled feeds, waits for `poll_interval`, and reads
again. Each batch has the new events of all feeds in time order.

- The cursor is a JSON object with one time for each feed: the time of the newest record
  that the connector read. Example: `{"sign_ins":"2026-11-03T09:10:31Z"}`. A bare RFC 3339
  time is also a valid cursor.
- With no cursor, the stream starts at the present time. Its first batch is empty and
  holds the start position.
- Each read starts `lookback` before the cursor, because Entra ID can add a record to the
  log some minutes after the time of the record. The connector does not emit a record two
  times in one stream. After a restart, it can emit the records of the lookback period
  again, with the same event identifiers.
- After a long stop, the connector reads the missed time in ranges of `max_window`.

**Backfill.** `fetch` reads one page of one feed for a time range and follows
`@odata.nextLink`. The feeds come one after the other. The events of one page are in time
order. The pages of a feed go from the newest records to the oldest records.

**Errors.**

| Condition | Error |
| --- | --- |
| HTTP 401 or 403, or the token service rejects the credentials | `Unauthorized` |
| HTTP 429 | `RateLimited` |
| HTTP 408 or 504, or no response in `request_timeout` | `Timeout` |
| Other HTTP 5xx, or no connection | `Unavailable` |
| The configuration is not valid, or a tenant or an endpoint does not exist | `Config`, `NotFound` |

After HTTP 401, the connector gets a new token one time and sends the request again.
After HTTP 429, the connector waits for the `Retry-After` time and sends the request again.
If the time is longer than `max_retry_after`, or after `rate_limit_retries` waits, the
result is `RateLimited`. The connector then sends no request to Microsoft Graph until the
`Retry-After` time is over. During this time, each read is `RateLimited` immediately. The
connector keeps a `Retry-After` time for one hour at most.

A record that has no identifier or no valid time cannot become an event. The connector
writes a warning to the log, counts the record in `EntraSource::rejected_records`, and
continues. A live stream reports such a record one time, although it reads the record again
in the lookback period.

**Limits.**

- Entra ID can add a record to the log late. The live stream does not read a late record
  if its time is more than `lookback` before the newest record that the connector read.
  Increase `lookback` if the tenant has a longer delay. Use `backfill` to read a time
  range again.
- One read of the live stream keeps all records of its time range in memory. Decrease
  `max_window` for a tenant with many sign-ins.
- The connector does not wait for `Retry-After` on the token endpoint. The result is
  `RateLimited`, and the runner retries with its backoff.

### Normalization of Entra ID records

The functions in `entra::normalize` do no I/O. Each event keeps the original record in
`Event::raw`. The functions write each GUID in lower case, so that one object has one
identifier in all events. The event identifier comes from the tenant, the record
identifier, and the record time. Thus the same record always gives the same event
identifier.

A sign-in record becomes an event with the class `Authentication` and the action
`sign_in`:

- The outcome is `Success` if `status.errorCode` is 0, and `Failure` for all other codes.
- The actor is the user (identifier, user principal name, IP address, user agent) or the
  service principal.
- The target is the application. For a service principal, the target is the resource.
- The attributes are `error_code`, `failure_reason`, `country`, `city`, `latitude`,
  `longitude`, `mfa_satisfied`, `app_id`, `app_name`, `resource_tenant`, `home_tenant`,
  `auth_protocol`, and some keys of `entra::normalize::attr`.
- `mfa_satisfied` is present only if the record shows the answer. It is `false` for a
  failed sign-in and for a service principal. It is `true` if the record names an MFA
  method, a Conditional Access policy that enforced MFA, or an MFA result in
  `status.additionalDetails` (for example `MFA completed in Azure AD`).

A directory audit record becomes an event with an action that depends on the activity:

| Activity | Action |
| --- | --- |
| Consent to application | `oauth.consent_grant` |
| Add service principal credentials | `app.credential_add` |
| Update application, certificates and secrets management | `app.credential_add` or `app.credential_remove` |
| Remove service principal credentials | `app.credential_remove` |
| Add member to role, and the completed PIM assignments | `role.assign` |
| Remove member from role, and the completed PIM removals | `role.remove` |
| Add app role assignment to service principal | `app.permission_grant` |
| Add service principal | `service_principal.create` |
| Add application | `app.create` |
| Add user | `user.create` |
| Update user | `user.update` |
| Reset or change of a user password | `user.password_reset` |
| Registration, change, or removal of security info | `mfa.method_change` |
| All other activities | The words of the activity in lower case with `.` between them. The class is `Other`. |

The attribute `privileged` is `true` for a directory role that Microsoft labels as
privileged, for example Global Administrator, Privileged Role Administrator, Application
Administrator, and Cloud Application Administrator. It is also `true` for a consent or a
permission grant that includes a permission with control of the directory, of credentials,
or of the mail and the files of all users.

If one service principal is the initiator and the target of a role assignment, `actor.id`
and `target.id` are the same.

The target of a consent, a credential change, and a permission grant is the object that
Entra ID names in the record. This is usually the service principal. The attribute `app_id`
holds the application (client) identifier. Use `app_id` to link these events to the
sign-ins of the application.

Only the activity `Consent to application` becomes `oauth.consent_grant`. The activity
`Add delegated permission grant` keeps its derived action
(`add.delegated.permission.grant`), because Entra ID writes the two records for one
consent.

## Tests

```sh
cargo test -p aegis-ingest --all-features
```

The tests use no network outside the loopback address and no real tenant. The tests of the
Entra ID source run against a `wiremock` server. All identifiers, names, and secrets in the
test data are examples.

| File | Contents |
| --- | --- |
| `tests/runner.rs` | Delivery of the 648 events of the attack log, checkpoints and restarts, retries, backfill, cancellation. |
| `tests/file_source.rs` | The JSON Lines connector: cursors, malformed lines, timed replay, configuration. |
| `tests/entra.rs` | The Entra ID connector: token, paging, live stream, backfill, HTTP 401 and 429, redirects. |
| `tests/registry.rs` | The registry and the configuration file. |
| `src/entra/normalize/tests.rs` | The conversion of each record type. |
