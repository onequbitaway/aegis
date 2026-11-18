# Connectors

A connector joins AEGIS to one system of the operator. This document tells you how to
write a connector, as native Rust code and as a WebAssembly plugin. Each part has a
worked example.

AEGIS is defensive only. A source connector only reads telemetry. An action connector
changes only the environment of the operator, through the administrative interface of
the product. Do not write a connector that acts on a system that the operator does not
own.

## Contents

- [The two connector types](#the-two-connector-types)
- [The connectors that AEGIS has](#the-connectors-that-aegis-has)
- [Native or plugin](#native-or-plugin)
- [The contracts](#the-contracts)
- [A native source connector and a native action connector](#a-native-source-connector-and-a-native-action-connector)
- [A connector as a WebAssembly plugin](#a-connector-as-a-webassembly-plugin)
- [Rules for each connector](#rules-for-each-connector)
- [Limits](#limits)

## The two connector types

| Type | Contract | Function |
| --- | --- | --- |
| Source connector | `aegis_contracts::SourceConnector` | Reads the telemetry of one system and converts each record to the normalized `Event`. |
| Action connector | `aegis_contracts::ActionConnector` | Does response actions in one system. The dispatcher calls it after the policy permits the action. |

## The connectors that AEGIS has

| Connector | Type | Configuration | Function |
| --- | --- | --- | --- |
| File source | Source | `[[sources]]` with `type = "file"` | Reads normalized events from a JSON Lines file. |
| Entra ID source | Source | `[[sources]]` with `type = "entra"` | Reads the sign-in log and the directory audit log of one Microsoft Entra ID tenant. |
| Microsoft Graph | Action | `[response.graph]` | `disable_service_principal`, `disable_user`, `kill_session`, `revoke_credential`, `rotate_credential`. |
| Webhook | Action | `[response.webhook]` | Sends a signed JSON document to an HTTPS endpoint of the operator, for each action type that has an endpoint. |
| Honeytokens | Action | Always present | `deploy_honeytoken`: records a decoy in the honeytoken registry. |
| Simulation | Action | Present with `response.dry_run = true` | Reports a dry run for an action type that has no other connector. It refuses each request that is not a dry run. |
| Plugins | Source or action | `[plugins]` | Each WebAssembly plugin of the plugin directory. |

Refer to [configuration.md](configuration.md) for the keys. Refer to the READMEs of
[`aegis-ingest`](../crates/ingest/README.md) and [`aegis-respond`](../crates/respond/README.md)
for the details of each connector.

## Native or plugin

| | Native connector | WebAssembly plugin |
| --- | --- | --- |
| Language | Rust | A language that compiles to a WebAssembly component with WASI 0.2 |
| Loaded by | A program that you build with the `aegis-app` library | The `aegis` program, from the plugin directory |
| Isolation | None. The code has all rights of the AEGIS process. | A sandbox with no files, no environment, and no sockets |
| Network | All that the process can reach | Only the hosts in `allowed_hosts`, through the host |
| State | The connector can keep state | No state between calls |

Use a plugin for code that you do not fully trust. Use a plugin also to add a connector
to the `aegis` program with no new build of AEGIS.

## The contracts

### `SourceConnector`

| Function | What you must do |
| --- | --- |
| `info()` | Return the name of the connector instance, the vendor, the product, and the version. |
| `check()` | Make sure that the connector can reach its source system. |
| `stream(cursor)` | Open a live stream of batches. Start after `cursor`, or at the present time with no cursor. |
| `fetch(range, cursor)` | Return one page of past events in a time range. Return no `next_cursor` after the last page. |

- Put the position after each batch in `EventBatch::next_cursor`. The ingestion runner
  saves that value and gives it back after a restart.
- Give each event a stable identifier. The runner can send a batch again after a stop,
  and a stable identifier lets a reader find the repeat.
- Use the event vocabulary for `Event::action` and `Event::attributes`. The detection
  rules read these names. Refer to [detection-packs.md](detection-packs.md#the-event-vocabulary).
- The name of a connector has ASCII letters, digits, `-`, and `_`, and 64 characters or
  fewer. Events go to the bus subject `aegis.events.{name}`.
- Return the correct error variant. The runner tries again after `Unavailable`,
  `RateLimited`, and `Timeout`. It stops after each other error.

### `ActionConnector`

| Function | What you must do |
| --- | --- |
| `info()` | Return the name of the connector, the vendor, the product, and the version. |
| `supported_actions()` | Return the action types that the connector can do. |
| `execute(request)` | Do one action, and return an `ActionOutcome`. |
| `revert(request)` | Undo an action. The default implementation returns `Error::Unsupported`. |

- **Obey `dry_run`.** If `request.dry_run` is `true`, change nothing. Return the status
  `simulated` and say what the connector would do.
- Return the status `succeeded` only after the change is complete.
- Put no secret in the outcome, in an error, or in a log line.
- The dispatcher calls the connector only after the policy and, if necessary, a person
  permitted the action. A connector must not do a policy check of its own in place of
  that.

## A native source connector and a native action connector

This example is one small program. It has a source connector for the sign-in log of a
VPN gateway. It also has an action connector that writes notifications and tickets to a
journal file. The program adds the two connectors to the application with `AppBuilder::source`
and `AppBuilder::action_connector`.

The sample log is a password spray: 12 failed sign-ins for 12 users from one
documentation address. All data is example data.

### Make the program

1. Make a directory next to the checkout of the repository. This procedure uses the
   name `aegis` for the checkout.

   ```sh
   mkdir -p ../native-connectors/src
   ```

2. Write the file `../native-connectors/Cargo.toml`:

   ```toml
   [package]
   name = "native-connectors"
   version = "0.1.0"
   edition = "2024"
   publish = false

   [dependencies]
   aegis-app = { path = "../aegis/crates/app", default-features = false }
   aegis-contracts = { path = "../aegis/crates/contracts" }
   aegis-core = { path = "../aegis/crates/core" }
   async-trait = "0.1.92"
   chrono = { version = "0.4.45", default-features = false, features = ["clock", "serde", "std"] }
   futures = "0.3.34"
   serde_json = "1.0.154"
   tokio = { version = "1.54.1", features = ["macros", "rt-multi-thread"] }
   uuid = "1.29.2"
   ```

   `default-features = false` builds the application with no database, no plugin host,
   and no HTTP server. This example needs none of them.

3. Copy the lock file of the repository. The build then uses the same dependency
   versions as AEGIS.

   ```sh
   cp Cargo.lock ../native-connectors/
   ```

4. Write the file `../native-connectors/src/main.rs`:

   ```rust
   //! A native source connector and a native action connector for AEGIS.
   //!
   //! The source reads the sign-in log of a VPN gateway of the operator. The action
   //! connector writes notifications and tickets to a journal file of the operator.

   use std::io::Write as _;
   use std::net::IpAddr;
   use std::path::PathBuf;
   use std::sync::Arc;

   use aegis_app::{App, RunOptions, starter};
   use aegis_contracts::action::{
       ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
   };
   use aegis_contracts::common::{EntityKind, EntityRef, EventId, TimeRange};
   use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action, attr};
   use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
   use aegis_contracts::{Error, Result};
   use aegis_core::{Config, Shutdown};
   use async_trait::async_trait;
   use chrono::{DateTime, Duration, Utc};

   /// One record of the gateway log, in the format of the vendor.
   #[derive(Clone)]
   struct GatewayRecord {
       serial: u32,
       time: DateTime<Utc>,
       user: String,
       address: IpAddr,
       accepted: bool,
   }

   /// A source connector for the sign-in log of a VPN gateway.
   struct GatewaySource {
       name: String,
       records: Vec<GatewayRecord>,
   }

   impl GatewaySource {
       /// Converts one vendor record to the normalized event.
       fn normalize(&self, record: &GatewayRecord) -> Event {
           let actor = Actor::new(EntityKind::User, record.user.clone())
               .with_name(record.user.clone())
               .with_ip(record.address);
           let event = Event::new(
               record.time,
               EventSource::new(self.name.clone(), "example", "vpn_gateway"),
               EventClass::Authentication,
               action::SIGN_IN,
               actor,
           )
           // The same record always gives the same event identifier.
           .with_id(EventId(uuid::Uuid::from_u128(u128::from(record.serial))))
           .with_target(EntityRef::new(EntityKind::Resource, "vpn-gateway-1"));
           if record.accepted {
               event.with_outcome(Outcome::Success)
           } else {
               event
                   .with_outcome(Outcome::Failure)
                   .with_attribute(attr::FAILURE_REASON, "The password is not correct.")
           }
       }

       /// The cursor is the number of records that the caller already has.
       fn offset(cursor: Option<&str>) -> Result<usize> {
           cursor.map_or(Ok(0), |text| {
               text.parse()
                   .map_err(|_| Error::InvalidInput("the cursor is not a number".to_owned()))
           })
       }
   }

   #[async_trait]
   impl SourceConnector for GatewaySource {
       fn info(&self) -> ConnectorInfo {
           ConnectorInfo {
               name: self.name.clone(),
               vendor: "example".to_owned(),
               product: "vpn_gateway".to_owned(),
               version: env!("CARGO_PKG_VERSION").to_owned(),
           }
       }

       async fn check(&self) -> Result<()> {
           // A real connector sends one cheap read request to the source system here.
           Ok(())
       }

       async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
           let offset = Self::offset(cursor.as_deref())?.min(self.records.len());
           let events: Vec<Event> = self.records[offset..]
               .iter()
               .map(|record| self.normalize(record))
               .collect();
           let batch = EventBatch {
               events,
               next_cursor: Some(self.records.len().to_string()),
           };
           // This log is complete, so the stream ends after one batch. A live connector
           // returns a stream that waits for new records.
           Ok(Box::pin(futures::stream::iter([Ok(batch)])))
       }

       async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
           let offset = Self::offset(cursor.as_deref())?;
           let events = self
               .records
               .iter()
               .filter(|record| range.contains(record.time))
               .skip(offset)
               .map(|record| self.normalize(record))
               .collect();
           Ok(EventBatch {
               events,
               next_cursor: None,
           })
       }
   }

   /// An action connector that writes notifications and tickets to a journal file.
   struct JournalConnector {
       path: PathBuf,
   }

   #[async_trait]
   impl ActionConnector for JournalConnector {
       fn info(&self) -> ConnectorInfo {
           ConnectorInfo {
               name: "soc-journal".to_owned(),
               vendor: "example".to_owned(),
               product: "journal".to_owned(),
               version: env!("CARGO_PKG_VERSION").to_owned(),
           }
       }

       fn supported_actions(&self) -> Vec<ActionKind> {
           vec![ActionKind::Notify, ActionKind::OpenTicket]
       }

       async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
           let line = format!("{} {}: {}", request.requested_at, request.target.id, request.reason);
           let (status, message) = if request.dry_run {
               // A dry run changes nothing. It reports what the connector would do.
               let message = format!("Would write one line to {}.", self.path.display());
               (ActionStatus::Simulated, message)
           } else {
               let mut file = std::fs::OpenOptions::new()
                   .create(true)
                   .append(true)
                   .open(&self.path)
                   .map_err(|error| Error::Unavailable(format!("cannot open the journal: {error}")))?;
               writeln!(file, "{line}")
                   .map_err(|error| Error::Unavailable(format!("cannot write the journal: {error}")))?;
               let message = format!("Wrote one line to {}.", self.path.display());
               (ActionStatus::Succeeded, message)
           };
           Ok(ActionOutcome {
               action_id: request.id,
               status,
               connector: self.info().name,
               message,
               details: serde_json::Value::Null,
               reversible: false,
               completed_at: Utc::now(),
           })
       }
   }

   /// Makes the log of a password spray: 12 failed sign-ins for 12 users from one address.
   fn sample_records() -> Vec<GatewayRecord> {
       let start = DateTime::<Utc>::from_timestamp(1_793_696_400, 0).unwrap_or_default();
       let address: IpAddr = [203, 0, 113, 80].into();
       (0..12)
           .map(|index| GatewayRecord {
               serial: index + 1,
               time: start + Duration::seconds(i64::from(index)),
               user: format!("user-{index:02}@example.com"),
               address,
               accepted: false,
           })
           .collect()
   }

   #[tokio::main]
   async fn main() -> Result<()> {
       let directory = std::env::args()
           .nth(1)
           .map(PathBuf::from)
           .ok_or_else(|| Error::InvalidInput("give the path of a new directory".to_owned()))?;

       // The starter directory has a working configuration. Each action is a dry run.
       starter::write(&directory)?;
       let config = Config::load(directory.join(starter::CONFIG_FILE))?;

       let source = GatewaySource {
           name: "vpn-gateway".to_owned(),
           records: sample_records(),
       };
       let journal = JournalConnector {
           path: directory.join("data/soc-journal.log"),
       };
       let app = Arc::new(
           App::builder(&config)
               .base_dir(&directory)
               .source(Arc::new(source))
               .action_connector(Arc::new(journal))
               .build()
               .await?,
       );

       // Run the service in a task. Stop it when the response to the log is complete.
       let shutdown = Shutdown::new();
       shutdown.listen_for_signals()?;
       let service = tokio::spawn({
           let (app, shutdown) = (app.clone(), shutdown.clone());
           async move { app.run_with(shutdown, RunOptions::default()).await }
       });
       app.wait_until(std::time::Duration::from_secs(30), || {
           let app = app.clone();
           async move { app.progress().playbook_runs == 1 && app.actions().total() == 3 }
       })
       .await?;
       shutdown.trigger();
       let summary = service
           .await
           .map_err(|error| Error::other("the service task", error))??;

       println!(
           "events: {}, detections: {}, playbook runs: {}",
           summary.progress.events_processed,
           summary.progress.detections,
           summary.progress.playbook_runs
       );
       // The journal has each request that went to the dispatcher, with its result.
       let mut lines: Vec<String> = Vec::new();
       for record in app.actions().records() {
           let result = serde_json::to_value(&record.result)?;
           let outcome = &result["disposition"]["executed"];
           lines.push(format!(
               "{} requested {:?} on {}: {} (connector {})",
               record.request.requested_by,
               record.request.kind,
               record.request.target.id,
               outcome["status"].as_str().unwrap_or("not executed"),
               outcome["connector"].as_str().unwrap_or("none"),
           ));
       }
       lines.sort();
       for line in lines {
           println!("{line}");
       }
       app.close().await;
       Ok(())
   }
   ```

### What the code shows

- **`normalize`** converts one vendor record to an `Event`. It uses the action
  `sign_in` and the attribute `failure_reason` of the event vocabulary. It makes the
  event identifier from the serial number of the record.
- **`stream`** starts at the cursor. The cursor is the number of records that the caller
  has.
- **`execute`** obeys `dry_run`. In a dry run, it writes no line and returns the status
  `simulated`.
- **`main`** writes a starter directory, and adds the two connectors to the application
  of that configuration. A connector of `action_connector` has priority over the
  configured connectors for its action types.

### Run the program

```sh
cargo run --manifest-path ../native-connectors/Cargo.toml -- /tmp/aegis-native
```

```text
events: 12, detections: 1, playbook runs: 1
playbook:block-password-spray-source requested BlockIp on 203.0.113.80: simulated (connector simulation)
playbook:block-password-spray-source requested Notify on security-operations: simulated (connector soc-journal)
responder requested BlockIp on 203.0.113.80: simulated (connector simulation)
```

What the output shows:

- The source connector delivered 12 events. The velocity detector found the password
  spray.
- The playbook `block-password-spray-source` and the Responder agent proposed actions.
- The `notify` request went to the native connector `soc-journal`. The starter
  configuration makes each action a dry run, so the connector wrote no line.
- `block_ip` has no connector in this program. It went to the simulation connector.

The directory argument must be a new directory. The program writes the starter files
there, and it does not replace a file.

Check the audit log of the run:

```sh
aegis audit verify --path /tmp/aegis-native/data/audit.jsonl
```

```text
Audit log /tmp/aegis-native/data/audit.jsonl
  Records checked: 22
  Chain: valid
```

The program stops the service when the three requests are in the journal. The number of
records can thus be different in your run.

### Other native connectors to read

| File | Contents |
| --- | --- |
| [`crates/ingest/src/file.rs`](../crates/ingest/src/file.rs) | The file source: a cursor and a timed replay. |
| [`crates/ingest/src/entra/`](../crates/ingest/src/entra) | The Entra ID source: tokens, pages, a live stream, and error mapping. |
| [`crates/respond/src/connectors/webhook.rs`](../crates/respond/src/connectors/webhook.rs) | The webhook connector: a signed request and `revert`. |
| [`crates/testkit/src/source.rs`](../crates/testkit/src/source.rs) | A small source connector for tests. |

## A connector as a WebAssembly plugin

A plugin is a WebAssembly component. The `aegis` program loads each plugin of the plugin
directory at the start, and runs it in a sandbox.

### The interface

The WIT package `aegis:plugin` in [`wit/plugin.wit`](../wit/plugin.wit) is the
interface. A plugin implements one of two worlds:

| World | The plugin exports | Result in AEGIS |
| --- | --- | --- |
| `source-connector` | `info`, `check`, `poll`, `fetch` | A source connector |
| `action-connector` | `info`, `supported-actions`, `execute`, `revert` | An action connector |

The host gives each plugin three functions:

| Import | Function |
| --- | --- |
| `config-get(key)` | Returns a value from the `[config]` table of the plugin manifest. |
| `log(level, message)` | Writes one message to the log of AEGIS. |
| `http-request(request)` | Asks the host to send one HTTP request. |

The plugin and the host exchange the contract types as JSON text: `ConnectorInfo`,
`EventBatch`, `ActionRequest`, and `ActionOutcome`. The README of
[`plugins`](../plugins/README.md) shows each JSON form and how to write a plugin in
Rust.

### The manifest

Each plugin has a TOML manifest next to its component file. The operator writes the
manifest. The plugin cannot change it.

| Key | Necessary | Meaning |
| --- | --- | --- |
| `name` | Yes | The name of the connector instance. |
| `kind` | Yes | `source` or `action`. |
| `component` | Yes | The path of the component file, relative to the directory of the manifest. |
| `sha256` | No | The SHA-256 of the component file. The host loads the file only if the hash is the same. |
| `poll_interval_ms` | No | The time between two `poll` calls of a source plugin. The default is 30000. |
| `allowed_hosts` | No | The destinations for HTTP requests. Each entry is `host` or `host:port`. The default is no network. |
| `[config]` | No | A table of text values. The plugin reads a value with `config-get`. |

A key that is not in this table is an error.

### The sandbox

A plugin is not trusted. The sandbox denies each access that the list below does not
permit.

- A plugin has no filesystem, no environment variables, no arguments, and no sockets.
- A plugin can read the clock and get random numbers.
- The only network path is `http-request`. The host sends the request only to a
  destination in `allowed_hosts`. The match is exact, with no wildcards.
- The scheme must be `https`. Plain `http` is permitted only for a loopback address.
- The host does not follow a redirect.
- The host makes a new instance for each call. A plugin keeps no state between calls.
- The host sets the connector name in each event and in each action outcome.
- The host refuses the status `succeeded` for a dry run, and the status `simulated` for a
  request that is not a dry run.
- A trap in a plugin is an error of that one call. The host continues.

The limits of one plugin:

| Limit | Default | Configuration key |
| --- | --- | --- |
| Memory of one instance | 64 MiB | `plugins.limits.max_memory_bytes` |
| Time of one call | 30 s | `plugins.limits.call_timeout_seconds` |
| Calls at the same time | 4 | `plugins.limits.max_concurrent_calls` |
| Time of one HTTP request | 10 s | `plugins.limits.http_timeout_seconds` |
| A manifest must have `sha256` | No | `plugins.limits.require_sha256` |
| Data that the host copies out of the plugin in one transfer | 8 MiB | None |
| Size of a component file | 32 MiB | None |
| Size of one HTTP response body | 4 MiB | None |
| HTTP requests in one call | 32 | None |
| Log messages in one call | 100 | None |

Refer to the README of [`aegis-plugin`](../crates/plugin/README.md) for the full rules.

### Worked example: build and install the example plugins

The repository has two example plugins in Rust:

- [`plugins/example-source`](../plugins/example-source/src/lib.rs) emits five fixed
  sign-in events and pages with a cursor.
- [`plugins/example-action`](../plugins/example-action/src/lib.rs) does the action
  `notify`: it sends a JSON message to a webhook, and it obeys `dry_run`.

Do these steps in the root of the repository.

1. Build the plugins. The file `rust-toolchain.toml` installs the target
   `wasm32-wasip2`.

   ```sh
   (cd plugins && cargo build --target wasm32-wasip2 --release --locked)
   ```

2. Make a starter directory with a plugin directory.

   ```sh
   aegis init --dir /tmp/aegis-plugins
   mkdir /tmp/aegis-plugins/plugins
   ```

3. Copy the two component files and the two manifests to the plugin directory.

   ```sh
   cp plugins/target/wasm32-wasip2/release/example_source.wasm \
       plugins/target/wasm32-wasip2/release/example_action.wasm \
       plugins/example-source/example-source.toml \
       plugins/example-action/example-action.toml \
       /tmp/aegis-plugins/plugins/
   ```

4. Calculate the hash of each component file. On Linux, use `sha256sum`.

   ```sh
   shasum -a 256 /tmp/aegis-plugins/plugins/example_source.wasm \
       /tmp/aegis-plugins/plugins/example_action.wasm
   ```

   ```text
   1703729f71fca078402cb19cf901040e38357e25b256d0eb3becb19bd65f50d9  /tmp/aegis-plugins/plugins/example_source.wasm
   f425ea123862e5b74cd10e087f551a862db3154ae76054d89acdf7d7ddff85de  /tmp/aegis-plugins/plugins/example_action.wasm
   ```

   The hashes of your build can be different.

5. Open `/tmp/aegis-plugins/plugins/example-source.toml`. Replace the comment line
   `# sha256 = "..."` with the hash of `example_source.wasm`. Set `poll_interval_ms` to
   `1000`, so that the example reads all events in some seconds. The lines then read:

   ```text
   sha256 = "1703729f71fca078402cb19cf901040e38357e25b256d0eb3becb19bd65f50d9"
   poll_interval_ms = 1000
   ```

6. Open `/tmp/aegis-plugins/plugins/example-action.toml`. Replace the comment line
   `# sha256 = "..."` with the hash of `example_action.wasm`. The line then reads:

   ```text
   sha256 = "f425ea123862e5b74cd10e087f551a862db3154ae76054d89acdf7d7ddff85de"
   ```

   This manifest permits one destination, `hooks.example.com`, which is an example name.
   For a real webhook, set `allowed_hosts` and `webhook_url` to your values.

7. Add this section at the end of `/tmp/aegis-plugins/aegis.toml`:

   ```toml
   [plugins]
   dir = "plugins"

   [plugins.limits]
   require_sha256 = true
   ```

8. Check the configuration.

   ```sh
   aegis config check --config /tmp/aegis-plugins/aegis.toml
   ```

   ```text
   The configuration /tmp/aegis-plugins/aegis.toml is valid.
     agents_dry_run: true
     api: off
     bus: memory
     connectors: webhook-notify, honeytokens, simulation
     dispatcher_dry_run: true
     model: false
     modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter
     playbook_mode: dry_run
     playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, respond-to-honeytoken-trip
     rule_pack: aegis-identity
     rules: 9
     sources: example-source
     storage: memory
   ```

   The action plugin is the connector `webhook-notify`. The source plugin is the source
   `example-source`.

### Worked example: run the source plugin

1. Run the service.

   ```sh
   AEGIS__TELEMETRY__LOG_LEVEL=info aegis run --config /tmp/aegis-plugins/aegis.toml
   ```

   The log shows the plugins and the source:

   ```text
   INFO aegis_app::app: loaded the connector plugins sources=1 actions=1
   INFO aegis_ingest::runner: ingestion started connector=example-source resumed=false
   ```

2. Wait for 10 seconds. Then press Ctrl-C.

   ```text
   AEGIS stopped. Events examined: 5. Detections: 0. Incident changes: 0. Playbook runs: 0.
   ```

   The plugin delivered its five events in batches of two. The five events are normal
   sign-ins, so they give no detection.

### Worked example: see the action plugin in a dry run

`aegis replay` examines the recorded attack log with the same configuration. The
playbooks send `notify` requests.

```sh
aegis replay --config /tmp/aegis-plugins/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run \
    --audit-file /tmp/aegis-plugins/data/replay-audit.jsonl
```

Each `notify` request now goes to the plugin:

```text
  notify                      other security-operations                       playbook:block-password-spray-source      executed: simulated (connector webhook-notify)
  notify                      other security-operations                       playbook:contain-rogue-service-principal  executed: simulated (connector webhook-notify)
  notify                      other security-operations                       playbook:respond-to-honeytoken-trip       executed: simulated (connector webhook-notify)
```

The requests are dry runs. The plugin thus sent no HTTP request.

### Worked example: a changed component does not load

If the component file changes after you pin it, AEGIS does not start. This command adds
one byte to the file:

```sh
printf 'x' >> /tmp/aegis-plugins/plugins/example_action.wasm
aegis config check --config /tmp/aegis-plugins/aegis.toml
```

```text
The configuration /tmp/aegis-plugins/aegis.toml has 1 problems:
  1. integrity error: [plugins] plugin webhook-notify: the SHA-256 of the component file is d3e8cf4c35d6e7f8146eb4095184f2ec35803dd07b34fd2200dafd2ab70d6af3, but the manifest expects f425ea123862e5b74cd10e087f551a862db3154ae76054d89acdf7d7ddff85de
```

## Rules for each connector

- **Defensive only.** Read only the telemetry of the operator. Change only the
  environment of the operator.
- **Use official interfaces.** Use the administrative API of the product, with
  credentials that the operator gives.
- **Least privilege.** Ask for the smallest permission that the connector needs. A
  source connector needs only read access.
- **Obey `dry_run`.** A dry run sends no request that changes a system.
- **Use HTTPS.** Do not follow a redirect with a credential.
- **Keep secrets out of text.** Put no secret, token, or full payload in an error, an
  outcome, or a log line.
- **Map errors correctly.** `Unavailable`, `RateLimited`, and `Timeout` tell AEGIS that a
  retry can succeed. `Unauthorized`, `InvalidInput`, and `Config` tell AEGIS that it
  cannot.
- **Test with no network.** Use a mock server at the HTTP boundary.

## Limits

- The `aegis` program cannot load a native connector that is not a part of AEGIS. A
  native connector needs a program that you build with the `aegis-app` library, as in
  the example above. Use a plugin to add a connector to the `aegis` program.
- The dispatcher has no path for `revert`. A connector can implement it, but no command
  and no API route calls it.
- A credential rotation of the Microsoft Graph connector gives the new secret to a
  receiver in the memory of the process. The `aegis` program has no vault connection.
- A plugin cannot keep state between calls, and it cannot start work on its own. The
  host calls it.
- A language that compiles to WebAssembly GC cannot make a plugin.
- The repository has no connector for EDR products, firewalls, cloud platforms, or SIEM
  products. Use the webhook connector or a plugin for them.
