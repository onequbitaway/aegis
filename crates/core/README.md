# aegis-core

`aegis-core` gives each AEGIS process the services that all subsystems use:

- **Configuration.** One TOML document, with overrides from environment variables.
- **Telemetry.** The `tracing` subscriber, with an optional OpenTelemetry trace exporter.
- **Module set.** The switch that selects the subsystems that a process runs.
- **Shutdown.** The signal that stops long-running loops.

The crate has no knowledge of the other subsystems. Each subsystem crate defines the type of
its configuration section and reads it through `Config`.

## Public API

| Item | Function |
| --- | --- |
| `Config::from_toml_str(text)` | Parses a TOML document. |
| `Config::load(path)` | Reads and parses a TOML file. |
| `Config::load_with_env(path)` | Reads a file, then applies the environment of the process. |
| `Config::with_overrides(variables)` | Applies overrides from an iterator of `(name, value)` pairs. |
| `Config::with_process_env()` | Applies the environment of the process as overrides. |
| `Config::section::<T>(name)` | Deserializes one top-level key into the type of the caller. |
| `Config::section_or_default::<T>(name)` | The same, but a missing section gives `T::default()`. |
| `Config::has_section(name)`, `Config::section_names()` | Show which sections the document has. |
| `TelemetryConfig`, `LogFormat`, `LogLevel` | The `[telemetry]` section. |
| `TelemetryConfig::from_config(&config)` | Reads the `[telemetry]` section. |
| `telemetry::init(&config)` | Builds the subscriber and installs it for the process. |
| `telemetry::subscriber(&config, writer)` | Builds the subscriber and does not install it. |
| `TelemetryGuard` | Stops the trace exporter when it is dropped. `shutdown()` returns the error. |
| `Module`, `ModuleSet` | The `[modules]` section. |
| `ModuleSet::from_config(&config)` | Reads the `[modules]` section and checks the rules. |
| `ModuleSet::new(modules)`, `all()`, `monitoring_only()` | Make a module set in code. |
| `ModuleSet::contains(module)`, `iter()` | Show which modules the process runs. |
| `Shutdown::new()`, `trigger()`, `is_triggered()`, `wait()` | The shutdown signal. |
| `Shutdown::child()` | A signal that follows its parent, but does not trigger it. |
| `Shutdown::listen_for_signals()` | Triggers the signal on Ctrl-C or SIGTERM. |

All functions that can fail return `aegis_contracts::Result`.

## Use the crate

```rust,no_run
use aegis_core::{Config, Module, ModuleSet, Shutdown, TelemetryConfig, telemetry};

#[tokio::main]
async fn main() -> aegis_contracts::Result<()> {
    let config = Config::load_with_env("aegis.toml")?;

    let _telemetry = telemetry::init(&TelemetryConfig::from_config(&config)?)?;
    let modules = ModuleSet::from_config(&config)?;

    let shutdown = Shutdown::new();
    shutdown.listen_for_signals()?;

    if modules.contains(Module::Ingest) {
        // Give `shutdown.child()` to the ingest loop.
    }

    shutdown.wait().await;
    Ok(())
}
```

A subsystem crate reads its section as follows:

```rust
use aegis_core::Config;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IngestConfig {
    batch_size: u32,
}

fn read(config: &Config) -> aegis_contracts::Result<IngestConfig> {
    config.section_or_default("ingest")
}
```

## Configure the process

### The configuration file

The file is a TOML document. Each top-level key is a section. A section is usually a table.
An array of tables is also a section.

```toml
[telemetry]
service_name = "aegis"
log_format = "json"
log_level = "info"
otlp_endpoint = "http://localhost:4318"

[modules]
enabled = ["ingest", "detection", "monitor"]
```

### Environment overrides

An environment variable can set one key. An override wins over the value in the file.

1. Start the name with `AEGIS__`.
2. Add the section name and the key name. Put `__` between the parts of the key path.
3. Use upper case or lower case. The name is not case-sensitive.

| Variable | Key |
| --- | --- |
| `AEGIS__TELEMETRY__SERVICE_NAME=aegis-dev` | `telemetry.service_name` |
| `AEGIS__TELEMETRY__LOG_LEVEL=debug` | `telemetry.log_level` |
| `AEGIS__MODELS__ROUTER__RETRIES=3` | `models.router.retries` |
| `AEGIS__MODULES__ENABLED=["ingest", "detection"]` | `modules.enabled` |

The text of the variable becomes a TOML value:

| Text | Result |
| --- | --- |
| `true` or `false` | A Boolean. |
| A TOML integer or a finite TOML float, for example `42` or `0.5` | A number. |
| A TOML string in quotation marks, for example `"42"` | The string in the quotation marks. |
| A TOML array, for example `["a", "b"]` | An array. |
| All other text | A string with the same text. |

Put quotation marks around digits that must stay a string. For example, a password of only
digits must be `AEGIS__STORE__PASSWORD='"123456"'` in a shell.

An override is an error in these conditions. The message names the variable and does not
show its value:

- The name has no key, has an empty part, or has more than 16 parts.
- A part matches two keys that are different only in case.
- Two variables set the same key, or one sets a key below the key of the other.
- A part of the key path, but not the last part, is a value that is not a table.

The sequence of the variables does not change the result or the error.

An override cannot set one element of an array. Set the full array, for example
`AEGIS__MODULES__ENABLED=["ingest", "detection"]`.

### Secrets in error messages

A configuration value can be a secret. The crate keeps the values of the file and of the
environment variables out of its error messages.

- A syntax error gives the line and the column, but not the text of the line.
- A section that does not match its type gives the section name, the key path, and the types.
  Example: ``the section `store` is not valid: key `pool_size`: invalid type: string, expected u32``.
- The `Debug` output of a `Config` shows only the section names.

A `Deserialize` implementation of a different crate can put a value in the text that it
writes. In that text, the crate puts `[redacted]` in the place of:

- Each string, date-time, and number of the section that has four or more characters.
- Each shorter string of the section that is a full word in a message.
- Each word of four or more characters in a message that is a part of a value of the section.
  A parser frequently shows only the part of a value that it could not read.

Example: ``key `url`: invalid character in the password '[redacted]'``.

These rules have limits:

- They cannot find a value that the implementation changed, for example an encoded form.
- They can hide a word that is not a secret, if a value of the section contains that word.
- A key is not a secret. Error messages show keys. Do not use a secret as a key.

Do more checks on a section after `Config::section` returns, and return `Error::Config` from
your crate. `ModuleSet::from_config` is an example. Do not put a value in your error. If you
do the checks in a `Deserialize` implementation, the rules above can hide words of your
message.

### The `[telemetry]` section

All keys are optional. An unknown key is an error.

| Key | Values | Default |
| --- | --- | --- |
| `service_name` | Text that is not empty. | `aegis` |
| `log_format` | `text`, `json` | `text` |
| `log_level` | `trace`, `debug`, `info`, `warn`, `error`, `off` | `info` |
| `otlp_endpoint` | The base URL of an OTLP/HTTP collector. | Not set. |

The subscriber writes the log lines to the standard error stream. The log level applies to
the log and to the trace data.

Trace export needs the Cargo feature `otlp`. A build without that feature rejects a
configuration that has `otlp_endpoint`. With no endpoint, the crate does not use the network.

Rules for `otlp_endpoint`:

- The URL must start with `http://` or `https://`.
- The exporter sends OTLP protobuf data to the path `/v1/traces` below the URL.
- The URL must not contain credentials, a query, or a fragment. To authenticate to the
  collector, set the standard variable `OTEL_EXPORTER_OTLP_HEADERS`.
- `service_name` is the `service.name` attribute of the trace data.

Keep the `TelemetryGuard` until the process stops. When the guard is dropped, the exporter
sends the spans that remain. This operation blocks the thread for a short time. If the
collector is not available, the exporter tries again and then writes an error event to the log.

Spans and events of the crates that do the export (`h2`, `hyper`, `opentelemetry`, `reqwest`,
`rustls`) go to the log only. They do not go to the collector, because each export would then
cause one more export.

### The `[modules]` section

`enabled` is the list of subsystems that the process starts. The names are `ingest`,
`detection`, `monitor`, `hunter`, `analyst`, `responder`, `deception`, `reporter`, and `api`.

With no `[modules]` section or no `enabled` key, the process runs `ingest`, `detection`, and
`monitor`. This set cannot change your environment. You must enable each module that can.

A module set must obey these rules. A set that breaks a rule is a configuration error that
names the rule.

| Rule | Meaning |
| --- | --- |
| `at-least-one-module` | The list must have one module or more. |
| `responder-requires-detection` | `responder` needs `detection` in the same process. |

## Stop the process

Make one `Shutdown` in the binary. Give a clone or a child to each long-running loop.

```rust
use aegis_core::Shutdown;

async fn run(shutdown: Shutdown) {
    loop {
        tokio::select! {
            () = shutdown.wait() => break,
            () = tokio::task::yield_now() => { /* Do one unit of work. */ }
        }
    }
}
```

- `trigger()` wakes all waiters of the handle, of its clones, and of its children.
- `child()` makes a signal for one subsystem. A trigger of the child does not stop the parent.
- `listen_for_signals()` triggers the signal on SIGINT or SIGTERM. On a system that is not
  Unix, it listens for Ctrl-C only. The listener is a thread of its own, so the function
  does not need a Tokio runtime.
- After the first stop request, a second SIGINT or SIGTERM does not stop the process. Set a
  time limit for the shutdown work in the binary.

## Cargo features

| Feature | Effect |
| --- | --- |
| `otlp` | Adds the OpenTelemetry OTLP trace exporter (HTTP with protobuf, TLS with `rustls`). |

## Test the crate

Run these commands from the root of the repository:

```sh
cargo test -p aegis-core --all-features
cargo test -p aegis-core
```

Run the two commands. The second command builds the crate without `otlp`. Only that build
has the test for an endpoint in a build that cannot export traces.

The tests do not use the network and do not need credentials:

- The collector in the `otlp` tests is a mock HTTP server on the same computer.
- The signal test sends SIGTERM and SIGINT to its own process with the `kill` program.
- The `child_process` test starts itself again as a child process. A test cannot change the
  environment of its own process safely, and it cannot read its own standard error stream.

To test code that logs, build a subscriber with a writer in memory:

```rust
use aegis_core::telemetry::{self, TelemetryConfig};

fn log_one_line() -> aegis_contracts::Result<()> {
    let (dispatch, _guard) = telemetry::subscriber(&TelemetryConfig::default(), std::io::sink)?;
    tracing::dispatcher::with_default(&dispatch, || tracing::info!("a log line"));
    Ok(())
}
```
