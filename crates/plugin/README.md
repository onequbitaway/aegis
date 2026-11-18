# aegis-plugin

`aegis-plugin` loads connectors that people write out of tree. A plugin is a WebAssembly
component. The host runs it in a sandbox and gives it to AEGIS as an ordinary
`Arc<dyn SourceConnector>` or `Arc<dyn ActionConnector>` value.

- The interface is the WIT package `aegis:plugin` in the [`wit`](../../wit) directory.
- Example plugins and the authoring guide are in the [`plugins`](../../plugins) directory.
- The engine is [Wasmtime](https://wasmtime.dev/) with the component model.

## Public API

| Item | Function |
| --- | --- |
| `PluginHost::new(HostLimits)` | Makes a host. Make one host for a process. |
| `PluginHost::load_source(&PluginManifest)` | Loads a source plugin. Returns `Arc<dyn SourceConnector>`. |
| `PluginHost::load_action(&PluginManifest)` | Loads an action plugin. Returns `Arc<dyn ActionConnector>`. |
| `PluginHost::load_dir(path)` | Loads each manifest (`*.toml`) of one directory. Returns `LoadedPlugins`. |
| `LoadedPlugins` | The fields `sources` and `actions`, in the order of the manifest file names. |
| `PluginManifest` | The data of one plugin. Use `from_file`, `from_toml_str`, or `new`. |
| `PluginKind` | `Source` or `Action`. |
| `HostLimits` | The resource limits of the sandbox. |

```rust
use aegis_plugin::{HostLimits, PluginHost};

let host = PluginHost::new(HostLimits::default())?;
let plugins = host.load_dir("/etc/aegis/plugins").await?;
for source in &plugins.sources {
    source.check().await?;
}
```

Call the load functions and the connector methods in a Tokio runtime.

`load_dir` stops at the first plugin that does not load, and returns its error. Thus a
plugin that fails its integrity check cannot go unnoticed.

## The plugin manifest

Each plugin has a TOML manifest next to its component file. The operator writes the
manifest. The plugin cannot change it.

```toml
name = "webhook-notify"
kind = "action"
component = "example_action.wasm"
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
poll_interval_ms = 30000
allowed_hosts = ["hooks.example.com", "127.0.0.1:8080"]

[config]
webhook_url = "https://hooks.example.com/services/T000/B000"
```

| Key | Necessary | Meaning |
| --- | --- | --- |
| `name` | Yes | The name of the connector instance. Use 1 to 64 characters from `a-z`, `A-Z`, `0-9`, `_`, and `-`. |
| `kind` | Yes | `source` or `action`. |
| `component` | Yes | The path of the component file, relative to the directory of the manifest. The path cannot contain `..`. |
| `sha256` | No | The SHA-256 of the component file. The host loads the file only if the hash is the same. |
| `poll_interval_ms` | No | The time between two `poll` calls of a source plugin. The default value is 30000. |
| `allowed_hosts` | No | The destinations for outbound HTTP. Each entry is `host` or `host:port`. The default value is an empty list: no network. |
| `[config]` | No | A table of strings. The plugin reads a value with `config-get`. |

A key that is not in this table is an error. The `Debug` output of a manifest hides the
values of `[config]`, because a value can be a secret.

## The sandbox

A plugin is not trusted. The sandbox is deny by default.

- **No ambient access.** A plugin has no filesystem, no environment variables, no
  arguments, no standard input, and no sockets. Its standard output goes nowhere. It can
  read the clock and get random numbers.
- **No other imports.** A component can import WASI and the `host` interface of
  `aegis:plugin`. A component that needs a different import does not load.
- **Network through the host only.** The only network path is the `http-request` import.
  The host sends the request, with these rules:
  - The host and the port must be in `allowed_hosts`. The match is exact: no wildcards
    and no subdomains. An entry without a port permits only the default port.
  - The scheme must be `https`. Plain `http` is permitted only for a loopback address
    (`127.0.0.0/8`, `::1`, or the name `localhost`).
  - A URL with a user name or a password is refused.
  - The host does not follow a redirect and does not try a request again.
  - A request to a loopback address does not use a proxy and does not ask DNS for
    `localhost`. Other requests use the proxy settings of the environment.
  - The plugin cannot set connection headers, for example `host`.
- **Limits.** Each call into a plugin has the limits of `HostLimits`.
- **Faults stay inside.** A trap in a plugin is an error of that one call. The host
  continues.
- **Output is not trusted.** The host decodes each result to the contract type. It sets
  the connector name in each event and in each action outcome. It refuses an action
  outcome that contradicts `dry_run`. It removes control characters from plugin text
  before the text goes to a log or an error.

The host links all WASI 0.2 interfaces, because the tools of many languages import them
in each component. The WASI context is empty, thus the calls of the plugin fail or return
nothing.

The engine does not support the WebAssembly GC proposal. A component that uses it does
not load. This is deliberate: refer to the comment in `src/sandbox.rs`.

### `HostLimits`

| Field | Default | Meaning |
| --- | --- | --- |
| `max_memory_bytes` | 64 MiB | The total linear memory of one plugin instance. |
| `max_transfer_bytes` | 8 MiB | The data that the host copies out of the plugin in one transfer: one result, or the parameters of one host function. |
| `call_timeout` | 30 s | The time of one call. The time includes the HTTP requests of the call. |
| `max_concurrent_calls` | 4 | The calls that run in one plugin at the same time. More calls wait. |
| `max_component_bytes` | 32 MiB | The size of a component file. |
| `http_timeout` | 10 s | The time of one HTTP request. |
| `max_http_response_bytes` | 4 MiB | The size of one HTTP response body. |
| `max_http_requests_per_call` | 32 | The HTTP requests of one call. A refused request counts. |
| `max_log_messages_per_call` | 100 | The log messages of one call. The host drops the remainder. |
| `require_sha256` | `false` | With `true`, a manifest without `sha256` does not load. |

The host also limits each instance to 1024 WASI resources and 1 MiB of random bytes in
one WASI call.

### Concurrency

The host makes a new instance for each call. Thus a connector is `Send + Sync`, calls
from many tasks run at the same time, and a plugin keeps no state between calls. A
plugin keeps its position in the cursor.

Plugin code runs on the task of the caller, on async Wasmtime. It gives control back to
the runtime at least every 10 ms. The host compiles a component and decodes a large
result on a blocking thread. When the caller drops the future of a call or drops a
stream, the plugin code stops.

### The event stream

`SourceConnector::stream` calls `poll` of the plugin again and again. The first call is
immediate. Then the host waits for `poll_interval_ms` between two calls. The host sends
the last cursor that the plugin returned. An error is one item of the stream, and the
stream continues after it. The stream ends when the caller drops it.

## Errors

| Condition | `aegis_contracts::Error` |
| --- | --- |
| The manifest or a limit is not valid, or the file is not a correct component. | `Config` |
| The manifest file or the component file does not exist. | `NotFound` |
| The hash of the component is not the hash in the manifest. | `Integrity` |
| The plugin returns an error. | The variant with the same name. The case `other` is `Other`. |
| The plugin returns JSON that is not the contract type. | `Serialization` |
| The call is not complete at the deadline. | `Timeout` |
| The plugin needs more memory than the limit. | `BudgetExceeded` |
| The plugin traps, or the sandbox stops it for a different reason. | `Other` |
| The action type is not in the list that the plugin declared. | `Unsupported` |

Each error message starts with `plugin <name>`.

## How to test

Install the WebAssembly target one time. The file `rust-toolchain.toml` does this
automatically when you use `rustup`.

```sh
rustup target add wasm32-wasip2
```

Run the tests from the root of the repository:

```sh
cargo test -p aegis-plugin --all-features
```

The integration tests build the guest plugins in `plugins/` with `cargo` and load them
through the host. The first run compiles the guests. A later run uses the cache in
`plugins/target`. If the guests do not build, the test shows the output of `cargo`.

The tests use no network. A `wiremock` server on a loopback address is the HTTP
destination.

| Test file | Subject |
| --- | --- |
| `tests/source_plugin.rs` | The example source plugin: `info`, `check`, `fetch`, and `stream`. |
| `tests/action_plugin.rs` | The example action plugin: dry run, live request, and `allowed_hosts`. |
| `tests/sandbox.rs` | Plugins that have a fault: loop, sleep, trap, memory, bad JSON, and more. |
| `tests/loading.rs` | Manifests, hashes, and `load_dir`. |
