# AEGIS connector plugins

A connector plugin is a WebAssembly component that AEGIS loads at run time. You can write
a plugin in a language that compiles to a component. This directory has two examples in
Rust and the guide for authors.

| Directory | Contents |
| --- | --- |
| [`example-source`](example-source) | A source connector. It emits fixed sign-in events and pages with a cursor. |
| [`example-action`](example-action) | An action connector. It sends a notification to a webhook and obeys `dry_run`. |
| [`tests`](tests) | Plugins that have a fault on request. Only the tests of the plugin host use them. |

This directory is a Cargo workspace of its own. The root workspace excludes it, because
the generated guest bindings contain `unsafe` code.

## The interface

The WIT package `aegis:plugin` in [`../wit/plugin.wit`](../wit/plugin.wit) is the
interface. A plugin implements one of two worlds:

| World | The plugin exports | Result in AEGIS |
| --- | --- | --- |
| `source-connector` | `info`, `check`, `poll`, `fetch` | A `SourceConnector` |
| `action-connector` | `info`, `supported-actions`, `execute`, `revert` | An `ActionConnector` |

The host gives each plugin three functions:

| Import | Function |
| --- | --- |
| `config-get(key)` | Returns a value from the `[config]` table of the plugin manifest. |
| `log(level, message)` | Writes one message to the log of AEGIS. |
| `http-request(request)` | Asks the host to send one HTTP request. |

The plugin and the host exchange the AEGIS contract types as JSON text. The types are in
[`crates/contracts`](../crates/contracts/src). These are the JSON forms:

`ConnectorInfo`, the result of `info`. The host replaces `name` with the name from the
manifest.

```json
{ "name": "example-source", "vendor": "aegis", "product": "example", "version": "0.1.0" }
```

`EventBatch`, the result of `poll` and `fetch`:

```json
{
  "events": [
    {
      "id": "018f0000-0000-7000-8000-000000000002",
      "time": "2026-01-02T03:01:00Z",
      "source": { "connector": "example-source", "vendor": "aegis", "product": "example" },
      "class": "authentication",
      "action": "sign_in",
      "outcome": "failure",
      "severity": "informational",
      "actor": { "kind": "user", "id": "bob@example.com", "ip": "203.0.113.7" },
      "attributes": { "failure_reason": "The password is not correct." }
    }
  ],
  "next_cursor": "2"
}
```

`ActionRequest`, the parameter of `execute` and `revert`:

```json
{
  "id": "018f0000-0000-7000-8000-0000000000a1",
  "kind": "notify",
  "target": { "kind": "user", "id": "bob@example.com" },
  "parameters": { "message": "Check the account of Bob." },
  "requested_by": "responder",
  "reason": "Many failed sign-ins for one account.",
  "evidence": [],
  "dry_run": false,
  "requested_at": "2026-01-02T03:05:00Z"
}
```

`ActionOutcome`, the result of `execute` and `revert`. The `status` is `succeeded`,
`failed`, `simulated`, or `skipped`.

```json
{
  "action_id": "018f0000-0000-7000-8000-0000000000a1",
  "status": "succeeded",
  "connector": "example-action",
  "message": "Sent a notification about bob@example.com to the webhook.",
  "details": { "http_status": 200 },
  "reversible": false,
  "completed_at": "2026-01-02T03:05:01Z"
}
```

The result of `supported-actions` is a JSON array of action types, for example
`["notify", {"custom": "quarantine_mailbox"}]`.

## How to write a plugin in Rust

1. Make a library crate with the crate type `cdylib`. Add `wit-bindgen`:

   ```toml
   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   serde_json = "1.0.154"
   wit-bindgen = "0.63.0"
   ```

2. Generate the bindings from the WIT directory and implement the `Guest` trait:

   ```rust
   mod bindings {
       wit_bindgen::generate!({
           path: "../../wit",
           world: "source-connector",
       });
   }

   use bindings::aegis::plugin::host;
   use bindings::aegis::plugin::types::Error;
   use bindings::exports::aegis::plugin::source::Guest;

   struct MySource;

   impl Guest for MySource {
       fn info() -> String { /* The JSON form of `ConnectorInfo`. */ }
       fn check() -> Result<(), Error> { /* Check the configuration. */ }
       fn poll(cursor: Option<String>) -> Result<String, Error> { /* New events. */ }
       fn fetch(start: String, end: String, cursor: Option<String>) -> Result<String, Error> {
           /* One page of past events. */
       }
   }

   bindings::export!(MySource with_types_in bindings);
   ```

3. Read [`example-source/src/lib.rs`](example-source/src/lib.rs) or
   [`example-action/src/lib.rs`](example-action/src/lib.rs) for a complete plugin.

## Rules for a plugin

Obey these rules. The host enforces most of them.

- **Keep no state between calls.** The host makes a new instance for each call. Put the
  read position in the cursor.
- **Source plugins: use the cursor.** `poll` gets the cursor of the previous batch and
  returns `next_cursor` for the next call. `fetch` returns no `next_cursor` after the
  last page.
- **Action plugins: obey `dry_run`.** When `dry_run` is `true`, change nothing and
  return the status `simulated`. The host refuses the status `succeeded` for a dry run.
- **Return the correct error case.** The cases `unavailable`, `rate-limited`, and
  `timeout` tell AEGIS that a retry can succeed. Do not put a secret, a token, or a full
  payload in an error message or a log message.
- **Use `http-request` for all network access.** A plugin has no sockets. The host sends
  a request only to a destination in `allowed_hosts` of the manifest. The scheme must
  be `https`. Plain `http` is permitted only for a loopback address. The host does not
  follow a redirect.
- **Do not use the filesystem or the environment.** A plugin has no files, no
  environment variables, and no arguments. Get the configuration with `config-get`.
  Write messages with `log`: the standard output of a plugin goes nowhere.
- **Stay in the limits.** The operator sets the limits of the host. These are the
  default values: 64 MiB of memory, 30 seconds for one call, 8 MiB for one result, 32
  HTTP requests in one call, 4 MiB for one HTTP response, and 100 log messages in one
  call.

## How to build

Install the WebAssembly target one time:

```sh
rustup target add wasm32-wasip2
```

Build all plugins of this directory:

```sh
cd plugins
cargo build --target wasm32-wasip2 --release
```

The component files are in `plugins/target/wasm32-wasip2/release/`, for example
`example_source.wasm`.

## How to install

1. Copy the component file to the plugin directory of AEGIS.
2. Put a manifest file with the extension `.toml` in the same directory. Start with
   [`example-source/example-source.toml`](example-source/example-source.toml) or
   [`example-action/example-action.toml`](example-action/example-action.toml).
3. Set `name` to the name of the connector instance, and `kind` to `source` or `action`.
4. Set `allowed_hosts` to the destinations that the plugin needs. Give no more
   destinations than necessary.
5. Pin the component. Calculate its hash and put the value in `sha256`. On Linux, use
   `sha256sum`.

   ```sh
   shasum -a 256 example_source.wasm
   ```

6. Put the configuration of the plugin in the `[config]` table. Each value is a string.

AEGIS loads each manifest of the plugin directory with `PluginHost::load_dir`. Refer to
[`crates/plugin/README.md`](../crates/plugin/README.md) for all manifest keys, the
sandbox rules, and the limits.

## Other languages

A plugin can be in each language that has a tool for WebAssembly components and WASI
0.2. Generate the bindings for the world `source-connector` or `action-connector` from
`../wit/plugin.wit`. The host accepts the WASI 0.2 imports that such tools add, but it
gives them an empty context: no files, no environment, and no sockets.

The host does not support the WebAssembly GC proposal. Thus a language that compiles to
WebAssembly GC cannot make a plugin.
