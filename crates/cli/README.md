# aegis-cli

`aegis-cli` builds the command-line program `aegis`. The program runs AEGIS as a service,
makes a starter directory, shows a demonstration, and examines event files, audit logs, and
configuration files.

The program is a thin layer on `aegis-app`. It is defensive only.

## Commands

| Command | Function |
| --- | --- |
| `aegis run --config <file>` | Runs the service until SIGINT or SIGTERM. With the module `api`, it also runs the operator API. |
| `aegis init --dir <dir>` | Writes a working starter directory. Replaces no file. |
| `aegis demo [--dir <dir>]` | Replays the recorded attack log in a new starter directory. |
| `aegis replay --config <file> --events <jsonl>` | Examines an event file and prints the report. |
| `aegis monitor --events <jsonl> [--config <file>]` | Prints each detection and each incident of an event file. Takes no action. |
| `aegis audit verify --path <file>` | Checks the hash chain of an audit log file. |
| `aegis audit show --path <file> [--limit N]` | Prints the newest records of an audit log file. |
| `aegis config check --config <file>` | Reports each problem of a configuration. Starts nothing. |

All commands have the option `--format text|json`. The default is `text`.

## Output and exit status

- A report goes to the standard output stream. The log goes to the standard error stream.
- The exit status is 0 only if the command did its work.
- A failure writes `error:` and the cause to the standard error stream, and the exit status
  is 1. A command line that is not valid has the exit status 2.

## Start quickly

```sh
# See AEGIS detect and contain the recorded attack, as a dry run with no model.
aegis demo

# Make a starter directory, check it, and run the service.
aegis init --dir ./aegis
aegis config check --config ./aegis/aegis.toml
aegis run --config ./aegis/aegis.toml
```

To use the web console and the REST API, start the operator API:

1. In `./aegis/aegis.toml`, add `"api"` to `enabled` in `[modules]`.
2. Remove the comment mark from the lines of the `[api]` section at the end of the file.
3. Put a token in the variable that `token_env` names, and run the service:

```sh
export AEGIS_TOKEN_ALICE="$(openssl rand -hex 32)"
aegis config check --config ./aegis/aegis.toml
aegis run --config ./aegis/aegis.toml
```

4. Open `http://127.0.0.1:8080/` and enter the token.

## The commands in detail

### `aegis run`

The command reads the configuration file, applies the `AEGIS__` environment variables,
installs the log subscriber of the `[telemetry]` section, builds the application, and runs
it. SIGINT or SIGTERM stops the service. Each component then completes the work that is in
progress. If one component fails, the command stops all components and exits with status 1.

A relative path in the configuration file starts at the directory of that file.

#### The operator API

With `api` in `[modules] enabled`, the command also runs the operator API of `aegis-api`:
the REST API, the web console at `/`, and ChatOps. The server uses the incident store, the
Defensive Graph, the audit log, the approval queue, the bus, and the agent runtime of the
service. The `[rbac]` section gives the permissions of each API principal.

- The server listens on `api.bind`. The default is `127.0.0.1:8080`. The server has no
  TLS. Refer to the README of `aegis-api` for all keys of the `[api]` section.
- Before the service starts, the command reads the token of each principal from the
  environment and opens the listener. If one of these steps fails, the command starts
  nothing and exits with status 1.
- A stop signal stops the server with the service. The server lets each open request
  complete. It also waits for each approval decision that is in progress.
- If the server fails, the command stops all components and exits with status 1.
- An approval through the REST API, the console, Slack, Teams, or gRPC runs the approved
  action one time. If the HTTP request ends first, for example at its time limit, the
  action still completes, and the audit log has the result.
- A playbook run through the API obeys `response.playbooks`: with `off`, the API has no
  playbook, and with `dry_run`, each run is a dry run.

These configurations stop the command at the start with an error that names the section:

| Configuration | Error |
| --- | --- |
| `api` in `[modules]`, and no `[api]` section | The section `api` is missing. |
| `api` in `[modules]`, and no agent module, for example `monitor` | The module `api` needs the agent runtime. |
| `api` in `[modules]`, in a build with no Cargo feature `api` | The module `api` needs the Cargo feature `api`. |
| An `[api]` section, in a build with no Cargo feature `api` | The section needs the Cargo feature `api`. |
| A principal with `token_env`, and the variable is not set | The message names the principal and the variable. |

The function `services` in `src/commands.rs` is the place to start one more long-running
component from the services of the application.

### `aegis init`

The command writes `aegis.toml`, the detection pack (`detections/`), the policies
(`policies/`), the sample playbooks (`playbooks/`), and the directory `data/`. The binary
holds these files, so the command needs no checkout of the repository.

The starter configuration changes nothing in your environment: in-memory storage, the
in-process bus, a file audit log, dry runs only, and no model. It opens no listener.

The file has the `[api]` section of the operator API as a comment: the bind address, and
one principal with its roles and the name of its token variable. The roles are roles of the
`[rbac.roles]` table of the same file.

If one of the files exists, the command writes no file and exits with status 1.

### `aegis demo`

The command does `init` in a new directory, and then replays the recorded attack log
(`fixtures/artex_style_attack.jsonl`, which the binary holds) as a dry run with no model.
Without `--dir`, the directory is a new temporary directory. The command does not read the
`AEGIS__` environment variables.

The report has the detections with their ATT&CK identifiers, the incident, each action with
its result, and the audit result: the number of records and the state of the chain. The
exit status is 0 only if the chain verifies, in the open log and in the file on the disk.

### `aegis replay`

The command examines each event of a JSON Lines file with the configuration, and prints the
same report as `demo`. The exit status is 1 if the audit chain is not valid.

| Option | Effect |
| --- | --- |
| `--dry-run` | Makes each action a dry run, also when the configuration permits changes. |
| `--audit-file <file>` | Writes the audit log to this file. Use it when a service holds the audit file of the configuration. |

Without `--dry-run`, the command obeys the configuration. A configuration that is live can
then change your environment.

### `aegis monitor`

The command is a monitoring-only session. A file source reads the event file, the
ingestion runner publishes each event on the bus, and the detection engine reads the bus.
The command prints each detection and each incident state when it occurs, and a summary at
the end. With `--format json`, each line is one JSON value with a `type` field.

The session runs only the modules `ingest`, `detection`, and `monitor`. No component of
these modules can take an action. The session uses the in-process bus, the in-memory
storage, and an audit log in a temporary directory. It does not touch the bus, the storage,
or the audit log of the configuration.

With `--config`, the session uses the rule pack and the detection settings of that
configuration. Without it, the session uses the starter configuration.

### `aegis audit verify` and `aegis audit show`

`verify` reads the file and checks the hash chain. It does not open the log for append, so
it can run while a service writes the file. If the chain is not valid, the report gives the
first invalid sequence and the reason, and the exit status is 1.

`show` prints the newest records, one line for each record, and the state of the chain.

### `aegis config check`

The command reports each problem of a configuration:

1. It reads all sections and the files that they name: the rule pack, the policy, the
   playbooks, the model settings, and the source settings. It checks each value of the
   `[api]` section and the rules of the module `api`. It reports all problems of this
   step, not only the first one.
2. If step 1 finds no problem, it builds the application. This step connects to the bus
   and to the database, runs the database migrations, and opens the audit log. With the
   module `api`, it then reads each secret that the `[api]` section names.

The command starts no source, no detection, no agent, and no server. It opens no listener.
The exit status is 1 if the configuration has a problem. Each problem names its section.
The report has the key `api`: the address in `api.bind`, or `off`.

## Cargo features

| Feature | Effect |
| --- | --- |
| `postgres` | PostgreSQL storage and the PostgreSQL audit log. |
| `plugins` | WebAssembly connector plugins. |
| `otlp` | The OpenTelemetry trace exporter. |
| `api` | The operator API: the module `api` and the `[api]` section. |
| `grpc` | The gRPC services of the operator API, on the port of the REST API. It includes `api`. |

`postgres`, `plugins`, `otlp`, and `api` are default features. `grpc` is not. Each one goes
to the same feature of `aegis-app`. The monitoring-only build has none of them, and it has
no HTTP server:

```sh
cargo build -p aegis-cli --no-default-features
```

To build the program with the gRPC services:

```sh
cargo build -p aegis-cli --features grpc
```

## TLS

The program installs the `aws-lc-rs` provider of rustls as the default of the process at
the start of `main`.

## Test the program

```sh
cargo test -p aegis-cli --all-features
```

`tests/cli.rs` runs the built program. The tests use temporary directories, no network
outside the loopback address, and no credentials.

One test starts `aegis run` with the operator API on a loopback port that the operating
system selects, sends requests to it, and stops it with SIGTERM. This test runs only on a
Unix system. It sends the signal with the `kill` program.

```sh
cargo test -p aegis-cli --no-default-features
```

This command tests the build with no operator API.
