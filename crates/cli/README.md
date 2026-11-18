# aegis-cli

`aegis-cli` builds the command-line program `aegis`. The program runs AEGIS as a service,
makes a starter directory, shows a demonstration, and examines event files, audit logs, and
configuration files.

The program is a thin layer on `aegis-app`. It is defensive only.

## Commands

| Command | Function |
| --- | --- |
| `aegis run --config <file>` | Runs the service until SIGINT or SIGTERM. |
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

## The commands in detail

### `aegis run`

The command reads the configuration file, applies the `AEGIS__` environment variables,
installs the log subscriber of the `[telemetry]` section, builds the application, and runs
it. SIGINT or SIGTERM stops the service. Each component then completes the work that is in
progress. If one component fails, the command stops all components and exits with status 1.

A relative path in the configuration file starts at the directory of that file.

The function `services` in `src/commands.rs` is the place to start one more long-running
component from the services of the application, for example an operator API.

### `aegis init`

The command writes `aegis.toml`, the detection pack (`detections/`), the policies
(`policies/`), the sample playbooks (`playbooks/`), and the directory `data/`. The binary
holds these files, so the command needs no checkout of the repository.

The starter configuration changes nothing in your environment: in-memory storage, the
in-process bus, a file audit log, dry runs only, and no model.

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
   playbooks, the model settings, and the source settings. It reports all problems of this
   step, not only the first one.
2. If step 1 finds no problem, it builds the application. This step connects to the bus
   and to the database, runs the database migrations, and opens the audit log.

The command starts no source, no detection, and no agent. The exit status is 1 if the
configuration has a problem. Each problem names its section.

## Cargo features

| Feature | Effect |
| --- | --- |
| `postgres` | PostgreSQL storage and the PostgreSQL audit log. |
| `plugins` | WebAssembly connector plugins. |
| `otlp` | The OpenTelemetry trace exporter. |

All three are default features. Each one goes to the same feature of `aegis-app`. The
monitoring-only build has none of them:

```sh
cargo build -p aegis-cli --no-default-features
```

## TLS

The program installs the `aws-lc-rs` provider of rustls as the default of the process at
the start of `main`.

## Test the program

```sh
cargo test -p aegis-cli --all-features
```

`tests/cli.rs` runs the built program. The tests use temporary directories, no network, and
no credentials.
