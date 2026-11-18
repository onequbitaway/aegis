# Operations

This document tells you how to operate AEGIS as a service. The subjects are the audit
log, approvals, a change of the rules or the policy, upgrades, backup, logs, and
troubleshooting.

The examples use the starter directory of the [quickstart](quickstart.md),
`/tmp/aegis-quickstart`.

## Contents

- [Start and stop the service](#start-and-stop-the-service)
- [The audit log](#the-audit-log)
- [Approvals](#approvals)
- [Apply a change of the rules, the policy, or the playbooks](#apply-a-change-of-the-rules-the-policy-or-the-playbooks)
- [What a restart keeps](#what-a-restart-keeps)
- [Upgrades](#upgrades)
- [Backup](#backup)
- [Logs and traces](#logs-and-traces)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)

## Start and stop the service

1. Check the configuration.

   ```sh
   aegis config check --config /tmp/aegis-quickstart/aegis.toml
   ```

2. Start the service.

   ```sh
   aegis run --config /tmp/aegis-quickstart/aegis.toml
   ```

3. To stop the service, send SIGINT (Ctrl-C) or SIGTERM. Each component completes the
   work that is in progress. The server waits for each approval decision that started.

   ```text
   AEGIS stopped. Events examined: 648. Detections: 8. Incident changes: 7. Playbook runs: 4.
   ```

- The exit status is 0 after a stop signal. It is 1 if a component failed.
- If one component fails, the service stops all components.
- A second stop signal does not stop the process faster.
- The report goes to the standard output stream. The log goes to the standard error
  stream.

A health check needs no token:

```sh
curl -s http://127.0.0.1:8080/healthz
```

```json
{"status":"ok"}
```

For deployment in containers, refer to [`deploy/README.md`](../deploy/README.md).

## The audit log

The audit log records each detection, each incident change, each agent decision, each
action proposal, each policy decision, each approval, and each action result. Each
record holds the hash of the record before it.

### Verify the chain

For a file audit log:

```sh
aegis audit verify --path /tmp/aegis-quickstart/data/audit.jsonl
```

```text
Audit log /tmp/aegis-quickstart/data/audit.jsonl
  Records checked: 162
  Chain: valid
```

- The command does not open the log for append. It can run while the service writes the
  file.
- The exit status is 1 if the chain is not valid.
- `--format json` gives the result as JSON.

For each audit log, also in PostgreSQL, a principal with the permission `view_audit` can
use the API:

```sh
curl -s -H "Authorization: Bearer $AEGIS_TOKEN_ALICE" \
    http://127.0.0.1:8080/api/v1/audit/verification
```

```json
{"valid":true,"checked":162}
```

### What the check finds

These are results of real checks on copies of an audit file. Each copy was changed for
the test.

One changed byte in record 12:

```text
Audit log /tmp/aegis-audit-test/changed.jsonl
  Records checked: 11
  Chain: NOT VALID
  First invalid sequence: 12
  Reason: hash does not match the record contents
```

Line 5 removed:

```text
Audit log /tmp/aegis-audit-test/removed.jsonl
  Records checked: 4
  Chain: NOT VALID
  First invalid sequence: 6
  Reason: expected sequence 5, found 6
```

A last line that is not complete:

```text
Audit log /tmp/aegis-audit-test/partial.jsonl
  Records checked: 155
  Chain: NOT VALID
  First invalid sequence: 156
  Reason: the last line is not complete: 20 bytes at byte offset 210897 have no line end. A write that did not complete can cause this. The log does not repair the file
```

The service does not start with an audit file that does not verify:

```text
integrity error: [audit] audit log /private/tmp/aegis-changed/data/audit.jsonl does not verify: first invalid sequence 12: hash does not match the record contents
```

### If the chain is not valid

1. Stop the service. Do not edit the file.
2. Make a copy of the file. Keep the copy as evidence.
3. Find the cause. The first invalid sequence is the first record that you cannot trust.
4. For a last line that is not complete, do the procedure below.
5. For each other cause, start a new audit file with a new path. Keep the old file.

### A last line that is not complete

A failure during a write can leave a last line that is not complete. AEGIS reports this
condition and does not repair the file.

1. Run `aegis audit verify`. Make sure that the reason is `the last line is not complete`
   and that the first invalid sequence is the last line of the file.
2. Make a copy of the file. Keep the copy as evidence.
3. Remove the bytes after the last line feed from the file.
4. Run `aegis audit verify` again. The chain is then valid.

### Show records

```sh
aegis audit show --path /tmp/aegis-quickstart/data/audit.jsonl --limit 3
```

```text
Audit log /tmp/aegis-quickstart/data/audit.jsonl: the newest 3 of 162 records
    160  2026-11-18T06:56:56.837262Z  agent_decision      reporter              The model wrote no report text for incident 508657f7-d921-8cb3-add4-c2bd62528abd: the model call failed: unavailable: no model is configured: add a [model] section to use a model. The template applies.
    161  2026-11-18T06:56:56.841218Z  agent_decision      reporter              Wrote the report for incident 508657f7-d921-8cb3-add4-c2bd62528abd on aegis.reports.508657f7-d921-8cb3-add4-c2bd62528abd. Text source: template.
    162  2026-11-18T06:56:58.797036Z  approval_decided    alice@example.com     alice@example.com rejected the action disable_service_principal on sp-sync-helper.
  Records checked: 162
  Chain: valid
```

The columns are the sequence, the time, the record type, the actor, and the summary.
`--format json` gives the full records. The console has the same data in the view
**Audit**.

### Explain an action or an incident

The explanation of an action is the list of the audit records that link to it. The list
has the proposal, the policy decision, the approval, and the result. A principal with the
permission `view_audit` can read it:

```sh
curl -s -H "Authorization: Bearer $AEGIS_TOKEN_ALICE" \
    http://127.0.0.1:8080/api/v1/actions/01a1ed46-d037-72c6-9071-953c8ae68626/explanation
```

The answer has the full records. This table shows the sequence, the type, the actor, and
the summary of each record of one answer:

| Sequence | Type | Actor | Summary |
| --- | --- | --- | --- |
| 51 | `agent_decision` | `responder` | The responder agent proposed disable_service_principal on service_principal:sp-sync-helper |
| 54 | `action_proposed` | `responder` | responder proposed the action disable_service_principal on service_principal sp-sync-helper. |
| 57 | `policy_decision` | `dispatcher` | Policy requires approval for the action disable_service_principal on service_principal sp-sync-helper. |
| 60 | `approval_requested` | `dispatcher` | The action disable_service_principal on service_principal sp-sync-helper waits for the approval 01a1ed46-d067-739b-8342-0d0a6b386658. |
| 155 | `approval_decided` | `alice@example.com` | alice@example.com approved the action disable_service_principal on sp-sync-helper. |
| 156 | `policy_decision` | `dispatcher` | Policy requires approval for the action disable_service_principal on service_principal sp-sync-helper. |
| 157 | `action_executed` | `dispatcher` | Connector simulation simulated the action disable_service_principal on service_principal sp-sync-helper. This was a dry run. Nothing changed. |

The route `GET /api/v1/incidents/{id}/explanation` gives the records of one incident and
of each action of that incident. The incident page of the console shows them.

### Keep the last hash in a different system

A file that lost its last records is still a correct chain. To find this, record the
sequence number and the hash of the last record in a different system at regular
intervals. The route `GET /api/v1/status` gives them:

```json
"audit":{"head":{"sequence":154,"hash":"1968d4da2ef558c0e6416ccda919767b77c12a34c7f63214f7d009092afe5139","time":"2026-11-18T06:10:03.833556Z"}}
```

After a restart, make sure that the log still has that record with that hash.

### Rules of the file audit log

- One process writes one audit file. A second process that opens the file fails.
- The file `<path>.lock` is the lock file. Do not remove it while the service operates.
- To start a new file, stop the service and set a new `audit.path`. Keep the old file:
  its last record is the end of that chain.
- `aegis replay` and `aegis config check` open the audit log of the configuration. While
  a service holds the file, use `aegis replay --audit-file <file>`.

## Approvals

A request waits for approval when the policy returns `require_approval`.

- **See the queue.** Use the view **Approvals** of the console, or
  `GET /api/v1/approvals`. The oldest request is first.
- **Decide.** Use the buttons of the console, or `POST /api/v1/approvals/{id}/decision`
  with the body `{"approve": true, "note": "text"}`.
- **Permission.** The principal needs `approve_actions`.
- **Rules.** The requester of an action cannot approve it. Only a person can decide.
- **Result.** For an approval, AEGIS runs the action one time and returns the result.
  The answer has a result also when the action failed.
- **Second decision.** A second decision on one request is refused with the status 409.

A decision completes also when the HTTP request goes away. The audit log has the
result.

With Slack or Teams, a mapped user can decide with the commands `approve <id> [note]` and
`reject <id> [note]`. Refer to the README of [`aegis-api`](../crates/api/README.md#chatops).

An approval that failed cannot run again. One approval permits one attempt. The agent or
the playbook must send a new request.

Refer to [policy.md](policy.md#approvals) for the approval rules.

## Apply a change of the rules, the policy, or the playbooks

The `aegis` program reads the configuration, the detection pack, the policy, and the
playbooks at the start. It has no reload command.

1. Change the files.
2. Run `aegis config check`. Correct each problem.
3. Test the change with `aegis replay --dry-run --audit-file <file>` on recorded events.
4. Stop the service.
5. Start the service.
6. Read the first new audit record. It has the type `config_change`. It names the rule
   pack, the digest of the policy, and the number of playbooks:

   ```text
   config_change  aegis  AEGIS started with the rule pack aegis-identity 0.1.0, the policy 9896d1c602f4cf7bd31db187b00956745f11d947a86ae51736074ac1be94d4b7, and 5 playbooks.
   ```

If a file is not valid, the service does not start. The message names the section and
the file.

A program that uses the `aegis-app` library can call `App::reload`. That function loads
the three parts again with no restart, keeps the old state if a file is not valid, and
writes a `config_change` record.

## What a restart keeps

| Data | Memory storage | PostgreSQL storage |
| --- | --- | --- |
| Incidents, the Defensive Graph, the approval queue | Gone | Kept |
| The audit log | Kept, in the file | Kept |
| The position of each source | Kept, if `ingest.checkpoint_dir` is set | Kept, if `ingest.checkpoint_dir` is set |
| Messages on the bus | Gone with the memory bus. Kept with NATS JetStream. | The same |
| The state of the velocity detectors and of the correlator | Gone | Gone |
| The honeytoken registry, and rotated secrets | Gone | Gone |
| The record of which playbook ran for which incident | Gone | Gone |

Effects that you must know:

- After a restart, the correlator starts an incident again with only the new detections.
  The incident store keeps the old detections.
- After a restart, a playbook can run a second time for an old incident.
- An approval request in the memory storage is gone after a stop. The action does not
  run.
- Move each rotated secret to your vault before the process stops.
- A source can send its last batch again after a stop. A repeated event gives the same
  detection identifier, and the stores do not make a second copy.

## Upgrades

AEGIS has no release at this time. An upgrade is a new build from the source code.

1. Read [`CHANGELOG.md`](../CHANGELOG.md) for changes to the configuration.
2. Build the new program. Refer to [quickstart.md](quickstart.md).
3. Make a backup. Refer to [Backup](#backup).
4. Run `aegis config check` with the new program. A key that the new program does not
   know is an error that names the key.
5. Stop the old service, and start the new program.

With the PostgreSQL storage, the program runs its database migrations at the start and
at `aegis config check`. A migration that ran does not run again. The role in the
database URL must own the schema.

## Backup

| Data | How to make a backup |
| --- | --- |
| The configuration directory | Copy `aegis.toml`, the detection pack, the policies, and the playbooks. Keep them in version control. |
| The file audit log | Copy the file. Then run `aegis audit verify` on the copy. |
| The checkpoints | Copy the directory of `ingest.checkpoint_dir`. |
| The PostgreSQL database | Use the backup tools of PostgreSQL, for example `pg_dump`. |
| The NATS stream | Use the backup tools of NATS. |

The secrets are not in these files. Keep them in your secret store.

A copy of the audit file while the service operates is a correct chain up to its last
complete line. If the last line of the copy is not complete, make the copy again.

This command made a backup of the test database of this document, inside the database
container:

```sh
pg_dump -U aegis -d aegis --format=custom --file=/tmp/aegis.dump
```

A restore of that backup was not tested for this document.

## Logs and traces

The section `[telemetry]` sets the log.

- The log goes to the standard error stream.
- `log_format = "json"` writes one JSON object in each line:

  ```json
  {"timestamp":"2026-11-18T06:49:39.912707Z","level":"INFO","fields":{"message":"loaded the policy","digest":"9896d1c602f4cf7bd31db187b00956745f11d947a86ae51736074ac1be94d4b7","rule":"data.aegis.response.decision"},"target":"aegis_policy::rego"}
  ```

- The starter configuration has `log_level = "warn"`. Use `info` to see the start, the
  sources, and the stop.
- To change the level for one run, use an override:
  `AEGIS__TELEMETRY__LOG_LEVEL=debug`.
- A log line does not contain a secret, a token, or a full payload.

Lines to look for at the level `info`:

| Line | Meaning |
| --- | --- |
| `opened the audit log path=... records=N` | The audit file verified, with N records. |
| `loaded the policy digest=...` | The policy compiled. The digest identifies its text. |
| `loaded the connector plugins sources=N actions=N` | The plugins loaded. |
| `the service started sources=N detection=true agents=true` | The components run. |
| `the operator API listens address=...` | The API accepts requests. |
| `ingestion started connector=... resumed=true` | A source continues at its saved position. |
| `ingestion stopped connector=... outcome=... events_published=N` | A source ended or stopped. |
| `stop signal received signal="SIGINT"` | The stop started. |
| `the service stopped` | All components completed their work. |

Traces: with `telemetry.otlp_endpoint`, the program starts an OTLP/HTTP trace exporter.
The components of AEGIS make no trace spans at this time. A test with a collector on the
loopback address got no trace data. Use the log and the audit log.

## Troubleshooting

Each message below is a real message of the program. A failure writes `error:` and the
cause to the standard error stream, and the exit status is 1.

### The configuration

| Message | Cause | Correction |
| --- | --- | --- |
| `cannot read the configuration file e/nope.toml: No such file or directory (os error 2)` | The path of `--config` is wrong. | Give the correct path. |
| ``the configuration file ... is not valid TOML at line 22, column 5: unclosed table, expected `]` `` | A syntax error. | Correct the line. |
| `the configuration has sections that AEGIS does not know: extras. The known sections are: ...` | A wrong section name. | Use a name of the list. |
| ``the section `response` is not valid: unknown field `dry_runs`, expected one of `dry_run`, ...`` | A wrong key name. | Use a key of the list. |
| ``the section `response` is not valid: key `dry_run`: invalid type: string, expected a boolean`` | A value of the wrong type, in the file or in an override. | Correct the value. |
| ``the module set breaks the rule `responder-requires-detection`: enable `detection`, or remove `responder` `` | The module set is not valid. | Change `modules.enabled`. |
| ``the section `detection` is not valid: not found: .../detections/none/pack.yml`` | The pack directory is wrong. | Correct `detection.pack`. |
| ``the section `detection` is not valid: rule .../rules/broken.yml: the selection "keywords" is a list of keywords; use a list of maps`` | A Sigma rule uses a part that is not supported. | Correct the rule. |
| ``the section `policy` is not valid: the policy file ... does not compile: expecting expression at ...:4:1`` | A syntax error in the policy. | Correct the policy. |
| ``the section `policy` is not valid: the policy does not compile or does not have the rule data.aegis.response.decision: not a valid rule path`` | The policy has no decision rule. | Add the rule, or set `policy.rule`. |
| ``the section `response` is not valid: 1 of the playbooks in ... are not valid: playbook broken.yaml: the trigger has no condition; ...`` | A playbook is not valid. | Correct the playbook. |
| ``the section `audit` is not valid: kind = "postgres" needs storage.kind = "postgres"`` | The audit log is in the database, and the storage is in memory. | Set the two to `postgres`, or use the file audit log. |
| ``the section `storage` is not valid: missing field `url` `` | The database URL is not set. | Set `AEGIS__STORAGE__URL`. |

### Secrets

| Message | Cause | Correction |
| --- | --- | --- |
| ``the section `api` is not valid: principal alice@example.com: the environment variable AEGIS_TOKEN_ALICE is not set`` | The token variable is not in the environment of the process. | Export the variable before the start. |
| ``the section `api` is not valid: principal alice@example.com: the token in AEGIS_TOKEN_SHORT must have 32 characters or more`` | The token is too short. | Make a token with `openssl rand -hex 32`. |
| ``the section `model` is not valid: provider gateway: the environment variable AEGIS_GATEWAY_API_KEY is not set`` | The API key of a model provider is not set. | Export the variable. |
| ``the section `sources` is not valid: entra source entra-prod: the environment variable AEGIS_ENTRA_CLIENT_SECRET is not set`` | The client secret of the source is not set. | Export the variable. |
| ``the section `response` is not valid: key `graph`: missing field `client_secret` `` | The client secret of the Microsoft Graph connector is not set. | Set `AEGIS__RESPONSE__GRAPH__CLIENT_SECRET`. |
| ``the section `response` is not valid: the secret of webhook connector soc-bridge must have 16 bytes or more`` | The webhook secret is too short. | Use a longer secret. |
| ``the section `bus` is not valid: key `nats.auth`: invalid type: integer, expected a string`` | An override with only digits became a number. | Put quotation marks in the value: `'"123456"'`. |

### The operator API

| Message | Cause | Correction |
| --- | --- | --- |
| ``the section `api` is missing: the operator API needs it. The API has no default principal and no open mode. ...`` | `api` is in `[modules]`, and the file has no `[api]` section. | Add the section, or remove the module. |
| ``the section `modules` is not valid: the module `api` needs the agent runtime, and no agent is enabled. ...`` | The module set has `api` and no agent module. | Add an agent module, for example `monitor`. |
| ``the section `api` is not valid: api.bind is not a loopback address. The server has no TLS. ...`` | The address is not a loopback address. | Use a loopback address, or use a proxy with TLS and set `allow_non_loopback`. |
| `[api] the operator API cannot listen on 127.0.0.1:8080: Address already in use (os error 48)` | A different program uses the port. | Stop that program, or change `api.bind`. |
| `{"error":{"code":"unauthorized","message":"The request has no valid bearer token."}}` | The request has no token, or a token that AEGIS does not know. | Send `Authorization: Bearer <token>`. |
| `{"error":{"code":"conflict","message":"The approval request already has a decision."}}` | A second decision on one request. | No correction. The first decision stays. |

### The audit log, the storage, and the bus

| Message | Cause | Correction |
| --- | --- | --- |
| `[audit] audit log ... has a writer already: the file ...audit.jsonl.lock is locked` | A service holds the audit file. | Stop the service, or use `aegis replay --audit-file <file>`. |
| `[audit] audit log ... does not verify: first invalid sequence 12: hash does not match the record contents` | The audit file changed. | Refer to [If the chain is not valid](#if-the-chain-is-not-valid). |
| `the hash chain of the audit log /tmp/aegis-audit-test/changed.jsonl is not valid: the first invalid sequence is 12: hash does not match the record contents` | `aegis audit verify` found a changed record. | The same. |
| `cannot read audit log nope.jsonl: No such file or directory (os error 2)` | The path of `--path` is wrong. | Give the correct path. |
| `[storage] connect to the database: the database connection failed (connection refused)` | The database does not answer. | Start the database, or correct the URL. |
| `[bus] connect to NATS: IO error: Connection refused (os error 61)` | The NATS server does not answer. | Start the server, or correct `bus.nats.urls`. |

### Events, plugins, and actions

| Message | Cause | Correction |
| --- | --- | --- |
| `the event file bad-events.jsonl is not valid: serialization error: line 1 is not a normalized event: Data problem at column 10` | A line of the file is not an event. | Correct the line. Refer to [detection-packs.md](detection-packs.md#the-event-vocabulary). |
| `the starter files exist already and AEGIS does not replace a file: site/aegis.toml, ..., and 21 more` | `aegis init` on a directory that has the files. | Use a new directory. |
| `[plugins] plugin webhook-notify: the SHA-256 of the component file is d3e8..., but the manifest expects f425...` | The component file changed after you pinned it. | Find the cause. Then build the plugin again, or correct the hash. |
| `failed (unsupported): unsupported: no action connector supports the action BlockIp` | Changes are permitted, and no connector does this action type. | Configure a connector for the action type. |
| `failed (invalid_input): invalid input: the target user user-dana is in the tenant tenant-contoso; connector entra-graph manages the tenant ...` | The telemetry uses a tenant name that the Microsoft Graph connector does not know. | Add the name to `tenant_aliases`. |
| `denied: The evaluation of the policy rule data.aegis.response.decision failed: rule conflicts with rule at ...` | Two complete policies are in `policy.paths`. | Load one policy. |
| `tier 2 failed; the detection stays suspicious ... error=timeout: provider local did not answer in 300s` | The model did not answer in time. | Use a faster model, or increase the time limits. |
| `error: cannot write the report to the standard output stream: Broken pipe (os error 32)` | The reader of the output closed early, for example `head`. | Use a reader that reads all lines, for example `sed -n 1,20p`. |

### The service runs, and nothing occurs

| Observation | Cause | Correction |
| --- | --- | --- |
| The log is empty. | The log level is `warn`. | Set `AEGIS__TELEMETRY__LOG_LEVEL=info`. |
| `ingestion stopped ... events_published=0`, and `resumed=true` | The source continues at its saved position, and the file has no new line. | To read a file again, remove its checkpoint file. |
| The incident list is empty after a restart. | The storage is in memory. | Use the PostgreSQL storage for durable data. |
| An incident stays `open`. | No detection is `malicious`, and no model is configured. | A person examines the incident. Or give the rule `aegis.verdict: malicious`. |
| Each action is `simulated`. | The dry run is on. | This is the default. Refer to [configuration.md](configuration.md#safe-defaults). |
| No request waits for approval. | With the default policy, a dry run is permitted with no approval. | Use the [approval rehearsal policy](../examples/offline-demo/policies/approval-rehearsal.rego), or permit changes. |

## Limits

- The `aegis` program has no command to reload the rules, the policy, or the playbooks.
- `aegis audit verify` and `aegis audit show` read only a file audit log. For the
  PostgreSQL audit log, use the API.
- No command and no API route shows an incident report.
- No command and no API route undoes an action.
- The service has no metrics endpoint. The route `GET /api/v1/status` gives the counts of
  the agent runtime.
- The components make no trace spans.
- A restore of a database backup was not tested for this document.
