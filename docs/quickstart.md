# Quickstart

This procedure takes you from a clean checkout to a service that you operate. You do
these tasks:

1. Build the `aegis` program.
2. Run the demonstration: AEGIS finds a recorded attack and proposes the containment.
3. Make a starter directory and run AEGIS as a service.
4. Use the web console to examine the incident and to decide an approval.
5. Check the audit log.

Each response action in this procedure is a dry run. AEGIS changes nothing in your
environment. The procedure uses no model, no database, and no network.

## Prerequisites

- Git.
- [rustup](https://rustup.rs). It installs the Rust toolchain that the repository pins.
- The C compiler and the linker that Rust uses on your computer.
- `openssl`, to make a token.
- A web browser on the same computer.

The first build downloads the dependencies from crates.io. After that, no step needs
the internet.

## 1. Build the program

1. Get the code.

   ```sh
   git clone https://github.com/onequbitaway/aegis.git
   cd aegis
   ```

2. Install the Rust toolchain that `rust-toolchain.toml` pins.

   ```sh
   rustup toolchain install
   ```

3. Build the program. The first build compiles all dependencies and takes some minutes.

   ```sh
   cargo build -p aegis-cli --locked
   ```

4. Put the program in the path of this terminal.

   ```sh
   export PATH="$PWD/target/debug:$PATH"
   ```

5. Make sure that the program runs.

   ```sh
   aegis --version
   ```

   ```text
   aegis 0.1.0
   ```

Do all the steps that follow in this terminal, in the root of the repository.

## 2. Run the demonstration

```sh
aegis demo
```

The command makes a starter directory in a temporary directory. Then it examines the
recorded attack log, `fixtures/artex_style_attack.jsonl`. The program holds a copy of
that file. The output has five parts.

```text
AEGIS demonstration: replay of the recorded attack log: 648 events, dry run, no model

Detections (9)
  2026-11-03T09:10:00.450Z  high           malicious   T1110.003               Sign-in burst from one address  [aegis.velocity.sign_in_burst]
  2026-11-03T09:10:31.000Z  high           malicious   T1078                   Successful sign-in after a sign-in burst  [aegis.velocity.sign_in_after_burst]
  2026-11-03T09:10:37.000Z  high           malicious   T1528                   Consent to privileged application permissions  [5b0f3c2e-8a41-4d6f-9c57-2e1a7b90d314]
  2026-11-03T09:10:40.000Z  high           malicious   T1098.001               New application credential immediately after a grant  [aegis.velocity.credential_after_grant]
  2026-11-03T09:10:46.000Z  high           malicious   T1098.003               Privileged role assigned by a workload identity  [a4d7e1b9-6c35-4f02-8e7a-1b9c0d5f2a63]
  2026-11-03T09:10:46.000Z  high           malicious   T1098.003               Workload identity gave itself a privileged role  [aegis.velocity.privileged_self_assignment]
  2026-11-03T09:10:52.000Z  high           malicious   T1078.004               Principal acts from two places at an impossible speed  [aegis.velocity.impossible_speed]
  2026-11-03T09:10:52.000Z  high           malicious   T1059.009               Chain of sensitive actions at machine speed  [aegis.velocity.machine_cadence]
  2026-11-03T09:11:15.000Z  critical       malicious   T1552                   Honeytoken used  [0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940]

Incidents (1)
  508657f7-d921-8cb3-add4-c2bd62528abd  critical       investigating   Multi-stage attack: 8 ATT&CK techniques in 9 detections
      Detections: 9
      Techniques: T1110.003, T1078, T1528, T1098.001, T1098.003, T1078.004, T1059.009, T1552
      Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper; service_principal sp-sync-helper; ip_address 203.0.113.51; ip_address 192.0.2.77; secret kv-prod/legacy-admin-password

Actions (23)
  block_ip                    ip_address 203.0.113.50                         responder                                 executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.50                         playbook:block-password-spray-source      executed: simulated (connector simulation)
  notify                      other security-operations                       playbook:block-password-spray-source      executed: simulated (connector simulation)
  kill_session                user user-dana                                  responder                                 executed: simulated (connector simulation)
  deploy_honeytoken           secret honeytoken-credential-tenant-contoso     deception                                 executed: simulated (connector honeytokens)
  kill_session                user user-dana                                  playbook:contain-compromised-user         executed: simulated (connector simulation)
  disable_user                user user-dana                                  playbook:contain-compromised-user         executed: simulated (connector simulation)
  open_ticket                 other identity-team                             playbook:contain-compromised-user         executed: simulated (connector simulation)
  disable_service_principal   service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
  revoke_credential           service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
  disable_service_principal   service_principal sp-sync-helper                playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  revoke_credential           service_principal sp-sync-helper                playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  kill_session                user user-dana                                  playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.50                         playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  notify                      other security-operations                       playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  open_ticket                 other incident-response                         playbook:contain-rogue-service-principal  executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.51                         responder                                 executed: simulated (connector simulation)
  block_ip                    ip_address 192.0.2.77                           responder                                 executed: simulated (connector simulation)
  snapshot_evidence           tenant tenant-contoso                           playbook:respond-to-honeytoken-trip       executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.50                         playbook:respond-to-honeytoken-trip       executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.51                         playbook:respond-to-honeytoken-trip       executed: simulated (connector simulation)
  block_ip                    ip_address 192.0.2.77                           playbook:respond-to-honeytoken-trip       executed: simulated (connector simulation)
  notify                      other security-operations                       playbook:respond-to-honeytoken-trip       executed: simulated (connector simulation)
  No action changed the environment.

Playbooks (4)
  block-password-spray-source: 2 requests, 0 failures
  contain-compromised-user: 3 requests, 0 failures
  contain-rogue-service-principal: 6 requests, 0 failures
  respond-to-honeytoken-trip: 5 requests, 0 failures

Audit log
  Records: 156
  Records checked: 156
  Chain: valid
  File: /var/folders/y_/frr890zj6p31j54nbf6cd50h0000gp/T/aegis-demo-w7ltJU/data/audit.jsonl

The starter directory is /var/folders/y_/frr890zj6p31j54nbf6cd50h0000gp/T/aegis-demo-w7ltJU.
Run the service with: aegis run --config /var/folders/y_/frr890zj6p31j54nbf6cd50h0000gp/T/aegis-demo-w7ltJU/aegis.toml
```

The path of the temporary directory is different on your computer.

### The first line

The line shows that AEGIS examined 648 events, that each action was a dry run, and that
AEGIS used no model.

### Detections

Each line is one detection of detection tier 1. Tier 1 is deterministic and uses no
model. The columns are:

| Column | Example | Meaning |
| --- | --- | --- |
| Time | `2026-11-03T09:10:00.450Z` | The time of the last event that caused the detection. |
| Severity | `high` | How important the detection is. |
| Verdict | `malicious` | The conclusion of the detector. `malicious` needs no more analysis. |
| Technique | `T1110.003` | The MITRE ATT&CK technique. |
| Title | `Sign-in burst from one address` | What the detector found. |
| Rule | `[aegis.velocity.sign_in_burst]` | The detector or the Sigma rule that made the detection. |

A rule identifier that starts with `aegis.velocity` is a built-in velocity detector. A
rule identifier that is a UUID is a Sigma rule of the detection pack.

The log has 600 failed sign-ins from one address in 30 seconds. They give one detection,
not 600.

### Incidents

The correlator put the nine detections in one incident, because they share entities.
The incident is `critical`, because it has three or more ATT&CK techniques. The state is
`investigating`: the Analyst agent confirmed the attack.

### Actions

Each line is one action request. The columns are the action type, the target, the
requester, and the result.

- The requester is an agent (`responder`, `deception`) or a playbook (`playbook:<name>`).
- Each request went through the policy, a connector, and the audit log.
- `executed: simulated` shows a dry run. The connector reported what it would do.
- The connector `simulation` reports a dry run for an action type that has no configured
  connector. The connector `honeytokens` is a part of AEGIS.
- The last line confirms that no action changed the environment.

The agents and the playbooks work independently. Thus some actions occur two times, for
example `block_ip` on `203.0.113.50`.

### Playbooks

Four of the six sample playbooks matched the incident. A failure is a step that sent no
request or got an error. The reversible containment steps of the playbooks have a revert
time. In a dry run, a revert time has no effect. Refer to [response.md](response.md).

### Audit log

The audit log has one record for each detection, incident change, agent decision, action
proposal, policy decision, and action result. Each record holds the hash of the record
before it. `Chain: valid` shows that no record changed after AEGIS wrote it.

Refer to [demo.md](demo.md) for each step of the attack and each record type.

## 3. Make a starter directory

`aegis init` writes a working configuration with the files that it needs. This procedure
uses the directory `/tmp/aegis-quickstart`. You can use a different directory.

1. Write the starter directory.

   ```sh
   aegis init --dir /tmp/aegis-quickstart
   ```

   ```text
   Wrote 28 files to /tmp/aegis-quickstart:
     /tmp/aegis-quickstart/aegis.toml
     /tmp/aegis-quickstart/detections/aegis-identity/indicators/examples.yml
     /tmp/aegis-quickstart/detections/aegis-identity/pack.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/account_locked_after_failed_sign_ins.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/consent_to_privileged_permissions.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/decoy_canary_hit.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/decoy_contact.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/honeytoken_used.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/legacy_mail_protocol_sign_in.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/mfa_method_changed_by_script_client.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/mfa_request_denied.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/privileged_application_permission_granted.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/privileged_role_assigned_by_workload_identity.yml
     /tmp/aegis-quickstart/detections/aegis-identity/rules/user_created_by_workload_identity.yml
     /tmp/aegis-quickstart/policies/README.md
     /tmp/aegis-quickstart/policies/default.rego
     /tmp/aegis-quickstart/policies/examples/auto_contain_service_principals.rego
     /tmp/aegis-quickstart/policies/examples/contain_first_with_timed_revert.rego
     /tmp/aegis-quickstart/policies/examples/maintenance_window.rego
     /tmp/aegis-quickstart/policies/examples/protected_entities.rego
     /tmp/aegis-quickstart/policies/examples/protected_entities.yaml
     /tmp/aegis-quickstart/playbooks/README.md
     /tmp/aegis-quickstart/playbooks/block-password-spray-source.yaml
     /tmp/aegis-quickstart/playbooks/contain-compromised-user.yaml
     /tmp/aegis-quickstart/playbooks/contain-rogue-service-principal.yaml
     /tmp/aegis-quickstart/playbooks/isolate-compromised-host.yaml
     /tmp/aegis-quickstart/playbooks/raise-friction-critical-identity-incident.yaml
     /tmp/aegis-quickstart/playbooks/respond-to-honeytoken-trip.yaml

   Next steps:
     aegis config check --config /tmp/aegis-quickstart/aegis.toml
     aegis run --config /tmp/aegis-quickstart/aegis.toml
   ```

   The command replaces no file. If a file exists, the command writes nothing and stops.

2. Check the configuration.

   ```sh
   aegis config check --config /tmp/aegis-quickstart/aegis.toml
   ```

   ```text
   The configuration /tmp/aegis-quickstart/aegis.toml is valid.
     agents_dry_run: true
     api: off
     bus: memory
     connectors: honeytokens, simulation
     decoy: off
     dispatcher_dry_run: true
     evidence_archive: /tmp/aegis-quickstart/data/evidence.jsonl
     model: false
     modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter
     playbook_mode: dry_run
     playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, raise-friction-critical-identity-incident, respond-to-honeytoken-trip
     rule_pack: aegis-identity
     rules: 11
     sources: 
     storage: memory
     timed_revert: /tmp/aegis-quickstart/data/pending-reverts.json
   ```

   The starter configuration has no source and no operator API. The next steps add them.

## 4. Prepare the service

The service needs events, and the console needs the operator API. To show an approval,
this procedure also uses a policy that makes one action type wait for a person.

1. Copy the recorded attack log to the starter directory.

   ```sh
   cp fixtures/artex_style_attack.jsonl /tmp/aegis-quickstart/events.jsonl
   ```

2. Copy the approval rehearsal policy to the starter directory.

   ```sh
   cp examples/offline-demo/policies/approval-rehearsal.rego /tmp/aegis-quickstart/policies/
   ```

   The default policy permits each dry run, so nothing waits for approval. With the
   rehearsal policy, each `disable_service_principal` request waits for a person, also in
   a dry run.

3. Open `/tmp/aegis-quickstart/aegis.toml` in an editor. Make the four changes that
   follow.

4. In the section `[modules]`, add `"api"` to the list. The line then reads:

   ```toml
   enabled = ["ingest", "detection", "monitor", "hunter", "analyst", "responder", "deception", "reporter", "api"]
   ```

5. In the section `[policy]`, name the rehearsal policy. The line then reads:

   ```toml
   paths = ["policies/approval-rehearsal.rego"]
   ```

6. Find the four comment lines of the source connector. Remove the comment mark and the
   space after it from each line. The lines then read:

   ```toml
   [[sources]]
   type = "file"
   name = "replay"
   path = "events.jsonl"
   ```

7. Find the comment lines of the `[api]` section at the end of the file. Remove the
   comment mark and the space after it from each line. The lines then read:

   ```toml
   [api]
   bind = "127.0.0.1:8080"

   [[api.principals]]
   id = "alice@example.com"
   roles = ["analyst", "approver"]
   token_env = "AEGIS_TOKEN_ALICE"
   ```

8. Save the file.
9. Make a token for the principal `alice@example.com`. The configuration holds only the
   name of the variable.

   ```sh
   export AEGIS_TOKEN_ALICE="$(openssl rand -hex 32)"
   ```

10. Show the token, and copy it. You put it in the console in a later step.

    ```sh
    echo "$AEGIS_TOKEN_ALICE"
    ```

11. Check the configuration again.

    ```sh
    aegis config check --config /tmp/aegis-quickstart/aegis.toml
    ```

    ```text
    The configuration /tmp/aegis-quickstart/aegis.toml is valid.
      agents_dry_run: true
      api: 127.0.0.1:8080
      bus: memory
      connectors: honeytokens, simulation
      decoy: off
      dispatcher_dry_run: true
      evidence_archive: /tmp/aegis-quickstart/data/evidence.jsonl
      model: false
      modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter, api
      playbook_mode: dry_run
      playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, raise-friction-critical-identity-incident, respond-to-honeytoken-trip
      rule_pack: aegis-identity
      rules: 11
      sources: replay
      storage: memory
      timed_revert: /tmp/aegis-quickstart/data/pending-reverts.json
    ```

    The lines `api` and `sources` show the two additions. If the check reports a problem,
    correct the file. Each problem names its section.

The directory [`examples/offline-demo`](../examples/offline-demo/README.md) has the same
configuration, ready to run.

## 5. Run the service

The starter configuration writes only warnings to the log. The variable in this command
is an environment override. It sets the log level to `info` for this run.

```sh
AEGIS__TELEMETRY__LOG_LEVEL=info aegis run --config /tmp/aegis-quickstart/aegis.toml
```

The log goes to the standard error stream:

```text
2026-11-18T20:01:26.601190Z  INFO aegis_policy::file_log: opened the audit log path=/private/tmp/aegis-quickstart/data/audit.jsonl records=0
2026-11-18T20:01:26.614000Z  INFO aegis_policy::rego: loaded the policy digest=2c4ae047606027ae20cb84a975f7142acf7cd7074d6afe24ba6eccadfcfe0c4d rule=data.aegis.response.decision
2026-11-18T20:01:26.618789Z  INFO aegis::commands: AEGIS runs. Send SIGINT or SIGTERM to stop. config=/tmp/aegis-quickstart/aegis.toml
2026-11-18T20:01:26.623409Z  INFO aegis_app::app: the service started sources=1 detection=true agents=true
2026-11-18T20:01:26.623418Z  INFO aegis_app::api: the operator API listens address=127.0.0.1:8080
2026-11-18T20:01:26.623474Z  INFO aegis_ingest::runner: ingestion started connector=replay resumed=false
2026-11-18T20:01:26.624015Z  INFO aegis_api::server: the API server listens address=Some(127.0.0.1:8080)
2026-11-18T20:01:26.749142Z  INFO aegis_ingest::runner: ingestion stopped connector=replay outcome=Completed events_published=648 batches=7 retries=0
2026-11-18T20:01:27.387355Z  INFO aegis_policy::approval: recorded a decision approval=01a1f03f-f957-730f-9f8d-a98f6e22431a principal=alice@example.com approve=true
2026-11-18T20:01:27.476285Z  INFO aegis_policy::approval: recorded a decision approval=01a1f03f-f95a-73ff-a409-6f3f543a553f principal=alice@example.com approve=false
2026-11-18T20:01:27.616588Z  INFO aegis_core::shutdown: stop signal received signal="SIGINT"
2026-11-18T20:01:27.616839Z  INFO aegis_app::api: the operator API stopped address=127.0.0.1:8080
2026-11-18T20:01:27.616902Z  INFO aegis_app::app: the service stopped
```

The source read the 648 events and stopped. The service continues to run. Keep this
terminal open.

## 6. Open the console

1. Open `http://127.0.0.1:8080/` in a browser on the same computer.
2. Put the token in the field **API token**. Select **Use the token**. The top of the
   page then shows `alice@example.com (human; analyst, approver)`.
3. The view **Incidents** opens. It shows one incident:

   | Severity | State | Title | Tenant |
   | --- | --- | --- | --- |
   | critical | investigating | Multi-stage attack: 8 ATT&CK techniques in 9 detections | tenant-contoso |

4. Select the title of the incident. The page shows the ATT&CK techniques, the entities,
   the timeline, the detections, and the audit records of the incident.

The console keeps the token until you close the tab. It uses no cookie.

## 7. Decide an approval

1. Select **Approvals**. The view shows this line and two requests:

   ```text
   2 actions wait for approval. The oldest request is first.
   ```

   The two requests have the title `disable service principal (dry run)`. One came from
   the Responder agent. One came from the playbook `contain-rogue-service-principal`.
   The line **Policy** of each request gives the reason of the policy:

   ```text
   Approval rehearsal: a person must approve this action, also in a dry run.
   ```

2. In the first request, write a note, for example `Quickstart rehearsal.`
3. Select **Approve**. The browser asks you to confirm. Confirm.
4. Read the result below the buttons:

   ```text
   Approved. The action result is simulated: Dry run: a connector for disable_service_principal would act on sp-sync-helper. No connector is configured for this action. Nothing changed.
   ```

   AEGIS ran the approved action one time. The action is a dry run, so the result is
   `simulated`.

5. In the second request, select **Reject**. The result is `Rejected.` AEGIS does not
   run a rejected action.

   The view also has the part **Timed reverts**. Each action of this procedure is a dry
   run, so the part shows `No action waits for a timed revert.` Refer to
   [response.md](response.md).
6. Select **Audit**. The newest records include your two decisions, with your identity:

   ```text
   approval decided   alice@example.com   alice@example.com rejected the action disable_service_principal on sp-sync-helper.
   ```

   The part **Hash chain** shows the state `valid`.

You can do the same decisions with the REST API. Refer to the
[offline example](../examples/offline-demo/README.md#use-the-rest-api-in-place-of-the-console).

## 8. Stop the service and check the audit log

1. Go to the first terminal. Press Ctrl-C. The service stops and prints its counts.

   ```text
   AEGIS stopped. Events examined: 648. Detections: 9. Incident changes: 7. Playbook runs: 4.
   ```

2. Check the hash chain of the audit log.

   ```sh
   aegis audit verify --path /tmp/aegis-quickstart/data/audit.jsonl
   ```

   ```text
   Audit log /tmp/aegis-quickstart/data/audit.jsonl
     Records checked: 163
     Chain: valid
   ```

   The exit status is 0 only if the chain is valid.

3. Show the newest records.

   ```sh
   aegis audit show --path /tmp/aegis-quickstart/data/audit.jsonl --limit 8
   ```

   ```text
   Audit log /tmp/aegis-quickstart/data/audit.jsonl: the newest 8 of 163 records
       156  2026-11-18T20:01:27.381122Z  approval_decided    alice@example.com     alice@example.com approved the action disable_service_principal on sp-sync-helper.
       157  2026-11-18T20:01:27.405916Z  policy_decision     dispatcher            Policy requires approval for the action disable_service_principal on service_principal sp-sync-helper.
       158  2026-11-18T20:01:27.409444Z  action_executed     dispatcher            Connector simulation simulated the action disable_service_principal on service_principal sp-sync-helper. This was a dry run. Nothing changed.
       159  2026-11-18T20:01:27.472933Z  approval_decided    alice@example.com     alice@example.com rejected the action disable_service_principal on sp-sync-helper.
       160  2026-11-18T20:01:27.477621Z  agent_decision      responder             Incident 508657f7-d921-8cb3-add4-c2bd62528abd: disable_service_principal on service_principal:sp-sync-helper: denied by policy. alice@example.com rejected the approval request 01a1f03f-f95a-73ff-a409-6f3f543a553f.
       161  2026-11-18T20:01:27.484357Z  agent_decision      responder             Incident 508657f7-d921-8cb3-add4-c2bd62528abd: Containment is not complete. Of 6 actions: 0 ran, 5 were dry runs, 0 wait for approval, 1 were denied, 0 failed. The incident stays open.
       162  2026-11-18T20:01:27.493122Z  agent_decision      reporter              The model wrote no report text for incident 508657f7-d921-8cb3-add4-c2bd62528abd: the model call failed: unavailable: no model is configured: add a [model] section to use a model. The template applies.
       163  2026-11-18T20:01:27.497291Z  agent_decision      reporter              Wrote the report for incident 508657f7-d921-8cb3-add4-c2bd62528abd on aegis.reports.508657f7-d921-8cb3-add4-c2bd62528abd. Text source: template.
     Records checked: 163
     Chain: valid
   ```

   Record 156 is your approval. Record 157 shows that AEGIS asked the policy again
   before it ran the action. Record 158 is the dry run of the action. Record 159 is your
   rejection. The records after it are the work of the agents after the rejection.

## Run the service again

The file source keeps its position in `data/checkpoints`. A second run thus reads no
event. The incidents are in memory, so they are gone after the stop.

To read the events again, remove the checkpoint before you start the service:

```sh
rm /tmp/aegis-quickstart/data/checkpoints/replay.checkpoint.json
```

The audit log continues its chain in each run.

## Next steps

| Task | Document |
| --- | --- |
| Understand each step of the recorded attack | [demo.md](demo.md) |
| Understand the components and the data flow | [architecture.md](architecture.md) |
| Set each key of `aegis.toml` | [configuration.md](configuration.md) |
| Write your policy | [policy.md](policy.md) |
| Contain first, with a timed revert | [response.md](response.md) |
| Run a decoy service | [deception.md](deception.md) |
| Write an abuse report or export indicators | [sharing.md](sharing.md) |
| Add a local model | [`examples/local-model`](../examples/local-model/README.md) |
| Connect Microsoft Entra ID | [`examples/entra`](../examples/entra/README.md) |
| Operate the service | [operations.md](operations.md) |

## Limits

- This procedure was tested on macOS with Apple silicon.
- The storage of the starter configuration is in memory. Incidents and approval requests
  do not continue after a stop.
- The operator API has no TLS. Keep the loopback address, or put a proxy with TLS before
  the server.
- The identifiers of the actions and the times in your output are different from the
  samples.
