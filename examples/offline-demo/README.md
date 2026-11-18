# Example: the service on one host, offline

This example runs AEGIS as a service with the operator API and the web console. It needs
no model, no database, and no network. The source is the recorded attack log of the
repository.

Each response action is a dry run. The example changes nothing in your environment.

The [quickstart](../../docs/quickstart.md) builds this configuration step by step.

## Files

| File | Contents |
| --- | --- |
| `aegis.toml` | The configuration. |
| `policies/approval-rehearsal.rego` | A policy that makes one action type wait for a person, also in a dry run. |
| `data/` | The audit log, the checkpoints, the revert store, and the evidence archive. AEGIS writes them. |

## What the configuration does

- **Source.** A file source reads `fixtures/artex_style_attack.jsonl`: 648 events.
- **Storage and bus.** The incidents, the Defensive Graph, and the bus are in the memory
  of the process.
- **Audit log.** The file `data/audit.jsonl` holds the hash-chained audit log.
- **Timed revert and evidence archive.** The tables `[response.revert]` and `[evidence]`
  are on, as in the starter configuration. Each action of this example is a dry run, so
  no action has a pending revert. Refer to [response.md](../../docs/response.md) and
  [sharing.md](../../docs/sharing.md).
- **Policy.** `approval-rehearsal.rego` is the default policy with one change. Each
  `disable_service_principal` request needs the approval of a person, also in a dry run.
- **Operator API.** The API and the console listen on `127.0.0.1:8080`. One principal,
  `alice@example.com`, has the roles `analyst` and `approver`.

## Run the example

Do these steps in the root of the repository.

1. Make a token for the principal. The token must have 32 characters or more.

   ```sh
   export AEGIS_TOKEN_ALICE="$(openssl rand -hex 32)"
   ```

2. Check the configuration.

   ```sh
   aegis config check --config examples/offline-demo/aegis.toml
   ```

   ```text
   The configuration examples/offline-demo/aegis.toml is valid.
     agents_dry_run: true
     api: 127.0.0.1:8080
     bus: memory
     connectors: honeytokens, simulation
     decoy: off
     dispatcher_dry_run: true
     evidence_archive: /private/tmp/aegis-src/examples/offline-demo/data/evidence.jsonl
     model: false
     modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter, api
     playbook_mode: dry_run
     playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, raise-friction-critical-identity-incident, respond-to-honeytoken-trip
     rule_pack: aegis-identity
     rules: 11
     sources: replay
     storage: memory
     timed_revert: /private/tmp/aegis-src/examples/offline-demo/data/pending-reverts.json
   ```

   The paths in the lines `evidence_archive` and `timed_revert` are paths of the test
   checkout.

3. Run the service.

   ```sh
   aegis run --config examples/offline-demo/aegis.toml
   ```

   The log goes to the standard error stream. These lines show that the service
   operates:

   ```text
   INFO aegis_app::app: the service started sources=1 detection=true agents=true
   INFO aegis_app::api: the operator API listens address=127.0.0.1:8080
   INFO aegis_ingest::runner: ingestion stopped connector=replay outcome=Completed events_published=648 batches=7 retries=0
   ```

4. Show the token, and copy it.

   ```sh
   echo "$AEGIS_TOKEN_ALICE"
   ```

5. Open `http://127.0.0.1:8080/` in a browser on the same host. Put the token in the
   field **API token**. Select **Use the token**.
6. Select **Incidents**. The list shows one critical incident with 9 detections.
7. Select **Approvals**. Two requests for `disable_service_principal` wait. One came from
   the Responder agent. One came from the playbook `contain-rogue-service-principal`.
8. Approve one request and reject the other one. The result of the approved request is
   `simulated`, because the action is a dry run.
9. Press Ctrl-C in the terminal of the service. The service stops and prints its counts.

   ```text
   AEGIS stopped. Events examined: 648. Detections: 9. Incident changes: 7. Playbook runs: 4.
   ```

10. Check the audit log.

    ```sh
    aegis audit verify --path examples/offline-demo/data/audit.jsonl
    ```

    ```text
    Audit log examples/offline-demo/data/audit.jsonl
      Records checked: 163
      Chain: valid
    ```

## Use the REST API in place of the console

Each console function is a REST call. Do these steps in a second terminal that has the
same `AEGIS_TOKEN_ALICE` value.

1. List the requests that wait for approval.

   ```sh
   curl -s -H "Authorization: Bearer $AEGIS_TOKEN_ALICE" \
       http://127.0.0.1:8080/api/v1/approvals
   ```

2. Approve one request. Replace `<id>` with the `id` of a request.

   ```sh
   curl -s -X POST -H "Authorization: Bearer $AEGIS_TOKEN_ALICE" \
       -H "Content-Type: application/json" \
       -d '{"approve": true, "note": "Rehearsal."}' \
       http://127.0.0.1:8080/api/v1/approvals/<id>/decision
   ```

   The answer has the request with the status `approved`, and the result of the action:

   ```json
   "disposition": {
       "executed": {
           "action_id": "01a1f040-7f4d-71b8-af1f-8fa6135c9414",
           "status": "simulated",
           "connector": "simulation",
           "message": "Dry run: a connector for disable_service_principal would act on sp-sync-helper. No connector is configured for this action. Nothing changed.",
           "details": {
               "configured_connector": false
           },
           "reversible": true,
           "completed_at": "2026-11-18T20:02:01.753555Z"
       }
   }
   ```

## Run the example again

The file source keeps its position in `data/checkpoints`. A second run thus reads no
event. The incidents are in memory, so they are gone after a stop.

To read the events again, remove the checkpoint before you start the service:

```sh
rm examples/offline-demo/data/checkpoints/replay.checkpoint.json
```

The audit log continues its chain in each run. Do not edit the audit file.

## Limits

- The storage is in memory. Incidents and approval requests do not continue after a stop.
- The operator API has no TLS. Keep the loopback address.
- The identifiers and the times in your output are different from the samples.
