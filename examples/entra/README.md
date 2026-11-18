# Example: Microsoft Entra ID source and Microsoft Graph actions

This example reads the sign-in log and the directory audit log of one Microsoft Entra ID
tenant. It proposes identity containment actions through Microsoft Graph.

Each response action is a dry run. A dry run sends no request that changes the tenant.

Use this example only with a tenant that you own or have authorization to defend.

## Files

| File | Contents |
| --- | --- |
| `aegis.toml` | The configuration, with placeholder identifiers and no secret. |
| `data/` | The audit log and the checkpoints. AEGIS writes them. |

## What you need

Make two application registrations in the tenant. Two registrations keep the read
permission and the change permissions apart.

| Registration | Microsoft Graph application permission | Use |
| --- | --- | --- |
| Read application | `AuditLog.Read.All` | The source connector reads the logs. |
| Response application | `Application.ReadWrite.All` for service principals and credentials. `User.ReadWrite.All` for users. | The action connector does the identity actions. |

Give the response application only the permissions for the actions that you use.

## Set the identifiers and the secrets

1. In `aegis.toml`, replace `00000000-0000-0000-0000-000000000000` with the identifier
   of your tenant. The value occurs two times.
2. Replace `11111111-1111-1111-1111-111111111111` with the client identifier of the read
   application.
3. Replace `22222222-2222-2222-2222-222222222222` with the client identifier of the
   response application.
4. Put the two client secrets in environment variables. Do not put a secret in the file.

   ```sh
   export AEGIS_ENTRA_CLIENT_SECRET='<the client secret of the read application>'
   export AEGIS__RESPONSE__GRAPH__CLIENT_SECRET='<the client secret of the response application>'
   ```

The two variables work differently:

- `AEGIS_ENTRA_CLIENT_SECRET` is the variable that `client_secret_env` names.
- `AEGIS__RESPONSE__GRAPH__CLIENT_SECRET` is an environment override. It sets the key
  `client_secret` of the section `[response.graph]`. That section has no key for the name
  of a variable.

## Check the configuration

```sh
aegis config check --config examples/entra/aegis.toml
```

```text
The configuration examples/entra/aegis.toml is valid.
  agents_dry_run: true
  api: off
  bus: memory
  connectors: entra-graph, honeytokens, simulation
  dispatcher_dry_run: true
  model: false
  modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter
  playbook_mode: dry_run
  playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, respond-to-honeytoken-trip
  rule_pack: aegis-identity
  rules: 9
  sources: entra-prod
  storage: memory
```

The check starts no source and sends no request to Microsoft. It does not prove that the
credentials are correct.

Without a secret, the check fails and names the key or the variable:

```text
configuration error: the section `response` is not valid: key `graph`: missing field `client_secret`
configuration error: the section `sources` is not valid: entra source entra-prod: the environment variable AEGIS_ENTRA_CLIENT_SECRET is not set
```

## Examine the response path with recorded events

Before you connect to the tenant, examine the response actions with the recorded attack
log. `aegis replay` uses no source connector, so it sends no request to Microsoft.

The recorded events use the tenant name `tenant-contoso`. The Microsoft Graph connector
refuses a target in a tenant that it does not manage. For this test only, add the name
as an alias with an environment override.

```sh
AEGIS__RESPONSE__GRAPH__TENANT_ALIASES='["tenant-contoso"]' \
    aegis replay --config examples/entra/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run
```

The identity actions now go to the connector `entra-graph`, as dry runs:

```text
  kill_session                user user-dana                                  responder                                 executed: simulated (connector entra-graph)
  disable_user                user user-dana                                  playbook:contain-compromised-user         executed: simulated (connector entra-graph)
  disable_service_principal   service_principal sp-sync-helper                responder                                 executed: simulated (connector entra-graph)
  revoke_credential           service_principal sp-sync-helper                responder                                 executed: simulated (connector entra-graph)
  block_ip                    ip_address 203.0.113.51                         responder                                 executed: simulated (connector simulation)
  No action changed the environment.
```

`block_ip`, `notify`, and `open_ticket` go to the simulation connector. The Microsoft
Graph connector does not do these actions. Configure a webhook connector for them.

## Run the service

```sh
aegis run --config examples/entra/aegis.toml
```

The source connector gets a token and reads the two logs each 30 seconds. With no saved
position, it starts at the present time. It does not read old records.

Stop the service with Ctrl-C. The connector saves its position in `data/checkpoints`.

## Before you permit changes

Keep the dry run until you examined the proposed actions for some days. Then do these
steps:

1. Read [`docs/policy.md`](../../docs/policy.md). Make sure that the policy gates each
   disruptive action.
2. Add the operator API with a principal that can approve. Refer to
   [`docs/configuration.md`](../../docs/configuration.md).
3. Set `response.dry_run`, `agents.dry_run`, and `response.playbooks` for your decision.
4. Run `aegis config check`. The lines `dispatcher_dry_run`, `agents_dry_run`, and
   `playbook_mode` show the result.

## Limits

- This example was not tested against a real tenant. The tests of the repository use a
  mock server for Microsoft Graph. The checks above were run: the configuration loads,
  and the dry-run response path works with the recorded events.
- The storage is in memory. Incidents and approval requests do not continue after a stop.
- A credential rotation gives the new secret to a receiver in memory. The command-line
  program has no vault connection. Refer to [`docs/connectors.md`](../../docs/connectors.md).
- The Microsoft Graph connector removes password credentials only, not certificates.
- The log of service principal sign-ins is a beta endpoint of Microsoft Graph. The
  example has it off.
