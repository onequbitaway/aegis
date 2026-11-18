# Revert, timed revert, and friction

This document describes three functions of the response path: the revert of an action,
the timed revert ("contain first"), and the friction actions.

Each function uses the one dispatcher. A revert goes through the policy, the approval
queue, and the audit log, as each other action. Refer to
[architecture.md](architecture.md#the-single-dispatch-path).

## Contents

- [Revert one action](#revert-one-action)
- [Contain first, with a timed revert](#contain-first-with-a-timed-revert)
- [Turn the timed revert on](#turn-the-timed-revert-on)
- [Decide a timed revert](#decide-a-timed-revert)
- [The policy for a revert](#the-policy-for-a-revert)
- [Friction actions](#friction-actions)
- [Restart and failure](#restart-and-failure)
- [Limits](#limits)

## Revert one action

A person can undo one action that a connector did before:

`POST /api/v1/actions/{id}/revert` with the body `{"reason": "text"}`.

- The principal needs the permission `approve_actions`.
- The revert is a request of its own, with the action type `{custom: revert}`. The policy
  decides it. With the default policy, a second person must approve it.
- The audit log gets each step with the principal, and each record links to the action.
- A dry run has nothing to revert. One execution can be reverted one time.
- The connector must be able to undo the action. If not, the answer is an error.

## Contain first, with a timed revert

A containment action that waits for a person can be too late. A containment action that
runs with no person can be wrong. A timed revert limits the cost of a wrong action: the
action runs, and AEGIS reverts it at a set time, unless a person confirms it.

A playbook step asks for a timed revert with the field `revert_after`, for example `4h`.
The sample playbooks use it for each reversible containment step. Refer to
[playbooks.md](playbooks.md#the-timed-revert).

Only an action type with an inverse can have a timed revert: `disable_user`,
`disable_service_principal`, `isolate_host`, `block_ip`, `tag`, `deploy_honeytoken`, and
a custom action. Before the action runs, the dispatcher asks the connector if it can undo
the action, and it writes the pending revert to a file.

## Turn the timed revert on

Add the table `[response.revert]` to `aegis.toml`. The starter configuration has it.

```toml
[response.revert]
store = "data/pending-reverts.json"
```

- With no table, the timed revert is off. An action with a revert time then runs only as
  a dry run. A request that is not a dry run does not run, and its result has the cause.
- `aegis run` starts the revert scheduler. The scheduler stops with the service.
- A dry run leaves no pending revert.
- One process uses one store file. `aegis replay --audit-file` and `aegis monitor` do not
  use the store of the configuration.

Refer to [configuration.md](configuration.md#responserevert) for each key.

## Decide a timed revert

The running service is the only component that changes the store. Thus the commands and
the console call the operator API of the service.

| Operation | API route | Command | Effect |
| --- | --- | --- | --- |
| List | `GET /api/v1/reverts` | `aegis reverts list` | The pending reverts, earliest revert time first. |
| Confirm | `POST /api/v1/reverts/{action_id}/confirm` | `aegis reverts confirm <ACTION_ID>` | The containment stays. AEGIS does not revert it. |
| Extend | `POST /api/v1/reverts/{action_id}/extend` | `aegis reverts extend <ACTION_ID> --by 2h` | The revert time moves. |
| Revert now | `POST /api/v1/reverts/{action_id}/cancel` | `aegis reverts cancel <ACTION_ID>` | The revert runs now, through the policy. |

- Each change needs the permission `approve_actions`. Only a person can confirm an action
  or move its time. An agent cannot keep its own containment.
- Each operation writes an audit record with the principal.
- The console shows the pending reverts in the view **Approvals**, with the buttons
  **Confirm the action** and **Revert now**.

The commands read the address from `--url` or from `AEGIS_API_URL`. The default is
`http://127.0.0.1:8080`. They read the token from the environment variable
`AEGIS_API_TOKEN`, or from the variable that `--token-env` names. The token is never an
argument. The commands send the token only over HTTPS, or over HTTP to a loopback
address.

This example uses the service of the [quickstart](quickstart.md#5-run-the-service). Each
action of that service is a dry run, so no action waits for a timed revert.

```sh
export AEGIS_API_TOKEN="$AEGIS_TOKEN_ALICE"
aegis reverts list --url http://127.0.0.1:8080
```

```text
Timed reverts (0) of the service at http://127.0.0.1:8080
  No action waits for a timed revert.
```

An action that has no pending revert gives an error, and the exit status is 1:

```sh
aegis reverts confirm 0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e --url http://127.0.0.1:8080
```

```text
error: the operator API answered POST /reverts/0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e/confirm with the status 404 (not_found): the action 0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e has no pending revert
```

## The policy for a revert

The policy is the authority for each part.

- With `policies/default.rego`, an action with a revert time needs approval as before,
  and each revert needs approval. The scheduler then puts its revert in the approval
  queue, and the containment stays until a person decides.
- `policies/examples/contain_first_with_timed_revert.rego` permits the two parts. A
  reversible action with a revert time of 4 hours or less runs first, for an incident
  with the severity `high` or `critical`. The scheduler reverts it with no approval. A
  revert that a person requests still needs approval.

Refer to [policy.md](policy.md#the-policy-for-a-revert).

## Friction actions

A friction action slows an attacker during a critical incident. It does not act on the
attacker. It changes a control in your own environment, and it has an inverse.

| Action | Connector | Effect |
| --- | --- | --- |
| `{custom: restrict_user_consent}` | Microsoft Graph | Users of the tenant cannot consent to applications. |
| `{custom: raise_friction}` | Webhook | Your automation raises a control, for example a change freeze. |

- A friction action runs only on a connector that can undo it.
- The sample playbook `raise-friction-critical-identity-incident` stops user consent for
  2 hours. It runs only for the tenants that its trigger names.
- With the starter configuration, the simulation connector takes the friction actions as
  dry runs. Thus you can rehearse the playbook with no Microsoft Graph connector.

Refer to [connectors.md](connectors.md#friction-actions).

## Restart and failure

- The store file keeps each pending revert. After a restart, the scheduler continues. A
  revert with a time in the past runs immediately.
- A store file that is not valid stops the start. AEGIS does not start with an empty
  store, because that loses pending reverts.
- If a revert fails, the containment stays. The scheduler writes an audit record and
  tries again after a delay that grows, up to `retry_max_seconds`.
- `GET /api/v1/status` shows the field `reverts`: `pending`, `reverted`,
  `failed_attempts`, `confirmed`, `extended`, `cancelled`, and `closed`.

## Limits

- Run one scheduler for one store file. Two processes with one file can lose a pending
  revert.
- `revoke_credential`, `rotate_credential`, `kill_session`, `rotate_secret`, `notify`,
  `enrich`, `snapshot_evidence`, and `open_ticket` have no inverse.
- The action journal of a replay report does not show a revert request. The audit log
  has each revert.
- The scheduler examines an approval of a timed revert each 60 seconds
  (`approval_poll_seconds`).
- The revert clock follows the monotonic clock of the process. It does not follow a later
  change of the system time.
- The timed revert was tested with a recording connector. It was not run against
  Microsoft Graph.
