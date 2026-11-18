# The demonstration: a recorded agent attack

This document explains the demonstration step by step. It shows each attack step in the
recorded log and the detection that fires. Then it shows the incident, the containment
that AEGIS proposes, and the audit trail.

The demonstration is a dry run. It uses no model and no network. It changes nothing in
your environment.

## The recorded log

The file [`fixtures/artex_style_attack.jsonl`](../fixtures/artex_style_attack.jsonl) is a
recorded log of an attack on an identity tenant. It has the pattern of an attack that an
automated agent does: many steps in a short time, with seconds between them.

- The log has 648 normalized events, one in each line.
- 612 events are the attack. 36 events are normal activity: 30 sign-ins from office
  addresses, and 6 API calls of a backup service principal.
- All data is example data. Each address is in a documentation range of RFC 5737. Each
  name is an example name.
- The `aegis` program holds a copy of the file. `aegis demo` needs no checkout.

## Run the demonstration

Build the program first. Refer to [quickstart.md](quickstart.md).

1. Run the full demonstration.

   ```sh
   aegis demo --dir /tmp/aegis-demo
   ```

   The quickstart shows the full output. The command writes a starter directory to
   `/tmp/aegis-demo`, and the audit log to `/tmp/aegis-demo/data/audit.jsonl`.

2. To see each detection at the moment when it occurs, run a monitoring session. This
   command takes no action.

   ```sh
   aegis monitor --events fixtures/artex_style_attack.jsonl
   ```

## The attack, step by step

All times are on 2026-11-03, in UTC. The line numbers are lines of the log file.

| Step | Time | Lines | Activity in the log | Detection | ATT&CK |
| --- | --- | --- | --- | --- | --- |
| 1 | 09:10:00 to 09:10:30 | 14 to 614 | 600 failed sign-ins for 150 users from the address `203.0.113.50`. | Sign-in burst from one address | T1110.003 Password Spraying |
| 2 | 09:10:31 | 615 | A sign-in for `user-dana` from the same address succeeds, with no multi-factor authentication. | Successful sign-in after a sign-in burst | T1078 Valid Accounts |
| 3 | 09:10:37 | 616 | `user-dana` consents to privileged permissions for the application `app-sync-helper`. | Consent to privileged application permissions | T1528 Steal Application Access Token |
| 4 | 09:10:40 | 617 | The service principal `sp-sync-helper` gets a new password credential, 3 seconds after the consent. | New application credential immediately after a grant | T1098.001 Additional Cloud Credentials |
| 5 | 09:10:43 | 618 | `sp-sync-helper` signs in from the address `203.0.113.51`. | None | |
| 6 | 09:10:46 | 619 | `sp-sync-helper` assigns the role Global Administrator to itself. | Two detections. Refer to the text below. | T1098.003 Additional Cloud Roles |
| 7 | 09:10:50 to 09:11:00 | 620 to 626 | `sp-sync-helper` calls APIs in two tenants from two continents, 2 seconds apart. | Principal acts from two places at an impossible speed | T1078.004 Cloud Accounts |
| 8 | 09:11:15 | 627 | `sp-sync-helper` reads a honeytoken in a vault. | Honeytoken used | T1552 Unsecured Credentials |

One more detection names no single step. The service principal did steps 4 to 7 in 9
seconds. The detector for machine cadence reports this chain at step 7:
"Chain of sensitive actions at machine speed", T1059.009 Cloud API.

The full attack takes 75 seconds. A person cannot respond in that time.

### Step 1: the password spray

The velocity detector `aegis.velocity.sign_in_burst` counts failed sign-ins for each
source address. It fires at 09:10:00.450, after 10 failed sign-ins for 10 different users
in 60 seconds:

```text
A password spray: 10 failed sign-ins for 10 users came from the address 203.0.113.50 in 60 seconds.
```

The detector then starts a cooldown for that address. Thus the 600 failed sign-ins give
one detection, not 600.

### Step 2: the sign-in that succeeds

During the cooldown, a sign-in from the spray address succeeds. The same detector gives
a second detection, `aegis.velocity.sign_in_after_burst`:

```text
The account user-dana signed in from the address 203.0.113.50 after a burst of failed sign-ins from that address. The account is possibly compromised.
```

### Step 3: the consent

The event has the action `oauth.consent_grant` and the attribute `privileged: true`. Its
scopes include `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`. The
Sigma rule
[`consent_to_privileged_permissions.yml`](../detections/aegis-identity/rules/consent_to_privileged_permissions.yml)
matches. The rule has the level `high`, so the verdict is `malicious`.

### Step 4: the new credential

The velocity detector `aegis.velocity.credential_after_grant` remembers each consent and
each permission grant for 120 seconds. A new credential for the same application in that
time gives a detection:

```text
The application app-sync-helper got a new credential 3000 milliseconds after a grant (oauth.consent_grant).
```

The detection keeps the attribute `credential_id` of the event. A playbook uses that
value to remove this credential.

### Step 6: the role assignment

One event gives two detections:

- The Sigma rule
  [`privileged_role_assigned_by_workload_identity.yml`](../detections/aegis-identity/rules/privileged_role_assigned_by_workload_identity.yml)
  matches a privileged role assignment by a service principal.
- The velocity detector `aegis.velocity.privileged_self_assignment` finds that the actor
  and the target are the same identity:

  ```text
  The workload identity sp-sync-helper gave the role or permission "Global Administrator" to itself.
  ```

### Step 7: the impossible speed

The velocity detector `aegis.velocity.impossible_speed` compares the events of one
principal. It reads the place and the resource tenant of each event.

```text
The principal sp-sync-helper acted from two places 8930 kilometers apart and in two resource tenants in 2 seconds.
```

The detector then starts a cooldown for that principal. The six API calls give one
detection.

### The chain at machine speed

The detector `aegis.velocity.machine_cadence` examines the steps of one principal. The
service principal got a credential, signed in, gave itself a role, and called an API.
These are four different actions with a median gap of 3 seconds. A person does not work
at that speed. The chain includes a privileged change, so the detection is `malicious`.
The detection arrives with the first API call of step 7.

### Step 8: the honeytoken

The event has the action `honeytoken.trip` and the attribute `honeytoken_id`. The Sigma
rule [`honeytoken_used.yml`](../detections/aegis-identity/rules/honeytoken_used.yml)
matches. The rule has the level `critical`. No approved task reads a honeytoken, so each
use shows an intruder.

### The normal activity

The 36 normal events give no detection. The office sign-ins succeed with multi-factor
authentication. The backup service principal calls one API in one tenant from one place.

## The incident

The correlator puts two detections in one incident when they are in the same tenant and
share an entity. The two detections must also be in one time window of one hour. The output of `aegis monitor`
shows how the incident grows:

```text
DETECTION  2026-11-03T09:10:00.450Z  high           malicious   T1110.003               Sign-in burst from one address  [aegis.velocity.sign_in_burst]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  high           open            Sign-in burst from one address
           Detections: 1
           Techniques: T1110.003
           Entities:   ip_address 203.0.113.50
DETECTION  2026-11-03T09:10:31.000Z  high           malicious   T1078                   Successful sign-in after a sign-in burst  [aegis.velocity.sign_in_after_burst]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  high           open            Multi-stage attack: 2 ATT&CK techniques in 2 detections
           Detections: 2
           Techniques: T1110.003, T1078
           Entities:   ip_address 203.0.113.50; user user-dana
DETECTION  2026-11-03T09:10:37.000Z  high           malicious   T1528                   Consent to privileged application permissions  [5b0f3c2e-8a41-4d6f-9c57-2e1a7b90d314]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  critical       open            Multi-stage attack: 3 ATT&CK techniques in 3 detections
           Detections: 3
           Techniques: T1110.003, T1078, T1528
           Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper
DETECTION  2026-11-03T09:10:40.000Z  high           malicious   T1098.001               New application credential immediately after a grant  [aegis.velocity.credential_after_grant]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  critical       open            Multi-stage attack: 4 ATT&CK techniques in 4 detections
           Detections: 4
           Techniques: T1110.003, T1078, T1528, T1098.001
           Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper; service_principal sp-sync-helper
DETECTION  2026-11-03T09:10:46.000Z  high           malicious   T1098.003               Privileged role assigned by a workload identity  [a4d7e1b9-6c35-4f02-8e7a-1b9c0d5f2a63]
DETECTION  2026-11-03T09:10:46.000Z  high           malicious   T1098.003               Workload identity gave itself a privileged role  [aegis.velocity.privileged_self_assignment]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  critical       open            Multi-stage attack: 5 ATT&CK techniques in 6 detections
           Detections: 6
           Techniques: T1110.003, T1078, T1528, T1098.001, T1098.003
           Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper; service_principal sp-sync-helper; ip_address 203.0.113.51
DETECTION  2026-11-03T09:10:52.000Z  high           malicious   T1078.004               Principal acts from two places at an impossible speed  [aegis.velocity.impossible_speed]
DETECTION  2026-11-03T09:10:52.000Z  high           malicious   T1059.009               Chain of sensitive actions at machine speed  [aegis.velocity.machine_cadence]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  critical       open            Multi-stage attack: 7 ATT&CK techniques in 8 detections
           Detections: 8
           Techniques: T1110.003, T1078, T1528, T1098.001, T1098.003, T1078.004, T1059.009
           Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper; service_principal sp-sync-helper; ip_address 203.0.113.51; ip_address 192.0.2.77
DETECTION  2026-11-03T09:11:15.000Z  critical       malicious   T1552                   Honeytoken used  [0c9e4f7a-2b6d-4e18-a3f5-7d21c6b8e940]
INCIDENT   508657f7-d921-8cb3-add4-c2bd62528abd  critical       open            Multi-stage attack: 8 ATT&CK techniques in 9 detections
           Detections: 9
           Techniques: T1110.003, T1078, T1528, T1098.001, T1098.003, T1078.004, T1059.009, T1552
           Entities:   ip_address 203.0.113.50; user user-dana; application app-sync-helper; service_principal sp-sync-helper; ip_address 203.0.113.51; ip_address 192.0.2.77; secret kv-prod/legacy-admin-password

Monitoring session complete: 648 events, 9 detections, 7 incident states. Actions taken: 0.
```

What the output shows:

- **One incident.** The spray address links steps 1 and 2. The user links steps 2, 3,
  and 4. The service principal links steps 4 to 8.
- **Severity.** The incident starts as `high`. It becomes `critical` at the third
  ATT&CK technique.
- **State.** The monitoring session runs no Analyst agent, so the state stays `open`. In
  the demonstration, the Analyst agent sets `investigating`.
- **Same identifier.** A detection identifier comes from the rule and the events. A
  second replay of the log thus gives the same detections and the same incident.

## The containment that AEGIS proposes

The demonstration runs all agents and all sample playbooks. Each request goes through the
one dispatch path: the policy, a connector, and the audit log. The demonstration has 23
requests. Each one is a dry run.

### Requests of the agents

| Requester | Action | Target | Reason in the request |
| --- | --- | --- | --- |
| Responder | `block_ip` | `203.0.113.50` | Block the address 203.0.113.50. The attack activity comes from it. |
| Responder | `kill_session` | `user-dana` | Stop the sessions of user user-dana. The identity is possibly compromised. |
| Responder | `disable_service_principal` | `sp-sync-helper` | Disable service_principal sp-sync-helper to stop its access. |
| Responder | `revoke_credential` | `sp-sync-helper` | Remove the credentials of service_principal sp-sync-helper, so that the attacker cannot use them. |
| Responder | `block_ip` | `203.0.113.51` | Block the address 203.0.113.51. The attack activity comes from it. |
| Responder | `block_ip` | `192.0.2.77` | Block the address 192.0.2.77. The attack activity comes from it. |
| Deception | `deploy_honeytoken` | `honeytoken-credential-tenant-contoso` | The incident shows misuse of an identity in the tenant tenant-contoso. A decoy credential shows if the attacker comes back. |

Each reason also names the detections that caused the request. The `revoke_credential`
request has the parameter `credential_id` with the value `credential-1` from step 4.

The Responder agent proposes the baseline actions for each entity of the incident. With
no model, it uses its deterministic path. A model can only add optional actions from a
list that the code makes.

### Requests of the playbooks

| Playbook | Requests | Actions |
| --- | --- | --- |
| `block-password-spray-source` | 2 | `block_ip`, `notify` |
| `contain-compromised-user` | 3 | `kill_session`, `disable_user`, `open_ticket` |
| `contain-rogue-service-principal` | 6 | `disable_service_principal`, `revoke_credential`, `kill_session`, `block_ip`, `notify`, `open_ticket` |
| `respond-to-honeytoken-trip` | 5 | `snapshot_evidence`, `block_ip` for three addresses, `notify` |

Two sample playbooks do not match. `isolate-compromised-host` needs a host, and the
incident has no host. `raise-friction-critical-identity-incident` runs only for the
tenants that its trigger names, and the trigger names only an example tenant.

The `block_ip`, `disable_user`, and `disable_service_principal` requests of the playbooks
have a revert time of 4 hours. In a dry run, a revert time has no effect. Refer to
[response.md](response.md).

### Why nothing changed

- The starter configuration has `response.dry_run = true` and `agents.dry_run = true`.
  The dispatcher sets `dry_run` on each request.
- The default policy permits a dry run.
- No real connector is configured. The simulation connector reports what a connector
  would do. It refuses each request that is not a dry run.
- The report line `No action changed the environment.` confirms the result.

The incident stays in the state `investigating`. A dry run does not contain an incident.
The Responder agent records this in the timeline:

```text
Containment is not complete. Of 6 actions: 0 ran, 6 were dry runs, 0 wait for approval, 0 were denied, 0 failed. The incident stays open.
```

## The audit trail

The demonstration writes 156 audit records. Each record holds the hash of the record
before it.

| Record type | Count | Written by | Contents |
| --- | --- | --- | --- |
| `config_change` | 1 | `aegis` | The start: the rule pack, the policy digest, the playbooks, the dry-run switches. |
| `detection` | 9 | `detection` | One record for each detection. |
| `incident` | 7 | `correlator` | One record for each change of the incident. |
| `agent_decision` | 66 | The agents | Each decision of an agent, with its evidence. |
| `action_proposed` | 23 | The requester | One record for each action request. |
| `policy_decision` | 23 | `dispatcher` | The decision of the policy for each request. |
| `action_executed` | 23 | `dispatcher` | The result of the connector for each request. |
| `other` | 4 | `playbook-engine` | One record for each playbook run. |

Show the first records:

```sh
aegis audit show --path /tmp/aegis-demo/data/audit.jsonl --limit 156 | sed -n 2,13p
```

```text
      1  2026-11-18T19:48:10.618535Z  config_change       aegis                 AEGIS started with the rule pack aegis-identity 0.2.0, the policy 9896d1c602f4cf7bd31db187b00956745f11d947a86ae51736074ac1be94d4b7, and 6 playbooks.
      2  2026-11-18T19:48:10.628445Z  detection           detection             The detector aegis.velocity.sign_in_burst made the detection "Sign-in burst from one address" (high, malicious).
      3  2026-11-18T19:48:10.634704Z  incident            correlator            The correlator opened the incident 508657f7-d921-8cb3-add4-c2bd62528abd: Sign-in burst from one address.
      4  2026-11-18T19:48:10.640562Z  agent_decision      supervisor            Gave incident 508657f7-d921-8cb3-add4-c2bd62528abd to the monitor.
      5  2026-11-18T19:48:10.644234Z  agent_decision      monitor               Added incident 508657f7-d921-8cb3-add4-c2bd62528abd to the Defensive Graph and gave it to the analyst.
      6  2026-11-18T19:48:10.649838Z  agent_decision      analyst               The analyst agent changed the incident 508657f7-d921-8cb3-add4-c2bd62528abd from open to investigating.
      7  2026-11-18T19:48:10.653006Z  agent_decision      analyst               Incident 508657f7-d921-8cb3-add4-c2bd62528abd: The model gave no assessment: the model call failed: unavailable: no model is configured: add a [model] section to use a model. Deterministic triage: 1 detections have the verdict malicious (aegis.velocity.sign_in_burst). ATT&CK techniques: T1110.003.
      8  2026-11-18T19:48:10.658237Z  agent_decision      responder             Proposed 1 containment actions as a dry run for incident 508657f7-d921-8cb3-add4-c2bd62528abd: block_ip.
      9  2026-11-18T19:48:10.662966Z  agent_decision      responder             The responder agent proposed block_ip on ip_address:203.0.113.50: Block the address 203.0.113.50. The attack activity comes from it. Detections: aegis.velocity.sign_in_burst.
     10  2026-11-18T19:48:10.666793Z  action_proposed     responder             responder proposed the action block_ip on ip_address 203.0.113.50.
     11  2026-11-18T19:48:10.672531Z  policy_decision     dispatcher            Policy permits the action block_ip on ip_address 203.0.113.50.
     12  2026-11-18T19:48:10.676892Z  action_executed     dispatcher            Connector simulation simulated the action block_ip on ip_address 203.0.113.50. This was a dry run. Nothing changed.
```

The times in your output are the times of your run.

Records 2 to 12 are the full path of the first action. The path has the detection, the
incident, the decisions of four agents, the proposal, the policy decision, and the
result.

### One record

Each line of the audit file is one JSON record. This command shows record 12:

```sh
sed -n 12p /tmp/aegis-demo/data/audit.jsonl | python3 -m json.tool
```

```json
{
    "actor": "dispatcher",
    "evidence": [
        {
            "id": "01a1f033-d321-771c-bbe8-edf35d3c8aff",
            "kind": "action"
        },
        {
            "id": "508657f7-d921-8cb3-add4-c2bd62528abd",
            "kind": "incident"
        },
        {
            "id": "d0f148d3-cd2c-84fb-bb5e-04224517c040",
            "kind": "detection",
            "note": "aegis.velocity.sign_in_burst"
        }
    ],
    "hash": "555927dba9be60a69fdbdeb5d22a53e570b76de901cc6a5c1b6ec152498ad285",
    "id": "01a1f033-d334-7602-b5d7-9a6e38d4af3e",
    "kind": "action_executed",
    "payload": {
        "action_id": "01a1f033-d321-771c-bbe8-edf35d3c8aff",
        "approval": null,
        "connector": "simulation",
        "dry_run": true,
        "dry_run_violation": false,
        "kind": "block_ip",
        "outcome": {
            "action_id": "01a1f033-d321-771c-bbe8-edf35d3c8aff",
            "completed_at": "2026-11-18T19:48:10.676766Z",
            "connector": "simulation",
            "details": {
                "configured_connector": false
            },
            "message": "Dry run: a connector for block_ip would act on 203.0.113.50. No connector is configured for this action. Nothing changed.",
            "reversible": true,
            "status": "simulated"
        },
        "target": {
            "id": "203.0.113.50",
            "kind": "ip_address"
        }
    },
    "prev_hash": "6969f5d1191877f38d05e86b520f4aa6689279b7c4b10fabe6d457b25578d9d6",
    "sequence": 12,
    "summary": "Connector simulation simulated the action block_ip on ip_address 203.0.113.50. This was a dry run. Nothing changed.",
    "time": "2026-11-18T19:48:10.676892Z"
}
```

- `evidence` links the record to the action, to the incident, and to the detection.
- `prev_hash` is the hash of record 11. `hash` is the hash of this record.
- `payload.dry_run` is `true`, and the status of the outcome is `simulated`.
- `reversible` is `true`: `block_ip` has an inverse, so a real connector can undo it.

### Check the chain

```sh
aegis audit verify --path /tmp/aegis-demo/data/audit.jsonl
```

```text
Audit log /tmp/aegis-demo/data/audit.jsonl
  Records checked: 156
  Chain: valid
```

If one byte of one record changes, the check fails and names the record. Refer to
[operations.md](operations.md#the-audit-log).

## Examine your own events

`aegis replay` examines an event file with a configuration and prints the same report.
The file has one normalized event in each line.

```sh
aegis replay --config /tmp/aegis-demo/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run \
    --audit-file /tmp/aegis-demo/data/replay-audit.jsonl
```

- `--dry-run` makes each action a dry run, also when the configuration permits changes.
- `--audit-file` writes the audit log of this replay to a file of its own.

## Limits

- The log is a recorded example. It is not data from a real tenant.
- The demonstration uses no model. Detection tier 2 does not run, because each detection
  of the log is `malicious`. The agents use their deterministic paths.
- The demonstration does not read the `AEGIS__` environment variables.
- With no real connector, each action goes to the simulation connector. The
  demonstration does not prove that a connector can change your environment.
