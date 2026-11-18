# Playbooks

A playbook is a YAML file that tells AEGIS which response actions to request for a known
type of incident. This document describes the format, the triggers, the target
selectors, the templates, the dry run, and how the policy applies.

All playbooks are defensive. Each action changes only the environment of the operator.

## Contents

- [How a playbook runs](#how-a-playbook-runs)
- [The format](#the-format)
- [Triggers](#triggers)
- [Steps](#steps)
- [Target selectors](#target-selectors)
- [Templates](#templates)
- [Run modes and the dry run](#run-modes-and-the-dry-run)
- [How the policy applies](#how-the-policy-applies)
- [Worked example: write and run a playbook](#worked-example-write-and-run-a-playbook)
- [Run a playbook through the API](#run-a-playbook-through-the-api)
- [The sample playbooks](#the-sample-playbooks)
- [Limits](#limits)

## How a playbook runs

1. The key `response.playbook_dir` names a directory. AEGIS loads each `.yaml` and `.yml`
   file of that directory at the start.
2. For an incident that is `open` or `investigating` and has a new detection, AEGIS
   examines the trigger of each playbook.
3. Each playbook that matches runs one time for that incident.
4. Each step makes one action request for each of its targets.
5. Each request goes through the one dispatcher. The path has the policy, an approval by
   a person, a connector, and the audit log.

A playbook does not wait for the Analyst agent. It runs when its trigger matches. Use the
trigger and the policy to control what a playbook can do.

The module `responder` must be in `[modules]`, and `response.playbooks` must not be
`"off"`.

## The format

```yaml
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
  entity_kinds: [ip_address]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    max_targets: 10
    parameters:
      duration_hours: 24
    reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
    continue_on_error: true
```

| Key | Necessary | Contents |
| --- | --- | --- |
| `name` | Yes | The name of the playbook. The requester of each request is `playbook:<name>`. |
| `description` | Yes | What the playbook does. |
| `trigger` | Yes | The conditions for an incident. |
| `steps` | Yes | The ordered steps. |

A key that the format does not know is an error. A playbook that is not valid stops the
start of AEGIS, and the message names the file.

## Triggers

All conditions of a trigger must be true. A trigger must have one condition or more.

| Field | Condition |
| --- | --- |
| `min_severity` | The incident has this severity or a larger one. |
| `techniques_any` | The incident has one or more of these ATT&CK techniques. |
| `techniques_all` | The incident has all of these ATT&CK techniques. |
| `entity_kinds` | The incident has an entity of each of these types. |
| `tenants` | The incident is in one of these tenants. |
| `statuses` | The incident has one of these states. The default is `open` and `investigating`. |

- A technique with no sub-technique, for example `T1098`, also matches its
  sub-techniques.
- The techniques of an incident come from the tags of the rules that matched. Refer to
  [detection-packs.md](detection-packs.md#attck-tags).
- An incident grows. A playbook runs at the first state of the incident that matches its
  trigger. Entities that come later are not targets of that run.

## Steps

| Field | Contents |
| --- | --- |
| `id` | A name for the step. The default is `step-N`. |
| `action` | The action type. Refer to the table below. |
| `target` | The target selector. |
| `parameters` | Parameters for the connector. Each text value is a template. |
| `reason` | A template for the reason of the request. |
| `continue_on_error` | With `true`, a failure of this step does not stop the playbook. The default is `false`. |
| `max_targets` | The largest number of targets. A step with more targets fails and sends no request. The default is 20. |

The action types and their default tiers:

| Tier | Action types |
| --- | --- |
| Auto: safe and reversible | `enrich`, `tag`, `notify`, `snapshot_evidence`, `open_ticket` |
| Gated: disruptive | `revoke_credential`, `rotate_credential`, `disable_service_principal`, `disable_user`, `kill_session`, `isolate_host`, `block_ip`, `rotate_secret`, `deploy_honeytoken`, and each custom action |

For a custom action of a plugin or a webhook, write `action: {custom: quarantine_mailbox}`.

The policy of the operator can change the tier of an action. Refer to
[policy.md](policy.md).

## Target selectors

| Selector | Targets |
| --- | --- |
| `{each_entity: <type>}` | Each entity of the incident that has this type, for example `user` or `ip_address`. |
| `{fixed: {kind: <type>, id: <id>, name: <name>}}` | One fixed entity, for example a chat channel or a ticket queue. |
| `incident_tenant` | The tenant of the incident. |

- A step with `each_entity` and no such entity in the incident sends no request.
- `max_targets` prevents a mass change from one incorrect incident. Set it for each step
  that selects entities.
- The entity types are `user`, `service_principal`, `application`, `device`, `host`,
  `ip_address`, `domain`, `tenant`, `session`, `secret`, `role`, `resource`, and `other`.

## Templates

A template variable goes between `{{` and `}}`.

| Variable | Value |
| --- | --- |
| `playbook.name` | The name of the playbook. |
| `incident.id`, `incident.title`, `incident.severity`, `incident.status`, `incident.tenant` | The data of the incident. |
| `incident.techniques` | The ATT&CK technique identifiers of the incident, with `, ` between them. |
| `target.id`, `target.kind`, `target.name`, `target.tenant` | The target of the request. |
| `detection.<key>` | The first value of the attribute `<key>` in the detections of the incident. |

- A variable that the engine does not know is an error at the start:

  ```text
  step notify-security-team: reason: the template variable "incident.nothing" is not known
  ```

- A variable with no value makes that request fail before the engine sends it:

  ```text
  reason: no detection of the incident has the attribute no_such_key
  ```

- The text of an incident can come from an attacker. A template puts it in the reason
  and in the parameters as text only.

## Run modes and the dry run

The key `response.playbooks` sets how the playbooks run:

| `response.playbooks` | Effect |
| --- | --- |
| `"off"` | No playbook runs. |
| `"dry_run"` (the default) | Each matching playbook runs, and each request is a dry run. |
| `"live"` | Each matching playbook runs. A request can change the environment, if the policy permits it. |

`response.dry_run = true` makes each request a dry run in all three modes. It is the
default. To let a playbook change the environment, you must set `response.dry_run = false`
and `response.playbooks = "live"`.

In a dry run:

- The policy still evaluates the request.
- The connector changes nothing and reports the status `simulated`.
- The audit log records each step, and says that the action was a dry run.

Always run a new playbook as a dry run first, and read the audit records.

## How the policy applies

A playbook cannot skip the policy or an approval. For each request, the policy gets this
data:

| Policy input | Value for a playbook request |
| --- | --- |
| `input.principal.id` | `playbook-engine` |
| `input.principal.kind` | `system` |
| `input.principal.roles` | `["playbook"]` |
| `input.action.requested_by` | `playbook:<name>` |
| `input.action.kind`, `input.action.target` | The action type and the target of the step. |
| `input.incident` | The identifier, the severity, and the state of the incident. |

The result for one step is one of these:

| Policy effect | Result of the step | A failure of the step |
| --- | --- | --- |
| `allow` | The connector does the action, or simulates it in a dry run. | No, unless the connector returns an error. |
| `require_approval` | The request waits in the approval queue. | No |
| `deny` | The request does not run. | No |

A denial and a pending approval are not failures. The playbook continues with the next
step.

With the default policy and with changes permitted, each step in the gated tier waits
for the approval of a person. The four-eyes rule does not stop a person who approves a
playbook request, because the requester is the playbook engine.

## Worked example: write and run a playbook

This example adds a playbook that reports a privileged role that a workload identity
got. It uses three actions of the auto tier, the three target selectors, and a
`detection` variable.

Build the program first. Refer to [quickstart.md](quickstart.md). Do these steps in the
root of the repository.

1. Make a starter directory.

   ```sh
   aegis init --dir /tmp/aegis-playbook
   ```

2. Write the file `/tmp/aegis-playbook/playbooks/report-privileged-role.yaml`:

   ```yaml
   # Tell the identity team about a privileged role that a workload identity got.
   name: report-privileged-role
   description: >-
     Label the service principal that got a privileged role, tell the security team, and
     open a ticket for the review of the role.
   trigger:
     min_severity: high
     techniques_any:
       - T1098.003  # Additional Cloud Roles
     entity_kinds:
       - service_principal
   steps:
     - id: tag-service-principal
       action: tag
       target:
         each_entity: service_principal
       max_targets: 3
       parameters:
         label: under-review
       reason: >-
         Incident {{incident.id}}: label {{target.name}} ({{target.id}}) for a review of
         its roles.

     - id: notify-security-team
       action: notify
       target:
         fixed:
           kind: other
           id: security-operations
           name: Security operations channel
       parameters:
         title: "{{incident.title}}"
         role: "{{detection.role_name}}"
       reason: >-
         Incident {{incident.id}} ({{incident.severity}}): a workload identity got the role
         {{detection.role_name}} in the tenant {{incident.tenant}}.
       continue_on_error: true

     - id: open-ticket
       action: open_ticket
       target: incident_tenant
       parameters:
         title: "Review the role {{detection.role_name}}"
         priority: "{{incident.severity}}"
       reason: >-
         Incident {{incident.id}}: review each assignment of the role
         {{detection.role_name}}. Playbook: {{playbook.name}}.
       continue_on_error: true
   ```

3. Check the configuration. The check loads each playbook.

   ```sh
   aegis config check --config /tmp/aegis-playbook/aegis.toml
   ```

   The summary lists the new playbook:

   ```text
     playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, report-privileged-role, respond-to-honeytoken-trip
   ```

4. Examine the recorded attack log as a dry run.

   ```sh
   aegis replay --config /tmp/aegis-playbook/aegis.toml \
       --events fixtures/artex_style_attack.jsonl --dry-run
   ```

   The report has three more actions and one more playbook:

   ```text
     tag                         service_principal sp-sync-helper                playbook:report-privileged-role           executed: simulated (connector simulation)
     notify                      other security-operations                       playbook:report-privileged-role           executed: simulated (connector simulation)
     open_ticket                 tenant tenant-contoso                           playbook:report-privileged-role           executed: simulated (connector simulation)
   ```

   ```text
   Playbooks (5)
     report-privileged-role: 3 requests, 0 failures
   ```

5. To read the full requests, add `--format json`. This is the `notify` request of the
   run:

   ```json
   {
     "kind": "notify",
     "target": {
       "kind": "other",
       "id": "security-operations",
       "name": "Security operations channel"
     },
     "parameters": {
       "role": "Global Administrator",
       "title": "Multi-stage attack: 5 ATT&CK techniques in 6 detections"
     },
     "requested_by": "playbook:report-privileged-role",
     "reason": "Incident 508657f7-d921-8cb3-add4-c2bd62528abd (critical): a workload identity got the role Global Administrator in the tenant tenant-contoso.",
     "dry_run": true
   }
   ```

   - `{{detection.role_name}}` became `Global Administrator`, from the detection of the
     role assignment.
   - The title shows the incident at the moment when the trigger matched: five
     techniques in six detections.

The directory [`examples/device-code-phishing`](../examples/device-code-phishing/README.md)
has one more playbook, with the detection pack that triggers it.

## Run a playbook through the API

A principal with the permission `run_playbooks` can start a playbook for an incident.

```sh
curl -s -X POST -H "Authorization: Bearer $AEGIS_TOKEN_ALICE" \
    -H "Content-Type: application/json" \
    -d '{"incident_id": "508657f7-d921-8cb3-add4-c2bd62528abd", "mode": "dry_run"}' \
    http://127.0.0.1:8080/api/v1/playbooks/block-password-spray-source/runs
```

- The answer has `trigger_matched` and the run with one result for each request.
- `response.playbooks` is the limit. With `"dry_run"`, each run is a dry run, also if the
  request asks for `"live"`. With `"off"`, the API has no playbook.
- The API writes an audit record with the principal before it starts the run.
- A run through the API does not use the rule "one time for one incident".

## The sample playbooks

The directory [`playbooks`](../playbooks/README.md) has five samples. `aegis init` copies
them to the starter directory.

| File | Use |
| --- | --- |
| `contain-rogue-service-principal.yaml` | Contain a service principal that an attacker controls. |
| `contain-compromised-user.yaml` | Stop the sessions of a compromised user account and disable the account. |
| `block-password-spray-source.yaml` | Block the address that a password spray comes from. |
| `isolate-compromised-host.yaml` | Save the evidence of a compromised host and isolate the host. |
| `respond-to-honeytoken-trip.yaml` | Save the evidence of a honeytoken use, block the source address, and tell the security team. |

Each action needs a connector that supports it. The identity actions need the Microsoft
Graph connector. The other actions need a webhook endpoint or a plugin for the action
type. Refer to [connectors.md](connectors.md).

## Limits

- The `aegis` program loads the playbooks at the start. To apply a changed playbook,
  stop the service and start it again.
- AEGIS remembers in memory which playbook ran for which incident. After a restart, a
  playbook can run a second time for an old incident.
- A playbook has no condition between steps and no wait. Each step runs in sequence.
- The dispatcher does not try a failed action again.
- A step cannot undo the action of a step before it. The dispatcher has no path for
  `revert`.
- A function that makes a response plan with a model exists in `aegis-respond`. The
  `aegis` program does not use it.
