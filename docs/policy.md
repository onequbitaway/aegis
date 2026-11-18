# Policy

The response policy tells AEGIS which actions run immediately, which actions need the
approval of a person, and which actions are not permitted. You own the policy. AEGIS has
no rules of its own about targets or actions.

This document describes the input of the policy, the decision, the fail-closed behavior,
the tiers, approvals, and role-based access control. It ends with worked policies.

## Contents

- [How AEGIS uses the policy](#how-aegis-uses-the-policy)
- [The input document](#the-input-document)
- [The decision](#the-decision)
- [Fail closed](#fail-closed)
- [Tiers](#tiers)
- [Approvals](#approvals)
- [Role-based access control](#role-based-access-control)
- [The policies that AEGIS ships](#the-policies-that-aegis-ships)
- [The policy for a revert](#the-policy-for-a-revert)
- [Worked example: write and test a policy](#worked-example-write-and-test-a-policy)
- [Examine a policy](#examine-a-policy)
- [Apply a changed policy](#apply-a-changed-policy)
- [Limits](#limits)

## How AEGIS uses the policy

- The policy language is [Rego](https://www.openpolicyagent.org/docs/policy-language).
  AEGIS evaluates the policy in its own process. No sidecar is necessary.
- The key `policy.paths` of the configuration names the policy files.
- The dispatcher asks the policy before each action, also for a dry run and also for a
  request of a playbook.
- The dispatcher asks the policy a second time before it runs an approved action.
- The dispatcher writes each decision to the audit log, with its reasons.
- A policy cannot open a network connection and cannot read the environment of the
  process.

## The input document

AEGIS gives each request to the policy as the `input` document. This is the input for
one request of the recorded attack log: the Responder agent asks to remove a credential.

```json
{
  "action": {
    "id": "01a1ed6a-5ef4-77ba-b9d4-839804bcefd8",
    "kind": "revoke_credential",
    "target": {
      "kind": "service_principal",
      "id": "sp-sync-helper",
      "name": "Sync Helper",
      "tenant": "tenant-contoso"
    },
    "parameters": { "credential_id": "credential-1" },
    "incident_id": "508657f7-d921-8cb3-add4-c2bd62528abd",
    "requested_by": "responder",
    "reason": "Remove the credentials of service_principal sp-sync-helper, so that the attacker cannot use them. Detections: aegis.velocity.credential_after_grant.",
    "evidence": [
      { "kind": "incident", "id": "508657f7-d921-8cb3-add4-c2bd62528abd" }
    ],
    "dry_run": true,
    "requested_at": "2026-11-18T06:48:53.748524Z"
  },
  "default_tier": "gated",
  "principal": { "id": "responder", "kind": "agent", "roles": ["responder"] },
  "incident": {
    "id": "508657f7-d921-8cb3-add4-c2bd62528abd",
    "severity": "critical",
    "status": "investigating"
  },
  "environment": null
}
```

The sample shows one of the evidence links of the request.

| Field | Contents |
| --- | --- |
| `input.action.kind` | The action type, for example `"notify"` or `"disable_user"`. A custom action is an object: `{"custom": "<name>"}`. |
| `input.action.target` | The entity that the action changes: `kind`, `id`, `name`, `tenant`. |
| `input.action.parameters` | The parameters for the connector. |
| `input.action.dry_run` | `true` if the action must change nothing. |
| `input.action.requested_by` | The agent, or `playbook:<name>` for a playbook. |
| `input.action.requested_at` | The time of the request, in RFC 3339 form. |
| `input.action.incident_id`, `input.action.reason`, `input.action.evidence` | The incident, the reason, and the evidence of the request. |
| `input.default_tier` | `"auto"` for a safe and reversible action. `"gated"` for each other action. |
| `input.principal` | The identity that makes the request: `id`, `kind`, `roles`. |
| `input.incident` | The incident, if there is one: `id`, `severity`, `status`. |
| `input.environment` | The table `[response.environment]` of the configuration, or `null`. |

The principal of a request is one of these:

| Requester | `input.principal.id` | `kind` | `roles` |
| --- | --- | --- | --- |
| An agent | The role name, for example `responder` | `agent` | The role name |
| A playbook | `playbook-engine` | `system` | `playbook` |

## The decision

AEGIS reads one rule of the policy. The default rule is `data.aegis.response.decision`.
The rule must return an object:

| Field | Value |
| --- | --- |
| `effect` | `"allow"`, `"require_approval"`, or `"deny"`. Necessary. |
| `tier` | `"auto"` or `"gated"`. Optional. The default is `input.default_tier`. |
| `reasons` | A list of sentences that explain the decision. Optional. |

| Effect | What the dispatcher does |
| --- | --- |
| `allow` | It calls the connector immediately. |
| `require_approval` | It puts the request in the approval queue. The action runs only after a person approves it. |
| `deny` | It does not call a connector. |

Write a reason for each rule. The reason goes to the audit log, to the console, and to
the incident timeline.

## Fail closed

If the policy gives no valid decision, AEGIS denies the action. This occurs in each of
these conditions:

- The rule has no value for the request.
- The evaluation fails, for example because two rules give different values.
- The evaluation takes more time than `policy.evaluation_time_limit_ms`.
- The result is not an object, or it has no `effect`, an `effect` that is not known, or a
  field that is not known.

Such a decision has the policy name `aegis.policy.fail_closed`. Its first reason gives
the cause. These are reasons of real runs:

```text
The `effect` field of the policy result has a value that is not valid: `permit`.
The policy rule data.aegis.response.decision gave no result for this request.
The evaluation of the policy rule data.aegis.response.decision failed: rule conflicts with rule at /tmp/aegis-policy/policies/default.rego:72:1 at /tmp/aegis-policy/policies/site.rego:32:1.
```

The third message is the result of two complete policies in `policy.paths`. Each shipped
policy file is a complete policy. Load one of them, not two together.

More fail-closed rules of the dispatch path:

- An error of the policy engine is a denial.
- A request that the audit log cannot record does not run.
- A policy file that does not compile, or that does not have the decision rule, stops the
  start of AEGIS.

Always write a `default decision` rule that denies. Then each request that no rule
matches has a clear reason in the audit log.

## Tiers

Each action type has a default tier. The policy gets it as `input.default_tier`.

| Tier | Action types | Meaning |
| --- | --- | --- |
| `auto` | `enrich`, `tag`, `notify`, `snapshot_evidence`, `open_ticket` | Safe and reversible. |
| `gated` | `revoke_credential`, `rotate_credential`, `disable_service_principal`, `disable_user`, `kill_session`, `isolate_host`, `block_ip`, `rotate_secret`, `deploy_honeytoken`, and each custom action | Disruptive. |

The tier is data for the policy. The policy decides what each tier means. The default
policy permits the auto tier and requires approval for the gated tier.

To change the tier of an action type in the default policy, change `default.rego`. Add
the name of the action type to one of the two sets at the top of the file:

```rego
# Action kinds that need approval always. Example: {"open_ticket", "block_ip"}
always_gated := {"open_ticket"}

# Action kinds that run with no approval. Example: {"kill_session"}
always_auto := {"kill_session"}
```

## Approvals

A request with the effect `require_approval` waits in the approval queue. A person
decides it through the web console, the REST API, Slack, or Teams.

1. The dispatcher writes an `approval_requested` audit record and publishes the request.
2. A principal with the permission `approve_actions` approves or rejects the request.
3. AEGIS writes an `approval_decided` audit record with the identity of the principal.
4. For an approval, the dispatcher evaluates the policy again. If the policy still
   permits the action, the dispatcher calls the connector one time.
5. For a rejection, the action does not run. The agent that proposed it gets a denial.

Two approval rules are on by default. The section `[approval]` sets them.

| Rule | Effect |
| --- | --- |
| `four_eyes` | The principal that requested an action cannot approve it. The principal can reject it. |
| `humans_only` | Only a principal of the type `human` can decide. |

More rules:

- One approval permits one attempt. If the connector call fails, send a new request.
- A second decision on one request is an error.
- If the audit log does not take the decision record, the request stays pending.

The quickstart shows an approval in the console. Refer to
[quickstart.md](quickstart.md#7-decide-an-approval).

## Role-based access control

Role-based access control decides what a person can do through the operator API. It is
not a part of the Rego policy.

The section `[rbac.roles]` gives the permissions of each role. A principal of the section
`[[api.principals]]` names its roles.

| Permission | Permits |
| --- | --- |
| `view_incidents` | Read incidents, the graph, the agents, the approval queue, and the live feed. |
| `view_audit` | Read the audit log, the chain check, and the explanations. |
| `approve_actions` | Approve or reject a gated action. |
| `run_playbooks` | List the playbooks and start a playbook for an incident. |
| `administer` | Give a goal to the agents. |
| `manage_policy` | Reload the rule pack, the policy, and the playbooks through the library function `App::reload_by`. |
| `manage_connectors` | No function of the `aegis` program uses this permission. |

- No permission includes a different permission.
- A role that the section does not name gives no permission.
- A request with no valid token gets the status 401. A principal with no permission for
  a route gets the status 403.

Keep the role that approves apart from the role that administers. This configuration has
three roles:

```toml
[rbac.roles]
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]
admin = ["view_incidents", "view_audit", "run_playbooks", "administer"]
```

The Rego policy can read the roles of the principal that makes a request, in
`input.principal.roles`. For an agent, the single role is the role name of the agent.

## The policies that AEGIS ships

`aegis init` copies these files to the directory `policies` of the starter directory.

| File | Behavior |
| --- | --- |
| [`policies/default.rego`](../policies/default.rego) | Permits a dry run. Permits an action in the auto tier. Requires approval for an action in the gated tier. Denies all other requests. |
| [`policies/examples/auto_contain_service_principals.rego`](../policies/examples/auto_contain_service_principals.rego) | The default behavior, and containment of a service principal runs with no approval when the incident is critical. |
| [`policies/examples/maintenance_window.rego`](../policies/examples/maintenance_window.rego) | The default behavior, but each change is denied in a maintenance window. |
| [`policies/examples/protected_entities.rego`](../policies/examples/protected_entities.rego) | The default behavior, but only a person with the role `incident_commander` can request a change to a protected entity. |
| [`policies/examples/contain_first_with_timed_revert.rego`](../policies/examples/contain_first_with_timed_revert.rego) | The default behavior, and a reversible action with a short revert time runs first. The revert scheduler reverts it with no approval. |
| [`examples/offline-demo/policies/approval-rehearsal.rego`](../examples/offline-demo/policies/approval-rehearsal.rego) | The default behavior, but one action type needs approval also in a dry run. |

The comments at the top of each file tell you how to change it.

The default policy has these rules, in this sequence:

```rego
# Rule 4. No other rule matches: deny.
default decision := {
	"effect": "deny",
	"tier": "gated",
	"reasons": ["No rule of the policy permits this request."],
}

# Rule 1. A dry run is allowed.
decision := {
	"effect": "allow",
	"tier": tier,
	"reasons": ["The request is a dry run. A dry run changes nothing."],
} if {
	input.action.dry_run == true
}

# Rule 2. An action in the auto tier is allowed.
else := {
	"effect": "allow",
	"tier": "auto",
	"reasons": ["The action is in the auto tier."],
} if {
	tier == "auto"
}

# Rule 3. An action in the gated tier needs approval.
else := {
	"effect": "require_approval",
	"tier": "gated",
	"reasons": ["The action is in the gated tier. A person must approve it."],
} if {
	tier == "gated"
}
```

The `else` chain gives the rules a sequence. The first rule that matches makes the
decision.

## The policy for a revert

A revert is a request of its own. The policy decides it as each other request.

| Input | Value for a revert |
| --- | --- |
| `input.action.kind` | `{"custom": "revert"}` |
| `input.action.target` | The target of the action that the revert undoes. |
| `input.action.parameters.reverts` | `action_id`, `kind`, `requested_by`, `connector`, `executed_at`, and `revert_after_seconds` if the action had a revert time. |
| `input.principal` | The person who requests the revert, or the revert scheduler: `id` is `revert-scheduler`, and `kind` is `system`. |
| `input.default_tier` | `gated` |

An action with a revert time has the parameter `revert_after_seconds`. A policy can
permit such an action with no approval. These rules are a part of
`policies/examples/contain_first_with_timed_revert.rego`:

```rego
has_short_revert if {
	seconds := input.action.parameters.revert_after_seconds
	is_number(seconds)
	seconds >= 1
	seconds <= max_revert_after_seconds
}

contain_first if {
	is_contain_first_action
	has_short_revert
	input.incident.severity in urgent_severities
}

timed_revert if {
	input.action.kind.custom == "revert"
	input.principal.kind == "system"
	input.principal.id == revert_scheduler
	is_number(input.action.parameters.reverts.revert_after_seconds)
}
```

- With `policies/default.rego`, each revert needs the approval of a person. The timed
  revert of the scheduler then waits in the approval queue, and the containment stays.
- `policies/examples/contain_first_with_timed_revert.rego` is a complete policy for
  "contain first". Its comments tell you how to change it.
- The four-eyes rule applies: the person who requests a revert cannot approve it.

Refer to [response.md](response.md).

## Worked example: write and test a policy

This example writes a policy for a site with two special rules:

- The account `user-dana` is a protected entity. No agent and no playbook can make it a
  target, also in a dry run.
- In a maintenance window, a block of an address needs the approval of a person, also in
  a dry run.

All other requests follow the default behavior.

Build the program first. Refer to [quickstart.md](quickstart.md). Do these steps in the
root of the repository.

1. Make a starter directory.

   ```sh
   aegis init --dir /tmp/aegis-policy
   ```

2. Write the file `/tmp/aegis-policy/policies/site.rego`:

   ```rego
   # The response policy of this site.
   package aegis.response

   import rego.v1

   # The entities that no agent and no playbook can change.
   protected := {
       {"kind": "user", "id": "user-dana"},
   }

   target_is_protected if {
       some entity in protected
       entity.kind == input.action.target.kind
       entity.id == input.action.target.id
   }

   in_maintenance_window if {
       window := input.environment.maintenance_window
       requested := time.parse_rfc3339_ns(input.action.requested_at)
       requested >= time.parse_rfc3339_ns(window.start)
       requested < time.parse_rfc3339_ns(window.end)
   }

   # No other rule matches: deny.
   default decision := {
       "effect": "deny",
       "tier": "gated",
       "reasons": ["No rule of the policy permits this request."],
   }

   # Rule 1. A protected entity is never a target, also in a dry run.
   decision := {
       "effect": "deny",
       "reasons": ["The target is a protected entity."],
   } if {
       target_is_protected
   }

   # Rule 2. In the maintenance window, a block of an address needs a person.
   else := {
       "effect": "require_approval",
       "tier": "gated",
       "reasons": ["The request is in the maintenance window. A person must approve a block."],
   } if {
       in_maintenance_window
       input.action.kind == "block_ip"
   }

   # Rule 3. A dry run is allowed. A dry run changes nothing.
   else := {
       "effect": "allow",
       "reasons": ["The request is a dry run. A dry run changes nothing."],
   } if {
       input.action.dry_run == true
   }

   # Rule 4. An action in the auto tier is allowed.
   else := {
       "effect": "allow",
       "tier": "auto",
       "reasons": ["The action is in the auto tier."],
   } if {
       input.default_tier == "auto"
   }

   # Rule 5. An action in the gated tier needs approval.
   else := {
       "effect": "require_approval",
       "tier": "gated",
       "reasons": ["The action is in the gated tier. A person must approve it."],
   } if {
       input.default_tier == "gated"
   }
   ```

3. Open `/tmp/aegis-policy/aegis.toml`. In the section `[policy]`, name the new file. The
   line then reads:

   ```toml
   paths = ["policies/site.rego"]
   ```

4. In the same file, add these lines after the line `playbook_dir = "playbooks"`. They
   give a maintenance window to the policy. This window is long, so that the test is in
   the window.

   ```toml
   [response.environment]
   maintenance_window = { start = "2026-01-01T00:00:00Z", end = "2036-01-01T00:00:00Z" }
   ```

5. Check the configuration. The check compiles the policy.

   ```sh
   aegis config check --config /tmp/aegis-policy/aegis.toml
   ```

   ```text
   The configuration /tmp/aegis-policy/aegis.toml is valid.
   ```

6. Test the policy with the recorded attack log, as a dry run.

   ```sh
   aegis replay --config /tmp/aegis-policy/aegis.toml \
       --events fixtures/artex_style_attack.jsonl --dry-run
   ```

   These are the lines of the requests of the agents:

   ```text
     block_ip                    ip_address 203.0.113.50                         responder                                 pending approval 01a1ed69-3f53-7332-90be-d3f15947c9cc
     kill_session                user user-dana                                  responder                                 denied: The target is a protected entity.
     deploy_honeytoken           secret honeytoken-credential-tenant-contoso     deception                                 executed: simulated (connector honeytokens)
     disable_service_principal   service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
     revoke_credential           service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
     block_ip                    ip_address 203.0.113.51                         responder                                 pending approval 01a1ed69-40e5-7496-b0bd-3b8be2ac094c
     block_ip                    ip_address 192.0.2.77                           responder                                 pending approval 01a1ed69-412e-775b-a74a-2b3c679735d9
   ```

   - Rule 1 denied `kill_session` on the protected account.
   - Rule 2 put each `block_ip` request in the approval queue.
   - Rule 3 permitted the other dry runs.

   A denial and a pending approval are not failures of a playbook:

   ```text
   Playbooks (4)
     block-password-spray-source: 2 requests, 0 failures
     contain-compromised-user: 3 requests, 0 failures
     contain-rogue-service-principal: 6 requests, 0 failures
     respond-to-honeytoken-trip: 5 requests, 0 failures
   ```

7. Read a decision in the audit log. Each `policy_decision` record has the effect, the
   reasons, the rule, and the incident. This is the payload of the denial:

   ```json
   {
    "action_id": "01a1ed69-3fa0-750d-97d9-17a001e3c900",
    "approval": null,
    "decision": {
     "effect": "deny",
     "evaluated_at": "2026-11-18T06:47:40.208518Z",
     "policy": "aegis.response.decision",
     "reasons": [
      "The target is a protected entity."
     ],
     "tier": "gated"
    },
    "error": null,
    "fail_closed": false,
    "incident": {
     "id": "508657f7-d921-8cb3-add4-c2bd62528abd",
     "severity": "high",
     "status": "investigating"
    }
   }
   ```

A replay keeps no approval queue after it ends. To decide a request, run the service.
Refer to [quickstart.md](quickstart.md).

## Examine a policy

A `print` call in a policy writes to the log of AEGIS at the level `debug`. Use it to
see the input of a rule. This rule is from a test policy with the file name
`show-input.rego`:

```rego
decision := {"effect": "allow", "reasons": ["The request is a dry run."]} if {
	print("principal", json.marshal(input.principal), input.default_tier)
	input.action.dry_run == true
}
```

Run a replay with the log level `debug`:

```sh
AEGIS__TELEMETRY__LOG_LEVEL=debug aegis replay \
    --config /tmp/aegis-policy/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run
```

The log then has one line for each call, for example:

```text
DEBUG aegis_policy::rego: the policy printed a message action=01a1ed6a-df40-7516-8e46-4f5fc64cfc72 output=/tmp/aegis-policy/policies/show-input.rego:8: principal {"id":"responder","kind":"agent","roles":["responder"]} gated
```

The log cuts a long message. Print one part of the input in each call. Do not print
secrets, and remove the `print` calls after the test.

## Apply a changed policy

The `aegis` program loads the policy at the start. To apply a changed policy:

1. Run `aegis config check`. The check compiles the policy.
2. Test the policy with `aegis replay --dry-run` on recorded events.
3. Stop the service, and start it again.

At each start, AEGIS writes a `config_change` audit record with the SHA-256 digest of the
policy. Compare the digest with the digest of the file that you approved. The log line
`loaded the policy digest=...` has the same value.

The policy engine itself can change its policy with no restart. A program that uses the
library calls `App::reload`. If the new policy does not compile, the old policy stays in
use. The `aegis` program has no command that calls this function.

## Limits

- The policy decides one request at a time. It does not see other requests, and it has
  no state.
- The policy cannot call a network service. The functions `http.send`,
  `net.lookup_ip_addr`, and `opa.runtime` do not exist in this engine.
- A revert has the action type `{custom: revert}` for each action that it undoes. The
  policy reads the type of that action from `input.action.parameters.reverts.kind`.
- The dispatcher does not try a failed action again.
- The approval queue of the memory storage does not continue after a stop.
- `aegis config check` does not find two complete policies that conflict. The conflict
  shows only when the policy evaluates a request, and then each request is denied.
