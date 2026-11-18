# Sample playbooks

These playbooks are defensive samples for the AEGIS playbook engine (`aegis-respond`). Each
playbook changes only the environment of the operator: the identity tenant, the firewall, the
EDR product, the chat channel, and the ticket system.

Copy a playbook and adapt it to your environment. The format is in
[`crates/respond/README.md`](../crates/respond/README.md#playbooks).

| File | Use |
| --- | --- |
| `contain-rogue-service-principal.yaml` | Contain a service principal that an attacker controls. This playbook is for the recorded attack in `fixtures/artex_style_attack.jsonl`. |
| `contain-compromised-user.yaml` | Stop the sessions of a compromised user account and disable the account. |
| `block-password-spray-source.yaml` | Block the address that a password spray comes from. |
| `isolate-compromised-host.yaml` | Save the evidence of a compromised host and isolate the host. |
| `respond-to-honeytoken-trip.yaml` | Save the evidence of a honeytoken trip, block the source address, and tell the security team. |
| `raise-friction-critical-identity-incident.yaml` | Stop user consent to applications in the tenant during a critical identity incident, with a timed revert, and tell the security team. |

## Before you use a playbook

1. Run the playbook in dry-run mode (`RunMode::DryRun`). Examine the report and the audit
   records. A dry run changes nothing.
2. Make sure that a connector supports each action of the playbook. The identity actions
   (`disable_service_principal`, `disable_user`, `kill_session`, `revoke_credential`) need the
   Microsoft Graph connector. The other actions need a webhook endpoint for the action type.
3. Set your policy. Each request goes through the policy engine. A playbook cannot skip the
   policy or an approval.
4. Make sure that each step with `revert_after` can do its timed revert. Refer to
   [Timed revert](#timed-revert).

## Timed revert

A wrong containment has a cost: a disabled account stops the work of its owner, and a blocked
address can stop legitimate users. Each reversible containment step in the samples has
`revert_after`. The action runs, and AEGIS reverts it at that time unless a person confirms
it. The notification and the ticket of each playbook tell the security team to confirm.

| Step | Playbooks | `revert_after` |
| --- | --- | --- |
| `block_ip` | `block-password-spray-source`, `contain-rogue-service-principal`, `respond-to-honeytoken-trip` | `4h` |
| `disable_user` | `contain-compromised-user` | `4h` |
| `disable_service_principal` | `contain-rogue-service-principal` | `4h` |
| `isolate_host` | `isolate-compromised-host` | `4h` |
| `restrict_user_consent` | `raise-friction-critical-identity-incident` | `2h` |

`kill_session`, `revoke_credential`, `snapshot_evidence`, `notify`, and `open_ticket` have no
inverse. The loader rejects `revert_after` on these steps.

A step with `revert_after` needs these items when it is not a dry run:

- A dispatcher with a revert store, and a revert scheduler that runs. Without a revert
  store, the step fails and changes nothing.
- A connector that can undo the action. For a webhook endpoint, set `reversible: true`. If
  the connector cannot undo the action, the step fails and changes nothing.
- A policy that fits. With `policies/default.rego`, each containment action and each revert
  needs the approval of a person. `policies/examples/contain_first_with_timed_revert.rego`
  lets a reversible action with a revert time of 4 hours or less run first, and lets the
  scheduler revert it.

Remove `revert_after` from a step if the action must stay until a person reverts it.

## The friction playbook

`raise-friction-critical-identity-incident.yaml` does not act on the attacker. It changes a
setting of your own tenant through Microsoft Graph: users cannot consent to applications.
The change applies to all users of the tenant, so the sample has three limits:

- The trigger has a `tenants` list with an example tenant. Replace it with your tenant. The
  playbook runs for no other tenant.
- The step has `revert_after: 2h`. AEGIS writes the earlier setting again after 2 hours,
  unless a person confirms the change.
- `restrict_user_consent` is a custom action, so the default policy requires approval.

The step needs the Microsoft Graph connector with the application permission
`Policy.ReadWrite.Authorization`.

## Conventions in the samples

- The fixed targets `security-operations`, `incident-response`, and `identity-team` are names
  for a chat channel and two ticket queues. Your webhook automation maps them to real places.
- `revoke_credential` reads the key of the credential from the detection attribute
  `credential_id`. If no detection of the incident has this attribute, the step fails and
  sends no request.
- `revert_after` is the time in which a person confirms the action. It is not the life of
  the action in your product: `duration_hours` of a `block_ip` step is a parameter for your
  firewall automation.
- Each step that selects entities has a `max_targets` limit. A step with more targets fails
  and sends no request. This prevents a mass change from one incorrect incident.
- Each step has `continue_on_error: true`. Thus a containment step that fails does not stop
  the notification and the ticket. The run report shows each failure. Remove the field from
  a step that must succeed before the next steps run.

The engine loads only `.yaml` and `.yml` files. It ignores this file.
