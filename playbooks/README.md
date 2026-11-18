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

## Before you use a playbook

1. Run the playbook in dry-run mode (`RunMode::DryRun`). Examine the report and the audit
   records. A dry run changes nothing.
2. Make sure that a connector supports each action of the playbook. The identity actions
   (`disable_service_principal`, `disable_user`, `kill_session`, `revoke_credential`) need the
   Microsoft Graph connector. The other actions need a webhook endpoint for the action type.
3. Set your policy. Each request goes through the policy engine. A playbook cannot skip the
   policy or an approval.

## Conventions in the samples

- The fixed targets `security-operations`, `incident-response`, and `identity-team` are names
  for a chat channel and two ticket queues. Your webhook automation maps them to real places.
- `revoke_credential` reads the key of the credential from the detection attribute
  `credential_id`. If no detection of the incident has this attribute, the step fails and
  sends no request.
- Each step that selects entities has a `max_targets` limit. A step with more targets fails
  and sends no request. This prevents a mass change from one incorrect incident.
- Each step has `continue_on_error: true`. Thus a containment step that fails does not stop
  the notification and the ticket. The run report shows each failure. Remove the field from
  a step that must succeed before the next steps run.

The engine loads only `.yaml` and `.yml` files. It ignores this file.
