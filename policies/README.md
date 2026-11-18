# Response policies

This directory has the response policies that AEGIS ships. A policy tells AEGIS which
response actions run immediately, which actions need the approval of a person, and which
actions are not permitted. You own the policy. AEGIS has no rules of its own.

The policy language is [Rego](https://www.openpolicyagent.org/docs/policy-language).
AEGIS evaluates the policy in its own process. A policy cannot open a network connection.

## Files

| File | Behavior |
| --- | --- |
| `default.rego` | Permits a dry run. Permits an action in the auto tier. Requires approval for an action in the gated tier. Denies all other requests. |
| `examples/auto_contain_service_principals.rego` | The default behavior, and containment of a service principal runs with no approval when the incident is critical. |
| `examples/maintenance_window.rego` | The default behavior, but each change is denied during the maintenance window that you give in the environment data. |
| `examples/protected_entities.rego` | The default behavior, but only a person with the role `incident_commander` can request a change to a protected entity, and the change needs approval. |
| `examples/protected_entities.yaml` | The list of protected entities for `protected_entities.rego`. Load it as a data file. |
| `examples/contain_first_with_timed_revert.rego` | The default behavior, and a reversible containment action or a friction action with a revert time of 4 hours or less runs with no approval for an incident with the severity `high` or `critical`. The revert scheduler reverts it with no approval, unless a person confirms the action. |

Each `.rego` file is a complete policy. Load one of them. Do not load two of them
together: they define the same rule. When two files give different results for a request,
AEGIS denies the request.

## How to use a policy

1. Copy `default.rego` or one of the examples to your configuration directory.
2. Read the comments at the top of the file. They describe the input, the result, and the
   changes that you can make.
3. Change the file.
4. Put the path of the file in the `paths` setting of the policy engine. Put each data
   file in the `data` setting.
5. Start AEGIS, or reload the policy.

AEGIS rejects a policy that does not compile and continues to use the policy that it has.
If a policy gives no valid result for a request, AEGIS denies the request.

## Revert requests

A revert is a request with the action `{"custom": "revert"}`. With `default.rego`, each
revert needs the approval of a person. This includes the timed revert that AEGIS requests
when nobody confirmed an action. The containment then stays until a person decides. Use
`examples/contain_first_with_timed_revert.rego` if the timed revert must run with no
person.

Refer to `crates/policy/README.md` for the full description of the input, the result, and
the configuration. Refer to `docs/response.md` for the timed revert.
