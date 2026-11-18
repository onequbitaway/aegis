# The default response policy of AEGIS.
#
# AEGIS asks this policy before it does a response action. You own this file. Change it to
# fit your environment. AEGIS has no rules of its own about which actions it can do.
#
# WHAT THIS POLICY DOES
#
#   1. A dry run is allowed. A dry run changes nothing.
#   2. An action in the "auto" tier is allowed.
#   3. An action in the "gated" tier needs the approval of a person.
#   4. All other requests are denied.
#
# THE INPUT
#
#   input.action.kind          The action, for example "notify" or "disable_user".
#                              A plugin action is an object: {"custom": "<name>"}.
#   input.action.target        The entity that the action changes: kind, id, name, tenant.
#   input.action.dry_run       true if the action must change nothing.
#   input.action.requested_by  The agent or the playbook that made the request.
#   input.action.requested_at  The time of the request (RFC 3339).
#   input.default_tier         "auto" for safe and reversible actions, "gated" for the rest.
#   input.principal            The identity that makes the request: id, kind, roles.
#   input.incident             The incident, if there is one: id, severity, status.
#                              severity is "informational", "low", "medium", "high",
#                              or "critical".
#   input.environment          Data that you give to AEGIS, for example a maintenance window.
#
# THE RESULT
#
#   The rule `decision` must be an object with these fields:
#
#     effect   "allow", "require_approval", or "deny". Mandatory.
#     tier     "auto" or "gated". Optional. The default is input.default_tier.
#     reasons  A list of sentences that explain the decision. Optional.
#
#   AEGIS denies the action if `decision` has no value, has a different shape, or cannot
#   be calculated.
#
# HOW TO CHANGE THIS POLICY
#
#   - To make an action need approval always, add its kind to `always_gated`.
#   - To let an action run with no approval, add its kind to `always_auto`.
#   - To deny some requests, add a rule before the dry-run rule. Refer to the files in
#     the `examples` directory.
#   - After a change, start AEGIS again or reload the policy. AEGIS rejects a policy that
#     does not compile and continues to use the policy that it has.
package aegis.response

import rego.v1

# Action kinds that need approval always. Example: {"open_ticket", "block_ip"}
always_gated := set()

# Action kinds that run with no approval. Example: {"kill_session"}
always_auto := set()

# The tier of the action. `always_gated` has priority over `always_auto`.
tier := "gated" if {
	input.action.kind in always_gated
} else := "auto" if {
	input.action.kind in always_auto
} else := input.default_tier

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
