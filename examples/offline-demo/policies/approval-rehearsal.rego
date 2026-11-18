# Example: rehearse the approval path while each action is a dry run.
#
# The default policy permits each dry run, so no request waits for a person while
# AEGIS operates in dry-run mode. With this policy, the action kinds in `rehearsed`
# need the approval of a person also in a dry run. All other requests follow the
# default policy.
#
# Use this policy to train the approvers and to test the approval path before you permit
# changes. A dry run changes nothing, also after an approval.
#
# To use this example, load this file in place of `default.rego`. Do not load the two
# files together: each of them is a complete policy.
#
# HOW TO CHANGE THIS POLICY
#
#   - Change `rehearsed` to select the actions that wait for a person in a dry run.
package aegis.response

import rego.v1

# The action kinds that need approval also in a dry run.
rehearsed := {"disable_service_principal"}

# No other rule matches: deny.
default decision := {
	"effect": "deny",
	"tier": "gated",
	"reasons": ["No rule of the policy permits this request."],
}

# A rehearsed action needs approval, also in a dry run.
decision := {
	"effect": "require_approval",
	"tier": "gated",
	"reasons": ["Approval rehearsal: a person must approve this action, also in a dry run."],
} if {
	input.action.kind in rehearsed
}

# A dry run is allowed. A dry run changes nothing.
else := {
	"effect": "allow",
	"reasons": ["The request is a dry run. A dry run changes nothing."],
} if {
	input.action.dry_run == true
}

# An action in the auto tier is allowed.
else := {
	"effect": "allow",
	"tier": "auto",
	"reasons": ["The action is in the auto tier."],
} if {
	input.default_tier == "auto"
}

# An action in the gated tier needs approval.
else := {
	"effect": "require_approval",
	"tier": "gated",
	"reasons": ["The action is in the gated tier. A person must approve it."],
} if {
	input.default_tier == "gated"
}
