# Example: deny all changes during a maintenance window.
#
# During planned work on your systems, a response action can interrupt the work or can be
# a reaction to the work itself. With this policy, AEGIS makes no change in the window.
# Detection and dry runs continue.
#
# Give the window to AEGIS in the environment data:
#
#   {"maintenance_window": {"start": "2026-03-01T22:00:00Z", "end": "2026-03-02T02:00:00Z"}}
#
# The policy compares the window with the time of the request. The start is in the window.
# The end is not in the window. With no window in the environment data, the default
# policy applies.
#
# If AEGIS cannot read a time in the window, it cannot calculate the decision. Then AEGIS
# denies each request that is not a dry run.
#
# To use this example, load this file in place of `default.rego`. Do not load the two
# files together: each of them is a complete policy.
package aegis.response

import rego.v1

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

# A dry run is allowed. A dry run changes nothing.
decision := {
	"effect": "allow",
	"reasons": ["The request is a dry run. A dry run changes nothing."],
} if {
	input.action.dry_run == true
}

# In the maintenance window, no action changes the environment.
else := {
	"effect": "deny",
	"reasons": ["The request is in the maintenance window. No changes are permitted."],
} if {
	in_maintenance_window
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
