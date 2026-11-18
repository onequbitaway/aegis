# Example: contain first, with a timed revert.
#
# A containment action that waits for a person can be too late. A containment action that
# runs with no person can be wrong. With this policy, a reversible containment action runs
# immediately, but only if the request has a timed revert with a short time. If no person
# confirms the action before that time, AEGIS reverts it.
#
#   - A request for one of the `contain_first_actions` or one of the `friction_actions`
#     runs with no approval if these two conditions are true: its parameter
#     `revert_after_seconds` is a number from 1 to `max_revert_after_seconds`, and the
#     incident has one of the `urgent_severities`.
#   - The revert scheduler of AEGIS reverts such an action at its time with no approval.
#   - All other requests follow the default policy. Thus a containment action with no
#     timed revert, or with a longer time, needs the approval of a person. A revert that
#     a person or an agent requests also needs approval.
#
# A playbook step sets the parameter with its field `revert_after`. AEGIS accepts the
# parameter only for an action that has an inverse.
#
# A revert is a request with the action {"custom": "revert"}. Its parameter `reverts`
# names the action that it undoes: action_id, kind, requested_by, connector, executed_at,
# and revert_after_seconds.
#
# To use this example, load this file in place of `default.rego`. Do not load the two
# files together: each of them is a complete policy.
#
# HOW TO CHANGE THIS POLICY
#
#   - Change `max_revert_after_seconds` to set the longest revert time.
#   - Change `contain_first_actions` and `friction_actions` to select the actions.
#   - Change `urgent_severities` to select the incidents to which the rule applies.
#   - Remove the rule for `timed_revert` if a person must approve each revert. A timed
#     revert then waits in the approval queue, and the containment stays.
package aegis.response

import rego.v1

# The longest revert time with which an action can run first, in seconds. 14400 is 4 hours.
max_revert_after_seconds := 14400

# The reversible actions that can run first.
contain_first_actions := {"disable_user", "disable_service_principal", "block_ip", "isolate_host"}

# The friction actions that can run first. A friction action is a custom action.
friction_actions := {"restrict_user_consent", "raise_friction"}

# The incident severities for which containment does not wait for a person.
urgent_severities := {"high", "critical"}

# The identity of the revert scheduler of AEGIS.
revert_scheduler := "revert-scheduler"

has_short_revert if {
	seconds := input.action.parameters.revert_after_seconds
	is_number(seconds)
	seconds >= 1
	seconds <= max_revert_after_seconds
}

is_contain_first_action if {
	input.action.kind in contain_first_actions
}

is_contain_first_action if {
	input.action.kind.custom in friction_actions
}

contain_first if {
	is_contain_first_action
	has_short_revert
	input.incident.severity in urgent_severities
}

# The revert that the scheduler requests when nobody confirmed an action with a timed
# revert.
timed_revert if {
	input.action.kind.custom == "revert"
	input.principal.kind == "system"
	input.principal.id == revert_scheduler
	is_number(input.action.parameters.reverts.revert_after_seconds)
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

# A reversible action with a short timed revert runs first.
else := {
	"effect": "allow",
	"tier": "auto",
	"reasons": ["The action has an inverse and a timed revert of a permitted length. It runs first. AEGIS reverts it if no person confirms it."],
} if {
	contain_first
}

# The scheduler reverts an action that nobody confirmed.
else := {
	"effect": "allow",
	"tier": "auto",
	"reasons": ["Nobody confirmed the action before its revert time. The revert scheduler reverts it."],
} if {
	timed_revert
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
