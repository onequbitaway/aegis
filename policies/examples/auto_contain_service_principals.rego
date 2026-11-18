# Example: contain a service principal immediately when the incident is critical.
#
# An attack that uses a service principal can do damage in seconds. With this policy, AEGIS
# does not wait for a person before it contains the service principal, but only when the
# incident is critical. All other requests follow the default policy.
#
# To use this example, load this file in place of `default.rego`. Do not load the two
# files together: each of them is a complete policy.
#
# HOW TO CHANGE THIS POLICY
#
#   - Change `containment_actions` to select the actions that can run with no approval.
#   - Change `urgent_severities` to select the incidents to which the rule applies.
package aegis.response

import rego.v1

# The actions that can run with no approval on a service principal.
containment_actions := {"disable_service_principal", "revoke_credential", "kill_session"}

# The incident severities for which containment does not wait for a person.
urgent_severities := {"critical"}

urgent_containment if {
	input.incident.severity in urgent_severities
	input.action.target.kind == "service_principal"
	input.action.kind in containment_actions
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

# Containment of a service principal in a critical incident runs immediately.
else := {
	"effect": "allow",
	"tier": "auto",
	"reasons": ["The incident is critical and the target is a service principal. Containment does not wait for approval."],
} if {
	urgent_containment
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
