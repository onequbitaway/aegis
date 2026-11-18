# Example: protect named entities from automatic changes.
#
# Some entities must stay available in an incident, for example an emergency access
# account. With this policy:
#
#   - An agent or a playbook cannot change a protected entity.
#   - A person with the role "incident_commander" can request a change to a protected
#     entity. A different person must approve the change.
#   - All other requests follow the default policy.
#
# The list of protected entities is in the data file `protected_entities.yaml`. Load the
# data file together with this policy. If the list is not loaded, this policy denies each
# request that is not a dry run, because it cannot know which entities are protected.
#
# To use this example, load this file in place of `default.rego`. Do not load the two
# files together: each of them is a complete policy.
package aegis.response

import rego.v1

# The role that can request a change to a protected entity.
override_role := "incident_commander"

list_is_loaded if {
	is_array(data.aegis.protected_entities)
}

target_is_protected if {
	some entity in data.aegis.protected_entities
	entity.kind == input.action.target.kind
	entity.id == input.action.target.id
}

requester_can_override if {
	input.principal.kind == "human"
	override_role in input.principal.roles
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

# Without the list, the policy cannot know which entities are protected.
else := {
	"effect": "deny",
	"reasons": ["The list of protected entities is not loaded."],
} if {
	not list_is_loaded
}

# An incident commander can request a change to a protected entity.
else := {
	"effect": "require_approval",
	"tier": "gated",
	"reasons": ["The target is a protected entity. An incident commander requested the change, and a different person must approve it."],
} if {
	target_is_protected
	requester_can_override
}

# No other identity can change a protected entity.
else := {
	"effect": "deny",
	"reasons": ["The target is a protected entity. Only an incident commander can request a change to it."],
} if {
	target_is_protected
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
