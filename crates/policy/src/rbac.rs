//! Role-based access control.
//!
//! The operator gives each role a set of permissions. A principal has the permissions of all
//! its roles. A role that the configuration does not name gives no permission.
//!
//! No permission includes a different permission. For example, [`Permission::Administer`]
//! does not include [`Permission::ApproveActions`]. Give a role each permission that it
//! needs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aegis_contracts::policy::Principal;
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

/// One operation that role-based access control guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read incidents, detections, and approval requests.
    ViewIncidents,
    /// Read the audit log.
    ViewAudit,
    /// Approve or reject gated actions.
    ApproveActions,
    /// Change the response policy.
    ManagePolicy,
    /// Add, change, or remove connectors.
    ManageConnectors,
    /// Start playbooks.
    RunPlaybooks,
    /// Change roles, principals, and system settings.
    Administer,
}

impl Permission {
    /// All permissions.
    pub const ALL: [Self; 7] = [
        Self::ViewIncidents,
        Self::ViewAudit,
        Self::ApproveActions,
        Self::ManagePolicy,
        Self::ManageConnectors,
        Self::RunPlaybooks,
        Self::Administer,
    ];

    /// Returns the name of the permission in the configuration, for example
    /// `approve_actions`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ViewIncidents => "view_incidents",
            Self::ViewAudit => "view_audit",
            Self::ApproveActions => "approve_actions",
            Self::ManagePolicy => "manage_policy",
            Self::ManageConnectors => "manage_connectors",
            Self::RunPlaybooks => "run_playbooks",
            Self::Administer => "administer",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The configuration of role-based access control.
///
/// The configuration is a map from a role name to the permissions of the role. Role names
/// are case-sensitive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbacConfig {
    /// The permissions of each role.
    #[serde(default)]
    pub roles: BTreeMap<String, BTreeSet<Permission>>,
}

impl RbacConfig {
    /// Gives `permissions` to `role`. The role keeps the permissions that it has.
    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>, permissions: &[Permission]) -> Self {
        self.roles
            .entry(role.into())
            .or_default()
            .extend(permissions.iter().copied());
        self
    }
}

/// The role-based access control check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rbac {
    roles: BTreeMap<String, BTreeSet<Permission>>,
}

impl Rbac {
    /// Makes the check from the configuration.
    #[must_use]
    pub fn new(config: RbacConfig) -> Self {
        Self {
            roles: config.roles,
        }
    }

    /// Returns `true` if a role of `principal` has `permission`.
    #[must_use]
    pub fn allows(&self, principal: &Principal, permission: Permission) -> bool {
        principal.roles.iter().any(|role| {
            self.roles
                .get(role)
                .is_some_and(|permissions| permissions.contains(&permission))
        })
    }

    /// Returns all permissions that the roles of `principal` give.
    #[must_use]
    pub fn permissions(&self, principal: &Principal) -> BTreeSet<Permission> {
        principal
            .roles
            .iter()
            .filter_map(|role| self.roles.get(role))
            .flatten()
            .copied()
            .collect()
    }

    /// Checks that `principal` has `permission`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if no role of the principal has the permission. The
    /// message names the permission that is missing.
    pub fn check(&self, principal: &Principal, permission: Permission) -> Result<()> {
        self.check_any(principal, &[permission])
    }

    /// Checks that `principal` has one or more of `permissions`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if the principal has none of the permissions. The
    /// message names the permissions that are missing. An empty `permissions` list gives
    /// this error for each principal.
    pub fn check_any(&self, principal: &Principal, permissions: &[Permission]) -> Result<()> {
        if permissions
            .iter()
            .any(|permission| self.allows(principal, *permission))
        {
            return Ok(());
        }
        let missing = permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        Err(Error::Unauthorized(format!(
            "principal {} does not have the permission {missing}",
            principal.id
        )))
    }
}

impl From<RbacConfig> for Rbac {
    fn from(config: RbacConfig) -> Self {
        Self::new(config)
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::policy::PrincipalKind;
    use serde_json::json;

    use super::*;

    fn rbac() -> Rbac {
        Rbac::new(
            RbacConfig::default()
                .with_role(
                    "analyst",
                    &[Permission::ViewIncidents, Permission::ViewAudit],
                )
                .with_role("approver", &[Permission::ApproveActions])
                .with_role("admin", &[Permission::Administer]),
        )
    }

    fn human(roles: &[&str]) -> Principal {
        Principal::new("alice@example.com", PrincipalKind::Human, roles)
    }

    #[test]
    fn a_principal_has_the_permissions_of_all_its_roles() {
        let rbac = rbac();
        let principal = human(&["analyst", "approver"]);
        assert_eq!(
            rbac.permissions(&principal),
            BTreeSet::from([
                Permission::ViewIncidents,
                Permission::ViewAudit,
                Permission::ApproveActions
            ])
        );
        rbac.check(&principal, Permission::ApproveActions).unwrap();
        rbac.check(&principal, Permission::ViewAudit).unwrap();
    }

    #[test]
    fn a_missing_permission_gives_unauthorized_that_names_only_the_permission() {
        let error = rbac()
            .check(&human(&["analyst"]), Permission::ApproveActions)
            .unwrap_err();
        let Error::Unauthorized(message) = error else {
            panic!("expected Unauthorized, found {error:?}");
        };
        assert_eq!(
            message,
            "principal alice@example.com does not have the permission approve_actions"
        );
        for other in ["analyst", "approver", "admin", "view_incidents"] {
            assert!(
                !message.contains(other),
                "the message must not show {other}"
            );
        }
    }

    #[test]
    fn an_unknown_role_and_no_role_give_nothing() {
        let rbac = rbac();
        for principal in [human(&["root"]), human(&[]), human(&["Admin"])] {
            assert_eq!(rbac.permissions(&principal), BTreeSet::new());
            for permission in Permission::ALL {
                assert!(
                    matches!(
                        rbac.check(&principal, permission),
                        Err(Error::Unauthorized(_))
                    ),
                    "{permission} for roles {:?}",
                    principal.roles
                );
            }
        }
    }

    #[test]
    fn no_permission_includes_a_different_permission() {
        let rbac = rbac();
        let admin = human(&["admin"]);
        assert!(rbac.allows(&admin, Permission::Administer));
        let others: Vec<Permission> = Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Administer)
            .collect();
        assert_eq!(others.len(), 6);
        for permission in others {
            assert!(!rbac.allows(&admin, permission), "{permission}");
        }
    }

    #[test]
    fn check_any_accepts_one_match_and_names_all_missing_permissions() {
        let rbac = rbac();
        let wanted = [Permission::ViewIncidents, Permission::ApproveActions];
        rbac.check_any(&human(&["approver"]), &wanted).unwrap();
        rbac.check_any(&human(&["analyst"]), &wanted).unwrap();
        let error = rbac.check_any(&human(&["admin"]), &wanted).unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized(message) if message.ends_with("view_incidents or approve_actions")),
            "{error}"
        );
        assert!(matches!(
            rbac.check_any(&human(&["admin"]), &[]),
            Err(Error::Unauthorized(_))
        ));
    }

    #[test]
    fn the_configuration_reads_the_documented_names() {
        let config: RbacConfig = serde_json::from_value(json!({
            "roles": {
                "operator": [
                    "view_incidents", "view_audit", "approve_actions", "manage_policy",
                    "manage_connectors", "run_playbooks", "administer"
                ]
            }
        }))
        .unwrap();
        let rbac = Rbac::from(config);
        let operator = human(&["operator"]);
        assert_eq!(rbac.permissions(&operator), BTreeSet::from(Permission::ALL));
        for permission in Permission::ALL {
            assert_eq!(json!(permission), json!(permission.as_str()));
            assert_eq!(permission.to_string(), permission.as_str());
        }
    }

    #[test]
    fn the_configuration_rejects_unknown_permissions_and_fields() {
        let unknown_permission = serde_json::from_value::<RbacConfig>(
            json!({ "roles": { "x": ["approve_everything"] } }),
        )
        .unwrap_err();
        assert!(
            unknown_permission
                .to_string()
                .contains("unknown variant `approve_everything`"),
            "{unknown_permission}"
        );
        let unknown_field =
            serde_json::from_value::<RbacConfig>(json!({ "role": {} })).unwrap_err();
        assert!(
            unknown_field.to_string().contains("unknown field `role`"),
            "{unknown_field}"
        );
        let empty: RbacConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(empty, RbacConfig::default());
    }
}
