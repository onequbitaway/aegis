//! The registry of action connectors.
//!
//! The [`Dispatcher`](crate::Dispatcher) asks the registry for the connector that does one
//! action type.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use aegis_contracts::action::{ActionConnector, ActionKind};
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

/// One line of the routing table. It names the connector that does one action type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The action type.
    pub kind: ActionKind,
    /// The name of the connector that does this action type.
    pub connector: String,
}

/// A set of named action connectors with a routing table.
///
/// [`select`](Self::select) uses the routing table first. If the table has no line for an
/// action type, the first registered connector that supports the type does the action.
#[derive(Default)]
pub struct ActionRegistry {
    connectors: Vec<(String, Arc<dyn ActionConnector>)>,
    routes: BTreeMap<ActionKind, String>,
}

impl fmt::Debug for ActionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionRegistry")
            .field("connectors", &self.names())
            .field("routes", &self.routes)
            .finish()
    }
}

impl ActionRegistry {
    /// Makes an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a connector. The name is [`ConnectorInfo::name`](aegis_contracts::ConnectorInfo).
    ///
    /// Returns [`Error::Config`] if the name is empty or if a connector has the same name.
    pub fn register(&mut self, connector: Arc<dyn ActionConnector>) -> Result<()> {
        let name = connector.info().name;
        if name.trim().is_empty() {
            return Err(Error::Config(
                "an action connector must have a name".to_owned(),
            ));
        }
        if self.connector(&name).is_some() {
            return Err(Error::Config(format!(
                "an action connector with the name {name:?} is already in the registry"
            )));
        }
        self.connectors.push((name, connector));
        Ok(())
    }

    /// Adds one line to the routing table. A second line for the same type replaces the first.
    ///
    /// Register the connector before you call this function. Returns [`Error::Config`] if
    /// the connector is not in the registry or does not support the action type.
    pub fn route(&mut self, kind: ActionKind, connector: impl Into<String>) -> Result<()> {
        let name = connector.into();
        let Some(target) = self.connector(&name) else {
            return Err(Error::Config(format!(
                "the route for {kind:?} names the connector {name:?}, which is not in the registry"
            )));
        };
        if !target.supported_actions().contains(&kind) {
            return Err(Error::Config(format!(
                "the route for {kind:?} names the connector {name:?}, which does not support this action"
            )));
        }
        self.routes.insert(kind, name);
        Ok(())
    }

    /// Adds each line of a routing table from the configuration.
    ///
    /// Stops at the first line that is not valid and returns its error.
    pub fn apply_routes(&mut self, routes: impl IntoIterator<Item = Route>) -> Result<()> {
        for route in routes {
            self.route(route.kind, route.connector)?;
        }
        Ok(())
    }

    /// Returns the connector that does `kind`.
    ///
    /// Returns [`Error::Unsupported`] if no connector supports the action type.
    pub fn select(&self, kind: &ActionKind) -> Result<Arc<dyn ActionConnector>> {
        if let Some(connector) = self.routes.get(kind).and_then(|name| self.connector(name)) {
            return Ok(connector);
        }
        self.connectors
            .iter()
            .find(|(_, connector)| connector.supported_actions().contains(kind))
            .map(|(_, connector)| Arc::clone(connector))
            .ok_or_else(|| {
                Error::Unsupported(format!("no action connector supports the action {kind:?}"))
            })
    }

    /// Returns the connector with this name.
    #[must_use]
    pub fn connector(&self, name: &str) -> Option<Arc<dyn ActionConnector>> {
        self.connectors
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, connector)| Arc::clone(connector))
    }

    /// Returns the names of the connectors, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.connectors
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Returns each action type that one or more connectors support, with no duplicates.
    #[must_use]
    pub fn supported_actions(&self) -> Vec<ActionKind> {
        let mut kinds: Vec<ActionKind> = self
            .connectors
            .iter()
            .flat_map(|(_, connector)| connector.supported_actions())
            .collect();
        kinds.sort();
        kinds.dedup();
        kinds
    }

    /// Returns the number of connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    /// Returns `true` if the registry has no connectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use aegis_testkit::RecordingConnector;

    use super::*;

    fn recording(name: &str, kinds: &[ActionKind]) -> Arc<dyn ActionConnector> {
        Arc::new(RecordingConnector::new(name, kinds.to_vec()))
    }

    #[test]
    fn select_uses_the_first_connector_that_supports_the_kind() {
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("edr", &[ActionKind::IsolateHost]))
            .unwrap();
        registry
            .register(recording("firewall", &[ActionKind::BlockIp]))
            .unwrap();
        registry
            .register(recording("backup-firewall", &[ActionKind::BlockIp]))
            .unwrap();

        let selected = registry.select(&ActionKind::BlockIp).unwrap();
        assert_eq!(selected.info().name, "firewall");
        assert_eq!(registry.names(), ["edr", "firewall", "backup-firewall"]);
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
        assert_eq!(
            registry.supported_actions(),
            [ActionKind::IsolateHost, ActionKind::BlockIp]
        );
    }

    #[test]
    fn an_explicit_route_wins_over_registration_order() {
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("firewall", &[ActionKind::BlockIp]))
            .unwrap();
        registry
            .register(recording("backup-firewall", &[ActionKind::BlockIp]))
            .unwrap();
        registry
            .apply_routes([Route {
                kind: ActionKind::BlockIp,
                connector: "backup-firewall".to_owned(),
            }])
            .unwrap();

        let selected = registry.select(&ActionKind::BlockIp).unwrap();
        assert_eq!(selected.info().name, "backup-firewall");
    }

    #[test]
    fn a_kind_with_no_connector_is_unsupported() {
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("firewall", &[ActionKind::BlockIp]))
            .unwrap();

        let error = registry.select(&ActionKind::IsolateHost).err().unwrap();
        assert!(
            matches!(&error, Error::Unsupported(message) if message.contains("IsolateHost")),
            "{error:?}"
        );
        let custom = registry
            .select(&ActionKind::Custom("quarantine_mailbox".to_owned()))
            .err()
            .unwrap();
        assert!(matches!(custom, Error::Unsupported(_)), "{custom:?}");
    }

    #[test]
    fn a_custom_kind_matches_by_its_exact_name() {
        let quarantine = ActionKind::Custom("quarantine_mailbox".to_owned());
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("mail", std::slice::from_ref(&quarantine)))
            .unwrap();

        assert_eq!(registry.select(&quarantine).unwrap().info().name, "mail");
        let other = registry
            .select(&ActionKind::Custom("purge_mailbox".to_owned()))
            .err()
            .unwrap();
        assert!(matches!(other, Error::Unsupported(_)), "{other:?}");
    }

    #[test]
    fn a_duplicate_or_empty_name_is_a_configuration_error() {
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("firewall", &[ActionKind::BlockIp]))
            .unwrap();

        let duplicate = registry
            .register(recording("firewall", &[ActionKind::Notify]))
            .unwrap_err();
        assert!(
            matches!(&duplicate, Error::Config(message) if message.contains("already")),
            "{duplicate:?}"
        );
        let unnamed = registry
            .register(recording(" ", &[ActionKind::Notify]))
            .unwrap_err();
        assert!(
            matches!(&unnamed, Error::Config(message) if message.contains("must have a name")),
            "{unnamed:?}"
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_route_to_an_unknown_or_unsuitable_connector_is_a_configuration_error() {
        let mut registry = ActionRegistry::new();
        registry
            .register(recording("firewall", &[ActionKind::BlockIp]))
            .unwrap();

        let unknown = registry.route(ActionKind::BlockIp, "edr").unwrap_err();
        assert!(
            matches!(&unknown, Error::Config(message) if message.contains("not in the registry")),
            "{unknown:?}"
        );
        let unsuitable = registry
            .route(ActionKind::IsolateHost, "firewall")
            .unwrap_err();
        assert!(
            matches!(&unsuitable, Error::Config(message) if message.contains("does not support")),
            "{unsuitable:?}"
        );
    }

    #[test]
    fn a_route_reads_from_configuration_text() {
        let route: Route =
            serde_json::from_str(r#"{"kind":{"custom":"quarantine_mailbox"},"connector":"mail"}"#)
                .unwrap();
        assert_eq!(
            route,
            Route {
                kind: ActionKind::Custom("quarantine_mailbox".to_owned()),
                connector: "mail".to_owned(),
            }
        );
    }
}
