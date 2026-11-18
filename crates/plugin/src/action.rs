//! An action connector that runs in a plugin.

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;

use crate::bindings::ActionConnectorPre;
use crate::sandbox::{HostState, Sandbox};

/// An [`ActionConnector`] whose code is a WebAssembly component.
pub(crate) struct PluginAction {
    sandbox: Sandbox,
    component: ActionConnectorPre<HostState>,
    info: ConnectorInfo,
    supported: Vec<ActionKind>,
}

/// The two exports that take an action request.
#[derive(Clone, Copy)]
enum Operation {
    Execute,
    Revert,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Revert => "revert",
        }
    }
}

impl PluginAction {
    /// Asks the plugin for its identity and its action types, and makes the connector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if `info` or `supported-actions` does not return
    /// the correct JSON, and the error of the sandbox if a call fails.
    pub(crate) async fn load(
        sandbox: Sandbox,
        component: ActionConnectorPre<HostState>,
    ) -> Result<Self> {
        let pre = component.clone();
        let (info, supported) = sandbox
            .call("info", move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    let action = plugin.aegis_plugin_action();
                    let info = action.call_info(&mut *store).await?;
                    let supported = action.call_supported_actions(store).await?;
                    Ok((info, supported))
                })
            })
            .await?;
        let info = sandbox.connector_info(info).await?;
        let supported = sandbox
            .decode("supported-actions", "a list of ActionKind", supported)
            .await?;
        Ok(Self {
            sandbox,
            component,
            info,
            supported,
        })
    }

    /// Sends one request to the plugin and checks the outcome.
    async fn run(&self, operation: Operation, request: &ActionRequest) -> Result<ActionOutcome> {
        let name = self.sandbox.name();
        if !self.supported.contains(&request.kind) {
            return Err(Error::Unsupported(format!(
                "plugin {name} does not support {:?}",
                request.kind
            )));
        }
        let request_json = serde_json::to_string(request)?;
        let pre = self.component.clone();
        let text = self
            .sandbox
            .call(operation.name(), move |store| {
                Box::pin(async move {
                    let plugin = pre.instantiate_async(&mut *store).await?;
                    let action = plugin.aegis_plugin_action();
                    match operation {
                        Operation::Execute => action.call_execute(store, &request_json).await,
                        Operation::Revert => action.call_revert(store, &request_json).await,
                    }
                })
            })
            .await?
            .map_err(|error| self.sandbox.guest_error(error))?;

        let mut outcome: ActionOutcome = self
            .sandbox
            .decode(operation.name(), "ActionOutcome", text)
            .await?;
        // A dry run changes nothing, and a real run is not a simulation. An outcome that
        // says something different breaks the contract. The host does not pass it on as
        // a success.
        let broken_rule = match (request.dry_run, outcome.status) {
            (true, ActionStatus::Succeeded) => {
                Some("the request was a dry run, but the plugin reports that it changed the target")
            }
            (false, ActionStatus::Simulated) => {
                Some("the request was not a dry run, but the plugin reports a simulation")
            }
            _ => None,
        };
        if let Some(broken_rule) = broken_rule {
            return Err(Error::other(
                format!(
                    "plugin {name}: `{}` broke the dry-run rule",
                    operation.name()
                ),
                broken_rule,
            ));
        }
        // The outcome is the answer to this request from this connector. The host does
        // not let the plugin say something different in the audit trail.
        if outcome.action_id != request.id {
            tracing::warn!(
                plugin = name,
                "The plugin returned an outcome for a different action. The host replaced the identifier."
            );
            outcome.action_id = request.id;
        }
        outcome.connector = name.to_owned();
        Ok(outcome)
    }
}

#[async_trait]
impl ActionConnector for PluginAction {
    fn info(&self) -> ConnectorInfo {
        self.info.clone()
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        self.supported.clone()
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.run(Operation::Execute, request).await
    }

    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.run(Operation::Revert, request).await
    }
}
