//! The action connector that issues honeytokens.

use std::sync::Arc;

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};

use super::{HoneytokenKind, HoneytokenRegistry, HoneytokenRequest};
use crate::names::{entity_label, snake_name};

/// The names of the request parameters that [`HoneytokenConnector`] reads.
pub mod parameter {
    /// The decoy type: `secret`, `credential`, `application`, `user`, or `other`.
    ///
    /// The default follows the type of the target.
    pub const KIND: &str = "kind";
    /// The description of the decoy. The default is the reason of the request.
    pub const DESCRIPTION: &str = "description";
    /// The identifier of the honeytoken. The default is a random identifier.
    pub const ID: &str = "id";
}

const VENDOR: &str = "aegis";
const PRODUCT: &str = "deception";

/// An action connector for [`ActionKind::DeployHoneytoken`].
///
/// The target of the request is the placement of the decoy. The connector issues a
/// honeytoken in the registry. It does not plant the decoy: read the decoy value from the
/// registry and plant it with the tool that owns the placement. The outcome never holds the
/// decoy value.
///
/// [`revert`](ActionConnector::revert) retires the honeytoken that the same request issued.
pub struct HoneytokenConnector {
    name: String,
    registry: Arc<HoneytokenRegistry>,
}

impl HoneytokenConnector {
    /// Makes a connector that issues honeytokens in `registry`.
    pub fn new(name: impl Into<String>, registry: Arc<HoneytokenRegistry>) -> Self {
        Self {
            name: name.into(),
            registry,
        }
    }

    fn outcome(
        &self,
        request: &ActionRequest,
        status: ActionStatus,
        message: String,
        details: Value,
    ) -> ActionOutcome {
        ActionOutcome {
            action_id: request.id,
            status,
            connector: self.name.clone(),
            message,
            details,
            reversible: true,
            completed_at: Utc::now(),
        }
    }

    fn check_kind(&self, request: &ActionRequest) -> Result<()> {
        if request.kind == ActionKind::DeployHoneytoken {
            return Ok(());
        }
        Err(Error::Unsupported(format!(
            "connector {} does not support the action {}",
            self.name,
            snake_name(&request.kind)
        )))
    }
}

fn text_parameter<'a>(request: &'a ActionRequest, name: &str) -> Result<Option<&'a str>> {
    match request.parameters.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(Error::InvalidInput(format!(
            "the parameter {name} must be a string"
        ))),
    }
}

/// Reads the honeytoken data from an action request.
fn honeytoken_request(request: &ActionRequest) -> Result<HoneytokenRequest> {
    let kind = match text_parameter(request, parameter::KIND)? {
        Some(name) => serde_json::from_value::<HoneytokenKind>(json!(name)).map_err(|_| {
            Error::InvalidInput(format!(
                "the parameter {} must be secret, credential, application, user, or other",
                parameter::KIND
            ))
        })?,
        None => HoneytokenKind::for_placement(request.target.kind),
    };
    let description = text_parameter(request, parameter::DESCRIPTION)?.unwrap_or(&request.reason);
    Ok(HoneytokenRequest {
        kind,
        placement: request.target.clone(),
        description: description.to_owned(),
        issued_by: request.requested_by.clone(),
        id: text_parameter(request, parameter::ID)?.map(str::to_owned),
        action_id: Some(request.id),
    })
}

#[async_trait]
impl ActionConnector for HoneytokenConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: VENDOR.to_owned(),
            product: PRODUCT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![ActionKind::DeployHoneytoken]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.check_kind(request)?;
        let issue = honeytoken_request(request)?;
        let placement = entity_label(&request.target);
        if request.dry_run {
            return Ok(self.outcome(
                request,
                ActionStatus::Simulated,
                format!(
                    "Would issue a honeytoken for the placement {placement}. This was a dry run. Nothing changed."
                ),
                json!({ "kind": issue.kind, "placement": request.target }),
            ));
        }
        let token = self.registry.issue(issue).await?;
        Ok(self.outcome(
            request,
            ActionStatus::Succeeded,
            format!(
                "Issued the honeytoken {} for the placement {placement}. Plant the decoy value from the registry at this placement.",
                token.id
            ),
            json!({
                "honeytoken_id": token.id,
                "kind": token.kind,
                "placement": token.placement,
            }),
        ))
    }

    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.check_kind(request)?;
        let token = self
            .registry
            .active()
            .into_iter()
            .find(|token| token.action_id == Some(request.id))
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "no active honeytoken comes from the action {}",
                    request.id
                ))
            })?;
        if request.dry_run {
            return Ok(self.outcome(
                request,
                ActionStatus::Simulated,
                format!(
                    "Would retire the honeytoken {}. This was a dry run. Nothing changed.",
                    token.id
                ),
                json!({ "honeytoken_id": token.id }),
            ));
        }
        let retired = self.registry.retire(&token.id).await?;
        Ok(self.outcome(
            request,
            ActionStatus::Succeeded,
            format!(
                "Retired the honeytoken {}. Remove the decoy from its placement.",
                retired.id
            ),
            json!({ "honeytoken_id": retired.id, "retired_at": retired.retired_at }),
        ))
    }
}
