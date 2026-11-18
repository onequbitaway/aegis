//! The SOAR engine: declarative playbooks for known incidents and response drafts for new
//! incidents.
//!
//! A playbook is a YAML file. It has a name, a description, a trigger, and ordered steps.
//!
//! ```yaml
//! name: block-spray-source
//! description: Block the address that a password spray comes from.
//! trigger:
//!   min_severity: medium
//!   techniques_any: [T1110.003]
//!   entity_kinds: [ip_address]
//! steps:
//!   - id: block-address
//!     action: block_ip
//!     target:
//!       each_entity: ip_address
//!     parameters:
//!       duration_hours: 24
//!     reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
//!     continue_on_error: true
//! ```
//!
//! # Trigger
//!
//! All conditions that the trigger has must be true. A trigger must have one condition or
//! more.
//!
//! | Field | Condition |
//! | --- | --- |
//! | `min_severity` | The incident has this severity or a larger one. |
//! | `techniques_any` | The incident has one or more of these ATT&CK techniques. |
//! | `techniques_all` | The incident has all of these ATT&CK techniques. |
//! | `entity_kinds` | The incident has an entity of each of these types. |
//! | `tenants` | The incident is in one of these tenants. |
//! | `statuses` | The incident has one of these states. The default is `open` and `investigating`. |
//!
//! A technique without a sub-technique, for example `T1098`, also matches its
//! sub-techniques.
//!
//! # Steps
//!
//! | Field | Contents |
//! | --- | --- |
//! | `id` | A name for the step. The default is `step-N`. |
//! | `action` | The action type, for example `disable_user`. For a custom action, `{custom: name}`. |
//! | `target` | `{each_entity: <type>}`, `{fixed: {kind: <type>, id: <id>}}`, or `incident_tenant`. |
//! | `parameters` | Parameters for the connector. Each string is a template. |
//! | `reason` | A template for the reason of the request. |
//! | `continue_on_error` | With `true`, a failure of this step does not stop the playbook. The default is `false`. |
//! | `max_targets` | The maximum number of targets. A step with more targets fails and sends no request. The default is 20. |
//! | `revert_after` | The time of a timed revert: a number of seconds, or a number with the unit `s`, `m`, `h`, or `d`, for example `4h`. Only an action with an inverse can have it. |
//!
//! The engine documentation lists the template variables. Refer to [`PlaybookEngine`].
//!
//! # Timed revert
//!
//! A step with `revert_after` asks for a timed revert. The engine sets the request
//! parameter `revert_after_seconds`. The action then reverts at that time, unless a person
//! confirms it before. Refer to [`revert`].
//!
//! Use `revert_after` for a containment action that has a cost when it is wrong, for
//! example `disable_user`, `block_ip`, or a friction action.

mod draft;
mod engine;
mod template;

use std::collections::BTreeMap;
use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::action::ActionKind;
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::incident::{Incident, IncidentStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use draft::{
    DEFAULT_FRICTION_REVERT_AFTER, DEFAULT_MAX_DRAFT_STEPS, DraftError, DraftOptions,
    draft_response, draft_response_with,
};
pub use engine::{
    DRAFT_PRINCIPAL_ID, LoadReport, PLAYBOOK_PRINCIPAL_ID, PlaybookEngine, PlaybookRun, RunMode,
    StepResult, StepRun,
};

use crate::friction;
use crate::names::snake_name;
use crate::revert::{self, EXECUTION_DETAILS_PARAMETER, REVERT_ACTION, REVERT_AFTER_PARAMETER};

/// The maximum number of steps in one playbook.
pub const MAX_STEPS: usize = 32;
/// The default maximum number of targets of one step.
pub const DEFAULT_MAX_TARGETS: usize = 20;
/// The largest value that a playbook can set for `max_targets`.
pub const MAX_TARGETS_LIMIT: usize = 1_000;

const MAX_NAME_LENGTH: usize = 64;
const MAX_TEXT_LENGTH: usize = 2_000;

/// An error from the playbook loader.
#[derive(Debug, thiserror::Error)]
pub enum PlaybookError {
    /// The playbook is not valid. The engine does not load it.
    #[error("playbook {file}: {reason}")]
    Invalid {
        /// The name of the playbook file.
        file: String,
        /// Why the playbook is not valid.
        reason: String,
    },
    /// The loader cannot read a file or a directory.
    #[error("playbook {file}: cannot read: {source}")]
    Io {
        /// The name of the file or the directory.
        file: String,
        /// The cause of the failure.
        #[source]
        source: std::io::Error,
    },
}

impl From<PlaybookError> for Error {
    fn from(error: PlaybookError) -> Self {
        Self::Config(error.to_string())
    }
}

/// Where a playbook comes from. Policy can use this to treat a model draft more strictly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookOrigin {
    /// The operator wrote the playbook.
    #[default]
    Operator,
    /// A model wrote the playbook for one incident. Refer to [`draft_response`].
    ModelDraft {
        /// The name of the provider that answered.
        provider: String,
        /// The model that answered.
        model: String,
    },
}

/// Selects the entities that a step acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSelector {
    /// Each entity of the incident that has this type.
    EachEntity(EntityKind),
    /// One fixed entity, for example a chat channel or a ticket queue.
    Fixed(EntityRef),
    /// The tenant of the incident. An incident with no tenant gives no target.
    IncidentTenant,
}

impl TargetSelector {
    /// Returns the targets for an incident, with no duplicates, in incident order.
    #[must_use]
    pub fn resolve(&self, incident: &Incident) -> Vec<EntityRef> {
        match self {
            Self::EachEntity(kind) => {
                let mut targets: Vec<EntityRef> = Vec::new();
                for entity in incident
                    .entities
                    .iter()
                    .filter(|entity| entity.kind == *kind)
                {
                    let known = targets
                        .iter()
                        .any(|target| target.id == entity.id && target.tenant == entity.tenant);
                    if !known {
                        targets.push(entity.clone());
                    }
                }
                targets
            }
            Self::Fixed(entity) => vec![entity.clone()],
            Self::IncidentTenant => incident
                .tenant
                .iter()
                .map(|tenant| EntityRef::new(EntityKind::Tenant, tenant.clone()))
                .collect(),
        }
    }

    /// Returns the entity type of the targets that the selector gives.
    fn kind(&self) -> EntityKind {
        match self {
            Self::EachEntity(kind) => *kind,
            Self::Fixed(entity) => entity.kind,
            Self::IncidentTenant => EntityKind::Tenant,
        }
    }
}

/// Returns the entity types that an action can change, or `None` if all types are permitted.
pub(crate) fn permitted_target_kinds(action: &ActionKind) -> Option<&'static [EntityKind]> {
    match action {
        ActionKind::DisableServicePrincipal => Some(&[EntityKind::ServicePrincipal]),
        ActionKind::DisableUser => Some(&[EntityKind::User]),
        ActionKind::KillSession => Some(&[EntityKind::User, EntityKind::Session]),
        ActionKind::RevokeCredential | ActionKind::RotateCredential => {
            Some(&[EntityKind::ServicePrincipal, EntityKind::Application])
        }
        ActionKind::IsolateHost => Some(&[EntityKind::Host, EntityKind::Device]),
        ActionKind::BlockIp => Some(&[EntityKind::IpAddress]),
        ActionKind::RotateSecret => Some(&[EntityKind::Secret]),
        // This friction action changes a setting of the tenant.
        ActionKind::Custom(name) if name == friction::RESTRICT_USER_CONSENT => {
            Some(&[EntityKind::Tenant])
        }
        ActionKind::Enrich
        | ActionKind::Tag
        | ActionKind::Notify
        | ActionKind::SnapshotEvidence
        | ActionKind::OpenTicket
        | ActionKind::DeployHoneytoken
        | ActionKind::Custom(_) => None,
    }
}

/// Returns an error text if `action` cannot change an entity of the type `kind`.
pub(crate) fn check_target_kind(action: &ActionKind, kind: EntityKind) -> Result<(), String> {
    match permitted_target_kinds(action) {
        Some(permitted) if !permitted.contains(&kind) => {
            let names: Vec<String> = permitted.iter().map(snake_name).collect();
            Err(format!(
                "the action {} needs a target of the type {}, not {}",
                snake_name(action),
                names.join(" or "),
                snake_name(&kind)
            ))
        }
        _ => Ok(()),
    }
}

/// The conditions that select a playbook for an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Trigger {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) min_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) techniques_any: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) techniques_all: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) entity_kinds: Vec<EntityKind>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tenants: Vec<String>,
    pub(crate) statuses: Vec<IncidentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) incident_id: Option<IncidentId>,
}

/// Returns `true` if the incident technique `found` satisfies the condition `wanted`.
fn technique_matches(wanted: &str, found: &str) -> bool {
    found == wanted
        || (!wanted.contains('.')
            && found
                .strip_prefix(wanted)
                .is_some_and(|rest| rest.starts_with('.')))
}

impl Trigger {
    /// Returns `true` if all conditions of the trigger are true for the incident.
    #[must_use]
    pub fn matches(&self, incident: &Incident) -> bool {
        let has_technique = |wanted: &String| {
            incident
                .attack
                .iter()
                .any(|technique| technique_matches(wanted, &technique.technique_id))
        };
        self.incident_id.is_none_or(|bound| bound == incident.id)
            && self.statuses.contains(&incident.status)
            && self
                .min_severity
                .is_none_or(|minimum| incident.severity >= minimum)
            && (self.techniques_any.is_empty() || self.techniques_any.iter().any(has_technique))
            && self.techniques_all.iter().all(has_technique)
            && self
                .entity_kinds
                .iter()
                .all(|kind| incident.entities.iter().any(|entity| entity.kind == *kind))
            && (self.tenants.is_empty()
                || incident
                    .tenant
                    .as_ref()
                    .is_some_and(|tenant| self.tenants.contains(tenant)))
    }

    /// Returns the incident that the playbook is for, if the playbook is a response draft.
    #[must_use]
    pub fn incident_id(&self) -> Option<IncidentId> {
        self.incident_id
    }
}

/// One step of a playbook. It gives one action request for each target.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Step {
    pub(crate) id: String,
    pub(crate) action: ActionKind,
    pub(crate) target: TargetSelector,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) parameters: BTreeMap<String, Value>,
    pub(crate) reason: String,
    pub(crate) continue_on_error: bool,
    pub(crate) max_targets: usize,
    /// The time of the timed revert, in seconds.
    #[serde(
        rename = "revert_after_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) revert_after: Option<u64>,
    /// With `true`, the reason and the parameters are plain text and not templates.
    #[serde(skip)]
    pub(crate) literal: bool,
}

impl Step {
    /// Returns the name of the step.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the action type of the step.
    #[must_use]
    pub fn action(&self) -> &ActionKind {
        &self.action
    }

    /// Returns the target selector of the step.
    #[must_use]
    pub fn target(&self) -> &TargetSelector {
        &self.target
    }

    /// Returns the parameters of the step, before the engine fills the templates.
    #[must_use]
    pub fn parameters(&self) -> &BTreeMap<String, Value> {
        &self.parameters
    }

    /// Returns the reason of the step, before the engine fills the template.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns `true` if a failure of this step does not stop the playbook.
    #[must_use]
    pub fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }

    /// Returns the maximum number of targets. A step with more targets sends no request.
    #[must_use]
    pub fn max_targets(&self) -> usize {
        self.max_targets
    }

    /// Returns the time of the timed revert of the step, if the step has one.
    ///
    /// Each request of the step has this time in the parameter `revert_after_seconds`.
    #[must_use]
    pub fn revert_after(&self) -> Option<Duration> {
        self.revert_after.map(Duration::from_secs)
    }
}

/// A playbook that passed validation.
///
/// Make a playbook with [`Playbook::from_yaml`] or [`draft_response`]. A playbook only makes
/// action requests. Each request goes through the dispatcher, so policy applies.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Playbook {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) origin: PlaybookOrigin,
    pub(crate) trigger: Trigger,
    pub(crate) steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlaybook {
    name: String,
    description: String,
    trigger: RawTrigger,
    steps: Vec<RawStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrigger {
    #[serde(default)]
    min_severity: Option<Severity>,
    #[serde(default)]
    techniques_any: Vec<String>,
    #[serde(default)]
    techniques_all: Vec<String>,
    #[serde(default)]
    entity_kinds: Vec<EntityKind>,
    #[serde(default)]
    tenants: Vec<String>,
    #[serde(default)]
    statuses: Vec<IncidentStatus>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    #[serde(default)]
    id: Option<String>,
    action: ActionKind,
    target: TargetSelector,
    #[serde(default)]
    parameters: BTreeMap<String, Value>,
    reason: String,
    #[serde(default)]
    continue_on_error: bool,
    #[serde(default)]
    max_targets: Option<usize>,
    #[serde(default)]
    revert_after: Option<Value>,
}

/// Returns `true` if `text` is a name: lower-case letters, digits, `-`, and `_`.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME_LENGTH
        && text.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_')
        })
}

/// Checks an ATT&CK technique identifier, for example `T1098` or `T1098.001`.
fn technique(text: &str) -> Result<String, String> {
    let id = text.trim().to_ascii_uppercase();
    let (main, sub) = match id.split_once('.') {
        Some((main, sub)) => (main, Some(sub)),
        None => (id.as_str(), None),
    };
    let digits = |part: &str, count: usize| {
        part.len() == count && part.chars().all(|character| character.is_ascii_digit())
    };
    let valid = main
        .strip_prefix('T')
        .is_some_and(|number| digits(number, 4))
        && sub.is_none_or(|number| digits(number, 3));
    if valid {
        Ok(id)
    } else {
        Err(format!(
            "{text:?} is not an ATT&CK technique identifier; use the form T1098 or T1098.001"
        ))
    }
}

fn validate_trigger(raw: RawTrigger) -> Result<Trigger, String> {
    let techniques = |list: Vec<String>| -> Result<Vec<String>, String> {
        list.iter().map(|text| technique(text)).collect()
    };
    let tenants: Vec<String> = raw
        .tenants
        .iter()
        .map(|tenant| tenant.trim().to_owned())
        .collect();
    if tenants.iter().any(String::is_empty) {
        return Err("trigger.tenants has an empty tenant".to_owned());
    }
    let trigger = Trigger {
        min_severity: raw.min_severity,
        techniques_any: techniques(raw.techniques_any)?,
        techniques_all: techniques(raw.techniques_all)?,
        entity_kinds: raw.entity_kinds,
        tenants,
        statuses: if raw.statuses.is_empty() {
            vec![IncidentStatus::Open, IncidentStatus::Investigating]
        } else {
            raw.statuses
        },
        incident_id: None,
    };
    let has_condition = trigger.min_severity.is_some()
        || !trigger.techniques_any.is_empty()
        || !trigger.techniques_all.is_empty()
        || !trigger.entity_kinds.is_empty()
        || !trigger.tenants.is_empty();
    if !has_condition {
        return Err(
            "the trigger has no condition; set min_severity, techniques_any, techniques_all, entity_kinds, or tenants"
                .to_owned(),
        );
    }
    Ok(trigger)
}

fn validate_step(position: usize, raw: RawStep) -> Result<Step, String> {
    let id = match raw.id {
        Some(id) => id.trim().to_owned(),
        None => format!("step-{position}"),
    };
    if !is_name(&id) {
        return Err(format!(
            "step {position}: the id {id:?} must have 1 to {MAX_NAME_LENGTH} characters: lower-case letters, digits, '-', and '_'"
        ));
    }
    let fail = |reason: String| format!("step {id}: {reason}");
    if matches!(&raw.action, ActionKind::Custom(name) if !is_name(name)) {
        return Err(fail(
            "the name of a custom action must be lower-case letters, digits, '-', and '_'"
                .to_owned(),
        ));
    }
    if matches!(&raw.action, ActionKind::Custom(name) if name == REVERT_ACTION) {
        return Err(fail(format!(
            "the custom action {REVERT_ACTION} is reserved; a playbook cannot revert an action"
        )));
    }
    if let TargetSelector::Fixed(entity) = &raw.target
        && entity.id.trim().is_empty()
    {
        return Err(fail("the fixed target has an empty id".to_owned()));
    }
    check_target_kind(&raw.action, raw.target.kind()).map_err(fail)?;
    let reason = raw.reason.trim().to_owned();
    if reason.is_empty() || reason.chars().count() > MAX_TEXT_LENGTH {
        return Err(fail(format!(
            "the reason must have 1 to {MAX_TEXT_LENGTH} characters"
        )));
    }
    template::check(&reason).map_err(|error| fail(format!("reason: {error}")))?;
    for (name, value) in &raw.parameters {
        if name == REVERT_AFTER_PARAMETER {
            return Err(fail(format!(
                "parameter {name}: use the step field revert_after for a timed revert"
            )));
        }
        if name == EXECUTION_DETAILS_PARAMETER {
            return Err(fail(format!(
                "parameter {name}: the name is reserved for the dispatcher"
            )));
        }
        template::check_value(value).map_err(|error| fail(format!("parameter {name}: {error}")))?;
    }
    let revert_after = match &raw.revert_after {
        Some(value) => {
            let seconds = revert::parse_revert_after(value)
                .map_err(|error| fail(format!("revert_after: {error}")))?;
            revert::check_kind(&raw.action)
                .map_err(|error| fail(format!("revert_after: {error}")))?;
            Some(seconds)
        }
        None => None,
    };
    let max_targets = raw.max_targets.unwrap_or(DEFAULT_MAX_TARGETS);
    if !(1..=MAX_TARGETS_LIMIT).contains(&max_targets) {
        return Err(fail(format!(
            "max_targets must be 1 to {MAX_TARGETS_LIMIT}"
        )));
    }
    Ok(Step {
        id,
        action: raw.action,
        target: raw.target,
        parameters: raw.parameters,
        reason,
        continue_on_error: raw.continue_on_error,
        max_targets,
        revert_after,
        literal: false,
    })
}

fn validate(raw: RawPlaybook) -> Result<Playbook, String> {
    let name = raw.name.trim().to_owned();
    if !is_name(&name) {
        return Err(format!(
            "the name {name:?} must have 1 to {MAX_NAME_LENGTH} characters: lower-case letters, digits, '-', and '_'"
        ));
    }
    let description = raw.description.trim().to_owned();
    if description.is_empty() || description.chars().count() > MAX_TEXT_LENGTH {
        return Err(format!(
            "the description must have 1 to {MAX_TEXT_LENGTH} characters"
        ));
    }
    let trigger = validate_trigger(raw.trigger)?;
    if raw.steps.is_empty() {
        return Err("the playbook has no steps".to_owned());
    }
    if raw.steps.len() > MAX_STEPS {
        return Err(format!(
            "the playbook has {} steps; the limit is {MAX_STEPS}",
            raw.steps.len()
        ));
    }
    let mut steps: Vec<Step> = Vec::with_capacity(raw.steps.len());
    for (index, raw_step) in raw.steps.into_iter().enumerate() {
        let step = validate_step(index + 1, raw_step)?;
        if steps.iter().any(|known| known.id == step.id) {
            return Err(format!("two steps have the id {:?}", step.id));
        }
        steps.push(step);
    }
    Ok(Playbook {
        name,
        description,
        origin: PlaybookOrigin::Operator,
        trigger,
        steps,
    })
}

impl Playbook {
    /// Reads and validates one playbook from YAML text.
    ///
    /// `file` is the name of the source. Each error names it.
    ///
    /// # Errors
    ///
    /// Returns [`PlaybookError::Invalid`] with the file name and the reason if the text is
    /// not valid YAML, has a field that is not known, or breaks a rule of the format.
    pub fn from_yaml(file: &str, text: &str) -> Result<Self, PlaybookError> {
        let invalid = |reason: String| PlaybookError::Invalid {
            file: file.to_owned(),
            reason,
        };
        let raw: RawPlaybook =
            serde_saphyr::from_str(text).map_err(|error| invalid(error.to_string()))?;
        validate(raw).map_err(invalid)
    }

    /// Returns the name of the playbook.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description of the playbook.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns where the playbook comes from.
    #[must_use]
    pub fn origin(&self) -> &PlaybookOrigin {
        &self.origin
    }

    /// Returns the trigger of the playbook.
    #[must_use]
    pub fn trigger(&self) -> &Trigger {
        &self.trigger
    }

    /// Returns the steps of the playbook, in order.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Returns `true` if the trigger of the playbook matches the incident.
    #[must_use]
    pub fn matches(&self, incident: &Incident) -> bool {
        self.trigger.matches(incident)
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::detection::AttackTechnique;
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    const VALID: &str = r#"
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
  entity_kinds: [ip_address]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    parameters:
      duration_hours: 24
      comment: "Incident {{incident.id}}"
    reason: "Block the spray address {{target.id}}."
    continue_on_error: true
    max_targets: 5
  - action: notify
    target:
      fixed:
        kind: other
        id: secops-channel
        name: Security operations
    reason: "A password spray came from the tenant {{incident.tenant}}."
  - action:
      custom: quarantine_mailbox
    target: incident_tenant
    reason: Quarantine.
"#;

    fn incident(severity: Severity, techniques: &[&str], entities: Vec<EntityRef>) -> Incident {
        Incident {
            id: IncidentId::new(),
            title: "Password spray".to_owned(),
            summary: String::new(),
            severity,
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tenant: Some("tenant-contoso".to_owned()),
            detections: Vec::new(),
            entities,
            attack: techniques
                .iter()
                .map(|id| AttackTechnique::new("tactic", *id, "name"))
                .collect(),
            timeline: Vec::new(),
        }
    }

    fn reason_of(yaml: &str) -> String {
        match Playbook::from_yaml("test.yaml", yaml).unwrap_err() {
            PlaybookError::Invalid { file, reason } => {
                assert_eq!(file, "test.yaml");
                reason
            }
            other => panic!("expected an invalid playbook, found {other:?}"),
        }
    }

    #[test]
    fn a_valid_playbook_reads_all_fields() {
        let playbook = Playbook::from_yaml("block.yaml", VALID).unwrap();
        assert_eq!(playbook.name(), "block-spray-source");
        assert_eq!(
            playbook.description(),
            "Block the address that a password spray comes from."
        );
        assert_eq!(playbook.origin(), &PlaybookOrigin::Operator);
        assert_eq!(playbook.trigger().incident_id(), None);
        assert_eq!(playbook.steps().len(), 3);

        let block = &playbook.steps()[0];
        assert_eq!(block.id(), "block-address");
        assert_eq!(block.action(), &ActionKind::BlockIp);
        assert_eq!(
            block.target(),
            &TargetSelector::EachEntity(EntityKind::IpAddress)
        );
        assert_eq!(block.parameters()["duration_hours"], json!(24));
        assert_eq!(
            block.parameters()["comment"],
            json!("Incident {{incident.id}}")
        );
        assert_eq!(block.reason(), "Block the spray address {{target.id}}.");
        assert!(block.continue_on_error());
        assert_eq!(block.max_targets(), 5);

        let notify = &playbook.steps()[1];
        assert_eq!(notify.id(), "step-2");
        assert_eq!(notify.action(), &ActionKind::Notify);
        assert_eq!(
            notify.target(),
            &TargetSelector::Fixed(
                EntityRef::new(EntityKind::Other, "secops-channel")
                    .with_name("Security operations")
            )
        );
        assert!(!notify.continue_on_error());
        assert_eq!(notify.max_targets(), DEFAULT_MAX_TARGETS);

        let custom = &playbook.steps()[2];
        assert_eq!(
            custom.action(),
            &ActionKind::Custom("quarantine_mailbox".to_owned())
        );
        assert_eq!(custom.target(), &TargetSelector::IncidentTenant);
    }

    #[test]
    fn the_trigger_needs_all_of_its_conditions() {
        let playbook = Playbook::from_yaml("block.yaml", VALID).unwrap();
        let address = || vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")];

        assert!(playbook.matches(&incident(Severity::High, &["T1110.003"], address())));
        assert!(playbook.matches(&incident(
            Severity::Medium,
            &["T1078", "T1110.003"],
            address()
        )));
        assert!(!playbook.matches(&incident(Severity::Low, &["T1110.003"], address())));
        assert!(!playbook.matches(&incident(Severity::High, &["T1110.001"], address())));
        assert!(!playbook.matches(&incident(Severity::High, &["T1110.003"], Vec::new())));
        assert!(!playbook.matches(&incident(
            Severity::High,
            &["T1110.003"],
            vec![EntityRef::new(EntityKind::User, "user-dana")]
        )));
    }

    #[test]
    fn the_trigger_ignores_incidents_that_are_closed() {
        let playbook = Playbook::from_yaml("block.yaml", VALID).unwrap();
        let mut closed = incident(
            Severity::High,
            &["T1110.003"],
            vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")],
        );
        for status in [
            IncidentStatus::FalsePositive,
            IncidentStatus::Resolved,
            IncidentStatus::Contained,
        ] {
            closed.status = status;
            assert!(!playbook.matches(&closed), "{status:?}");
        }
        closed.status = IncidentStatus::Investigating;
        assert!(playbook.matches(&closed));

        let with_statuses = VALID.replace(
            "  min_severity: medium\n",
            "  min_severity: medium\n  statuses: [contained]\n",
        );
        let playbook = Playbook::from_yaml("block.yaml", &with_statuses).unwrap();
        assert!(!playbook.matches(&closed));
        closed.status = IncidentStatus::Contained;
        assert!(playbook.matches(&closed));
    }

    #[test]
    fn a_parent_technique_matches_its_sub_techniques_only() {
        assert!(technique_matches("T1098", "T1098"));
        assert!(technique_matches("T1098", "T1098.001"));
        assert!(!technique_matches("T1098", "T10981"));
        assert!(!technique_matches("T1098.001", "T1098"));
        assert!(!technique_matches("T1098.001", "T1098.003"));

        let yaml = VALID
            .replace(
                "techniques_any: [T1110.003]",
                "techniques_all: [t1098, T1528]",
            )
            .replace(
                "  entity_kinds: [ip_address]\n",
                "  tenants: [tenant-contoso]\n",
            );
        let playbook = Playbook::from_yaml("block.yaml", &yaml).unwrap();
        assert!(playbook.matches(&incident(
            Severity::High,
            &["T1098.003", "T1528"],
            Vec::new()
        )));
        assert!(!playbook.matches(&incident(Severity::High, &["T1098.003"], Vec::new())));
        let mut other_tenant = incident(Severity::High, &["T1098.003", "T1528"], Vec::new());
        other_tenant.tenant = Some("tenant-fabrikam".to_owned());
        assert!(!playbook.matches(&other_tenant));
        other_tenant.tenant = None;
        assert!(!playbook.matches(&other_tenant));
    }

    #[test]
    fn each_entity_gives_each_matching_entity_one_time() {
        let entities = vec![
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            EntityRef::new(EntityKind::User, "user-dana"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
            EntityRef::new(EntityKind::IpAddress, "203.0.113.50").with_name("again"),
        ];
        let incident = incident(Severity::High, &[], entities);
        let targets = TargetSelector::EachEntity(EntityKind::IpAddress).resolve(&incident);
        assert_eq!(
            targets,
            [
                EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.51"),
            ]
        );
        assert_eq!(
            TargetSelector::EachEntity(EntityKind::Host).resolve(&incident),
            []
        );
        assert_eq!(
            TargetSelector::IncidentTenant.resolve(&incident),
            [EntityRef::new(EntityKind::Tenant, "tenant-contoso")]
        );
        let mut no_tenant = incident;
        no_tenant.tenant = None;
        assert_eq!(TargetSelector::IncidentTenant.resolve(&no_tenant), []);
    }

    #[test]
    fn yaml_that_is_not_valid_names_the_file() {
        let reason = reason_of("name: [unclosed");
        assert!(!reason.is_empty());
        let error = Playbook::from_yaml("broken.yaml", "name: [unclosed").unwrap_err();
        assert!(
            error.to_string().starts_with("playbook broken.yaml: "),
            "{error}"
        );
        let contract: Error = error.into();
        assert!(
            matches!(&contract, Error::Config(message) if message.starts_with("playbook broken.yaml: ")),
            "{contract:?}"
        );
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let reason = reason_of(&VALID.replace("continue_on_error: true", "continue_on_eror: true"));
        assert!(reason.contains("continue_on_eror"), "{reason}");
    }

    #[test]
    fn an_unknown_action_or_entity_type_is_rejected() {
        let reason = reason_of(&VALID.replace("action: block_ip", "action: launch_counter_attack"));
        assert!(reason.contains("launch_counter_attack"), "{reason}");
        let reason = reason_of(&VALID.replace("each_entity: ip_address", "each_entity: mainframe"));
        assert!(reason.contains("mainframe"), "{reason}");
    }

    #[test]
    fn a_trigger_with_no_condition_is_rejected() {
        let yaml = VALID
            .replace("  min_severity: medium\n", "  statuses: [open]\n")
            .replace("  techniques_any: [T1110.003]\n", "")
            .replace("  entity_kinds: [ip_address]\n", "");
        let reason = reason_of(&yaml);
        assert!(
            reason.starts_with("the trigger has no condition"),
            "{reason}"
        );
    }

    #[test]
    fn a_technique_identifier_that_is_not_valid_is_rejected() {
        for bad in [
            "1110",
            "T110",
            "T1110.3",
            "TA0001",
            "T1110.0033",
            "password spray",
        ] {
            let reason = reason_of(&VALID.replace("T1110.003", &format!("\"{bad}\"")));
            assert!(
                reason.contains("is not an ATT&CK technique identifier"),
                "{bad}: {reason}"
            );
        }
        assert_eq!(technique(" t1098.001 ").unwrap(), "T1098.001");
    }

    #[test]
    fn a_step_with_a_target_type_that_the_action_cannot_change_is_rejected() {
        let reason = reason_of(&VALID.replace("each_entity: ip_address", "each_entity: user"));
        assert_eq!(
            reason,
            "step block-address: the action block_ip needs a target of the type ip_address, not user"
        );
        let reason = reason_of(&VALID.replace(
            "action:\n      custom: quarantine_mailbox",
            "action: disable_user",
        ));
        assert_eq!(
            reason,
            "step step-3: the action disable_user needs a target of the type user, not tenant"
        );
    }

    #[test]
    fn a_template_error_names_the_step_and_the_field() {
        let reason = reason_of(&VALID.replace("{{target.id}}.", "{{target.address}}."));
        assert_eq!(
            reason,
            "step block-address: reason: the template variable \"target.address\" is not known"
        );
        let reason =
            reason_of(&VALID.replace("Incident {{incident.id}}", "Incident {{incident.id"));
        assert_eq!(
            reason,
            "step block-address: parameter comment: the template has `{{` with no `}}`"
        );
    }

    #[test]
    fn names_ids_and_counts_have_limits() {
        let reason = reason_of(&VALID.replace("name: block-spray-source", "name: Block Spray"));
        assert!(
            reason.starts_with("the name \"Block Spray\" must have"),
            "{reason}"
        );
        let reason = reason_of(&VALID.replace(
            "description: Block the address that a password spray comes from.",
            "description: \"  \"",
        ));
        assert!(reason.starts_with("the description must have"), "{reason}");
        let reason = reason_of(&VALID.replace("id: block-address", "id: Block Address"));
        assert!(
            reason.starts_with("step 1: the id \"Block Address\" must have"),
            "{reason}"
        );
        let reason = reason_of(&VALID.replace("id: block-address", "id: step-2"));
        assert_eq!(reason, "two steps have the id \"step-2\"");
        let reason = reason_of(&VALID.replace("reason: Quarantine.", "reason: \"\""));
        assert!(
            reason.starts_with("step step-3: the reason must have"),
            "{reason}"
        );
        let reason =
            reason_of(&VALID.replace("custom: quarantine_mailbox", "custom: \"Bad Name\""));
        assert!(
            reason.starts_with("step step-3: the name of a custom action"),
            "{reason}"
        );
        let reason = reason_of(&VALID.replace("id: secops-channel", "id: \" \""));
        assert_eq!(reason, "step step-2: the fixed target has an empty id");
        for bad in ["0", "1001"] {
            let reason =
                reason_of(&VALID.replace("max_targets: 5", &format!("max_targets: {bad}")));
            assert_eq!(
                reason, "step block-address: max_targets must be 1 to 1000",
                "{bad}"
            );
        }

        let (head, _) = VALID.split_once("steps:").unwrap();
        assert_eq!(
            reason_of(&format!("{head}steps: []\n")),
            "the playbook has no steps"
        );
        let step = "  - action: notify\n    target: incident_tenant\n    reason: Tell.\n";
        let many = format!("{head}steps:\n{}", step.repeat(MAX_STEPS + 1));
        assert_eq!(
            reason_of(&many),
            "the playbook has 33 steps; the limit is 32"
        );
        let most = format!("{head}steps:\n{}", step.repeat(MAX_STEPS));
        assert_eq!(
            Playbook::from_yaml("many.yaml", &most)
                .unwrap()
                .steps()
                .len(),
            MAX_STEPS
        );
    }

    #[test]
    fn a_step_reads_its_timed_revert() {
        let yaml = VALID.replace(
            "    max_targets: 5\n",
            "    max_targets: 5\n    revert_after: 4h\n",
        );
        let playbook = Playbook::from_yaml("block.yaml", &yaml).unwrap();
        assert_eq!(
            playbook.steps()[0].revert_after(),
            Some(Duration::from_secs(14_400))
        );
        assert_eq!(playbook.steps()[1].revert_after(), None);
        let value = serde_json::to_value(&playbook).unwrap();
        assert_eq!(value["steps"][0]["revert_after_seconds"], json!(14_400));
        assert_eq!(value["steps"][1].get("revert_after_seconds"), None);

        // A number is a number of seconds.
        let seconds = VALID.replace(
            "    max_targets: 5\n",
            "    max_targets: 5\n    revert_after: 900\n",
        );
        let playbook = Playbook::from_yaml("block.yaml", &seconds).unwrap();
        assert_eq!(
            playbook.steps()[0].revert_after(),
            Some(Duration::from_secs(900))
        );

        // A custom action can have a timed revert. The connector decides if it has an inverse.
        let custom = VALID.replace(
            "    reason: Quarantine.",
            "    revert_after: 30m\n    reason: Quarantine.",
        );
        let playbook = Playbook::from_yaml("block.yaml", &custom).unwrap();
        assert_eq!(
            playbook.steps()[2].revert_after(),
            Some(Duration::from_secs(1_800))
        );
    }

    #[test]
    fn a_timed_revert_that_is_not_valid_is_rejected() {
        let with = |value: &str| {
            VALID.replace(
                "    max_targets: 5\n",
                &format!("    max_targets: 5\n    revert_after: {value}\n"),
            )
        };
        assert_eq!(
            reason_of(&with("4 hours")),
            "step block-address: revert_after: the revert time \"4 hours\" is not valid; use a number of seconds, or a number with the unit s, m, h, or d, for example 4h"
        );
        assert_eq!(
            reason_of(&with("0")),
            "step block-address: revert_after: the revert time must be 1 to 2592000 seconds, not 0"
        );
        assert_eq!(
            reason_of(&with("31d")),
            "step block-address: revert_after: the revert time must be 1 to 2592000 seconds, not 2678400"
        );

        // An action with no inverse cannot have a timed revert.
        let notify = VALID.replace(
            "  - action: notify\n",
            "  - action: notify\n    revert_after: 4h\n",
        );
        assert_eq!(
            reason_of(&notify),
            "step step-2: revert_after: the action notify has no inverse, so it cannot have a timed revert"
        );

        // The step field is the only way to set the timed revert.
        let parameter = VALID.replace("duration_hours: 24", "revert_after_seconds: 600");
        assert_eq!(
            reason_of(&parameter),
            "step block-address: parameter revert_after_seconds: use the step field revert_after for a timed revert"
        );
        let reserved = VALID.replace("duration_hours: 24", "execution_details: {}");
        assert_eq!(
            reason_of(&reserved),
            "step block-address: parameter execution_details: the name is reserved for the dispatcher"
        );
    }

    #[test]
    fn the_revert_action_is_reserved_and_consent_friction_needs_the_tenant() {
        let revert = VALID.replace("custom: quarantine_mailbox", "custom: revert");
        assert_eq!(
            reason_of(&revert),
            "step step-3: the custom action revert is reserved; a playbook cannot revert an action"
        );

        let friction = VALID.replace(
            "custom: quarantine_mailbox",
            "custom: restrict_user_consent",
        );
        let playbook = Playbook::from_yaml("block.yaml", &friction).unwrap();
        assert_eq!(
            playbook.steps()[2].action(),
            &ActionKind::Custom("restrict_user_consent".to_owned())
        );
        let on_address = VALID.replace(
            "action: block_ip",
            "action:\n      custom: restrict_user_consent",
        );
        assert_eq!(
            reason_of(&on_address),
            "step block-address: the action custom:restrict_user_consent needs a target of the type tenant, not ip_address"
        );
        // The other friction action is for a control of the operator, with a target of any
        // type.
        let raise = VALID.replace("action: block_ip", "action:\n      custom: raise_friction");
        assert!(Playbook::from_yaml("block.yaml", &raise).is_ok());
    }

    #[test]
    fn a_playbook_serializes_for_display() {
        let playbook = Playbook::from_yaml("block.yaml", VALID).unwrap();
        let value = serde_json::to_value(&playbook).unwrap();
        assert_eq!(value["name"], "block-spray-source");
        assert_eq!(value["origin"], "operator");
        assert_eq!(value["trigger"]["min_severity"], "medium");
        assert_eq!(
            value["trigger"]["statuses"],
            json!(["open", "investigating"])
        );
        assert_eq!(
            value["steps"][0]["target"],
            json!({ "each_entity": "ip_address" })
        );
        assert_eq!(value["steps"][2]["target"], "incident_tenant");
    }
}
