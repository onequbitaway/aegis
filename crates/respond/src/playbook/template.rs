//! Text templates for the reason and the parameters of a playbook step.
//!
//! A template is text with variables between `{{` and `}}`, for example
//! `Disable {{target.id}} for incident {{incident.id}}.`
//!
//! | Variable | Value |
//! | --- | --- |
//! | `playbook.name` | The name of the playbook. |
//! | `incident.id` | The identifier of the incident. |
//! | `incident.title` | The title of the incident. |
//! | `incident.severity` | The severity of the incident, for example `high`. |
//! | `incident.status` | The state of the incident, for example `open`. |
//! | `incident.tenant` | The tenant of the incident. |
//! | `incident.techniques` | The ATT&CK technique identifiers of the incident, with commas. |
//! | `target.id` | The identifier of the target entity. |
//! | `target.kind` | The type of the target entity, for example `service_principal`. |
//! | `target.name` | The display name of the target entity, or its identifier. |
//! | `target.tenant` | The tenant of the target entity. |
//! | `detection.<key>` | The first value of the attribute `<key>` in the detections. |
//!
//! A variable with no value is an error. The engine does not send the request.

use aegis_contracts::common::EntityRef;
use aegis_contracts::incident::Incident;
use serde_json::Value;

use crate::names::{snake_name, truncate};

const OPEN: &str = "{{";
const CLOSE: &str = "}}";
const MAX_VALUE_LENGTH: usize = 256;

/// The data that a template can read.
pub(crate) struct Scope<'a> {
    pub(crate) playbook: &'a str,
    pub(crate) incident: &'a Incident,
    pub(crate) target: &'a EntityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Variable {
    PlaybookName,
    IncidentId,
    IncidentTitle,
    IncidentSeverity,
    IncidentStatus,
    IncidentTenant,
    IncidentTechniques,
    TargetId,
    TargetKind,
    TargetName,
    TargetTenant,
    DetectionAttribute(String),
}

impl Variable {
    fn parse(name: &str) -> Result<Self, String> {
        let variable = match name {
            "playbook.name" => Self::PlaybookName,
            "incident.id" => Self::IncidentId,
            "incident.title" => Self::IncidentTitle,
            "incident.severity" => Self::IncidentSeverity,
            "incident.status" => Self::IncidentStatus,
            "incident.tenant" => Self::IncidentTenant,
            "incident.techniques" => Self::IncidentTechniques,
            "target.id" => Self::TargetId,
            "target.kind" => Self::TargetKind,
            "target.name" => Self::TargetName,
            "target.tenant" => Self::TargetTenant,
            other => {
                let key = other.strip_prefix("detection.").unwrap_or_default();
                let key_is_valid = !key.is_empty()
                    && key.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '_'
                    });
                if !key_is_valid {
                    return Err(format!("the template variable {other:?} is not known"));
                }
                Self::DetectionAttribute(key.to_owned())
            }
        };
        Ok(variable)
    }

    fn value(&self, scope: &Scope<'_>) -> Result<String, String> {
        let missing = |what: &str| format!("the template needs {what}, which has no value");
        match self {
            Self::PlaybookName => Ok(scope.playbook.to_owned()),
            Self::IncidentId => Ok(scope.incident.id.to_string()),
            Self::IncidentTitle => Ok(truncate(&scope.incident.title, MAX_VALUE_LENGTH)),
            Self::IncidentSeverity => Ok(snake_name(&scope.incident.severity)),
            Self::IncidentStatus => Ok(snake_name(&scope.incident.status)),
            Self::IncidentTenant => scope
                .incident
                .tenant
                .clone()
                .ok_or_else(|| missing("incident.tenant")),
            Self::IncidentTechniques => Ok(scope
                .incident
                .attack
                .iter()
                .map(|technique| technique.technique_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")),
            Self::TargetId => Ok(scope.target.id.clone()),
            Self::TargetKind => Ok(snake_name(&scope.target.kind)),
            Self::TargetName => Ok(scope
                .target
                .name
                .clone()
                .unwrap_or_else(|| scope.target.id.clone())),
            Self::TargetTenant => scope
                .target
                .tenant
                .clone()
                .ok_or_else(|| missing("target.tenant")),
            Self::DetectionAttribute(key) => {
                let found = scope
                    .incident
                    .detections
                    .iter()
                    .find_map(|detection| match detection.attributes.get(key) {
                        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
                        Some(Value::Number(number)) => Some(number.to_string()),
                        Some(Value::Bool(flag)) => Some(flag.to_string()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        format!("no detection of the incident has the attribute {key}")
                    })?;
                if found.chars().count() > MAX_VALUE_LENGTH {
                    return Err(format!(
                        "the detection attribute {key} is longer than {MAX_VALUE_LENGTH} characters"
                    ));
                }
                Ok(found)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment<'a> {
    Text(&'a str),
    Variable(Variable),
}

fn parse(text: &str) -> Result<Vec<Segment<'_>>, String> {
    let mut segments = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        if start > 0 {
            segments.push(Segment::Text(&rest[..start]));
        }
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else {
            return Err("the template has `{{` with no `}}`".to_owned());
        };
        segments.push(Segment::Variable(Variable::parse(after[..end].trim())?));
        rest = &after[end + CLOSE.len()..];
    }
    if !rest.is_empty() {
        segments.push(Segment::Text(rest));
    }
    Ok(segments)
}

/// Checks the syntax and the variable names of a template.
pub(crate) fn check(text: &str) -> Result<(), String> {
    parse(text).map(|_| ())
}

/// Checks each string in a parameter value.
pub(crate) fn check_value(value: &Value) -> Result<(), String> {
    match value {
        Value::String(text) => check(text),
        Value::Array(items) => items.iter().try_for_each(check_value),
        Value::Object(fields) => fields.values().try_for_each(check_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

/// Replaces each variable in a template with its value.
pub(crate) fn render(text: &str, scope: &Scope<'_>) -> Result<String, String> {
    let mut output = String::with_capacity(text.len());
    for segment in parse(text)? {
        match segment {
            Segment::Text(literal) => output.push_str(literal),
            Segment::Variable(variable) => output.push_str(&variable.value(scope)?),
        }
    }
    Ok(output)
}

/// Replaces each variable in each string of a parameter value.
pub(crate) fn render_value(value: &Value, scope: &Scope<'_>) -> Result<Value, String> {
    Ok(match value {
        Value::String(text) => Value::String(render(text, scope)?),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| render_value(item, scope))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| Ok((key.clone(), render_value(field, scope)?)))
                .collect::<Result<_, String>>()?,
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::{DetectionId, EntityKind, IncidentId, Severity};
    use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
    use aegis_contracts::incident::IncidentStatus;
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn incident() -> Incident {
        let mut detection = Detection {
            id: DetectionId::new(),
            rule_id: "rule".to_owned(),
            title: "Credential added".to_owned(),
            description: String::new(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time: Utc::now(),
            attack: Vec::new(),
            event_ids: Vec::new(),
            entities: Vec::new(),
            tenant: None,
            attributes: Default::default(),
        };
        detection
            .attributes
            .insert("credential_id".to_owned(), json!("credential-1"));
        detection.attributes.insert("count".to_owned(), json!(600));
        Incident {
            id: IncidentId::new(),
            title: "Rogue service principal".to_owned(),
            summary: String::new(),
            severity: Severity::Critical,
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tenant: Some("tenant-contoso".to_owned()),
            detections: vec![detection],
            entities: Vec::new(),
            attack: vec![
                AttackTechnique::new("persistence", "T1098.001", "Additional Cloud Credentials"),
                AttackTechnique::new(
                    "credential-access",
                    "T1528",
                    "Steal Application Access Token",
                ),
            ],
            timeline: Vec::new(),
        }
    }

    #[test]
    fn render_replaces_each_variable() {
        let incident = incident();
        let target = EntityRef::new(EntityKind::ServicePrincipal, "sp-1").with_name("Sync Helper");
        let scope = Scope {
            playbook: "contain",
            incident: &incident,
            target: &target,
        };
        let text = render(
            "{{playbook.name}}: disable {{ target.kind }} {{target.id}} ({{target.name}}) in {{incident.tenant}}. \
             {{incident.title}} is {{incident.severity}}/{{incident.status}} [{{incident.techniques}}] key {{detection.credential_id}} n={{detection.count}}",
            &scope,
        )
        .unwrap();
        assert_eq!(
            text,
            "contain: disable service_principal sp-1 (Sync Helper) in tenant-contoso. \
             Rogue service principal is critical/open [T1098.001, T1528] key credential-1 n=600"
        );
        assert_eq!(
            render("{{incident.id}}", &scope).unwrap(),
            incident.id.to_string()
        );
        assert_eq!(
            render("no variables { } }}", &scope).unwrap(),
            "no variables { } }}"
        );
    }

    #[test]
    fn the_target_name_falls_back_to_the_identifier() {
        let incident = incident();
        let target = EntityRef::new(EntityKind::User, "user-dana");
        let scope = Scope {
            playbook: "contain",
            incident: &incident,
            target: &target,
        };
        assert_eq!(render("{{target.name}}", &scope).unwrap(), "user-dana");
    }

    #[test]
    fn a_variable_with_no_value_is_an_error() {
        let mut incident = incident();
        incident.tenant = None;
        let target = EntityRef::new(EntityKind::User, "user-dana");
        let scope = Scope {
            playbook: "contain",
            incident: &incident,
            target: &target,
        };
        assert_eq!(
            render("{{incident.tenant}}", &scope).unwrap_err(),
            "the template needs incident.tenant, which has no value"
        );
        assert_eq!(
            render("{{target.tenant}}", &scope).unwrap_err(),
            "the template needs target.tenant, which has no value"
        );
        assert_eq!(
            render("{{detection.key_id}}", &scope).unwrap_err(),
            "no detection of the incident has the attribute key_id"
        );
    }

    #[test]
    fn a_long_title_is_cut_and_a_long_attribute_is_an_error() {
        let mut incident = incident();
        incident.title = "t".repeat(MAX_VALUE_LENGTH + 50);
        incident.detections[0].attributes.insert(
            "credential_id".to_owned(),
            json!("k".repeat(MAX_VALUE_LENGTH + 1)),
        );
        let target = EntityRef::new(EntityKind::User, "user-dana");
        let scope = Scope {
            playbook: "contain",
            incident: &incident,
            target: &target,
        };
        assert_eq!(
            render("{{incident.title}}", &scope).unwrap(),
            format!("{}...", "t".repeat(MAX_VALUE_LENGTH))
        );
        assert_eq!(
            render("{{detection.credential_id}}", &scope).unwrap_err(),
            "the detection attribute credential_id is longer than 256 characters"
        );
    }

    #[test]
    fn check_finds_unknown_variables_and_open_braces() {
        assert_eq!(check("Disable {{target.id}}."), Ok(()));
        assert_eq!(
            check("Disable {{target.identifier}}.").unwrap_err(),
            "the template variable \"target.identifier\" is not known"
        );
        assert_eq!(
            check("{{detection.Bad-Key}}").unwrap_err(),
            "the template variable \"detection.Bad-Key\" is not known"
        );
        assert_eq!(
            check("Disable {{target.id").unwrap_err(),
            "the template has `{{` with no `}}`"
        );
        assert_eq!(
            check_value(&json!({ "a": ["ok", { "b": "{{nope}}" }] })).unwrap_err(),
            "the template variable \"nope\" is not known"
        );
        assert_eq!(
            check_value(&json!({ "a": [1, true, null, "{{target.id}}"] })),
            Ok(())
        );
    }

    #[test]
    fn render_value_keeps_the_structure_and_the_types() {
        let incident = incident();
        let target = EntityRef::new(EntityKind::IpAddress, "203.0.113.50");
        let scope = Scope {
            playbook: "contain",
            incident: &incident,
            target: &target,
        };
        let rendered = render_value(
            &json!({ "address": "{{target.id}}", "ttl": 3600, "tags": ["aegis", "{{incident.severity}}"], "log": true }),
            &scope,
        )
        .unwrap();
        assert_eq!(
            rendered,
            json!({ "address": "203.0.113.50", "ttl": 3600, "tags": ["aegis", "critical"], "log": true })
        );
    }
}
