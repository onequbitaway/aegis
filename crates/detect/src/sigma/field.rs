//! Field lookup: a dotted path in a rule against one event.

use std::net::IpAddr;

use aegis_contracts::event::Event;
use serde_json::Value;

use crate::common::{class_name, kind_name, outcome_name, severity_name};

/// One value that a field path found in an event.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Leaf<'a> {
    /// A JSON `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number.
    Number(&'a serde_json::Number),
    /// A string.
    Text(&'a str),
    /// An IP address from a typed field of the event.
    Ip(IpAddr),
    /// A JSON object. It exists, but no value test matches it.
    Structure,
}

/// A field of the event that a rule names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldPath {
    Action,
    Outcome,
    Severity,
    Class,
    ActorId,
    ActorKind,
    ActorName,
    ActorTenant,
    ActorIp,
    ActorUserAgent,
    ActorSessionId,
    TargetId,
    TargetKind,
    TargetName,
    TargetTenant,
    SourceConnector,
    SourceVendor,
    SourceProduct,
    SourceTenant,
    /// A key of `Event::attributes`, and a path into its value.
    Attribute {
        /// The text after `attributes.`, for a key that contains `.`.
        flat: String,
        /// The first part of the path.
        key: String,
        /// The parts after the key.
        path: Vec<String>,
    },
    /// A path into `Event::raw`.
    Raw(Vec<String>),
}

const TYPED_FIELDS: &[(&str, FieldPath)] = &[
    ("action", FieldPath::Action),
    ("outcome", FieldPath::Outcome),
    ("severity", FieldPath::Severity),
    ("class", FieldPath::Class),
    ("actor.id", FieldPath::ActorId),
    ("actor.kind", FieldPath::ActorKind),
    ("actor.name", FieldPath::ActorName),
    ("actor.tenant", FieldPath::ActorTenant),
    ("actor.ip", FieldPath::ActorIp),
    ("actor.user_agent", FieldPath::ActorUserAgent),
    ("actor.session_id", FieldPath::ActorSessionId),
    ("target.id", FieldPath::TargetId),
    ("target.kind", FieldPath::TargetKind),
    ("target.name", FieldPath::TargetName),
    ("target.tenant", FieldPath::TargetTenant),
    ("source.connector", FieldPath::SourceConnector),
    ("source.vendor", FieldPath::SourceVendor),
    ("source.product", FieldPath::SourceProduct),
    ("source.tenant", FieldPath::SourceTenant),
];

/// Top-level names of the event that are structures or have no text form.
const STRUCTURES: &[&str] = &["actor", "target", "source", "attributes", "id", "time"];

fn split_path(text: &str) -> Result<Vec<String>, String> {
    let parts: Vec<String> = text.split('.').map(str::to_owned).collect();
    if parts.iter().any(String::is_empty) {
        return Err(format!("the field path {text:?} has an empty part"));
    }
    Ok(parts)
}

impl FieldPath {
    /// Converts the field name of a rule to a path.
    ///
    /// A name that is not a field of the event is a key of the attributes.
    pub(crate) fn parse(name: &str) -> Result<Self, String> {
        if name.is_empty() {
            return Err("a field name is empty".to_owned());
        }
        if let Some((_, path)) = TYPED_FIELDS.iter().find(|(typed, _)| *typed == name) {
            return Ok(path.clone());
        }
        if name == "raw" {
            return Ok(Self::Raw(Vec::new()));
        }
        if let Some(rest) = name.strip_prefix("raw.") {
            return Ok(Self::Raw(split_path(rest)?));
        }
        let head = name.split('.').next().unwrap_or(name);
        if head != "attributes" && STRUCTURES.contains(&head) {
            let known: Vec<&str> = TYPED_FIELDS
                .iter()
                .map(|(typed, _)| *typed)
                .filter(|typed| typed.split('.').next() == Some(head))
                .collect();
            return Err(if known.is_empty() {
                format!("the field {name:?} is not available to rules")
            } else {
                format!(
                    "the field {name:?} is not known; the fields of {head} are {}",
                    known.join(", ")
                )
            });
        }
        let flat = match name.strip_prefix("attributes.") {
            Some(rest) => rest,
            None if name == "attributes" => {
                return Err(
                    "the field \"attributes\" needs a key, for example attributes.app_id"
                        .to_owned(),
                );
            }
            None => name,
        };
        let mut parts = split_path(flat)?.into_iter();
        let key = parts.next().unwrap_or_default();
        Ok(Self::Attribute {
            flat: flat.to_owned(),
            key,
            path: parts.collect(),
        })
    }

    /// Calls `visit` for each value of the field until one call returns `true`.
    ///
    /// The function returns `true` if a call returned `true`. A list gives one call for each
    /// item. A field that the event does not have gives no call.
    pub(crate) fn any(&self, event: &Event, visit: &mut dyn FnMut(Leaf<'_>) -> bool) -> bool {
        let mut text = |value: Option<&str>| value.is_some_and(|value| visit(Leaf::Text(value)));
        let target = event.target.as_ref();
        match self {
            Self::Action => text(Some(&event.action)),
            Self::Outcome => text(Some(outcome_name(event.outcome))),
            Self::Severity => text(Some(severity_name(event.severity))),
            Self::Class => text(Some(class_name(event.class))),
            Self::ActorId => text(Some(&event.actor.id)),
            Self::ActorKind => text(Some(kind_name(event.actor.kind))),
            Self::ActorName => text(event.actor.name.as_deref()),
            Self::ActorTenant => text(event.actor.tenant.as_deref()),
            Self::ActorIp => event.actor.ip.is_some_and(|ip| visit(Leaf::Ip(ip))),
            Self::ActorUserAgent => text(event.actor.user_agent.as_deref()),
            Self::ActorSessionId => text(event.actor.session_id.as_deref()),
            Self::TargetId => text(target.map(|target| target.id.as_str())),
            Self::TargetKind => text(target.map(|target| kind_name(target.kind))),
            Self::TargetName => text(target.and_then(|target| target.name.as_deref())),
            Self::TargetTenant => text(target.and_then(|target| target.tenant.as_deref())),
            Self::SourceConnector => text(Some(&event.source.connector)),
            Self::SourceVendor => text(Some(&event.source.vendor)),
            Self::SourceProduct => text(Some(&event.source.product)),
            Self::SourceTenant => text(event.source.tenant.as_deref()),
            Self::Attribute { flat, key, path } => {
                if !path.is_empty()
                    && let Some(value) = event.attributes.get(flat)
                {
                    return walk(value, &[], visit);
                }
                event
                    .attributes
                    .get(key)
                    .is_some_and(|value| walk(value, path, visit))
            }
            Self::Raw(path) => event
                .raw
                .as_ref()
                .is_some_and(|value| walk(value, path, visit)),
        }
    }

    /// Returns `true` if the event has a value for the field. A `null` is a value.
    pub(crate) fn exists(&self, event: &Event) -> bool {
        self.any(event, &mut |_| true)
    }
}

/// Follows `path` into `value` and visits what it finds. A list on the way applies the
/// remaining path to each item.
fn walk(value: &Value, path: &[String], visit: &mut dyn FnMut(Leaf<'_>) -> bool) -> bool {
    let Some((head, rest)) = path.split_first() else {
        return leaves(value, visit);
    };
    match value {
        Value::Object(map) => map.get(head).is_some_and(|child| walk(child, rest, visit)),
        Value::Array(items) => items.iter().any(|item| walk(item, path, visit)),
        _ => false,
    }
}

fn leaves(value: &Value, visit: &mut dyn FnMut(Leaf<'_>) -> bool) -> bool {
    match value {
        Value::Null => visit(Leaf::Null),
        Value::Bool(flag) => visit(Leaf::Bool(*flag)),
        Value::Number(number) => visit(Leaf::Number(number)),
        Value::String(text) => visit(Leaf::Text(text)),
        Value::Array(items) => items.iter().any(|item| leaves(item, visit)),
        Value::Object(_) => visit(Leaf::Structure),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use aegis_contracts::common::{EntityKind, EntityRef, Severity};
    use aegis_contracts::event::{Actor, EventClass, EventSource, Outcome};
    use chrono::DateTime;
    use serde_json::json;

    use super::*;

    fn event() -> Event {
        let actor = Actor::new(EntityKind::ServicePrincipal, "sp-1")
            .with_name("Sync")
            .with_tenant("home")
            .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
            .with_user_agent("agent/1.0")
            .with_session_id("session-1");
        Event::new(
            DateTime::UNIX_EPOCH,
            EventSource::new("conn", "vendor", "product").with_tenant("tenant-1"),
            EventClass::UserAccessManagement,
            "role.assign",
            actor,
        )
        .with_outcome(Outcome::Failure)
        .with_severity(Severity::High)
        .with_target(
            EntityRef::new(EntityKind::Role, "role-1")
                .with_name("Admin")
                .with_tenant("tenant-2"),
        )
        .with_attribute("privileged", true)
        .with_attribute("count", 7)
        .with_attribute("scopes", json!(["a.read", "b.write"]))
        .with_attribute(
            "geo",
            json!({ "city": "Seattle", "point": { "lat": 47.6 } }),
        )
        .with_attribute("dotted.key", "flat")
        .with_attribute("nothing", Value::Null)
        .with_attribute("empty", json!([]))
        .with_raw(json!({
            "properties": {
                "targets": [
                    { "name": "one", "tags": ["x", "y"] },
                    { "name": "two" }
                ]
            }
        }))
    }

    /// Returns each value of the field in a text form.
    fn values(name: &str, event: &Event) -> Vec<String> {
        let path = FieldPath::parse(name).unwrap();
        let mut found = Vec::new();
        path.any(event, &mut |leaf| {
            found.push(match leaf {
                Leaf::Null => "null".to_owned(),
                Leaf::Bool(flag) => format!("bool:{flag}"),
                Leaf::Number(number) => format!("number:{number}"),
                Leaf::Text(text) => text.to_owned(),
                Leaf::Ip(ip) => format!("ip:{ip}"),
                Leaf::Structure => "structure".to_owned(),
            });
            false
        });
        found
    }

    #[test]
    fn typed_fields_give_the_names_that_the_contracts_encode() {
        let event = event();
        let expected = [
            ("action", "role.assign"),
            ("outcome", "failure"),
            ("severity", "high"),
            ("class", "user_access_management"),
            ("actor.id", "sp-1"),
            ("actor.kind", "service_principal"),
            ("actor.name", "Sync"),
            ("actor.tenant", "home"),
            ("actor.ip", "ip:203.0.113.9"),
            ("actor.user_agent", "agent/1.0"),
            ("actor.session_id", "session-1"),
            ("target.id", "role-1"),
            ("target.kind", "role"),
            ("target.name", "Admin"),
            ("target.tenant", "tenant-2"),
            ("source.connector", "conn"),
            ("source.vendor", "vendor"),
            ("source.product", "product"),
            ("source.tenant", "tenant-1"),
        ];
        assert_eq!(expected.len(), TYPED_FIELDS.len());
        for (name, value) in expected {
            assert_eq!(values(name, &event), [value], "{name}");
        }
    }

    #[test]
    fn optional_fields_that_are_absent_give_no_value() {
        let mut event = event();
        event.target = None;
        event.actor.ip = None;
        event.actor.user_agent = None;
        event.source.tenant = None;
        for name in [
            "target.id",
            "target.kind",
            "target.name",
            "actor.ip",
            "actor.user_agent",
            "source.tenant",
        ] {
            assert_eq!(values(name, &event), Vec::<String>::new(), "{name}");
            assert!(!FieldPath::parse(name).unwrap().exists(&event), "{name}");
        }
    }

    #[test]
    fn a_bare_name_and_the_attributes_prefix_read_the_same_attribute() {
        let event = event();
        assert_eq!(values("privileged", &event), ["bool:true"]);
        assert_eq!(values("attributes.privileged", &event), ["bool:true"]);
        assert_eq!(values("count", &event), ["number:7"]);
        assert_eq!(values("missing", &event), Vec::<String>::new());
    }

    #[test]
    fn a_list_gives_one_value_for_each_item_and_an_empty_list_gives_none() {
        let event = event();
        assert_eq!(values("scopes", &event), ["a.read", "b.write"]);
        assert_eq!(values("empty", &event), Vec::<String>::new());
    }

    #[test]
    fn a_path_goes_into_objects_and_a_flat_key_with_a_dot_wins() {
        let event = event();
        assert_eq!(values("geo.city", &event), ["Seattle"]);
        assert_eq!(values("attributes.geo.point.lat", &event), ["number:47.6"]);
        assert_eq!(values("geo", &event), ["structure"]);
        assert_eq!(values("geo.city.name", &event), Vec::<String>::new());
        assert_eq!(values("dotted.key", &event), ["flat"]);
    }

    #[test]
    fn a_null_attribute_exists_and_gives_a_null_value() {
        let event = event();
        assert_eq!(values("nothing", &event), ["null"]);
        assert!(FieldPath::parse("nothing").unwrap().exists(&event));
        assert!(!FieldPath::parse("missing").unwrap().exists(&event));
    }

    #[test]
    fn a_raw_path_applies_to_each_item_of_a_list_on_the_way() {
        let mut event = event();
        assert_eq!(
            values("raw.properties.targets.name", &event),
            ["one", "two"]
        );
        assert_eq!(values("raw.properties.targets.tags", &event), ["x", "y"]);
        assert_eq!(values("raw", &event), ["structure"]);
        assert_eq!(values("raw.properties.none", &event), Vec::<String>::new());
        event.raw = None;
        assert_eq!(
            values("raw.properties.targets.name", &event),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_visit_stops_at_the_first_value_that_matches() {
        let event = event();
        let path = FieldPath::parse("scopes").unwrap();
        let mut calls = 0;
        assert!(path.any(&event, &mut |_| {
            calls += 1;
            true
        }));
        assert_eq!(calls, 1);
    }

    #[test]
    fn parse_rejects_names_that_no_event_has() {
        let unknown = FieldPath::parse("actor.email").unwrap_err();
        assert!(unknown.contains("actor.id"), "{unknown}");
        assert!(unknown.contains("\"actor.email\""), "{unknown}");
        for name in [
            "",
            "actor",
            "target",
            "source",
            "attributes",
            "id",
            "time",
            "time.year",
        ] {
            assert!(FieldPath::parse(name).is_err(), "{name:?}");
        }
        for name in ["a..b", "raw.", "attributes.", ".a"] {
            let error = FieldPath::parse(name).unwrap_err();
            assert!(error.contains("empty part"), "{name:?}: {error}");
        }
    }
}
