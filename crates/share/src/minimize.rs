//! Data minimization: what stays in a document, and what the builder masks.
//!
//! A document for another organization must not hold the internal data of the operator.
//! The builder thus keeps a field only if a rule permits it:
//!
//! - It always keeps the time, the class, the action, the result, the remote address,
//!   and the user agent of an event.
//! - It keeps an event attribute only if the key is in the [`AllowList`].
//! - It never keeps the original record (`raw`) of an event.
//! - It replaces the identifier of each principal and each target with a label such as
//!   `masked-3`. The same entity has the same label in one report.
//! - It removes names, tenants, sessions, and connector names.
//! - It replaces each masked value that appears in kept text with `[masked]`.
//! - It replaces each part of kept text that looks like a secret.
//!
//! [`AllowList`] changes the first five rules. No option turns off the removal of
//! secrets or keeps the original record.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::event::{Event, action, attr};
use aegis_contracts::{Detection, Incident};
use aho_corasick::{AhoCorasick, MatchKind};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::address::canonical_address;
use crate::error::ShareError;
use crate::secrets::{scrub_addresses, scrub_secrets, strip_query};
use crate::text::{MAX_TEXT_CHARS, MAX_TOKEN_CHARS, MAX_USER_AGENT_CHARS, clean, time_text, token};

/// The text that replaces a masked value in kept text.
pub(crate) const MASK: &str = "[masked]";

/// The key of the source port attribute.
///
/// The key is not in the shared vocabulary of `aegis_contracts::event::attr`. A connector
/// can supply it. An abuse desk needs the source port when many customers share the
/// address.
pub const SOURCE_PORT: &str = "source_port";

/// The attribute keys that a document keeps by default.
///
/// These attributes describe what the remote client did. They do not name an entity of
/// the operator.
pub const DEFAULT_ATTRIBUTES: &[&str] = &[
    attr::AUTH_PROTOCOL,
    attr::BYTES_RECEIVED,
    attr::CLIENT_FINGERPRINT,
    attr::DESTINATION_PORT,
    attr::ERROR_CODE,
    attr::FAILURE_REASON,
    attr::HTTP_METHOD,
    attr::HTTP_PATH,
    attr::HTTP_STATUS,
    attr::OPERATION,
    SOURCE_PORT,
];

/// Attribute keys that hold an identifier or a name of the operator.
///
/// If the allow list does not keep such a key, the builder also masks its value in all
/// kept text.
const IDENTITY_ATTRIBUTES: &[&str] = &[
    attr::APP_ID,
    attr::APP_NAME,
    attr::CANARY_ID,
    attr::CREDENTIAL_ID,
    attr::DECOY_ID,
    attr::HOME_TENANT,
    attr::HONEYTOKEN_ID,
    attr::RESOURCE_TENANT,
    attr::ROLE_ID,
];

/// The largest number of items of an attribute array that a document keeps.
const MAX_ARRAY_ITEMS: usize = 32;

/// A value with this number of characters or fewer is masked only as a full word.
const MAX_BOUNDED_CHARS: usize = 5;

/// A field of an event that the builder masks or removes by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The identifier of the principal that did the activity.
    ActorId,
    /// The display name of the principal.
    ActorName,
    /// The identifier of the entity that the activity changed or accessed.
    TargetId,
    /// The display name of the target.
    TargetName,
    /// The tenant of the principal, of the target, and of the event source.
    Tenant,
    /// The identifier of the session.
    Session,
    /// The name of the connector instance that supplied the event.
    Connector,
    /// The vendor and the product that supplied the event.
    Product,
}

/// The fields and the attributes that stay in a document.
///
/// The default list keeps no [`Field`] and keeps the keys in [`DEFAULT_ATTRIBUTES`].
///
/// ```
/// use aegis_share::{AllowList, Field};
///
/// let allow = AllowList::default()
///     .with_field(Field::TargetName)
///     .with_attribute("destination_ip")
///     .without_attribute("failure_reason");
/// assert!(allow.permits_field(Field::TargetName));
/// assert!(!allow.permits_field(Field::ActorId));
/// assert!(allow.permits_attribute("destination_ip"));
/// assert!(!allow.permits_attribute("failure_reason"));
/// assert!(!allow.permits_attribute("app_id"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowList {
    /// The fields that stay as they are.
    #[serde(default)]
    fields: BTreeSet<Field>,
    /// The attribute keys that stay.
    #[serde(default = "default_attributes")]
    attributes: BTreeSet<String>,
}

fn default_attributes() -> BTreeSet<String> {
    DEFAULT_ATTRIBUTES
        .iter()
        .map(|key| (*key).to_owned())
        .collect()
}

impl Default for AllowList {
    fn default() -> Self {
        Self {
            fields: BTreeSet::new(),
            attributes: default_attributes(),
        }
    }
}

impl AllowList {
    /// Makes a list that keeps no field and no attribute.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            fields: BTreeSet::new(),
            attributes: BTreeSet::new(),
        }
    }

    /// Keeps `field` as it is.
    #[must_use]
    pub fn with_field(mut self, field: Field) -> Self {
        self.fields.insert(field);
        self
    }

    /// Keeps the attribute `key`.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>) -> Self {
        self.attributes.insert(key.into());
        self
    }

    /// Removes the attribute `key` from the list.
    #[must_use]
    pub fn without_attribute(mut self, key: &str) -> Self {
        self.attributes.remove(key);
        self
    }

    /// Returns `true` if `field` stays as it is.
    #[must_use]
    pub fn permits_field(&self, field: Field) -> bool {
        self.fields.contains(&field)
    }

    /// Returns `true` if the attribute `key` stays.
    #[must_use]
    pub fn permits_attribute(&self, key: &str) -> bool {
        self.attributes.contains(key)
    }

    /// Returns the fields that stay, in order.
    pub fn fields(&self) -> impl Iterator<Item = Field> + '_ {
        self.fields.iter().copied()
    }

    /// Returns the attribute keys that stay, in order.
    pub fn attributes(&self) -> impl Iterator<Item = &str> {
        self.attributes.iter().map(String::as_str)
    }
}

/// Finds masked values in kept text and replaces them.
#[derive(Debug)]
pub(crate) struct Redactor {
    automaton: Option<AhoCorasick>,
    /// For each pattern, `true` if a match must be a full word.
    bounded: Vec<bool>,
}

impl Redactor {
    /// Makes a redactor for a set of values. A value with one character is ignored.
    pub(crate) fn new(values: BTreeSet<String>) -> Result<Self, ShareError> {
        let patterns: Vec<String> = values
            .into_iter()
            .filter(|value| value.chars().count() >= 2)
            .collect();
        if patterns.is_empty() {
            return Ok(Self {
                automaton: None,
                bounded: Vec::new(),
            });
        }
        let bounded = patterns
            .iter()
            .map(|pattern| pattern.chars().count() <= MAX_BOUNDED_CHARS)
            .collect();
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|error| ShareError::encode("the table of masked values", error))?;
        Ok(Self {
            automaton: Some(automaton),
            bounded,
        })
    }

    /// Makes a redactor from the values that the allow list does not keep.
    pub(crate) fn for_inputs(
        incident: Option<&Incident>,
        detections: &[Detection],
        events: &[Event],
        allow: &AllowList,
    ) -> Result<Self, ShareError> {
        let mut values = BTreeSet::new();
        for event in events {
            collect_event(event, allow, &mut values);
        }
        if let Some(incident) = incident {
            if !allow.permits_field(Field::Tenant) {
                add_value(&mut values, incident.tenant.as_deref());
            }
            for entity in &incident.entities {
                collect_entity(entity, allow, &mut values);
            }
        }
        for detection in detections {
            if !allow.permits_field(Field::Tenant) {
                add_value(&mut values, detection.tenant.as_deref());
            }
            for entity in &detection.entities {
                collect_entity(entity, allow, &mut values);
            }
        }
        Self::new(values)
    }

    /// Returns `text` with each masked value replaced by [`MASK`].
    ///
    /// The comparison ignores ASCII case. A short value matches only as a full word. If
    /// the search fails, the result is only [`MASK`].
    pub(crate) fn redact(&self, text: &str) -> String {
        let Some(automaton) = &self.automaton else {
            return text.to_owned();
        };
        let Ok(matches) = automaton.try_find_overlapping_iter(text) else {
            return MASK.to_owned();
        };
        let mut spans: Vec<(usize, usize)> = matches
            .filter(|found| {
                let full_word = self
                    .bounded
                    .get(found.pattern().as_usize())
                    .copied()
                    .unwrap_or(false);
                !full_word || is_full_word(text, found.start(), found.end())
            })
            .map(|found| (found.start(), found.end()))
            .collect();
        if spans.is_empty() {
            return text.to_owned();
        }
        spans.sort_unstable();
        let mut output = String::with_capacity(text.len());
        let mut position = 0;
        let mut open: Option<(usize, usize)> = None;
        for (start, end) in spans {
            match open {
                Some((_, open_end)) if start <= open_end => {
                    open = open.map(|(open_start, _)| (open_start, open_end.max(end)));
                }
                Some((open_start, open_end)) => {
                    output.push_str(text.get(position..open_start).unwrap_or_default());
                    output.push_str(MASK);
                    position = open_end;
                    open = Some((start, end));
                }
                None => open = Some((start, end)),
            }
        }
        if let Some((open_start, open_end)) = open {
            output.push_str(text.get(position..open_start).unwrap_or_default());
            output.push_str(MASK);
            position = open_end;
        }
        output.push_str(text.get(position..).unwrap_or_default());
        output
    }
}

fn is_full_word(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).and_then(|head| head.chars().next_back());
    let after = text.get(end..).and_then(|tail| tail.chars().next());
    !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
}

fn add_value(values: &mut BTreeSet<String>, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    values.insert(value.to_owned());
    // A name such as `dana@contoso.example` also gives its two parts.
    if let Some((local, domain)) = value.split_once('@') {
        for part in [local.trim(), domain.trim()] {
            if !part.is_empty() {
                values.insert(part.to_owned());
            }
        }
    }
}

fn collect_entity(entity: &EntityRef, allow: &AllowList, values: &mut BTreeSet<String>) {
    // The addresses are the subject of the documents. The address policy controls them.
    if entity.kind == EntityKind::IpAddress {
        return;
    }
    if !(allow.permits_field(Field::ActorId) && allow.permits_field(Field::TargetId)) {
        add_value(values, Some(&entity.id));
    }
    if !(allow.permits_field(Field::ActorName) && allow.permits_field(Field::TargetName)) {
        add_value(values, entity.name.as_deref());
    }
    if !allow.permits_field(Field::Tenant) {
        add_value(values, entity.tenant.as_deref());
    }
}

fn collect_event(event: &Event, allow: &AllowList, values: &mut BTreeSet<String>) {
    if !allow.permits_field(Field::ActorId) {
        add_value(values, Some(&event.actor.id));
    }
    if !allow.permits_field(Field::ActorName) {
        add_value(values, event.actor.name.as_deref());
    }
    if !allow.permits_field(Field::Session) {
        add_value(values, event.actor.session_id.as_deref());
    }
    if !allow.permits_field(Field::Connector) {
        add_value(values, Some(&event.source.connector));
    }
    if !allow.permits_field(Field::Tenant) {
        add_value(values, event.actor.tenant.as_deref());
        add_value(values, event.source.tenant.as_deref());
    }
    if let Some(target) = &event.target {
        if !allow.permits_field(Field::TargetId) {
            add_value(values, Some(&target.id));
        }
        if !allow.permits_field(Field::TargetName) {
            add_value(values, target.name.as_deref());
        }
        if !allow.permits_field(Field::Tenant) {
            add_value(values, target.tenant.as_deref());
        }
    }
    for key in IDENTITY_ATTRIBUTES {
        if !allow.permits_attribute(key) {
            add_value(values, event.attribute_str(key));
        }
    }
}

/// Returns the action name that a document shows.
///
/// With `disclose_decoys` set to `false`, the name of a decoy action becomes a neutral
/// name. A receiver often sends an abuse report to its customer. The report must then
/// not say which service of the operator is a decoy.
pub(crate) fn shown_action(name: &str, disclose_decoys: bool) -> String {
    if !disclose_decoys {
        match name {
            action::DECOY_CONTACT | action::DECOY_CANARY_HIT => {
                return "service.contact".to_owned();
            }
            action::HONEYTOKEN_TRIP => return "secret.access".to_owned(),
            _ => {}
        }
    }
    clean(name, MAX_TOKEN_CHARS)
}

/// Makes the minimized form of events for one report.
pub(crate) struct Minimizer<'a> {
    allow: &'a AllowList,
    redactor: &'a Redactor,
    disclose_decoys: bool,
    /// The subject addresses of the report. Kept text can name them.
    subject_addresses: Vec<IpAddr>,
    labels: HashMap<(EntityKind, String), usize>,
    text_cache: HashMap<(bool, String), String>,
}

impl<'a> Minimizer<'a> {
    pub(crate) fn new(
        allow: &'a AllowList,
        redactor: &'a Redactor,
        disclose_decoys: bool,
        subject_addresses: Vec<IpAddr>,
    ) -> Self {
        Self {
            allow,
            redactor,
            disclose_decoys,
            subject_addresses,
            labels: HashMap::new(),
            text_cache: HashMap::new(),
        }
    }

    /// Returns the label of a masked entity, for example `masked-3`.
    ///
    /// The label is a counter in the order of first use. It is not a hash, so it gives no
    /// way to test a guess of the identifier.
    fn label(&mut self, kind: EntityKind, id: &str) -> String {
        let next = self.labels.len() + 1;
        let number = *self.labels.entry((kind, id.to_owned())).or_insert(next);
        format!("masked-{number}")
    }

    /// Returns free text with masked values, secrets, and other addresses replaced.
    pub(crate) fn free_text(&mut self, text: &str) -> String {
        self.cached(text, true, MAX_TEXT_CHARS)
    }

    /// Returns a user agent with masked values and secrets replaced.
    ///
    /// The address check does not run. A browser version has the form of an address.
    pub(crate) fn user_agent(&mut self, text: &str) -> String {
        self.cached(text, false, MAX_USER_AGENT_CHARS)
    }

    fn cached(&mut self, text: &str, addresses: bool, max_chars: usize) -> String {
        let key = (addresses, text.to_owned());
        if let Some(found) = self.text_cache.get(&key) {
            return found.clone();
        }
        let masked = scrub_secrets(&self.redactor.redact(text));
        let masked = if addresses {
            scrub_addresses(&masked, &self.subject_addresses)
        } else {
            masked
        };
        let result = clean(&masked, max_chars);
        self.text_cache.insert(key, result.clone());
        result
    }

    fn entity(
        &mut self,
        kind: EntityKind,
        id: &str,
        name: Option<&str>,
        tenant: Option<&str>,
        id_field: Field,
        name_field: Field,
    ) -> Value {
        let mut fields = Map::new();
        fields.insert("kind".to_owned(), Value::String(token(&kind)));
        let shown_id = if self.allow.permits_field(id_field) {
            clean(id, MAX_TOKEN_CHARS)
        } else {
            self.label(kind, id)
        };
        fields.insert("id".to_owned(), Value::String(shown_id));
        if self.allow.permits_field(name_field)
            && let Some(name) = name
        {
            fields.insert(
                "name".to_owned(),
                Value::String(clean(name, MAX_TOKEN_CHARS)),
            );
        }
        if self.allow.permits_field(Field::Tenant)
            && let Some(tenant) = tenant
        {
            fields.insert(
                "tenant".to_owned(),
                Value::String(clean(tenant, MAX_TOKEN_CHARS)),
            );
        }
        Value::Object(fields)
    }

    fn attribute(&mut self, key: &str, value: &Value) -> Option<Value> {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => Some(value.clone()),
            Value::String(text) => Some(Value::String(self.attribute_text(key, text))),
            Value::Array(items) => {
                let mut kept = Vec::with_capacity(items.len().min(MAX_ARRAY_ITEMS));
                for item in items.iter().take(MAX_ARRAY_ITEMS) {
                    match item {
                        Value::Null | Value::Bool(_) | Value::Number(_) => kept.push(item.clone()),
                        Value::String(text) => {
                            kept.push(Value::String(self.attribute_text(key, text)));
                        }
                        // A nested value can hold any data. The document does not keep it.
                        Value::Array(_) | Value::Object(_) => return None,
                    }
                }
                Some(Value::Array(kept))
            }
            Value::Object(_) => None,
        }
    }

    fn attribute_text(&mut self, key: &str, text: &str) -> String {
        if key == attr::CLIENT_FINGERPRINT {
            clean(text, MAX_TOKEN_CHARS)
        } else if key == attr::HTTP_PATH {
            self.free_text(&strip_query(text))
        } else {
            self.free_text(text)
        }
    }

    /// Returns the minimized form of one event, as the fields of a JSON object.
    pub(crate) fn event(&mut self, event: &Event) -> Map<String, Value> {
        let mut fields = Map::new();
        fields.insert("type".to_owned(), Value::String("event".to_owned()));
        fields.insert("record".to_owned(), Value::String(event.id.to_string()));
        fields.insert("time".to_owned(), Value::String(time_text(event.time)));
        fields.insert("class".to_owned(), Value::String(token(&event.class)));
        fields.insert(
            "action".to_owned(),
            Value::String(shown_action(&event.action, self.disclose_decoys)),
        );
        fields.insert("outcome".to_owned(), Value::String(token(&event.outcome)));
        if let Some(ip) = event.actor.ip {
            fields.insert(
                "source_address".to_owned(),
                Value::String(canonical_address(ip).to_string()),
            );
        }
        if let Some(user_agent) = event.actor.user_agent.as_deref() {
            let shown = self.user_agent(user_agent);
            fields.insert("user_agent".to_owned(), Value::String(shown));
        }
        let actor = self.entity(
            event.actor.kind,
            &event.actor.id,
            event.actor.name.as_deref(),
            event.actor.tenant.as_deref(),
            Field::ActorId,
            Field::ActorName,
        );
        fields.insert("actor".to_owned(), actor);
        if self.allow.permits_field(Field::Session)
            && let Some(session) = event.actor.session_id.as_deref()
        {
            fields.insert(
                "session".to_owned(),
                Value::String(clean(session, MAX_TOKEN_CHARS)),
            );
        }
        if let Some(target) = &event.target {
            let target = self.entity(
                target.kind,
                &target.id,
                target.name.as_deref(),
                target.tenant.as_deref(),
                Field::TargetId,
                Field::TargetName,
            );
            fields.insert("target".to_owned(), target);
        }

        let mut source = Map::new();
        if self.allow.permits_field(Field::Connector) {
            source.insert(
                "connector".to_owned(),
                Value::String(clean(&event.source.connector, MAX_TOKEN_CHARS)),
            );
        }
        if self.allow.permits_field(Field::Product) {
            source.insert(
                "vendor".to_owned(),
                Value::String(clean(&event.source.vendor, MAX_TOKEN_CHARS)),
            );
            source.insert(
                "product".to_owned(),
                Value::String(clean(&event.source.product, MAX_TOKEN_CHARS)),
            );
        }
        if self.allow.permits_field(Field::Tenant)
            && let Some(tenant) = event.source.tenant.as_deref()
        {
            source.insert(
                "tenant".to_owned(),
                Value::String(clean(tenant, MAX_TOKEN_CHARS)),
            );
        }
        if !source.is_empty() {
            fields.insert("source".to_owned(), Value::Object(source));
        }

        let mut attributes = BTreeMap::new();
        for (key, value) in &event.attributes {
            if self.allow.permits_attribute(key)
                && let Some(kept) = self.attribute(key, value)
            {
                attributes.insert(clean(key, MAX_TOKEN_CHARS), kept);
            }
        }
        if !attributes.is_empty() {
            fields.insert(
                "attributes".to_owned(),
                Value::Object(attributes.into_iter().collect()),
            );
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::EventId;
    use aegis_contracts::event::{Actor, EventClass, EventSource, Outcome};
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn redactor(values: &[&str]) -> Redactor {
        Redactor::new(values.iter().map(|value| (*value).to_owned()).collect()).unwrap()
    }

    fn sample_event() -> Event {
        let actor = Actor::new(EntityKind::User, "user-dana")
            .with_name("dana@contoso.example")
            .with_tenant("tenant-contoso")
            .with_ip("203.0.113.50".parse().unwrap())
            .with_user_agent("python-httpx/0.27.0")
            .with_session_id("session-77");
        Event::new(
            Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 31).unwrap(),
            EventSource::new("entra-prod", "microsoft", "entra_id").with_tenant("tenant-contoso"),
            EventClass::Authentication,
            action::SIGN_IN,
            actor,
        )
        .with_id(EventId(Uuid::from_u128(7)))
        .with_outcome(Outcome::Failure)
        .with_target(
            EntityRef::new(EntityKind::Application, "app-portal")
                .with_name("Portal")
                .with_tenant("tenant-contoso"),
        )
        .with_attribute(attr::AUTH_PROTOCOL, "ropc")
        .with_attribute(attr::ERROR_CODE, "50126")
        .with_attribute(
            attr::FAILURE_REASON,
            "Invalid password for dana@contoso.example in tenant-contoso.",
        )
        .with_attribute(attr::APP_ID, "app-portal")
        .with_attribute(attr::COUNTRY, "RO")
        .with_attribute(attr::MFA_SATISFIED, false)
        .with_raw(json!({"userPrincipalName": "dana@contoso.example", "token": "abc"}))
    }

    fn minimized(event: &Event, allow: &AllowList) -> Value {
        let redactor = Redactor::for_inputs(None, &[], std::slice::from_ref(event), allow).unwrap();
        let mut minimizer = Minimizer::new(
            allow,
            &redactor,
            false,
            vec!["203.0.113.50".parse().unwrap()],
        );
        Value::Object(minimizer.event(event))
    }

    #[test]
    fn the_default_list_keeps_no_field_and_the_default_attributes() {
        let allow = AllowList::default();
        assert_eq!(allow.fields().count(), 0);
        let kept: Vec<&str> = allow.attributes().collect();
        assert_eq!(
            kept,
            [
                "auth_protocol",
                "bytes_received",
                "client_fingerprint",
                "destination_port",
                "error_code",
                "failure_reason",
                "http_method",
                "http_path",
                "http_status",
                "operation",
                "source_port",
            ]
        );
        assert_eq!(AllowList::strict().attributes().count(), 0);
        assert_eq!(AllowList::strict().fields().count(), 0);
    }

    #[test]
    fn the_allow_list_decodes_from_json_and_rejects_unknown_keys() {
        let allow: AllowList =
            serde_json::from_str(r#"{"fields":["target_name"],"attributes":["operation"]}"#)
                .unwrap();
        assert_eq!(allow.fields().collect::<Vec<_>>(), [Field::TargetName]);
        assert_eq!(allow.attributes().collect::<Vec<_>>(), ["operation"]);
        assert_eq!(
            serde_json::from_str::<AllowList>("{}").unwrap(),
            AllowList::default()
        );
        let error = serde_json::from_str::<AllowList>(r#"{"field":[]}"#).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn a_default_event_has_labels_and_no_internal_value() {
        let value = minimized(&sample_event(), &AllowList::default());
        assert_eq!(
            value,
            json!({
                "type": "event",
                "record": "00000000-0000-0000-0000-000000000007",
                "time": "2026-11-03T09:10:31.000Z",
                "class": "authentication",
                "action": "sign_in",
                "outcome": "failure",
                "source_address": "203.0.113.50",
                "user_agent": "python-httpx/0.27.0",
                "actor": {"kind": "user", "id": "masked-1"},
                "target": {"kind": "application", "id": "masked-2"},
                "attributes": {
                    "auth_protocol": "ropc",
                    "error_code": "50126",
                    "failure_reason": "Invalid password for [masked] in [masked].",
                },
            })
        );
        let text = value.to_string();
        for hidden in [
            "user-dana",
            "dana",
            "contoso",
            "session-77",
            "entra-prod",
            "microsoft",
            "app-portal",
            "Portal",
            "userPrincipalName",
            "\"RO\"",
            "mfa_satisfied",
        ] {
            assert!(!text.contains(hidden), "{hidden} is in {text}");
        }
    }

    #[test]
    fn the_strict_list_keeps_no_attribute() {
        let value = minimized(&sample_event(), &AllowList::strict());
        assert_eq!(value.get("attributes"), None);
        assert_eq!(value["actor"], json!({"kind": "user", "id": "masked-1"}));
    }

    #[test]
    fn each_allowed_field_stays_as_it_is() {
        let allow = AllowList::default()
            .with_field(Field::ActorId)
            .with_field(Field::ActorName)
            .with_field(Field::TargetId)
            .with_field(Field::TargetName)
            .with_field(Field::Tenant)
            .with_field(Field::Session)
            .with_field(Field::Connector)
            .with_field(Field::Product)
            .with_attribute(attr::APP_ID)
            .with_attribute(attr::COUNTRY);
        let value = minimized(&sample_event(), &allow);
        assert_eq!(
            value["actor"],
            json!({
                "kind": "user",
                "id": "user-dana",
                "name": "dana@contoso.example",
                "tenant": "tenant-contoso",
            })
        );
        assert_eq!(
            value["target"],
            json!({
                "kind": "application",
                "id": "app-portal",
                "name": "Portal",
                "tenant": "tenant-contoso",
            })
        );
        assert_eq!(value["session"], json!("session-77"));
        assert_eq!(
            value["source"],
            json!({
                "connector": "entra-prod",
                "vendor": "microsoft",
                "product": "entra_id",
                "tenant": "tenant-contoso",
            })
        );
        assert_eq!(value["attributes"]["app_id"], json!("app-portal"));
        assert_eq!(value["attributes"]["country"], json!("RO"));
        assert_eq!(
            value["attributes"]["failure_reason"],
            json!("Invalid password for dana@contoso.example in tenant-contoso.")
        );
        // The original record never stays.
        assert_eq!(value.get("raw"), None);
        assert!(!value.to_string().contains("userPrincipalName"));
    }

    #[test]
    fn one_allowed_field_does_not_keep_the_others() {
        let allow = AllowList::default().with_field(Field::TargetName);
        let value = minimized(&sample_event(), &allow);
        assert_eq!(
            value["target"],
            json!({"kind": "application", "id": "masked-2", "name": "Portal"})
        );
        assert_eq!(value["actor"], json!({"kind": "user", "id": "masked-1"}));
        assert_eq!(value.get("session"), None);
        assert_eq!(value.get("source"), None);
    }

    #[test]
    fn the_same_entity_has_the_same_label_and_a_new_entity_has_the_next_label() {
        let allow = AllowList::default();
        let first = sample_event();
        let mut second = sample_event();
        second.actor.id = "user-erin".to_owned();
        // A service principal with the identifier of a user is a different entity.
        let mut third = sample_event();
        third.actor.kind = EntityKind::ServicePrincipal;
        let events = [first.clone(), second.clone(), third.clone(), first.clone()];
        let redactor = Redactor::for_inputs(None, &[], &events, &allow).unwrap();
        let mut minimizer = Minimizer::new(&allow, &redactor, false, Vec::new());
        let labels: Vec<String> = events
            .iter()
            .map(|event| {
                minimizer.event(event)["actor"]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(labels, ["masked-1", "masked-3", "masked-4", "masked-1"]);
    }

    #[test]
    fn kept_text_loses_secrets_other_addresses_and_the_query() {
        let event = sample_event()
            .with_attribute(attr::HTTP_PATH, "/t/tenant-contoso/login?password=hunter2")
            .with_attribute(attr::OPERATION, "GET /users from 10.1.2.3 and 203.0.113.50")
            .with_attribute(
                attr::FAILURE_REASON,
                "Authorization: Bearer abcDEF123456 was refused",
            )
            .with_attribute(attr::CLIENT_FINGERPRINT, "0123456789abcdef0123456789abcdef")
            .with_attribute(attr::HTTP_STATUS, 401)
            .with_attribute(attr::DESTINATION_PORT, 443);
        let value = minimized(&event, &AllowList::default());
        assert_eq!(
            value["attributes"],
            json!({
                "auth_protocol": "ropc",
                "client_fingerprint": "0123456789abcdef0123456789abcdef",
                "destination_port": 443,
                "error_code": "50126",
                "failure_reason": "Authorization: Bearer [secret removed] was refused",
                "http_path": "/t/[masked]/login?[query removed]",
                "http_status": 401,
                "operation": "GET /users from [address removed] and 203.0.113.50",
            })
        );
    }

    #[test]
    fn a_user_agent_loses_secrets_and_keeps_a_browser_version() {
        let mut event = sample_event();
        event.actor.user_agent = Some(
            "Mozilla/5.0 Chrome/120.0.0.0 key=sk-proj-0123456789abcdefghijklmnop for user-dana\u{1b}[0m"
                .to_owned(),
        );
        let value = minimized(&event, &AllowList::default());
        assert_eq!(
            value["user_agent"],
            json!("Mozilla/5.0 Chrome/120.0.0.0 key=[secret removed] for [masked]{U+001B}[0m")
        );
    }

    #[test]
    fn attribute_arrays_keep_scalars_and_nested_values_are_dropped() {
        let allow = AllowList::default()
            .with_attribute("list")
            .with_attribute("nested")
            .with_attribute("object")
            .with_attribute("long");
        let event = sample_event()
            .with_attribute("list", json!(["a", 1, true, null, "user-dana"]))
            .with_attribute("nested", json!(["a", ["b"]]))
            .with_attribute("object", json!({"user": "x"}))
            .with_attribute("long", json!((0..40).collect::<Vec<u32>>()));
        let value = minimized(&event, &allow);
        assert_eq!(
            value["attributes"]["list"],
            json!(["a", 1, true, null, "[masked]"])
        );
        assert_eq!(value["attributes"].get("nested"), None);
        assert_eq!(value["attributes"].get("object"), None);
        assert_eq!(value["attributes"]["long"].as_array().unwrap().len(), 32);
    }

    #[test]
    fn decoy_actions_get_a_neutral_name_unless_disclosed() {
        assert_eq!(
            shown_action(action::DECOY_CONTACT, false),
            "service.contact"
        );
        assert_eq!(
            shown_action(action::DECOY_CANARY_HIT, false),
            "service.contact"
        );
        assert_eq!(
            shown_action(action::HONEYTOKEN_TRIP, false),
            "secret.access"
        );
        assert_eq!(shown_action(action::DECOY_CONTACT, true), "decoy.contact");
        assert_eq!(
            shown_action(action::HONEYTOKEN_TRIP, true),
            "honeytoken.trip"
        );
        assert_eq!(shown_action(action::SIGN_IN, false), "sign_in");
        assert_eq!(shown_action("odd\naction", false), "odd{U+000A}action");
    }

    #[test]
    fn the_redactor_ignores_case_and_merges_matches_that_overlap() {
        let redactor = redactor(&["contoso.example", "dana@contoso.example", "Sync Helper"]);
        assert_eq!(
            redactor.redact("mail DANA@Contoso.Example now"),
            "mail [masked] now"
        );
        assert_eq!(
            redactor.redact("app sync helper at contoso.example."),
            "app [masked] at [masked]."
        );
        assert_eq!(redactor.redact("nothing here"), "nothing here");
        assert_eq!(redactor.redact(""), "");
    }

    #[test]
    fn a_short_value_matches_only_as_a_full_word() {
        let redactor = redactor(&["dana", "bob", "x"]);
        assert_eq!(
            redactor.redact("user dana, bob."),
            "user [masked], [masked]."
        );
        assert_eq!(redactor.redact("/home/dana/file"), "/home/[masked]/file");
        // The value is a part of a longer word. That word is a different value.
        assert_eq!(
            redactor.redact("bandana and bobsled"),
            "bandana and bobsled"
        );
        // A value with one character is ignored.
        assert_eq!(redactor.redact("x marks"), "x marks");

        let long = redactor_long();
        assert_eq!(long.redact("xtenant-contosoy"), "x[masked]y");
    }

    fn redactor_long() -> Redactor {
        redactor(&["tenant-contoso"])
    }

    #[test]
    fn an_empty_redactor_changes_nothing() {
        let redactor = redactor(&[]);
        assert_eq!(redactor.redact("user-dana"), "user-dana");
    }

    #[test]
    fn the_redactor_takes_values_from_the_incident_and_the_detections() {
        use aegis_contracts::common::{DetectionId, IncidentId, Severity};
        use aegis_contracts::detection::{DetectionTier, Verdict};
        use aegis_contracts::incident::IncidentStatus;

        let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 0).unwrap();
        let detection = Detection {
            id: DetectionId(Uuid::from_u128(1)),
            rule_id: "rule".to_owned(),
            title: "Title".to_owned(),
            description: "Text".to_owned(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time,
            attack: Vec::new(),
            event_ids: Vec::new(),
            entities: vec![
                EntityRef::new(EntityKind::Secret, "kv-prod/legacy-admin-password"),
                EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
            ],
            tenant: Some("tenant-fabrikam".to_owned()),
            attributes: BTreeMap::new(),
        };
        let incident = Incident {
            id: IncidentId(Uuid::from_u128(2)),
            title: "Title".to_owned(),
            summary: String::new(),
            severity: Severity::High,
            status: IncidentStatus::Open,
            created_at: time,
            updated_at: time,
            tenant: Some("tenant-contoso".to_owned()),
            detections: vec![detection.clone()],
            entities: vec![
                EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper")
                    .with_name("Sync Helper"),
            ],
            attack: Vec::new(),
            timeline: Vec::new(),
        };
        let redactor =
            Redactor::for_inputs(Some(&incident), &[detection], &[], &AllowList::default())
                .unwrap();
        assert_eq!(
            redactor.redact(
                "sp-sync-helper (Sync Helper) read kv-prod/legacy-admin-password in \
                 tenant-contoso and tenant-fabrikam from 203.0.113.50"
            ),
            "[masked] ([masked]) read [masked] in [masked] and [masked] from 203.0.113.50"
        );
    }
}
