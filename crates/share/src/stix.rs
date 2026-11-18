//! The STIX 2.1 form of an indicator set.
//!
//! [`IndicatorSet::to_stix`] makes a STIX 2.1 bundle. The bundle has:
//!
//! - the marking definition of the TLP level that the caller selects;
//! - one `identity` object for the producer, if the options name one;
//! - one `indicator` object for each indicator.
//!
//! # Identifiers
//!
//! The identifiers are stable. The same indicator set and the same options always give
//! the same bundle. Each identifier is a version 5 UUID in the namespace of the options.
//! The name of the UUID is the type and the pattern of the object. STIX forbids the
//! namespace of the cyber-observable objects for this use, so the options reject it.
//!
//! # Patterns
//!
//! | Indicator | Pattern |
//! | --- | --- |
//! | IPv4 address | `[ipv4-addr:value = '203.0.113.50']` |
//! | IPv6 address | `[ipv6-addr:value = '2001:db8::1']` |
//! | Domain | `[domain-name:value = 'bad.example']` |
//! | User agent | `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'curl/8.4.0']` |
//!
//! In a pattern string, a backslash comes before each apostrophe and each backslash.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::error::ShareError;
use crate::indicator::{Indicator, IndicatorBasis, IndicatorKind, IndicatorSet};
use crate::text::{json_pretty, time_text};

/// The default namespace of the object identifiers.
///
/// An operator that wants identifiers of its own sets a different namespace in
/// [`StixOptions`]. Two operators with the same namespace give the same identifier to the
/// same pattern.
pub const DEFAULT_NAMESPACE: Uuid = Uuid::from_u128(0x4364_9b42_ff78_4a03_a600_4424_29b7_9dce);

/// The namespace that STIX keeps for cyber-observable objects. Other objects must not
/// use it.
const OBSERVABLE_NAMESPACE: Uuid = Uuid::from_u128(0x00ab_edb4_aa42_466c_9c01_fed2_3315_a9b7);

/// The default time after the last evidence at which an indicator stops being valid.
pub const DEFAULT_VALID_DAYS: i64 = 30;

/// The time of the TLP marking definitions in the STIX 2.1 specification.
const TLP_CREATED: &str = "2017-01-20T00:00:00.000Z";

/// A Traffic Light Protocol level. The level says how far the receiver can share the data.
///
/// STIX 2.1 defines one marking for each of these four levels. `White` is the level that
/// TLP 2.0 names `CLEAR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    /// No limit on disclosure.
    White,
    /// Disclosure in the community of the receiver.
    Green,
    /// Disclosure in the organization of the receiver, and to its clients if they must know.
    Amber,
    /// No disclosure outside the named receivers.
    Red,
}

impl Tlp {
    /// Returns the label of the level, for example `TLP:AMBER`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::White => "TLP:WHITE",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::Red => "TLP:RED",
        }
    }

    fn level(self) -> &'static str {
        match self {
            Self::White => "white",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
        }
    }

    /// Returns the identifier of the marking definition that STIX 2.1 gives to the level.
    #[must_use]
    pub fn marking_id(self) -> &'static str {
        match self {
            Self::White => "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            Self::Green => "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            Self::Amber => "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            Self::Red => "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        }
    }

    /// Returns the marking definition object, as the STIX 2.1 specification gives it.
    #[must_use]
    pub fn marking_definition(self) -> Value {
        json!({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": self.marking_id(),
            "created": TLP_CREATED,
            "definition_type": "tlp",
            "name": self.label(),
            "definition": { "tlp": self.level() },
        })
    }
}

/// The options of [`IndicatorSet::to_stix`].
///
/// There is no default TLP level. The caller must select one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixOptions {
    /// The TLP level of all indicators in the bundle.
    pub tlp: Tlp,
    /// The time of the export. It becomes `created` and `modified` of each object. The
    /// export does not read the clock, so that the same input gives the same bundle.
    pub generated_at: DateTime<Utc>,
    /// The namespace of the object identifiers.
    pub namespace: Uuid,
    /// The time after the last evidence at which an indicator stops being valid. With
    /// `None`, an indicator has no end. An address can get a new user, so set an end.
    pub valid_for: Option<TimeDelta>,
    /// The name of the producer. With a name, the bundle has an `identity` object. The
    /// default gives no name.
    pub producer: Option<String>,
}

impl StixOptions {
    /// Makes options with the default namespace, an end after [`DEFAULT_VALID_DAYS`]
    /// days, and no producer.
    #[must_use]
    pub fn new(tlp: Tlp, generated_at: DateTime<Utc>) -> Self {
        Self {
            tlp,
            generated_at,
            namespace: DEFAULT_NAMESPACE,
            valid_for: Some(TimeDelta::days(DEFAULT_VALID_DAYS)),
            producer: None,
        }
    }

    /// Sets the namespace of the object identifiers.
    #[must_use]
    pub fn with_namespace(mut self, namespace: Uuid) -> Self {
        self.namespace = namespace;
        self
    }

    /// Sets the time after the last evidence at which an indicator stops being valid.
    #[must_use]
    pub fn with_valid_for(mut self, valid_for: Option<TimeDelta>) -> Self {
        self.valid_for = valid_for;
        self
    }

    /// Sets the name of the producer.
    #[must_use]
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = Some(producer.into());
        self
    }

    fn validate(&self) -> Result<(), ShareError> {
        if self.namespace == OBSERVABLE_NAMESPACE || self.namespace.is_nil() {
            return Err(ShareError::option(
                "namespace",
                "the value must not be nil or the STIX namespace of cyber-observable objects",
            ));
        }
        if self
            .valid_for
            .is_some_and(|valid_for| valid_for <= TimeDelta::zero())
        {
            return Err(ShareError::option(
                "valid_for",
                "the value must be more than zero",
            ));
        }
        if let Some(producer) = &self.producer
            && (producer.trim().is_empty() || producer.chars().any(crate::text::is_unsafe_char))
        {
            return Err(ShareError::option(
                "producer",
                "the name must not be empty and must not have control characters",
            ));
        }
        Ok(())
    }

    fn id(&self, kind: &str, name: &str) -> String {
        let uuid = Uuid::new_v5(&self.namespace, format!("{kind}:{name}").as_bytes());
        format!("{kind}--{uuid}")
    }
}

/// Returns `text` as a string constant of the STIX pattern language.
fn pattern_string(text: &str) -> String {
    let mut constant = String::with_capacity(text.len() + 2);
    constant.push('\'');
    for character in text.chars() {
        if matches!(character, '\'' | '\\') {
            constant.push('\\');
        }
        constant.push(character);
    }
    constant.push('\'');
    constant
}

/// Returns the STIX pattern of an indicator.
#[must_use]
pub fn stix_pattern(kind: IndicatorKind, value: &str) -> String {
    let path = match kind {
        IndicatorKind::Ipv4 => "ipv4-addr:value",
        IndicatorKind::Ipv6 => "ipv6-addr:value",
        IndicatorKind::Domain => "domain-name:value",
        IndicatorKind::UserAgent => {
            "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"
        }
    };
    format!("[{path} = {}]", pattern_string(value))
}

fn indicator_name(indicator: &Indicator) -> String {
    let label = match indicator.kind {
        IndicatorKind::Ipv4 => "IPv4 address",
        IndicatorKind::Ipv6 => "IPv6 address",
        IndicatorKind::Domain => "Domain",
        IndicatorKind::UserAgent => "User agent",
    };
    format!("{label} {}", indicator.value)
}

fn indicator_description(indicator: &Indicator) -> String {
    let basis = match indicator.basis {
        IndicatorBasis::MaliciousActivity => {
            "The producer saw this value in activity that its detection rules classified as \
             malicious, or in the use of a decoy credential."
        }
        IndicatorBasis::AnomalousActivity => {
            "The producer saw this value in contacts with a decoy, or in activity that its \
             detection rules classified as suspicious."
        }
    };
    format!(
        "{basis} Log records: {}. Detections: {}. The data does not identify a person or a group.",
        indicator.events, indicator.detections
    )
}

fn indicator_object(
    indicator: &Indicator,
    options: &StixOptions,
    created: &str,
    producer_id: Option<&str>,
) -> Value {
    let pattern = stix_pattern(indicator.kind, &indicator.value);
    let mut object = Map::new();
    object.insert("type".to_owned(), json!("indicator"));
    object.insert("spec_version".to_owned(), json!("2.1"));
    object.insert("id".to_owned(), json!(options.id("indicator", &pattern)));
    object.insert("created".to_owned(), json!(created));
    object.insert("modified".to_owned(), json!(created));
    if let Some(producer_id) = producer_id {
        object.insert("created_by_ref".to_owned(), json!(producer_id));
    }
    object.insert("name".to_owned(), json!(indicator_name(indicator)));
    object.insert(
        "description".to_owned(),
        json!(indicator_description(indicator)),
    );
    object.insert(
        "indicator_types".to_owned(),
        json!([indicator.basis.stix_type()]),
    );
    object.insert("pattern".to_owned(), json!(pattern));
    object.insert("pattern_type".to_owned(), json!("stix"));
    object.insert("pattern_version".to_owned(), json!("2.1"));
    object.insert(
        "valid_from".to_owned(),
        json!(time_text(indicator.first_seen)),
    );
    let valid_until = options
        .valid_for
        .and_then(|valid_for| indicator.last_seen.checked_add_signed(valid_for))
        .filter(|until| *until > indicator.first_seen);
    if let Some(until) = valid_until {
        object.insert("valid_until".to_owned(), json!(time_text(until)));
    }
    let mut phases: Vec<&str> = indicator
        .techniques
        .iter()
        .flat_map(|technique| technique.tactics.iter().map(String::as_str))
        .collect();
    phases.sort_unstable();
    phases.dedup();
    if !phases.is_empty() {
        let phases: Vec<Value> = phases
            .into_iter()
            .map(|phase| json!({"kill_chain_name": "mitre-attack", "phase_name": phase}))
            .collect();
        object.insert("kill_chain_phases".to_owned(), Value::Array(phases));
    }
    if !indicator.techniques.is_empty() {
        let references: Vec<Value> = indicator
            .techniques
            .iter()
            .map(|technique| {
                json!({
                    "source_name": "mitre-attack",
                    "external_id": technique.id,
                    "url": technique.url,
                })
            })
            .collect();
        object.insert("external_references".to_owned(), Value::Array(references));
    }
    object.insert(
        "object_marking_refs".to_owned(),
        json!([options.tlp.marking_id()]),
    );
    Value::Object(object)
}

impl IndicatorSet {
    /// Returns the indicators as a STIX 2.1 bundle.
    ///
    /// The objects are in this order: the TLP marking definition, the identity of the
    /// producer if the options name one, then the indicators.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::InvalidOption`] if:
    ///
    /// - the namespace is nil, or is the STIX namespace of cyber-observable objects;
    /// - `valid_for` is not more than zero;
    /// - the producer name is empty or has control characters.
    pub fn to_stix(&self, options: &StixOptions) -> Result<Value, ShareError> {
        options.validate()?;
        let created = time_text(options.generated_at);
        let mut objects: Vec<Value> = vec![options.tlp.marking_definition()];
        let producer_id = options.producer.as_deref().map(|name| {
            let id = options.id("identity", name.trim());
            objects.push(json!({
                "type": "identity",
                "spec_version": "2.1",
                "id": id,
                "created": created,
                "modified": created,
                "name": name.trim(),
                "identity_class": "organization",
                "object_marking_refs": [options.tlp.marking_id()],
            }));
            id
        });
        objects.extend(self.indicators.iter().map(|indicator| {
            indicator_object(indicator, options, &created, producer_id.as_deref())
        }));
        let member_ids: Vec<&str> = objects
            .iter()
            .filter_map(|object| object.get("id").and_then(Value::as_str))
            .collect();
        let bundle_id = options.id(
            "bundle",
            &format!("{created}:{}:{}", options.tlp.label(), member_ids.join(",")),
        );
        Ok(json!({
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }))
    }

    /// Returns the STIX 2.1 bundle as JSON text in printable ASCII.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`to_stix`](Self::to_stix).
    pub fn to_stix_string(&self, options: &StixOptions) -> Result<String, ShareError> {
        Ok(json_pretty(&self.to_stix(options)?))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn a_pattern_string_has_a_backslash_before_an_apostrophe_and_a_backslash() {
        assert_eq!(pattern_string("plain"), "'plain'");
        assert_eq!(pattern_string("it's"), "'it\\'s'");
        assert_eq!(pattern_string("C:\\tool"), "'C:\\\\tool'");
        assert_eq!(pattern_string("'] OR [x:y = '"), "'\\'] OR [x:y = \\''");
        assert_eq!(pattern_string(""), "''");
    }

    #[test]
    fn each_indicator_type_has_its_pattern() {
        assert_eq!(
            stix_pattern(IndicatorKind::Ipv4, "203.0.113.50"),
            "[ipv4-addr:value = '203.0.113.50']"
        );
        assert_eq!(
            stix_pattern(IndicatorKind::Ipv6, "2001:db8::1"),
            "[ipv6-addr:value = '2001:db8::1']"
        );
        assert_eq!(
            stix_pattern(IndicatorKind::Domain, "bad.example"),
            "[domain-name:value = 'bad.example']"
        );
        assert_eq!(
            stix_pattern(IndicatorKind::UserAgent, "curl/8.4.0"),
            "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'curl/8.4.0']"
        );
    }

    #[test]
    fn the_tlp_markings_are_the_objects_of_the_specification() {
        assert_eq!(
            Tlp::White.marking_definition(),
            json!({
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": "TLP:WHITE",
                "definition": {"tlp": "white"},
            })
        );
        assert_eq!(
            Tlp::Green.marking_id(),
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        );
        assert_eq!(
            Tlp::Amber.marking_id(),
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        );
        assert_eq!(
            Tlp::Red.marking_id(),
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
        );
        assert_eq!(
            Tlp::Amber.marking_definition()["definition"]["tlp"],
            "amber"
        );
        assert_eq!(Tlp::Red.marking_definition()["name"], "TLP:RED");
        assert_eq!(Tlp::Green.label(), "TLP:GREEN");
    }

    #[test]
    fn options_that_break_the_format_are_rejected() {
        let time = Utc.with_ymd_and_hms(2026, 11, 3, 10, 0, 0).unwrap();
        let set = IndicatorSet {
            indicators: Vec::new(),
            skipped: Vec::new(),
        };
        let check = |options: StixOptions, name: &str| {
            let error = set.to_stix(&options).unwrap_err();
            assert!(
                matches!(&error, ShareError::InvalidOption { name: found, .. } if *found == name),
                "{error}"
            );
        };
        check(
            StixOptions::new(Tlp::Green, time).with_namespace(OBSERVABLE_NAMESPACE),
            "namespace",
        );
        check(
            StixOptions::new(Tlp::Green, time).with_namespace(Uuid::nil()),
            "namespace",
        );
        check(
            StixOptions::new(Tlp::Green, time).with_valid_for(Some(TimeDelta::zero())),
            "valid_for",
        );
        check(
            StixOptions::new(Tlp::Green, time).with_valid_for(Some(TimeDelta::seconds(-1))),
            "valid_for",
        );
        check(
            StixOptions::new(Tlp::Green, time).with_producer("  "),
            "producer",
        );
        check(
            StixOptions::new(Tlp::Green, time).with_producer("Name\u{1b}[0m"),
            "producer",
        );
        assert!(set.to_stix(&StixOptions::new(Tlp::Green, time)).is_ok());
    }

    #[test]
    fn the_default_namespace_is_the_documented_value() {
        assert_eq!(
            DEFAULT_NAMESPACE.to_string(),
            "43649b42-ff78-4a03-a600-442429b79dce"
        );
        assert_eq!(
            OBSERVABLE_NAMESPACE.to_string(),
            "00abedb4-aa42-466c-9c01-fed23315a9b7"
        );
    }
}
