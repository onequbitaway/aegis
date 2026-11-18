//! The Sigma rule engine of tier 1.
//!
//! [`SigmaRule::parse`] compiles one rule in Sigma YAML. [`SigmaDetector`] evaluates a set
//! of rules against each [`Event`].
//!
//! A rule that is not valid is an error. The error names the rule file and the cause. The
//! engine never changes such a rule to a rule that matches all events.
//!
//! # Supported parts of Sigma
//!
//! | Part | Support |
//! | --- | --- |
//! | `title` | Necessary. |
//! | `id` | Optional. The default is `sigma.` and the title in lower case with `-`. |
//! | `status` | `stable`, `test`, `experimental`. A `deprecated` or `unsupported` rule never matches. |
//! | `description` | Optional. |
//! | `level` | `informational`, `low`, `medium`, `high`, `critical`. The default is `medium`. |
//! | `tags` | `attack.t1110.003` names a technique. `attack.credential-access` names a tactic. |
//! | `logsource` | `product`, `service`, and `category`. Refer to the table below. |
//! | `detection` | Named selections and one `condition`. |
//! | `aegis.verdict` | `malicious` or `suspicious`. An AEGIS extension. |
//!
//! The engine ignores all other top-level keys, for example `author` and `references`.
//!
//! ## Log source
//!
//! | Key | The rule applies to an event if |
//! | --- | --- |
//! | `product` | the value is the product or the vendor of `Event::source` |
//! | `service` | the value is the product or the connector of `Event::source` |
//! | `category` | the value is the name of `Event::class`, for example `authentication` |
//!
//! The categories `process_creation`, `network_connection`, and `file_event` are also
//! accepted. They select the process, network, and file classes.
//!
//! ## Selections
//!
//! A selection is a map of fields, or a list of such maps. All fields of a map must match.
//! One map of a list must match. A field with a list of values matches if one value
//! matches. Text comparison ignores case. `*` matches zero or more characters and `?`
//! matches one character. Write `\*` and `\?` for the literal characters.
//!
//! | Modifier | Meaning |
//! | --- | --- |
//! | `contains`, `startswith`, `endswith` | The value is a part, the start, or the end of the text. |
//! | `re` | The value is a regular expression. It keeps the case. |
//! | `cidr` | The value is a network. The field is an address in that network. |
//! | `gt`, `gte`, `lt`, `lte` | A numeric comparison. |
//! | `exists` | With `true`, the event has the field. With `false`, it does not. |
//! | `all` | Each value of the list must match, not only one. |
//!
//! A value `null` matches a field that is absent or `null`.
//!
//! ## Fields
//!
//! | Field name | Value |
//! | --- | --- |
//! | `action`, `outcome`, `severity`, `class` | The top-level fields of the event. |
//! | `actor.id`, `actor.kind`, `actor.name`, `actor.tenant`, `actor.ip`, `actor.user_agent`, `actor.session_id` | The actor. |
//! | `target.id`, `target.kind`, `target.name`, `target.tenant` | The target. |
//! | `source.connector`, `source.vendor`, `source.product`, `source.tenant` | The source. |
//! | `attributes.<key>` | One attribute. A path such as `attributes.geo.city` goes into objects. |
//! | `raw.<path>` | A path into the original record. |
//! | any other name | The attribute with that name. `app_id` is `attributes.app_id`. |
//!
//! A field that holds a list matches if one item of the list matches.
//!
//! ## Conditions
//!
//! `and`, `or`, `not`, parentheses, `1 of selection*`, `all of selection*`, a number
//! before `of`, `1 of them`, and `all of them`. A list of conditions matches if one
//! condition matches.
//!
//! ## Parts that are not supported
//!
//! Keyword lists, aggregation (`| count()`, `timeframe`), correlation rules, and all
//! other modifiers are errors. The engine does not ignore them, because a rule that loses
//! a part can match too many events.
//!
//! ## The verdict
//!
//! The detections of a rule with the level `high` or `critical` are `malicious`. The
//! detections of all other rules are `suspicious`, and tier 2 examines them. The key
//! `aegis.verdict` replaces this default. Write it as one key or as a map:
//!
//! ```yaml
//! aegis.verdict: suspicious
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use aegis_contracts::common::Severity;
use aegis_contracts::event::{Event, EventClass};
use aegis_contracts::{AttackTechnique, Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

use self::condition::Condition;
use self::field::{FieldPath, Leaf};
use self::matcher::{Comparison, Matcher, TextMode, ValueMode};
use crate::attack::techniques_from_tags;
use crate::common::{
    EVENT_CLASSES, default_verdict, detection_id, event_entities, event_tenant, severity_from_name,
};
use crate::error::{DetectError, yaml_reason};
use crate::files::read_text;

mod condition;
mod field;
mod matcher;

/// The largest size of one rule file in bytes.
pub const MAX_RULE_BYTES: u64 = 1024 * 1024;

/// The identifier of [`SigmaDetector`].
pub const SIGMA_DETECTOR_ID: &str = "aegis.sigma";

/// The `status` of a Sigma rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigmaStatus {
    /// The rule is in production use.
    Stable,
    /// The rule is in test.
    Test,
    /// The rule is new and can give false positives.
    Experimental,
    /// A different rule replaces this rule. The rule never matches.
    Deprecated,
    /// The rule cannot operate in its current form. The rule never matches.
    Unsupported,
}

impl SigmaStatus {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "stable" => Some(Self::Stable),
            "test" => Some(Self::Test),
            "experimental" => Some(Self::Experimental),
            "deprecated" => Some(Self::Deprecated),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Sigma category names that are not the name of an [`EventClass`].
const CATEGORY_ALIASES: &[(&str, EventClass)] = &[
    ("process_creation", EventClass::ProcessActivity),
    ("network_connection", EventClass::NetworkActivity),
    ("file_event", EventClass::FileActivity),
];

#[derive(Debug, Clone, Default)]
struct LogSource {
    product: Option<String>,
    service: Option<String>,
    class: Option<EventClass>,
}

impl LogSource {
    fn matches(&self, event: &Event) -> bool {
        let source = &event.source;
        let is = |found: &str, expected: &str| found.eq_ignore_ascii_case(expected);
        self.class.is_none_or(|class| class == event.class)
            && self
                .product
                .as_deref()
                .is_none_or(|product| is(&source.product, product) || is(&source.vendor, product))
            && self.service.as_deref().is_none_or(|service| {
                is(&source.product, service) || is(&source.connector, service)
            })
    }
}

#[derive(Debug, Clone)]
enum Test {
    /// The `exists` modifier.
    Exists(bool),
    /// One of the values must match.
    Any(Vec<Matcher>),
    /// The `all` modifier: each of the values must match.
    All(Vec<Matcher>),
}

#[derive(Debug, Clone)]
struct FieldTest {
    field: FieldPath,
    test: Test,
}

impl FieldTest {
    fn value_matches(&self, matcher: &Matcher, event: &Event) -> bool {
        if matches!(matcher, Matcher::Null) {
            !self
                .field
                .any(event, &mut |leaf| !matches!(leaf, Leaf::Null))
        } else {
            self.field.any(event, &mut |leaf| matcher.matches(leaf))
        }
    }

    fn passes(&self, event: &Event) -> bool {
        match &self.test {
            Test::Exists(expected) => self.field.exists(event) == *expected,
            Test::Any(matchers) => matchers
                .iter()
                .any(|matcher| self.value_matches(matcher, event)),
            Test::All(matchers) => matchers
                .iter()
                .all(|matcher| self.value_matches(matcher, event)),
        }
    }
}

/// A named selection: one or more maps of field tests. One map must match in full.
#[derive(Debug, Clone)]
struct Selection {
    alternatives: Vec<Vec<FieldTest>>,
}

impl Selection {
    fn matches(&self, event: &Event) -> bool {
        self.alternatives
            .iter()
            .any(|tests| tests.iter().all(|test| test.passes(event)))
    }
}

/// One compiled Sigma rule.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    id: String,
    title: String,
    description: String,
    status: Option<SigmaStatus>,
    level: Severity,
    verdict: Verdict,
    tags: Vec<String>,
    attack: Vec<AttackTechnique>,
    origin: String,
    logsource: LogSource,
    selections: Vec<Selection>,
    condition: Condition,
}

impl SigmaRule {
    /// Compiles a rule from Sigma YAML.
    ///
    /// `origin` is the name of the rule file. It appears in each error.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Rule`] if the text is not YAML, if a necessary key is absent,
    /// or if the rule uses a part of Sigma that the engine does not support.
    pub fn parse(text: &str, origin: &str) -> std::result::Result<Self, DetectError> {
        let fail = |reason: String| DetectError::rule(origin, reason);
        let document: Value =
            serde_saphyr::from_str(text).map_err(|error| fail(yaml_reason(&error)))?;
        let Value::Object(rule) = document else {
            return Err(fail("the rule must be a YAML map".to_owned()));
        };
        Self::compile(&rule, origin).map_err(fail)
    }

    /// Reads and compiles one rule file.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Io`] if the file cannot be read, and [`DetectError::Rule`] if
    /// the file is larger than [`MAX_RULE_BYTES`] or the rule is not valid.
    pub fn load(path: &Path) -> std::result::Result<Self, DetectError> {
        let origin = path.display().to_string();
        let text = read_text(path, MAX_RULE_BYTES, |reason| {
            DetectError::rule(&origin, reason)
        })?;
        Self::parse(&text, &origin)
    }

    fn compile(rule: &Map<String, Value>, origin: &str) -> std::result::Result<Self, String> {
        let title = text_key(rule, "title")?
            .map(str::trim)
            .filter(|title| !title.is_empty())
            .ok_or("the rule has no title")?
            .to_owned();
        let id = match text_key(rule, "id")?.map(str::trim) {
            Some("") => return Err("the id is empty".to_owned()),
            Some(id) => id.to_owned(),
            None => format!("sigma.{}", slug(&title)),
        };
        let status = text_key(rule, "status")?
            .map(|name| {
                SigmaStatus::from_name(name).ok_or_else(|| {
                    format!(
                        "the status {name:?} is not known; use stable, test, experimental, \
                         deprecated, or unsupported"
                    )
                })
            })
            .transpose()?;
        let level = match text_key(rule, "level")? {
            Some(name) => severity_from_name(name).ok_or_else(|| {
                format!(
                    "the level {name:?} is not known; use informational, low, medium, high, \
                     or critical"
                )
            })?,
            None => Severity::Medium,
        };
        let verdict = match verdict_key(rule)? {
            Some("malicious") => Verdict::Malicious,
            Some("suspicious") => Verdict::Suspicious,
            Some(other) => {
                return Err(format!(
                    "aegis.verdict is {other:?}; use malicious or suspicious"
                ));
            }
            None => default_verdict(level),
        };
        let tags = match rule.get("tags") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
                .ok_or("tags must be a list of strings")?,
            Some(_) => return Err("tags must be a list of strings".to_owned()),
        };
        let logsource = match rule.get("logsource") {
            None | Some(Value::Null) => LogSource::default(),
            Some(Value::Object(map)) => compile_logsource(map)?,
            Some(_) => return Err("logsource must be a map".to_owned()),
        };
        let Some(Value::Object(detection)) = rule.get("detection") else {
            return Err("the rule has no detection map".to_owned());
        };
        let (names, selections) = compile_selections(detection)?;
        let condition = compile_condition(detection.get("condition"), &names)?;

        Ok(Self {
            id,
            title,
            description: text_key(rule, "description")?
                .unwrap_or_default()
                .trim()
                .to_owned(),
            status,
            level,
            verdict,
            attack: techniques_from_tags(&tags),
            tags,
            origin: origin.to_owned(),
            logsource,
            selections,
            condition,
        })
    }

    /// Returns the identifier of the rule.
    ///
    /// This is the `id` of the rule. A rule with no `id` gets `sigma.` and its title in
    /// lower case with `-` between the words.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the title of the rule.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the description of the rule.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the status of the rule, if the rule has one.
    #[must_use]
    pub fn status(&self) -> Option<SigmaStatus> {
        self.status
    }

    /// Returns the severity that the `level` of the rule gives. The default is `medium`.
    #[must_use]
    pub fn level(&self) -> Severity {
        self.level
    }

    /// Returns the verdict of the detections of this rule.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Returns the tags of the rule.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns the ATT&CK techniques that the tags name.
    #[must_use]
    pub fn attack(&self) -> &[AttackTechnique] {
        &self.attack
    }

    /// Returns the name of the file that the rule came from.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns `false` for a rule with the status `deprecated` or `unsupported`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !matches!(
            self.status,
            Some(SigmaStatus::Deprecated | SigmaStatus::Unsupported)
        )
    }

    /// Returns `true` if the rule is active and the event matches the log source and the
    /// condition of the rule.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        self.is_active()
            && self.logsource.matches(event)
            && self.condition.evaluate(&|index| {
                self.selections
                    .get(index)
                    .is_some_and(|selection| selection.matches(event))
            })
    }

    /// Returns a detection if the event matches the rule.
    #[must_use]
    pub fn detect(&self, event: &Event) -> Option<Detection> {
        if !self.matches(event) {
            return None;
        }
        let event_ids = vec![event.id];
        Some(Detection {
            id: detection_id(&self.id, &event_ids),
            rule_id: self.id.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            severity: self.level,
            verdict: self.verdict,
            tier: DetectionTier::Deterministic,
            time: event.time,
            attack: self.attack.clone(),
            event_ids,
            entities: event_entities(event),
            tenant: event_tenant(event).map(str::to_owned),
            attributes: BTreeMap::from([
                ("detector".to_owned(), json!(SIGMA_DETECTOR_ID)),
                ("action".to_owned(), json!(event.action)),
            ]),
        })
    }
}

fn text_key<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

/// Reads `aegis.verdict`, as one key or as the key `verdict` in the map `aegis`.
fn verdict_key(rule: &Map<String, Value>) -> std::result::Result<Option<&str>, String> {
    if let Some(verdict) = text_key(rule, "aegis.verdict")? {
        return Ok(Some(verdict));
    }
    match rule.get("aegis") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => match map.get("verdict") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err("aegis.verdict must be a string".to_owned()),
        },
        Some(_) => Err("aegis must be a map".to_owned()),
    }
}

fn slug(title: &str) -> String {
    let mut slug = String::with_capacity(title.len());
    for character in title.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() {
            slug.push(character);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_end_matches('-').to_owned()
}

fn class_for_category(category: &str) -> Option<EventClass> {
    EVENT_CLASSES
        .iter()
        .map(|(class, name)| (*name, *class))
        .chain(CATEGORY_ALIASES.iter().copied())
        .find(|(name, _)| name.eq_ignore_ascii_case(category))
        .map(|(_, class)| class)
}

fn compile_logsource(map: &Map<String, Value>) -> std::result::Result<LogSource, String> {
    let named = |key: &str| -> std::result::Result<Option<String>, String> {
        match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) if !text.trim().is_empty() => {
                Ok(Some(text.trim().to_owned()))
            }
            Some(_) => Err(format!(
                "logsource.{key} must be a string that is not empty"
            )),
        }
    };
    let class = named("category")?
        .map(|category| {
            class_for_category(&category).ok_or_else(|| {
                let known: Vec<&str> = EVENT_CLASSES.iter().map(|(_, name)| *name).collect();
                format!(
                    "the logsource category {category:?} is not known; the categories are {}",
                    known.join(", ")
                )
            })
        })
        .transpose()?;
    Ok(LogSource {
        product: named("product")?,
        service: named("service")?,
        class,
    })
}

const MODIFIERS: &str = "contains, startswith, endswith, re, cidr, all, gt, gte, lt, lte, exists";

fn compile_field_test(key: &str, value: &Value) -> std::result::Result<FieldTest, String> {
    let mut parts = key.split('|');
    let name = parts.next().unwrap_or_default().trim();
    let field = FieldPath::parse(name)?;

    let mut mode: Option<ValueMode> = None;
    let mut all = false;
    let mut exists = false;
    for modifier in parts {
        let selected = match modifier.trim() {
            "contains" => ValueMode::Text(TextMode::Contains),
            "startswith" => ValueMode::Text(TextMode::StartsWith),
            "endswith" => ValueMode::Text(TextMode::EndsWith),
            "re" => ValueMode::Regex,
            "cidr" => ValueMode::Cidr,
            "gt" => ValueMode::Compare(Comparison::Greater),
            "gte" => ValueMode::Compare(Comparison::GreaterOrEqual),
            "lt" => ValueMode::Compare(Comparison::Less),
            "lte" => ValueMode::Compare(Comparison::LessOrEqual),
            "all" if !all => {
                all = true;
                continue;
            }
            "exists" if !exists => {
                exists = true;
                continue;
            }
            "all" | "exists" => {
                return Err(format!(
                    "the field {name:?} has the modifier {modifier:?} two times"
                ));
            }
            other => {
                return Err(format!(
                    "the field {name:?} has the modifier {other:?}, which is not supported; \
                     the modifiers are {MODIFIERS}"
                ));
            }
        };
        if mode.replace(selected).is_some() {
            return Err(format!(
                "the field {name:?} has more than one of the modifiers contains, startswith, \
                 endswith, re, cidr, gt, gte, lt, and lte"
            ));
        }
    }

    if exists {
        if mode.is_some() || all {
            return Err(format!(
                "the field {name:?} has the modifier exists with a different modifier"
            ));
        }
        let Value::Bool(expected) = value else {
            return Err(format!(
                "the field {name:?} with exists needs true or false"
            ));
        };
        return Ok(FieldTest {
            field,
            test: Test::Exists(*expected),
        });
    }

    let mode = mode.unwrap_or(ValueMode::Text(TextMode::Equals));
    let values: &[Value] = match value {
        Value::Array(items) if items.is_empty() => {
            return Err(format!("the field {name:?} has an empty list of values"));
        }
        Value::Array(items) => items,
        single => std::slice::from_ref(single),
    };
    let matchers = values
        .iter()
        .map(|value| Matcher::new(value, mode))
        .collect::<std::result::Result<Vec<Matcher>, String>>()
        .map_err(|reason| format!("the field {name:?}: {reason}"))?;
    Ok(FieldTest {
        field,
        test: if all {
            Test::All(matchers)
        } else {
            Test::Any(matchers)
        },
    })
}

fn compile_field_map(
    name: &str,
    map: &Map<String, Value>,
) -> std::result::Result<Vec<FieldTest>, String> {
    if map.is_empty() {
        return Err(format!(
            "the selection {name:?} has an empty map, which would match all events"
        ));
    }
    map.iter()
        .map(|(key, value)| compile_field_test(key, value))
        .collect::<std::result::Result<Vec<FieldTest>, String>>()
        .map_err(|reason| format!("the selection {name:?}: {reason}"))
}

fn compile_selections(
    detection: &Map<String, Value>,
) -> std::result::Result<(Vec<String>, Vec<Selection>), String> {
    let mut names = Vec::new();
    let mut selections = Vec::new();
    for (name, value) in detection {
        if name == "condition" {
            continue;
        }
        if name == "timeframe" {
            return Err("the detection has a timeframe; aggregation is not supported".to_owned());
        }
        if condition::is_reserved(name)
            || name.is_empty()
            || name.contains(|character: char| {
                character.is_whitespace() || matches!(character, '(' | ')' | '|' | '*' | '?')
            })
        {
            return Err(format!("{name:?} is not a valid name for a selection"));
        }
        let alternatives = match value {
            Value::Object(map) => vec![compile_field_map(name, map)?],
            Value::Array(items) if items.is_empty() => {
                return Err(format!("the selection {name:?} is an empty list"));
            }
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::Object(map) => compile_field_map(name, map),
                    _ => Err(format!(
                        "the selection {name:?} is a list of keywords; use a list of maps"
                    )),
                })
                .collect::<std::result::Result<Vec<_>, String>>()?,
            _ => {
                return Err(format!(
                    "the selection {name:?} must be a map or a list of maps"
                ));
            }
        };
        names.push(name.clone());
        selections.push(Selection { alternatives });
    }
    if selections.is_empty() {
        return Err("the detection has no selection".to_owned());
    }
    Ok((names, selections))
}

fn compile_condition(
    value: Option<&Value>,
    names: &[String],
) -> std::result::Result<Condition, String> {
    match value {
        Some(Value::String(text)) => condition::parse(text, names),
        Some(Value::Array(items)) if !items.is_empty() => {
            let parts = items
                .iter()
                .map(|item| match item {
                    Value::String(text) => condition::parse(text, names),
                    _ => Err("the condition must be a string or a list of strings".to_owned()),
                })
                .collect::<std::result::Result<Vec<Condition>, String>>()?;
            Ok(Condition::Or(parts))
        }
        Some(_) => Err("the condition must be a string or a list of strings".to_owned()),
        None => Err("the detection has no condition".to_owned()),
    }
}

/// A detector that evaluates a set of Sigma rules against each event.
///
/// The detector keeps no state between events.
#[derive(Debug, Clone, Default)]
pub struct SigmaDetector {
    rules: Vec<SigmaRule>,
}

impl SigmaDetector {
    /// Makes a detector for `rules`. The detections keep the order of the rules.
    #[must_use]
    pub fn new(rules: Vec<SigmaRule>) -> Self {
        Self { rules }
    }

    /// Returns the rules of the detector.
    #[must_use]
    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    /// Evaluates each rule against the event. Returns one detection for each rule that
    /// matches.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Vec<Detection> {
        self.rules
            .iter()
            .filter_map(|rule| rule.detect(event))
            .collect()
    }
}

#[async_trait]
impl Detector for SigmaDetector {
    fn id(&self) -> &str {
        SIGMA_DETECTOR_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        Ok(self.evaluate(event))
    }
}

#[cfg(test)]
mod tests;
