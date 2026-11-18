//! The suppression settings of a rule: the key `aegis.suppress`.

use aegis_contracts::Verdict;
use aegis_contracts::common::Severity;
use aegis_contracts::event::Event;
use serde_json::{Map, Value};

use super::field::{FieldPath, Leaf};
use crate::common::{canonical_ip, default_verdict, severity_from_name};

/// The largest number of key fields in `aegis.suppress`.
pub const MAX_SUPPRESSION_FIELDS: usize = 8;

/// The largest value of `window_seconds` in `aegis.suppress`: 30 days.
pub const MAX_SUPPRESSION_WINDOW_SECONDS: u64 = 30 * 24 * 3_600;

/// The detection for a rule that matches many times for one key in one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repeat {
    /// The number of matches in one window that gives the detection.
    pub count: u64,
    /// The severity of the detection.
    pub level: Severity,
    /// The verdict of the detection.
    pub verdict: Verdict,
}

/// The suppression settings of one rule: the key `aegis.suppress`.
///
/// With these settings, the rule and one key give ONE detection in a window. The engine
/// counts each later match in the window and makes no detection for it.
///
/// ```yaml
/// aegis.suppress:
///   window_seconds: 600
///   fields: [actor.ip, client_fingerprint]   # optional
///   repeat:                                  # optional
///     count: 10
///     level: high
/// ```
///
/// - `window_seconds` is the length of the window. The window starts with the first match.
/// - `fields` are the event fields that make the key, with the names that selections
///   use. Without `fields`, the key is the entities of the detection.
/// - `repeat` gives one more detection when the count of matches in the window reaches
///   `count`. Its severity is `level` (the default is `high`). Its verdict comes from the
///   level, or from the key `verdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    fields: Vec<(String, FieldPath)>,
    window_seconds: u64,
    repeat: Option<Repeat>,
}

fn count_key(map: &Map<String, Value>, key: &str, least: u64) -> Result<Option<u64>, String> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|count| *count >= least)
            .map(Some)
            .ok_or_else(|| {
                format!("aegis.suppress: {key} must be a whole number of {least} or more")
            }),
    }
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    known: &[&str],
    place: &str,
) -> Result<(), String> {
    match map.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "{place} has the key {key:?}, which is not known; the keys are {}",
            known.join(", ")
        )),
        None => Ok(()),
    }
}

impl Suppression {
    /// Reads the value of `aegis.suppress`.
    pub(super) fn compile(value: &Value) -> Result<Self, String> {
        let Value::Object(map) = value else {
            return Err("aegis.suppress must be a map".to_owned());
        };
        reject_unknown_keys(
            map,
            &["window_seconds", "fields", "repeat"],
            "aegis.suppress",
        )?;
        let window_seconds =
            count_key(map, "window_seconds", 1)?.ok_or("aegis.suppress has no window_seconds")?;
        if window_seconds > MAX_SUPPRESSION_WINDOW_SECONDS {
            return Err(format!(
                "aegis.suppress: window_seconds must be {MAX_SUPPRESSION_WINDOW_SECONDS} or \
                 less, but it is {window_seconds}"
            ));
        }
        let fields = match map.get("fields") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) if !items.is_empty() => {
                if items.len() > MAX_SUPPRESSION_FIELDS {
                    return Err(format!(
                        "aegis.suppress: fields has {} names; the limit is \
                         {MAX_SUPPRESSION_FIELDS}",
                        items.len()
                    ));
                }
                items
                    .iter()
                    .map(|item| {
                        let name = item
                            .as_str()
                            .ok_or("aegis.suppress: fields must be a list of field names")?;
                        let path = FieldPath::parse(name.trim())
                            .map_err(|reason| format!("aegis.suppress: {reason}"))?;
                        Ok((name.trim().to_owned(), path))
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
            Some(_) => {
                return Err(
                    "aegis.suppress: fields must be a list of field names that is not empty; \
                     omit the key to use the entities of the detection"
                        .to_owned(),
                );
            }
        };
        let repeat = match map.get("repeat") {
            None | Some(Value::Null) => None,
            Some(Value::Object(repeat)) => {
                reject_unknown_keys(
                    repeat,
                    &["count", "level", "verdict"],
                    "aegis.suppress.repeat",
                )?;
                let count =
                    count_key(repeat, "count", 2)?.ok_or("aegis.suppress.repeat has no count")?;
                let level = match repeat.get("level") {
                    None | Some(Value::Null) => Severity::High,
                    Some(Value::String(name)) => severity_from_name(name).ok_or_else(|| {
                        format!(
                            "aegis.suppress.repeat: the level {name:?} is not known; use \
                             informational, low, medium, high, or critical"
                        )
                    })?,
                    Some(_) => {
                        return Err("aegis.suppress.repeat: level must be a string".to_owned());
                    }
                };
                let verdict = match repeat.get("verdict") {
                    None | Some(Value::Null) => default_verdict(level),
                    Some(Value::String(name)) if name == "malicious" => Verdict::Malicious,
                    Some(Value::String(name)) if name == "suspicious" => Verdict::Suspicious,
                    Some(_) => {
                        return Err(
                            "aegis.suppress.repeat: verdict must be malicious or suspicious"
                                .to_owned(),
                        );
                    }
                };
                Some(Repeat {
                    count,
                    level,
                    verdict,
                })
            }
            Some(_) => return Err("aegis.suppress: repeat must be a map".to_owned()),
        };
        Ok(Self {
            fields,
            window_seconds,
            repeat,
        })
    }

    /// Returns the length of the window in seconds.
    #[must_use]
    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// Returns the names of the key fields. An empty list means the entities of the
    /// detection.
    pub fn fields(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(name, _)| name.as_str())
    }

    /// Returns the settings of the detection for many matches, if the rule has them.
    #[must_use]
    pub fn repeat(&self) -> Option<Repeat> {
        self.repeat
    }

    /// Returns the values of the key fields of an event, one text for each field.
    ///
    /// Returns `None` if the rule names no field. Text is in lower case. A field with more
    /// than one value gives all its values. A field that the event does not have gives an
    /// empty text.
    #[must_use]
    pub fn key(&self, event: &Event) -> Option<Vec<String>> {
        if self.fields.is_empty() {
            return None;
        }
        let parts = self
            .fields
            .iter()
            .map(|(_, path)| {
                let mut values: Vec<String> = Vec::new();
                path.any(event, &mut |leaf| {
                    values.push(match leaf {
                        Leaf::Null => "null".to_owned(),
                        Leaf::Bool(flag) => flag.to_string(),
                        Leaf::Number(number) => number.to_string(),
                        Leaf::Text(text) => text.to_lowercase(),
                        Leaf::Ip(ip) => canonical_ip(ip).to_string(),
                        Leaf::Structure => "{}".to_owned(),
                    });
                    false
                });
                // The separator is a control character, which a field value rarely has.
                values.join("\u{1f}")
            })
            .collect();
        Some(parts)
    }
}
