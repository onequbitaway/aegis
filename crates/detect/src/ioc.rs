//! The indicator matcher of tier 1.
//!
//! An [`IocStore`] holds indicators of compromise: IP addresses and networks, DNS domains,
//! user agents, application identifiers, and client fingerprints. The store is a
//! [`Detector`]. It returns one detection for each indicator that an event matches.
//!
//! Each lookup is a hash lookup or a prefix lookup. The cost for one event does not grow
//! with the number of indicators.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{Event, attr};
use aegis_contracts::{AttackTechnique, Detection, DetectionTier, Detector, Result, Verdict};
use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::attack::techniques_from_tags;
use crate::common::{
    CLIENT_FINGERPRINT_PREFIX, canonical_ip, default_verdict, detection_id, event_entities,
    event_tenant, fingerprint_token, ip_entity, push_entity,
};
use crate::error::{DetectError, yaml_reason};
use crate::files::read_text;

/// The identifier of the [`IocStore`] detector.
pub const IOC_DETECTOR_ID: &str = "aegis.ioc";

/// The largest size of one indicator file in bytes.
pub const MAX_INDICATOR_BYTES: u64 = 16 * 1024 * 1024;

/// The smallest length of a user agent indicator. A shorter text matches too many clients.
pub const MIN_USER_AGENT_LENGTH: usize = 4;

/// The longest DNS name that the store looks up. A longer text is not a DNS name.
const MAX_DOMAIN_LENGTH: usize = 253;

/// The number of bytes of a user agent that the store examines.
const MAX_USER_AGENT_BYTES: usize = 8 * 1024;

/// The number of characters of an event value that a detection keeps.
const MAX_MATCHED_VALUE_CHARS: usize = 256;

/// The type of an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// An IP address, or a network in CIDR form.
    #[serde(alias = "cidr", alias = "ip_address")]
    Ip,
    /// A DNS domain. The indicator also matches each subdomain.
    Domain,
    /// A part of a user agent. The comparison ignores ASCII case.
    UserAgent,
    /// An application (client) identifier. The comparison ignores case.
    AppId,
    /// A client fingerprint: the attribute `client_fingerprint` of an event. The
    /// comparison ignores ASCII case.
    ClientFingerprint,
}

impl IndicatorKind {
    /// Returns the name of the type, as an indicator file writes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::UserAgent => "user_agent",
            Self::AppId => "app_id",
            Self::ClientFingerprint => "client_fingerprint",
        }
    }
}

/// One indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    /// The type of the indicator.
    #[serde(rename = "type")]
    pub kind: IndicatorKind,
    /// The value: an address, a network, a domain, a part of a user agent, an application
    /// identifier, or a client fingerprint.
    pub value: String,
    /// What the indicator shows, and where it comes from.
    pub description: String,
    /// The severity of a match.
    pub severity: Severity,
    /// Sigma tags, for example `attack.command-and-control` and `attack.t1071.001`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The verdict of a match. The default is `malicious` for the severities `high` and
    /// `critical`, and `suspicious` for all others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// The rule identifier of a match. The default is `ioc:{type}:{value}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The time at which the source saw the value for the first time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    /// The time at which the source saw the value for the last time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    /// A note that says where the indicator comes from, for example `aegis decoy export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The time in seconds in which the engine makes one detection for this indicator,
    /// one matched value, and one actor. The engine counts the other matches. With no
    /// value, each event that matches gives a detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppress_seconds: Option<u64>,
}

impl Indicator {
    /// Makes an indicator with the necessary fields. All other fields are empty.
    pub fn new(
        kind: IndicatorKind,
        value: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            kind,
            value: value.into(),
            description: description.into(),
            severity,
            tags: Vec::new(),
            verdict: None,
            id: None,
            first_seen: None,
            last_seen: None,
            source: None,
            suppress_seconds: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndicatorFile {
    indicators: Vec<Indicator>,
}

/// Writes indicators as the YAML text of an indicator file.
///
/// [`indicators_from_yaml`] reads the text again.
///
/// # Errors
///
/// Returns [`DetectError::Indicator`] with the file name `origin` if the indicators cannot
/// be written as YAML.
pub fn indicators_to_yaml(
    indicators: &[Indicator],
    origin: &str,
) -> std::result::Result<String, DetectError> {
    let file = IndicatorFile {
        indicators: indicators.to_vec(),
    };
    serde_saphyr::to_string(&file)
        .map_err(|error| DetectError::indicator(origin, format!("cannot write YAML: {error}")))
}

/// Writes indicators as the JSON text of an indicator file.
///
/// [`indicators_from_json`] reads the text again.
///
/// # Errors
///
/// Returns [`DetectError::Indicator`] with the file name `origin` if the indicators cannot
/// be written as JSON.
pub fn indicators_to_json(
    indicators: &[Indicator],
    origin: &str,
) -> std::result::Result<String, DetectError> {
    let file = IndicatorFile {
        indicators: indicators.to_vec(),
    };
    serde_json::to_string_pretty(&file)
        .map_err(|error| DetectError::indicator(origin, format!("cannot write JSON: {error}")))
}

/// Reads indicators from YAML text. The text is a map with the list `indicators`.
///
/// `origin` is the name of the file. It appears in the error.
///
/// # Errors
///
/// Returns [`DetectError::Indicator`] if the text is not valid.
pub fn indicators_from_yaml(
    text: &str,
    origin: &str,
) -> std::result::Result<Vec<Indicator>, DetectError> {
    serde_saphyr::from_str::<IndicatorFile>(text)
        .map(|file| file.indicators)
        .map_err(|error| DetectError::indicator(origin, yaml_reason(&error)))
}

/// Reads indicators from JSON text. The text is an object with the array `indicators`.
///
/// `origin` is the name of the file. It appears in the error.
///
/// # Errors
///
/// Returns [`DetectError::Indicator`] if the text is not valid.
pub fn indicators_from_json(
    text: &str,
    origin: &str,
) -> std::result::Result<Vec<Indicator>, DetectError> {
    serde_json::from_str::<IndicatorFile>(text)
        .map(|file| file.indicators)
        .map_err(|error| DetectError::indicator(origin, error.to_string()))
}

/// Reads one indicator file. A file with the extension `json` is JSON. All other files are
/// YAML.
///
/// # Errors
///
/// Returns [`DetectError::Io`] if the file cannot be read, and [`DetectError::Indicator`] if
/// the file is larger than [`MAX_INDICATOR_BYTES`] or is not valid.
pub fn load_indicators(path: &Path) -> std::result::Result<Vec<Indicator>, DetectError> {
    let origin = path.display().to_string();
    let text = read_text(path, MAX_INDICATOR_BYTES, |reason| {
        DetectError::indicator(&origin, reason)
    })?;
    let is_json = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if is_json {
        indicators_from_json(&text, &origin)
    } else {
        indicators_from_yaml(&text, &origin)
    }
}

#[derive(Debug)]
struct Entry {
    indicator: Indicator,
    /// The value in the form that the store compares.
    normal: String,
    rule_id: String,
    verdict: Verdict,
    attack: Vec<AttackTechnique>,
    /// The suppression window of the indicator.
    suppress: Option<TimeDelta>,
}

/// One match of an event value with an indicator.
struct Hit<'a> {
    entry: usize,
    field: &'static str,
    value: Cow<'a, str>,
    entity: Option<EntityRef>,
}

type PrefixTable<K> = BTreeMap<u8, HashMap<K, Vec<usize>>>;

/// A set of indicators, with the indexes for fast lookup.
#[derive(Debug, Default)]
pub struct IocStore {
    entries: Vec<Entry>,
    /// IPv4 networks: prefix length, then network bits, then the entries.
    v4: PrefixTable<u32>,
    /// IPv6 networks: prefix length, then network bits, then the entries.
    v6: PrefixTable<u128>,
    domains: HashMap<String, Vec<usize>>,
    app_ids: HashMap<String, Vec<usize>>,
    fingerprints: HashMap<String, Vec<usize>>,
    user_agents: Option<AhoCorasick>,
    /// The entry for each pattern of `user_agents`.
    user_agent_entries: Vec<usize>,
}

fn lower_if_needed(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_uppercase) {
        Cow::Owned(text.to_lowercase())
    } else {
        Cow::Borrowed(text)
    }
}

fn mask_v4(bits: u32, prefix: u8) -> u32 {
    let shift = 32_u32.saturating_sub(u32::from(prefix));
    bits & u32::MAX.checked_shl(shift).unwrap_or(0)
}

fn mask_v6(bits: u128, prefix: u8) -> u128 {
    let shift = 128_u32.saturating_sub(u32::from(prefix));
    bits & u128::MAX.checked_shl(shift).unwrap_or(0)
}

fn normal_domain(text: &str) -> std::result::Result<String, String> {
    let domain = text.trim().trim_end_matches('.').to_lowercase();
    let domain = domain.strip_prefix("*.").unwrap_or(&domain);
    let labels: Vec<&str> = domain.split('.').collect();
    let valid_label = |label: &&str| {
        !label.is_empty()
            && label
                .chars()
                .all(|character| character.is_alphanumeric() || matches!(character, '-' | '_'))
    };
    if domain.len() > MAX_DOMAIN_LENGTH || !labels.iter().all(valid_label) {
        return Err(format!("{text:?} is not a DNS domain"));
    }
    if labels.len() < 2 {
        return Err(format!(
            "the domain {text:?} has one label; a domain indicator needs two or more"
        ));
    }
    Ok(domain.to_owned())
}

impl IocStore {
    /// Makes a store from indicators.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Indicator`] with the file name `indicators` if an indicator is
    /// not valid. Refer to [`IocStore::with_origin`] for the rules.
    pub fn new(indicators: Vec<Indicator>) -> std::result::Result<Self, DetectError> {
        Self::with_origin(indicators, "indicators")
    }

    /// Makes a store from indicators. `origin` is the name that an error shows.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Indicator`] if an indicator:
    ///
    /// - has an empty value or an empty description;
    /// - has a value that is not valid for its type;
    /// - is a network that contains all addresses;
    /// - is a user agent shorter than [`MIN_USER_AGENT_LENGTH`];
    /// - has the verdict `benign`;
    /// - has a `first_seen` time after its `last_seen` time;
    /// - has an empty `source`, or a `suppress_seconds` of zero;
    /// - has the same type and value as an earlier indicator.
    pub fn with_origin(
        indicators: Vec<Indicator>,
        origin: &str,
    ) -> std::result::Result<Self, DetectError> {
        let mut store = Self::default();
        let mut seen: HashSet<(IndicatorKind, String)> = HashSet::new();
        let mut user_agent_patterns: Vec<String> = Vec::new();
        for (position, indicator) in indicators.into_iter().enumerate() {
            let fail = |reason: String| {
                DetectError::indicator(origin, format!("indicator {}: {reason}", position + 1))
            };
            let value = indicator.value.trim();
            if value.is_empty() {
                return Err(fail("the value is empty".to_owned()));
            }
            if indicator.description.trim().is_empty() {
                return Err(fail(format!("the indicator {value:?} has no description")));
            }
            if indicator.verdict == Some(Verdict::Benign) {
                return Err(fail(format!(
                    "the indicator {value:?} has the verdict benign; use malicious or suspicious"
                )));
            }
            if let (Some(first), Some(last)) = (indicator.first_seen, indicator.last_seen)
                && first > last
            {
                return Err(fail(format!(
                    "the indicator {value:?} has a first_seen time after its last_seen time"
                )));
            }
            if indicator
                .source
                .as_deref()
                .is_some_and(|source| source.trim().is_empty())
            {
                return Err(fail(format!("the indicator {value:?} has an empty source")));
            }
            let suppress = match indicator.suppress_seconds {
                None => None,
                Some(seconds) => Some(
                    i64::try_from(seconds)
                        .ok()
                        .filter(|seconds| *seconds > 0)
                        .and_then(TimeDelta::try_seconds)
                        .ok_or_else(|| {
                            fail(format!(
                                "the indicator {value:?} has a suppress_seconds of {seconds}; \
                                 use 1 or more"
                            ))
                        })?,
                ),
            };
            let entry = store.entries.len();
            let normal = match indicator.kind {
                IndicatorKind::Ip => {
                    let network = value
                        .parse::<IpNet>()
                        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| fail(format!("{value:?} is not an address or a network")))?
                        .trunc();
                    if network.prefix_len() == 0 {
                        return Err(fail(format!(
                            "the network {value:?} contains all addresses"
                        )));
                    }
                    match network.network() {
                        IpAddr::V4(address) => store
                            .v4
                            .entry(network.prefix_len())
                            .or_default()
                            .entry(u32::from(address))
                            .or_default()
                            .push(entry),
                        IpAddr::V6(address) => store
                            .v6
                            .entry(network.prefix_len())
                            .or_default()
                            .entry(u128::from(address))
                            .or_default()
                            .push(entry),
                    }
                    if network.prefix_len() == network.max_prefix_len() {
                        network.addr().to_string()
                    } else {
                        network.to_string()
                    }
                }
                IndicatorKind::Domain => {
                    let domain = normal_domain(value).map_err(fail)?;
                    store.domains.entry(domain.clone()).or_default().push(entry);
                    domain
                }
                IndicatorKind::UserAgent => {
                    if value.chars().count() < MIN_USER_AGENT_LENGTH {
                        return Err(fail(format!(
                            "the user agent {value:?} is shorter than {MIN_USER_AGENT_LENGTH} characters"
                        )));
                    }
                    user_agent_patterns.push(value.to_owned());
                    store.user_agent_entries.push(entry);
                    value.to_ascii_lowercase()
                }
                IndicatorKind::AppId => {
                    let app_id = value.to_lowercase();
                    store.app_ids.entry(app_id.clone()).or_default().push(entry);
                    app_id
                }
                IndicatorKind::ClientFingerprint => {
                    let token = fingerprint_token(value)
                        .ok_or_else(|| fail("the value is empty".to_owned()))?;
                    store
                        .fingerprints
                        .entry(token.clone())
                        .or_default()
                        .push(entry);
                    token
                }
            };
            if !seen.insert((indicator.kind, normal.clone())) {
                return Err(fail(format!(
                    "the {} indicator {normal:?} is in the set two times",
                    indicator.kind.name()
                )));
            }
            let rule_id = match indicator.id.as_deref().map(str::trim) {
                Some("") => return Err(fail(format!("the indicator {value:?} has an empty id"))),
                Some(id) => id.to_owned(),
                None => format!("ioc:{}:{normal}", indicator.kind.name()),
            };
            store.entries.push(Entry {
                verdict: indicator
                    .verdict
                    .unwrap_or_else(|| default_verdict(indicator.severity)),
                attack: techniques_from_tags(&indicator.tags),
                rule_id,
                normal,
                suppress,
                indicator,
            });
        }
        if !user_agent_patterns.is_empty() {
            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&user_agent_patterns)
                .map_err(|error| {
                    DetectError::indicator(origin, format!("the user agent indicators: {error}"))
                })?;
            store.user_agents = Some(automaton);
        }
        Ok(store)
    }

    /// Returns the number of indicators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the store has no indicator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the indicators, in the order in which the store received them.
    pub fn indicators(&self) -> impl Iterator<Item = &Indicator> {
        self.entries.iter().map(|entry| &entry.indicator)
    }

    fn address_hits<'a>(&self, ip: IpAddr, field: &'static str, hits: &mut Vec<Hit<'a>>) {
        let ip = canonical_ip(ip);
        let mut add = |entries: Option<&Vec<usize>>| {
            for entry in entries.into_iter().flatten() {
                hits.push(Hit {
                    entry: *entry,
                    field,
                    value: Cow::Owned(ip.to_string()),
                    entity: Some(ip_entity(ip)),
                });
            }
        };
        match ip {
            IpAddr::V4(address) => {
                let bits = u32::from(address);
                for (prefix, table) in &self.v4 {
                    add(table.get(&mask_v4(bits, *prefix)));
                }
            }
            IpAddr::V6(address) => {
                let bits = u128::from(address);
                for (prefix, table) in &self.v6 {
                    add(table.get(&mask_v6(bits, *prefix)));
                }
            }
        }
    }

    fn domain_hits<'a>(&self, text: &'a str, field: &'static str, hits: &mut Vec<Hit<'a>>) {
        let name = text.trim().trim_end_matches('.');
        if self.domains.is_empty() || name.is_empty() || name.len() > MAX_DOMAIN_LENGTH {
            return;
        }
        let name = lower_if_needed(name);
        let mut rest: &str = &name;
        loop {
            for entry in self.domains.get(rest).into_iter().flatten() {
                hits.push(Hit {
                    entry: *entry,
                    field,
                    value: Cow::Owned(name.to_string()),
                    entity: Some(EntityRef::new(EntityKind::Domain, name.to_string())),
                });
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => break,
            }
        }
    }

    fn app_id_hits<'a>(&self, text: &'a str, field: &'static str, hits: &mut Vec<Hit<'a>>) {
        if self.app_ids.is_empty() {
            return;
        }
        let app_id = lower_if_needed(text.trim());
        for entry in self.app_ids.get(app_id.as_ref()).into_iter().flatten() {
            hits.push(Hit {
                entry: *entry,
                field,
                value: Cow::Borrowed(text),
                entity: Some(EntityRef::new(EntityKind::Application, text)),
            });
        }
    }

    fn fingerprint_hits<'a>(&self, text: &'a str, hits: &mut Vec<Hit<'a>>) {
        if self.fingerprints.is_empty() {
            return;
        }
        let Some(token) = fingerprint_token(text) else {
            return;
        };
        for entry in self.fingerprints.get(&token).into_iter().flatten() {
            hits.push(Hit {
                entry: *entry,
                field: "attributes.client_fingerprint",
                value: Cow::Owned(token.clone()),
                entity: Some(EntityRef::new(
                    EntityKind::Other,
                    format!("{CLIENT_FINGERPRINT_PREFIX}{token}"),
                )),
            });
        }
    }

    fn user_agent_hits<'a>(&self, text: &'a str, hits: &mut Vec<Hit<'a>>) {
        let Some(automaton) = &self.user_agents else {
            return;
        };
        let bytes = text.as_bytes();
        let examined = bytes.get(..MAX_USER_AGENT_BYTES).unwrap_or(bytes);
        for found in automaton.find_overlapping_iter(examined) {
            if let Some(entry) = self.user_agent_entries.get(found.pattern().as_usize()) {
                hits.push(Hit {
                    entry: *entry,
                    field: "actor.user_agent",
                    value: Cow::Borrowed(text),
                    entity: None,
                });
            }
        }
    }

    /// Returns one detection for each indicator that the event matches.
    ///
    /// The store examines these fields:
    ///
    /// | Indicator | Fields |
    /// | --- | --- |
    /// | `ip` | `actor.ip`, `attributes.destination_ip` |
    /// | `domain` | `attributes.destination_domain`, and the target if it is a domain |
    /// | `user_agent` | `actor.user_agent` |
    /// | `app_id` | `attributes.app_id`, and the actor and the target if they are applications |
    /// | `client_fingerprint` | `attributes.client_fingerprint` |
    ///
    /// The store keeps no state, so it does not apply `suppress_seconds`. The
    /// [`DetectionEngine`](crate::engine::DetectionEngine) applies it.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Vec<Detection> {
        self.matches(event)
            .into_iter()
            .map(|(_, detection)| detection)
            .collect()
    }

    /// Returns one detection for each indicator that the event matches, with the
    /// suppression window of the indicator.
    pub(crate) fn matches(&self, event: &Event) -> Vec<(Option<TimeDelta>, Detection)> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut hits: Vec<Hit<'_>> = Vec::new();
        if let Some(ip) = event.actor.ip {
            self.address_hits(ip, "actor.ip", &mut hits);
        }
        if let Some(ip) = event
            .attribute_str(attr::DESTINATION_IP)
            .and_then(|text| text.trim().parse::<IpAddr>().ok())
        {
            self.address_hits(ip, "attributes.destination_ip", &mut hits);
        }
        if let Some(domain) = event.attribute_str(attr::DESTINATION_DOMAIN) {
            self.domain_hits(domain, "attributes.destination_domain", &mut hits);
        }
        if let Some(app_id) = event.attribute_str(attr::APP_ID) {
            self.app_id_hits(app_id, "attributes.app_id", &mut hits);
        }
        if let Some(target) = &event.target {
            match target.kind {
                EntityKind::Domain => self.domain_hits(&target.id, "target.id", &mut hits),
                EntityKind::Application => self.app_id_hits(&target.id, "target.id", &mut hits),
                _ => {}
            }
        }
        if event.actor.kind == EntityKind::Application {
            self.app_id_hits(&event.actor.id, "actor.id", &mut hits);
        }
        if let Some(user_agent) = event.actor.user_agent.as_deref() {
            self.user_agent_hits(user_agent, &mut hits);
        }
        if let Some(fingerprint) = event.attribute_str(attr::CLIENT_FINGERPRINT) {
            self.fingerprint_hits(fingerprint, &mut hits);
        }
        if hits.is_empty() {
            return Vec::new();
        }

        // One detection for each indicator: the first field that matched it.
        hits.sort_by_key(|hit| hit.entry);
        hits.dedup_by_key(|hit| hit.entry);
        hits.into_iter()
            .filter_map(|hit| {
                let entry = self.entries.get(hit.entry)?;
                Some((entry.suppress, detection(entry, event, hit)))
            })
            .collect()
    }
}

fn detection(entry: &Entry, event: &Event, hit: Hit<'_>) -> Detection {
    let indicator = &entry.indicator;
    let kind = indicator.kind.name();
    let matched: String = hit.value.chars().take(MAX_MATCHED_VALUE_CHARS).collect();
    let mut entities = event_entities(event);
    if let Some(entity) = hit.entity {
        push_entity(&mut entities, entity);
    }
    let event_ids = vec![event.id];
    Detection {
        id: detection_id(&entry.rule_id, &event_ids),
        rule_id: entry.rule_id.clone(),
        title: format!("Indicator match: {kind} {}", entry.normal),
        description: format!(
            "{} The event field {} matched the indicator.",
            indicator.description.trim(),
            hit.field
        ),
        severity: indicator.severity,
        verdict: entry.verdict,
        tier: DetectionTier::Deterministic,
        time: event.time,
        attack: entry.attack.clone(),
        event_ids,
        entities,
        tenant: event_tenant(event).map(str::to_owned),
        attributes: BTreeMap::from([
            ("detector".to_owned(), json!(IOC_DETECTOR_ID)),
            ("indicator_type".to_owned(), json!(kind)),
            ("indicator_value".to_owned(), json!(entry.normal)),
            ("matched_field".to_owned(), json!(hit.field)),
            ("matched_value".to_owned(), json!(matched)),
        ]),
    }
}

#[async_trait]
impl Detector for IocStore {
    fn id(&self) -> &str {
        IOC_DETECTOR_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        Ok(self.evaluate(event))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use aegis_contracts::common::EventId;
    use aegis_contracts::event::{Actor, EventClass, EventSource, action};
    use chrono::DateTime;
    use uuid::Uuid;

    use super::*;

    fn indicator(kind: IndicatorKind, value: &str) -> Indicator {
        Indicator {
            kind,
            value: value.to_owned(),
            description: "A test indicator.".to_owned(),
            severity: Severity::High,
            tags: vec![
                "attack.command-and-control".to_owned(),
                "attack.t1071.001".to_owned(),
            ],
            verdict: None,
            id: None,
            first_seen: None,
            last_seen: None,
            source: None,
            suppress_seconds: None,
        }
    }

    fn store(indicators: Vec<Indicator>) -> IocStore {
        IocStore::new(indicators).unwrap()
    }

    fn reason(indicators: Vec<Indicator>) -> String {
        match IocStore::new(indicators).unwrap_err() {
            DetectError::Indicator { file, reason } => {
                assert_eq!(file, "indicators");
                reason
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    fn event(ip: &str) -> Event {
        let actor = Actor::new(EntityKind::User, "user-1")
            .with_ip(ip.parse().unwrap())
            .with_user_agent("Mozilla/5.0 (X11; Linux x86_64)");
        Event::new(
            DateTime::UNIX_EPOCH,
            EventSource::new("c", "v", "p").with_tenant("tenant-1"),
            EventClass::NetworkActivity,
            action::NETWORK_CONNECT,
            actor,
        )
        .with_id(EventId(Uuid::from_u128(9)))
    }

    fn rule_ids(store: &IocStore, event: &Event) -> Vec<String> {
        store
            .evaluate(event)
            .into_iter()
            .map(|found| found.rule_id)
            .collect()
    }

    #[test]
    fn an_address_indicator_matches_only_that_address() {
        let store = store(vec![indicator(IndicatorKind::Ip, "203.0.113.200")]);
        assert_eq!(
            rule_ids(&store, &event("203.0.113.200")),
            ["ioc:ip:203.0.113.200"]
        );
        assert_eq!(
            rule_ids(&store, &event("203.0.113.201")),
            Vec::<String>::new()
        );
        assert_eq!(
            rule_ids(&store, &event("::ffff:203.0.113.200")),
            ["ioc:ip:203.0.113.200"]
        );
    }

    #[test]
    fn a_network_indicator_matches_each_address_in_the_network() {
        let store = store(vec![
            indicator(IndicatorKind::Ip, "192.0.2.128/25"),
            indicator(IndicatorKind::Ip, "192.0.2.200/29"),
            indicator(IndicatorKind::Ip, "2001:db8:bad::/48"),
        ]);
        assert_eq!(
            rule_ids(&store, &event("192.0.2.129")),
            ["ioc:ip:192.0.2.128/25"]
        );
        assert_eq!(
            rule_ids(&store, &event("192.0.2.201")),
            ["ioc:ip:192.0.2.128/25", "ioc:ip:192.0.2.200/29"]
        );
        assert_eq!(
            rule_ids(&store, &event("192.0.2.127")),
            Vec::<String>::new()
        );
        assert_eq!(
            rule_ids(&store, &event("2001:db8:bad:1::7")),
            ["ioc:ip:2001:db8:bad::/48"]
        );
        assert_eq!(
            rule_ids(&store, &event("2001:db8:bae::7")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_destination_address_of_a_connection_is_examined() {
        let store = store(vec![indicator(IndicatorKind::Ip, "203.0.113.200")]);
        let event = event("198.51.100.10").with_attribute(attr::DESTINATION_IP, "203.0.113.200");
        let detections = store.evaluate(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].attributes["matched_field"],
            json!("attributes.destination_ip")
        );
        let other =
            self::event("198.51.100.10").with_attribute(attr::DESTINATION_IP, "not an address");
        assert_eq!(store.evaluate(&other), []);
    }

    #[test]
    fn one_indicator_gives_one_detection_when_two_fields_match() {
        let store = store(vec![indicator(IndicatorKind::Ip, "203.0.113.0/24")]);
        let event = event("203.0.113.7").with_attribute(attr::DESTINATION_IP, "203.0.113.8");
        let detections = store.evaluate(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].attributes["matched_field"], json!("actor.ip"));
        assert_eq!(
            detections[0].attributes["matched_value"],
            json!("203.0.113.7")
        );
    }

    #[test]
    fn a_domain_indicator_matches_the_domain_and_its_subdomains() {
        let store = store(vec![indicator(IndicatorKind::Domain, "Bad.Example.")]);
        let with_domain =
            |domain: &str| event("198.51.100.10").with_attribute(attr::DESTINATION_DOMAIN, domain);
        for domain in [
            "bad.example",
            "BAD.example",
            "a.b.bad.example",
            "bad.example.",
        ] {
            assert_eq!(
                rule_ids(&store, &with_domain(domain)),
                ["ioc:domain:bad.example"],
                "{domain}"
            );
        }
        for domain in ["notbad.example", "bad.example.org", "example", "", "bad"] {
            assert_eq!(
                rule_ids(&store, &with_domain(domain)),
                Vec::<String>::new(),
                "{domain}"
            );
        }
        let long = format!("{}.bad.example", "a.".repeat(200));
        assert_eq!(rule_ids(&store, &with_domain(&long)), Vec::<String>::new());

        let target = event("198.51.100.10")
            .with_target(EntityRef::new(EntityKind::Domain, "cdn.bad.example"));
        let detections = store.evaluate(&target);
        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].attributes["matched_field"],
            json!("target.id")
        );
    }

    #[test]
    fn a_user_agent_indicator_matches_a_part_of_the_user_agent() {
        let store = store(vec![
            indicator(IndicatorKind::UserAgent, "example-tool/"),
            indicator(IndicatorKind::UserAgent, "Linux x86"),
        ]);
        let mut event = event("198.51.100.10");
        assert_eq!(rule_ids(&store, &event), ["ioc:user_agent:linux x86"]);
        event.actor.user_agent = Some("EXAMPLE-TOOL/2.1 (linux x86_64)".to_owned());
        assert_eq!(
            rule_ids(&store, &event),
            ["ioc:user_agent:example-tool/", "ioc:user_agent:linux x86"]
        );
        event.actor.user_agent = Some("curl/8.0".to_owned());
        assert_eq!(rule_ids(&store, &event), Vec::<String>::new());
        event.actor.user_agent = None;
        assert_eq!(rule_ids(&store, &event), Vec::<String>::new());
    }

    #[test]
    fn an_app_id_indicator_matches_the_attribute_the_target_and_the_actor() {
        let store = store(vec![indicator(IndicatorKind::AppId, "App-Rogue")]);
        let by_attribute = event("198.51.100.10").with_attribute(attr::APP_ID, "app-rogue");
        assert_eq!(rule_ids(&store, &by_attribute), ["ioc:app_id:app-rogue"]);

        let by_target = event("198.51.100.10")
            .with_target(EntityRef::new(EntityKind::Application, "APP-ROGUE"));
        let detections = store.evaluate(&by_target);
        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].attributes["matched_field"],
            json!("target.id")
        );

        let mut by_actor = event("198.51.100.10");
        by_actor.actor.kind = EntityKind::Application;
        by_actor.actor.id = "app-rogue".to_owned();
        assert_eq!(rule_ids(&store, &by_actor), ["ioc:app_id:app-rogue"]);

        let user_with_same_id = {
            let mut event = event("198.51.100.10");
            event.actor.id = "app-rogue".to_owned();
            event
        };
        assert_eq!(rule_ids(&store, &user_with_same_id), Vec::<String>::new());
        let other = event("198.51.100.10").with_attribute(attr::APP_ID, "app-rogue-2");
        assert_eq!(rule_ids(&store, &other), Vec::<String>::new());
    }

    #[test]
    fn a_detection_has_the_data_of_the_indicator_and_the_event() {
        let mut first = indicator(IndicatorKind::Ip, "203.0.113.200");
        first.description = "  A relay of a known campaign. ".to_owned();
        first.severity = Severity::Critical;
        let store = store(vec![first]);
        let event = event("203.0.113.200");
        let detections = store.evaluate(&event);
        assert_eq!(detections.len(), 1);
        let found = &detections[0];
        assert_eq!(found.title, "Indicator match: ip 203.0.113.200");
        assert_eq!(
            found.description,
            "A relay of a known campaign. The event field actor.ip matched the indicator."
        );
        assert_eq!(found.severity, Severity::Critical);
        assert_eq!(found.verdict, Verdict::Malicious);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(found.time, event.time);
        assert_eq!(found.event_ids, [event.id]);
        assert_eq!(found.tenant.as_deref(), Some("tenant-1"));
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "command-and-control",
                "T1071.001",
                "Web Protocols"
            )]
        );
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::User, "user-1"),
                ip_entity(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))),
            ]
        );
        assert_eq!(found.attributes["detector"], json!("aegis.ioc"));
        assert_eq!(found.attributes["indicator_type"], json!("ip"));
        assert_eq!(found.attributes["indicator_value"], json!("203.0.113.200"));
        assert_eq!(found.id, store.evaluate(&event)[0].id);
    }

    #[test]
    fn a_domain_match_adds_the_domain_to_the_entities() {
        let store = store(vec![indicator(IndicatorKind::Domain, "bad.example")]);
        let event =
            event("198.51.100.10").with_attribute(attr::DESTINATION_DOMAIN, "C2.Bad.Example");
        let detections = store.evaluate(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].entities.last(),
            Some(&EntityRef::new(EntityKind::Domain, "c2.bad.example"))
        );
    }

    #[test]
    fn the_verdict_follows_the_severity_unless_the_indicator_sets_it() {
        let mut low = indicator(IndicatorKind::Ip, "203.0.113.1");
        low.severity = Severity::Low;
        let mut forced = indicator(IndicatorKind::Ip, "203.0.113.2");
        forced.severity = Severity::Low;
        forced.verdict = Some(Verdict::Malicious);
        forced.id = Some(" feed-7 ".to_owned());
        let store = store(vec![low, forced]);
        let first = store.evaluate(&event("203.0.113.1"));
        assert_eq!(first[0].verdict, Verdict::Suspicious);
        let second = store.evaluate(&event("203.0.113.2"));
        assert_eq!(second[0].verdict, Verdict::Malicious);
        assert_eq!(second[0].rule_id, "feed-7");
    }

    #[test]
    fn a_long_user_agent_is_cut_in_the_detection() {
        let store = store(vec![indicator(IndicatorKind::UserAgent, "example-tool/")]);
        let mut event = event("198.51.100.10");
        event.actor.user_agent = Some(format!("example-tool/{}", "x".repeat(1_000)));
        let detections = store.evaluate(&event);
        assert_eq!(detections.len(), 1);
        let matched = detections[0].attributes["matched_value"].as_str().unwrap();
        assert_eq!(matched.chars().count(), 256);
    }

    #[test]
    fn an_empty_store_gives_no_detection() {
        let store = IocStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.evaluate(&event("203.0.113.200")), []);
    }

    #[test]
    fn indicators_that_are_not_valid_are_errors_with_their_position() {
        let good = || indicator(IndicatorKind::Ip, "203.0.113.200");
        let cases: Vec<(Indicator, &str)> = vec![
            (
                indicator(IndicatorKind::Ip, "  "),
                "indicator 2: the value is empty",
            ),
            (
                indicator(IndicatorKind::Ip, "office"),
                "indicator 2: \"office\" is not an address or a network",
            ),
            (
                indicator(IndicatorKind::Ip, "0.0.0.0/0"),
                "indicator 2: the network \"0.0.0.0/0\" contains all addresses",
            ),
            (
                indicator(IndicatorKind::Ip, "::/0"),
                "indicator 2: the network \"::/0\" contains all addresses",
            ),
            (
                indicator(IndicatorKind::Domain, "example"),
                "indicator 2: the domain \"example\" has one label; a domain indicator needs two or more",
            ),
            (
                indicator(IndicatorKind::Domain, "bad domain.example"),
                "indicator 2: \"bad domain.example\" is not a DNS domain",
            ),
            (
                indicator(IndicatorKind::Domain, "a..example"),
                "indicator 2: \"a..example\" is not a DNS domain",
            ),
            (
                indicator(IndicatorKind::UserAgent, "abc"),
                "indicator 2: the user agent \"abc\" is shorter than 4 characters",
            ),
            (
                indicator(IndicatorKind::Ip, "203.0.113.200/32"),
                "indicator 2: the ip indicator \"203.0.113.200\" is in the set two times",
            ),
            (
                Indicator {
                    description: " ".to_owned(),
                    ..indicator(IndicatorKind::Ip, "203.0.113.9")
                },
                "indicator 2: the indicator \"203.0.113.9\" has no description",
            ),
            (
                Indicator {
                    verdict: Some(Verdict::Benign),
                    ..indicator(IndicatorKind::Ip, "203.0.113.9")
                },
                "indicator 2: the indicator \"203.0.113.9\" has the verdict benign; use malicious or suspicious",
            ),
            (
                Indicator {
                    id: Some(String::new()),
                    ..indicator(IndicatorKind::Ip, "203.0.113.9")
                },
                "indicator 2: the indicator \"203.0.113.9\" has an empty id",
            ),
        ];
        assert_eq!(cases.len(), 12);
        for (bad, expected) in cases {
            assert_eq!(reason(vec![good(), bad]), expected);
        }
    }

    #[test]
    fn a_network_with_host_bits_is_cut_to_its_network() {
        let store = store(vec![indicator(IndicatorKind::Ip, "203.0.113.77/24")]);
        assert_eq!(
            rule_ids(&store, &event("203.0.113.1")),
            ["ioc:ip:203.0.113.0/24"]
        );
    }

    const YAML: &str = r"
indicators:
  - type: ip
    value: 192.0.2.128/25
    description: A network of an example campaign.
    severity: high
    tags: [attack.command-and-control, attack.t1071.001]
  - type: domain
    value: bad.example
    description: An example domain.
    severity: medium
    verdict: malicious
    id: feed-domain-1
  - type: user_agent
    value: example-tool/
    description: An example client.
    severity: low
  - type: app_id
    value: app-rogue
    description: An example application.
    severity: critical
";

    #[test]
    fn indicators_load_from_yaml() {
        let indicators = indicators_from_yaml(YAML, "indicators/a.yml").unwrap();
        assert_eq!(indicators.len(), 4);
        assert_eq!(indicators[0].kind, IndicatorKind::Ip);
        assert_eq!(indicators[0].value, "192.0.2.128/25");
        assert_eq!(indicators[0].severity, Severity::High);
        assert_eq!(
            indicators[0].tags,
            ["attack.command-and-control", "attack.t1071.001"]
        );
        assert_eq!(indicators[1].verdict, Some(Verdict::Malicious));
        assert_eq!(indicators[1].id.as_deref(), Some("feed-domain-1"));
        assert_eq!(indicators[2].kind, IndicatorKind::UserAgent);
        assert_eq!(indicators[2].tags, Vec::<String>::new());
        assert_eq!(indicators[3].kind, IndicatorKind::AppId);
        let store = store(indicators);
        assert_eq!(store.len(), 4);
        assert_eq!(store.indicators().count(), 4);
    }

    #[test]
    fn indicators_load_from_json_and_the_cidr_type_is_an_address_type() {
        let text = r#"{"indicators":[{"type":"cidr","value":"192.0.2.128/25","description":"d","severity":"high"}]}"#;
        let indicators = indicators_from_json(text, "indicators/a.json").unwrap();
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].kind, IndicatorKind::Ip);
    }

    #[test]
    fn an_indicator_file_that_is_not_valid_names_the_file_and_the_cause() {
        let unknown_type =
            "indicators:\n  - type: hash\n    value: x\n    description: d\n    severity: low\n";
        let error = indicators_from_yaml(unknown_type, "indicators/a.yml").unwrap_err();
        let text = error.to_string();
        assert!(
            text.starts_with("indicator file indicators/a.yml: "),
            "{text}"
        );
        assert!(text.contains("unknown variant `hash`"), "{text}");

        let no_severity = "indicators:\n  - type: ip\n    value: 192.0.2.1\n    description: d\n";
        let text = indicators_from_yaml(no_severity, "a.yml")
            .unwrap_err()
            .to_string();
        assert!(text.contains("missing field `severity`"), "{text}");

        let typo = "indicators:\n  - type: ip\n    value: 192.0.2.1\n    description: d\n    severity: low\n    sevrity: high\n";
        let text = indicators_from_yaml(typo, "a.yml").unwrap_err().to_string();
        assert!(text.contains("unknown field `sevrity`"), "{text}");

        let text = indicators_from_yaml("- a\n", "a.yml")
            .unwrap_err()
            .to_string();
        assert!(text.starts_with("indicator file a.yml: "), "{text}");

        let error = indicators_from_json("{\"indicators\": [", "a.json").unwrap_err();
        assert!(
            matches!(&error, DetectError::Indicator { file, .. } if file == "a.json"),
            "{error}"
        );
    }

    #[test]
    fn load_indicators_selects_the_format_by_the_extension() {
        let directory = tempfile::tempdir().unwrap();
        let yaml = directory.path().join("a.yml");
        std::fs::write(&yaml, YAML).unwrap();
        assert_eq!(load_indicators(&yaml).unwrap().len(), 4);

        let json = directory.path().join("b.JSON");
        std::fs::write(
            &json,
            r#"{"indicators":[{"type":"ip","value":"192.0.2.1","description":"d","severity":"low"}]}"#,
        )
        .unwrap();
        assert_eq!(load_indicators(&json).unwrap().len(), 1);

        let broken = directory.path().join("c.yml");
        std::fs::write(&broken, "indicators: 5\n").unwrap();
        let error = load_indicators(&broken).unwrap_err();
        assert!(
            matches!(&error, DetectError::Indicator { file, .. } if *file == broken.display().to_string()),
            "{error}"
        );
        let absent = load_indicators(&directory.path().join("none.yml")).unwrap_err();
        assert!(matches!(absent, DetectError::Io { .. }), "{absent}");
    }

    #[tokio::test]
    async fn the_store_is_a_tier_one_detector() {
        let store = store(vec![indicator(IndicatorKind::Ip, "203.0.113.200")]);
        assert_eq!(Detector::id(&store), "aegis.ioc");
        assert_eq!(store.tier(), DetectionTier::Deterministic);
        let detections = store.inspect(&event("203.0.113.200")).await.unwrap();
        assert_eq!(detections.len(), 1);
        assert_eq!(store.inspect(&event("203.0.113.9")).await.unwrap(), []);
    }

    #[test]
    fn a_client_fingerprint_indicator_matches_the_attribute_of_the_event() {
        let store = store(vec![indicator(
            IndicatorKind::ClientFingerprint,
            "FP-7c1d09",
        )]);
        let with = |fingerprint: &str| {
            event("203.0.113.9").with_attribute(attr::CLIENT_FINGERPRINT, fingerprint)
        };
        let detections = store.evaluate(&with("fp-7C1D09"));
        assert_eq!(detections.len(), 1);
        let found = &detections[0];
        assert_eq!(found.rule_id, "ioc:client_fingerprint:fp-7c1d09");
        assert_eq!(found.title, "Indicator match: client_fingerprint fp-7c1d09");
        assert_eq!(
            found.attributes["matched_field"],
            json!("attributes.client_fingerprint")
        );
        assert_eq!(found.attributes["matched_value"], json!("fp-7c1d09"));
        // The fingerprint is an entity of the kind `other`, one time.
        let fingerprints: Vec<&EntityRef> = found
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Other)
            .collect();
        assert_eq!(
            fingerprints,
            [&EntityRef::new(
                EntityKind::Other,
                "client_fingerprint:fp-7c1d09"
            )]
        );

        assert_eq!(rule_ids(&store, &with("fp-7c1d0")), Vec::<String>::new());
        assert_eq!(rule_ids(&store, &with("fp-7c1d099")), Vec::<String>::new());
        assert_eq!(
            rule_ids(&store, &event("203.0.113.9")),
            Vec::<String>::new()
        );
        // A fingerprint that is not a text is not examined.
        let number = event("203.0.113.9").with_attribute(attr::CLIENT_FINGERPRINT, 7);
        assert_eq!(rule_ids(&store, &number), Vec::<String>::new());
    }

    #[test]
    fn a_long_fingerprint_matches_through_its_digest() {
        let long = "f".repeat(300);
        let store = store(vec![indicator(IndicatorKind::ClientFingerprint, &long)]);
        let token = fingerprint_token(&long).unwrap();
        assert!(token.starts_with("sha256:"), "{token}");
        let from_event = event("203.0.113.9").with_attribute(attr::CLIENT_FINGERPRINT, long);
        assert_eq!(
            rule_ids(&store, &from_event),
            [format!("ioc:client_fingerprint:{token}")]
        );
        // An indicator with the digest form matches the same event.
        let by_token = self::store(vec![indicator(IndicatorKind::ClientFingerprint, &token)]);
        assert_eq!(rule_ids(&by_token, &from_event).len(), 1);
    }

    #[test]
    fn the_times_the_source_and_the_suppression_time_are_checked() {
        let at = |seconds: i64| DateTime::from_timestamp(1_793_696_400 + seconds, 0);
        let mut reversed = indicator(IndicatorKind::Ip, "192.0.2.1");
        reversed.first_seen = at(10);
        reversed.last_seen = at(5);
        assert_eq!(
            reason(vec![reversed]),
            "indicator 1: the indicator \"192.0.2.1\" has a first_seen time after its \
             last_seen time"
        );
        let mut no_source = indicator(IndicatorKind::Ip, "192.0.2.1");
        no_source.source = Some("  ".to_owned());
        assert_eq!(
            reason(vec![no_source]),
            "indicator 1: the indicator \"192.0.2.1\" has an empty source"
        );
        for seconds in [0, u64::MAX] {
            let mut zero = indicator(IndicatorKind::Ip, "192.0.2.1");
            zero.suppress_seconds = Some(seconds);
            assert_eq!(
                reason(vec![zero]),
                format!(
                    "indicator 1: the indicator \"192.0.2.1\" has a suppress_seconds of \
                     {seconds}; use 1 or more"
                )
            );
        }

        // Equal times, one time alone, a source, and a suppression time are valid.
        let mut valid = indicator(IndicatorKind::Ip, "192.0.2.1");
        valid.first_seen = at(5);
        valid.last_seen = at(5);
        valid.source = Some("a feed".to_owned());
        valid.suppress_seconds = Some(60);
        let mut only_last = indicator(IndicatorKind::Ip, "192.0.2.2");
        only_last.last_seen = at(5);
        let store = store(vec![valid, only_last]);
        assert_eq!(store.len(), 2);
        let matches = store.matches(&event("192.0.2.1"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, Some(TimeDelta::seconds(60)));
        let matches = store.matches(&event("192.0.2.2"));
        assert_eq!(matches[0].0, None);
    }

    #[test]
    fn an_indicator_file_with_the_optional_keys_round_trips_as_yaml_and_as_json() {
        let text = "indicators:\n  - type: client_fingerprint\n    value: fp-1\n    \
                    description: A client.\n    severity: medium\n    first_seen: \
                    \"2026-01-05T08:00:00Z\"\n    last_seen: 2026-01-06T17:30:00Z\n    source: \
                    a decoy\n    suppress_seconds: 3600\n  - type: ip\n    value: 192.0.2.1\n    \
                    description: An address.\n    severity: high\n";
        let indicators = indicators_from_yaml(text, "a.yml").unwrap();
        assert_eq!(indicators.len(), 2);
        let first = &indicators[0];
        assert_eq!(first.kind, IndicatorKind::ClientFingerprint);
        assert_eq!(
            first.first_seen.map(|time| time.to_rfc3339()).as_deref(),
            Some("2026-01-05T08:00:00+00:00")
        );
        assert_eq!(
            first.last_seen.map(|time| time.to_rfc3339()).as_deref(),
            Some("2026-01-06T17:30:00+00:00")
        );
        assert_eq!(first.source.as_deref(), Some("a decoy"));
        assert_eq!(first.suppress_seconds, Some(3_600));
        assert_eq!(
            indicators[1],
            Indicator::new(
                IndicatorKind::Ip,
                "192.0.2.1",
                "An address.",
                Severity::High
            )
        );

        let yaml = indicators_to_yaml(&indicators, "out.yml").unwrap();
        assert_eq!(indicators_from_yaml(&yaml, "out.yml").unwrap(), indicators);
        // An indicator with no optional key writes none of them.
        assert_eq!(yaml.matches("first_seen").count(), 1);
        assert_eq!(yaml.matches("suppress_seconds").count(), 1);
        let json = indicators_to_json(&indicators, "out.json").unwrap();
        assert_eq!(indicators_from_json(&json, "out.json").unwrap(), indicators);

        let bad_time = text.replace("2026-01-06T17:30:00Z", "yesterday");
        let error = indicators_from_yaml(&bad_time, "a.yml").unwrap_err();
        assert!(
            matches!(&error, DetectError::Indicator { file, .. } if file == "a.yml"),
            "{error}"
        );
    }

    #[test]
    fn the_masks_keep_the_network_bits() {
        assert_eq!(mask_v4(0xffff_ffff, 0), 0);
        assert_eq!(mask_v4(0xffff_ffff, 24), 0xffff_ff00);
        assert_eq!(mask_v4(0xffff_ffff, 32), 0xffff_ffff);
        assert_eq!(mask_v6(u128::MAX, 0), 0);
        assert_eq!(mask_v6(u128::MAX, 64), u128::MAX << 64);
        assert_eq!(mask_v6(u128::MAX, 128), u128::MAX);
    }
}
