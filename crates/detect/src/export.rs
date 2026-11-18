//! Indicator export: the detections of decoys become an indicator file.
//!
//! A client that contacts a decoy shows its address, its user agent, and its fingerprint.
//! [`export_decoy_indicators`] turns the detections of decoys into indicators in the format
//! of a rule pack. Each indicator has the time of the first and the last detection, and a
//! source note. [`indicators_to_yaml`](crate::ioc::indicators_to_yaml) writes the file, and
//! [`RulePack::load`](crate::pack::RulePack::load) reads it.
//!
//! Examine the file before you add it to a pack. A decoy shows what a client did. It does
//! not show who the client is: many clients can share one address or one user agent.
//! The export is thus careful by default:
//!
//! - No indicator has a severity above `medium`. A match is then `suspicious`, and tier 2
//!   examines it.
//! - A user agent indicator has the severity `low`.
//! - A user agent that starts with `Mozilla/` is not exported. Most browsers send it.
//! - Each indicator has a suppression time, so that one client gives one detection in
//!   that time.
//!
//! ```
//! use aegis_detect::export::{ExportOptions, export_decoy_indicators};
//! use aegis_detect::ioc::indicators_to_yaml;
//!
//! # fn example(detections: &[aegis_contracts::Detection]) -> Result<(), aegis_detect::DetectError> {
//! let indicators = export_decoy_indicators(detections, &ExportOptions::default())?;
//! let text = indicators_to_yaml(&indicators, "decoy.yml")?;
//! # let _ = text;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::net::IpAddr;

use aegis_contracts::common::{EntityKind, Severity};
use aegis_contracts::event::attr;
use aegis_contracts::{Detection, Verdict};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::common::{CLIENT_FINGERPRINT_PREFIX, canonical_ip, fingerprint_token};
use crate::error::DetectError;
use crate::ioc::{Indicator, IndicatorKind, MIN_USER_AGENT_LENGTH};

/// The key of the detection attribute that holds the user agent of the client.
pub const USER_AGENT_ATTRIBUTE: &str = "user_agent";

/// The key of the detection attribute that holds the decoy path that a client asked for.
pub const DECOY_PATH_ATTRIBUTE: &str = "decoy_path";

/// The source note that the export writes by default.
pub const DEFAULT_EXPORT_SOURCE: &str = "aegis decoy detections";

/// The start of a user agent that most browsers send.
const BROWSER_USER_AGENT_PREFIX: &str = "mozilla/";

/// The settings of [`export_decoy_indicators`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportOptions {
    /// The source note of each indicator.
    pub source: String,
    /// The largest severity of an indicator. An indicator gets the largest severity of its
    /// detections, but not more than this value.
    pub max_severity: Severity,
    /// The largest severity of a user agent indicator. Many clients can share one user
    /// agent.
    pub max_user_agent_severity: Severity,
    /// With `true`, the export also has the user agents that start with `Mozilla/`.
    pub browser_user_agents: bool,
    /// The addresses and the networks that the export never names, for example an
    /// approved scanner of the operator.
    pub excluded_networks: Vec<String>,
    /// The suppression time in seconds of each indicator. With `None`, each event that
    /// matches an indicator gives a detection.
    pub suppress_seconds: Option<u64>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            source: DEFAULT_EXPORT_SOURCE.to_owned(),
            max_severity: Severity::Medium,
            max_user_agent_severity: Severity::Low,
            browser_user_agents: false,
            excluded_networks: Vec::new(),
            suppress_seconds: Some(3_600),
        }
    }
}

/// Returns `true` if a detection comes from a decoy.
///
/// The engine marks such a detection with the attribute `decoy_id` (a decoy service) or
/// `decoy_path` (a decoy path of an endpoint). A `benign` detection is not from a decoy:
/// tier 2 found that the contact was normal.
#[must_use]
pub fn is_decoy_detection(detection: &Detection) -> bool {
    detection.verdict != Verdict::Benign
        && (detection.attributes.contains_key(attr::DECOY_ID)
            || detection.attributes.contains_key(DECOY_PATH_ATTRIBUTE))
}

/// What the export knows about one value.
struct Seen {
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    severity: Severity,
    detections: u64,
}

fn note(
    seen: &mut BTreeMap<(IndicatorKind, String), Seen>,
    key: (IndicatorKind, String),
    detection: &Detection,
) {
    let entry = seen.entry(key).or_insert(Seen {
        first: detection.time,
        last: detection.time,
        severity: detection.severity,
        detections: 0,
    });
    entry.first = entry.first.min(detection.time);
    entry.last = entry.last.max(detection.time);
    entry.severity = entry.severity.max(detection.severity);
    entry.detections = entry.detections.saturating_add(1);
}

/// Makes indicators from the detections of decoys.
///
/// The function uses only the detections for which [`is_decoy_detection`] is `true`. It
/// ignores all others, so you can give it all detections of an incident. Each value gives
/// one indicator:
///
/// | Value | Source in the detection | Indicator type |
/// | --- | --- | --- |
/// | Address | Each entity of the kind `ip_address` | `ip` |
/// | Client fingerprint | The entity or the attribute `client_fingerprint` | `client_fingerprint` |
/// | User agent | The attribute `user_agent` | `user_agent` |
///
/// Each indicator has `first_seen` and `last_seen` from the times of its detections, the
/// source note of the options, and the tags `attack.reconnaissance` and `attack.t1595`.
/// The indicators are in order of type and value. The same detections thus always give
/// the same indicators.
///
/// # Errors
///
/// Returns [`DetectError::Config`] if the source note is empty, if `suppress_seconds` is
/// zero, or if an excluded network is not an address or a network.
pub fn export_decoy_indicators(
    detections: &[Detection],
    options: &ExportOptions,
) -> Result<Vec<Indicator>, DetectError> {
    let source = options.source.trim();
    if source.is_empty() {
        return Err(DetectError::Config(
            "the source note of the indicator export is empty".to_owned(),
        ));
    }
    if options.suppress_seconds == Some(0) {
        return Err(DetectError::Config(
            "suppress_seconds of the indicator export must be 1 or more, but it is 0".to_owned(),
        ));
    }
    let excluded = options
        .excluded_networks
        .iter()
        .map(|text| {
            let text = text.trim();
            text.parse::<IpNet>()
                .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    DetectError::Config(format!(
                        "the excluded network {text:?} of the indicator export is not an \
                         address or a network"
                    ))
                })
        })
        .collect::<Result<Vec<IpNet>, DetectError>>()?;

    let mut seen: BTreeMap<(IndicatorKind, String), Seen> = BTreeMap::new();
    for detection in detections.iter().filter(|found| is_decoy_detection(found)) {
        for entity in &detection.entities {
            match entity.kind {
                EntityKind::IpAddress => {
                    let Ok(ip) = entity.id.parse::<IpAddr>() else {
                        continue;
                    };
                    let ip = canonical_ip(ip);
                    if !excluded.iter().any(|network| network.contains(&ip)) {
                        note(&mut seen, (IndicatorKind::Ip, ip.to_string()), detection);
                    }
                }
                EntityKind::Other => {
                    if let Some(token) = entity
                        .id
                        .strip_prefix(CLIENT_FINGERPRINT_PREFIX)
                        .and_then(fingerprint_token)
                    {
                        note(
                            &mut seen,
                            (IndicatorKind::ClientFingerprint, token),
                            detection,
                        );
                    }
                }
                _ => {}
            }
        }
        let text = |key: &str| {
            detection
                .attributes
                .get(key)
                .and_then(|value| value.as_str())
        };
        if let Some(token) = text(attr::CLIENT_FINGERPRINT).and_then(fingerprint_token) {
            let key = (IndicatorKind::ClientFingerprint, token);
            // The entity of the same fingerprint counted this detection.
            if !seen.contains_key(&key)
                || !detection.entities.iter().any(|entity| {
                    entity.id.strip_prefix(CLIENT_FINGERPRINT_PREFIX) == Some(key.1.as_str())
                })
            {
                note(&mut seen, key, detection);
            }
        }
        if let Some(user_agent) = text(USER_AGENT_ATTRIBUTE).map(str::trim) {
            let is_browser = user_agent
                .get(..BROWSER_USER_AGENT_PREFIX.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(BROWSER_USER_AGENT_PREFIX));
            if user_agent.chars().count() >= MIN_USER_AGENT_LENGTH
                && (options.browser_user_agents || !is_browser)
            {
                note(
                    &mut seen,
                    (IndicatorKind::UserAgent, user_agent.to_ascii_lowercase()),
                    detection,
                );
            }
        }
    }

    Ok(seen
        .into_iter()
        .map(|((kind, value), seen)| {
            let (what, limit) = match kind {
                IndicatorKind::Ip => ("at this address", options.max_severity),
                IndicatorKind::UserAgent => (
                    "with this user agent",
                    options.max_severity.min(options.max_user_agent_severity),
                ),
                _ => ("with this fingerprint", options.max_severity),
            };
            Indicator {
                kind,
                value,
                description: format!(
                    "A client {what} contacted a decoy. The source made {} for it.",
                    if seen.detections == 1 {
                        "1 detection".to_owned()
                    } else {
                        format!("{} detections", seen.detections)
                    }
                ),
                severity: seen.severity.min(limit),
                tags: vec![
                    "attack.reconnaissance".to_owned(),
                    "attack.t1595".to_owned(),
                ],
                verdict: None,
                id: None,
                first_seen: Some(seen.first),
                last_seen: Some(seen.last),
                source: Some(source.to_owned()),
                suppress_seconds: options.suppress_seconds,
            }
        })
        .collect())
}

/// Adds new indicators to the indicators of an existing file.
///
/// An indicator that the two lists have (the same type and the same value, with no
/// difference for case) stays one time. It keeps the text of the existing indicator. Its
/// `first_seen` is the older time, its `last_seen` is the newer time, and its severity is
/// the larger severity. All other new indicators come after the existing indicators.
///
/// Use this function to export again into a file that you loaded before. A pack must not
/// have one indicator two times.
#[must_use]
pub fn merge_indicators(existing: Vec<Indicator>, new: Vec<Indicator>) -> Vec<Indicator> {
    let key = |indicator: &Indicator| (indicator.kind, indicator.value.trim().to_lowercase());
    let mut merged = existing;
    for indicator in new {
        let found = key(&indicator);
        match merged.iter_mut().find(|known| key(known) == found) {
            Some(known) => {
                known.first_seen = match (known.first_seen, indicator.first_seen) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (left, right) => left.or(right),
                };
                known.last_seen = match (known.last_seen, indicator.last_seen) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (left, right) => left.or(right),
                };
                known.severity = known.severity.max(indicator.severity);
                if known.source.is_none() {
                    known.source = indicator.source;
                }
                if known.suppress_seconds.is_none() {
                    known.suppress_seconds = indicator.suppress_seconds;
                }
            }
            None => merged.push(indicator),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegis_contracts::DetectionTier;
    use aegis_contracts::common::{EntityRef, EventId};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::common::detection_id;
    use crate::ioc::IocStore;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_793_696_400 + seconds, 0).unwrap()
    }

    /// A detection of a decoy contact from an address, with a fingerprint and a user agent.
    fn decoy_detection(sequence: u32, seconds: i64, ip: &str, user_agent: &str) -> Detection {
        let event_ids = vec![EventId(Uuid::from_u128(u128::from(sequence)))];
        Detection {
            id: detection_id("decoy-contact", &event_ids),
            rule_id: "decoy-contact".to_owned(),
            title: "Client contacted a decoy".to_owned(),
            description: "A contact.".to_owned(),
            severity: Severity::Low,
            verdict: Verdict::Suspicious,
            tier: DetectionTier::Deterministic,
            time: at(seconds),
            attack: Vec::new(),
            event_ids,
            entities: vec![
                EntityRef::new(EntityKind::Other, "unknown"),
                EntityRef::new(EntityKind::IpAddress, ip),
                EntityRef::new(EntityKind::Other, "client_fingerprint:fp-1"),
            ],
            tenant: Some("tenant-1".to_owned()),
            attributes: BTreeMap::from([
                ("decoy_id".to_owned(), json!("maze-1")),
                ("client_fingerprint".to_owned(), json!("fp-1")),
                ("user_agent".to_owned(), json!(user_agent)),
            ]),
        }
    }

    fn summary(indicators: &[Indicator]) -> Vec<(IndicatorKind, &str, Severity)> {
        indicators
            .iter()
            .map(|indicator| (indicator.kind, indicator.value.as_str(), indicator.severity))
            .collect()
    }

    #[test]
    fn the_export_has_the_address_the_fingerprint_and_the_user_agent_of_a_decoy_client() {
        let detections = vec![
            decoy_detection(1, 100, "203.0.113.80", "Probe-Tool/1.0"),
            decoy_detection(2, 40, "203.0.113.80", "Probe-Tool/1.0"),
            decoy_detection(3, 250, "203.0.113.81", "Probe-Tool/1.0"),
        ];
        let indicators = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
        assert_eq!(
            summary(&indicators),
            [
                (IndicatorKind::Ip, "203.0.113.80", Severity::Low),
                (IndicatorKind::Ip, "203.0.113.81", Severity::Low),
                (IndicatorKind::UserAgent, "probe-tool/1.0", Severity::Low),
                (IndicatorKind::ClientFingerprint, "fp-1", Severity::Low),
            ]
        );
        let address = &indicators[0];
        assert_eq!(address.first_seen, Some(at(40)));
        assert_eq!(address.last_seen, Some(at(100)));
        assert_eq!(address.source.as_deref(), Some("aegis decoy detections"));
        assert_eq!(address.suppress_seconds, Some(3_600));
        assert_eq!(address.verdict, None);
        assert_eq!(address.id, None);
        assert_eq!(address.tags, ["attack.reconnaissance", "attack.t1595"]);
        assert_eq!(
            address.description,
            "A client at this address contacted a decoy. The source made 2 detections for it."
        );
        assert_eq!(
            indicators[1].description,
            "A client at this address contacted a decoy. The source made 1 detection for it."
        );
        // The fingerprint and the user agent are in all three detections.
        let fingerprint = &indicators[3];
        assert_eq!(fingerprint.first_seen, Some(at(40)));
        assert_eq!(fingerprint.last_seen, Some(at(250)));
        assert_eq!(
            fingerprint.description,
            "A client with this fingerprint contacted a decoy. The source made 3 detections \
             for it."
        );
        assert_eq!(
            indicators[2].description,
            "A client with this user agent contacted a decoy. The source made 3 detections \
             for it."
        );
        // The indicators are a valid set for a pack.
        assert_eq!(IocStore::new(indicators).unwrap().len(), 4);
    }

    #[test]
    fn only_the_detections_of_decoys_give_indicators() {
        let mut normal = decoy_detection(1, 0, "198.51.100.10", "office-tool/2.0");
        normal.attributes.remove("decoy_id");
        assert!(!is_decoy_detection(&normal));
        let mut benign = decoy_detection(2, 0, "198.51.100.11", "office-tool/2.0");
        benign.verdict = Verdict::Benign;
        assert!(!is_decoy_detection(&benign));
        let mut decoy_path = decoy_detection(3, 0, "203.0.113.90", "scan/1.0");
        decoy_path.attributes.remove("decoy_id");
        decoy_path
            .attributes
            .insert(DECOY_PATH_ATTRIBUTE.to_owned(), json!("/.env"));
        assert!(is_decoy_detection(&decoy_path));

        let indicators =
            export_decoy_indicators(&[normal, benign, decoy_path], &ExportOptions::default())
                .unwrap();
        assert_eq!(
            summary(&indicators),
            [
                (IndicatorKind::Ip, "203.0.113.90", Severity::Low),
                (IndicatorKind::UserAgent, "scan/1.0", Severity::Low),
                (IndicatorKind::ClientFingerprint, "fp-1", Severity::Low),
            ]
        );
        assert_eq!(
            export_decoy_indicators(&[], &ExportOptions::default()).unwrap(),
            []
        );
    }

    #[test]
    fn the_severity_is_the_largest_of_the_detections_up_to_the_limit() {
        let low = decoy_detection(1, 0, "203.0.113.80", "probe/1.0");
        let mut critical = decoy_detection(2, 10, "203.0.113.80", "probe/1.0");
        critical.severity = Severity::Critical;
        let detections = [low, critical];
        // The default limit is medium, and low for a user agent.
        let default = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
        assert_eq!(
            summary(&default),
            [
                (IndicatorKind::Ip, "203.0.113.80", Severity::Medium),
                (IndicatorKind::UserAgent, "probe/1.0", Severity::Low),
                (IndicatorKind::ClientFingerprint, "fp-1", Severity::Medium),
            ]
        );
        let options = ExportOptions {
            max_severity: Severity::High,
            max_user_agent_severity: Severity::Critical,
            ..ExportOptions::default()
        };
        let raised = export_decoy_indicators(&detections, &options).unwrap();
        assert_eq!(
            summary(&raised),
            [
                (IndicatorKind::Ip, "203.0.113.80", Severity::High),
                // The limit for all indicators also applies to a user agent.
                (IndicatorKind::UserAgent, "probe/1.0", Severity::High),
                (IndicatorKind::ClientFingerprint, "fp-1", Severity::High),
            ]
        );
    }

    #[test]
    fn a_browser_user_agent_and_a_short_user_agent_are_not_exported() {
        let browser = decoy_detection(
            1,
            0,
            "203.0.113.80",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        );
        let short = decoy_detection(2, 0, "203.0.113.81", "ab");
        let detections = [browser, short];
        let kinds = |indicators: &[Indicator]| -> Vec<IndicatorKind> {
            indicators.iter().map(|indicator| indicator.kind).collect()
        };
        let default = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
        assert_eq!(
            kinds(&default),
            [
                IndicatorKind::Ip,
                IndicatorKind::Ip,
                IndicatorKind::ClientFingerprint
            ]
        );
        let options = ExportOptions {
            browser_user_agents: true,
            ..ExportOptions::default()
        };
        let with_browser = export_decoy_indicators(&detections, &options).unwrap();
        assert_eq!(
            summary(&with_browser)[2],
            (
                IndicatorKind::UserAgent,
                "mozilla/5.0 (x11; linux x86_64) applewebkit/537.36",
                Severity::Low
            )
        );
        assert_eq!(with_browser.len(), 4);
    }

    #[test]
    fn an_excluded_network_and_an_address_that_is_not_valid_are_not_exported() {
        let mut detections = vec![
            decoy_detection(1, 0, "203.0.113.80", "probe/1.0"),
            decoy_detection(2, 0, "198.51.100.77", "probe/1.0"),
            decoy_detection(3, 0, "not an address", "probe/1.0"),
            decoy_detection(4, 0, "::ffff:198.51.100.78", "probe/1.0"),
        ];
        for detection in &mut detections {
            detection.attributes.remove("user_agent");
            detection.attributes.remove("client_fingerprint");
            detection
                .entities
                .retain(|entity| entity.kind == EntityKind::IpAddress);
        }
        let options = ExportOptions {
            excluded_networks: vec!["198.51.100.0/24".to_owned(), " 192.0.2.1 ".to_owned()],
            ..ExportOptions::default()
        };
        let indicators = export_decoy_indicators(&detections, &options).unwrap();
        assert_eq!(
            summary(&indicators),
            [(IndicatorKind::Ip, "203.0.113.80", Severity::Low)]
        );
        // With no exclusion, the mapped address has its IPv4 form.
        let all = export_decoy_indicators(&detections, &ExportOptions::default()).unwrap();
        let values: Vec<&str> = all
            .iter()
            .map(|indicator| indicator.value.as_str())
            .collect();
        assert_eq!(values, ["198.51.100.77", "198.51.100.78", "203.0.113.80"]);
    }

    #[test]
    fn a_fingerprint_that_is_only_an_attribute_or_only_an_entity_is_exported_one_time() {
        let mut only_attribute = decoy_detection(1, 0, "203.0.113.80", "probe/1.0");
        only_attribute.entities.truncate(2);
        let mut only_entity = decoy_detection(2, 10, "203.0.113.80", "probe/1.0");
        only_entity.attributes.remove("client_fingerprint");
        let indicators =
            export_decoy_indicators(&[only_attribute, only_entity], &ExportOptions::default())
                .unwrap();
        let fingerprints: Vec<&Indicator> = indicators
            .iter()
            .filter(|indicator| indicator.kind == IndicatorKind::ClientFingerprint)
            .collect();
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, "fp-1");
        assert_eq!(
            fingerprints[0].description,
            "A client with this fingerprint contacted a decoy. The source made 2 detections \
             for it."
        );
        // The actor entity `unknown` has the kind `other`, but it is not a fingerprint.
        assert!(
            indicators
                .iter()
                .all(|indicator| indicator.value != "unknown")
        );
    }

    #[test]
    fn options_that_are_not_valid_are_errors() {
        let detections = [decoy_detection(1, 0, "203.0.113.80", "probe/1.0")];
        let cases = [
            (
                ExportOptions {
                    source: "  ".to_owned(),
                    ..ExportOptions::default()
                },
                "the source note of the indicator export is empty",
            ),
            (
                ExportOptions {
                    suppress_seconds: Some(0),
                    ..ExportOptions::default()
                },
                "suppress_seconds of the indicator export must be 1 or more, but it is 0",
            ),
            (
                ExportOptions {
                    excluded_networks: vec!["office".to_owned()],
                    ..ExportOptions::default()
                },
                "the excluded network \"office\" of the indicator export is not an address or a \
                 network",
            ),
        ];
        for (options, expected) in cases {
            let error = export_decoy_indicators(&detections, &options).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
        // With no suppression time, the indicators have none.
        let options = ExportOptions {
            suppress_seconds: None,
            source: " my export ".to_owned(),
            ..ExportOptions::default()
        };
        let indicators = export_decoy_indicators(&detections, &options).unwrap();
        assert_eq!(indicators[0].suppress_seconds, None);
        assert_eq!(indicators[0].source.as_deref(), Some("my export"));
    }

    #[test]
    fn the_options_read_from_a_partial_map_and_reject_unknown_keys() {
        let options: ExportOptions =
            serde_json::from_value(json!({ "max_severity": "high", "suppress_seconds": null }))
                .unwrap();
        assert_eq!(options.max_severity, Severity::High);
        assert_eq!(options.suppress_seconds, None);
        assert_eq!(options.source, DEFAULT_EXPORT_SOURCE);
        assert_eq!(
            serde_json::from_value::<ExportOptions>(json!({})).unwrap(),
            ExportOptions::default()
        );
        assert!(serde_json::from_value::<ExportOptions>(json!({ "sources": [] })).is_err());
    }

    #[test]
    fn merge_keeps_the_existing_text_and_the_widest_times() {
        let mut existing = Indicator::new(
            IndicatorKind::Ip,
            "203.0.113.80",
            "The operator wrote this text.",
            Severity::Low,
        );
        existing.first_seen = Some(at(100));
        existing.last_seen = Some(at(200));
        existing.id = Some("my-id".to_owned());
        let untouched = Indicator::new(
            IndicatorKind::Domain,
            "bad.example",
            "A domain.",
            Severity::High,
        );

        let mut newer = Indicator::new(
            IndicatorKind::Ip,
            " 203.0.113.80 ",
            "A client at this address contacted a decoy.",
            Severity::Medium,
        );
        newer.first_seen = Some(at(50));
        newer.last_seen = Some(at(900));
        newer.source = Some("aegis decoy detections".to_owned());
        newer.suppress_seconds = Some(3_600);
        let added = Indicator::new(
            IndicatorKind::ClientFingerprint,
            "fp-1",
            "A fingerprint.",
            Severity::Medium,
        );

        let merged = merge_indicators(
            vec![existing, untouched.clone()],
            vec![newer, added.clone()],
        );
        assert_eq!(merged.len(), 3);
        let first = &merged[0];
        assert_eq!(first.value, "203.0.113.80");
        assert_eq!(first.description, "The operator wrote this text.");
        assert_eq!(first.id.as_deref(), Some("my-id"));
        assert_eq!(first.severity, Severity::Medium);
        assert_eq!(first.first_seen, Some(at(50)));
        assert_eq!(first.last_seen, Some(at(900)));
        assert_eq!(first.source.as_deref(), Some("aegis decoy detections"));
        assert_eq!(first.suppress_seconds, Some(3_600));
        assert_eq!(merged[1], untouched);
        assert_eq!(merged[2], added);
        // The merged list is a valid set: no indicator is there two times.
        assert_eq!(IocStore::new(merged).unwrap().len(), 3);
    }

    #[test]
    fn merge_takes_the_time_that_one_side_has() {
        let mut existing =
            Indicator::new(IndicatorKind::Ip, "203.0.113.80", "Text.", Severity::High);
        existing.last_seen = Some(at(10));
        existing.source = Some("a feed".to_owned());
        let mut newer = Indicator::new(IndicatorKind::Ip, "203.0.113.80", "New.", Severity::Low);
        newer.first_seen = Some(at(5));
        newer.source = Some("aegis decoy detections".to_owned());
        let merged = merge_indicators(vec![existing], vec![newer]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].first_seen, Some(at(5)));
        assert_eq!(merged[0].last_seen, Some(at(10)));
        assert_eq!(merged[0].severity, Severity::High);
        assert_eq!(merged[0].source.as_deref(), Some("a feed"));
        assert_eq!(merged[0].suppress_seconds, None);
    }
}
