//! The indicator export: which values it gives, and the rules of the STIX and CSV forms.
//!
//! The default policy leaves out each reserved range and each documentation range. The
//! tests of that policy thus need public addresses. They use addresses of well-known
//! public services as stand-ins. No test sends a document.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, action, attr};
use aegis_contracts::{AttackTechnique, Detection, Verdict};
use aegis_share::{
    AddressPolicy, CSV_HEADER, DEFAULT_NAMESPACE, Indicator, IndicatorBasis, IndicatorKind,
    IndicatorOptions, IndicatorSet, ShareError, SkipReason, StixOptions, Tlp,
};
use aegis_testkit::fixtures;
use chrono::{DateTime, TimeDelta};
use serde_json::{Value, json};
use uuid::Uuid;

const SCRIPT_USER_AGENT: &str = "python-httpx/0.27.0";
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

/// The tactics of ATT&CK, for the check of the kill chain phases.
const TACTICS: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

fn with_documentation() -> IndicatorOptions {
    IndicatorOptions::new().with_addresses(AddressPolicy::new().with_documentation_ranges())
}

fn stix_options() -> StixOptions {
    StixOptions::new(Tlp::Amber, support::report_time())
}

/// Makes an event with the action `name` from an actor with an optional address.
fn event(number: u128, seconds: i64, name: &str, ip: Option<&str>) -> Event {
    let mut actor = Actor::new(EntityKind::Host, format!("host-{number}"));
    if let Some(ip) = ip {
        actor = actor.with_ip(ip.parse().unwrap());
    }
    Event::new(
        support::at(seconds),
        EventSource::new("sensor", "example", "sensor"),
        EventClass::NetworkActivity,
        name,
        actor,
    )
    .with_id(support::event_id(number))
}

fn malicious(number: u128, seconds: i64, events: &[&Event], entities: Vec<EntityRef>) -> Detection {
    support::detection(number, Verdict::Malicious, seconds, events, entities)
}

fn values(set: &IndicatorSet, kind: IndicatorKind) -> Vec<&str> {
    set.of_kind(kind)
        .map(|indicator| indicator.value.as_str())
        .collect()
}

fn skipped(set: &IndicatorSet) -> Vec<(Option<IndicatorKind>, &str, SkipReason)> {
    set.skipped
        .iter()
        .map(|skipped| (skipped.kind, skipped.value.as_str(), skipped.reason))
        .collect()
}

// ---------------------------------------------------------------------------------------
// An independent check of the STIX 2.1 rules for the objects that the export makes.
// ---------------------------------------------------------------------------------------

/// Checks a STIX timestamp: RFC 3339 in UTC with the letter `Z`.
fn stix_time(value: &Value) -> DateTime<chrono::Utc> {
    let text = value.as_str().expect("a timestamp is a string");
    let bytes = text.as_bytes();
    assert!(text.len() == 20 || text.len() == 24, "{text}");
    assert_eq!(bytes[4], b'-', "{text}");
    assert_eq!(bytes[7], b'-', "{text}");
    assert_eq!(bytes[10], b'T', "{text}");
    assert_eq!(bytes[13], b':', "{text}");
    assert_eq!(bytes[16], b':', "{text}");
    assert!(text.ends_with('Z'), "{text}");
    DateTime::parse_from_rfc3339(text)
        .unwrap_or_else(|error| panic!("{text}: {error}"))
        .to_utc()
}

/// Checks a STIX identifier: the object type, two hyphens, and a UUID of RFC 4122.
fn stix_id(value: &Value, kind: &str) -> Uuid {
    let text = value.as_str().expect("an identifier is a string");
    let (prefix, uuid_text) = text
        .split_once("--")
        .expect("an identifier has two hyphens");
    assert_eq!(prefix, kind, "{text}");
    assert_eq!(uuid_text.len(), 36, "{text}");
    assert_eq!(uuid_text, uuid_text.to_lowercase(), "{text}");
    let uuid = Uuid::parse_str(uuid_text).unwrap_or_else(|error| panic!("{text}: {error}"));
    assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122, "{text}");
    uuid
}

/// Parses one property name of an object path: plain, or in apostrophes.
fn path_parts(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = path;
    loop {
        if let Some(quoted) = rest.strip_prefix('\'') {
            let end = quoted.find('\'').expect("a quoted name has an end");
            let name = &quoted[..end];
            assert!(!name.is_empty() && !name.contains('\\'), "{path}");
            parts.push(name.to_owned());
            rest = &quoted[end + 1..];
        } else {
            let end = rest.find('.').unwrap_or(rest.len());
            let name = &rest[..end];
            // A plain name has no hyphen and no full stop.
            assert!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                    && !name.starts_with(|character: char| character.is_ascii_digit()),
                "{path}"
            );
            parts.push(name.to_owned());
            rest = &rest[end..];
        }
        match rest.strip_prefix('.') {
            Some(next) => rest = next,
            None => {
                assert!(rest.is_empty(), "{path}");
                return parts;
            }
        }
    }
}

/// Parses a pattern with one comparison: `[type:path = 'string']`.
///
/// Returns the object type, the property names, and the value of the string constant.
fn parse_pattern(pattern: &str) -> (String, Vec<String>, String) {
    let inner = pattern
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or_else(|| panic!("no brackets: {pattern}"));
    let (object_path, constant) = inner
        .split_once(" = ")
        .unwrap_or_else(|| panic!("no comparison: {pattern}"));
    let (object_type, path) = object_path
        .split_once(':')
        .unwrap_or_else(|| panic!("no object type: {pattern}"));
    assert!(
        !object_type.is_empty()
            && object_type
                .chars()
                .all(|character| character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '-'),
        "{pattern}"
    );
    // The string constant: apostrophes around the text. A backslash comes only before an
    // apostrophe or a backslash.
    let body = constant
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or_else(|| panic!("no string constant: {pattern}"));
    let mut value = String::new();
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let next = characters.next().expect("a backslash has a next character");
                assert!(matches!(next, '\'' | '\\'), "bad escape in {pattern}");
                value.push(next);
            }
            '\'' => panic!("an apostrophe with no backslash in {pattern}"),
            other => value.push(other),
        }
    }
    (object_type.to_owned(), path_parts(path), value)
}

fn check_domain(name: &str) {
    assert!(name.len() <= 253, "{name}");
    let labels: Vec<&str> = name.split('.').collect();
    assert!(labels.len() >= 2, "{name}");
    for label in labels {
        assert!(
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'
                    || byte == b'_'),
            "{name}"
        );
    }
}

/// Checks the pattern of one indicator and returns the type and the value.
fn check_pattern(pattern: &str) -> (IndicatorKind, String) {
    let (object_type, path, value) = parse_pattern(pattern);
    let kind = match (object_type.as_str(), path.as_slice()) {
        ("ipv4-addr", [property]) if property == "value" => {
            let address: Ipv4Addr = value.parse().unwrap_or_else(|_| panic!("{pattern}"));
            assert_eq!(address.to_string(), value);
            IndicatorKind::Ipv4
        }
        ("ipv6-addr", [property]) if property == "value" => {
            let address: Ipv6Addr = value.parse().unwrap_or_else(|_| panic!("{pattern}"));
            assert_eq!(address.to_string(), value);
            IndicatorKind::Ipv6
        }
        ("domain-name", [property]) if property == "value" => {
            check_domain(&value);
            IndicatorKind::Domain
        }
        ("network-traffic", [extensions, extension, header, name])
            if extensions == "extensions"
                && extension == "http-request-ext"
                && header == "request_header"
                && name == "User-Agent" =>
        {
            assert!(!value.is_empty());
            IndicatorKind::UserAgent
        }
        _ => panic!("the export does not make this pattern: {pattern}"),
    };
    (kind, value)
}

fn keys(object: &Value) -> BTreeSet<&str> {
    object
        .as_object()
        .expect("a STIX object is a JSON object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// Checks a bundle against the rules of STIX 2.1 and returns the indicator objects.
fn check_bundle(bundle: &Value, tlp: Tlp) -> Vec<&Value> {
    assert_eq!(keys(bundle), BTreeSet::from(["type", "id", "objects"]));
    assert_eq!(bundle["type"], "bundle");
    assert_eq!(stix_id(&bundle["id"], "bundle").get_version_num(), 5);
    let objects = bundle["objects"].as_array().expect("objects is an array");
    assert!(!objects.is_empty());

    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut uuids: BTreeSet<Uuid> = BTreeSet::new();
    for object in objects {
        let kind = object["type"].as_str().expect("an object has a type");
        let uuid = stix_id(&object["id"], kind);
        assert!(ids.insert(object["id"].as_str().unwrap()), "a repeated id");
        // A producer must not use one UUID for two objects.
        assert!(uuids.insert(uuid), "a repeated UUID");
        assert_eq!(object["spec_version"], "2.1");
    }
    assert!(uuids.insert(stix_id(&bundle["id"], "bundle")));

    // The marking definition is the object that the specification gives.
    let markings: Vec<&Value> = objects
        .iter()
        .filter(|object| object["type"] == "marking-definition")
        .collect();
    assert_eq!(markings.len(), 1);
    assert_eq!(markings[0], &tlp.marking_definition());
    assert_eq!(markings[0]["definition_type"], "tlp");
    assert_eq!(
        stix_time(&markings[0]["created"]).to_rfc3339(),
        "2017-01-20T00:00:00+00:00"
    );

    let identities: Vec<&Value> = objects
        .iter()
        .filter(|object| object["type"] == "identity")
        .collect();
    assert!(identities.len() <= 1);
    for identity in &identities {
        for required in ["type", "spec_version", "id", "created", "modified", "name"] {
            assert!(
                identity.get(required).is_some(),
                "identity has no {required}"
            );
        }
        assert_eq!(
            stix_time(&identity["created"]),
            stix_time(&identity["modified"])
        );
        assert!(!identity["name"].as_str().unwrap().is_empty());
    }

    let indicators: Vec<&Value> = objects
        .iter()
        .filter(|object| object["type"] == "indicator")
        .collect();
    assert_eq!(
        markings.len() + identities.len() + indicators.len(),
        objects.len()
    );
    let permitted: BTreeSet<&str> = [
        "type",
        "spec_version",
        "id",
        "created",
        "modified",
        "created_by_ref",
        "name",
        "description",
        "indicator_types",
        "pattern",
        "pattern_type",
        "pattern_version",
        "valid_from",
        "valid_until",
        "kill_chain_phases",
        "external_references",
        "object_marking_refs",
    ]
    .into();
    for indicator in &indicators {
        let found = keys(indicator);
        for required in [
            "type",
            "spec_version",
            "id",
            "created",
            "modified",
            "pattern",
            "pattern_type",
            "valid_from",
        ] {
            assert!(found.contains(required), "indicator has no {required}");
        }
        assert!(found.is_subset(&permitted), "{found:?}");
        assert_eq!(stix_id(&indicator["id"], "indicator").get_version_num(), 5);
        let created = stix_time(&indicator["created"]);
        assert!(stix_time(&indicator["modified"]) >= created);
        assert_eq!(indicator["pattern_type"], "stix");
        assert_eq!(indicator["pattern_version"], "2.1");
        check_pattern(indicator["pattern"].as_str().unwrap());
        let valid_from = stix_time(&indicator["valid_from"]);
        if let Some(valid_until) = indicator.get("valid_until") {
            assert!(stix_time(valid_until) > valid_from);
        }
        let types = indicator["indicator_types"].as_array().unwrap();
        assert_eq!(types.len(), 1);
        assert!(["malicious-activity", "anomalous-activity"].contains(&types[0].as_str().unwrap()));
        for name in ["name", "description"] {
            assert!(!indicator[name].as_str().unwrap().is_empty());
        }
        if let Some(phases) = indicator.get("kill_chain_phases") {
            let phases = phases.as_array().unwrap();
            assert!(!phases.is_empty());
            for phase in phases {
                assert_eq!(
                    keys(phase),
                    BTreeSet::from(["kill_chain_name", "phase_name"])
                );
                assert_eq!(phase["kill_chain_name"], "mitre-attack");
                assert!(TACTICS.contains(&phase["phase_name"].as_str().unwrap()));
            }
        }
        if let Some(references) = indicator.get("external_references") {
            let references = references.as_array().unwrap();
            assert!(!references.is_empty());
            for reference in references {
                assert_eq!(reference["source_name"], "mitre-attack");
                let id = reference["external_id"].as_str().unwrap();
                assert!(id.starts_with('T') && id.len() >= 5, "{id}");
                assert!(
                    reference["url"]
                        .as_str()
                        .unwrap()
                        .starts_with("https://attack.mitre.org/techniques/T")
                );
            }
        }
        // Each reference of the object points at an object in the bundle.
        let marking_refs = indicator["object_marking_refs"].as_array().unwrap();
        assert_eq!(marking_refs, &[json!(tlp.marking_id())]);
        assert!(ids.contains(tlp.marking_id()));
        if let Some(creator) = indicator.get("created_by_ref") {
            assert!(ids.contains(creator.as_str().unwrap()));
            assert_eq!(creator, &identities[0]["id"]);
        }
    }
    indicators
}

// ---------------------------------------------------------------------------------------
// An independent parser of RFC 4180 CSV.
// ---------------------------------------------------------------------------------------

fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if quoted {
            match character {
                '"' if characters.peek() == Some(&'"') => {
                    characters.next();
                    field.push('"');
                }
                '"' => {
                    quoted = false;
                    assert!(
                        matches!(characters.peek(), None | Some(',') | Some('\r')),
                        "text after a closing quote"
                    );
                }
                other => field.push(other),
            }
            continue;
        }
        match character {
            '"' => {
                assert!(field.is_empty(), "a quote in the middle of a field");
                quoted = true;
            }
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {
                assert_eq!(characters.next(), Some('\n'), "CR with no LF");
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            '\n' => panic!("LF with no CR"),
            other => field.push(other),
        }
    }
    assert!(!quoted, "a quoted field has no end");
    assert!(
        field.is_empty() && record.is_empty(),
        "the last line has no CR LF"
    );
    records
}

// ---------------------------------------------------------------------------------------
// The recorded attack log.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_attack_log_gives_the_three_attacker_addresses_and_the_script_user_agent() {
    let (incident, events) = support::attack_incident().await;
    let set = IndicatorSet::collect(&incident.detections, &events, &with_documentation()).unwrap();
    assert_eq!(set.skipped, []);
    assert_eq!(
        values(&set, IndicatorKind::Ipv4),
        ["192.0.2.77", "203.0.113.50", "203.0.113.51"]
    );
    assert_eq!(values(&set, IndicatorKind::Ipv6), Vec::<&str>::new());
    assert_eq!(values(&set, IndicatorKind::Domain), Vec::<&str>::new());
    assert_eq!(values(&set, IndicatorKind::UserAgent), [SCRIPT_USER_AGENT]);
    assert_eq!(set.indicators.len(), 4);

    let spray = &set.indicators[1];
    assert_eq!(spray.kind, IndicatorKind::Ipv4);
    assert_eq!(spray.basis, IndicatorBasis::MaliciousActivity);
    // Ten cited records of the burst, the sign-in, the grant, and the credential.
    assert_eq!(spray.events, 13);
    assert_eq!(spray.detections, 4);
    assert_eq!(spray.first_seen, support::at(600));
    assert_eq!(spray.last_seen, support::at(640));
    let techniques: Vec<&str> = spray
        .techniques
        .iter()
        .map(|technique| technique.id.as_str())
        .collect();
    assert_eq!(techniques, ["T1078", "T1098.001", "T1110.003", "T1528"]);

    // No address and no user agent of normal activity is in an output or in a note.
    let stix = set.to_stix_string(&stix_options()).unwrap();
    let csv = set.to_csv(Tlp::Amber);
    let notes = serde_json::to_string(&set).unwrap();
    let normal_addresses: BTreeSet<String> = events
        .iter()
        .filter_map(|event| event.actor.ip)
        .filter(|address| {
            ![
                fixtures::SPRAY_IP,
                fixtures::WORKLOAD_IP,
                fixtures::DISTANT_IP,
            ]
            .contains(address)
        })
        .map(|address| address.to_string())
        .collect();
    assert_eq!(
        normal_addresses,
        BTreeSet::from([
            "198.51.100.10".to_owned(),
            "198.51.100.11".to_owned(),
            "198.51.100.12".to_owned(),
            "198.51.100.20".to_owned(),
        ])
    );
    for (name, text) in [("stix", &stix), ("csv", &csv), ("notes", &notes)] {
        for address in &normal_addresses {
            assert!(!text.contains(address.as_str()), "{address} is in {name}");
        }
        assert!(
            !text.contains("Mozilla"),
            "the browser user agent is in {name}"
        );
        // The export has no internal name of the operator.
        for internal in [
            "user-",
            "contoso",
            "fabrikam",
            "sync-helper",
            "Sync Helper",
            "kv-prod",
            "honeytoken",
        ] {
            assert!(!text.contains(internal), "{internal} is in {name}");
        }
    }
}

#[tokio::test]
async fn the_default_options_give_no_value_from_a_documentation_range() {
    let (incident, events) = support::attack_incident().await;
    let set =
        IndicatorSet::collect(&incident.detections, &events, &IndicatorOptions::new()).unwrap();
    assert_eq!(set.indicators, []);
    assert_eq!(
        skipped(&set),
        [
            (
                Some(IndicatorKind::Ipv4),
                "192.0.2.77",
                SkipReason::DocumentationAddress
            ),
            (
                Some(IndicatorKind::Ipv4),
                "203.0.113.50",
                SkipReason::DocumentationAddress
            ),
            (
                Some(IndicatorKind::Ipv4),
                "203.0.113.51",
                SkipReason::DocumentationAddress
            ),
            (
                Some(IndicatorKind::UserAgent),
                SCRIPT_USER_AGENT,
                SkipReason::NoShareableClient
            ),
        ]
    );
    let bundle = set.to_stix(&stix_options()).unwrap();
    assert_eq!(check_bundle(&bundle, Tlp::Amber).len(), 0);
    assert_eq!(bundle["objects"].as_array().unwrap().len(), 1);
    assert_eq!(set.to_csv(Tlp::Amber), format!("{CSV_HEADER}\r\n"));
}

#[tokio::test]
async fn the_stix_indicator_of_the_spray_address_is_the_known_answer() {
    let (incident, events) = support::attack_incident().await;
    let set = IndicatorSet::collect(&incident.detections, &events, &with_documentation()).unwrap();
    let bundle = set.to_stix(&stix_options()).unwrap();
    let indicators = check_bundle(&bundle, Tlp::Amber);
    assert_eq!(indicators.len(), 4);
    // The identifier is the version 5 UUID that Python gives:
    // uuid.uuid5(uuid.UUID("43649b42-ff78-4a03-a600-442429b79dce"),
    //            "indicator:[ipv4-addr:value = '203.0.113.50']")
    assert_eq!(
        indicators[1],
        &json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--4d9e67a8-e7b7-5a11-9ad8-042e935fd6e0",
            "created": "2026-11-03T10:00:00.000Z",
            "modified": "2026-11-03T10:00:00.000Z",
            "name": "IPv4 address 203.0.113.50",
            "description": "The producer saw this value in activity that its detection rules \
                            classified as malicious, or in the use of a decoy credential. Log \
                            records: 13. Detections: 4. The data does not identify a person or \
                            a group.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '203.0.113.50']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-11-03T09:10:00.000Z",
            "valid_until": "2026-12-03T09:10:40.000Z",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1078",
                    "url": "https://attack.mitre.org/techniques/T1078/",
                },
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1098.001",
                    "url": "https://attack.mitre.org/techniques/T1098/001/",
                },
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1110.003",
                    "url": "https://attack.mitre.org/techniques/T1110/003/",
                },
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1528",
                    "url": "https://attack.mitre.org/techniques/T1528/",
                },
            ],
            "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
        })
    );
    assert_eq!(
        bundle["objects"][0],
        json!({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": "TLP:AMBER",
            "definition": {"tlp": "amber"},
        })
    );
}

#[tokio::test]
async fn the_identifiers_are_the_same_in_each_run_and_for_each_input_order() {
    let (incident, events) = support::attack_incident().await;
    let options = with_documentation();
    let first = IndicatorSet::collect(&incident.detections, &events, &options).unwrap();
    let first_text = first.to_stix_string(&stix_options()).unwrap();
    assert_eq!(first.to_stix_string(&stix_options()).unwrap(), first_text);

    let mut detections = incident.detections.clone();
    detections.reverse();
    detections.push(incident.detections[0].clone());
    let mut reversed = events.clone();
    reversed.reverse();
    reversed.extend(events.iter().take(40).cloned());
    let second = IndicatorSet::collect(&detections, &reversed, &options).unwrap();
    assert_eq!(second, first);
    assert_eq!(second.to_stix_string(&stix_options()).unwrap(), first_text);
    assert_eq!(second.to_csv(Tlp::Amber), first.to_csv(Tlp::Amber));

    let ids = |bundle: &Value| -> Vec<String> {
        bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| object["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let bundle = first.to_stix(&stix_options()).unwrap();
    assert_eq!(ids(&bundle).len(), 5);

    // The identifier of an indicator comes from its pattern. A later export gives the
    // same identifier to the same indicator, and a new identifier to the bundle.
    let mut later_options = stix_options();
    later_options.generated_at += TimeDelta::days(1);
    let later = first.to_stix(&later_options).unwrap();
    assert_eq!(ids(&later), ids(&bundle));
    assert_ne!(later["id"], bundle["id"]);

    // A different namespace gives different identifiers.
    let other = first
        .to_stix(&stix_options().with_namespace(Uuid::from_u128(0x1234)))
        .unwrap();
    check_bundle(&other, Tlp::Amber);
    assert_eq!(ids(&other)[0], ids(&bundle)[0]);
    for (left, right) in ids(&other).iter().zip(ids(&bundle)).skip(1) {
        assert_ne!(*left, right);
    }

    // The recipe of the identifiers: a version 5 UUID of the type and the pattern.
    let pattern = "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'python-httpx/0.27.0']";
    let expected = Uuid::new_v5(
        &DEFAULT_NAMESPACE,
        format!("indicator:{pattern}").as_bytes(),
    );
    assert_eq!(ids(&bundle)[4], format!("indicator--{expected}"));
}

// ---------------------------------------------------------------------------------------
// The rules for the values.
// ---------------------------------------------------------------------------------------

#[test]
fn a_private_a_reserved_and_an_operator_address_are_never_exported() {
    let names = [
        "8.8.8.8",
        "8.8.4.4",
        "10.0.0.5",
        "100.64.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "224.0.0.1",
        "::ffff:10.0.0.6",
        "::ffff:8.8.4.5",
        "2606:4700:4700::1111",
        "fd00::1",
        "fe80::1",
        "::1",
        "203.0.113.9",
        "2001:db8::9",
        "not-an-address",
    ];
    let entities: Vec<EntityRef> = names.iter().map(|name| support::ip_entity(name)).collect();
    let detection = malicious(1, 600, &[], entities);
    let options = IndicatorOptions::new()
        .with_addresses(AddressPolicy::new().with_operator_network("8.8.4.0/24".parse().unwrap()));
    let set = IndicatorSet::collect(std::slice::from_ref(&detection), &[], &options).unwrap();

    assert_eq!(values(&set, IndicatorKind::Ipv4), ["8.8.8.8"]);
    assert_eq!(values(&set, IndicatorKind::Ipv6), ["2606:4700:4700::1111"]);
    assert_eq!(set.indicators.len(), 2);
    let v4 = Some(IndicatorKind::Ipv4);
    let v6 = Some(IndicatorKind::Ipv6);
    assert_eq!(
        skipped(&set),
        [
            (None, "not-an-address", SkipReason::NotAnAddress),
            (v4, "10.0.0.5", SkipReason::PrivateAddress),
            (v4, "10.0.0.6", SkipReason::PrivateAddress),
            (v4, "100.64.1.1", SkipReason::PrivateAddress),
            (v4, "127.0.0.1", SkipReason::ReservedAddress),
            (v4, "169.254.169.254", SkipReason::ReservedAddress),
            (v4, "192.168.1.1", SkipReason::PrivateAddress),
            (v4, "203.0.113.9", SkipReason::DocumentationAddress),
            (v4, "224.0.0.1", SkipReason::ReservedAddress),
            (v4, "8.8.4.4", SkipReason::OperatorAddress),
            (v4, "8.8.4.5", SkipReason::OperatorAddress),
            (v6, "2001:db8::9", SkipReason::DocumentationAddress),
            (v6, "::1", SkipReason::ReservedAddress),
            (v6, "fd00::1", SkipReason::PrivateAddress),
            (v6, "fe80::1", SkipReason::ReservedAddress),
        ]
    );

    // The outputs name only the two public addresses.
    let stix = set.to_stix_string(&stix_options()).unwrap();
    let csv = set.to_csv(Tlp::Green);
    for excluded in names
        .iter()
        .filter(|name| !["8.8.8.8", "2606:4700:4700::1111"].contains(name))
    {
        let bare = excluded.trim_start_matches("::ffff:");
        assert!(
            !stix.contains(&format!("'{bare}'")) && !stix.contains(&format!("address {bare}\"")),
            "{bare} is in the STIX text"
        );
        assert!(
            !csv.contains(&format!(",{bare},")),
            "{bare} is in the CSV text"
        );
    }

    // The documentation option permits only the documentation ranges.
    let permissive = IndicatorOptions::new().with_addresses(
        AddressPolicy::new()
            .with_documentation_ranges()
            .with_operator_network("8.8.4.0/24".parse().unwrap()),
    );
    let set = IndicatorSet::collect(&[detection], &[], &permissive).unwrap();
    assert_eq!(
        values(&set, IndicatorKind::Ipv4),
        ["8.8.8.8", "203.0.113.9"]
    );
    assert_eq!(
        values(&set, IndicatorKind::Ipv6),
        ["2001:db8::9", "2606:4700:4700::1111"]
    );
}

#[test]
fn an_address_that_only_normal_activity_shows_is_never_exported() {
    let attack = event(1, 600, action::SIGN_IN, Some("93.184.216.34"));
    let normal = event(2, 601, action::SIGN_IN, Some("93.184.216.99"));
    let normal_v6 = event(3, 602, action::API_CALL, Some("2606:4700::99"));
    // A benign detection and a suspicious detection do not make an indicator.
    let benign_event = event(4, 603, action::SIGN_IN, Some("93.184.216.100"));
    let suspicious_event = event(5, 604, action::SIGN_IN, Some("93.184.216.101"));
    let detections = [
        malicious(1, 600, &[&attack], Vec::new()),
        support::detection(
            2,
            Verdict::Benign,
            603,
            &[&benign_event],
            vec![support::ip_entity("93.184.216.100")],
        ),
        support::detection(
            3,
            Verdict::Suspicious,
            604,
            &[&suspicious_event],
            Vec::new(),
        ),
    ];
    let events = [attack, normal, normal_v6, benign_event, suspicious_event];
    let set = IndicatorSet::collect(&detections, &events, &IndicatorOptions::new()).unwrap();
    assert_eq!(values(&set, IndicatorKind::Ipv4), ["93.184.216.34"]);
    assert_eq!(set.indicators.len(), 1);
    assert_eq!(set.skipped, []);
    let text = format!(
        "{}{}",
        set.to_stix_string(&stix_options()).unwrap(),
        set.to_csv(Tlp::Green)
    );
    for address in [
        "93.184.216.99",
        "2606:4700::99",
        "93.184.216.100",
        "93.184.216.101",
    ] {
        assert!(!text.contains(address), "{address}");
    }

    // With the option, the suspicious detection gives an indicator with a weaker basis.
    let mut options = IndicatorOptions::new();
    options.include_suspicious = true;
    let set = IndicatorSet::collect(&detections, &events, &options).unwrap();
    assert_eq!(
        values(&set, IndicatorKind::Ipv4),
        ["93.184.216.34", "93.184.216.101"]
    );
    assert_eq!(set.indicators[0].basis, IndicatorBasis::MaliciousActivity);
    assert_eq!(set.indicators[1].basis, IndicatorBasis::AnomalousActivity);
}

#[test]
fn a_decoy_event_gives_indicators_with_no_detection() {
    let contact = event(1, 600, action::DECOY_CONTACT, Some("93.184.216.34"))
        .with_attribute(attr::DECOY_ID, "decoy-7")
        .with_attribute(attr::HTTP_PATH, "/v1/models");
    let mut contact = contact;
    contact.actor.user_agent = Some("scanner-one/1.0".to_owned());
    let mut canary = event(2, 610, action::DECOY_CANARY_HIT, Some("2606:4700::bad"));
    canary.actor.user_agent = Some("agent-two/2.0".to_owned());
    let mut trip = event(3, 620, action::HONEYTOKEN_TRIP, Some("93.184.216.35"));
    trip.actor.user_agent = Some("agent-three/3.0".to_owned());
    // An HTTP request to a real endpoint is not decoy evidence.
    let mut request = event(4, 630, action::HTTP_REQUEST, Some("93.184.216.36"));
    request.actor.user_agent = Some("browser-four/4.0".to_owned());
    let events = [contact, canary, trip, request];
    let set = IndicatorSet::collect(&[], &events, &IndicatorOptions::new()).unwrap();

    let found: Vec<(IndicatorKind, &str, IndicatorBasis, usize, usize)> = set
        .indicators
        .iter()
        .map(|indicator: &Indicator| {
            (
                indicator.kind,
                indicator.value.as_str(),
                indicator.basis,
                indicator.events,
                indicator.detections,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                IndicatorKind::Ipv4,
                "93.184.216.34",
                IndicatorBasis::AnomalousActivity,
                1,
                0
            ),
            (
                IndicatorKind::Ipv4,
                "93.184.216.35",
                IndicatorBasis::MaliciousActivity,
                1,
                0
            ),
            (
                IndicatorKind::Ipv6,
                "2606:4700::bad",
                IndicatorBasis::AnomalousActivity,
                1,
                0
            ),
            (
                IndicatorKind::UserAgent,
                "agent-three/3.0",
                IndicatorBasis::MaliciousActivity,
                1,
                0
            ),
            (
                IndicatorKind::UserAgent,
                "agent-two/2.0",
                IndicatorBasis::AnomalousActivity,
                1,
                0
            ),
            (
                IndicatorKind::UserAgent,
                "scanner-one/1.0",
                IndicatorBasis::AnomalousActivity,
                1,
                0
            ),
        ]
    );
    assert_eq!(set.indicators[0].first_seen, support::at(600));
    // The identifier of the decoy is not in an output.
    let stix = set.to_stix_string(&stix_options()).unwrap();
    assert!(!stix.contains("decoy-7"));
    assert!(!stix.contains("/v1/models"));
    let bundle = set.to_stix(&stix_options()).unwrap();
    let indicators = check_bundle(&bundle, Tlp::Amber);
    assert_eq!(
        indicators[0]["indicator_types"],
        json!(["anomalous-activity"])
    );
    assert_eq!(
        indicators[1]["indicator_types"],
        json!(["malicious-activity"])
    );
    assert_eq!(indicators[0].get("kill_chain_phases"), None);
    assert_eq!(indicators[0].get("external_references"), None);
}

#[test]
fn the_remote_side_of_an_event_is_the_side_that_is_not_the_operator() {
    // A connection that goes out: the actor is a host of the operator.
    let mut outbound = event(1, 600, action::NETWORK_CONNECT, Some("10.0.0.5"))
        .with_attribute(attr::DESTINATION_IP, "93.184.216.34")
        .with_attribute(attr::DESTINATION_DOMAIN, "C2.Bad-Host.NET.");
    outbound.actor.user_agent = Some("internal-updater/1.0".to_owned());
    // A host with no address looks up a domain. The domain is the target.
    let lookup = event(2, 601, "dns.query", None)
        .with_target(EntityRef::new(EntityKind::Domain, "lookup.bad-host.net"));
    // Activity that comes in: the destination is a public address of the operator that
    // is not in the list of operator networks.
    let mut inbound = event(3, 602, action::HTTP_REQUEST, Some("93.184.216.50"))
        .with_attribute(attr::DESTINATION_IP, "198.41.0.4")
        .with_attribute(attr::DESTINATION_DOMAIN, "portal.operator-site.net");
    inbound.actor.user_agent = Some("attack-tool/9.9".to_owned());
    let detection = malicious(1, 602, &[&outbound, &lookup, &inbound], Vec::new());
    let events = [outbound, lookup, inbound];
    let set = IndicatorSet::collect(&[detection], &events, &IndicatorOptions::new()).unwrap();

    assert_eq!(
        values(&set, IndicatorKind::Ipv4),
        ["93.184.216.34", "93.184.216.50"]
    );
    assert_eq!(
        values(&set, IndicatorKind::Domain),
        ["c2.bad-host.net", "lookup.bad-host.net"]
    );
    assert_eq!(values(&set, IndicatorKind::UserAgent), ["attack-tool/9.9"]);
    assert_eq!(set.skipped, []);
    let text = format!(
        "{}{}{}",
        set.to_stix_string(&stix_options()).unwrap(),
        set.to_csv(Tlp::Green),
        serde_json::to_string(&set).unwrap()
    );
    for own in [
        "10.0.0.5",
        "198.41.0.4",
        "operator-site",
        "internal-updater",
    ] {
        assert!(!text.contains(own), "{own} is in an output");
    }
}

#[test]
fn a_domain_of_the_operator_and_a_reserved_domain_are_never_exported() {
    let names = [
        "evil.bad-host.net",
        "contoso-corp.net",
        "login.contoso-corp.net",
        "notcontoso-corp.net",
        "printer.local",
        "db.internal",
        "host.corp",
        "4.3.2.1.in-addr.arpa",
        "www.example.com",
        "bad.example",
        "bücher.example",
        "single",
        "93.184.216.34",
    ];
    let entities: Vec<EntityRef> = names
        .iter()
        .map(|name| EntityRef::new(EntityKind::Domain, *name))
        .collect();
    let detection = malicious(1, 600, &[], entities);
    let options = IndicatorOptions::new().with_operator_domain("Contoso-Corp.NET.");
    let set = IndicatorSet::collect(std::slice::from_ref(&detection), &[], &options).unwrap();
    assert_eq!(
        values(&set, IndicatorKind::Domain),
        ["evil.bad-host.net", "notcontoso-corp.net"]
    );
    let domain = Some(IndicatorKind::Domain);
    assert_eq!(
        skipped(&set),
        [
            (domain, "4.3.2.1.in-addr.arpa", SkipReason::ReservedDomain),
            (domain, "93.184.216.34", SkipReason::InvalidDomain),
            (domain, "bad.example", SkipReason::DocumentationDomain),
            (domain, "bücher.example", SkipReason::InvalidDomain),
            (domain, "contoso-corp.net", SkipReason::OperatorDomain),
            (domain, "db.internal", SkipReason::ReservedDomain),
            (domain, "host.corp", SkipReason::ReservedDomain),
            (domain, "login.contoso-corp.net", SkipReason::OperatorDomain),
            (domain, "printer.local", SkipReason::ReservedDomain),
            (domain, "single", SkipReason::InvalidDomain),
            (domain, "www.example.com", SkipReason::DocumentationDomain),
        ]
    );
    let stix = set.to_stix_string(&stix_options()).unwrap();
    assert!(!stix.contains("login.contoso-corp.net"));
    assert!(!stix.contains("'contoso-corp.net'"));

    // The documentation option permits the documentation domains, and nothing more.
    let mut permissive = with_documentation();
    permissive.operator_domains = vec!["contoso-corp.net".to_owned()];
    let set = IndicatorSet::collect(std::slice::from_ref(&detection), &[], &permissive).unwrap();
    assert_eq!(
        values(&set, IndicatorKind::Domain),
        [
            "bad.example",
            "evil.bad-host.net",
            "notcontoso-corp.net",
            "www.example.com"
        ]
    );

    // An operator domain that is not a DNS name is an error. It does not silently
    // protect nothing.
    let wrong = IndicatorOptions::new().with_operator_domain("https://contoso-corp.net/");
    let error = IndicatorSet::collect(&[detection], &[], &wrong).unwrap_err();
    assert!(
        matches!(&error, ShareError::InvalidOption { name, .. } if *name == "operator_domains"),
        "{error}"
    );
}

#[test]
fn a_value_that_clients_with_no_link_to_the_attack_also_show_is_not_exported() {
    let mut attack = event(1, 600, action::SIGN_IN, Some("93.184.216.34"));
    attack.actor.user_agent = Some(BROWSER_USER_AGENT.to_owned());
    let mut second = event(2, 601, action::SIGN_IN, Some("93.184.216.34"));
    second.actor.user_agent = Some("rare-tool/0.1".to_owned());
    // A different record from the attacker address, which no detection cites.
    let mut same_client = event(3, 602, action::API_CALL, Some("93.184.216.34"));
    same_client.actor.user_agent = Some("rare-tool/0.1".to_owned());
    // An office user has the same browser. The comparison ignores case.
    let mut office = event(4, 603, action::SIGN_IN, Some("198.41.0.4"));
    office.actor.user_agent = Some(BROWSER_USER_AGENT.to_uppercase());

    // A host of the operator connects to two domains. A different host connects to one
    // of them in normal activity.
    let beacon = event(5, 604, action::NETWORK_CONNECT, Some("10.0.0.5"))
        .with_attribute(attr::DESTINATION_DOMAIN, "cdn.shared-host.net");
    let beacon_two = event(6, 605, action::NETWORK_CONNECT, Some("10.0.0.5"))
        .with_attribute(attr::DESTINATION_DOMAIN, "c2.bad-host.net");
    let mut repeat = event(7, 606, action::NETWORK_CONNECT, Some("10.0.0.5"))
        .with_attribute(attr::DESTINATION_DOMAIN, "c2.bad-host.net");
    repeat.actor.id = "host-6".to_owned();
    let other_host = event(8, 607, action::NETWORK_CONNECT, Some("10.0.0.77"))
        .with_attribute(attr::DESTINATION_DOMAIN, "CDN.shared-host.net");

    let detection = malicious(
        1,
        605,
        &[&attack, &second, &beacon, &beacon_two],
        Vec::new(),
    );
    let events = [
        attack,
        second,
        same_client,
        office,
        beacon,
        beacon_two,
        repeat,
        other_host,
    ];
    let set = IndicatorSet::collect(&[detection], &events, &IndicatorOptions::new()).unwrap();
    assert_eq!(values(&set, IndicatorKind::UserAgent), ["rare-tool/0.1"]);
    assert_eq!(values(&set, IndicatorKind::Domain), ["c2.bad-host.net"]);
    assert_eq!(values(&set, IndicatorKind::Ipv4), ["93.184.216.34"]);
    assert_eq!(
        skipped(&set),
        [
            (
                Some(IndicatorKind::Domain),
                "cdn.shared-host.net",
                SkipReason::SeenInNormalActivity
            ),
            (
                Some(IndicatorKind::UserAgent),
                BROWSER_USER_AGENT,
                SkipReason::SeenInNormalActivity
            ),
        ]
    );
    // The count is the count of the evidence events, not of all events.
    assert_eq!(
        set.of_kind(IndicatorKind::UserAgent).next().unwrap().events,
        1
    );
}

#[test]
fn a_user_agent_that_is_short_long_or_from_a_local_client_is_not_exported() {
    let with_agent = |number: u128, ip: &str, user_agent: &str| {
        let mut event = event(number, 600, action::SIGN_IN, Some(ip));
        event.actor.user_agent = Some(user_agent.to_owned());
        event
    };
    let long = "L".repeat(600);
    let events = [
        with_agent(1, "93.184.216.34", "abc"),
        with_agent(2, "93.184.216.34", &long),
        with_agent(3, "93.184.216.34", "  good-agent/1.0  "),
        with_agent(4, "10.0.0.5", "local-agent/1.0"),
    ];
    let detection = malicious(1, 600, &events.iter().collect::<Vec<_>>(), Vec::new());
    let set = IndicatorSet::collect(&[detection], &events, &IndicatorOptions::new()).unwrap();
    assert_eq!(values(&set, IndicatorKind::UserAgent), ["good-agent/1.0"]);
    let user_agent = Some(IndicatorKind::UserAgent);
    let cut = format!("{}...[cut]", "L".repeat(256));
    assert_eq!(
        skipped(&set),
        [
            (user_agent, cut.as_str(), SkipReason::TooLong),
            (user_agent, "abc", SkipReason::TooShort),
        ]
    );
    // A local client is a system of the operator. Its address and its user agent are in
    // no output and in no note.
    assert_eq!(values(&set, IndicatorKind::Ipv4), ["93.184.216.34"]);
    let all = serde_json::to_string(&set).unwrap();
    assert!(!all.contains("local-agent"));
    assert!(!all.contains("10.0.0.5"));
}

// ---------------------------------------------------------------------------------------
// The formats.
// ---------------------------------------------------------------------------------------

/// Makes a set with each indicator type and with values that need escapes.
fn rich_set() -> IndicatorSet {
    let with_agent = |number: u128, ip: &str, user_agent: &str| {
        let mut event = event(
            number,
            600 + i64::try_from(number).unwrap(),
            action::SIGN_IN,
            Some(ip),
        );
        event.actor.user_agent = Some(user_agent.to_owned());
        event
    };
    let events = [
        with_agent(1, "93.184.216.34", "it's a \\ tool, \"v1\" (x64; rv:1.0)"),
        with_agent(
            2,
            "2606:4700:4700::1111",
            "=HYPERLINK(\"http://x.test\",\"y\")",
        ),
        with_agent(3, "93.184.216.35", "-dash-agent"),
        with_agent(4, "93.184.216.36", "@at-agent"),
        with_agent(5, "93.184.216.37", "+plus-agent"),
        event(6, 610, action::NETWORK_CONNECT, None)
            .with_attribute(attr::DESTINATION_DOMAIN, "c2.bad-host.net")
            .with_attribute(attr::DESTINATION_IP, "2a00:1450:4001:81b::200e"),
        event(7, 611, action::DECOY_CONTACT, Some("93.184.216.38")),
    ];
    let mut detection = malicious(
        1,
        612,
        &events.iter().take(6).collect::<Vec<_>>(),
        vec![EntityRef::new(EntityKind::Domain, "named.bad-host.net")],
    );
    detection.attack = vec![
        AttackTechnique::new("credential-access", "T1110.003", "Password Spraying"),
        AttackTechnique::new("command-and-control", "T1071.001", "Web Protocols"),
        AttackTechnique::new("unknown", "T1595", "Active Scanning"),
    ];
    IndicatorSet::collect(&[detection], &events, &IndicatorOptions::new()).unwrap()
}

#[test]
fn the_stix_bundle_follows_the_rules_of_the_format_for_each_indicator_type() {
    let set = rich_set();
    assert_eq!(set.skipped, []);
    // Five IPv4 addresses, two IPv6 addresses, two domains, and five user agents.
    assert_eq!(set.indicators.len(), 14);
    for tlp in [Tlp::White, Tlp::Green, Tlp::Amber, Tlp::Red] {
        let options = StixOptions::new(tlp, support::report_time()).with_producer("Example Org");
        let bundle = set.to_stix(&options).unwrap();
        let indicators = check_bundle(&bundle, tlp);
        assert_eq!(indicators.len(), 14);
        // The pattern of each indicator gives back its type and its value.
        for (object, indicator) in indicators.iter().zip(&set.indicators) {
            let (kind, value) = check_pattern(object["pattern"].as_str().unwrap());
            assert_eq!(kind, indicator.kind);
            assert_eq!(value, indicator.value);
            assert_eq!(
                object["indicator_types"],
                json!([indicator.basis.stix_type()])
            );
            assert_eq!(
                object["valid_from"],
                json!(format_time(indicator.first_seen))
            );
        }
        // The text form parses to the same bundle.
        let text = set.to_stix_string(&options).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), bundle);
        // The identity of the producer is in the bundle, with the name of the caller.
        assert_eq!(bundle["objects"][1]["type"], "identity");
        assert_eq!(bundle["objects"][1]["name"], "Example Org");
        assert_eq!(bundle["objects"][1]["identity_class"], "organization");
    }
    let kinds: BTreeSet<IndicatorKind> = set.indicators.iter().map(|found| found.kind).collect();
    assert_eq!(kinds.len(), 4);

    // With no producer, the bundle has no identity and no creator reference.
    let anonymous = set.to_stix(&stix_options()).unwrap();
    let indicators = check_bundle(&anonymous, Tlp::Amber);
    assert_eq!(anonymous["objects"].as_array().unwrap().len(), 15);
    assert!(
        indicators
            .iter()
            .all(|object| object.get("created_by_ref").is_none())
    );
    assert!(!anonymous.to_string().contains("Example Org"));

    // A technique with a tactic that ATT&CK does not have gives no kill chain phase.
    let address = indicators
        .iter()
        .find(|object| object["name"] == "IPv4 address 93.184.216.34")
        .unwrap();
    assert_eq!(
        address["kill_chain_phases"],
        json!([
            {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"},
            {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
        ])
    );
    let external: Vec<&str> = address["external_references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reference| reference["external_id"].as_str().unwrap())
        .collect();
    assert_eq!(external, ["T1071.001", "T1110.003", "T1595"]);

    // With no end, an indicator has no `valid_until`.
    let endless = set.to_stix(&stix_options().with_valid_for(None)).unwrap();
    for object in check_bundle(&endless, Tlp::Amber) {
        assert_eq!(object.get("valid_until"), None);
    }
    let week = set
        .to_stix(&stix_options().with_valid_for(Some(TimeDelta::days(7))))
        .unwrap();
    let decoy = check_bundle(&week, Tlp::Amber)
        .into_iter()
        .find(|object| object["name"] == "IPv4 address 93.184.216.38")
        .unwrap();
    assert_eq!(decoy["valid_from"], "2026-11-03T09:10:11.000Z");
    assert_eq!(decoy["valid_until"], "2026-11-10T09:10:11.000Z");
}

fn format_time(time: DateTime<chrono::Utc>) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[test]
fn the_pattern_check_of_this_test_rejects_patterns_that_are_not_valid() {
    // The checks above must be able to fail. Each of these patterns breaks one rule.
    let bad = [
        "ipv4-addr:value = '8.8.8.8'",
        "[ipv4-addr:value = 8.8.8.8]",
        "[ipv4-addr:value = '8.8.8.8",
        "[ipv4-addr:value = '999.8.8.8']",
        "[ipv4-addr:value = '2606:4700::1']",
        "[ipv6-addr:value = '8.8.8.8']",
        "[ipv4-addr:value == '8.8.8.8']",
        "[IPv4-Addr:value = '8.8.8.8']",
        "[domain-name:value = 'no_dot']",
        "[domain-name:value = 'Upper.Example']",
        "[domain-name:value = 'it's.example']",
        "[network-traffic:extensions.http-request-ext.request_header.User-Agent = 'x']",
        "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'a\\nb']",
        "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'a'b']",
        "[file:name = 'x']",
    ];
    assert_eq!(bad.len(), 15);
    for pattern in bad {
        let result = std::panic::catch_unwind(|| check_pattern(pattern));
        assert!(result.is_err(), "the check accepts {pattern}");
    }
    assert_eq!(
        check_pattern("[domain-name:value = 'ok.example']"),
        (IndicatorKind::Domain, "ok.example".to_owned())
    );
}

#[test]
fn the_csv_file_follows_rfc_4180_and_gives_each_value_back() {
    let set = rich_set();
    let text = set.to_csv(Tlp::Green);
    let records = parse_csv(&text);
    assert_eq!(records.len(), set.indicators.len() + 1);
    assert_eq!(
        records[0],
        [
            "type",
            "value",
            "basis",
            "first_seen",
            "last_seen",
            "events",
            "detections",
            "techniques",
            "tlp"
        ]
    );
    assert_eq!(records[0].join(","), CSV_HEADER);
    let rows = &records[1..];
    assert_eq!(rows.len(), 14);
    for (row, indicator) in rows.iter().zip(&set.indicators) {
        assert_eq!(row.len(), 9, "{row:?}");
        assert!(["ipv4", "ipv6", "domain", "user_agent"].contains(&row[0].as_str()));
        assert_eq!(row[0], indicator.kind.name());
        // A value that starts a formula has an apostrophe before it.
        let formula = indicator.value.starts_with(['=', '+', '-', '@']);
        if formula {
            assert_eq!(row[1], format!("'{}", indicator.value));
        } else {
            assert_eq!(row[1], indicator.value);
        }
        assert!(
            !row[1].starts_with(['=', '+', '-', '@', '\t', '\r']),
            "{row:?}"
        );
        assert!(["malicious_activity", "anomalous_activity"].contains(&row[2].as_str()));
        let first = DateTime::parse_from_rfc3339(&row[3]).unwrap();
        let last = DateTime::parse_from_rfc3339(&row[4]).unwrap();
        assert!(row[3].ends_with('Z') && row[4].ends_with('Z'));
        assert_eq!(first.to_utc(), indicator.first_seen);
        assert_eq!(last.to_utc(), indicator.last_seen);
        assert_eq!(row[5].parse::<usize>().unwrap(), indicator.events);
        assert_eq!(row[6].parse::<usize>().unwrap(), indicator.detections);
        let techniques: Vec<&str> = row[7].split(';').filter(|id| !id.is_empty()).collect();
        let expected: Vec<&str> = indicator
            .techniques
            .iter()
            .map(|technique| technique.id.as_str())
            .collect();
        assert_eq!(techniques, expected);
        assert_eq!(row[8], "TLP:GREEN");
    }
    // The set has the four values that start a formula, and one with a comma and quotes.
    let guarded = rows.iter().filter(|row| row[1].starts_with('\'')).count();
    assert_eq!(guarded, 4);
    assert!(
        text.contains(
            "user_agent,\"it's a \\ tool, \"\"v1\"\" (x64; rv:1.0)\",malicious_activity,"
        )
    );
    assert!(text.contains("user_agent,\"'=HYPERLINK(\"\"http://x.test\"\",\"\"y\"\")\","));
    assert!(text.contains("\r\nuser_agent,'-dash-agent,"));
    assert_eq!(text.matches("\r\n").count(), 15);
    assert_eq!(text.matches('\n').count(), 15);

    assert_eq!(
        rows[0],
        [
            "ipv4",
            "93.184.216.34",
            "malicious_activity",
            "2026-11-03T09:10:01.000Z",
            "2026-11-03T09:10:01.000Z",
            "1",
            "1",
            "T1071.001;T1110.003;T1595",
            "TLP:GREEN"
        ]
    );
}
