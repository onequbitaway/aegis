//! Test data that the integration tests share: the incident of the recorded attack log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use aegis_contracts::audit::{AuditEntry, AuditKind, AuditRecord, seal};
use aegis_contracts::common::{AuditId, EvidenceKind, EvidenceRef};
use aegis_contracts::event::Event;
use aegis_contracts::{Detection, Incident};
use aegis_detect::engine::{DetectionEngine, EngineConfig};
use aegis_detect::pack::RulePack;
use aegis_share::{AbuseReportOptions, AddressPolicy};
use aegis_testkit::ScriptedModel;
use aegis_testkit::fixtures;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use uuid::Uuid;

/// The time of the reports in the tests: one hour after the start of the attack log.
pub fn report_time() -> DateTime<Utc> {
    fixtures::base_time() + TimeDelta::hours(1)
}

/// Replays the recorded attack log through the detection engine with the shipped rule
/// pack. Returns the one incident that the engine makes, and the events.
pub async fn attack_incident() -> (Incident, Vec<Event>) {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detections/aegis-identity");
    let pack = RulePack::load(directory).unwrap();
    // The model has an empty script. All detections of the log are deterministic.
    let model = Arc::new(ScriptedModel::new("unused"));
    let engine = DetectionEngine::new(EngineConfig::default(), pack)
        .unwrap()
        .with_triage(model)
        .unwrap();
    let events = fixtures::artex_style_attack();
    for event in &events {
        engine.process(event).await.unwrap();
    }
    let mut incidents = engine.incidents();
    assert_eq!(incidents.len(), 1);
    (incidents.remove(0), events)
}

/// Makes the audit record of one detection, as the service writes it.
///
/// The summary and the payload hold internal names, as in a real audit log.
fn detection_entry(detection: &Detection) -> AuditEntry {
    let mut evidence = vec![EvidenceRef::new(EvidenceKind::Detection, detection.id)];
    evidence.extend(
        detection
            .event_ids
            .iter()
            .map(|id| EvidenceRef::new(EvidenceKind::Event, id)),
    );
    AuditEntry::new(
        AuditKind::Detection,
        "tier1",
        format!(
            "The detector {} made the detection \"{}\".",
            detection.rule_id, detection.title
        ),
    )
    .with_payload(json!({
        "detection_id": detection.id,
        "title": detection.title,
        "entities": detection.entities,
        "tenant": detection.tenant,
    }))
    .with_evidence(evidence)
}

/// Makes a hash chain with one record for each detection of `incident`.
///
/// The record identifiers and the times are fixed, so the chain is the same in each run.
pub fn audit_chain(incident: &Incident) -> Vec<AuditRecord> {
    let mut records: Vec<AuditRecord> = Vec::new();
    for (position, detection) in incident.detections.iter().enumerate() {
        let mut record = seal(
            records.last(),
            detection_entry(detection),
            detection.time + TimeDelta::milliseconds(5),
        )
        .unwrap();
        record.id = AuditId(Uuid::from_u128(0xa0d1_0000 + position as u128));
        record.hash = record.compute_hash().unwrap();
        records.push(record);
    }
    records
}

/// Returns the options of the tests: a fixed report time and the documentation ranges.
///
/// The recorded attack log uses the documentation ranges, so the tests must permit them.
pub fn options() -> AbuseReportOptions {
    AbuseReportOptions::new(report_time())
        .with_addresses(AddressPolicy::new().with_documentation_ranges())
}

/// Returns a time that is `seconds` after the start of the attack log.
pub fn at(seconds: i64) -> DateTime<Utc> {
    fixtures::base_time() + TimeDelta::seconds(seconds)
}

/// Returns a fixed event identifier.
pub fn event_id(number: u128) -> aegis_contracts::common::EventId {
    aegis_contracts::common::EventId(Uuid::from_u128(0xe000_0000 + number))
}

/// Makes a failed sign-in of the user `user-erin` from `ip`.
pub fn sign_in_from(number: u128, seconds: i64, ip: &str, user_agent: &str) -> Event {
    use aegis_contracts::common::EntityKind;
    use aegis_contracts::event::{Actor, EventClass, EventSource, Outcome, action};

    let actor = Actor::new(EntityKind::User, "user-erin")
        .with_name("erin@contoso.example")
        .with_tenant(fixtures::TENANT)
        .with_ip(ip.parse().unwrap())
        .with_user_agent(user_agent);
    Event::new(
        at(seconds),
        EventSource::new("idp-prod", "example", "identity").with_tenant(fixtures::TENANT),
        EventClass::Authentication,
        action::SIGN_IN,
        actor,
    )
    .with_id(event_id(number))
    .with_outcome(Outcome::Failure)
}

/// Returns the entity of an IP address.
pub fn ip_entity(ip: &str) -> aegis_contracts::common::EntityRef {
    aegis_contracts::common::EntityRef::new(aegis_contracts::common::EntityKind::IpAddress, ip)
}

/// Makes a deterministic detection with one technique.
pub fn detection(
    number: u128,
    verdict: aegis_contracts::Verdict,
    seconds: i64,
    events: &[&Event],
    entities: Vec<aegis_contracts::common::EntityRef>,
) -> Detection {
    use aegis_contracts::common::{DetectionId, Severity};
    use aegis_contracts::{AttackTechnique, DetectionTier};

    Detection {
        id: DetectionId(Uuid::from_u128(0xd000_0000 + number)),
        rule_id: format!("test.rule.{number}"),
        title: format!("Rule {number} for erin@contoso.example"),
        description: "The rule found activity in tenant-contoso.".to_owned(),
        severity: Severity::High,
        verdict,
        tier: DetectionTier::Deterministic,
        time: at(seconds),
        attack: vec![AttackTechnique::new(
            "credential-access",
            "T1110.003",
            "Password Spraying",
        )],
        event_ids: events.iter().map(|event| event.id).collect(),
        entities,
        tenant: Some(fixtures::TENANT.to_owned()),
        attributes: Default::default(),
    }
}

/// Makes an open incident with `detections`.
pub fn incident(detections: Vec<Detection>) -> Incident {
    use aegis_contracts::common::{IncidentId, Severity};
    use aegis_contracts::incident::IncidentStatus;

    Incident {
        id: IncidentId(Uuid::from_u128(0x1c1d_0001)),
        title: "Incident in tenant-contoso".to_owned(),
        summary: "The user erin@contoso.example is involved.".to_owned(),
        severity: Severity::High,
        status: IncidentStatus::Open,
        created_at: at(0),
        updated_at: at(0),
        tenant: Some(fixtures::TENANT.to_owned()),
        detections,
        entities: Vec::new(),
        attack: Vec::new(),
        timeline: Vec::new(),
    }
}

/// Returns the Markdown text that is not in a code block and not in a code span.
///
/// The function follows the CommonMark rule for a code span: a run of backticks opens
/// the span, and the next run of the same length closes it. It also checks that each
/// fence is one that the report writer makes, and that a code block holds only JSON lines.
pub fn outside_code(markdown: &str) -> String {
    let mut outside = String::new();
    let mut in_block = false;
    let mut fences = 0;
    for line in markdown.lines() {
        if line.starts_with("```") {
            assert!(
                (!in_block && line == "```json") || (in_block && line == "```"),
                "unexpected fence line {line:?}"
            );
            in_block = !in_block;
            fences += 1;
            continue;
        }
        if in_block {
            assert!(
                line.starts_with('{') && line.ends_with('}'),
                "a code block line is not one JSON object: {line:?}"
            );
            continue;
        }
        let characters: Vec<char> = line.chars().collect();
        let run_at = |start: usize| {
            characters[start..]
                .iter()
                .take_while(|character| **character == '`')
                .count()
        };
        let mut index = 0;
        while index < characters.len() {
            if characters[index] != '`' {
                outside.push(characters[index]);
                index += 1;
                continue;
            }
            let opening = run_at(index);
            let mut search = index + opening;
            let mut close = None;
            while search < characters.len() {
                if characters[search] == '`' {
                    let run = run_at(search);
                    if run == opening {
                        close = Some(search + run);
                        break;
                    }
                    search += run;
                } else {
                    search += 1;
                }
            }
            match close {
                Some(end) => index = end,
                None => {
                    outside.extend(std::iter::repeat_n('`', opening));
                    index += opening;
                }
            }
        }
        outside.push('\n');
    }
    assert!(!in_block, "a code block has no end");
    assert_eq!(fences % 2, 0);
    outside
}
