//! The abuse report of the recorded attack log, and the rules of the report builder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::net::IpAddr;

use aegis_contracts::Verdict;
use aegis_contracts::common::TimeRange;
use aegis_contracts::event::Event;
use aegis_contracts::incident::IncidentStatus;
use aegis_share::{
    AbuseReport, AbuseReportPackage, AddressClass, AddressPolicy, AllowList, BuildNote, ClaimKind,
    EvidenceItemKind, EvidenceManifest, Field, HostingNetwork, NetworkMap, ReportSubject, Reporter,
    ShareError,
};
use aegis_testkit::fixtures::{self, expected};
use chrono::TimeDelta;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Command and Scripting Interpreter, Cloud API: the chain of actions at machine speed.
const CLOUD_API: &str = "T1059.009";

async fn attack_package() -> (AbuseReportPackage, Vec<Event>) {
    let (incident, events) = support::attack_incident().await;
    let audit = support::audit_chain(&incident);
    let package = AbuseReport::build(&incident, &events, &audit, &support::options()).unwrap();
    (package, events)
}

fn subject_address(report: &AbuseReport) -> IpAddr {
    match &report.subject {
        ReportSubject::Address { address } => *address,
        ReportSubject::Network { .. } => panic!("the report is a network report"),
    }
}

/// Returns each document of the package as text, with a name for the test output.
fn documents(package: &AbuseReportPackage) -> Vec<(String, String)> {
    let mut documents = Vec::new();
    for (position, report) in package.reports.iter().enumerate() {
        for file in report.files().unwrap() {
            documents.push((format!("report {position} {}", file.name), file.content));
        }
        documents.push((
            format!("report {position} value"),
            report.to_json().unwrap().to_string(),
        ));
    }
    documents.push((
        "package".to_owned(),
        serde_json::to_string(package).unwrap(),
    ));
    documents
}

/// The internal names of the operator in the attack log.
fn internal_values(events: &[Event]) -> BTreeSet<String> {
    let mut values: BTreeSet<String> = [
        fixtures::VICTIM_USER_ID,
        "dana@contoso.example",
        "contoso.example",
        fixtures::TENANT,
        fixtures::OTHER_TENANT,
        "contoso",
        "fabrikam",
        fixtures::ROGUE_APP_ID,
        fixtures::ROGUE_PRINCIPAL_ID,
        "Sync Helper",
        fixtures::HONEYTOKEN_ID,
        "honeytoken",
        "kv-prod",
        "legacy-admin-password",
        "Global Administrator",
        "62e90394-69f5-4237-9190-012177145e10",
        "credential-1",
        "Directory.ReadWrite.All",
        "entra_id",
        "microsoft",
        "Bucharest",
        "Singapore",
        "latitude",
        "mfa_satisfied",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for event in events {
        values.insert(event.actor.id.clone());
        values.extend(event.actor.name.clone());
        values.extend(event.actor.tenant.clone());
        values.extend(event.source.tenant.clone());
        values.insert(event.source.connector.clone());
        if let Some(target) = &event.target {
            values.insert(target.id.clone());
            values.extend(target.name.clone());
        }
    }
    values
}

fn assert_absent(documents: &[(String, String)], values: &BTreeSet<String>) {
    assert!(!documents.is_empty());
    assert!(!values.is_empty());
    for (name, text) in documents {
        let lower = text.to_lowercase();
        for value in values {
            assert!(
                !lower.contains(&value.to_lowercase()),
                "the internal value {value:?} is in the document {name}"
            );
        }
    }
}

#[tokio::test]
async fn the_package_has_one_report_for_each_of_the_three_attacker_addresses() {
    let (package, _) = attack_package().await;
    assert_eq!(package.notes, []);
    assert_eq!(package.reports.len(), 3);
    let addresses: Vec<IpAddr> = package.reports.iter().map(subject_address).collect();
    assert_eq!(
        addresses,
        [
            fixtures::DISTANT_IP,
            fixtures::SPRAY_IP,
            fixtures::WORKLOAD_IP
        ]
    );
    let records: Vec<usize> = package
        .reports
        .iter()
        .map(|report| report.addresses[0].records)
        .collect();
    assert_eq!(records, [3, 603, 6]);

    for (report, address) in package.reports.iter().zip(addresses) {
        assert_eq!(report.format, "aegis.abuse-report/1");
        assert_eq!(
            report.reference,
            "AEGIS-508657f7-d921-8cb3-add4-c2bd62528abd"
        );
        assert_eq!(report.generated_at, support::report_time());
        assert_eq!(report.addresses.len(), 1);
        assert_eq!(report.addresses[0].address, address);
        let markdown = report.to_markdown();
        assert!(
            markdown.starts_with(&format!("# Abuse report: activity from {address}\n")),
            "{markdown}"
        );
        assert!(markdown.contains(&format!("| Subject | IP address {address} |")));
        assert_eq!(
            report.to_json().unwrap()["subject"]["address"],
            address.to_string()
        );
        // A report names no other attacker address and no office address.
        let others = [
            fixtures::DISTANT_IP,
            fixtures::SPRAY_IP,
            fixtures::WORKLOAD_IP,
            fixtures::OFFICE_IP,
        ];
        for file in report.files().unwrap() {
            for other in others.iter().filter(|other| **other != address) {
                assert!(
                    !file.content.contains(&other.to_string()),
                    "{other} is in {} of the report for {address}",
                    file.name
                );
            }
            assert!(!file.content.contains("198.51.100."), "{}", file.name);
        }
    }
}

#[tokio::test]
async fn the_spray_report_says_what_occurred_in_plain_words_with_utc_times() {
    let (package, _) = attack_package().await;
    let report = &package.reports[1];
    let claims: Vec<_> = report.claims().collect();
    assert_eq!(claims.len(), 8);
    let titles: Vec<&str> = claims.iter().map(|claim| claim.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Sign-in attempts that failed",
            "Sign-in attempt that succeeded",
            "Grant of consent to an application that succeeded",
            "Addition of a credential to an application that succeeded",
            "Detection: activity classified as malicious",
            "Detection: activity classified as malicious",
            "Detection: activity classified as malicious",
            "Detection: activity classified as malicious",
        ]
    );
    assert_eq!(
        claims[0].statement,
        "The log records show 600 sign-in attempts from the address 203.0.113.50. All 600 \
         failed. The first was at 2026-11-03T09:10:00.000Z. The last was at \
         2026-11-03T09:10:29.950Z. The records name 150 different accounts."
    );
    assert_eq!(claims[0].records, 600);
    assert_eq!(claims[0].evidence.len(), 600);
    assert_eq!(claims[0].evidence[0], "E0001");
    assert_eq!(claims[0].evidence[599], "E0600");
    assert_eq!(claims[0].excerpt.len(), 3);
    assert_eq!(
        claims[1].statement,
        "The log records show 1 sign-in attempt from the address 203.0.113.50. It succeeded. \
         The time was 2026-11-03T09:10:31.000Z. The records name 1 account."
    );
    assert_eq!(
        claims[4].statement,
        "A detection rule of the reporter classified activity from the address 203.0.113.50 as \
         malicious. The time of the detection was 2026-11-03T09:10:00.450Z."
    );

    let markdown = report.to_markdown();
    for heading in [
        "## Summary",
        "## What occurred",
        "### Address 203.0.113.50",
        "#### C1. Sign-in attempts that failed",
        "## Addresses and ports",
        "## User agents and client fingerprints",
        "## ATT&CK techniques",
        "## Evidence and integrity",
    ] {
        assert!(
            markdown.lines().any(|line| line == heading),
            "no heading {heading:?}"
        );
    }
    assert!(markdown.contains("| First activity (UTC) | 2026-11-03T09:10:00.000Z |"));
    assert!(markdown.contains("| Last activity (UTC) | 2026-11-03T09:10:40.000Z |"));
    assert!(markdown.contains("| Report time (UTC) | 2026-11-03T10:00:00.000Z |"));
    assert!(markdown.contains("| Log records | 603 |"));
    assert!(markdown.contains("| Reporter | The sender of this message |"));
    assert!(markdown.contains("- Evidence: E0001 to E0600 (600 items)\n"));
    assert!(markdown.contains("- Log excerpt (3 of 600 items):\n"));
    assert!(markdown.contains(
        "- 203.0.113.50: 603 log records, from 2026-11-03T09:10:00.000Z to \
         2026-11-03T09:10:40.000Z. The log records give no port number.\n"
    ));
    assert!(markdown.contains("- 203.0.113.50, User agent: `python-httpx/0.27.0` (603 records)\n"));
    assert!(markdown.contains(
        "All times are in UTC. This report gives log data of the reporter. It does not identify \
         a person or a group.\n"
    ));
}

#[tokio::test]
async fn each_report_gives_the_attack_techniques_of_its_detections() {
    let (package, _) = attack_package().await;
    let techniques = |position: usize| -> Vec<&str> {
        package.reports[position]
            .techniques
            .iter()
            .map(|technique| technique.id.as_str())
            .collect()
    };
    // The chain at machine speed names the distant address and the workload address.
    assert_eq!(techniques(0), [CLOUD_API, expected::CLOUD_ACCOUNT]);
    assert_eq!(
        techniques(1),
        [
            "T1078",
            expected::CREDENTIAL_ADD,
            expected::PASSWORD_SPRAY,
            expected::CONSENT_GRANT
        ]
    );
    assert_eq!(
        techniques(2),
        [
            CLOUD_API,
            expected::CLOUD_ACCOUNT,
            expected::ROLE_ASSIGN,
            "T1552"
        ]
    );

    let spray = &package.reports[1];
    assert_eq!(
        spray.techniques[2].name.as_deref(),
        Some("Password Spraying")
    );
    assert_eq!(spray.techniques[2].tactics, ["credential-access"]);
    assert_eq!(
        spray.techniques[2].url,
        "https://attack.mitre.org/techniques/T1110/003/"
    );
    assert!(spray.to_markdown().contains(
        "- T1110.003 Password Spraying (credential-access), \
         <https://attack.mitre.org/techniques/T1110/003/>, claims C5\n"
    ));
    // Each technique of a report comes from a detection claim that has evidence.
    for report in &package.reports {
        assert!(!report.techniques.is_empty());
        for technique in &report.techniques {
            let backed = report.claims().any(|claim| {
                claim.kind == ClaimKind::Detection
                    && !claim.evidence.is_empty()
                    && claim.techniques.contains(technique)
            });
            assert!(backed, "{} has no claim", technique.id);
        }
    }
}

#[tokio::test]
async fn each_claim_has_evidence_items_that_the_report_holds() {
    let (package, _) = attack_package().await;
    let claim_counts: Vec<usize> = package
        .reports
        .iter()
        .map(|report| report.claims().count())
        .collect();
    assert_eq!(claim_counts, [3, 8, 9]);
    for report in &package.reports {
        let address = subject_address(report);
        for claim in report.claims() {
            assert!(!claim.evidence.is_empty(), "{}", claim.id);
            assert!(!claim.excerpt.is_empty(), "{}", claim.id);
            assert!(!claim.statement.is_empty(), "{}", claim.id);
            assert_eq!(claim.address, address);
            let cited: Vec<_> = claim
                .evidence
                .iter()
                .map(|id| {
                    report
                        .evidence
                        .iter()
                        .find(|item| item.id == *id)
                        .unwrap_or_else(|| panic!("the report does not hold {id}"))
                })
                .collect();
            // The excerpt is the start of the evidence of the claim.
            let expected_excerpt: Vec<&str> = cited
                .iter()
                .take(3)
                .map(|item| item.content.as_str())
                .collect();
            assert_eq!(claim.excerpt, expected_excerpt, "{}", claim.id);
            // The evidence is about the address of the claim.
            let events: Vec<Value> = cited
                .iter()
                .filter(|item| item.kind == EvidenceItemKind::Event)
                .map(|item| serde_json::from_str(&item.content).unwrap())
                .collect();
            assert!(!events.is_empty(), "{} cites no log record", claim.id);
            for event in &events {
                assert_eq!(event["source_address"], address.to_string(), "{}", claim.id);
            }
            if claim.kind == ClaimKind::Activity {
                assert_eq!(claim.evidence.len(), claim.records, "{}", claim.id);
                for event in &events {
                    assert_eq!(event["action"].as_str(), claim.action.as_deref());
                }
            } else {
                // A detection claim also cites the sealed audit record of the detection.
                let audit = cited
                    .iter()
                    .filter(|item| item.kind == EvidenceItemKind::AuditRecord)
                    .count();
                assert_eq!(audit, 1, "{}", claim.id);
            }
        }
        report.check().unwrap();
    }
}

#[tokio::test]
async fn the_builder_drops_a_claim_that_has_no_evidence() {
    // The detection names an address, but it cites no event and has no audit record.
    let spray = support::sign_in_from(1, 600, "203.0.113.50", "curl/8.4.0");
    let with_evidence = support::detection(
        1,
        Verdict::Malicious,
        600,
        &[&spray],
        vec![support::ip_entity("203.0.113.50")],
    );
    let without_evidence = support::detection(
        2,
        Verdict::Malicious,
        601,
        &[],
        vec![
            support::ip_entity("203.0.113.50"),
            support::ip_entity("192.0.2.9"),
            support::ip_entity("not an address"),
        ],
    );
    let incident = support::incident(vec![with_evidence, without_evidence.clone()]);
    let package = AbuseReport::build(&incident, &[spray], &[], &support::options()).unwrap();

    assert_eq!(package.reports.len(), 1);
    let report = &package.reports[0];
    let kinds: Vec<ClaimKind> = report.claims().map(|claim| claim.kind).collect();
    assert_eq!(kinds, [ClaimKind::Activity, ClaimKind::Detection]);
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(
        package.notes,
        [
            BuildNote::EntityNotAnAddress {
                detection: without_evidence.id
            },
            BuildNote::AddressWithoutRecords {
                address: "192.0.2.9".parse().unwrap()
            },
            BuildNote::DetectionWithoutEvidence {
                address: "203.0.113.50".parse().unwrap(),
                detection: without_evidence.id
            },
        ]
    );

    // A claim with no evidence fails the check of a report.
    let mut broken = report.clone();
    broken.addresses[0].claims[1].evidence.clear();
    let error = broken.check().unwrap_err();
    assert!(
        matches!(&error, ShareError::ClaimWithoutEvidence { claim } if claim == "C2"),
        "{error}"
    );
    let mut unknown = report.clone();
    unknown.addresses[0].claims[0].evidence = vec!["E9999".to_owned()];
    let error = unknown.check().unwrap_err();
    assert!(
        matches!(&error, ShareError::ClaimWithoutEvidence { claim } if claim == "C1"),
        "{error}"
    );
}

#[tokio::test]
async fn the_victim_user_and_the_tenant_names_are_in_no_output() {
    let (package, events) = attack_package().await;
    let values = internal_values(&events);
    // The log has 150 sprayed users, eight office users, and the named entities.
    assert!(values.len() > 300, "{}", values.len());
    assert!(values.contains("user-dana"));
    assert!(values.contains("tenant-contoso"));
    let documents = documents(&package);
    assert_eq!(documents.len(), 3 * 5 + 1);
    assert_absent(&documents, &values);

    // The masked entities are still in the evidence, as labels.
    let spray = &package.reports[1];
    let first: Value = serde_json::from_str(&spray.evidence[0].content).unwrap();
    assert_eq!(
        first["actor"],
        serde_json::json!({"kind": "user", "id": "masked-1"})
    );
    assert_eq!(
        first["target"],
        serde_json::json!({"kind": "application", "id": "masked-2"})
    );
    assert_eq!(first.get("raw"), None);
    assert_eq!(first.get("source"), None);
}

#[tokio::test]
async fn the_allow_list_keeps_the_selected_fields() {
    let (incident, events) = support::attack_incident().await;
    let mut options = support::options();
    options.allow = AllowList::default()
        .with_field(Field::ActorId)
        .with_field(Field::Tenant);
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    let documents = documents(&package);

    // The allowed values are now in the output. This also shows that the check of the
    // test before can fail.
    let json = &documents
        .iter()
        .find(|(name, _)| name == "report 1 report.json")
        .unwrap()
        .1;
    assert!(json.contains("user-dana"));
    assert!(json.contains("tenant-contoso"));
    let foothold: Value = package.reports[1]
        .evidence
        .iter()
        .map(|item| serde_json::from_str::<Value>(&item.content).unwrap())
        .find(|event| event["outcome"] == "success" && event["action"] == "sign_in")
        .unwrap();
    assert_eq!(
        foothold["actor"],
        serde_json::json!({"kind": "user", "id": "user-dana", "tenant": "tenant-contoso"})
    );

    // The fields that the list does not name stay masked.
    let still_masked: BTreeSet<String> = [
        "dana@contoso.example",
        "Sync Helper",
        fixtures::ROGUE_APP_ID,
        "kv-prod",
        "Portal",
        "app-portal",
        fixtures::HONEYTOKEN_ID,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_absent(&documents, &still_masked);
}

#[tokio::test]
async fn the_manifest_hashes_are_the_sha256_of_the_items() {
    let (package, _) = attack_package().await;
    let item_counts: Vec<usize> = package
        .reports
        .iter()
        .map(|report| report.evidence.len())
        .collect();
    // The log records of the address, and one audit record for each detection.
    assert_eq!(item_counts, [3 + 2, 603 + 4, 6 + 5]);

    for report in &package.reports {
        let manifest = &report.manifest;
        assert_eq!(manifest.algorithm, "sha256");
        assert_eq!(manifest.file_name, "evidence.jsonl");
        assert_eq!(manifest.items.len(), report.evidence.len());
        let mut file = Vec::new();
        for (entry, item) in manifest.items.iter().zip(&report.evidence) {
            // An independent SHA-256 of the bytes of the item.
            let digest = hex::encode(Sha256::digest(item.content.as_bytes()));
            assert_eq!(entry.id, item.id);
            assert_eq!(entry.sha256, digest, "{}", item.id);
            assert_eq!(item.sha256, digest, "{}", item.id);
            assert_eq!(entry.bytes, u64::try_from(item.content.len()).unwrap());
            assert!(!item.content.contains('\n'));
            assert!(
                item.content
                    .bytes()
                    .all(|byte| (0x20..0x7f).contains(&byte))
            );
            file.extend_from_slice(item.content.as_bytes());
            file.push(b'\n');
        }
        assert_eq!(report.evidence_jsonl().as_bytes(), file.as_slice());
        assert_eq!(manifest.file_sha256, hex::encode(Sha256::digest(&file)));
        assert_eq!(manifest.file_bytes, u64::try_from(file.len()).unwrap());

        // The files of the report agree with the manifest file.
        let files = report.files().unwrap();
        let names: Vec<&str> = files.iter().map(|file| file.name).collect();
        assert_eq!(
            names,
            [
                "report.md",
                "report.json",
                "evidence.jsonl",
                "manifest.json"
            ]
        );
        let decoded: EvidenceManifest = serde_json::from_str(&files[3].content).unwrap();
        assert_eq!(&decoded, manifest);
        decoded.verify_file(&files[2].content).unwrap();
        decoded.verify_items(&report.evidence).unwrap();
        // The Markdown gives the hash of the file and the hash of each excerpt item.
        assert!(
            files[0]
                .content
                .contains(&format!("`{}`", manifest.file_sha256))
        );
        for claim in report.claims() {
            for id in claim.evidence.iter().take(claim.excerpt.len()) {
                let item = report.evidence.iter().find(|item| item.id == *id).unwrap();
                assert!(
                    files[0]
                        .content
                        .contains(&format!("| {} | `{}` |\n", item.id, item.sha256)),
                    "{id}"
                );
            }
        }
    }

    // A known answer. The hash comes from `printf '%s' '<the line>' | shasum -a 256`.
    let first = &package.reports[0].evidence[0];
    assert_eq!(
        first.content,
        "{\"action\":\"api.call\",\"actor\":{\"id\":\"masked-1\",\"kind\":\"service_principal\"},\
         \"attributes\":{\"operation\":\"GET /servicePrincipals\"},\"class\":\"api_activity\",\
         \"item\":\"E0001\",\"outcome\":\"success\",\
         \"record\":\"01930000-0000-7000-8000-00000000026c\",\"source_address\":\"192.0.2.77\",\
         \"time\":\"2026-11-03T09:10:52.000Z\",\"type\":\"event\",\
         \"user_agent\":\"python-httpx/0.27.0\"}"
    );
    assert_eq!(
        package.reports[0].manifest.items[0].sha256,
        "06a468ac322bee9ba4a9d14a3002430a23a676201279f66cc594199ac2ebb239"
    );
}

#[tokio::test]
async fn a_changed_evidence_file_fails_the_manifest_check() {
    let (package, _) = attack_package().await;
    let report = &package.reports[2];
    let file = report.evidence_jsonl();
    report.manifest.verify_file(&file).unwrap();
    let changed = file.replacen("203.0.113.51", "203.0.113.52", 1);
    assert_ne!(changed, file);
    let error = report.manifest.verify_file(&changed).unwrap_err();
    assert!(
        matches!(&error, ShareError::Manifest { item, reason }
            if item == "E0001"
                && reason == "the SHA-256 of the item is not the value in the manifest"),
        "{error}"
    );
}

#[tokio::test]
async fn the_audit_evidence_holds_the_record_hash_and_no_record_text() {
    let (incident, events) = support::attack_incident().await;
    let audit = support::audit_chain(&incident);
    assert_eq!(audit.len(), 9);
    let package = AbuseReport::build(&incident, &events, &audit, &support::options()).unwrap();
    let distant = &package.reports[0];
    // The seventh and the eighth detection of the incident name this address: the chain
    // at machine speed, and the principal in two places. Each has one audit record.
    assert_eq!(distant.evidence.len(), 5);
    for (position, sequence, title, word) in [
        (3, 7, "Chain of sensitive actions at machine speed", "Chain"),
        (4, 8, "Principal acts from two places", "Principal"),
    ] {
        let item: Value = serde_json::from_str(&distant.evidence[position].content).unwrap();
        let record = &audit[sequence - 1];
        assert_eq!(
            item,
            serde_json::json!({
                "item": format!("E000{}", position + 1),
                "type": "audit_record",
                "audit_kind": "detection",
                "sequence": sequence,
                "record": record.id.to_string(),
                "time": "2026-11-03T09:10:52.005Z",
                "record_hash": record.hash,
                "detections": [incident.detections[sequence - 1].id.to_string()],
            })
        );
        assert_eq!(
            distant.evidence[position].kind,
            EvidenceItemKind::AuditRecord
        );
        assert!(record.summary.contains(title), "{}", record.summary);
        assert!(!distant.evidence[position].content.contains(word));
    }
}

#[tokio::test]
async fn an_audit_record_with_a_wrong_hash_stops_the_build() {
    let (incident, events) = support::attack_incident().await;
    let mut audit = support::audit_chain(&incident);
    audit[2].summary = "A changed summary.".to_owned();
    let error = AbuseReport::build(&incident, &events, &audit, &support::options()).unwrap_err();
    assert!(
        matches!(error, ShareError::AuditIntegrity { sequence: 3 }),
        "{error}"
    );
}

#[tokio::test]
async fn an_incident_that_is_a_false_positive_gives_no_report() {
    let (mut incident, events) = support::attack_incident().await;
    incident.status = IncidentStatus::FalsePositive;
    let error = AbuseReport::build(&incident, &events, &[], &support::options()).unwrap_err();
    assert!(
        matches!(&error, ShareError::NotReportable(reason)
            if reason == "the state of the incident is false_positive"),
        "{error}"
    );
}

#[tokio::test]
async fn the_default_policy_gives_no_report_about_a_documentation_address() {
    let (incident, events) = support::attack_incident().await;
    let options = aegis_share::AbuseReportOptions::new(support::report_time());
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    assert_eq!(package.reports, []);
    let excluded = |address: IpAddr| BuildNote::AddressExcluded {
        address,
        class: AddressClass::Documentation,
    };
    assert_eq!(
        package.notes,
        [
            excluded(fixtures::DISTANT_IP),
            excluded(fixtures::SPRAY_IP),
            excluded(fixtures::WORKLOAD_IP)
        ]
    );
}

#[tokio::test]
async fn an_operator_address_and_a_private_address_get_no_report() {
    let (mut incident, mut events) = support::attack_incident().await;
    // A malicious detection cites a record from a private address.
    let internal = support::sign_in_from(1, 700, "10.20.30.40", "curl/8.4.0");
    incident.detections.push(support::detection(
        1,
        Verdict::Malicious,
        700,
        &[&internal],
        vec![support::ip_entity("::ffff:10.20.30.40")],
    ));
    events.push(internal);
    let mut options = support::options();
    options.addresses = AddressPolicy::new()
        .with_documentation_ranges()
        .with_operator_network("203.0.113.50/32".parse().unwrap());
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();

    let addresses: Vec<IpAddr> = package.reports.iter().map(subject_address).collect();
    assert_eq!(addresses, [fixtures::DISTANT_IP, fixtures::WORKLOAD_IP]);
    assert_eq!(
        package.notes,
        [
            BuildNote::AddressExcluded {
                address: "10.20.30.40".parse().unwrap(),
                class: AddressClass::Private
            },
            BuildNote::AddressExcluded {
                address: fixtures::SPRAY_IP,
                class: AddressClass::Operator
            },
        ]
    );
    for report in &package.reports {
        for file in report.files().unwrap() {
            assert!(!file.content.contains("203.0.113.50"), "{}", file.name);
            assert!(!file.content.contains("10.20.30.40"), "{}", file.name);
        }
    }
}

#[tokio::test]
async fn only_a_malicious_detection_makes_an_attacker_address_by_default() {
    let suspicious_event = support::sign_in_from(1, 600, "203.0.113.60", "curl/8.4.0");
    let benign_event = support::sign_in_from(2, 601, "203.0.113.61", "curl/8.4.0");
    let suspicious = support::detection(
        1,
        Verdict::Suspicious,
        600,
        &[&suspicious_event],
        Vec::new(),
    );
    let benign = support::detection(2, Verdict::Benign, 601, &[&benign_event], Vec::new());
    let incident = support::incident(vec![suspicious.clone(), benign.clone()]);
    let events = [suspicious_event, benign_event];

    let package = AbuseReport::build(&incident, &events, &[], &support::options()).unwrap();
    assert_eq!(package.reports, []);
    assert_eq!(
        package.notes,
        [
            BuildNote::DetectionNotUsed {
                detection: suspicious.id,
                verdict: Verdict::Suspicious
            },
            BuildNote::DetectionNotUsed {
                detection: benign.id,
                verdict: Verdict::Benign
            },
        ]
    );

    // With the option, the suspicious detection gives a report. The benign one never does.
    let mut options = support::options();
    options.include_suspicious = true;
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    assert_eq!(package.reports.len(), 1);
    assert_eq!(
        subject_address(&package.reports[0]),
        "203.0.113.60".parse::<IpAddr>().unwrap()
    );
    let detection_claim = package.reports[0]
        .claims()
        .find(|claim| claim.kind == ClaimKind::Detection)
        .unwrap();
    assert_eq!(
        detection_claim.title,
        "Detection: activity classified as suspicious"
    );
    assert!(
        detection_claim
            .statement
            .contains("classified activity from the address 203.0.113.60 as suspicious."),
        "{}",
        detection_claim.statement
    );
    assert_eq!(
        package.notes,
        [BuildNote::DetectionNotUsed {
            detection: benign.id,
            verdict: Verdict::Benign
        }]
    );
}

#[tokio::test]
async fn a_report_gives_ports_and_fingerprints_and_does_not_say_what_is_a_decoy() {
    use aegis_contracts::event::{action, attr};

    let decoy_event = |number: u128, seconds: i64, name: &str, port: u16| {
        let mut event = support::sign_in_from(number, seconds, "203.0.113.50", "agent-x/1.0")
            .with_attribute(attr::DECOY_ID, "decoy-7")
            .with_attribute(attr::DECOY_KIND, "model_api")
            .with_attribute(attr::CANARY_ID, "canary-42")
            .with_attribute(attr::HONEYTOKEN_ID, "key-blue")
            .with_attribute(attr::HELD_MILLISECONDS, 30_000)
            .with_attribute(attr::CLIENT_FINGERPRINT, "fp-1a2b3c")
            .with_attribute(attr::DESTINATION_PORT, port)
            .with_attribute(attr::HTTP_METHOD, "POST")
            .with_attribute(attr::HTTP_PATH, "/v1/chat/completions")
            .with_attribute(attr::BYTES_RECEIVED, 512);
        event.action = name.to_owned();
        event
    };
    let events = [
        decoy_event(1, 600, action::DECOY_CONTACT, 8443),
        decoy_event(2, 601, action::DECOY_CONTACT, 8443),
        decoy_event(3, 602, action::DECOY_CANARY_HIT, 8080),
        decoy_event(4, 603, action::HONEYTOKEN_TRIP, 8443),
    ];
    let detection = support::detection(
        1,
        Verdict::Malicious,
        603,
        &events.iter().collect::<Vec<_>>(),
        Vec::new(),
    );
    let incident = support::incident(vec![detection.clone(), detection]);

    let package = AbuseReport::build(&incident, &events, &[], &support::options()).unwrap();
    let report = &package.reports[0];
    let activity = &report.addresses[0];
    let ports: Vec<(u16, usize)> = activity
        .ports
        .iter()
        .map(|port| (port.port, port.records))
        .collect();
    assert_eq!(ports, [(8080, 1), (8443, 3)]);
    assert_eq!(activity.client_fingerprints.len(), 1);
    assert_eq!(activity.client_fingerprints[0].value, "fp-1a2b3c");
    assert_eq!(activity.client_fingerprints[0].records, 4);
    assert_eq!(activity.user_agents[0].value, "agent-x/1.0");
    let markdown = report.to_markdown();
    assert!(markdown.contains(
        "- 203.0.113.50: 4 log records, from 2026-11-03T09:10:00.000Z to \
         2026-11-03T09:10:03.000Z. Destination ports: 8080 (1 record), 8443 (3 records).\n"
    ));
    assert!(markdown.contains("- 203.0.113.50, Client fingerprint: `fp-1a2b3c` (4 records)\n"));

    // The two decoy actions have one neutral name. A repeated detection makes one claim.
    let titles: Vec<&str> = report.claims().map(|claim| claim.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Requests to a service of the reporter that failed",
            "Access to a protected secret that failed",
            "Detection: activity classified as malicious",
        ]
    );
    let first: Value = serde_json::from_str(&report.evidence[0].content).unwrap();
    assert_eq!(first["action"], "service.contact");
    assert_eq!(
        first["attributes"],
        serde_json::json!({
            "bytes_received": 512,
            "client_fingerprint": "fp-1a2b3c",
            "destination_port": 8443,
            "http_method": "POST",
            "http_path": "/v1/chat/completions",
        })
    );
    for file in report.files().unwrap() {
        let lower = file.content.to_lowercase();
        for hidden in [
            "decoy",
            "honeytoken",
            "canary",
            "model_api",
            "key-blue",
            "held_milliseconds",
        ] {
            assert!(!lower.contains(hidden), "{hidden} is in {}", file.name);
        }
    }

    // With the option, the report says that the service is a decoy.
    let mut options = support::options();
    options.disclose_decoys = true;
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    let titles: Vec<&str> = package.reports[0]
        .claims()
        .map(|claim| claim.title.as_str())
        .collect();
    assert_eq!(
        titles,
        [
            "Requests to a decoy service that failed",
            "Request to a canary address of a decoy service that failed",
            "Use of a decoy credential that failed",
            "Detection: activity classified as malicious",
        ]
    );
    // The identifiers of the decoy stay out. The allow list controls them.
    assert!(
        !package.reports[0]
            .to_json_string()
            .unwrap()
            .contains("decoy-7")
    );
}

#[tokio::test]
async fn a_claim_about_a_client_that_uses_no_account_names_no_account() {
    use aegis_contracts::common::EntityKind;
    use aegis_contracts::event::action;

    // The actor of a decoy contact is the remote client. It is not an account.
    let mut first = support::sign_in_from(1, 600, "203.0.113.50", "agent-x/1.0");
    first.action = action::HTTP_REQUEST.to_owned();
    first.actor.kind = EntityKind::IpAddress;
    first.actor.id = "203.0.113.50".to_owned();
    let mut second = first.clone();
    second.id = support::event_id(2);
    second.time = support::at(605);
    let events = [first, second];
    let detection = support::detection(
        1,
        Verdict::Malicious,
        605,
        &events.iter().collect::<Vec<_>>(),
        Vec::new(),
    );
    let incident = support::incident(vec![detection]);
    let package = AbuseReport::build(&incident, &events, &[], &support::options()).unwrap();
    let claim = package.reports[0].claims().next().unwrap();
    assert_eq!(claim.title, "HTTP requests that failed");
    assert_eq!(
        claim.statement,
        "The log records show 2 HTTP requests from the address 203.0.113.50. All 2 failed. \
         The first was at 2026-11-03T09:10:00.000Z. The last was at 2026-11-03T09:10:05.000Z."
    );
}

#[tokio::test]
async fn a_network_map_adds_one_report_for_each_hosting_network() {
    let (incident, events) = support::attack_incident().await;
    let audit = support::audit_chain(&incident);
    let hosting = HostingNetwork::new("AS64500 Example Hosting <b>")
        .with_abuse_contact("abuse@hosting.example");
    let cloud = HostingNetwork::new("AS64501 Example Cloud");
    let mut options = support::options();
    options.networks = NetworkMap::new()
        .with_prefix("203.0.113.0/24".parse().unwrap(), hosting)
        .with_address(fixtures::DISTANT_IP, cloud);
    let package = AbuseReport::build(&incident, &events, &audit, &options).unwrap();
    assert_eq!(package.notes, []);
    assert_eq!(package.reports.len(), 5);

    let network = &package.reports[3];
    assert_eq!(
        network.subject,
        ReportSubject::Network {
            name: "AS64500 Example Hosting <b>".to_owned(),
            abuse_contact: Some("abuse@hosting.example".to_owned()),
            addresses: vec![fixtures::SPRAY_IP, fixtures::WORKLOAD_IP],
        }
    );
    assert_eq!(network.addresses.len(), 2);
    assert_eq!(network.addresses[0].address, fixtures::SPRAY_IP);
    assert_eq!(network.addresses[1].address, fixtures::WORKLOAD_IP);
    assert_eq!(network.evidence.len(), 603 + 6 + 9);
    assert_eq!(network.claims().count(), 17);
    let ids: Vec<&str> = network.claims().map(|claim| claim.id.as_str()).collect();
    assert_eq!(ids[0], "C1");
    assert_eq!(ids[16], "C17");
    network.check().unwrap();
    network
        .manifest
        .verify_file(&network.evidence_jsonl())
        .unwrap();
    // The report of this network does not name the address in the other network.
    for file in network.files().unwrap() {
        assert!(!file.content.contains("192.0.2.77"), "{}", file.name);
    }
    let markdown = network.to_markdown();
    assert!(
        markdown.starts_with("# Abuse report: activity from AS64500 Example Hosting \\<b\\>\n")
    );
    assert!(
        markdown.contains("| Subject | Network AS64500 Example Hosting \\<b\\> (2 addresses) |")
    );
    assert!(markdown.contains("| Abuse contact | abuse@hosting.example |"));
    assert!(markdown.contains("### Address 203.0.113.50\n"));
    assert!(markdown.contains("### Address 203.0.113.51\n"));

    // One entity has one label in the report. The rogue service principal is the
    // target of a record from the first address and the actor at the second address.
    let events_of = |action: &str| -> Vec<Value> {
        network
            .evidence
            .iter()
            .map(|item| serde_json::from_str::<Value>(&item.content).unwrap())
            .filter(|event| event["action"] == action)
            .collect()
    };
    let credential = events_of("app.credential_add");
    let role = events_of("role.assign");
    assert_eq!(credential.len(), 1);
    assert_eq!(role.len(), 1);
    assert_eq!(credential[0]["target"]["kind"], "service_principal");
    assert_eq!(credential[0]["target"]["id"], role[0]["actor"]["id"]);
    assert_eq!(role[0]["actor"]["id"], role[0]["target"]["id"]);

    let cloud_report = &package.reports[4];
    assert_eq!(
        cloud_report.subject,
        ReportSubject::Network {
            name: "AS64501 Example Cloud".to_owned(),
            abuse_contact: None,
            addresses: vec![fixtures::DISTANT_IP],
        }
    );
    // Three log records of the address, and one audit record for each of its two
    // detections.
    assert_eq!(cloud_report.evidence.len(), 3 + 2);
}

#[tokio::test]
async fn the_evidence_limit_keeps_the_cited_records_and_says_what_it_left_out() {
    let (incident, events) = support::attack_incident().await;
    let mut options = support::options();
    options.max_evidence_items = 20;
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    assert_eq!(
        package.notes,
        [BuildNote::EvidenceLimited {
            address: fixtures::SPRAY_IP,
            records: 603,
            included: 20
        }]
    );
    let report = &package.reports[1];
    assert_eq!(report.evidence.len(), 20);
    assert_eq!(report.addresses[0].records, 603);
    assert_eq!(report.addresses[0].records_in_evidence, 20);
    let claims: Vec<_> = report.claims().collect();
    // All four types of activity and all four detections still have evidence.
    assert_eq!(claims.len(), 8);
    assert_eq!(claims[0].records, 600);
    assert_eq!(claims[0].evidence.len(), 17);
    assert!(
        claims[0].statement.ends_with(
            "The records name 150 different accounts. This package holds 17 of the 600 records."
        ),
        "{}",
        claims[0].statement
    );
    for claim in &claims {
        assert!(!claim.evidence.is_empty(), "{}", claim.id);
    }
    // The ten records that the burst detection cites are in the evidence.
    let burst = &incident.detections[0];
    assert_eq!(burst.event_ids.len(), 10);
    for id in &burst.event_ids {
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.content.contains(&id.to_string())),
            "{id}"
        );
    }
    report.check().unwrap();
}

#[tokio::test]
async fn the_time_range_limits_the_records_of_an_address() {
    let (incident, events) = support::attack_incident().await;
    let mut options = support::options();
    // Ten seconds from the start of the spray. The end is not in the range.
    options.window = Some(TimeRange {
        start: support::at(600),
        end: support::at(610),
    });
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    assert_eq!(package.reports.len(), 1);
    let report = &package.reports[0];
    assert_eq!(subject_address(report), fixtures::SPRAY_IP);
    assert_eq!(report.addresses[0].records, 200);
    assert_eq!(
        report.last_seen,
        support::at(610) - TimeDelta::milliseconds(50)
    );

    // With no margin, the range is from the first to the last detection evidence.
    let mut options = support::options();
    options.activity_margin = TimeDelta::zero();
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    assert_eq!(package.reports.len(), 3);
    assert_eq!(package.reports[1].addresses[0].records, 603);
}

#[tokio::test]
async fn options_that_are_not_valid_are_rejected() {
    let (incident, events) = support::attack_incident().await;
    let check = |change: &dyn Fn(&mut aegis_share::AbuseReportOptions), name: &str| {
        let mut options = support::options();
        change(&mut options);
        let error = AbuseReport::build(&incident, &events, &[], &options).unwrap_err();
        assert!(
            matches!(&error, ShareError::InvalidOption { name: found, .. } if *found == name),
            "{error}"
        );
    };
    check(
        &|options| options.max_evidence_items = 0,
        "max_evidence_items",
    );
    check(&|options| options.excerpt_lines = 0, "excerpt_lines");
    check(
        &|options| options.activity_margin = TimeDelta::seconds(-1),
        "activity_margin",
    );
    check(
        &|options| {
            options.window = Some(TimeRange {
                start: support::at(10),
                end: support::at(10),
            });
        },
        "window",
    );
}

#[tokio::test]
async fn the_package_is_the_same_for_the_same_input_in_any_order() {
    let (incident, events) = support::attack_incident().await;
    let audit = support::audit_chain(&incident);
    let options = support::options();
    let first = AbuseReport::build(&incident, &events, &audit, &options).unwrap();
    let second = AbuseReport::build(&incident, &events, &audit, &options).unwrap();
    assert_eq!(first, second);

    let mut reversed_events = events.clone();
    reversed_events.reverse();
    // A repeated event does not make a second evidence item.
    reversed_events.extend(events.iter().take(50).cloned());
    let mut reversed_audit = audit.clone();
    reversed_audit.reverse();
    let third = AbuseReport::build(&incident, &reversed_events, &reversed_audit, &options).unwrap();
    assert_eq!(first, third);
    assert_eq!(first.reports.len(), 3);
    for (left, right) in first.reports.iter().zip(&third.reports) {
        assert_eq!(left.to_markdown(), right.to_markdown());
        assert_eq!(
            left.to_json_string().unwrap(),
            right.to_json_string().unwrap()
        );
        assert_eq!(left.manifest.file_sha256, right.manifest.file_sha256);
    }
}

#[tokio::test]
async fn the_reporter_is_in_the_report_only_if_the_caller_gives_one() {
    let (incident, events) = support::attack_incident().await;
    let options = support::options().with_reporter(Reporter {
        name: "Example Org [SOC]".to_owned(),
        contact: Some("soc@example.org".to_owned()),
    });
    let package = AbuseReport::build(&incident, &events, &[], &options).unwrap();
    let report = &package.reports[0];
    assert!(
        report
            .to_markdown()
            .contains("| Reporter | Example Org \\[SOC\\] (soc@example.org) |")
    );
    let json = report.to_json().unwrap();
    assert_eq!(json["reporter"]["name"], "Example Org [SOC]");
    assert_eq!(json["reporter"]["contact"], "soc@example.org");

    let (anonymous, _) = attack_package().await;
    assert_eq!(
        anonymous.reports[0].to_json().unwrap().get("reporter"),
        None
    );
}
