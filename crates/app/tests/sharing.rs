//! The evidence archive and the documents for other defenders: abuse reports and
//! indicators from the recorded attack log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_app::App;
use aegis_app::evidence::{EvidenceRecord, read_archive};
use aegis_app::settings::Settings;
use aegis_app::sharing::{self, IncidentSource, Tlp};
use aegis_contracts::Error;
use aegis_contracts::common::IncidentId;
use aegis_contracts::incident::{IncidentStatus, IncidentStore};
use aegis_testkit::fixtures;
use chrono::{DateTime, TimeZone, Utc};

use support::Starter;

const SHARE: &str = "\n[share]\noperator_networks = [\"198.51.100.0/24\"]\n\
                     permit_documentation_ranges = true\n";

fn report_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 4, 8, 0, 0).unwrap()
}

/// Replays the recorded attack log and returns the application and the settings with
/// the `[share]` section.
async fn replayed(starter: &Starter) -> (App, Settings, IncidentId) {
    let config = starter.config_with(|text| text + SHARE);
    let app = starter.build(&config, |builder| builder).await;
    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();
    assert_eq!(report.incidents.len(), 1);
    let settings = app.settings().clone();
    (app, settings, report.incidents[0].id)
}

#[tokio::test]
async fn the_archive_has_each_detection_its_events_and_the_last_state_of_the_incident() {
    let starter = Starter::new();
    let (app, _, incident_id) = replayed(&starter).await;
    let stored = app.incidents().get(incident_id).await.unwrap().unwrap();
    let archive = app.evidence().unwrap();
    let path = starter.path().join("data/evidence.jsonl");
    assert_eq!(archive.path(), path);
    let stats = archive.stats();
    assert_eq!(stats.records_dropped, 0);
    assert_eq!(app.status_sections().await["evidence"]["enabled"], true);
    assert_eq!(
        app.status_sections().await["evidence"]["records_written"],
        stats.records_written
    );

    let data = read_archive(&path).unwrap();
    assert_eq!(data.invalid_lines, 0);
    // The nine detections of the replay, and the events that they name. The sign-in burst
    // names 10 events. The other detections name 8 more events.
    assert_eq!(data.detections.len(), 9);
    for detection in &stored.detections {
        assert!(data.detections.contains(detection), "{}", detection.rule_id);
    }
    assert_eq!(data.events.len(), 18);
    let named: std::collections::BTreeSet<_> = data
        .detections
        .iter()
        .flat_map(|detection| detection.event_ids.iter().copied())
        .collect();
    let archived: std::collections::BTreeSet<_> =
        data.events.iter().map(|event| event.id).collect();
    assert_eq!(archived, named);
    // The last state of the incident is the state of the store, with the work of the
    // agents.
    assert_eq!(data.incidents, std::slice::from_ref(&stored));
    assert_eq!(stored.status, IncidentStatus::Investigating);
    assert!(data.missing_detections.is_empty());
    // Each line is one record.
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count() as u64, stats.records_written);
    for line in text.lines() {
        serde_json::from_str::<EvidenceRecord>(line).unwrap();
    }
}

#[tokio::test]
async fn a_session_that_does_not_write_the_files_of_the_configuration_has_no_archive() {
    let starter = Starter::new();
    let config = starter.config();
    // With no `[evidence]` section, the application has no archive.
    let without = starter.config_with(|text| {
        let start = text.find("[evidence]").unwrap();
        let end = start + text[start..].find("\n\n").unwrap();
        format!("{}{}", &text[..start], &text[end..])
    });
    let app = starter.build(&without, |builder| builder).await;
    assert!(app.evidence().is_none());
    assert_eq!(
        app.status_sections().await["evidence"],
        serde_json::json!({ "enabled": false })
    );
    drop(app);
    // A local session and a second application with its own audit file write no archive.
    let session = starter
        .build(&config, |builder| {
            builder.local_session(starter.path().join("session-audit.jsonl"))
        })
        .await;
    assert!(session.evidence().is_none());
    session
        .replay(fixtures::artex_style_attack())
        .await
        .unwrap();
    assert!(!starter.path().join("data/evidence.jsonl").exists());
}

#[tokio::test]
async fn the_abuse_report_comes_from_the_archive_and_refuses_without_operator_networks() {
    let starter = Starter::new();
    let (app, settings, incident_id) = replayed(&starter).await;

    // No network of the operator: no document.
    let mut no_networks = settings.clone();
    no_networks.share.addresses.operator_networks.clear();
    let error = sharing::abuse_report(&no_networks, incident_id, report_time())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with("the section `share` has no `operator_networks`.")
                && message.ends_with("AEGIS wrote no document")),
        "{error:?}"
    );

    // The service can run: the function only reads the files.
    let bundle = sharing::abuse_report(&settings, incident_id, report_time())
        .await
        .unwrap();
    assert_eq!(bundle.incident_id, incident_id);
    assert_eq!(
        bundle.evidence.incident_source,
        Some(IncidentSource::EvidenceArchive)
    );
    assert_eq!(bundle.evidence.detections, 9);
    assert_eq!(bundle.evidence.events, 18);
    assert_eq!(bundle.evidence.events_not_in_archive, 0);
    assert_eq!(bundle.evidence.detections_not_in_archive, 0);
    assert_eq!(bundle.evidence.audit_records, 9);
    assert_eq!(bundle.evidence.audit_records_checked, 156);
    assert_eq!(bundle.package.reports.len(), 3);
    let files = bundle.files().unwrap();
    assert_eq!(files.len(), 12);
    assert_eq!(
        files[0].path,
        std::path::Path::new("address-192.0.2.77/report.md")
    );
    for report in &bundle.package.reports {
        report.check().unwrap();
        report
            .manifest
            .verify_file(&report.evidence_jsonl())
            .unwrap();
        assert_eq!(report.generated_at, report_time());
    }
    // The same data and the same time give the same reports.
    let again = sharing::abuse_report(&settings, incident_id, report_time())
        .await
        .unwrap();
    assert_eq!(again, bundle);

    // With the office network as the only permitted range, each attacker address of the
    // recorded log is in a documentation range, so no report names it.
    let mut strict = settings.clone();
    strict.share.addresses.permit_documentation_ranges = false;
    let none = sharing::abuse_report(&strict, incident_id, report_time())
        .await
        .unwrap();
    assert_eq!(none.package.reports, []);
    assert_eq!(none.files().unwrap(), []);
    let notes = none.notes();
    assert_eq!(notes.len(), 3);
    assert_eq!(
        notes[0],
        "No report names the address 192.0.2.77: its class is documentation."
    );

    // An incident that no source has.
    let unknown = IncidentId::new();
    let error = sharing::abuse_report(&settings, unknown, report_time())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message)
            if message.starts_with(&format!("the incident {unknown} was not found."))
                && message.contains("holds 1 incidents")),
        "{error:?}"
    );

    // A person closes the incident as a false positive. It gives no report, and its
    // detections give no indicator.
    let mut closed = app.incidents().get(incident_id).await.unwrap().unwrap();
    closed.status = IncidentStatus::FalsePositive;
    app.incidents().save(&closed).await.unwrap();
    let error = sharing::abuse_report(&settings, incident_id, report_time())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("false_positive")),
        "{error:?}"
    );
    let bundle = sharing::indicators(&settings, None).await.unwrap();
    assert_eq!(bundle.shared.indicators, []);
    assert_eq!(bundle.false_positive_incidents, 1);
    assert_eq!(bundle.evidence.detections, 0);
    let error = sharing::indicators(&settings, Some(incident_id))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)), "{error:?}");
}

#[tokio::test]
async fn the_indicators_name_only_the_attacker_side_and_a_changed_audit_log_is_refused() {
    let starter = Starter::new();
    let (app, settings, incident_id) = replayed(&starter).await;

    let bundle = sharing::indicators(&settings, Some(incident_id))
        .await
        .unwrap();
    let values: Vec<&str> = bundle
        .shared
        .indicators
        .iter()
        .map(|indicator| indicator.value.as_str())
        .collect();
    assert_eq!(
        values,
        [
            "192.0.2.77",
            "203.0.113.50",
            "203.0.113.51",
            "python-httpx/0.27.0"
        ]
    );
    // The recorded attack log has no decoy.
    assert_eq!(bundle.decoy, []);
    let stix: serde_json::Value = serde_json::from_str(
        &bundle
            .stix(Tlp::Red, report_time(), Some("Example SOC"))
            .unwrap(),
    )
    .unwrap();
    let objects = stix["objects"].as_array().unwrap();
    // The marking, the identity of the producer, and four indicators.
    assert_eq!(objects.len(), 6);
    assert_eq!(objects[0]["name"], "TLP:RED");
    assert_eq!(objects[1]["type"], "identity");
    assert_eq!(objects[1]["name"], "Example SOC");
    let csv = bundle.csv(Tlp::White);
    assert_eq!(csv.matches("\r\n").count(), 5);
    assert!(csv.contains(",TLP:WHITE\r\n"), "{csv}");
    // All detections of the archive give the same indicators as the one incident.
    let all = sharing::indicators(&settings, None).await.unwrap();
    assert_eq!(all.shared, bundle.shared);

    // The office network is not the network of the operator in this configuration: an
    // address of the spray range is. The export then never names that range.
    let mut other = settings.clone();
    other.share.addresses.operator_networks = vec!["203.0.113.0/24".parse().unwrap()];
    let narrowed = sharing::indicators(&other, Some(incident_id))
        .await
        .unwrap();
    let values: Vec<&str> = narrowed
        .shared
        .indicators
        .iter()
        .map(|indicator| indicator.value.as_str())
        .collect();
    // The client at the distant address shows the same user agent, so the user agent stays.
    assert_eq!(values, ["192.0.2.77", "python-httpx/0.27.0"]);
    assert_eq!(
        narrowed.skipped(),
        ["2 values were left out: operator_address."]
    );

    // One changed byte in the audit log: the log is not evidence, and no document is made.
    drop(app);
    let audit = starter.audit_file();
    let text = std::fs::read_to_string(&audit).unwrap();
    let title = "Sign-in burst from one address";
    assert!(text.contains(title));
    std::fs::write(
        &audit,
        text.replacen(title, "Sign-in burst from two addresses", 1),
    )
    .unwrap();
    for error in [
        sharing::abuse_report(&settings, incident_id, report_time())
            .await
            .unwrap_err(),
        sharing::indicators(&settings, None).await.unwrap_err(),
    ] {
        assert!(
            matches!(&error, Error::Integrity(message)
                if message.starts_with("the hash chain of the audit log is not valid")),
            "{error:?}"
        );
    }
}
