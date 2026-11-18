//! Tests of the incident store.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use aegis_contracts::common::{
    DetectionId, EntityKind, EntityRef, EventId, EvidenceKind, EvidenceRef, IncidentId, Severity,
};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry};
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;

use crate::support::TestDb;

fn incident(title: &str, status: IncidentStatus, age_seconds: i64) -> Incident {
    Incident {
        id: IncidentId::new(),
        title: title.to_owned(),
        summary: String::new(),
        severity: Severity::High,
        status,
        created_at: Utc::now() - Duration::seconds(age_seconds),
        updated_at: Utc::now(),
        tenant: None,
        detections: Vec::new(),
        entities: Vec::new(),
        attack: Vec::new(),
        timeline: Vec::new(),
    }
}

fn titles(incidents: Vec<Incident>) -> Vec<String> {
    incidents.into_iter().map(|item| item.title).collect()
}

#[tokio::test]
async fn incidents_list_newest_first_with_an_optional_status_filter() {
    let database = TestDb::new().await;
    let store = database.store.incidents();
    let old = incident("old", IncidentStatus::Open, 300);
    let contained = incident("contained", IncidentStatus::Contained, 200);
    let new = incident("new", IncidentStatus::Open, 100);
    for item in [&old, &contained, &new] {
        store.save(item).await.unwrap();
    }

    assert_eq!(
        titles(store.list(None, 10).await.unwrap()),
        ["new", "contained", "old"]
    );
    assert_eq!(
        titles(store.list(Some(IncidentStatus::Open), 10).await.unwrap()),
        ["new", "old"]
    );
    assert_eq!(titles(store.list(None, 1).await.unwrap()), ["new"]);
    assert_eq!(store.list(None, 0).await.unwrap(), Vec::new());
    assert_eq!(
        store
            .list(Some(IncidentStatus::FalsePositive), 10)
            .await
            .unwrap(),
        Vec::new()
    );

    let mut changed = old.clone();
    changed.status = IncidentStatus::Resolved;
    store.save(&changed).await.unwrap();
    assert_eq!(store.get(old.id).await.unwrap(), Some(changed));
    assert_eq!(store.get(IncidentId::new()).await.unwrap(), None);
    assert_eq!(store.list(None, 10).await.unwrap().len(), 3);
    // The status filter uses the new status of the changed incident.
    assert_eq!(
        titles(store.list(Some(IncidentStatus::Open), 10).await.unwrap()),
        ["new"]
    );
    assert_eq!(
        titles(
            store
                .list(Some(IncidentStatus::Resolved), 10)
                .await
                .unwrap()
        ),
        ["old"]
    );
}

#[tokio::test]
async fn each_status_is_a_filter() {
    let database = TestDb::new().await;
    let store = database.store.incidents();
    let statuses = [
        IncidentStatus::Open,
        IncidentStatus::Investigating,
        IncidentStatus::Contained,
        IncidentStatus::Resolved,
        IncidentStatus::FalsePositive,
    ];
    for (age, status) in (0..).zip(statuses) {
        store
            .save(&incident(&format!("{status:?}"), status, age))
            .await
            .unwrap();
    }
    for status in statuses {
        assert_eq!(
            titles(store.list(Some(status), 10).await.unwrap()),
            [format!("{status:?}")]
        );
    }
}

#[tokio::test]
async fn incidents_one_nanosecond_apart_are_in_time_order() {
    let database = TestDb::new().await;
    let store = database.store.incidents();
    let base = Utc.with_ymd_and_hms(2026, 5, 6, 7, 8, 9).unwrap();
    // The identifiers go up with the times. Thus the order of the identifiers is oldest
    // first, and only the full time gives the order newest first.
    let mut items: Vec<Incident> = ["first", "second", "third"]
        .iter()
        .map(|title| incident(title, IncidentStatus::Open, 0))
        .collect();
    for (item, nanoseconds) in items.iter_mut().zip([1, 2, 3]) {
        item.created_at = base + Duration::nanoseconds(nanoseconds);
    }
    assert!(items[0].id < items[1].id && items[1].id < items[2].id);
    for item in &items {
        store.save(item).await.unwrap();
    }
    assert_eq!(
        titles(store.list(None, 10).await.unwrap()),
        ["third", "second", "first"]
    );
    assert_eq!(
        titles(store.list(Some(IncidentStatus::Open), 2).await.unwrap()),
        ["third", "second"]
    );
}

#[tokio::test]
async fn an_incident_keeps_each_field() {
    let database = TestDb::new().await;
    let store = database.store.incidents();
    let user = EntityRef::new(EntityKind::User, "user-1")
        .with_name("Alice")
        .with_tenant("contoso");
    let time =
        Utc.with_ymd_and_hms(2026, 5, 6, 7, 8, 9).unwrap() + Duration::nanoseconds(123_456_789);
    let technique =
        AttackTechnique::new("persistence", "T1098.001", "Additional Cloud Credentials");
    let detection = Detection {
        id: DetectionId::new(),
        rule_id: "velocity.credential_add".to_owned(),
        title: "Credential added to an application".to_owned(),
        description: "A service principal got a new secret. \"Quoted\" text and a\nnew line."
            .to_owned(),
        severity: Severity::High,
        verdict: Verdict::Suspicious,
        tier: DetectionTier::Deterministic,
        time,
        attack: vec![technique.clone()],
        event_ids: vec![EventId::new(), EventId::new()],
        entities: vec![user.clone()],
        tenant: Some("contoso".to_owned()),
        attributes: BTreeMap::from([
            ("rate".to_owned(), json!(0.1 + 0.2)),
            ("count".to_owned(), json!(u64::MAX)),
            (
                "window".to_owned(),
                json!({ "seconds": 60, "limits": [1.5, null] }),
            ),
        ]),
    };
    let saved = Incident {
        id: IncidentId::new(),
        title: "Credential abuse \u{1F512}".to_owned(),
        summary: "An attacker added a credential and signed in.".to_owned(),
        severity: Severity::Critical,
        status: IncidentStatus::Investigating,
        created_at: time,
        updated_at: time + Duration::nanoseconds(1),
        tenant: Some("contoso".to_owned()),
        detections: vec![detection],
        entities: vec![user, EntityRef::new(EntityKind::IpAddress, "203.0.113.7")],
        attack: vec![technique],
        timeline: vec![TimelineEntry {
            time,
            author: "analyst".to_owned(),
            description: "Confirmed the sign-in burst.".to_owned(),
            evidence: vec![
                EvidenceRef::new(EvidenceKind::Event, EventId::new()).with_note("First sign-in."),
            ],
        }],
    };

    store.save(&saved).await.unwrap();
    assert_eq!(store.get(saved.id).await.unwrap(), Some(saved.clone()));
    assert_eq!(store.list(None, 10).await.unwrap(), vec![saved.clone()]);
    assert_eq!(
        store
            .list(Some(IncidentStatus::Investigating), 10)
            .await
            .unwrap(),
        vec![saved]
    );
}
