//! Tests of the hash-chained audit log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::audit::{
    AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification, GENESIS_HASH, seal,
    verify_chain,
};
use aegis_contracts::common::{EvidenceKind, EvidenceRef};
use aegis_storage::{PgAuditLog, PgStore};
use chrono::{SubsecRound, Utc};
use serde_json::json;
use sqlx::postgres::PgConnection;
use sqlx::{Connection, Executor};

use crate::support::{TestDb, config, message, sqlstate};

async fn log_with(database: &TestDb, count: usize) -> PgAuditLog {
    let log = database.store.audit();
    for index in 0..count {
        log.append(AuditEntry::new(
            AuditKind::AgentDecision,
            "analyst",
            format!("Decision {index}."),
        ))
        .await
        .unwrap();
    }
    log
}

fn sequences(records: &[AuditRecord]) -> Vec<u64> {
    records.iter().map(|record| record.sequence).collect()
}

fn valid(checked: u64) -> ChainVerification {
    ChainVerification {
        valid: true,
        checked,
        first_invalid_sequence: None,
        reason: None,
    }
}

/// Inserts a record with plain SQL, as a client that does not use the store.
async fn insert_record(
    sql: &mut PgConnection,
    record: &AuditRecord,
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO aegis.audit_log \
             (sequence, id, recorded_at, kind, actor, summary, payload, evidence, prev_hash, hash) \
         VALUES ($1, $2, $3, 'other', $4, $5, 'null', '[]', $6, $7)",
    )
    .bind(i64::try_from(record.sequence).unwrap())
    .bind(record.id.0)
    .bind(record.time)
    .bind(&record.actor)
    .bind(&record.summary)
    .bind(&record.prev_hash)
    .bind(&record.hash)
    .execute(sql)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn append_builds_a_chain_that_verifies() {
    let database = TestDb::new().await;
    let empty = database.store.audit();
    assert_eq!(empty.verify().await.unwrap(), valid(0));
    assert_eq!(empty.read(1, 10).await.unwrap(), Vec::new());

    let log = log_with(&database, 3).await;
    let records = log.read(1, 10).await.unwrap();
    assert_eq!(sequences(&records), [1, 2, 3]);
    assert_eq!(records[0].prev_hash, GENESIS_HASH);
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[2].prev_hash, records[1].hash);
    assert_eq!(records[2].summary, "Decision 2.");
    assert_eq!(log.verify().await.unwrap(), valid(3));
    // The records that the store read form a chain for the contract function too.
    assert_eq!(verify_chain(None, &records).unwrap(), valid(3));
    // The times do not go back.
    assert!(records.windows(2).all(|pair| pair[0].time <= pair[1].time));
}

#[tokio::test]
async fn read_starts_at_the_sequence_and_obeys_the_limit() {
    let database = TestDb::new().await;
    let log = log_with(&database, 5).await;
    assert_eq!(sequences(&log.read(2, 2).await.unwrap()), [2, 3]);
    assert_eq!(sequences(&log.read(0, 10).await.unwrap()), [1, 2, 3, 4, 5]);
    assert_eq!(sequences(&log.read(5, 10).await.unwrap()), [5]);
    assert_eq!(log.read(6, 10).await.unwrap(), Vec::new());
    assert_eq!(log.read(1, 0).await.unwrap(), Vec::new());
    assert_eq!(log.read(u64::MAX, 10).await.unwrap(), Vec::new());
}

#[tokio::test]
async fn a_record_survives_a_round_trip_with_exactly_the_same_hash() {
    let database = TestDb::new().await;
    let log = database.store.audit();
    let payload = json!({
        "score": 0.1 + 0.2,
        "ratio": 1.0,
        "third": 1.0 / 3.0,
        "tiny": 5e-324,
        "huge": 1.797_693_134_862_315_7e308,
        "exponent": 1e21,
        "small_exponent": 1.5e-7,
        // A parser with less than full precision gives a different number for each of
        // these values.
        "hard_to_parse": [
            1.071_566_039_146_582_6e-75,
            -1.603_964_615_428_183e143,
            3.026_199_944_157_320_3e-52,
        ],
        "negative_zero": -0.0,
        "big_unsigned": u64::MAX,
        "smallest": i64::MIN,
        "text": "Zoë \u{1F512} \"quoted\" back\\slash\nnew line \u{0} end",
        "nested": {
            "list": [1, 2.5, null, true, { "deep": { "deeper": [0.1, 1e-10, 123_456_789.125] } }],
            "empty_object": {},
            "empty_list": [],
        },
    });
    let evidence = vec![
        EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("Sign-in burst."),
        EvidenceRef::new(EvidenceKind::External, "TICKET-7"),
    ];
    let before = Utc::now().trunc_subsecs(6);
    let appended = log
        .append(
            AuditEntry::new(AuditKind::ActionExecuted, "responder", "Disabled a user.")
                .with_payload(payload.clone())
                .with_evidence(evidence.clone()),
        )
        .await
        .unwrap();

    assert_eq!(appended.sequence, 1);
    assert_eq!(appended.kind, AuditKind::ActionExecuted);
    assert_eq!(appended.actor, "responder");
    assert_eq!(appended.summary, "Disabled a user.");
    assert_eq!(appended.payload, payload);
    assert_eq!(appended.evidence, evidence);
    assert_eq!(appended.prev_hash, GENESIS_HASH);
    assert_eq!(appended.hash, appended.compute_hash().unwrap());
    // The time has microsecond precision and is the present time.
    assert_eq!(appended.time, appended.time.trunc_subsecs(6));
    assert!(appended.time >= before - chrono::Duration::seconds(60));
    assert!(appended.time <= Utc::now() + chrono::Duration::seconds(60));

    // A second process reads the record from the table.
    let read = database
        .second_store()
        .await
        .audit()
        .read(1, 10)
        .await
        .unwrap();
    assert_eq!(read, vec![appended.clone()]);
    assert_eq!(read[0].hash, appended.hash);
    assert_eq!(read[0].compute_hash().unwrap(), appended.hash);
    assert_eq!(
        serde_json::to_string(&read[0]).unwrap(),
        serde_json::to_string(&appended).unwrap()
    );
    assert_eq!(log.verify().await.unwrap(), valid(1));

    // The table holds the payload and the evidence as the JSON text of the record.
    let mut sql = database.sql().await;
    let (stored_payload, stored_evidence, payload_type): (String, String, String) = sqlx::query_as(
        "SELECT payload, evidence, pg_catalog.pg_typeof(payload)::text \
             FROM aegis.audit_log WHERE sequence = 1",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    sql.close().await.unwrap();
    assert_eq!(stored_payload, serde_json::to_string(&payload).unwrap());
    assert_eq!(stored_evidence, serde_json::to_string(&evidence).unwrap());
    assert_eq!(payload_type, "text");
}

#[tokio::test]
async fn a_direct_update_or_delete_is_rejected_by_the_trigger() {
    let database = TestDb::new().await;
    let log = log_with(&database, 3).await;
    let before = log.read(1, 10).await.unwrap();
    // The connection is a superuser, so only the trigger can reject the statements.
    let mut sql = database.sql().await;

    let statements = [
        (
            "UPDATE aegis.audit_log SET summary = 'Changed.' WHERE sequence = 2",
            "UPDATE",
        ),
        (
            "UPDATE aegis.audit_log SET hash = repeat('a', 64) WHERE sequence = 3",
            "UPDATE",
        ),
        ("UPDATE aegis.audit_log SET summary = summary", "UPDATE"),
        ("DELETE FROM aegis.audit_log WHERE sequence = 3", "DELETE"),
        ("DELETE FROM aegis.audit_log", "DELETE"),
        ("TRUNCATE aegis.audit_log", "TRUNCATE"),
    ];
    for (statement, operation) in statements {
        let error = sql.execute(statement).await.unwrap_err();
        assert_eq!(sqlstate(&error), "23000", "{statement}");
        assert_eq!(
            message(&error),
            format!("the audit log is append-only: {operation} is not permitted"),
            "{statement}"
        );
    }
    sql.close().await.unwrap();

    assert_eq!(log.read(1, 10).await.unwrap(), before);
    assert_eq!(log.verify().await.unwrap(), valid(3));
}

#[tokio::test]
async fn a_direct_insert_that_does_not_continue_the_chain_is_rejected() {
    let database = TestDb::new().await;
    let log = log_with(&database, 2).await;
    let records = log.read(1, 10).await.unwrap();
    let mut sql = database.sql().await;
    let entry = || AuditEntry::new(AuditKind::Other, "intruder", "Forged.");

    // A record that takes a position that is in use.
    let fork = seal(Some(&records[0]), entry(), Utc::now()).unwrap();
    assert_eq!(fork.sequence, 2);
    // A record that leaves a gap.
    let mut gap = seal(Some(&records[1]), entry(), Utc::now()).unwrap();
    gap.sequence = 4;
    // A record at the next position that does not link to the last record.
    let mut unlinked = seal(Some(&records[1]), entry(), Utc::now()).unwrap();
    unlinked.prev_hash = records[0].hash.clone();

    for forged in [&fork, &gap, &unlinked] {
        let error = insert_record(&mut sql, forged).await.unwrap_err();
        assert_eq!(sqlstate(&error), "23000", "{forged:?}");
        assert_eq!(
            message(&error),
            "the audit record does not continue the chain after sequence 2"
        );
    }
    assert_eq!(log.read(1, 10).await.unwrap(), records);

    // A record that continues the chain is accepted, also from a client that is not the store.
    let next = seal(Some(&records[1]), entry(), Utc::now()).unwrap();
    insert_record(&mut sql, &next).await.unwrap();
    sql.close().await.unwrap();
    assert_eq!(log.verify().await.unwrap(), valid(3));
    assert_eq!(sequences(&log.read(1, 10).await.unwrap()), [1, 2, 3]);
    // The store continues after that record.
    let after = log.append(entry()).await.unwrap();
    assert_eq!(after.sequence, 4);
    assert_eq!(after.prev_hash, next.hash);
}

#[tokio::test]
async fn verify_finds_a_change_that_went_around_the_trigger() {
    let database = TestDb::new().await;
    let log = log_with(&database, 4).await;
    assert_eq!(log.verify().await.unwrap(), valid(4));

    // Only the owner of the table can switch the trigger off.
    let mut sql = database.sql().await;
    sql.execute("ALTER TABLE aegis.audit_log DISABLE TRIGGER audit_log_append_only")
        .await
        .unwrap();
    sql.execute("UPDATE aegis.audit_log SET summary = 'Changed.' WHERE sequence = 3")
        .await
        .unwrap();

    let report = log.verify().await.unwrap();
    assert_eq!(
        report,
        ChainVerification {
            valid: false,
            checked: 2,
            first_invalid_sequence: Some(3),
            reason: Some("hash does not match the record contents".to_owned()),
        }
    );

    // A removed record breaks the chain at the record after it.
    sql.execute("DELETE FROM aegis.audit_log WHERE sequence = 2")
        .await
        .unwrap();
    sql.close().await.unwrap();
    let report = log.verify().await.unwrap();
    assert_eq!(
        report,
        ChainVerification {
            valid: false,
            checked: 1,
            first_invalid_sequence: Some(3),
            reason: Some("expected sequence 2, found 3".to_owned()),
        }
    );
}

#[tokio::test]
async fn a_changed_payload_number_format_breaks_the_chain() {
    let database = TestDb::new().await;
    let log = database.store.audit();
    log.append(
        AuditEntry::new(AuditKind::Detection, "tier1", "Found a burst.")
            .with_payload(json!({ "rate": 0.1 + 0.2 })),
    )
    .await
    .unwrap();

    let mut sql = database.sql().await;
    sql.execute("ALTER TABLE aegis.audit_log DISABLE TRIGGER audit_log_append_only")
        .await
        .unwrap();
    // The number 0.30000000000000004 becomes 0.3, as a rounding store would write it.
    let changed = sql
        .execute(
            "UPDATE aegis.audit_log \
             SET payload = replace(payload, '0.30000000000000004', '0.3') WHERE sequence = 1",
        )
        .await
        .unwrap();
    sql.close().await.unwrap();
    assert_eq!(changed.rows_affected(), 1);

    let read = log.read(1, 1).await.unwrap();
    assert_eq!(read[0].payload, json!({ "rate": 0.3 }));
    let report = log.verify().await.unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_invalid_sequence, Some(1));
}

#[tokio::test]
async fn concurrent_appends_from_several_tasks_produce_one_unbroken_chain() {
    const STORES: usize = 3;
    const TASKS: usize = 24;
    const APPENDS_PER_TASK: usize = 5;

    let database = TestDb::new().await;
    // Each store has its own connection pool, as each process has.
    let mut stores: Vec<PgStore> = vec![database.store.clone()];
    while stores.len() < STORES {
        stores.push(database.second_store().await);
    }

    let mut tasks = tokio::task::JoinSet::new();
    for task in 0..TASKS {
        let log = stores[task % STORES].audit();
        tasks.spawn(async move {
            let mut appended = Vec::new();
            for index in 0..APPENDS_PER_TASK {
                let entry = AuditEntry::new(
                    AuditKind::ActionProposed,
                    format!("task-{task}"),
                    format!("Entry {index}."),
                )
                .with_payload(json!({ "task": task, "index": index }));
                appended.push(log.append(entry).await?);
            }
            Ok::<_, Error>(appended)
        });
    }
    let results = tokio::time::timeout(Duration::from_secs(120), tasks.join_all())
        .await
        .unwrap();
    assert_eq!(results.len(), TASKS);
    let mut returned: Vec<AuditRecord> = Vec::new();
    for result in results {
        let appended = result.unwrap();
        assert_eq!(appended.len(), APPENDS_PER_TASK);
        // One task sees its own records in the order of its appends.
        assert!(
            appended
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        returned.extend(appended);
    }

    let total = TASKS * APPENDS_PER_TASK;
    let log = stores[0].audit();
    let records = log.read(1, total + 10).await.unwrap();
    assert_eq!(records.len(), total);
    let expected: Vec<u64> = (1..=u64::try_from(total).unwrap()).collect();
    assert_eq!(sequences(&records), expected);
    assert_eq!(
        log.verify().await.unwrap(),
        valid(u64::try_from(total).unwrap())
    );
    assert_eq!(
        verify_chain(None, &records).unwrap(),
        valid(u64::try_from(total).unwrap())
    );
    // No hash and no link appears two times: the chain did not fork.
    let hashes: BTreeSet<&str> = records.iter().map(|record| record.hash.as_str()).collect();
    let links: BTreeSet<&str> = records
        .iter()
        .map(|record| record.prev_hash.as_str())
        .collect();
    assert_eq!(hashes.len(), total);
    assert_eq!(links.len(), total);
    // Each append returned the record that the table holds at that position.
    returned.sort_by_key(|record| record.sequence);
    assert_eq!(returned, records);
    // The times do not go back.
    assert!(records.windows(2).all(|pair| pair[0].time <= pair[1].time));
}

#[tokio::test]
async fn verify_checks_a_log_that_is_longer_than_one_page() {
    const RECORDS: usize = 1_203;

    let database = TestDb::new().await;
    // Seal the chain here and write it with one statement. The store reads it in pages.
    let mut chain: Vec<AuditRecord> = Vec::with_capacity(RECORDS);
    for index in 0..RECORDS {
        let entry = AuditEntry::new(AuditKind::Other, "loader", format!("Record {index}."));
        let record = seal(chain.last(), entry, Utc::now()).unwrap();
        chain.push(record);
    }
    let mut sql = database.sql().await;
    let inserted = sqlx::query(
        "INSERT INTO aegis.audit_log \
             (sequence, id, recorded_at, kind, actor, summary, payload, evidence, prev_hash, hash) \
         SELECT sequence, id, recorded_at, 'other', 'loader', summary, 'null', '[]', prev_hash, hash \
         FROM unnest($1::bigint[], $2::uuid[], $3::timestamptz[], $4::text[], $5::text[], $6::text[]) \
             AS r (sequence, id, recorded_at, summary, prev_hash, hash) \
         ORDER BY sequence",
    )
    .bind(
        chain
            .iter()
            .map(|record| i64::try_from(record.sequence).unwrap())
            .collect::<Vec<i64>>(),
    )
    .bind(chain.iter().map(|record| record.id.0).collect::<Vec<_>>())
    .bind(chain.iter().map(|record| record.time).collect::<Vec<_>>())
    .bind(
        chain
            .iter()
            .map(|record| record.summary.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        chain
            .iter()
            .map(|record| record.prev_hash.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        chain
            .iter()
            .map(|record| record.hash.clone())
            .collect::<Vec<_>>(),
    )
    .execute(&mut sql)
    .await
    .unwrap();
    assert_eq!(inserted.rows_affected(), u64::try_from(RECORDS).unwrap());

    let log = database.store.audit();
    let total = u64::try_from(RECORDS).unwrap();
    assert_eq!(log.verify().await.unwrap(), valid(total));
    assert_eq!(log.read(1, RECORDS + 10).await.unwrap(), chain);
    // The store appends after the last record of the last page.
    let appended = log
        .append(AuditEntry::new(AuditKind::Other, "store", "One more."))
        .await
        .unwrap();
    assert_eq!(appended.sequence, total + 1);
    assert_eq!(appended.prev_hash, chain[RECORDS - 1].hash);
    assert_eq!(log.verify().await.unwrap(), valid(total + 1));

    sql.execute("ALTER TABLE aegis.audit_log DISABLE TRIGGER audit_log_append_only")
        .await
        .unwrap();
    sql.execute("UPDATE aegis.audit_log SET actor = 'intruder' WHERE sequence = 1100")
        .await
        .unwrap();
    sql.close().await.unwrap();
    let report = log.verify().await.unwrap();
    assert_eq!(
        report,
        ChainVerification {
            valid: false,
            checked: 1_099,
            first_invalid_sequence: Some(1_100),
            reason: Some("hash does not match the record contents".to_owned()),
        }
    );
}

#[tokio::test]
async fn an_append_that_fails_leaves_no_gap_in_the_chain() {
    let database = TestDb::new().await;
    let log = log_with(&database, 1).await;

    // PostgreSQL text cannot hold the character U+0000.
    let error = log
        .append(AuditEntry::new(AuditKind::Other, "actor\0", "Not stored."))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("SQLSTATE 22021")),
        "{error:?}"
    );

    let next = log
        .append(AuditEntry::new(AuditKind::Other, "actor", "Stored."))
        .await
        .unwrap();
    assert_eq!(next.sequence, 2);
    assert_eq!(log.verify().await.unwrap(), valid(2));
}

#[tokio::test]
async fn a_role_with_only_insert_and_select_can_append_and_cannot_change_a_record() {
    let mut database = TestDb::new().await;
    log_with(&database, 2).await;
    let password = "app-role-password";
    let role = database.create_role(password).await;

    database
        .run_for_identifier(
            &[
                "GRANT USAGE ON SCHEMA aegis TO %I",
                "GRANT INSERT, SELECT ON aegis.audit_log TO %I",
            ],
            &role,
        )
        .await;

    let url = database.url_for_role(&role, password);
    let store = PgStore::connect(&config(&url)).await.unwrap();
    let log = store.audit();
    let appended = log
        .append(AuditEntry::new(
            AuditKind::PolicyDecision,
            "policy",
            "Permitted an action.",
        ))
        .await
        .unwrap();
    assert_eq!(appended.sequence, 3);
    assert_eq!(sequences(&log.read(1, 10).await.unwrap()), [1, 2, 3]);
    assert_eq!(log.verify().await.unwrap(), valid(3));

    // The role has no privilege to change, remove, or empty the table.
    let mut sql = PgConnection::connect(&url).await.unwrap();
    for statement in [
        "UPDATE aegis.audit_log SET summary = 'Changed.' WHERE sequence = 1",
        "DELETE FROM aegis.audit_log WHERE sequence = 1",
        "TRUNCATE aegis.audit_log",
        "ALTER TABLE aegis.audit_log DISABLE TRIGGER audit_log_append_only",
    ] {
        let error = sql.execute(statement).await.unwrap_err();
        assert_eq!(sqlstate(&error), "42501", "{statement}");
    }
    sql.close().await.unwrap();
    assert_eq!(log.verify().await.unwrap(), valid(3));
}
