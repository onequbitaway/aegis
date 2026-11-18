//! The hash-chained audit log.
//!
//! # Storage
//!
//! The table `aegis.audit_log` holds one row for each record. The table keeps each field
//! byte for byte:
//!
//! - The payload and the evidence are JSON text. The `jsonb` type can change the format of
//!   a number, and then the hash of the record changes.
//! - The time is `timestamptz`, which keeps microseconds. A sealed record has no smaller
//!   time unit.
//!
//! # One chain
//!
//! An append runs in one transaction. The transaction takes an advisory lock, reads the
//! last record, seals the next record, and writes it. The lock is in the database, so the
//! appends of all processes run one after the other. If a client does not take the lock,
//! the primary key and a trigger still reject a second record with the same position.
//!
//! # Privileges
//!
//! The application role needs only `INSERT` and `SELECT` on `aegis.audit_log`. A trigger
//! rejects `UPDATE`, `DELETE`, and `TRUNCATE` for each role that keeps triggers on.

use aegis_contracts::audit::{
    AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification, seal, verify_chain,
};
use aegis_contracts::common::AuditId;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::error::db_error;
use crate::json::{sql_limit, variant_from_name, variant_name};

/// The two keys of the advisory lock for appends.
///
/// The first key is the ASCII text `aegi`. The second key selects the audit log. The
/// database driver uses the one-key form of the lock for migrations, so the keys cannot
/// collide.
const APPEND_LOCK_KEYS: (i32, i32) = (0x6165_6769, 1);

/// The number of records that one step of a chain check reads.
const VERIFY_PAGE_SIZE: i64 = 500;

/// Starts the transaction of an append.
///
/// With this isolation level, the statement after the lock sees each record that a
/// different session committed while this session waited for the lock.
const BEGIN_APPEND: &str = "BEGIN ISOLATION LEVEL READ COMMITTED";

const LOCK_APPENDS: &str = "SELECT pg_catalog.pg_advisory_xact_lock($1, $2)";

const DATABASE_TIME: &str = "SELECT pg_catalog.clock_timestamp()";

/// Reads the last record and the clock of the database server in one statement.
const READ_LAST: &str = "SELECT pg_catalog.clock_timestamp(), sequence, id, recorded_at, kind, \
         actor, summary, payload, evidence, prev_hash, hash \
     FROM aegis.audit_log \
     ORDER BY sequence DESC \
     LIMIT 1";

const READ_FROM: &str = "SELECT sequence, id, recorded_at, kind, actor, summary, payload, \
         evidence, prev_hash, hash \
     FROM aegis.audit_log \
     WHERE sequence >= $1 \
     ORDER BY sequence ASC \
     LIMIT $2";

const INSERT: &str = "INSERT INTO aegis.audit_log \
         (sequence, id, recorded_at, kind, actor, summary, payload, evidence, prev_hash, hash) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// One row of the audit table, in column order.
type AuditRow = (
    i64,
    Uuid,
    DateTime<Utc>,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// The clock of the database server and the last row of the audit table.
type LastRow = (
    DateTime<Utc>,
    i64,
    Uuid,
    DateTime<Utc>,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// The column values of one record.
#[derive(Debug, Clone, PartialEq)]
struct StoredRecord {
    sequence: i64,
    id: Uuid,
    recorded_at: DateTime<Utc>,
    kind: String,
    actor: String,
    summary: String,
    payload: String,
    evidence: String,
    prev_hash: String,
    hash: String,
}

impl From<AuditRow> for StoredRecord {
    fn from(row: AuditRow) -> Self {
        let (sequence, id, recorded_at, kind, actor, summary, payload, evidence, prev_hash, hash) =
            row;
        Self {
            sequence,
            id,
            recorded_at,
            kind,
            actor,
            summary,
            payload,
            evidence,
            prev_hash,
            hash,
        }
    }
}

impl StoredRecord {
    /// Makes the column values of a record.
    fn from_record(record: &AuditRecord) -> Result<Self> {
        let sequence = i64::try_from(record.sequence).map_err(|_| {
            Error::Integrity(format!(
                "audit: sequence {} is too large for the database",
                record.sequence
            ))
        })?;
        Ok(Self {
            sequence,
            id: record.id.0,
            recorded_at: record.time,
            kind: variant_name(&record.kind)?,
            actor: record.actor.clone(),
            summary: record.summary.clone(),
            payload: serde_json::to_string(&record.payload)?,
            evidence: serde_json::to_string(&record.evidence)?,
            prev_hash: record.prev_hash.clone(),
            hash: record.hash.clone(),
        })
    }

    /// Makes the record from the column values.
    ///
    /// A row that does not decode is an integrity failure: only a change that went around
    /// the store can make such a row.
    fn into_record(self) -> Result<AuditRecord> {
        let sequence = self.sequence;
        let integrity = |field: &str, detail: String| {
            Error::Integrity(format!(
                "audit: the {field} of record {sequence} cannot be decoded: {detail}"
            ))
        };
        let kind: AuditKind = variant_from_name("the audit kind", &self.kind)
            .map_err(|error| integrity("kind", error.to_string()))?;
        Ok(AuditRecord {
            sequence: u64::try_from(sequence)
                .map_err(|error| integrity("sequence", error.to_string()))?,
            id: AuditId(self.id),
            time: self.recorded_at,
            kind,
            actor: self.actor,
            summary: self.summary,
            payload: serde_json::from_str(&self.payload)
                .map_err(|error| integrity("payload", error.to_string()))?,
            evidence: serde_json::from_str(&self.evidence)
                .map_err(|error| integrity("evidence", error.to_string()))?,
            prev_hash: self.prev_hash,
            hash: self.hash,
        })
    }
}

/// Checks one page of rows that continues the chain after `anchor`.
///
/// `checked_before` is the number of records that the check already examined. The result
/// counts all records from the start of the chain.
fn verify_page(
    anchor: Option<&AuditRecord>,
    rows: Vec<StoredRecord>,
    checked_before: u64,
) -> Result<(ChainVerification, Option<AuditRecord>)> {
    let mut records = Vec::with_capacity(rows.len());
    let mut undecodable = None;
    for row in rows {
        let sequence = row.sequence;
        match row.into_record() {
            Ok(record) => records.push(record),
            Err(error) => {
                undecodable = Some((sequence, error.to_string()));
                break;
            }
        }
    }
    let report = verify_chain(anchor, &records)?;
    let checked = checked_before + report.checked;
    if !report.valid {
        return Ok((ChainVerification { checked, ..report }, None));
    }
    if let Some((sequence, reason)) = undecodable {
        return Ok((
            ChainVerification {
                valid: false,
                checked,
                first_invalid_sequence: u64::try_from(sequence).ok(),
                reason: Some(reason),
            },
            None,
        ));
    }
    Ok((ChainVerification { checked, ..report }, records.pop()))
}

/// The audit log in the table `aegis.audit_log`.
///
/// Get a value from [`PgStore::audit`](crate::PgStore::audit).
#[derive(Debug, Clone)]
pub struct PgAuditLog {
    pool: PgPool,
}

impl PgAuditLog {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn read_rows(&self, from_sequence: i64, limit: i64) -> Result<Vec<StoredRecord>> {
        let rows: Vec<AuditRow> = sqlx::query_as(READ_FROM)
            .bind(from_sequence)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db_error("read the audit log", error))?;
        Ok(rows.into_iter().map(StoredRecord::from).collect())
    }
}

#[async_trait]
impl AuditLog for PgAuditLog {
    /// Seals `entry` as the next record and writes it.
    ///
    /// The time of the record is the clock of the database server, so all processes use
    /// one clock. The time is never before the time of the record before it.
    ///
    /// # Errors
    ///
    /// - [`Error::Integrity`]: the last record in the table cannot be decoded. The log
    ///   accepts no record until an operator examines the table.
    /// - [`Error::InvalidInput`]: the database cannot hold a value of the entry, for
    ///   example text with the character U+0000. The log does not change.
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord> {
        const OPERATION: &str = "append to the audit log";
        let failed = |error| db_error(OPERATION, error);

        let mut transaction = self.pool.begin_with(BEGIN_APPEND).await.map_err(failed)?;
        sqlx::query(LOCK_APPENDS)
            .bind(APPEND_LOCK_KEYS.0)
            .bind(APPEND_LOCK_KEYS.1)
            .execute(&mut *transaction)
            .await
            .map_err(failed)?;
        let last: Option<LastRow> = sqlx::query_as(READ_LAST)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(failed)?;
        let (now, previous) = match last {
            Some((
                now,
                sequence,
                id,
                recorded_at,
                kind,
                actor,
                summary,
                payload,
                evidence,
                prev_hash,
                hash,
            )) => {
                let row: AuditRow = (
                    sequence,
                    id,
                    recorded_at,
                    kind,
                    actor,
                    summary,
                    payload,
                    evidence,
                    prev_hash,
                    hash,
                );
                (now, Some(StoredRecord::from(row).into_record()?))
            }
            // The table is empty. Only the clock is necessary.
            None => {
                let now: DateTime<Utc> = sqlx::query_scalar(DATABASE_TIME)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(failed)?;
                (now, None)
            }
        };
        let time = previous.as_ref().map_or(now, |record| now.max(record.time));

        let record = seal(previous.as_ref(), entry, time)?;
        let stored = StoredRecord::from_record(&record)?;
        sqlx::query(INSERT)
            .bind(stored.sequence)
            .bind(stored.id)
            .bind(stored.recorded_at)
            .bind(stored.kind)
            .bind(stored.actor)
            .bind(stored.summary)
            .bind(stored.payload)
            .bind(stored.evidence)
            .bind(stored.prev_hash)
            .bind(stored.hash)
            .execute(&mut *transaction)
            .await
            .map_err(failed)?;
        transaction.commit().await.map_err(failed)?;
        Ok(record)
    }

    /// Reads records in sequence order.
    ///
    /// # Errors
    ///
    /// [`Error::Integrity`]: a stored record cannot be decoded.
    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
        let Ok(from_sequence) = i64::try_from(from_sequence) else {
            // No record can have a sequence number this large.
            return Ok(Vec::new());
        };
        self.read_rows(from_sequence, sql_limit(limit))
            .await?
            .into_iter()
            .map(StoredRecord::into_record)
            .collect()
    }

    /// Reads the full table and checks the chain from the first record.
    ///
    /// A record that cannot be decoded makes the chain not valid. It is not an error.
    async fn verify(&self) -> Result<ChainVerification> {
        let mut anchor: Option<AuditRecord> = None;
        let mut checked = 0;
        loop {
            let from_sequence = anchor.as_ref().map_or(Ok(1), |record| {
                i64::try_from(record.sequence + 1).map_err(|_| {
                    Error::Integrity("audit: the sequence is too large for the database".to_owned())
                })
            })?;
            let rows = self.read_rows(from_sequence, VERIFY_PAGE_SIZE).await?;
            let page_is_last = i64::try_from(rows.len()).ok() != Some(VERIFY_PAGE_SIZE);
            let (report, last) = verify_page(anchor.as_ref(), rows, checked)?;
            if !report.valid || page_is_last {
                return Ok(report);
            }
            checked = report.checked;
            anchor = last;
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::audit::GENESIS_HASH;
    use aegis_contracts::common::{EvidenceKind, EvidenceRef};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn time(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 2, 3, 4, 5, second).unwrap()
            + chrono::Duration::microseconds(123_456)
    }

    fn chain(count: usize) -> Vec<AuditRecord> {
        let mut records: Vec<AuditRecord> = Vec::new();
        for index in 0..count {
            let entry = AuditEntry::new(
                AuditKind::AgentDecision,
                "analyst",
                format!("Decision {index}."),
            )
            .with_payload(json!({ "index": index, "confidence": 0.1 + 0.2 }));
            let record = seal(records.last(), entry, time(u32::try_from(index).unwrap())).unwrap();
            records.push(record);
        }
        records
    }

    fn rows(records: &[AuditRecord]) -> Vec<StoredRecord> {
        records
            .iter()
            .map(|record| StoredRecord::from_record(record).unwrap())
            .collect()
    }

    #[test]
    fn a_record_survives_the_columns_with_the_same_hash() {
        let entry = AuditEntry::new(AuditKind::ActionExecuted, "responder", "Disabled a user.")
            .with_payload(json!({
                "score": 0.1 + 0.2,
                "ratio": 1.0,
                "tiny": 5e-324,
                "huge": 1.797_693_134_862_315_7e308,
                "exponent": 1e21,
                // A parser with less than full precision gives a different number for
                // each of these values.
                "hard_to_parse": [
                    1.071_566_039_146_582_6e-75,
                    -1.603_964_615_428_183e143,
                    3.026_199_944_157_320_3e-52,
                ],
                "negative_zero": -0.0,
                "big_unsigned": u64::MAX,
                "smallest": i64::MIN,
                "nested": { "list": [1, 2.5, null, { "deep": "\u{0}\u{1F600} \"quoted\"" }] },
            }))
            .with_evidence(vec![
                EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("Sign-in burst."),
            ]);
        let record = seal(None, entry, time(0)).unwrap();

        let stored = StoredRecord::from_record(&record).unwrap();
        assert_eq!(stored.sequence, 1);
        assert_eq!(stored.kind, "action_executed");
        assert_eq!(stored.prev_hash, GENESIS_HASH);
        assert_eq!(stored.recorded_at, record.time);

        let read = stored.clone().into_record().unwrap();
        assert_eq!(read, record);
        assert_eq!(read.compute_hash().unwrap(), record.hash);
        // The columns of the record that the store read are the same text.
        assert_eq!(StoredRecord::from_record(&read).unwrap(), stored);
    }

    #[test]
    fn a_row_with_changed_text_does_not_decode_to_the_same_hash() {
        let record = chain(1).remove(0);
        let mut stored = StoredRecord::from_record(&record).unwrap();
        stored.payload = stored.payload.replace("0.30000000000000004", "0.3");
        let read = stored.into_record().unwrap();
        assert_ne!(read.compute_hash().unwrap(), record.hash);
    }

    #[test]
    fn rows_that_do_not_decode_are_integrity_errors() {
        let record = chain(1).remove(0);
        let good = StoredRecord::from_record(&record).unwrap();

        let mut bad_kind = good.clone();
        bad_kind.kind = "rewritten".to_owned();
        let mut bad_payload = good.clone();
        bad_payload.payload = "{".to_owned();
        let mut bad_evidence = good.clone();
        bad_evidence.evidence = "{}".to_owned();
        let mut bad_sequence = good;
        bad_sequence.sequence = -4;

        for (row, field) in [
            (bad_kind, "kind"),
            (bad_payload, "payload"),
            (bad_evidence, "evidence"),
            (bad_sequence, "sequence"),
        ] {
            let sequence = row.sequence;
            let error = row.into_record().unwrap_err();
            match error {
                Error::Integrity(message) => assert!(
                    message.starts_with(&format!(
                        "audit: the {field} of record {sequence} cannot be decoded"
                    )),
                    "{message}"
                ),
                other => panic!("expected Integrity, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_sequence_above_the_database_range_is_an_integrity_error() {
        let mut record = chain(1).remove(0);
        record.sequence = u64::MAX;
        let error = StoredRecord::from_record(&record).unwrap_err();
        assert!(matches!(error, Error::Integrity(message) if message.contains("too large")));
    }

    #[test]
    fn pages_of_a_good_chain_verify_and_count_all_records() {
        let records = chain(5);
        let (first, anchor) = verify_page(None, rows(&records[..2]), 0).unwrap();
        assert!(first.valid);
        assert_eq!(first.checked, 2);
        assert_eq!(anchor.as_ref(), Some(&records[1]));

        let (second, last) =
            verify_page(anchor.as_ref(), rows(&records[2..]), first.checked).unwrap();
        assert_eq!(
            second,
            ChainVerification {
                valid: true,
                checked: 5,
                first_invalid_sequence: None,
                reason: None,
            }
        );
        assert_eq!(last.as_ref(), Some(&records[4]));
    }

    #[test]
    fn an_empty_page_is_valid_and_has_no_last_record() {
        let (report, last) = verify_page(None, Vec::new(), 0).unwrap();
        assert!(report.valid);
        assert_eq!(report.checked, 0);
        assert_eq!(last, None);
    }

    #[test]
    fn a_changed_row_in_a_later_page_is_found_with_the_total_count() {
        let records = chain(4);
        let mut page = rows(&records[2..]);
        page[1].summary = "Changed.".to_owned();
        let (report, last) = verify_page(Some(&records[1]), page, 2).unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked, 3);
        assert_eq!(report.first_invalid_sequence, Some(4));
        assert_eq!(
            report.reason.as_deref(),
            Some("hash does not match the record contents")
        );
        assert_eq!(last, None);
    }

    #[test]
    fn a_missing_row_breaks_the_chain_at_the_next_record() {
        let records = chain(4);
        let mut page = rows(&records);
        page.remove(1);
        let (report, _) = verify_page(None, page, 0).unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked, 1);
        assert_eq!(report.first_invalid_sequence, Some(3));
        assert_eq!(
            report.reason.as_deref(),
            Some("expected sequence 2, found 3")
        );
    }

    #[test]
    fn a_row_that_does_not_decode_makes_the_chain_invalid_at_that_record() {
        let records = chain(3);
        let mut page = rows(&records);
        page[2].payload = "not json".to_owned();
        let (report, last) = verify_page(None, page, 0).unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked, 2);
        assert_eq!(report.first_invalid_sequence, Some(3));
        let reason = report.reason.unwrap();
        assert!(
            reason.contains("the payload of record 3 cannot be decoded"),
            "{reason}"
        );
        assert_eq!(last, None);
    }

    #[test]
    fn an_earlier_broken_link_wins_over_a_later_row_that_does_not_decode() {
        let records = chain(3);
        let mut page = rows(&records);
        page[0].actor = "intruder".to_owned();
        page[2].payload = "not json".to_owned();
        let (report, _) = verify_page(None, page, 0).unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_sequence, Some(1));
        assert_eq!(report.checked, 0);
    }
}
