//! The audit routes, and the search for the last record of the audit log.

use aegis_contracts::audit::{AuditLog, AuditRecord, ChainVerification};
use aegis_contracts::{Error, Result};
use axum::Json;
use axum::extract::{RawQuery, State};
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::Ctx;
use crate::error::ApiResult;
use crate::extract::Params;

/// The last record of the audit log: its position, its hash, and its time.
///
/// An operator can keep this value in a different system. A later comparison shows that
/// the end of the log is not gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AuditHead {
    /// The sequence number of the last record.
    pub sequence: u64,
    /// The hash of the last record.
    pub hash: String,
    /// The time of the last record.
    pub time: DateTime<Utc>,
}

impl From<AuditRecord> for AuditHead {
    fn from(record: AuditRecord) -> Self {
        Self {
            sequence: record.sequence,
            hash: record.hash,
            time: record.time,
        }
    }
}

/// Reads the first record at or after `sequence`.
async fn first_at(log: &dyn AuditLog, sequence: u64) -> Result<Option<AuditRecord>> {
    let record = log.read(sequence, 1).await?.into_iter().next();
    if let Some(record) = &record
        && record.sequence < sequence
    {
        return Err(Error::Integrity(format!(
            "the audit log returned sequence {} for a read that starts at sequence {sequence}",
            record.sequence
        )));
    }
    Ok(record)
}

/// Finds the last record of the log.
///
/// The [`AuditLog`] contract has no function for the last record. This function finds it
/// with reads of one record: it doubles the step until a read is empty, and then it halves
/// the range. A log with `n` records needs about `2 * log2(n)` reads. With `known`, the
/// search starts at that record, so a log with no new record needs one read.
///
/// `None` means that the log is empty.
pub(crate) async fn find_audit_head(
    log: &dyn AuditLog,
    known: Option<AuditHead>,
) -> Result<Option<AuditHead>> {
    // `low` is a sequence number that has a record, or 0. `head` is that record.
    let mut low = known.as_ref().map_or(0, |head| head.sequence);
    let mut head = known;
    let mut step: u64 = 1;
    // After the first loop, no record has the sequence number `high` or a larger one.
    let mut high = loop {
        let Some(probe) = low.checked_add(step) else {
            return Ok(head);
        };
        match first_at(log, probe).await? {
            Some(record) => {
                low = record.sequence;
                head = Some(record.into());
                step = step.saturating_mul(2);
            }
            None => break probe,
        }
    };
    while high.saturating_sub(low) > 1 {
        let middle = low + (high - low) / 2;
        match first_at(log, middle).await? {
            Some(record) => {
                low = record.sequence;
                head = Some(record.into());
            }
            None => high = middle,
        }
    }
    Ok(head)
}

/// One page of audit records.
#[derive(Debug, Serialize)]
pub(crate) struct AuditPage {
    items: Vec<AuditRecord>,
    /// The `from_sequence` value of the next page. `null` if this page is not full.
    next_sequence: Option<u64>,
}

/// `GET /audit`: the audit records in sequence order.
pub(crate) async fn list(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<AuditPage>> {
    let params = Params::parse(query.as_deref(), &["from_sequence", "limit"])?;
    let from_sequence = params.number("from_sequence")?.unwrap_or(1);
    let limit = params.limit(&ctx.limits)?;
    let mut items = ctx.state.parts().audit.read(from_sequence, limit).await?;
    items.truncate(limit);
    let next_sequence = match items.last() {
        Some(last) if items.len() == limit => last.sequence.checked_add(1),
        _ => None,
    };
    Ok(Json(AuditPage {
        items,
        next_sequence,
    }))
}

/// `GET /audit/verification`: the result of a check of the full hash chain.
pub(crate) async fn verification(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<ChainVerification>> {
    Params::parse(query.as_deref(), &[])?;
    Ok(Json(ctx.state.parts().audit.verify().await?))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aegis_contracts::audit::{AuditEntry, AuditKind, seal};
    use async_trait::async_trait;

    use super::*;

    /// An audit log that counts its reads and can lose its order.
    #[derive(Default)]
    struct CountingLog {
        records: Mutex<Vec<AuditRecord>>,
        reads: AtomicUsize,
        broken: bool,
    }

    impl CountingLog {
        fn with_records(count: usize) -> Self {
            let log = Self::default();
            for _ in 0..count {
                log.push();
            }
            log
        }

        fn push(&self) {
            let mut records = self.records.lock().unwrap();
            let entry = AuditEntry::new(AuditKind::Other, "test", "A record.");
            let record = seal(records.last(), entry, Utc::now()).unwrap();
            records.push(record);
        }

        fn reads(&self) -> usize {
            self.reads.swap(0, Ordering::SeqCst)
        }

        fn record(&self, sequence: u64) -> AuditRecord {
            self.records.lock().unwrap()[usize::try_from(sequence).unwrap() - 1].clone()
        }
    }

    #[async_trait]
    impl AuditLog for CountingLog {
        async fn append(&self, _entry: AuditEntry) -> Result<AuditRecord> {
            Err(Error::Unsupported("append".to_owned()))
        }

        async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let records = self.records.lock().unwrap();
            if self.broken {
                return Ok(records.iter().take(limit).cloned().collect());
            }
            Ok(records
                .iter()
                .filter(|record| record.sequence >= from_sequence)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn verify(&self) -> Result<ChainVerification> {
            Err(Error::Unsupported("verify".to_owned()))
        }
    }

    #[tokio::test]
    async fn an_empty_log_has_no_head() {
        let log = CountingLog::default();
        assert_eq!(find_audit_head(&log, None).await.unwrap(), None);
        assert_eq!(log.reads(), 1);
    }

    #[tokio::test]
    async fn the_head_is_the_last_record_for_each_log_length() {
        for count in 1..=40_u64 {
            let log = CountingLog::with_records(usize::try_from(count).unwrap());
            let head = find_audit_head(&log, None).await.unwrap().unwrap();
            assert_eq!(head, AuditHead::from(log.record(count)), "{count} records");
        }
    }

    #[tokio::test]
    async fn the_search_needs_few_reads() {
        let log = CountingLog::with_records(1_000);
        let head = find_audit_head(&log, None).await.unwrap().unwrap();
        assert_eq!(head.sequence, 1_000);
        let reads = log.reads();
        assert!(reads <= 22, "{reads} reads for 1000 records");
    }

    #[tokio::test]
    async fn a_known_head_makes_the_next_search_one_read() {
        let log = CountingLog::with_records(100);
        let head = find_audit_head(&log, None).await.unwrap();
        log.reads();

        assert_eq!(find_audit_head(&log, head.clone()).await.unwrap(), head);
        assert_eq!(log.reads(), 1);

        for _ in 0..7 {
            log.push();
        }
        let newer = find_audit_head(&log, head).await.unwrap().unwrap();
        assert_eq!(newer, AuditHead::from(log.record(107)));
        assert!(log.reads() <= 7);
    }

    #[tokio::test]
    async fn a_log_that_returns_an_earlier_record_is_an_integrity_error() {
        let mut log = CountingLog::with_records(3);
        log.broken = true;
        let error = find_audit_head(&log, None).await.unwrap_err();
        assert!(
            matches!(&error, Error::Integrity(message) if message == "the audit log returned sequence 1 for a read that starts at sequence 3"),
            "{error}"
        );
    }
}
