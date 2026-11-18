use std::sync::Mutex;

use aegis_contracts::Result;
use aegis_contracts::audit::{
    AuditEntry, AuditLog, AuditRecord, ChainVerification, seal, verify_chain,
};
use async_trait::async_trait;
use chrono::Utc;

use crate::lock;

/// An audit log that keeps all records in memory. The records form a real hash chain.
#[derive(Default)]
pub struct MemoryAuditLog {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditLog {
    /// Returns all records in sequence order.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        lock(&self.records).clone()
    }

    /// Changes the stored records with `change`. Use this to test tamper detection.
    pub fn tamper(&self, change: impl FnOnce(&mut Vec<AuditRecord>)) {
        change(&mut lock(&self.records));
    }
}

#[async_trait]
impl AuditLog for MemoryAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord> {
        let mut records = lock(&self.records);
        let record = seal(records.last(), entry, Utc::now())?;
        records.push(record.clone());
        Ok(record)
    }

    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
        Ok(lock(&self.records)
            .iter()
            .filter(|record| record.sequence >= from_sequence)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn verify(&self) -> Result<ChainVerification> {
        verify_chain(None, &lock(&self.records))
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::audit::{AuditKind, GENESIS_HASH};

    use super::*;

    async fn log_with(count: usize) -> MemoryAuditLog {
        let log = MemoryAuditLog::default();
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

    #[tokio::test]
    async fn append_builds_a_chain_that_verifies() {
        let log = log_with(3).await;
        let records = log.records();
        assert_eq!(
            records
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(records[0].prev_hash, GENESIS_HASH);
        assert_eq!(records[2].prev_hash, records[1].hash);
        let report = log.verify().await.unwrap();
        assert!(report.valid);
        assert_eq!(report.checked, 3);
    }

    #[tokio::test]
    async fn read_starts_at_the_sequence_and_obeys_the_limit() {
        let log = log_with(5).await;
        let page: Vec<u64> = log
            .read(2, 2)
            .await
            .unwrap()
            .iter()
            .map(|record| record.sequence)
            .collect();
        assert_eq!(page, [2, 3]);
        assert!(log.read(6, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn verify_finds_a_changed_record() {
        let log = log_with(3).await;
        log.tamper(|records| records[1].summary = "Changed.".to_owned());
        let report = log.verify().await.unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_sequence, Some(2));
    }
}
