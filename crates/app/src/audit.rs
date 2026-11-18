//! The live audit feed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_contracts::Result;
use aegis_contracts::audit::{AuditEntry, AuditLog, AuditRecord, ChainVerification};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use async_trait::async_trait;

use crate::activity::Activity;

/// An audit log that also publishes each sealed record on the bus subject `aegis.audit`.
///
/// The log is the record of truth. The bus is only a live feed for consumers that show
/// the records. Thus the decorator appends first and publishes second. A publish failure
/// does not fail the append and does not remove the record. The failure goes to the
/// process log, and [`PublishingAuditLog::publish_failures`] counts it.
pub struct PublishingAuditLog {
    inner: Arc<dyn AuditLog>,
    bus: Arc<dyn MessageBus>,
    activity: Arc<Activity>,
    publish_failures: AtomicU64,
}

impl PublishingAuditLog {
    /// Makes the decorator around `inner`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn AuditLog>,
        bus: Arc<dyn MessageBus>,
        activity: Arc<Activity>,
    ) -> Self {
        Self {
            inner,
            bus,
            activity,
            publish_failures: AtomicU64::new(0),
        }
    }

    /// Returns the number of records that the log holds and that the bus did not take.
    #[must_use]
    pub fn publish_failures(&self) -> u64 {
        self.publish_failures.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl AuditLog for PublishingAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord> {
        let record = self.inner.append(entry).await?;
        if let Err(error) = publish_json(self.bus.as_ref(), subject::AUDIT, &record).await {
            self.publish_failures.fetch_add(1, Ordering::Relaxed);
            // The record is in the log. Only the live feed misses it.
            tracing::warn!(
                sequence = record.sequence,
                %error,
                "the audit log has the record, but the bus did not take it"
            );
        }
        self.activity.bump();
        Ok(record)
    }

    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
        self.inner.read(from_sequence, limit).await
    }

    async fn verify(&self) -> Result<ChainVerification> {
        self.inner.verify().await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_contracts::Error;
    use aegis_contracts::audit::AuditKind;
    use aegis_contracts::bus::BusStream;
    use aegis_testkit::{MemoryAuditLog, MemoryBus};

    use super::*;

    fn entry(summary: &str) -> AuditEntry {
        AuditEntry::new(AuditKind::Other, "test", summary)
    }

    struct DownBus;

    #[async_trait]
    impl MessageBus for DownBus {
        async fn publish(&self, _: &str, _: Vec<u8>) -> Result<()> {
            Err(Error::Unavailable("the bus is down".to_owned()))
        }

        async fn subscribe(&self, _: &str, _: Option<&str>) -> Result<BusStream> {
            Err(Error::Unavailable("the bus is down".to_owned()))
        }
    }

    struct DownLog;

    #[async_trait]
    impl AuditLog for DownLog {
        async fn append(&self, _: AuditEntry) -> Result<AuditRecord> {
            Err(Error::Unavailable("the log is down".to_owned()))
        }

        async fn read(&self, _: u64, _: usize) -> Result<Vec<AuditRecord>> {
            Ok(Vec::new())
        }

        async fn verify(&self) -> Result<ChainVerification> {
            Err(Error::Unavailable("the log is down".to_owned()))
        }
    }

    #[tokio::test]
    async fn each_sealed_record_goes_to_the_log_and_then_to_the_bus() {
        let inner = Arc::new(MemoryAuditLog::default());
        let bus = Arc::new(MemoryBus::default());
        let activity = Arc::new(Activity::new());
        let log = PublishingAuditLog::new(inner.clone(), bus.clone(), activity.clone());

        let first = log.append(entry("The first record.")).await.unwrap();
        let second = log.append(entry("The second record.")).await.unwrap();

        assert_eq!(inner.records(), [first.clone(), second.clone()]);
        let published: Vec<AuditRecord> = bus
            .published_to(subject::AUDIT)
            .iter()
            .map(|message| message.decode().unwrap())
            .collect();
        // The bus has the sealed records: the sequence, the hashes, and the time.
        assert_eq!(published, [first.clone(), second.clone()]);
        assert_eq!(bus.published().len(), 2);
        assert_eq!(second.prev_hash, first.hash);
        assert_eq!(log.publish_failures(), 0);
        assert_eq!(activity.count(), 2);

        assert_eq!(log.read(2, 10).await.unwrap(), [second]);
        let verification = log.verify().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checked, 2);
    }

    #[tokio::test]
    async fn a_publish_failure_does_not_fail_or_lose_the_append() {
        let inner = Arc::new(MemoryAuditLog::default());
        let activity = Arc::new(Activity::new());
        let log = PublishingAuditLog::new(inner.clone(), Arc::new(DownBus), activity.clone());

        let record = log.append(entry("The bus is down.")).await.unwrap();

        assert_eq!(record.sequence, 1);
        assert_eq!(inner.records(), [record]);
        assert_eq!(log.publish_failures(), 1);
        assert!(log.verify().await.unwrap().valid);
        assert_eq!(activity.count(), 1);
    }

    #[tokio::test]
    async fn an_append_failure_publishes_nothing_and_returns_the_error() {
        let bus = Arc::new(MemoryBus::default());
        let activity = Arc::new(Activity::new());
        let log = PublishingAuditLog::new(Arc::new(DownLog), bus.clone(), activity.clone());

        let error = log.append(entry("The log is down.")).await.unwrap_err();

        assert!(
            matches!(&error, Error::Unavailable(message) if message == "the log is down"),
            "{error:?}"
        );
        assert_eq!(bus.published(), []);
        assert_eq!(log.publish_failures(), 0);
        assert_eq!(activity.count(), 0);
    }
}
