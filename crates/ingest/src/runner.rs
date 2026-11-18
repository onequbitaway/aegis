//! The runner that moves events from one connector to the bus.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use aegis_contracts::bus::{self, MessageBus};
use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{EventBatch, SourceConnector};
use aegis_contracts::{Error, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::check_connector_name;
use crate::checkpoint::CheckpointStore;

/// The rules for a retry after an error that [`Error::is_retryable`] accepts.
///
/// The delay doubles with each retry: `initial_delay`, then two times that value, and so
/// on. The delay is not more than `max_delay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// The number of retries in sequence before the runner stops with the error.
    ///
    /// A batch that the runner publishes and saves sets the count back to zero.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// The delay before the first retry.
    #[serde(default = "default_initial_delay", with = "humantime_serde")]
    pub initial_delay: Duration,
    /// The longest delay before a retry.
    #[serde(default = "default_max_delay", with = "humantime_serde")]
    pub max_delay: Duration,
}

fn default_max_retries() -> u32 {
    5
}

fn default_initial_delay() -> Duration {
    Duration::from_millis(500)
}

fn default_max_delay() -> Duration {
    Duration::from_secs(30)
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_delay: default_initial_delay(),
            max_delay: default_max_delay(),
        }
    }
}

impl RetryPolicy {
    /// Returns the delay before retry number `retry`. The first retry is number 1.
    #[must_use]
    pub fn delay(&self, retry: u32) -> Duration {
        let doublings = retry.saturating_sub(1).min(31);
        self.initial_delay
            .saturating_mul(1_u32 << doublings)
            .min(self.max_delay)
    }
}

/// A snapshot of the counters of one [`IngestRunner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IngestStats {
    /// The number of events that the runner published.
    pub events_published: u64,
    /// The number of batches that the runner published completely.
    pub batches: u64,
    /// The number of retries after an error.
    pub retries: u64,
}

/// The reason why [`IngestRunner::run`] or [`IngestRunner::backfill`] returned without an
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// The source has no more events.
    Completed,
    /// The cancellation signal fired.
    Cancelled,
}

#[derive(Default)]
struct Counters {
    events_published: AtomicU64,
    batches: AtomicU64,
    retries: AtomicU64,
}

/// Sets the "in operation" flag of a runner back when the operation ends.
struct Operation<'a>(&'a AtomicBool);

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The result of one step that the cancellation signal can interrupt.
enum Step<T> {
    Done(T),
    Cancelled,
}

/// Drives one source connector: it publishes the events and saves the cursor.
///
/// The runner publishes each event as JSON to `aegis.events.{connector name}`. It publishes
/// a batch before it saves the cursor of the batch. Thus a stop can repeat events, but it
/// cannot lose them.
///
/// The runner publishes the events in the order in which the connector supplies them.
pub struct IngestRunner {
    source: Arc<dyn SourceConnector>,
    bus: Arc<dyn MessageBus>,
    checkpoints: Arc<dyn CheckpointStore>,
    cancel: CancellationToken,
    retry: RetryPolicy,
    name: String,
    subject: String,
    counters: Counters,
    in_operation: AtomicBool,
}

impl IngestRunner {
    /// Makes a runner for `source`.
    ///
    /// The runner stops when `cancel` fires. The name of the connector must have only ASCII
    /// letters, digits, `-`, and `_`, because it is one token of the bus subject. A
    /// different name is [`Error::InvalidInput`].
    pub fn new(
        source: Arc<dyn SourceConnector>,
        bus: Arc<dyn MessageBus>,
        checkpoints: Arc<dyn CheckpointStore>,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let name = source.info().name;
        check_connector_name(&name)?;
        let subject = format!("{}.{name}", bus::subject::EVENTS);
        Ok(Self {
            source,
            bus,
            checkpoints,
            cancel,
            retry: RetryPolicy::default(),
            name,
            subject,
            counters: Counters::default(),
            in_operation: AtomicBool::new(false),
        })
    }

    /// Sets the retry rules.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Returns the name of the connector.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the bus subject that gets the events.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns a snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> IngestStats {
        IngestStats {
            events_published: self.counters.events_published.load(Ordering::Relaxed),
            batches: self.counters.batches.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
        }
    }

    /// Reads the live stream of the connector until the source ends or the cancellation
    /// signal fires.
    ///
    /// The runner starts at the cursor in the checkpoint store. After each batch, it
    /// publishes all events and then saves [`EventBatch::next_cursor`].
    ///
    /// # Errors
    ///
    /// After a retryable error, the runner waits and then opens the stream again at the
    /// last cursor. It returns the error when the retry limit is reached. It returns a
    /// permanent error immediately. It returns [`Error::InvalidInput`] if a different
    /// `run` or `backfill` of this runner is in progress.
    pub async fn run(&self) -> Result<RunOutcome> {
        let _operation = self.begin()?;
        let mut failures = 0_u32;

        let mut cursor = loop {
            match self.checkpoints.load(&self.name).await {
                Ok(cursor) => break cursor,
                Err(error) => {
                    if let Step::Cancelled = self.wait_before_retry(error, &mut failures).await? {
                        return Ok(RunOutcome::Cancelled);
                    }
                }
            }
        };
        tracing::info!(
            connector = %self.name,
            resumed = cursor.is_some(),
            "ingestion started"
        );

        loop {
            let opened = match self
                .unless_cancelled(self.source.stream(cursor.clone()))
                .await
            {
                Step::Done(opened) => opened,
                Step::Cancelled => return Ok(self.stopped(RunOutcome::Cancelled)),
            };
            let mut stream = match opened {
                Ok(stream) => stream,
                Err(error) => {
                    if let Step::Cancelled = self.wait_before_retry(error, &mut failures).await? {
                        return Ok(self.stopped(RunOutcome::Cancelled));
                    }
                    continue;
                }
            };
            loop {
                let item = match self.unless_cancelled(stream.next()).await {
                    Step::Done(item) => item,
                    Step::Cancelled => return Ok(self.stopped(RunOutcome::Cancelled)),
                };
                match item {
                    None => return Ok(self.stopped(RunOutcome::Completed)),
                    Some(Ok(batch)) => {
                        if let Step::Cancelled = self.deliver(&batch, true, &mut failures).await? {
                            return Ok(self.stopped(RunOutcome::Cancelled));
                        }
                        if batch.next_cursor.is_some() {
                            cursor = batch.next_cursor;
                        }
                        failures = 0;
                    }
                    Some(Err(error)) => {
                        if let Step::Cancelled =
                            self.wait_before_retry(error, &mut failures).await?
                        {
                            return Ok(self.stopped(RunOutcome::Cancelled));
                        }
                        // The state of the stream after an error is not known. Open it again.
                        break;
                    }
                }
            }
        }
    }

    /// Reads all past events in `range` with [`SourceConnector::fetch`] and publishes them.
    ///
    /// A backfill does not read or change the checkpoint of the live stream.
    ///
    /// # Errors
    ///
    /// The retry rules of [`run`](Self::run) apply to each page. The function returns
    /// [`Error::Integrity`] if the connector returns the cursor that it received, because
    /// the read cannot make progress.
    pub async fn backfill(&self, range: TimeRange) -> Result<RunOutcome> {
        let _operation = self.begin()?;
        let mut failures = 0_u32;
        let mut cursor: Option<String> = None;
        loop {
            let fetched = match self
                .unless_cancelled(self.source.fetch(range, cursor.clone()))
                .await
            {
                Step::Done(fetched) => fetched,
                Step::Cancelled => return Ok(RunOutcome::Cancelled),
            };
            let batch = match fetched {
                Ok(batch) => batch,
                Err(error) => {
                    if let Step::Cancelled = self.wait_before_retry(error, &mut failures).await? {
                        return Ok(RunOutcome::Cancelled);
                    }
                    continue;
                }
            };
            if let Step::Cancelled = self.deliver(&batch, false, &mut failures).await? {
                return Ok(RunOutcome::Cancelled);
            }
            failures = 0;
            match batch.next_cursor {
                None => return Ok(RunOutcome::Completed),
                Some(next) if cursor.as_deref() == Some(next.as_str()) => {
                    return Err(Error::Integrity(format!(
                        "connector {} returned the same backfill cursor two times",
                        self.name
                    )));
                }
                Some(next) => cursor = Some(next),
            }
        }
    }

    /// Marks the runner as in operation. Only one operation can be in progress.
    fn begin(&self) -> Result<Operation<'_>> {
        if self.in_operation.swap(true, Ordering::AcqRel) {
            return Err(Error::InvalidInput(format!(
                "the runner of connector {} is already in operation",
                self.name
            )));
        }
        Ok(Operation(&self.in_operation))
    }

    fn stopped(&self, outcome: RunOutcome) -> RunOutcome {
        let stats = self.stats();
        tracing::info!(
            connector = %self.name,
            ?outcome,
            events_published = stats.events_published,
            batches = stats.batches,
            retries = stats.retries,
            "ingestion stopped"
        );
        outcome
    }

    /// Publishes all events of `batch` in order. With `checkpoint`, saves the cursor then.
    ///
    /// The cancellation signal does not interrupt a batch that is in progress. It
    /// interrupts only the wait before a retry.
    async fn deliver(
        &self,
        batch: &EventBatch,
        checkpoint: bool,
        failures: &mut u32,
    ) -> Result<Step<()>> {
        for event in &batch.events {
            loop {
                match bus::publish_json(self.bus.as_ref(), &self.subject, event).await {
                    Ok(()) => break,
                    Err(error) => {
                        if let Step::Cancelled = self.wait_before_retry(error, failures).await? {
                            return Ok(Step::Cancelled);
                        }
                    }
                }
            }
            self.counters
                .events_published
                .fetch_add(1, Ordering::Relaxed);
        }
        if checkpoint && let Some(cursor) = batch.next_cursor.as_deref() {
            loop {
                match self.checkpoints.save(&self.name, cursor).await {
                    Ok(()) => break,
                    Err(error) => {
                        if let Step::Cancelled = self.wait_before_retry(error, failures).await? {
                            return Ok(Step::Cancelled);
                        }
                    }
                }
            }
        }
        self.counters.batches.fetch_add(1, Ordering::Relaxed);
        Ok(Step::Done(()))
    }

    /// Decides what follows `error`: a wait and a retry, or the end of the operation.
    ///
    /// Returns the error if it is permanent or if the retry limit is reached.
    async fn wait_before_retry(&self, error: Error, failures: &mut u32) -> Result<Step<()>> {
        if !error.is_retryable() {
            tracing::error!(connector = %self.name, %error, "ingestion stopped: permanent error");
            return Err(error);
        }
        if *failures >= self.retry.max_retries {
            tracing::error!(
                connector = %self.name,
                %error,
                retries = *failures,
                "ingestion stopped: retry limit reached"
            );
            return Err(error);
        }
        *failures += 1;
        self.counters.retries.fetch_add(1, Ordering::Relaxed);
        let delay = self.retry.delay(*failures);
        tracing::warn!(
            connector = %self.name,
            %error,
            retry = *failures,
            max_retries = self.retry.max_retries,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "ingestion error: retry after the delay"
        );
        Ok(self.unless_cancelled(tokio::time::sleep(delay)).await)
    }

    /// Waits for `future`, but stops the wait when the cancellation signal fires.
    async fn unless_cancelled<T>(&self, future: impl Future<Output = T>) -> Step<T> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Step::Cancelled,
            value = future => Step::Done(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_doubles_from_the_initial_delay_up_to_the_maximum() {
        let policy = RetryPolicy {
            max_retries: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(450),
        };
        let delays: Vec<u128> = (1..=5)
            .map(|retry| policy.delay(retry).as_millis())
            .collect();
        assert_eq!(delays, [100, 200, 400, 450, 450]);
        assert_eq!(policy.delay(0).as_millis(), 100);
    }

    #[test]
    fn the_delay_does_not_overflow_for_a_large_retry_number() {
        let policy = RetryPolicy {
            max_retries: u32::MAX,
            initial_delay: Duration::from_secs(u64::MAX / 2),
            max_delay: Duration::MAX,
        };
        assert_eq!(
            policy.delay(2),
            Duration::from_secs(u64::MAX / 2).saturating_mul(2)
        );
        assert_eq!(policy.delay(u32::MAX), Duration::MAX);
    }

    #[test]
    fn the_default_policy_has_five_retries_from_half_a_second_to_thirty_seconds() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.delay(1), Duration::from_millis(500));
        assert_eq!(policy.delay(7), Duration::from_secs(30));
    }

    #[test]
    fn the_policy_reads_human_durations_and_uses_defaults_for_absent_fields() {
        let policy: RetryPolicy =
            serde_json::from_str(r#"{"max_retries": 2, "initial_delay": "250ms"}"#).unwrap();
        assert_eq!(
            policy,
            RetryPolicy {
                max_retries: 2,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(30),
            }
        );
        let text = serde_json::to_string(&policy).unwrap();
        assert_eq!(serde_json::from_str::<RetryPolicy>(&text).unwrap(), policy);
        let error = serde_json::from_str::<RetryPolicy>(r#"{"retries": 2}"#).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}
