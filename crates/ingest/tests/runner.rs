//! Integration tests for [`IngestRunner`]: delivery, checkpoints, retries, and backfill.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::{EventId, TimeRange};
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use aegis_ingest::{
    CheckpointStore, FileCheckpointStore, FileSource, FileSourceConfig, IngestRunner, IngestStats,
    MemoryCheckpointStore, RetryPolicy, RunOutcome,
};
use aegis_testkit::{MemoryBus, StaticSource, fixtures};
use async_trait::async_trait;
use common::{FaultyBus, FaultySource, FaultyStore, fixture_path, published_events};
use futures::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const SUBJECT: &str = "aegis.events.static";

/// The longest time that a test waits for a runner.
const LIMIT: Duration = Duration::from_secs(60);

fn retry(max_retries: u32) -> RetryPolicy {
    RetryPolicy {
        max_retries,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(1),
    }
}

fn runner(
    source: Arc<dyn SourceConnector>,
    bus: Arc<dyn MessageBus>,
    store: Arc<dyn CheckpointStore>,
    cancel: &CancellationToken,
) -> IngestRunner {
    IngestRunner::new(source, bus, store, cancel.clone())
        .unwrap()
        .with_retry(retry(3))
}

async fn run(runner: &IngestRunner) -> Result<RunOutcome> {
    tokio::time::timeout(LIMIT, runner.run())
        .await
        .expect("the runner must stop")
}

fn ids(events: &[Event]) -> Vec<EventId> {
    events.iter().map(|event| event.id).collect()
}

#[tokio::test]
async fn all_events_of_the_attack_log_arrive_on_the_connector_subject_in_order() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(50));
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );
    assert_eq!(runner.name(), "static");
    assert_eq!(runner.subject(), SUBJECT);

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    let published = published_events(&bus, SUBJECT);
    assert_eq!(published.len(), 648);
    assert_eq!(published, expected);
    assert_eq!(
        bus.published().len(),
        648,
        "no message on a different subject"
    );
    assert_eq!(
        runner.stats(),
        IngestStats {
            events_published: 648,
            batches: 13,
            retries: 0,
        }
    );
    assert_eq!(store.load("static").await.unwrap().as_deref(), Some("648"));
}

#[tokio::test]
async fn the_file_source_delivers_the_fixture_file_through_the_runner() {
    let source =
        Arc::new(FileSource::new(FileSourceConfig::new("replay", fixture_path())).unwrap());
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    let published = published_events(&bus, "aegis.events.replay");
    assert_eq!(published.len(), fixtures::ATTACK_LOG_EVENTS);
    assert_eq!(published, fixtures::artex_style_attack());
    assert_eq!(bus.published().len(), fixtures::ATTACK_LOG_EVENTS);
    assert_eq!(
        runner.stats(),
        IngestStats {
            events_published: 648,
            batches: 7,
            retries: 0,
        }
    );
    assert_eq!(store.load("replay").await.unwrap().as_deref(), Some("648"));
}

#[tokio::test]
async fn a_runner_that_stops_mid_stream_and_a_new_runner_lose_no_event() {
    let expected = fixtures::artex_style_attack();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(50));

    // The token fires during the third batch. The runner completes the batch and stops.
    let cancel = CancellationToken::new();
    let bus = Arc::new(FaultyBus::default().cancel_at(120, cancel.clone()));
    let first_store = Arc::new(FileCheckpointStore::new(directory.path()));
    let first = runner(source.clone(), bus.clone(), first_store, &cancel);
    assert_eq!(run(&first).await.unwrap(), RunOutcome::Cancelled);
    assert_eq!(first.stats().events_published, 150);
    assert_eq!(first.stats().batches, 3);
    assert_eq!(published_events(&bus.inner, SUBJECT), expected[..150]);

    // A new runner and a new store object on the same directory: a restart of the process.
    let second_store = Arc::new(FileCheckpointStore::new(directory.path()));
    assert_eq!(
        second_store.load("static").await.unwrap().as_deref(),
        Some("150")
    );
    let second = runner(
        source,
        bus.clone(),
        second_store.clone(),
        &CancellationToken::new(),
    );
    assert_eq!(run(&second).await.unwrap(), RunOutcome::Completed);
    assert_eq!(second.stats().events_published, 498);

    let published = published_events(&bus.inner, SUBJECT);
    assert_eq!(published.len(), 648);
    assert_eq!(
        published, expected,
        "no event is lost, repeated, or out of order"
    );
    assert_eq!(
        second_store.load("static").await.unwrap().as_deref(),
        Some("648")
    );
}

#[tokio::test]
async fn a_crash_between_publish_and_checkpoint_repeats_the_batch_and_loses_no_event() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(50));
    let bus = Arc::new(MemoryBus::default());
    // The third save fails with a permanent error: the batch is on the bus, the cursor is not saved.
    let store = Arc::new(
        FaultyStore::default().fail_save(2, Error::other("disk", std::io::Error::other("full"))),
    );

    let first = runner(
        source.clone(),
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );
    let error = run(&first).await.unwrap_err();
    assert!(
        matches!(&error, Error::Other { context, .. } if context == "disk"),
        "{error}"
    );
    assert_eq!(published_events(&bus, SUBJECT), expected[..150]);
    assert_eq!(
        store.inner.load("static").await.unwrap().as_deref(),
        Some("100")
    );

    let second = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );
    assert_eq!(run(&second).await.unwrap(), RunOutcome::Completed);

    let published = published_events(&bus, SUBJECT);
    assert_eq!(published.len(), 698);
    assert_eq!(published[..150], expected[..150]);
    assert_eq!(
        published[150..],
        expected[100..],
        "the second runner starts at the saved cursor"
    );
    let mut counts: BTreeMap<EventId, usize> = BTreeMap::new();
    for event in &published {
        *counts.entry(event.id).or_default() += 1;
    }
    assert_eq!(counts.len(), 648, "each event of the log is on the bus");
    let repeated: Vec<EventId> = counts
        .iter()
        .filter(|(_, count)| **count == 2)
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        repeated,
        ids(&expected[100..150]),
        "only the batch of the crash is repeated"
    );
}

#[tokio::test]
async fn a_permanent_bus_error_in_a_batch_stops_the_runner_and_the_restart_loses_no_event() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(50));
    let bus = Arc::new(
        FaultyBus::default().fail_attempt(120, Error::Unauthorized("bus credentials".to_owned())),
    );
    let store = Arc::new(MemoryCheckpointStore::new());

    let first = runner(
        source.clone(),
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );
    let error = run(&first).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message == "bus credentials"),
        "{error}"
    );
    assert_eq!(first.stats().retries, 0);
    assert_eq!(published_events(&bus.inner, SUBJECT), expected[..120]);
    assert_eq!(
        store.load("static").await.unwrap().as_deref(),
        Some("100"),
        "the cursor of the incomplete batch is not saved"
    );

    let second = runner(source, bus.clone(), store, &CancellationToken::new());
    assert_eq!(run(&second).await.unwrap(), RunOutcome::Completed);
    let published = published_events(&bus.inner, SUBJECT);
    assert_eq!(published.len(), 668);
    assert_eq!(published[120..], expected[100..]);
}

#[tokio::test(start_paused = true)]
async fn a_connector_that_is_unavailable_two_times_and_then_succeeds_delivers_all_events() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(
        FaultySource::new("static", expected.clone(), 100).fail_open([
            Error::Unavailable("first".to_owned()),
            Error::Unavailable("second".to_owned()),
        ]),
    );
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source.clone(),
        bus.clone(),
        store,
        &CancellationToken::new(),
    );

    let started = Instant::now();
    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);
    let waited = started.elapsed();

    assert_eq!(published_events(&bus, SUBJECT), expected);
    assert_eq!(
        runner.stats(),
        IngestStats {
            events_published: 648,
            batches: 7,
            retries: 2,
        }
    );
    assert_eq!(source.opened(), [None, None, None]);
    // The delays are 100 ms and 200 ms.
    assert!(
        (Duration::from_millis(300)..Duration::from_millis(320)).contains(&waited),
        "{waited:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn each_retryable_error_variant_is_retried() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(
        FaultySource::new("static", expected.clone(), 100).fail_open([
            Error::Unavailable("down".to_owned()),
            Error::RateLimited("slow down".to_owned()),
            Error::Timeout("late".to_owned()),
        ]),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        source,
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );
    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);
    assert_eq!(runner.stats().retries, 3);
    assert_eq!(published_events(&bus, SUBJECT).len(), 648);
}

#[tokio::test(start_paused = true)]
async fn an_error_in_the_stream_makes_the_runner_open_the_stream_again_at_the_last_cursor() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(
        FaultySource::new("static", expected.clone(), 100)
            .fail_stream_after(2, Error::Timeout("read".to_owned())),
    );
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source.clone(),
        bus.clone(),
        store,
        &CancellationToken::new(),
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    assert_eq!(source.opened(), [None, Some("200".to_owned())]);
    let published = published_events(&bus, SUBJECT);
    assert_eq!(published.len(), 648);
    assert_eq!(published, expected, "the runner repeats and loses no event");
    assert_eq!(runner.stats().retries, 1);
}

#[tokio::test]
async fn a_permanent_error_stops_the_runner_with_that_error() {
    let source = Arc::new(
        FaultySource::new("static", fixtures::artex_style_attack(), 100)
            .fail_open([Error::Unauthorized("bad credentials".to_owned())]),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        source.clone(),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );

    let error = run(&runner).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message) if message == "bad credentials"),
        "{error}"
    );
    assert_eq!(runner.stats(), IngestStats::default());
    assert_eq!(source.opened().len(), 1, "no retry after a permanent error");
    assert_eq!(bus.published().len(), 0);
}

#[tokio::test]
async fn a_permanent_error_in_the_stream_stops_the_runner_after_the_good_batches() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(
        FaultySource::new("static", expected.clone(), 100)
            .fail_stream_after(3, Error::Serialization("line 301".to_owned())),
    );
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );

    let error = run(&runner).await.unwrap_err();

    assert!(
        matches!(&error, Error::Serialization(message) if message == "line 301"),
        "{error}"
    );
    assert_eq!(published_events(&bus, SUBJECT), expected[..300]);
    assert_eq!(store.load("static").await.unwrap().as_deref(), Some("300"));
}

#[tokio::test(start_paused = true)]
async fn the_runner_stops_with_the_error_when_the_retry_limit_is_reached() {
    let failures = (1..=10).map(|attempt| Error::Unavailable(format!("attempt {attempt}")));
    let source = Arc::new(
        FaultySource::new("static", fixtures::artex_style_attack(), 100).fail_open(failures),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        source.clone(),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );

    let started = Instant::now();
    let error = run(&runner).await.unwrap_err();
    let waited = started.elapsed();

    // Three retries follow the first attempt. The error of the fourth attempt comes back.
    assert!(
        matches!(&error, Error::Unavailable(message) if message == "attempt 4"),
        "{error}"
    );
    assert_eq!(runner.stats().retries, 3);
    assert_eq!(source.opened().len(), 4);
    assert_eq!(bus.published().len(), 0);
    // The delays are 100 ms, 200 ms, and 400 ms.
    assert!(
        (Duration::from_millis(700)..Duration::from_millis(730)).contains(&waited),
        "{waited:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_delivered_batch_sets_the_retry_count_back_to_zero() {
    let expected = fixtures::artex_style_attack();
    // Four errors in total, but not more than one in sequence. The limit is one retry.
    let source = Arc::new(
        FaultySource::new("static", expected.clone(), 100)
            .fail_stream_after(1, Error::Unavailable("a".to_owned()))
            .fail_stream_after(1, Error::Unavailable("b".to_owned()))
            .fail_stream_after(1, Error::Unavailable("c".to_owned()))
            .fail_stream_after(1, Error::Unavailable("d".to_owned())),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = IngestRunner::new(
        source.clone(),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        CancellationToken::new(),
    )
    .unwrap()
    .with_retry(retry(1));

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    assert_eq!(runner.stats().retries, 4);
    assert_eq!(
        source.opened(),
        [
            None,
            Some("100".to_owned()),
            Some("200".to_owned()),
            Some("300".to_owned()),
            Some("400".to_owned())
        ]
    );
    assert_eq!(published_events(&bus, SUBJECT), expected);
}

#[tokio::test(start_paused = true)]
async fn a_retryable_bus_error_is_retried_and_each_event_arrives_one_time() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(50));
    let bus = Arc::new(
        FaultyBus::default()
            .fail_attempt(5, Error::Unavailable("bus".to_owned()))
            .fail_attempt(6, Error::Timeout("bus".to_owned())),
    );
    let runner = runner(
        source,
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    assert_eq!(published_events(&bus.inner, SUBJECT), expected);
    assert_eq!(
        runner.stats(),
        IngestStats {
            events_published: 648,
            batches: 13,
            retries: 2,
        }
    );
}

#[tokio::test(start_paused = true)]
async fn retryable_checkpoint_errors_are_retried() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(StaticSource::new("static", expected.clone()).with_page_size(100));
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(
        FaultyStore::default()
            .fail_load([Error::Unavailable("store".to_owned())])
            .fail_save(1, Error::Unavailable("store".to_owned())),
    );
    let runner = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    assert_eq!(published_events(&bus, SUBJECT), expected);
    assert_eq!(runner.stats().retries, 2);
    assert_eq!(
        store.inner.load("static").await.unwrap().as_deref(),
        Some("648")
    );
}

#[tokio::test]
async fn a_permanent_error_of_the_checkpoint_load_stops_the_runner_before_it_reads() {
    let source = Arc::new(FaultySource::new(
        "static",
        fixtures::artex_style_attack(),
        100,
    ));
    let bus = Arc::new(MemoryBus::default());
    let store =
        Arc::new(FaultyStore::default().fail_load([Error::Integrity("damaged file".to_owned())]));
    let runner = runner(
        source.clone(),
        bus.clone(),
        store,
        &CancellationToken::new(),
    );

    let error = run(&runner).await.unwrap_err();

    assert!(
        matches!(&error, Error::Integrity(message) if message == "damaged file"),
        "{error}"
    );
    assert_eq!(
        source.opened().len(),
        0,
        "the runner must not start from the beginning"
    );
    assert_eq!(bus.published().len(), 0);
}

#[tokio::test]
async fn a_token_that_fired_before_the_start_stops_the_runner_before_it_reads() {
    let source = Arc::new(FaultySource::new(
        "static",
        fixtures::artex_style_attack(),
        100,
    ));
    let bus = Arc::new(MemoryBus::default());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let runner = runner(
        source.clone(),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &cancel,
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Cancelled);
    assert_eq!(source.opened().len(), 0);
    assert_eq!(bus.published().len(), 0);
}

#[tokio::test]
async fn the_token_stops_a_runner_that_waits_for_the_next_batch() {
    let expected = fixtures::artex_style_attack();
    let source = Arc::new(FaultySource::new("static", expected.clone(), 648).endless());
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let cancel = CancellationToken::new();
    let runner = Arc::new(runner(source, bus.clone(), store.clone(), &cancel));

    let mut messages = bus.subscribe("aegis.events.>", Some("test")).await.unwrap();
    let task = tokio::spawn({
        let runner = runner.clone();
        async move { runner.run().await }
    });
    // Wait until the one batch of the source is on the bus. Then the stream is idle.
    for _ in 0..648 {
        tokio::time::timeout(LIMIT, messages.next())
            .await
            .expect("the runner must publish the batch")
            .unwrap()
            .unwrap();
    }
    cancel.cancel();

    let outcome = tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();
    assert_eq!(outcome.unwrap(), RunOutcome::Cancelled);
    assert_eq!(runner.stats().events_published, 648);
    assert_eq!(store.load("static").await.unwrap().as_deref(), Some("648"));
}

#[tokio::test(start_paused = true)]
async fn the_token_stops_a_runner_that_waits_for_a_retry() {
    let failures = (0..10).map(|_| Error::Unavailable("down".to_owned()));
    let source = Arc::new(
        FaultySource::new("static", fixtures::artex_style_attack(), 100).fail_open(failures),
    );
    let cancel = CancellationToken::new();
    let runner = Arc::new(
        IngestRunner::new(
            source.clone(),
            Arc::new(MemoryBus::default()),
            Arc::new(MemoryCheckpointStore::new()),
            cancel.clone(),
        )
        .unwrap()
        .with_retry(RetryPolicy {
            max_retries: 5,
            initial_delay: Duration::from_secs(3600),
            max_delay: Duration::from_secs(3600),
        }),
    );

    let started = Instant::now();
    let task = tokio::spawn({
        let runner = runner.clone();
        async move { runner.run().await }
    });
    // Let the runner task run until it counts the retry. It then waits for one hour.
    for _ in 0..1_000 {
        if runner.stats().retries > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        runner.stats().retries,
        1,
        "the runner must wait for the retry"
    );
    cancel.cancel();

    let outcome = tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();
    assert_eq!(outcome.unwrap(), RunOutcome::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(3600),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(source.opened().len(), 1);
}

/// A source whose stream gives one batch that has no cursor.
struct NoCursorSource(Vec<Event>);

#[async_trait]
impl SourceConnector for NoCursorSource {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: "static".to_owned(),
            vendor: "aegis".to_owned(),
            product: "test".to_owned(),
            version: "0".to_owned(),
        }
    }

    async fn check(&self) -> Result<()> {
        Ok(())
    }

    async fn stream(&self, _cursor: Option<String>) -> Result<EventStream> {
        let batch = EventBatch {
            events: self.0.clone(),
            next_cursor: None,
        };
        Ok(Box::pin(futures::stream::iter([Ok(batch)])))
    }

    /// Returns the cursor that it received, so that a backfill cannot make progress.
    async fn fetch(&self, _range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        Ok(EventBatch {
            events: self.0.clone(),
            next_cursor: Some(cursor.unwrap_or_else(|| "stuck".to_owned())),
        })
    }
}

#[tokio::test]
async fn a_batch_without_a_cursor_is_published_and_does_not_change_the_checkpoint() {
    let events = fixtures::artex_style_attack()[..5].to_vec();
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    store.save("static", "earlier").await.unwrap();
    let runner = runner(
        Arc::new(NoCursorSource(events.clone())),
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );

    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Completed);

    assert_eq!(published_events(&bus, SUBJECT), events);
    assert_eq!(
        store.load("static").await.unwrap().as_deref(),
        Some("earlier")
    );
    assert_eq!(runner.stats().batches, 1);
}

fn spray_range() -> TimeRange {
    TimeRange {
        start: fixtures::base_time() + chrono::Duration::minutes(10),
        end: fixtures::base_time() + chrono::Duration::seconds(10 * 60 + 30),
    }
}

#[tokio::test]
async fn backfill_publishes_all_pages_of_the_range_and_does_not_change_the_checkpoint() {
    let all = fixtures::artex_style_attack();
    let range = spray_range();
    let expected: Vec<Event> = all
        .iter()
        .filter(|event| range.contains(event.time))
        .cloned()
        .collect();
    assert_eq!(expected.len(), 602, "the spray and two normal events");
    let source = Arc::new(StaticSource::new("static", all).with_page_size(100));
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let runner = runner(
        source,
        bus.clone(),
        store.clone(),
        &CancellationToken::new(),
    );

    let outcome = tokio::time::timeout(LIMIT, runner.backfill(range))
        .await
        .unwrap();

    assert_eq!(outcome.unwrap(), RunOutcome::Completed);
    assert_eq!(published_events(&bus, SUBJECT), expected);
    assert_eq!(
        runner.stats(),
        IngestStats {
            events_published: 602,
            batches: 7,
            retries: 0,
        }
    );
    assert_eq!(store.load("static").await.unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn backfill_repeats_a_page_after_a_retryable_error_and_stops_at_a_permanent_error() {
    let all = fixtures::artex_style_attack();
    let range = spray_range();
    let source = Arc::new(
        FaultySource::new("static", all.clone(), 100)
            .fail_fetch([Error::RateLimited("slow down".to_owned())]),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        source,
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );
    assert_eq!(
        tokio::time::timeout(LIMIT, runner.backfill(range))
            .await
            .unwrap()
            .unwrap(),
        RunOutcome::Completed
    );
    assert_eq!(published_events(&bus, SUBJECT).len(), 602);
    assert_eq!(runner.stats().retries, 1);

    let denied = Arc::new(
        FaultySource::new("static", all, 100)
            .fail_fetch([Error::Unauthorized("no permission".to_owned())]),
    );
    let bus = Arc::new(MemoryBus::default());
    let runner = self::runner(
        denied,
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );
    let error = tokio::time::timeout(LIMIT, runner.backfill(range))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message == "no permission"),
        "{error}"
    );
    assert_eq!(bus.published().len(), 0);
}

#[tokio::test]
async fn backfill_stops_when_the_connector_returns_the_same_cursor_again() {
    let events = fixtures::artex_style_attack()[..2].to_vec();
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        Arc::new(NoCursorSource(events)),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &CancellationToken::new(),
    );

    let error = tokio::time::timeout(LIMIT, runner.backfill(spray_range()))
        .await
        .unwrap()
        .unwrap_err();

    assert!(
        matches!(&error, Error::Integrity(message) if message.contains("static")),
        "{error}"
    );
    assert_eq!(
        bus.published().len(),
        4,
        "two pages before the runner sees the repeated cursor"
    );
}

#[tokio::test]
async fn backfill_stops_when_the_token_fired() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let bus = Arc::new(MemoryBus::default());
    let runner = runner(
        Arc::new(StaticSource::new("static", fixtures::artex_style_attack())),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &cancel,
    );
    let outcome = tokio::time::timeout(LIMIT, runner.backfill(spray_range()))
        .await
        .unwrap();
    assert_eq!(outcome.unwrap(), RunOutcome::Cancelled);
    assert_eq!(bus.published().len(), 0);
}

#[tokio::test]
async fn a_second_operation_of_one_runner_at_the_same_time_is_rejected() {
    let source =
        Arc::new(FaultySource::new("static", fixtures::artex_style_attack(), 648).endless());
    let bus = Arc::new(MemoryBus::default());
    let cancel = CancellationToken::new();
    let runner = Arc::new(runner(
        source,
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        &cancel,
    ));
    let mut messages = bus.subscribe("aegis.events.>", None).await.unwrap();
    let task = tokio::spawn({
        let runner = runner.clone();
        async move { runner.run().await }
    });
    tokio::time::timeout(LIMIT, messages.next())
        .await
        .expect("the first operation must start")
        .unwrap()
        .unwrap();

    let error = runner.run().await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("already in operation")),
        "{error}"
    );
    let error = runner.backfill(spray_range()).await.unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));

    cancel.cancel();
    assert_eq!(
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        RunOutcome::Cancelled
    );
    // The first operation ended. The runner accepts a new operation.
    assert_eq!(run(&runner).await.unwrap(), RunOutcome::Cancelled);
}

#[tokio::test]
async fn a_connector_name_that_is_not_one_subject_token_is_rejected() {
    for name in ["entra.prod", "all *", ">", ""] {
        let source = Arc::new(StaticSource::new(name, Vec::new()));
        let result = IngestRunner::new(
            source,
            Arc::new(MemoryBus::default()),
            Arc::new(MemoryCheckpointStore::new()),
            CancellationToken::new(),
        );
        assert!(
            matches!(result, Err(Error::InvalidInput(_))),
            "{name:?} must be rejected"
        );
    }
}
