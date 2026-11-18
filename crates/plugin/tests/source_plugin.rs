//! Tests that load the example source plugin through the host.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus;
use aegis_contracts::common::TimeRange;
use aegis_contracts::event::{self, EventClass, Outcome};
use aegis_contracts::source::{ConnectorInfo, EventBatch, SourceConnector};
use aegis_contracts::{EntityKind, Error, Event, Severity};
use aegis_plugin::{HostLimits, PluginHost, PluginKind, PluginManifest};
use aegis_testkit::MemoryBus;
use futures::StreamExt;

/// The name that the operator gives to the connector instance in these tests.
const NAME: &str = "example-prod";
/// The identifiers of the five events of the example plugin, in time order.
const EVENT_IDS: [&str; 5] = [
    "018f0000-0000-7000-8000-000000000001",
    "018f0000-0000-7000-8000-000000000002",
    "018f0000-0000-7000-8000-000000000003",
    "018f0000-0000-7000-8000-000000000004",
    "018f0000-0000-7000-8000-000000000005",
];
/// The longest time that a test waits for the plugin.
const PATIENCE: Duration = Duration::from_secs(30);

fn manifest() -> PluginManifest {
    let mut manifest = common::manifest(NAME, PluginKind::Source, "example-source");
    manifest.poll_interval = Duration::from_millis(10);
    manifest
}

async fn load(manifest: &PluginManifest) -> Arc<dyn SourceConnector> {
    let host = PluginHost::new(HostLimits::default()).unwrap();
    host.load_source(manifest).await.unwrap()
}

fn all_time() -> TimeRange {
    TimeRange {
        start: common::time("2000-01-01T00:00:00Z"),
        end: common::time("2100-01-01T00:00:00Z"),
    }
}

fn ids(events: &[Event]) -> Vec<String> {
    events.iter().map(|event| event.id.to_string()).collect()
}

#[tokio::test]
async fn info_is_the_identity_of_the_plugin_with_the_name_of_the_manifest() {
    let source = load(&manifest()).await;
    assert_eq!(
        source.info(),
        ConnectorInfo {
            name: NAME.to_owned(),
            vendor: "aegis".to_owned(),
            product: "example".to_owned(),
            version: "0.1.0".to_owned(),
        }
    );
}

#[tokio::test]
async fn check_succeeds_with_good_configuration_and_fails_with_bad_configuration() {
    let source = load(&manifest()).await;
    source.check().await.unwrap();

    let mut bad = manifest();
    bad.config.insert("page_size".to_owned(), "many".to_owned());
    let error = load(&bad).await.check().await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.starts_with("plugin example-prod: ") && message.contains("page_size")),
        "{error:?}"
    );
}

#[tokio::test]
async fn fetch_pages_through_the_range_with_the_cursor() {
    let source = load(&manifest()).await;
    let mut pages: Vec<EventBatch> = Vec::new();
    let mut cursor = None;
    loop {
        let batch = source.fetch(all_time(), cursor).await.unwrap();
        cursor = batch.next_cursor.clone();
        pages.push(batch);
        if cursor.is_none() {
            break;
        }
        assert!(pages.len() < 10, "the plugin did not complete the read");
    }

    let sizes: Vec<usize> = pages.iter().map(|page| page.events.len()).collect();
    assert_eq!(sizes, [2, 2, 1]);
    let cursors: Vec<Option<&str>> = pages
        .iter()
        .map(|page| page.next_cursor.as_deref())
        .collect();
    assert_eq!(cursors, [Some("2"), Some("4"), None]);
    let events: Vec<Event> = pages.into_iter().flat_map(|page| page.events).collect();
    assert_eq!(ids(&events), EVENT_IDS);
    assert!(events.iter().map(|event| event.time).is_sorted());
}

#[tokio::test]
async fn fetch_returns_normalized_events() {
    let source = load(&manifest()).await;
    let batch = source
        .fetch(all_time(), Some("1".to_owned()))
        .await
        .unwrap();
    assert_eq!(batch.events.len(), 2);

    let failed = &batch.events[0];
    assert_eq!(failed.id.to_string(), EVENT_IDS[1]);
    assert_eq!(failed.time, common::time("2026-01-02T03:01:00Z"));
    assert_eq!(failed.class, EventClass::Authentication);
    assert_eq!(failed.action, event::action::SIGN_IN);
    assert_eq!(failed.outcome, Outcome::Failure);
    assert_eq!(failed.severity, Severity::Informational);
    assert_eq!(failed.actor.kind, EntityKind::User);
    assert_eq!(failed.actor.id, "bob@example.com");
    assert_eq!(failed.actor.ip, Some("203.0.113.7".parse().unwrap()));
    assert_eq!(
        failed.attribute_str(event::attr::FAILURE_REASON),
        Some("The password is not correct.")
    );
    assert_eq!(failed.source.vendor, "aegis");
    assert_eq!(failed.source.product, "example");
    // The host sets the connector name. The plugin wrote `example-source`.
    assert_eq!(failed.source.connector, NAME);
}

#[tokio::test]
async fn fetch_returns_only_the_events_in_the_range() {
    let source = load(&manifest()).await;
    let range = TimeRange {
        start: common::time("2026-01-02T03:01:00Z"),
        end: common::time("2026-01-02T03:03:00Z"),
    };
    let batch = source.fetch(range, None).await.unwrap();
    assert_eq!(ids(&batch.events), EVENT_IDS[1..3]);
    assert_eq!(batch.next_cursor, None);

    let before_all = TimeRange {
        start: common::time("2000-01-01T00:00:00Z"),
        end: common::time("2026-01-02T03:00:00Z"),
    };
    let batch = source.fetch(before_all, None).await.unwrap();
    assert_eq!(batch.events, Vec::new());
    assert_eq!(batch.next_cursor, None);
}

#[tokio::test]
async fn fetch_obeys_the_page_size_of_the_manifest_configuration() {
    let mut manifest = manifest();
    manifest
        .config
        .insert("page_size".to_owned(), "4".to_owned());
    let source = load(&manifest).await;
    let batch = source.fetch(all_time(), None).await.unwrap();
    assert_eq!(ids(&batch.events), EVENT_IDS[..4]);
    assert_eq!(batch.next_cursor.as_deref(), Some("4"));
}

#[tokio::test]
async fn fetch_refuses_a_bad_cursor_and_a_reversed_range() {
    let source = load(&manifest()).await;
    let error = source
        .fetch(all_time(), Some("abc".to_owned()))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message)
            if message.starts_with("plugin example-prod: ") && message.contains("abc")),
        "{error:?}"
    );

    let reversed = TimeRange {
        start: all_time().end,
        end: all_time().start,
    };
    let error = source.fetch(reversed, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("ends before it starts")),
        "{error:?}"
    );
}

#[tokio::test]
async fn stream_yields_the_events_as_batches_and_stays_open() {
    let source = load(&manifest()).await;
    let stream = source.stream(None).await.unwrap();
    let batches: Vec<EventBatch> = tokio::time::timeout(
        PATIENCE,
        stream.take(5).map(|batch| batch.unwrap()).collect(),
    )
    .await
    .expect("the stream did not yield five batches");

    let sizes: Vec<usize> = batches.iter().map(|batch| batch.events.len()).collect();
    // After the last event, the stream stays open and yields empty batches.
    assert_eq!(sizes, [2, 2, 1, 0, 0]);
    let cursors: Vec<Option<&str>> = batches
        .iter()
        .map(|batch| batch.next_cursor.as_deref())
        .collect();
    assert_eq!(
        cursors,
        [Some("2"), Some("4"), Some("5"), Some("5"), Some("5")]
    );
    let events: Vec<Event> = batches.into_iter().flat_map(|batch| batch.events).collect();
    assert_eq!(ids(&events), EVENT_IDS);
    assert_eq!(events.len(), 5);
    assert!(events.iter().all(|event| event.source.connector == NAME));
}

#[tokio::test]
async fn stream_continues_after_the_cursor_of_an_earlier_batch() {
    let source = load(&manifest()).await;
    let mut stream = source.stream(Some("4".to_owned())).await.unwrap();
    let batch = tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("the stream did not yield a batch")
        .expect("the stream ended")
        .unwrap();
    assert_eq!(ids(&batch.events), EVENT_IDS[4..]);
    assert_eq!(batch.next_cursor.as_deref(), Some("5"));
}

#[tokio::test]
async fn stream_sends_the_previous_cursor_again_when_a_batch_has_no_next_cursor() {
    // This guest shows the cursor of each call in an event. Its batches have no cursor.
    let mut manifest = common::manifest(NAME, PluginKind::Source, "faulty-source");
    manifest.poll_interval = Duration::from_millis(10);
    manifest
        .config
        .insert("mode".to_owned(), "echo-cursor".to_owned());
    let source = load(&manifest).await;

    let stream = source.stream(Some("position-7".to_owned())).await.unwrap();
    let batches: Vec<EventBatch> = tokio::time::timeout(
        PATIENCE,
        stream.take(3).map(|batch| batch.unwrap()).collect(),
    )
    .await
    .expect("the stream did not yield three batches");

    assert_eq!(batches.len(), 3);
    for batch in &batches {
        assert_eq!(batch.next_cursor, None);
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].attribute_str("cursor"), Some("position-7"));
    }
}

#[tokio::test]
async fn the_events_of_a_plugin_go_through_the_message_bus_as_ordinary_events() {
    let source = load(&manifest()).await;
    let bus = MemoryBus::default();
    // The connector name is one token of the subject.
    let subject = format!("{}.{}", bus::subject::EVENTS, source.info().name);
    assert_eq!(subject, "aegis.events.example-prod");

    let stream = source.stream(None).await.unwrap();
    let batches: Vec<EventBatch> = tokio::time::timeout(
        PATIENCE,
        stream.take(3).map(|batch| batch.unwrap()).collect(),
    )
    .await
    .expect("the stream did not yield three batches");
    let sent: Vec<Event> = batches.into_iter().flat_map(|batch| batch.events).collect();
    assert_eq!(sent.len(), 5);
    for event in &sent {
        bus::publish_json(&bus, &subject, event).await.unwrap();
    }

    let received: Vec<Event> = bus
        .published_to("aegis.events.*")
        .iter()
        .map(|message| message.decode().unwrap())
        .collect();
    assert_eq!(ids(&received), EVENT_IDS);
    assert_eq!(received, sent);
}

#[tokio::test]
async fn a_large_batch_decodes_to_all_its_events() {
    // The JSON text of this batch is larger than 1 MiB. The host decodes a text of this
    // size on a blocking thread.
    let mut manifest = common::manifest(NAME, PluginKind::Source, "faulty-source");
    manifest
        .config
        .insert("mode".to_owned(), "many-events".to_owned());
    manifest
        .config
        .insert("event_count".to_owned(), "5000".to_owned());
    let source = load(&manifest).await;

    let mut stream = source.stream(Some("9".to_owned())).await.unwrap();
    let batch = tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("the stream did not yield a batch")
        .expect("the stream ended")
        .unwrap();

    assert_eq!(batch.events.len(), 5000);
    assert_eq!(batch.next_cursor.as_deref(), Some("9"));
    assert!(serde_json::to_vec(&batch).unwrap().len() > 1024 * 1024);
    let indexes: Vec<u64> = batch
        .events
        .iter()
        .filter_map(|event| event.attributes.get("index")?.as_u64())
        .collect();
    assert_eq!(indexes, (0..5000).collect::<Vec<u64>>());
    assert!(
        batch
            .events
            .iter()
            .all(|event| event.source.connector == NAME)
    );
}

#[tokio::test]
async fn stream_yields_an_error_as_an_item_and_continues() {
    let source = load(&manifest()).await;
    let stream = source
        .stream(Some("not-a-number".to_owned()))
        .await
        .unwrap();
    let items: Vec<_> = tokio::time::timeout(PATIENCE, stream.take(2).collect())
        .await
        .expect("the stream did not yield two items");
    assert_eq!(items.len(), 2);
    for item in items {
        let error = item.unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("not-a-number")),
            "{error:?}"
        );
    }
}

/// The clock of this test moves only when each task waits for a timer. Then it jumps to
/// the time of the next timer. Thus the test measures the waits of the host exactly, and
/// it does not wait in real time.
#[tokio::test(start_paused = true)]
async fn stream_waits_for_the_poll_interval_between_two_polls() {
    let interval = Duration::from_secs(3600);
    let mut manifest = manifest();
    manifest.poll_interval = interval;
    let source = load(&manifest).await;
    let mut stream = source.stream(None).await.unwrap();
    let opened = tokio::time::Instant::now();

    // The first poll is immediate: the host does not wait for a timer before it.
    let first = stream.next().await.expect("the stream ended").unwrap();
    assert_eq!(first.next_cursor.as_deref(), Some("2"));
    assert_eq!(opened.elapsed(), Duration::ZERO);

    // The second poll comes one interval after the first poll, and the third poll one
    // interval after the second poll.
    let second = stream.next().await.expect("the stream ended").unwrap();
    assert_eq!(second.next_cursor.as_deref(), Some("4"));
    assert_eq!(opened.elapsed(), interval);
    let third = stream.next().await.expect("the stream ended").unwrap();
    assert_eq!(third.next_cursor.as_deref(), Some("5"));
    assert_eq!(opened.elapsed(), interval * 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_tasks_can_use_one_connector_at_the_same_time() {
    let source = load(&manifest()).await;
    let tasks: Vec<_> = (0..24)
        .map(|index| {
            let source = Arc::clone(&source);
            tokio::spawn(async move {
                let cursor = (index % 5).to_string();
                let batch = source.fetch(all_time(), Some(cursor)).await.unwrap();
                (index % 5, batch)
            })
        })
        .collect();
    assert_eq!(tasks.len(), 24);
    for task in tasks {
        let (offset, batch) = tokio::time::timeout(PATIENCE, task)
            .await
            .expect("a task did not complete")
            .unwrap();
        // Each call has its own instance, thus each task gets the page that it asked for.
        assert_eq!(
            ids(&batch.events),
            EVENT_IDS[offset..(offset + 2).min(5)],
            "offset {offset}"
        );
    }

    // The stream is `Send` and `'static`: a different task can own it.
    let mut stream = source.stream(None).await.unwrap();
    let first = tokio::spawn(async move { stream.next().await })
        .await
        .unwrap()
        .expect("the stream ended")
        .unwrap();
    assert_eq!(first.events.len(), 2);
}
