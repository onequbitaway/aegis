//! Integration tests for [`FileSource`].
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::Duration;

use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{EventBatch, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use aegis_ingest::{FileSource, FileSourceConfig, ReplayPace};
use aegis_testkit::fixtures;
use chrono::{DateTime, Utc};
use common::fixture_path;
use futures::StreamExt;
use tokio::time::Instant;

fn fixture_source(batch_size: usize) -> FileSource {
    FileSource::new(FileSourceConfig::new("replay", fixture_path()).with_batch_size(batch_size))
        .unwrap()
}

fn write_file(directory: &Path, text: &str) -> FileSource {
    let path = directory.join("events.jsonl");
    std::fs::write(&path, text).unwrap();
    FileSource::new(FileSourceConfig::new("file", path).with_batch_size(2)).unwrap()
}

async fn collect(source: &FileSource, cursor: Option<&str>) -> Vec<Result<EventBatch>> {
    let stream = source.stream(cursor.map(str::to_owned)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(60), stream.collect())
        .await
        .expect("the stream must end at the end of the file")
}

fn events_of(batches: &[Result<EventBatch>]) -> Vec<Event> {
    batches
        .iter()
        .flat_map(|batch| batch.as_ref().unwrap().events.clone())
        .collect()
}

fn all_time() -> TimeRange {
    TimeRange {
        start: DateTime::<Utc>::MIN_UTC,
        end: DateTime::<Utc>::MAX_UTC,
    }
}

#[tokio::test]
async fn the_stream_reads_the_fixture_file_in_batches_with_line_cursors() {
    let source = fixture_source(100);
    let batches = collect(&source, None).await;

    let sizes: Vec<usize> = batches
        .iter()
        .map(|batch| batch.as_ref().unwrap().events.len())
        .collect();
    assert_eq!(sizes, [100, 100, 100, 100, 100, 100, 48]);
    let cursors: Vec<Option<&str>> = batches
        .iter()
        .map(|batch| batch.as_ref().unwrap().next_cursor.as_deref())
        .collect();
    assert_eq!(
        cursors,
        [
            Some("100"),
            Some("200"),
            Some("300"),
            Some("400"),
            Some("500"),
            Some("600"),
            Some("648")
        ]
    );
    let events = events_of(&batches);
    assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
    assert_eq!(events, fixtures::artex_style_attack());
}

#[tokio::test]
async fn the_stream_continues_after_the_line_of_the_cursor() {
    let source = fixture_source(100);
    let expected = fixtures::artex_style_attack();

    let resumed = collect(&source, Some("600")).await;
    assert_eq!(resumed.len(), 1);
    assert_eq!(events_of(&resumed), expected[600..]);
    assert_eq!(
        resumed[0].as_ref().unwrap().next_cursor.as_deref(),
        Some("648")
    );

    assert_eq!(collect(&source, Some("648")).await.len(), 0);
    assert_eq!(collect(&source, Some("9000")).await.len(), 0);
}

#[tokio::test]
async fn the_connector_reports_its_name_and_checks_that_the_file_opens() {
    let source = fixture_source(100);
    let info = source.info();
    assert_eq!(
        (
            info.name.as_str(),
            info.vendor.as_str(),
            info.product.as_str()
        ),
        ("replay", "aegis", "file")
    );
    assert_eq!(source.config().batch_size, 100);
    source.check().await.unwrap();

    let directory = tempfile::tempdir().unwrap();
    let missing = FileSource::new(FileSourceConfig::new(
        "missing",
        directory.path().join("none.jsonl"),
    ))
    .unwrap();
    let error = missing.check().await.unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message.contains("none.jsonl")),
        "{error}"
    );
    let error = missing.stream(None).await.err().unwrap();
    assert!(matches!(error, Error::NotFound(_)));
    let error = missing.fetch(all_time(), None).await.unwrap_err();
    assert!(matches!(error, Error::NotFound(_)));
}

#[tokio::test]
async fn empty_lines_are_ignored_and_counted_in_the_cursor() {
    let events = fixtures::artex_style_attack();
    let lines: Vec<String> = events[..3]
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect();
    let directory = tempfile::tempdir().unwrap();
    // Lines: 1 empty, 2 event, 3 spaces, 4 event, 5 event, 6 empty. No newline at the end.
    let text = format!("\n{}\n   \n{}\n{}\n", lines[0], lines[1], lines[2]);
    let source = write_file(directory.path(), text.trim_end_matches('\n'));

    let batches = collect(&source, None).await;
    assert_eq!(events_of(&batches), events[..3]);
    let cursors: Vec<Option<&str>> = batches
        .iter()
        .map(|batch| batch.as_ref().unwrap().next_cursor.as_deref())
        .collect();
    assert_eq!(cursors, [Some("4"), Some("5")]);

    let resumed = collect(&source, Some("4")).await;
    assert_eq!(events_of(&resumed), events[2..3]);
}

#[tokio::test]
async fn a_malformed_line_is_a_serialization_error_with_the_line_number() {
    let events = fixtures::artex_style_attack();
    let good = fixtures::to_jsonl(&events[..3]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = write_file(directory.path(), &format!("{good}{{\"id\": broken\n{good}"));

    let batches = collect(&source, None).await;

    // The events before the bad line arrive first. The error ends the stream.
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].as_ref().unwrap().events, events[..2]);
    assert_eq!(batches[1].as_ref().unwrap().events, events[2..3]);
    assert_eq!(
        batches[1].as_ref().unwrap().next_cursor.as_deref(),
        Some("3")
    );
    let error = batches[2].as_ref().unwrap_err();
    assert!(
        matches!(error, Error::Serialization(message)
            if message.contains("events.jsonl line 4:") && !message.contains("broken")),
        "{error}"
    );

    // The first page of a backfill ends before the bad line. The second page reaches it.
    let first_page = source.fetch(all_time(), None).await.unwrap();
    assert_eq!(first_page.events, events[..2]);
    assert_eq!(first_page.next_cursor.as_deref(), Some("2"));
    let error = source
        .fetch(all_time(), first_page.next_cursor)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message) if message.contains(" line 4:")),
        "{error}"
    );
}

#[tokio::test]
async fn a_line_that_is_valid_json_but_not_an_event_is_a_serialization_error() {
    let directory = tempfile::tempdir().unwrap();
    let source = write_file(directory.path(), "{\"id\": 1}\n");
    let batches = collect(&source, None).await;
    assert_eq!(batches.len(), 1);
    let error = batches[0].as_ref().unwrap_err();
    assert!(
        matches!(error, Error::Serialization(message) if message.contains(" line 1:")),
        "{error}"
    );
}

#[tokio::test]
async fn a_line_that_is_not_utf8_is_a_serialization_error_with_the_line_number() {
    let events = fixtures::artex_style_attack();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let mut bytes = fixtures::to_jsonl(&events[..1]).unwrap().into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
    std::fs::write(&path, bytes).unwrap();
    let source = FileSource::new(FileSourceConfig::new("file", path)).unwrap();

    let batches = collect(&source, None).await;
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].as_ref().unwrap().events, events[..1]);
    let error = batches[1].as_ref().unwrap_err();
    assert!(
        matches!(error, Error::Serialization(message) if message.contains("line 2: the line is not valid UTF-8")),
        "{error}"
    );
}

#[tokio::test]
async fn a_cursor_that_is_not_a_line_number_is_invalid_input() {
    let source = fixture_source(100);
    for cursor in ["abc", "-1", "1.5", ""] {
        let error = source.stream(Some(cursor.to_owned())).await.err().unwrap();
        assert!(matches!(error, Error::InvalidInput(_)), "{cursor:?}");
        let error = source
            .fetch(all_time(), Some(cursor.to_owned()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)), "{cursor:?}");
    }
}

#[tokio::test]
async fn fetch_pages_through_the_events_in_the_range() {
    let source = fixture_source(250);
    let range = TimeRange {
        start: fixtures::base_time() + chrono::Duration::minutes(10),
        end: fixtures::base_time() + chrono::Duration::seconds(10 * 60 + 30),
    };
    let expected: Vec<Event> = fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| range.contains(event.time))
        .collect();
    assert_eq!(expected.len(), 602);

    let mut cursor = None;
    let mut pages = Vec::new();
    let mut events = Vec::new();
    loop {
        let batch = source.fetch(range, cursor.clone()).await.unwrap();
        pages.push((batch.events.len(), batch.next_cursor.clone()));
        events.extend(batch.events);
        cursor = batch.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(pages.len() < 10, "the read must end");
    }

    // Lines 1 to 12 are before the range. Thus the first page ends at line 262.
    assert_eq!(
        pages,
        [
            (250, Some("262".to_owned())),
            (250, Some("512".to_owned())),
            (102, None)
        ]
    );
    assert_eq!(events, expected);
}

#[tokio::test]
async fn fetch_returns_an_empty_last_page_for_a_range_with_no_events() {
    let source = fixture_source(100);
    let range = TimeRange {
        start: fixtures::base_time() - chrono::Duration::hours(2),
        end: fixtures::base_time() - chrono::Duration::hours(1),
    };
    let batch = source.fetch(range, None).await.unwrap();
    assert_eq!(batch.events.len(), 0);
    assert_eq!(batch.next_cursor, None);
}

fn timed_event(seconds: i64) -> Event {
    fixtures::sign_in(
        fixtures::base_time() + chrono::Duration::seconds(seconds),
        "user-1",
        fixtures::OFFICE_IP,
        true,
    )
}

#[tokio::test(start_paused = true)]
async fn a_timed_replay_keeps_the_time_gaps_divided_by_the_speed() {
    // Recorded at 0 s, 60 s, 60 s, 180 s. With speed 60: emitted at 0 s, 1 s, 1 s, 3 s.
    let events = [
        timed_event(0),
        timed_event(60),
        timed_event(60),
        timed_event(180),
    ];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    std::fs::write(&path, fixtures::to_jsonl(&events).unwrap()).unwrap();
    let source = FileSource::new(
        FileSourceConfig::new("timed", path).with_pace(ReplayPace::Timed { speed: 60.0 }),
    )
    .unwrap();

    let started = Instant::now();
    let mut stream = source.stream(None).await.unwrap();
    let mut arrivals = Vec::new();
    while let Some(batch) = tokio::time::timeout(Duration::from_secs(600), stream.next())
        .await
        .expect("the replay must not stop")
    {
        let batch = batch.unwrap();
        arrivals.push((
            started.elapsed().as_millis() / 100,
            batch.events,
            batch.next_cursor,
        ));
    }

    assert_eq!(
        arrivals,
        [
            (0, events[..1].to_vec(), Some("1".to_owned())),
            (10, events[1..3].to_vec(), Some("3".to_owned())),
            (30, events[3..].to_vec(), Some("4".to_owned())),
        ],
        "arrival times are in tenths of a second"
    );
}

#[tokio::test(start_paused = true)]
async fn a_timed_replay_from_a_cursor_starts_its_clock_at_the_first_event_that_it_reads() {
    let events = [timed_event(0), timed_event(3600), timed_event(3602)];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    std::fs::write(&path, fixtures::to_jsonl(&events).unwrap()).unwrap();
    let source = FileSource::new(
        FileSourceConfig::new("timed", path).with_pace(ReplayPace::Timed { speed: 1.0 }),
    )
    .unwrap();

    let started = Instant::now();
    let mut stream = source.stream(Some("1".to_owned())).await.unwrap();
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first.events, events[1..2]);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );
    let second = stream.next().await.unwrap().unwrap();
    assert_eq!(second.events, events[2..]);
    assert_eq!(started.elapsed().as_millis() / 100, 20);
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn a_fast_replay_does_not_wait_for_the_recorded_gaps() {
    let events = [timed_event(0), timed_event(86_400)];
    let directory = tempfile::tempdir().unwrap();
    let source = write_file(directory.path(), &fixtures::to_jsonl(&events).unwrap());
    let batches = collect(&source, None).await;
    assert_eq!(batches.len(), 1);
    assert_eq!(events_of(&batches), events);
}

#[test]
fn a_configuration_that_cannot_replay_is_rejected() {
    let config = |change: fn(&mut FileSourceConfig)| {
        let mut config = FileSourceConfig::new("file", "events.jsonl");
        change(&mut config);
        match FileSource::new(config) {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    };
    assert!(config(|config| config.batch_size = 0).contains("batch_size"));
    assert!(config(|config| config.pace = ReplayPace::Timed { speed: 0.0 }).contains("speed"));
    assert!(config(|config| config.pace = ReplayPace::Timed { speed: -2.0 }).contains("speed"));
    assert!(config(|config| config.pace = ReplayPace::Timed { speed: f64::NAN }).contains("speed"));
    assert!(
        config(|config| config.pace = ReplayPace::Timed {
            speed: f64::INFINITY
        })
        .contains("speed")
    );
    assert!(config(|config| config.name = "a.b".to_owned()).contains("connector name"));
}

#[test]
fn the_configuration_reads_toml_with_defaults_and_rejects_unknown_fields() {
    let minimal: FileSourceConfig = toml::from_str(
        r#"
        name = "replay"
        path = "fixtures/artex_style_attack.jsonl"
        "#,
    )
    .unwrap();
    assert_eq!(
        minimal,
        FileSourceConfig {
            name: "replay".to_owned(),
            path: "fixtures/artex_style_attack.jsonl".into(),
            pace: ReplayPace::Fast,
            batch_size: 100,
        }
    );

    let full: FileSourceConfig = toml::from_str(
        r#"
        name = "replay"
        path = "/var/lib/aegis/events.jsonl"
        pace = { mode = "timed", speed = 60.0 }
        batch_size = 25
        "#,
    )
    .unwrap();
    assert_eq!(full.pace, ReplayPace::Timed { speed: 60.0 });
    assert_eq!(full.batch_size, 25);
    let text = toml::to_string(&full).unwrap();
    assert_eq!(toml::from_str::<FileSourceConfig>(&text).unwrap(), full);

    let error = toml::from_str::<FileSourceConfig>(
        r#"
        name = "replay"
        path = "events.jsonl"
        speed = 2.0
        "#,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("unknown field `speed`"),
        "{error}"
    );
}
