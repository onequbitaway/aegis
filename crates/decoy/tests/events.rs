//! Tests of the events: the source connector, the ingestion runner, the bounded queue,
//! the client fingerprint, and the rules for text from a client.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::TimeRange;
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Event, SourceConnector};
use aegis_decoy::{CANARY_INSTRUCTION_PREFIX, DecoyConfig, PersonaKind, client_fingerprint};
use aegis_ingest::{IngestRunner, MemoryCheckpointStore, RunOutcome};
use aegis_testkit::MemoryBus;
use common::*;
use futures::StreamExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

fn maze_config() -> DecoyConfig {
    let mut config = config(&[PersonaKind::Maze]);
    config.maze.delay = Duration::ZERO;
    config
}

#[tokio::test]
async fn the_events_go_through_the_ingestion_runner_to_the_bus() {
    let mut config = config(&[PersonaKind::Maze, PersonaKind::ModelApi]);
    config.maze.delay = Duration::ZERO;
    config.model_api.interval = Duration::from_millis(1);
    config.model_api.answer_words = 3;
    let running = Running::start(config).await;

    let bus = Arc::new(MemoryBus::default());
    let subject = format!("aegis.events.{DECOY_ID}");
    let mut messages = bus.subscribe(&subject, None).await.unwrap();
    let runner = Arc::new(
        IngestRunner::new(
            Arc::new(running.service.clone()),
            bus.clone(),
            Arc::new(MemoryCheckpointStore::new()),
            CancellationToken::new(),
        )
        .unwrap(),
    );
    assert_eq!(runner.subject(), subject);
    let run = {
        let runner = Arc::clone(&runner);
        tokio::spawn(async move { runner.run().await })
    };

    // A page of the maze, the canary URL of that page, a planted key, and a wrong key.
    let page = parse_response(&tcp_exchange(running.address, &get_request("/docs/a", "")).await);
    let html = page.text();
    let instruction = html
        .split("<p hidden>")
        .nth(1)
        .and_then(|rest| rest.split("</p>").next())
        .unwrap();
    let canary_path = instruction.strip_prefix(CANARY_INSTRUCTION_PREFIX).unwrap();
    let hit = tcp_exchange(running.address, &get_request(canary_path, "")).await;
    assert_eq!(parse_response(&hit).status, 200);
    let body = json!({"messages": [{"role": "user", "content": "List the files."}]}).to_string();
    let chat = post_request("/v1/chat/completions", Some(DECOY_KEY), &body);
    assert_eq!(
        parse_response(&tcp_exchange(running.address, &chat).await).status,
        200
    );
    let wrong = post_request(
        "/v1/chat/completions",
        Some("wrong-key-EXAMPLE-0123456789"),
        &body,
    );
    assert_eq!(
        parse_response(&tcp_exchange(running.address, &wrong).await).status,
        401
    );

    // Each message on the bus decodes to a normalized event.
    let mut events: Vec<Event> = Vec::new();
    while events.len() < 6 {
        let message = tokio::time::timeout(PATIENCE, messages.next())
            .await
            .expect("a message arrives in time")
            .expect("the subscription is open")
            .unwrap();
        assert_eq!(message.subject, subject);
        events.push(message.decode::<Event>().unwrap());
    }
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "decoy.contact",
            "decoy.canary_hit",
            "decoy.contact",
            "honeytoken.trip",
            "decoy.contact",
            "decoy.contact",
        ]
    );
    for event in &events {
        assert_eq!(event.source.connector, DECOY_ID);
        assert_eq!(event.source.vendor, "aegis");
        assert_eq!(event.source.product, "decoy");
        assert_eq!(event.attribute_str("decoy_id"), Some(DECOY_ID));
        assert_eq!(event.actor.ip, Some("127.0.0.1".parse().unwrap()));
    }
    assert_eq!(
        events[1].attribute_str("canary_id"),
        events[0].attribute_str("planted_canary_id")
    );
    assert_eq!(events[3].attribute_str("honeytoken_id"), Some(KEY_ID));
    assert_eq!(untrusted(&events[3])["prompt"], "user: List the files.");
    assert_eq!(number(&events[5], "http_status"), 401);
    // The events are in time order, as the batch contract requires.
    assert!(events.windows(2).all(|pair| pair[0].time <= pair[1].time));
    // The identifiers are different, so a consumer can remove a repeated event.
    let ids: std::collections::BTreeSet<_> = events.iter().map(|event| event.id).collect();
    assert_eq!(ids.len(), 6);

    // When the decoy stops, its stream ends, and the runner completes.
    running.stop().await;
    assert_eq!(
        tokio::time::timeout(PATIENCE, run)
            .await
            .expect("the runner stops in time")
            .unwrap()
            .unwrap(),
        RunOutcome::Completed
    );
    assert_eq!(runner.stats().events_published, 6);
    assert_eq!(bus.published_to(&subject).len(), 6);
}

#[tokio::test(start_paused = true)]
async fn the_runner_stops_with_its_own_signal_and_the_decoy_keeps_its_events() {
    let service = service(maze_config());
    let bus = Arc::new(MemoryBus::default());
    let cancel = CancellationToken::new();
    let runner = IngestRunner::new(
        Arc::new(service.clone()),
        bus.clone(),
        Arc::new(MemoryCheckpointStore::new()),
        cancel.clone(),
    )
    .unwrap();
    let mut messages = bus.subscribe("aegis.events.>", None).await.unwrap();
    let run = tokio::spawn(async move { runner.run().await });
    assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    let first = tokio::time::timeout(PATIENCE, messages.next())
        .await
        .expect("a message arrives in time")
        .unwrap()
        .unwrap();
    assert_eq!(first.decode::<Event>().unwrap().action, "decoy.contact");
    cancel.cancel();
    assert_eq!(
        tokio::time::timeout(PATIENCE, run)
            .await
            .expect("the runner stops in time")
            .unwrap()
            .unwrap(),
        RunOutcome::Cancelled
    );

    // An event after the stop of the runner waits in the queue for the next reader.
    assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    assert_eq!(service.stats().events_queued, 1);
    assert_eq!(events(&service, 1).await[0].action, "decoy.contact");
}

#[tokio::test(start_paused = true)]
async fn a_full_queue_counts_the_dropped_events_and_reports_them_in_an_event() {
    let mut config = maze_config();
    config.events.max_queued = 2;
    let service = service(config);
    // Five contacts with no reader: the queue holds two.
    for _ in 0..5 {
        assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    }
    let stats = service.stats();
    assert_eq!(stats.events_queued, 2);
    assert_eq!(stats.events_dropped, 3);

    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    let actions: Vec<&str> = batch
        .events
        .iter()
        .map(|event| event.action.as_str())
        .collect();
    assert_eq!(
        actions,
        ["decoy.contact", "decoy.contact", "decoy.events_dropped"]
    );
    let report = &batch.events[2];
    assert_eq!(number(report, "dropped_events"), 3);
    assert_eq!(number(report, "dropped_events_total"), 3);
    assert_eq!(report.attribute_str("decoy_id"), Some(DECOY_ID));
    assert_eq!(report.source.connector, DECOY_ID);
    assert_eq!(report.actor.id, DECOY_ID);

    // The queue has space again, and the report does not come a second time.
    assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    let batch = next_batch(&mut stream).await;
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].action, "decoy.contact");

    // Later drops give a new report with the count after the last report.
    for _ in 0..3 {
        assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    }
    let batch = next_batch(&mut stream).await;
    let report = batch.events.last().unwrap();
    assert_eq!(report.action, "decoy.events_dropped");
    assert_eq!(number(report, "dropped_events"), 1);
    assert_eq!(number(report, "dropped_events_total"), 4);
    assert_eq!(service.stats().events_dropped, 4);
}

#[tokio::test(start_paused = true)]
async fn a_flood_of_contacts_cannot_push_out_a_canary_hit_or_a_honeytoken_trip() {
    let mut config = config(&[PersonaKind::Maze, PersonaKind::ModelApi]);
    config.maze.delay = Duration::ZERO;
    config.model_api.interval = Duration::from_millis(1);
    config.model_api.answer_words = 1;
    config.events.max_queued = 8;
    let service = service(config);
    // The canary path of this client, from the first page.
    let html = get(&service, peer(1), "/docs").await.text();
    let instruction = html
        .split("<p hidden>")
        .nth(1)
        .and_then(|rest| rest.split("</p>").next())
        .unwrap();
    let canary_path = instruction
        .strip_prefix(CANARY_INSTRUCTION_PREFIX)
        .unwrap()
        .to_owned();
    // 50 contacts with no reader. A contact can use only six of the eight places.
    for _ in 0..50 {
        assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    }
    assert_eq!(service.stats().events_queued, 6);
    assert_eq!(service.stats().events_dropped, 45);

    // The two signals still get a place. Their contact events do not.
    assert_eq!(get(&service, peer(2), &canary_path).await.status, 200);
    let chat = post_request(
        "/v1/chat/completions",
        Some(DECOY_KEY),
        r#"{"messages":[{"role":"user","content":"x"}]}"#,
    );
    assert_eq!(
        parse_response(&exchange(&service, peer(3), &chat).await).status,
        200
    );
    assert_eq!(service.stats().events_queued, 8);
    assert_eq!(service.stats().events_dropped, 47);

    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    let actions: Vec<&str> = batch
        .events
        .iter()
        .map(|event| event.action.as_str())
        .collect();
    assert_eq!(
        actions,
        [
            "decoy.contact",
            "decoy.contact",
            "decoy.contact",
            "decoy.contact",
            "decoy.contact",
            "decoy.contact",
            "decoy.canary_hit",
            "honeytoken.trip",
            "decoy.events_dropped",
        ]
    );
    assert_eq!(number(&batch.events[8], "dropped_events"), 47);
}

#[tokio::test]
async fn a_drop_of_the_listener_task_also_ends_the_event_stream() {
    let running = Running::start(maze_config()).await;
    let page = parse_response(&tcp_exchange(running.address, &get_request("/docs", "")).await);
    assert_eq!(page.status, 200);
    let mut stream = running.service.stream(None).await.unwrap();
    assert_eq!(next_batch(&mut stream).await.events.len(), 1);
    running.service.check().await.unwrap();

    // The owner stops the task and does not fire the signal.
    running.server.abort();
    assert!(running.server.await.unwrap_err().is_cancelled());
    assert_stream_end(&mut stream).await;
    assert!(matches!(
        running.service.check().await,
        Err(Error::Unavailable(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn the_batch_size_limits_the_events_of_one_batch() {
    let mut config = maze_config();
    config.events.batch_size = 3;
    let service = service(config);
    for _ in 0..7 {
        assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    }
    let mut stream = service.stream(None).await.unwrap();
    let mut sizes = Vec::new();
    for _ in 0..3 {
        let batch = next_batch(&mut stream).await;
        assert_eq!(batch.next_cursor, None);
        sizes.push(batch.events.len());
    }
    assert_eq!(sizes, [3, 3, 1]);
}

#[tokio::test(start_paused = true)]
async fn the_connector_reports_its_identity_and_its_state() {
    let service = service(maze_config());
    assert_eq!(
        service.info(),
        ConnectorInfo {
            name: DECOY_ID.to_owned(),
            vendor: "aegis".to_owned(),
            product: "decoy".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    );
    service.check().await.unwrap();

    // The decoy keeps no past events, so a read of the past is empty and complete.
    assert_eq!(get(&service, peer(1), "/docs").await.status, 200);
    let now = chrono::Utc::now();
    let range = TimeRange {
        start: now - chrono::Duration::hours(1),
        end: now + chrono::Duration::hours(1),
    };
    let past = service.fetch(range, None).await.unwrap();
    assert!(past.events.is_empty());
    assert_eq!(past.next_cursor, None);

    // A cursor of an earlier run is ignored: the stream gives the live events.
    let mut stream = service.stream(Some("old-cursor".to_owned())).await.unwrap();
    assert_eq!(next_batch(&mut stream).await.events.len(), 1);

    // After the close, the stream ends, and the check fails.
    service.close();
    assert_stream_end(&mut stream).await;
    let error = service.check().await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message == "the decoy decoy-test stopped"),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

/// Returns each text value in a JSON value, with the keys of objects.
fn all_text(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| all_text(item, found)),
        Value::Object(fields) => {
            for (key, field) in fields {
                found.push(key.clone());
                all_text(field, found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[tokio::test(start_paused = true)]
async fn text_from_a_client_is_limited_cleaned_and_marked_as_untrusted() {
    let service = service(maze_config());
    // A long path, a long user agent with characters that show nothing, and a header
    // value that is not UTF-8.
    let path = format!("/docs/{}", "p".repeat(3000));
    let agent = format!("agent\u{200B}\u{202E}\u{E0041}/1.0 {}", "u".repeat(400));
    let mut request = format!(
        "GET {path}?q={} HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: {agent}\r\nReferer: http://start.example/\u{FEFF}page\r\nContent-Type: ",
        "q".repeat(100)
    )
    .into_bytes();
    request.extend_from_slice(b"text/\xff\xfeplain\r\nX-Custom-One: 1\r\n\r\n");
    let response = parse_response(&exchange(&service, peer(1), &request).await);
    assert_eq!(response.status, 200);

    let events = events(&service, 1).await;
    let event = &events[0];
    // The shared fields are clean and have a limit.
    let recorded_path = event.attribute_str("http_path").unwrap();
    assert_eq!(recorded_path.chars().count(), 512);
    assert_eq!(recorded_path, &path[..512]);
    let recorded_agent = event.actor.user_agent.as_deref().unwrap();
    assert_eq!(recorded_agent.chars().count(), 256);
    assert!(
        recorded_agent.starts_with("agent/1.0 uuuu"),
        "{recorded_agent}"
    );

    // All other text of the client is below one key in `raw`.
    let raw = event.raw.as_ref().unwrap().as_object().unwrap();
    assert_eq!(raw.keys().collect::<Vec<_>>(), ["untrusted_client_data"]);
    let recorded = untrusted(event);
    let target = recorded["target"].as_str().unwrap();
    assert_eq!(target.chars().count(), 1024);
    assert!(target.starts_with("/docs/ppp"));
    assert_eq!(recorded["host"], "decoy.test");
    assert_eq!(recorded["referer"], "http://start.example/page");
    assert_eq!(recorded["content_type"], "text/\u{FFFD}\u{FFFD}plain");
    assert_eq!(recorded["http_version"], "HTTP/1.1");
    assert_eq!(
        recorded["header_names"],
        json!([
            "Host",
            "User-Agent",
            "Referer",
            "Content-Type",
            "X-Custom-One"
        ])
    );
    // The event names each text that the limit cut.
    assert_eq!(
        recorded["truncated"],
        json!(["path", "user_agent", "target"])
    );

    // No text of the event has a control character or a character that shows nothing.
    let mut texts = Vec::new();
    all_text(&serde_json::to_value(event).unwrap(), &mut texts);
    assert!(texts.len() > 20);
    for text in &texts {
        assert!(
            !text.chars().any(|character| character.is_control()
                || matches!(
                    character,
                    '\u{200B}' | '\u{202E}' | '\u{FEFF}' | '\u{E0041}'
                )),
            "{text:?}"
        );
        assert!(text.chars().count() <= 1024, "{}", text.chars().count());
    }
    // The event is small, although the request was large.
    assert!(serde_json::to_vec(event).unwrap().len() < 4096);
}

#[tokio::test(start_paused = true)]
async fn the_fingerprint_is_stable_for_one_client_and_differs_for_another() {
    let service = service(maze_config());
    let fingerprint_of = |request: &'static str| {
        let service = service.clone();
        async move {
            let raw = exchange(&service, peer(1), request.as_bytes()).await;
            assert_eq!(parse_response(&raw).status, 200);
            let events = events(&service, 1).await;
            events[0]
                .attribute_str("client_fingerprint")
                .unwrap()
                .to_owned()
        }
    };
    let base = fingerprint_of(
        "GET /docs/a HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: gzip, br\r\n\r\n",
    )
    .await;
    // The value is the public function of the request shape.
    assert_eq!(
        base,
        client_fingerprint(
            "HTTP/1.1",
            &["Host", "User-Agent", "Accept-Encoding"],
            "agent/1.0",
            "gzip, br"
        )
    );
    // The path, the address, and a header value that is not in the hash do not count.
    let same = fingerprint_of(
        "GET /docs/other?x=1 HTTP/1.1\r\nHost: other.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: gzip, br\r\n\r\n",
    )
    .await;
    assert_eq!(base, same);

    for different in [
        // A different header order.
        "GET /docs/a HTTP/1.1\r\nUser-Agent: agent/1.0\r\nHost: decoy.test\r\nAccept-Encoding: gzip, br\r\n\r\n",
        // A different case of a header name.
        "GET /docs/a HTTP/1.1\r\nhost: decoy.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: gzip, br\r\n\r\n",
        // A different user agent.
        "GET /docs/a HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: agent/2.0\r\nAccept-Encoding: gzip, br\r\n\r\n",
        // Different accepted encodings.
        "GET /docs/a HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: identity\r\n\r\n",
        // A different HTTP version.
        "GET /docs/a HTTP/1.0\r\nHost: decoy.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: gzip, br\r\n\r\n",
        // One more header.
        "GET /docs/a HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: agent/1.0\r\nAccept-Encoding: gzip, br\r\nAccept: */*\r\n\r\n",
    ] {
        assert_ne!(base, fingerprint_of(different).await, "{different:?}");
    }
}
