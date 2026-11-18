//! Tests of the tarpit persona: the pace, the hold limit, the byte limit, and the event.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use aegis_contracts::{EntityKind, EventClass, Outcome, Severity};
use aegis_decoy::{DecoyConfig, PersonaKind};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

const REQUEST: &[u8] =
    b"GET /admin/login?next=%2F HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: test-agent/1.0\r\n\r\n";

/// A tarpit that sends 4 bytes each second and holds a client for 10 seconds.
fn tarpit_config() -> DecoyConfig {
    let mut config = config(&[PersonaKind::Tarpit]);
    config.tarpit.chunk_bytes = 4;
    config.tarpit.interval = Duration::from_secs(1);
    config.limits.max_hold = Duration::from_secs(10);
    config
}

#[tokio::test(start_paused = true)]
async fn the_bytes_arrive_at_the_configured_pace_and_the_hold_ends_at_the_maximum() {
    let service = service(tarpit_config());
    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    client.write_all(REQUEST).await.unwrap();
    let timeline = read_timeline(&mut client, start).await;
    server.await.unwrap();

    // The head comes immediately. Then one chunk comes each second: nine chunks before
    // the limit. At the limit, the end of the page and the last chunk come.
    assert_eq!(timeline.len(), 11, "{timeline:?}");
    let (head_time, head) = &timeline[0];
    assert_eq!(*head_time, Duration::ZERO);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(head.ends_with(b"\r\n\r\n"));
    for (index, (time, bytes)) in timeline[1..10].iter().enumerate() {
        let second = u64::try_from(index).unwrap() + 1;
        assert_eq!(*time, Duration::from_secs(second), "chunk {index}");
        // One chunk frame with four data bytes.
        assert_eq!(bytes.len(), 9, "chunk {index}: {bytes:?}");
        assert!(bytes.starts_with(b"4\r\n") && bytes.ends_with(b"\r\n"));
    }
    let (end_time, end) = &timeline[10];
    assert_eq!(*end_time, Duration::from_secs(10));
    assert_eq!(end, b"15\r\n</p>\n</body>\n</html>\n\r\n0\r\n\r\n");

    // The full answer is valid HTTP with a chunked body.
    let raw: Vec<u8> = timeline
        .iter()
        .flat_map(|(_, bytes)| bytes.clone())
        .collect();
    let response = parse_response(&raw);
    assert_eq!(response.status, 200);
    assert_eq!(response.reason, "OK");
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(response.chunks.len(), 10);
    assert!(response.chunks[..9].iter().all(|chunk| chunk.len() == 4));
    let text = response.text();
    assert_eq!(text.len(), 36 + 21);
    assert!(
        text.starts_with("<!DOCTYPE html>\n<html lang=\"en\">\n<he"),
        "{text}"
    );
    assert!(text.ends_with("</p>\n</body>\n</html>\n"), "{text}");

    // One contact event holds the time and the byte counts.
    let events = events(&service, 1).await;
    let event = &events[0];
    assert_eq!(event.action, "decoy.contact");
    assert_eq!(event.class, EventClass::NetworkActivity);
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(event.severity, Severity::Medium);
    assert_eq!(event.source.connector, DECOY_ID);
    assert_eq!(event.actor.kind, EntityKind::IpAddress);
    assert_eq!(event.actor.ip, Some(peer(1).ip()));
    assert_eq!(event.actor.user_agent.as_deref(), Some("test-agent/1.0"));
    assert_eq!(event.attribute_str("decoy_id"), Some(DECOY_ID));
    assert_eq!(event.attribute_str("decoy_kind"), Some("tarpit"));
    assert_eq!(event.attribute_str("decoy_result"), Some("hold_limit"));
    assert_eq!(event.attribute_str("http_method"), Some("GET"));
    assert_eq!(event.attribute_str("http_path"), Some("/admin/login"));
    assert_eq!(number(event, "http_status"), 200);
    assert_eq!(number(event, "held_milliseconds"), 10_000);
    assert_eq!(
        number(event, "bytes_received"),
        u64::try_from(REQUEST.len()).unwrap()
    );
    assert_eq!(
        number(event, "bytes_sent"),
        u64::try_from(raw.len()).unwrap()
    );
    assert_eq!(event.attribute_str("client_fingerprint").unwrap().len(), 32);
    assert_eq!(untrusted(event)["target"], "/admin/login?next=%2F");
    assert_eq!(service.stats().active_connections, 0);
}

#[tokio::test(start_paused = true)]
async fn an_interval_that_does_not_divide_the_hold_still_ends_at_the_maximum() {
    let mut config = tarpit_config();
    config.tarpit.interval = Duration::from_secs(3);
    let service = service(config);
    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    client.write_all(REQUEST).await.unwrap();
    let timeline = read_timeline(&mut client, start).await;
    server.await.unwrap();
    let times: Vec<u64> = timeline.iter().map(|(time, _)| time.as_secs()).collect();
    assert_eq!(times, [0, 3, 6, 9, 10]);
    let raw: Vec<u8> = timeline
        .iter()
        .flat_map(|(_, bytes)| bytes.clone())
        .collect();
    assert_eq!(parse_response(&raw).chunks.len(), 4);
    let events = events(&service, 1).await;
    assert_eq!(number(&events[0], "held_milliseconds"), 10_000);
}

#[tokio::test(start_paused = true)]
async fn the_answer_ends_at_the_byte_limit_and_is_still_valid() {
    let mut config = tarpit_config();
    config.tarpit.chunk_bytes = 1024;
    config.tarpit.interval = Duration::from_millis(10);
    config.limits.max_hold = Duration::from_secs(3600);
    config.limits.max_response_bytes = 65_536;
    let service = service(config);
    let raw = exchange(&service, peer(1), REQUEST).await;

    assert!(raw.len() <= 65_536, "{}", raw.len());
    // One more chunk does not fit below the limit.
    assert!(raw.len() + 1024 > 65_536, "{}", raw.len());
    let response = parse_response(&raw);
    assert_eq!(response.status, 200);
    assert!(response.text().ends_with("</p>\n</body>\n</html>\n"));
    let data_chunks = response.chunks.len() - 1;
    assert!(
        response.chunks[..data_chunks]
            .iter()
            .all(|chunk| chunk.len() == 1024)
    );

    let events = events(&service, 1).await;
    assert_eq!(events[0].attribute_str("decoy_result"), Some("byte_limit"));
    assert_eq!(
        number(&events[0], "bytes_sent"),
        u64::try_from(raw.len()).unwrap()
    );
    // The hold ended at the byte limit, a long time before the hold limit.
    let held = number(&events[0], "held_milliseconds");
    assert_eq!(held, 10 * (u64::try_from(data_chunks).unwrap() + 1));
}

#[tokio::test(start_paused = true)]
async fn a_client_that_leaves_ends_the_hold_and_the_event_has_the_real_time() {
    let service = service(tarpit_config());
    let (mut client, server) = connect(&service, peer(1));
    client.write_all(REQUEST).await.unwrap();
    // Read the head and the chunks of the first two seconds, then leave.
    let mut buffer = [0_u8; 4096];
    let mut reads = 0;
    while reads < 3 {
        assert!(client.read(&mut buffer).await.unwrap() > 0);
        reads += 1;
    }
    drop(client);
    server.await.unwrap();

    let events = events(&service, 1).await;
    assert_eq!(
        events[0].attribute_str("decoy_result"),
        Some("client_closed")
    );
    // The write at the third second finds that the client is gone.
    assert_eq!(number(&events[0], "held_milliseconds"), 3000);
    assert_eq!(number(&events[0], "http_status"), 200);
    assert_eq!(service.stats().active_connections, 0);
}

#[tokio::test(start_paused = true)]
async fn an_http_1_0_client_gets_a_body_that_ends_at_the_close() {
    let service = service(tarpit_config());
    let raw = exchange(
        &service,
        peer(1),
        b"GET / HTTP/1.0\r\nUser-Agent: old-agent\r\n\r\n",
    )
    .await;
    let response = parse_response(&raw);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), None);
    assert_eq!(response.header("content-length"), None);
    // Nine pieces of four bytes with no chunk frame, and the end of the page.
    let text = response.text();
    assert_eq!(text.len(), 36 + 21);
    assert!(text.starts_with("<!DOCTYPE html>"));
    assert!(text.ends_with("</p>\n</body>\n</html>\n"));
    let events = events(&service, 1).await;
    assert_eq!(number(&events[0], "held_milliseconds"), 10_000);
    assert_eq!(untrusted(&events[0])["http_version"], "HTTP/1.0");
}

#[tokio::test(start_paused = true)]
async fn a_head_request_gets_only_the_status_line_and_the_headers() {
    let service = service(tarpit_config());
    let raw = exchange(
        &service,
        peer(1),
        b"HEAD /x HTTP/1.1\r\nHost: decoy.test\r\n\r\n",
    )
    .await;
    let (response, head_length) = parse_head(&raw);
    assert_eq!(response.status, 200);
    assert_eq!(head_length, raw.len(), "a HEAD answer has no body");
    let events = events(&service, 1).await;
    assert_eq!(events[0].attribute_str("http_method"), Some("HEAD"));
    assert_eq!(events[0].attribute_str("decoy_result"), Some("completed"));
}

#[tokio::test(start_paused = true)]
async fn the_tarpit_answers_each_method_and_each_path() {
    let service = service(tarpit_config());
    for (index, request) in [
        "POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\nuser=root",
        "DELETE /api/v9/users/1 HTTP/1.1\r\nHost: x\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET http://decoy.test/absolute HTTP/1.1\r\nHost: x\r\n\r\n",
    ]
    .iter()
    .enumerate()
    {
        let raw = exchange(&service, peer(1), request.as_bytes()).await;
        let response = parse_response(&raw);
        assert_eq!(response.status, 200, "request {index}");
        assert_eq!(response.chunks.len(), 10, "request {index}");
    }
    let events = events(&service, 4).await;
    let paths: Vec<&str> = events
        .iter()
        .map(|event| event.attribute_str("http_path").unwrap())
        .collect();
    assert_eq!(
        paths,
        ["/wp-login.php", "/api/v9/users/1", "*", "/absolute"]
    );
    assert!(
        events
            .iter()
            .all(|event| event.attribute_str("decoy_kind") == Some("tarpit"))
    );
    assert_eq!(number(&events[0], "bytes_received"), 68);
}

#[tokio::test]
async fn a_tcp_client_is_held_for_the_maximum_time() {
    let mut config = tarpit_config();
    config.tarpit.interval = Duration::from_millis(20);
    config.limits.max_hold = Duration::from_millis(200);
    let running = Running::start(config).await;

    let started = std::time::Instant::now();
    let raw = tcp_exchange(running.address, REQUEST).await;
    let elapsed = started.elapsed();
    // The clock is real here, so the test examines only the lower limit.
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    let response = parse_response(&raw);
    assert_eq!(response.status, 200);
    // Ten intervals fit in the hold: nine data chunks at most, and the end of the page.
    assert!(
        (1..=10).contains(&response.chunks.len()),
        "{}",
        response.chunks.len()
    );
    assert!(response.text().ends_with("</p>\n</body>\n</html>\n"));

    let events = events(&running.service, 1).await;
    let event = &events[0];
    assert_eq!(event.attribute_str("decoy_result"), Some("hold_limit"));
    assert!(number(event, "held_milliseconds") >= 200);
    assert_eq!(event.actor.ip, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(
        number(event, "bytes_sent"),
        u64::try_from(raw.len()).unwrap()
    );
    running.stop().await;
}
