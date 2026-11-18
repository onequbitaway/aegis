//! Tests of the hard limits: sizes, times, connection counts, and the memory bound.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::{Outcome, Severity, SourceConnector};
use aegis_decoy::{DecoyConfig, DecoyService, PersonaKind};
use common::*;
use futures::StreamExt;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

fn maze_config() -> DecoyConfig {
    let mut config = config(&[PersonaKind::Maze]);
    config.maze.delay = Duration::ZERO;
    config
}

/// A tarpit that holds each client for one hour, so a connection stays open in a test.
///
/// The tarpit finds that a client left when it writes the next bytes: after 5 seconds.
fn holding_config() -> DecoyConfig {
    let mut config = config(&[PersonaKind::Tarpit]);
    config.tarpit.interval = Duration::from_secs(5);
    config.limits.max_hold = Duration::from_secs(3600);
    config
}

/// Proves that the service still answers a correct request.
async fn assert_responsive(service: &DecoyService) {
    let page = get(service, peer(200), "/docs").await;
    assert_eq!(page.status, 200);
}

/// Opens a connection that the tarpit holds. Returns after the head of the answer came.
async fn hold(service: &DecoyService, from: std::net::SocketAddr) -> tokio::io::DuplexStream {
    let (mut client, _server) = connect(service, from);
    client.write_all(&get_request("/", "")).await.unwrap();
    let mut buffer = [0_u8; 1024];
    let count = client.read(&mut buffer).await.unwrap();
    assert!(buffer[..count].starts_with(b"HTTP/1.1 200 OK\r\n"));
    client
}

/// Opens a connection above a limit. The service closes it and sends no byte.
async fn assert_refused(service: &DecoyService, from: std::net::SocketAddr) {
    let (mut client, server) = connect(service, from);
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.unwrap();
    assert!(raw.is_empty(), "a refused connection gets no byte: {raw:?}");
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_request_head_above_the_size_limit_gets_431() {
    let mut config = maze_config();
    config.limits.max_header_bytes = 1024;
    let service = service(config);

    // A head of exactly the limit is accepted.
    let prefix = "GET /docs HTTP/1.1\r\nHost: decoy.test\r\nX-Fill: ";
    let fill = "a".repeat(1024 - prefix.len() - 4);
    let at_limit = format!("{prefix}{fill}\r\n\r\n");
    assert_eq!(at_limit.len(), 1024);
    let response = parse_response(&exchange(&service, peer(1), at_limit.as_bytes()).await);
    assert_eq!(response.status, 200);

    // One more byte is refused.
    let above = format!("{prefix}{fill}a\r\n\r\n");
    let start = Instant::now();
    let response = parse_response(&exchange(&service, peer(1), above.as_bytes()).await);
    assert_eq!(response.status, 431);
    assert_eq!(response.text(), "431 Request Header Fields Too Large\n");
    assert_eq!(start.elapsed(), Duration::ZERO, "the refusal is immediate");

    // A head with no end is refused at the limit, with no wait for more data.
    let endless = vec![b'x'; 10_000];
    let response = parse_response(&exchange(&service, peer(1), &endless).await);
    assert_eq!(response.status, 431);

    let events = events(&service, 3).await;
    assert_eq!(events[0].attribute_str("decoy_result"), Some("completed"));
    for refused in &events[1..] {
        assert_eq!(refused.action, "decoy.contact");
        assert_eq!(
            refused.attribute_str("decoy_result"),
            Some("header_too_large")
        );
        assert_eq!(refused.attribute_str("decoy_kind"), Some("listener"));
        assert_eq!(refused.outcome, Outcome::Failure);
        assert_eq!(number(refused, "http_status"), 431);
        // The decoy did not read the request, so the event has no request data.
        assert!(!refused.attributes.contains_key("http_path"));
    }
    // The count includes the bytes that the decoy discarded before the close.
    assert_eq!(number(&events[1], "bytes_received"), 1025);
    assert_eq!(number(&events[2], "bytes_received"), 10_000);
    // The buffer of a connection never held more than the limit and the small answer.
    assert!(service.stats().peak_tracked_bytes < 4 * 1024);
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn a_client_that_floods_after_a_refusal_is_read_only_up_to_a_limit() {
    let mut config = maze_config();
    config.limits.max_header_bytes = 1024;
    let service = service(config);
    // One megabyte with no end of the headers.
    let flood = vec![b'x'; 1024 * 1024];
    let start = Instant::now();
    let response = parse_response(&exchange(&service, peer(1), &flood).await);
    assert_eq!(response.status, 431);
    // The decoy does not wait for a client that still sends.
    assert_eq!(start.elapsed(), Duration::ZERO);

    let events = events(&service, 1).await;
    // The head limit, and then 64 KiB that the decoy discards before it closes.
    assert_eq!(number(&events[0], "bytes_received"), 1024 + 64 * 1024);
    assert!(service.stats().peak_tracked_bytes < 4 * 1024);
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn more_headers_than_the_limit_gets_431() {
    let mut config = maze_config();
    config.limits.max_headers = 4;
    let service = service(config);
    let four = "A: 1\r\nB: 2\r\nC: 3\r\n";
    assert_eq!(get_with(&service, peer(1), "/docs", four).await.status, 200);
    let five = "A: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n";
    assert_eq!(get_with(&service, peer(1), "/docs", five).await.status, 431);
    let events = events(&service, 2).await;
    assert_eq!(
        events[1].attribute_str("decoy_result"),
        Some("header_too_large")
    );
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn a_body_above_the_size_limit_gets_413_before_the_decoy_reads_it() {
    let mut config = config(&[PersonaKind::ModelApi]);
    config.limits.max_body_bytes = 2048;
    let service = service(config);

    // A body of exactly the limit is read.
    let frame = json!({"messages": [{"role": "user", "content": ""}]}).to_string();
    let fill = "a".repeat(2048 - frame.len());
    let body = json!({"messages": [{"role": "user", "content": fill}]}).to_string();
    assert_eq!(body.len(), 2048);
    let request = post_request(
        "/v1/chat/completions",
        Some("wrong-key-EXAMPLE-0123456789"),
        &body,
    );
    assert_eq!(
        parse_response(&exchange(&service, peer(1), &request).await).status,
        401
    );

    // The client only declares a large body and sends none of it.
    let head =
        "POST /v1/chat/completions HTTP/1.1\r\nHost: decoy.test\r\nContent-Length: 2049\r\n\r\n";
    let start = Instant::now();
    let response = parse_response(&exchange(&service, peer(1), head.as_bytes()).await);
    assert_eq!(response.status, 413);
    assert_eq!(response.text(), "413 Content Too Large\n");
    assert_eq!(
        start.elapsed(),
        Duration::ZERO,
        "the decoy does not wait for the body"
    );

    let huge = "POST /v1/models HTTP/1.1\r\nContent-Length: 99999999999999999999999999\r\n\r\n";
    let response = parse_response(&exchange(&service, peer(1), huge.as_bytes()).await);
    assert_eq!(response.status, 413);

    let events = events(&service, 3).await;
    assert_eq!(
        number(&events[0], "bytes_received"),
        u64::try_from(request.len()).unwrap()
    );
    for refused in &events[1..] {
        assert_eq!(
            refused.attribute_str("decoy_result"),
            Some("body_too_large")
        );
        assert_eq!(number(refused, "http_status"), 413);
    }
    assert_eq!(
        number(&events[1], "bytes_received"),
        u64::try_from(head.len()).unwrap()
    );
    assert_eq!(service.stats().tracked_bytes, events_bytes_bound(&service));
}

/// The decoy keeps only queued events after all connections ended.
fn events_bytes_bound(service: &DecoyService) -> usize {
    let stats = service.stats();
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.events_queued, 0, "the test read all events");
    0
}

#[tokio::test(start_paused = true)]
async fn a_request_that_is_not_valid_gets_a_clean_refusal() {
    let service = service(maze_config());
    for (request, status, reason) in [
        ("GET /docs\r\n\r\n", 400, "bad_request"),
        ("NOT A REQUEST\r\n\r\n", 400, "bad_request"),
        (
            "GET /docs HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
            400,
            "bad_request",
        ),
        (
            "POST /docs HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
            400,
            "bad_request",
        ),
        (
            "POST /docs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            411,
            "bad_request",
        ),
        (
            "POST /docs HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
            411,
            "bad_request",
        ),
    ] {
        let response = parse_response(&exchange(&service, peer(1), request.as_bytes()).await);
        assert_eq!(response.status, status, "{request:?}");
        let events = events(&service, 1).await;
        assert_eq!(
            events[0].attribute_str("decoy_result"),
            Some(reason),
            "{request:?}"
        );
        assert_eq!(number(&events[0], "http_status"), u64::from(status));
        assert_eq!(events[0].outcome, Outcome::Failure);
    }
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn a_silent_client_is_cut_off_at_the_header_time_limit() {
    let mut config = maze_config();
    config.limits.header_read_timeout = Duration::from_secs(7);
    let service = service(config);
    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    // The client sends nothing and only waits.
    let timeline = read_timeline(&mut client, start).await;
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].0, Duration::from_secs(7));
    let response = parse_response(&timeline[0].1);
    assert_eq!(response.status, 408);
    drop(client);
    server.await.unwrap();

    let events = events(&service, 1).await;
    let event = &events[0];
    assert_eq!(event.attribute_str("decoy_result"), Some("read_timeout"));
    assert_eq!(event.attribute_str("decoy_kind"), Some("listener"));
    assert_eq!(event.severity, Severity::Low);
    assert_eq!(number(event, "held_milliseconds"), 7000);
    assert_eq!(number(event, "bytes_received"), 0);
    assert!(!event.attributes.contains_key("http_method"));
    assert_eq!(event.raw, None);
    assert_eq!(service.stats().active_connections, 0);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_sends_one_byte_at_a_time_is_cut_off_at_the_same_limit() {
    let mut config = maze_config();
    config.limits.header_read_timeout = Duration::from_secs(7);
    let service = service(config);
    let (client, server) = connect(&service, peer(1));
    let (mut reader, mut writer) = tokio::io::split(client);
    let start = Instant::now();
    // One byte each second never completes the request, and it never stops. The bytes
    // go at 0.5, 1.5, ... seconds, so no byte goes at the instant of the limit.
    let slow = tokio::spawn(async move {
        let request = get_request(
            "/docs",
            "X-Fill: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        for byte in request {
            if writer.write_all(&[byte]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw).await.unwrap();
    // The limit is for the full head. A new byte does not start the time again.
    assert_eq!(start.elapsed(), Duration::from_secs(7));
    assert_eq!(parse_response(&raw).status, 408);
    drop(reader);
    slow.abort();
    let _ = slow.await;
    server.await.unwrap();

    let events = events(&service, 1).await;
    assert_eq!(
        events[0].attribute_str("decoy_result"),
        Some("read_timeout")
    );
    assert_eq!(number(&events[0], "bytes_received"), 7);
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn a_client_that_does_not_send_the_declared_body_is_cut_off() {
    let mut config = config(&[PersonaKind::ModelApi]);
    config.limits.header_read_timeout = Duration::from_secs(60);
    config.limits.body_read_timeout = Duration::from_secs(4);
    let service = service(config);
    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    client
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"mess")
        .await
        .unwrap();
    let timeline = read_timeline(&mut client, start).await;
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].0, Duration::from_secs(4));
    assert_eq!(parse_response(&timeline[0].1).status, 408);
    drop(client);
    server.await.unwrap();

    let events = events(&service, 1).await;
    assert_eq!(
        events[0].attribute_str("decoy_result"),
        Some("read_timeout")
    );
    assert_eq!(events[0].attribute_str("http_method"), Some("POST"));
    assert_eq!(number(&events[0], "held_milliseconds"), 4000);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_does_not_read_is_cut_off_at_the_write_time_limit() {
    let mut config = maze_config();
    config.limits.write_timeout = Duration::from_secs(3);
    let service = service(config);
    // The stream holds 64 bytes only, and the client reads nothing.
    let (mut client, server) = connect_with_buffer(&service, peer(1), 64);
    let start = Instant::now();
    client
        .write_all(b"GET /docs HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(3));

    let events = events(&service, 1).await;
    let event = &events[0];
    assert_eq!(event.attribute_str("decoy_result"), Some("write_timeout"));
    assert_eq!(number(event, "held_milliseconds"), 3000);
    // The decoy sent only what the stream accepted.
    assert_eq!(number(event, "bytes_sent"), 64);
    assert_eq!(service.stats().active_connections, 0);
    drop(client);
    assert_responsive(&service).await;
}

#[tokio::test(start_paused = true)]
async fn a_slow_reader_cannot_hold_a_connection_past_the_hold_limit() {
    let mut config = config(&[PersonaKind::Tarpit]);
    config.tarpit.chunk_bytes = 8;
    config.tarpit.interval = Duration::from_secs(1);
    config.limits.max_hold = Duration::from_secs(10);
    config.limits.write_timeout = Duration::from_secs(3);
    let service = service(config);
    // The stream holds 16 bytes. The client reads the head fast. Then it reads 16 bytes
    // each 2.9 seconds, so each write of the decoy ends a moment before its time limit.
    let (mut client, server) = connect_with_buffer(&service, peer(1), 16);
    let start = Instant::now();
    client.write_all(&get_request("/", "")).await.unwrap();
    let reader = tokio::spawn(async move {
        let mut buffer = [0_u8; 16];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let count = client.read(&mut buffer).await.unwrap();
            assert!(count > 0, "the head is complete before the end");
            head.extend_from_slice(&buffer[..count]);
        }
        loop {
            tokio::time::sleep(Duration::from_millis(2900)).await;
            match client.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });
    server.await.unwrap();
    // The decoy ended the connection at the hold limit and one write time limit. Without
    // the limit, nine slow writes of 2.9 seconds keep the connection for 26 seconds.
    assert_eq!(start.elapsed(), Duration::from_secs(13));
    reader.await.unwrap();

    let events = events(&service, 1).await;
    assert_eq!(
        events[0].attribute_str("decoy_result"),
        Some("write_timeout")
    );
    assert_eq!(number(&events[0], "held_milliseconds"), 13_000);
    assert_eq!(service.stats().active_connections, 0);
}

#[tokio::test(start_paused = true)]
async fn the_hold_limit_cuts_off_a_client_in_each_phase() {
    // The hold limit is shorter than each other time limit.
    let mut config = maze_config();
    config.limits.max_hold = Duration::from_secs(2);
    config.limits.header_read_timeout = Duration::from_secs(60);
    config.limits.body_read_timeout = Duration::from_secs(60);
    let service = service(config);

    let start = Instant::now();
    let silent = exchange(&service, peer(1), b"").await;
    assert_eq!(start.elapsed(), Duration::from_secs(2));
    assert_eq!(parse_response(&silent).status, 408);

    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    client
        .write_all(b"POST /docs HTTP/1.1\r\nContent-Length: 10\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(2));
    assert_eq!(parse_response(&raw).status, 408);
    drop(client);
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn one_address_gets_only_the_configured_number_of_connections() {
    let mut config = holding_config();
    config.limits.max_connections_per_address = 2;
    let service = service(config);

    let first = hold(&service, peer(1)).await;
    let _second = hold(&service, peer(1)).await;
    // The third connection of the address is closed immediately, with no byte.
    let start = Instant::now();
    assert_refused(&service, peer(1)).await;
    assert_eq!(start.elapsed(), Duration::ZERO);
    // A different port of the same address is the same address.
    let mut other_port = peer(1);
    other_port.set_port(50_000);
    assert_refused(&service, other_port).await;
    // A different address still gets in.
    let _other = hold(&service, peer(2)).await;

    let stats = service.stats();
    assert_eq!(stats.connections_accepted, 3);
    assert_eq!(stats.connections_refused, 2);
    assert_eq!(stats.active_connections, 3);

    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    assert_eq!(batch.events.len(), 2);
    for refused in &batch.events {
        assert_eq!(refused.action, "decoy.contact");
        assert_eq!(
            refused.attribute_str("decoy_result"),
            Some("refused_address_limit")
        );
        assert_eq!(refused.actor.ip, Some(peer(1).ip()));
        assert_eq!(refused.outcome, Outcome::Failure);
        assert_eq!(number(refused, "held_milliseconds"), 0);
    }

    // When one connection of the address ends, the address gets in again.
    drop(first);
    let ended = next_batch(&mut stream).await;
    assert_eq!(ended.events.len(), 1);
    assert_eq!(
        ended.events[0].attribute_str("decoy_result"),
        Some("client_closed")
    );
    let _again = hold(&service, peer(1)).await;
    assert_eq!(service.stats().active_connections, 3);
}

#[tokio::test(start_paused = true)]
async fn the_decoy_gets_only_the_configured_number_of_connections() {
    let mut config = holding_config();
    config.limits.max_connections = 3;
    config.limits.max_connections_per_address = 3;
    let service = service(config);

    let mut held = Vec::new();
    for last in 1..=3 {
        held.push(hold(&service, peer(last)).await);
    }
    assert_refused(&service, peer(4)).await;
    assert_refused(&service, peer(5)).await;
    let stats = service.stats();
    assert_eq!(stats.active_connections, 3);
    assert_eq!(stats.peak_connections, 3);
    assert_eq!(stats.connections_refused, 2);

    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    assert_eq!(batch.events.len(), 2);
    for refused in &batch.events {
        assert_eq!(
            refused.attribute_str("decoy_result"),
            Some("refused_connection_limit")
        );
        assert_eq!(refused.severity, Severity::Low);
    }

    // A free place lets a new client in.
    held.pop();
    let ended = next_batch(&mut stream).await;
    assert_eq!(
        ended.events[0].attribute_str("decoy_result"),
        Some("client_closed")
    );
    held.push(hold(&service, peer(4)).await);
    assert_eq!(service.stats().active_connections, 3);
    assert_eq!(service.stats().peak_connections, 3);
}

#[tokio::test(start_paused = true)]
async fn a_flood_of_refused_connections_cannot_fill_the_event_queue() {
    let mut config = holding_config();
    config.limits.max_connections = 1;
    config.limits.max_connections_per_address = 1;
    config.events.max_queued = 8;
    let service = service(config);
    let held = hold(&service, peer(1)).await;
    // 100 connections above the limit. Their events get only half of the queue.
    for last in 2..102 {
        assert_refused(&service, peer(last)).await;
    }
    let stats = service.stats();
    assert_eq!(stats.connections_refused, 100);
    assert_eq!(stats.events_queued, 4);
    assert_eq!(stats.events_dropped, 96);

    // The contact of the held client had a request, so it still has space in the queue.
    drop(held);
    let mut stream = service.stream(None).await.unwrap();
    let mut results = Vec::new();
    while results.len() < 6 {
        let batch = next_batch(&mut stream).await;
        results.extend(batch.events.iter().map(|event| {
            event
                .attribute_str("decoy_result")
                .map_or_else(|| event.action.clone(), str::to_owned)
        }));
    }
    assert_eq!(
        results,
        [
            "refused_connection_limit",
            "refused_connection_limit",
            "refused_connection_limit",
            "refused_connection_limit",
            "decoy.events_dropped",
            "client_closed",
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_flood_of_empty_connections_gets_only_half_of_the_event_queue() {
    let mut config = maze_config();
    config.events.max_queued = 8;
    let service = service(config);
    // 30 clients connect and leave with no request.
    for last in 0..30 {
        let (client, server) = connect(&service, peer(last));
        drop(client);
        server.await.unwrap();
    }
    let stats = service.stats();
    assert_eq!(stats.connections_accepted, 30);
    assert_eq!(stats.requests, 0);
    assert_eq!(stats.events_queued, 4);
    assert_eq!(stats.events_dropped, 26);
    // A contact with a request still has a place.
    assert_responsive(&service).await;
    assert_eq!(service.stats().events_queued, 5);

    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    let results: Vec<&str> = batch
        .events
        .iter()
        .filter_map(|event| event.attribute_str("decoy_result"))
        .collect();
    assert_eq!(
        results,
        [
            "no_request",
            "no_request",
            "no_request",
            "no_request",
            "completed"
        ]
    );
    assert_eq!(batch.events[0].severity, Severity::Low);
    assert_eq!(number(&batch.events[0], "bytes_received"), 0);
    assert_eq!(batch.events[5].action, "decoy.events_dropped");
    assert_eq!(number(&batch.events[5], "dropped_events"), 26);
}

#[tokio::test(start_paused = true)]
async fn five_hundred_parallel_clients_do_not_exceed_the_memory_bound() {
    const CLIENTS: usize = 500;
    const ADMITTED: usize = 32;
    let mut config = config(&[PersonaKind::ModelApi]);
    config.limits.max_connections = ADMITTED;
    config.limits.max_connections_per_address = 2;
    config.limits.max_header_bytes = 2048;
    config.limits.max_body_bytes = 4096;
    config.events.max_queued_bytes = 64 * 1024;
    config.model_api.max_prompt_chars = 512;
    config.model_api.interval = Duration::from_millis(100);
    config.model_api.answer_words = 5;
    let service = service(config);
    // The bound comes only from the configuration.
    let bound = service.memory_bound();
    assert_eq!(bound, 32 * (2 * 2048 + 4096 + 65_536) + 64 * 1024);

    // Each client sends the head and a part of a large body, and then waits for all
    // other clients. Thus the decoy holds the buffers of all admitted clients at one time.
    let body = json!({"messages": [{"role": "user", "content": "p".repeat(4000)}]}).to_string();
    let request = Arc::new(post_request("/v1/chat/completions", Some(DECOY_KEY), &body));
    let split = request.len() - 1000;
    let all_waiting = Arc::new(tokio::sync::Barrier::new(CLIENTS));
    let mut clients = Vec::new();
    for index in 0..CLIENTS {
        let service = service.clone();
        let request = Arc::clone(&request);
        let all_waiting = Arc::clone(&all_waiting);
        clients.push(tokio::spawn(async move {
            // 250 addresses with two clients each.
            let address = peer(u8::try_from(index / 2).unwrap());
            let (mut client, server) = connect(&service, address);
            let first_part = client.write_all(&request[..split]).await;
            all_waiting.wait().await;
            let second_part = client.write_all(&request[split..]).await;
            let mut raw = Vec::new();
            client.read_to_end(&mut raw).await.unwrap();
            drop(client);
            server.await.unwrap();
            (raw, first_part.is_ok() && second_part.is_ok())
        }));
    }
    let mut served = 0;
    let mut refused = 0;
    for client in clients {
        let (raw, _) = client.await.unwrap();
        if raw.is_empty() {
            // A clean refusal: the decoy closed the connection and sent no byte.
            refused += 1;
        } else {
            let response = parse_response(&raw);
            assert_eq!(response.status, 200);
            assert_eq!(response.json()["object"], "chat.completion");
            served += 1;
        }
    }
    assert_eq!(served, ADMITTED);
    assert_eq!(refused, CLIENTS - ADMITTED);

    let stats = service.stats();
    assert_eq!(stats.connections_accepted, 32);
    assert_eq!(stats.connections_refused, 468);
    assert_eq!(stats.peak_connections, ADMITTED);
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.honeytoken_trips, 32);
    // The decoy held real buffers for the admitted clients, and it stayed below the bound.
    assert!(
        stats.peak_tracked_bytes > ADMITTED * 4096,
        "{}",
        stats.peak_tracked_bytes
    );
    assert!(
        stats.peak_tracked_bytes <= bound,
        "{} > {bound}",
        stats.peak_tracked_bytes
    );
    // 500 unlimited clients need more than the bound. Thus the limit did the work.
    assert!(CLIENTS * (2048 + 4096) > bound);
    // The queue of recorded data stayed below its own limit, and the decoy counted
    // each event that did not fit.
    assert!(stats.tracked_bytes <= 64 * 1024, "{}", stats.tracked_bytes);
    assert!(stats.events_dropped > 0);

    // The report of the dropped events comes with the next read.
    let mut stream = service.stream(None).await.unwrap();
    let batch = next_batch(&mut stream).await;
    let report = batch.events.last().unwrap();
    assert_eq!(report.action, "decoy.events_dropped");
    assert_eq!(number(report, "dropped_events"), stats.events_dropped);
    assert_eq!(number(report, "dropped_events_total"), stats.events_dropped);

    // The service still answers.
    let request = post_request("/v1/chat/completions", Some(DECOY_KEY), &body);
    let response = parse_response(&exchange(&service, peer(250), &request).await);
    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn the_listener_refuses_connections_above_the_limit_and_stays_responsive() {
    let mut config = holding_config();
    config.limits.max_connections = 4;
    config.limits.max_connections_per_address = 4;
    config.tarpit.interval = Duration::from_millis(10);
    let running = Running::start(config).await;
    let mut stream = running.service.stream(None).await.unwrap();

    // Four clients that the tarpit holds. All come from the loopback address.
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut client = tokio::net::TcpStream::connect(running.address)
            .await
            .unwrap();
        client.write_all(&get_request("/", "")).await.unwrap();
        let mut buffer = [0_u8; 1024];
        let count = client.read(&mut buffer).await.unwrap();
        assert!(buffer[..count].starts_with(b"HTTP/1.1 200 OK\r\n"));
        held.push(client);
    }
    assert_eq!(running.service.stats().active_connections, 4);

    // Twenty more clients are closed with no answer.
    for _ in 0..20 {
        let raw = tcp_exchange(running.address, &get_request("/", "")).await;
        assert!(raw.is_empty(), "{raw:?}");
    }
    let stats = running.service.stats();
    assert_eq!(stats.connections_refused, 20);
    assert_eq!(stats.peak_connections, 4);

    // One held client leaves. The contact event shows that its place is free.
    drop(held.pop());
    let ended = loop {
        let batch = tokio::time::timeout(PATIENCE, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Some(event) = batch
            .events
            .into_iter()
            .find(|event| event.attribute_str("decoy_result") == Some("client_closed"))
        {
            break event;
        }
    };
    assert_eq!(ended.attribute_str("decoy_kind"), Some("tarpit"));
    let mut client = tokio::net::TcpStream::connect(running.address)
        .await
        .unwrap();
    client.write_all(&get_request("/", "")).await.unwrap();
    let mut buffer = [0_u8; 1024];
    let count = client.read(&mut buffer).await.unwrap();
    assert!(buffer[..count].starts_with(b"HTTP/1.1 200 OK\r\n"));

    // A stop closes each held client and records its contact.
    let service = running.service.clone();
    running.stop().await;
    assert_eq!(service.stats().active_connections, 0);
    let mut interrupted = 0;
    while let Some(batch) = tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("the stream ends in time")
    {
        interrupted += batch
            .unwrap()
            .events
            .iter()
            .filter(|event| event.attribute_str("decoy_result") == Some("interrupted"))
            .count();
    }
    assert_eq!(interrupted, 4);
}
