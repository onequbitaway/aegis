//! Shared helpers for the integration tests of the decoy.
//!
//! Most tests give the service one end of an in-memory stream. Thus the tests need no
//! network, and the paused Tokio clock drives each wait. Some tests use a listener on the
//! loopback address to prove the real accept path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use aegis_contracts::source::{EventBatch, EventStream};
use aegis_contracts::{Event, SourceConnector};
use aegis_decoy::{DecoyConfig, DecoyKeyConfig, DecoyService, PersonaKind};
use futures::StreamExt;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// The name of the variable that holds the seed in the tests.
pub const SEED_ENV: &str = "AEGIS_DECOY_SEED";
/// Two example seeds. They are not secrets.
pub const SEED_A: &str = "example-seed-a-0123456789abcdef0123456789";
pub const SEED_B: &str = "example-seed-b-0123456789abcdef0123456789";
/// The name of the variable that holds the decoy key in the tests.
pub const KEY_ENV: &str = "AEGIS_DECOY_MODEL_KEY";
/// An example decoy key. It gives no access to any system.
pub const DECOY_KEY: &str = "decoy-key-EXAMPLE-0123456789abcdefABCDEF";
/// The honeytoken identifier of the example decoy key.
pub const KEY_ID: &str = "ht-decoy-model-key";
/// The name of the decoy in the tests.
pub const DECOY_ID: &str = "decoy-test";
/// The longest time that a test waits for the service. It is a guard, not a delay.
pub const PATIENCE: Duration = Duration::from_secs(60);

/// Returns the function that reads the test environment with the seed `seed`.
pub fn env(seed: &'static str) -> impl Fn(&str) -> Option<String> {
    move |name| match name {
        SEED_ENV => Some(seed.to_owned()),
        KEY_ENV => Some(DECOY_KEY.to_owned()),
        _ => None,
    }
}

/// Makes a configuration for the loopback address with one planted decoy key.
pub fn config(personas: &[PersonaKind]) -> DecoyConfig {
    let mut config = DecoyConfig::new(
        DECOY_ID,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        personas.iter().copied(),
        SEED_ENV,
    );
    config.model_api.keys = vec![DecoyKeyConfig::new(KEY_ID, KEY_ENV)];
    config
}

/// Makes a service with the seed A and no listener.
pub fn service(config: DecoyConfig) -> DecoyService {
    DecoyService::with_env(config, env(SEED_A)).unwrap()
}

/// Returns an example client address. The tests send no data to it.
pub fn peer(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 40_000)
}

/// Gives one end of an in-memory stream to the service, as a connection from `peer`.
///
/// Returns the client end and the task of the service.
pub fn connect(service: &DecoyService, peer: SocketAddr) -> (DuplexStream, JoinHandle<()>) {
    connect_with_buffer(service, peer, 256 * 1024)
}

/// As [`connect`], with a stream that holds `buffer` bytes in each direction.
pub fn connect_with_buffer(
    service: &DecoyService,
    peer: SocketAddr,
    buffer: usize,
) -> (DuplexStream, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(buffer);
    let service = service.clone();
    let task = tokio::spawn(async move { service.serve_connection(server, peer).await });
    (client, task)
}

/// Sends `request` from `peer` and returns all bytes of the answer.
pub async fn exchange(service: &DecoyService, peer: SocketAddr, request: &[u8]) -> Vec<u8> {
    let (mut client, server) = connect(service, peer);
    // The service can close before it reads all bytes. Then the write fails, and the
    // answer still tells the result.
    let _ = client.write_all(request).await;
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.unwrap();
    drop(client);
    server.await.unwrap();
    raw
}

/// Makes a `GET` request for `target` with more header lines.
pub fn get_request(target: &str, headers: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: decoy.test\r\n{headers}\r\n").into_bytes()
}

/// Sends a `GET` request from `peer` and returns the parsed answer.
pub async fn get(service: &DecoyService, peer: SocketAddr, target: &str) -> Response {
    get_with(service, peer, target, "User-Agent: test-agent/1.0\r\n").await
}

/// As [`get`], with the header lines `headers`.
pub async fn get_with(
    service: &DecoyService,
    peer: SocketAddr,
    target: &str,
    headers: &str,
) -> Response {
    parse_response(&exchange(service, peer, &get_request(target, headers)).await)
}

/// Makes a `POST` request with a JSON body and the bearer token `key`.
pub fn post_request(target: &str, key: Option<&str>, body: &str) -> Vec<u8> {
    let authorization = key.map_or(String::new(), |key| {
        format!("Authorization: Bearer {key}\r\n")
    });
    format!(
        "POST {target} HTTP/1.1\r\nHost: decoy.test\r\nUser-Agent: test-agent/1.0\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Reads the answer until the service closes. Returns each read with its arrival time.
///
/// The time is the time of the Tokio clock after `start`. With a paused clock, the value
/// is exact.
pub async fn read_timeline(client: &mut DuplexStream, start: Instant) -> Vec<(Duration, Vec<u8>)> {
    let mut timeline = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = client.read(&mut buffer).await.unwrap();
        if count == 0 {
            return timeline;
        }
        timeline.push((start.elapsed(), buffer[..count].to_vec()));
    }
}

/// One HTTP response that the strict test parser accepted.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// The body, with the chunk frames removed.
    pub body: Vec<u8>,
    /// The data of each chunk, if the body is chunked.
    pub chunks: Vec<Vec<u8>>,
    /// The number of bytes of the full response on the wire.
    pub wire_length: usize,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(found, _)| found.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).expect("the body is UTF-8")
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("the body is JSON")
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reads the status line and the headers. Returns them and the number of bytes used.
///
/// The function fails the test if the bytes are not a valid response head, or if the
/// head breaks a rule that each decoy response obeys.
pub fn parse_head(raw: &[u8]) -> (Response, usize) {
    let mut slots = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut slots);
    let length = match parsed.parse(raw).expect("a valid response head") {
        httparse::Status::Complete(length) => length,
        httparse::Status::Partial => panic!("the response head is not complete: {raw:?}"),
    };
    assert_eq!(parsed.version, Some(1), "the response is HTTP/1.1");
    let headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|header| {
            (
                header.name.to_owned(),
                String::from_utf8(header.value.to_vec()).expect("a header value is UTF-8"),
            )
        })
        .collect();
    let response = Response {
        status: parsed.code.expect("a status code"),
        reason: parsed.reason.expect("a reason phrase").to_owned(),
        headers,
        body: Vec::new(),
        chunks: Vec::new(),
        wire_length: raw.len(),
    };
    // Rules for each response of the decoy.
    assert_eq!(response.header("connection"), Some("close"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(
        response.header("content-encoding"),
        None,
        "the decoy never compresses a body"
    );
    assert!(response.header("date").is_some());
    assert!(response.header("content-type").is_some());
    let has_length = response.header("content-length").is_some();
    let has_encoding = response.header("transfer-encoding").is_some();
    assert!(
        !(has_length && has_encoding),
        "a response has one body framing"
    );
    (response, length)
}

/// Reads one full response. The function fails the test if the response is not valid.
///
/// A body with `Content-Length` must have this length exactly. A chunked body must have
/// valid chunks, the last chunk, and nothing after it.
pub fn parse_response(raw: &[u8]) -> Response {
    let (mut response, head_length) = parse_head(raw);
    let rest = &raw[head_length..];
    if let Some(encoding) = response.header("transfer-encoding") {
        assert_eq!(encoding, "chunked");
        let (body, chunks) = decode_chunked(rest);
        response.body = body;
        response.chunks = chunks;
    } else if let Some(length) = response.header("content-length") {
        let length: usize = length.parse().expect("a content length");
        assert_eq!(rest.len(), length, "the body has the declared length");
        response.body = rest.to_vec();
    } else {
        response.body = rest.to_vec();
    }
    response
}

/// Removes the chunk frames. The function fails the test for each framing fault.
pub fn decode_chunked(mut rest: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut body = Vec::new();
    let mut chunks = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n").expect("a chunk size line");
        let size_text = std::str::from_utf8(&rest[..line_end]).expect("a chunk size is ASCII");
        assert!(
            !size_text.is_empty() && size_text.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "a chunk size is hexadecimal: {size_text:?}"
        );
        let size = usize::from_str_radix(size_text, 16).expect("a chunk size");
        rest = &rest[line_end + 2..];
        if size == 0 {
            assert_eq!(rest, b"\r\n", "nothing follows the last chunk");
            return (body, chunks);
        }
        assert!(rest.len() >= size + 2, "the chunk data is complete");
        assert_eq!(&rest[size..size + 2], b"\r\n", "a chunk ends with CRLF");
        body.extend_from_slice(&rest[..size]);
        chunks.push(rest[..size].to_vec());
        rest = &rest[size + 2..];
    }
}

/// Reads the next batch of a stream. Fails the test if no batch arrives.
///
/// The time limit is a guard against a wait with no end. With a paused clock, it ends
/// the test immediately when nothing more can occur.
pub async fn next_batch(stream: &mut EventStream) -> EventBatch {
    tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("a batch arrives in time")
        .expect("the event stream is open")
        .unwrap()
}

/// Reads the end of a stream. Fails the test if a batch arrives or nothing occurs.
pub async fn assert_stream_end(stream: &mut EventStream) {
    let next = tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("the stream ends in time");
    assert!(next.is_none(), "the stream has one more batch: {next:?}");
}

/// Reads `count` events from the service. Fails the test if they do not arrive.
///
/// The function also fails the test if a batch brings more events than expected.
pub async fn events(service: &DecoyService, count: usize) -> Vec<Event> {
    let mut stream = service.stream(None).await.unwrap();
    let mut events = Vec::new();
    while events.len() < count {
        let batch = next_batch(&mut stream).await;
        assert_eq!(batch.next_cursor, None);
        events.extend(batch.events);
    }
    assert_eq!(events.len(), count, "{events:#?}");
    events
}

/// Returns the one event with the action `action`. Fails the test for zero or two.
pub fn only<'a>(events: &'a [Event], action: &str) -> &'a Event {
    let found: Vec<&Event> = events
        .iter()
        .filter(|event| event.action == action)
        .collect();
    assert_eq!(found.len(), 1, "one {action} event in {events:#?}");
    found[0]
}

/// Returns a number attribute of an event.
pub fn number(event: &Event, key: &str) -> u64 {
    event
        .attributes
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("the attribute {key} is a number in {event:#?}"))
}

/// Returns the text of the client that the event holds as untrusted data.
pub fn untrusted(event: &Event) -> &serde_json::Map<String, Value> {
    event
        .raw
        .as_ref()
        .and_then(|raw| raw.get(aegis_decoy::UNTRUSTED_CLIENT_DATA))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("the event has untrusted client data: {event:#?}"))
}

/// A decoy that listens on the loopback address.
pub struct Running {
    pub address: SocketAddr,
    pub service: DecoyService,
    pub cancel: CancellationToken,
    pub server: JoinHandle<()>,
}

impl Running {
    /// Binds the decoy to a free loopback port and starts it.
    pub async fn start(config: DecoyConfig) -> Self {
        let bound = DecoyService::bind_with_env(config, env(SEED_A))
            .await
            .unwrap();
        let address = bound.local_addr();
        let service = bound.service();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(bound.serve(cancel.clone()));
        Self {
            address,
            service,
            cancel,
            server,
        }
    }

    /// Stops the decoy and waits for its task.
    pub async fn stop(self) {
        self.cancel.cancel();
        self.server.await.unwrap();
    }
}

/// Sends `request` over TCP and returns all bytes of the answer.
///
/// A connection that the decoy resets gives the bytes that arrived before the reset.
pub async fn tcp_exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        // A refused connection can fail the write. The read tells the result.
        let _ = stream.write_all(request).await;
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return raw,
                Ok(count) => raw.extend_from_slice(&buffer[..count]),
            }
        }
    };
    tokio::time::timeout(PATIENCE, exchange)
        .await
        .expect("the decoy closes the connection in time")
}
