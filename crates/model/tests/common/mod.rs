//! Helpers that the integration tests share.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use aegis_contracts::Result;
use aegis_contracts::model::{ChatChunk, ChatStream};
use futures::StreamExt;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use wiremock::{MockServer, Request, ResponseTemplate};

/// The longest time that a test waits for one result.
pub const WAIT: Duration = Duration::from_secs(10);

/// Awaits `future`, and fails the test if it does not complete in [`WAIT`].
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("the operation did not complete in time")
}

/// Makes the body of a server-sent event stream from `data` lines.
pub fn sse_body(events: &[String]) -> String {
    events
        .iter()
        .map(|data| format!("data: {data}\n\n"))
        .collect()
}

/// Makes an event stream answer that has an `event` line and a `data` line for each value.
pub fn named_sse_body(events: &[Value]) -> String {
    events
        .iter()
        .map(|event| {
            format!(
                "event: {}\ndata: {event}\n\n",
                event["type"].as_str().unwrap()
            )
        })
        .collect()
}

/// Makes a response that carries an event stream.
pub fn sse_response(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "text/event-stream")
}

/// Reads all items of a chat stream.
pub async fn collect(stream: ChatStream) -> Vec<Result<ChatChunk>> {
    within(stream.collect::<Vec<_>>()).await
}

/// Reads all chunks of a chat stream that has no error.
pub async fn collect_ok(stream: ChatStream) -> Vec<ChatChunk> {
    collect(stream)
        .await
        .into_iter()
        .map(|chunk| chunk.expect("the stream has an error"))
        .collect()
}

/// Returns the requests that the server received.
pub async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap()
}

/// Returns the one request that the server received.
pub async fn only_request(server: &MockServer) -> Request {
    let mut requests = requests(server).await;
    assert_eq!(requests.len(), 1, "the server must receive one request");
    requests.remove(0)
}

/// Returns the value of one header of a request, or `None`.
pub fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().unwrap())
}

/// Returns the JSON body of a request.
pub fn json_body(request: &Request) -> Value {
    request.body_json().unwrap()
}

/// Returns a local address on which no server listens.
pub async fn closed_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// One step of a [`stream_server`] script.
enum Step {
    /// Sends bytes as one part of the body.
    Send(Vec<u8>),
    /// Closes the connection before the body is complete.
    Abort,
}

/// The control of a [`stream_server`]. The server keeps the connection open until the
/// test drops this value.
pub struct StreamScript(mpsc::UnboundedSender<Step>);

impl StreamScript {
    fn step(&self, step: Step) {
        assert!(self.0.send(step).is_ok(), "the stream server stopped");
    }

    /// Sends bytes as one part of the body.
    pub fn send(&self, part: impl AsRef<[u8]>) {
        self.step(Step::Send(part.as_ref().to_vec()));
    }

    /// Closes the connection before the body is complete.
    pub fn abort(&self) {
        self.step(Step::Abort);
    }
}

/// Starts a server that answers one request with an event stream.
///
/// The server sends the response headers, and then one part of the body for each call of
/// [`StreamScript::send`]. Thus a test controls when each part arrives.
pub async fn stream_server() -> (SocketAddr, StreamScript) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut steps) = mpsc::unbounded_channel::<Step>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read the request head and the body. The body length comes from the head.
        let mut received = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                return;
            }
            received.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&received);
            if let Some(head_end) = text.find("\r\n\r\n") {
                let length = text[..head_end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if received.len() >= head_end + 4 + length {
                    break;
                }
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        socket.flush().await.unwrap();
        while let Some(step) = steps.recv().await {
            match step {
                Step::Send(part) => {
                    let mut frame = format!("{:x}\r\n", part.len()).into_bytes();
                    frame.extend_from_slice(&part);
                    frame.extend_from_slice(b"\r\n");
                    socket.write_all(&frame).await.unwrap();
                    socket.flush().await.unwrap();
                }
                Step::Abort => return,
            }
        }
    });
    (address, StreamScript(sender))
}
