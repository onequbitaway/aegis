//! One connection of a decoy: read one request, answer it slowly, and close.
//!
//! Each step has a limit, so a client cannot hold the decoy:
//!
//! - The request line and the headers have a size limit and a time limit.
//! - The body has a size limit and a time limit.
//! - Each write has a time limit.
//! - The connection has a total time limit and a limit for the bytes that the decoy sends.
//!
//! The total time limit is the hold limit. At the hold limit, the decoy ends the answer.
//! The last write gets one write time limit more. Thus no connection lives longer than
//! the hold limit and one write time limit.
//!
//! The decoy is slow only when it writes an answer. It never waits without a limit for a
//! client that is slow or silent.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::events::{ClientRecord, ContactFacts, Priority};
use crate::fingerprint::client_fingerprint;
use crate::gate::{Permit, Reservation};
use crate::http::{self, BodyLength, FramingError, HeadError, RequestHead, ResponseHead};
use crate::names::result;
use crate::persona::{Body, Reply, RequestView, Signal};
use crate::service::{Admission, Shared};
use crate::text::{Cleaned, clean, clean_bytes};

/// The longest time that the decoy reads after an error answer, before it closes.
const LINGER_TIME: Duration = Duration::from_secs(1);
/// The largest number of bytes that the decoy reads and discards after the request.
const SPARE_INBOUND_BYTES: usize = 64 * 1024;
/// The memory that the decoy counts for the pieces of a streamed answer.
const STREAM_BUFFER_BYTES: usize = 4096;

const MAX_METHOD_CHARACTERS: usize = 16;
const MAX_PATH_CHARACTERS: usize = 512;
const MAX_TARGET_CHARACTERS: usize = 1024;
const MAX_USER_AGENT_CHARACTERS: usize = 256;
const MAX_HOST_CHARACTERS: usize = 255;
const MAX_CONTENT_TYPE_CHARACTERS: usize = 128;
const MAX_REFERER_CHARACTERS: usize = 512;
const MAX_HEADER_NAMES: usize = 64;
const MAX_HEADER_NAME_CHARACTERS: usize = 64;

/// Why the decoy could not read a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum RequestFailure {
    #[error("the client sent no data")]
    NoRequest,
    #[error("the client closed the connection before the request was complete")]
    Closed,
    #[error("the client did not send the request in the permitted time")]
    Timeout,
    #[error("the request line and the headers are above a limit")]
    HeadTooLarge,
    #[error("the request is not valid HTTP/1.x")]
    Malformed,
    #[error("the request body has no fixed length")]
    LengthRequired,
    #[error("the request body is above the size limit")]
    BodyTooLarge,
    #[error("the interim response failed: {0}")]
    Send(SendError),
}

impl RequestFailure {
    /// Returns the `decoy_result` value of this failure.
    fn result(self) -> &'static str {
        match self {
            Self::NoRequest => result::NO_REQUEST,
            Self::Closed => result::CLIENT_CLOSED,
            Self::Timeout => result::READ_TIMEOUT,
            Self::HeadTooLarge => result::HEADER_TOO_LARGE,
            Self::Malformed | Self::LengthRequired => result::BAD_REQUEST,
            Self::BodyTooLarge => result::BODY_TOO_LARGE,
            Self::Send(error) => error.result(),
        }
    }

    /// Returns the status that the decoy sends before it closes, if it sends one.
    fn status(self) -> Option<u16> {
        match self {
            Self::NoRequest | Self::Closed | Self::Send(_) => None,
            Self::Timeout => Some(408),
            Self::HeadTooLarge => Some(431),
            Self::Malformed => Some(400),
            Self::LengthRequired => Some(411),
            Self::BodyTooLarge => Some(413),
        }
    }
}

/// Why a write to the client failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum SendError {
    #[error("the client closed the connection")]
    Closed,
    #[error("the client did not read in the permitted time")]
    Stalled,
    #[error("the answer is above the byte limit of the connection")]
    ByteLimit,
}

impl SendError {
    /// Returns the `decoy_result` value of this failure.
    fn result(self) -> &'static str {
        match self {
            Self::Closed => result::CLIENT_CLOSED,
            Self::Stalled => result::WRITE_TIMEOUT,
            Self::ByteLimit => result::BYTE_LIMIT,
        }
    }
}

/// How a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Idle {
    /// The time is over.
    Elapsed,
    /// The client sent all its data, or the decoy reads no more data.
    Ended,
    /// The connection failed.
    Failed,
}

/// The record of one connection. Its drop writes the `decoy.contact` event.
///
/// The event comes from the drop, so each admitted connection gives one contact event.
/// This is also true when the decoy stops and drops the task of the connection.
struct Recorder {
    shared: Arc<Shared>,
    started: Instant,
    client: ClientRecord,
    result: &'static str,
    status: Option<u16>,
    received: u64,
    sent: u64,
    planted_canary: Option<String>,
    memory: Option<Reservation>,
    permit: Option<Permit>,
}

impl Recorder {
    /// Adds `bytes` to the memory count of the connection.
    fn grow(&mut self, bytes: usize) {
        if let Some(memory) = &mut self.memory {
            memory.grow(bytes);
        }
    }

    /// Removes `bytes` from the memory count of the connection.
    fn shrink(&mut self, bytes: usize) {
        if let Some(memory) = &mut self.memory {
            memory.shrink(bytes);
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        // Free the place and the memory count first. Thus a reader of the event sees a
        // decoy that already has space for the next connection.
        drop(self.memory.take());
        drop(self.permit.take());
        let facts = ContactFacts {
            result: self.result,
            status: self.status,
            held: self.started.elapsed(),
            bytes_received: self.received,
            bytes_sent: self.sent,
            planted_canary: self.planted_canary.as_deref(),
        };
        tracing::debug!(
            decoy = %self.shared.config.id,
            client = %self.client.address,
            result = facts.result,
            held_ms = u64::try_from(facts.held.as_millis()).unwrap_or(u64::MAX),
            bytes_received = facts.bytes_received,
            bytes_sent = facts.bytes_sent,
            "decoy contact ended"
        );
        let event = self.shared.factory.contact(&self.client, &facts);
        // A contact with no request is the least important event.
        let priority = if self.client.method.is_some() {
            Priority::Normal
        } else {
            Priority::Low
        };
        self.shared.emit(event, priority);
    }
}

/// Serves one admitted connection until it ends.
pub(crate) async fn serve<S>(shared: Arc<Shared>, mut stream: S, admission: Admission)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let deadline = started + shared.config.limits.max_hold;
    let last_write = deadline + shared.config.limits.write_timeout;
    let record = Recorder {
        shared: Arc::clone(&shared),
        started,
        client: ClientRecord::new(admission.address),
        result: result::INTERRUPTED,
        status: None,
        received: 0,
        sent: 0,
        planted_canary: None,
        memory: Some(Reservation::new(Arc::clone(&shared.gauge))),
        permit: Some(admission.permit),
    };
    let mut session = Session {
        shared: &shared,
        stream: &mut stream,
        record,
        deadline,
        last_write,
        client_open: true,
        spare_inbound: SPARE_INBOUND_BYTES,
    };
    session.run().await;
}

/// The state of one connection.
struct Session<'a, S> {
    shared: &'a Shared,
    stream: &'a mut S,
    record: Recorder,
    /// The instant at which the decoy ends the answer: the hold limit.
    deadline: Instant,
    /// The instant after which the decoy waits for no write: the hold limit and one
    /// write time limit. The last bytes of an answer go in this time.
    last_write: Instant,
    /// `false` after the client closed its side of the connection.
    client_open: bool,
    /// The number of bytes that the decoy still reads and discards after the request.
    spare_inbound: usize,
}

impl<S> Session<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(&mut self) {
        let shared = self.shared;
        let limits = &shared.config.limits;

        self.record.grow(limits.max_header_bytes);
        let mut buffer = vec![0_u8; limits.max_header_bytes];
        let (head, head_length) = match self.read_head(&mut buffer).await {
            Ok(parsed) => parsed,
            Err(failure) => return self.fail(failure).await,
        };
        self.record.grow(head.size());
        self.describe(&head);

        let leftover = buffer.get(head_length..).unwrap_or_default();
        let body = match self.read_body(&head, leftover).await {
            Ok(body) => body,
            Err(failure) => return self.fail(failure).await,
        };
        drop(buffer);
        self.record.shrink(limits.max_header_bytes);

        let fingerprint = self.record.client.fingerprint.clone().unwrap_or_default();
        let view = RequestView {
            head: &head,
            path: head.path(),
            query: head.query(),
            body: &body,
            client: self.record.client.address,
            fingerprint: &fingerprint,
        };
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let planned = shared.personas.plan(&view, remaining);
        shared.count_request();
        self.record.client.kind = planned.kind;
        self.record.planted_canary = planned.planted_canary;
        match planned.signal {
            Some(Signal::CanaryHit(hit)) => {
                // The event is the signal. The log line is for a debug session only, so
                // a client cannot fill the log.
                tracing::debug!(
                    decoy = %shared.config.id,
                    client = %self.record.client.address,
                    canary_id = %hit.id,
                    "decoy canary hit"
                );
                shared.count_canary_hit();
                let event = shared.factory.canary_hit(&self.record.client, &hit);
                shared.emit(event, Priority::High);
            }
            Some(Signal::HoneytokenTrip { key_id, captured }) => {
                tracing::debug!(
                    decoy = %shared.config.id,
                    client = %self.record.client.address,
                    honeytoken_id = %key_id,
                    "a client used a planted decoy key"
                );
                shared.count_honeytoken_trip();
                let event = shared
                    .factory
                    .honeytoken_trip(&self.record.client, &key_id, captured);
                shared.emit(event, Priority::High);
            }
            None => {}
        }
        // The answer does not need the body.
        let body_length = body.len();
        drop(body);
        self.record.shrink(body_length);

        let head_only = head.method == "HEAD";
        let chunked = head.minor_version >= 1;
        self.record.result = self.write_reply(planned.reply, head_only, chunked).await;
        self.shutdown().await;
    }

    /// Records why the request failed, sends the error status, and closes.
    async fn fail(&mut self, failure: RequestFailure) {
        tracing::debug!(
            decoy = %self.shared.config.id,
            client = %self.record.client.address,
            reason = %failure,
            "decoy request refused"
        );
        self.record.result = failure.result();
        if let Some(status) = failure.status() {
            // The result stays the failure of the request, with or without the answer.
            self.write_reply(Reply::plain(status), false, false).await;
            self.shutdown().await;
            // The client can still send. Read for a short time, so the close is clean
            // and the client gets the answer.
            let until = (Instant::now() + LINGER_TIME).min(self.deadline);
            self.idle(until, true).await;
        }
    }

    /// Reads the request line and the headers into `buffer`.
    ///
    /// `buffer` has the size of the head limit. After the read, it holds only the bytes
    /// that the client sent. The time limit is for the full read, not for one read. Thus
    /// a client that sends one byte at a time cannot hold the connection.
    async fn read_head(
        &mut self,
        buffer: &mut Vec<u8>,
    ) -> Result<(RequestHead, usize), RequestFailure> {
        let limits = &self.shared.config.limits;
        let deadline = (self.record.started + limits.header_read_timeout).min(self.deadline);
        let mut filled = 0;
        loop {
            let Some(space) = buffer.get_mut(filled..).filter(|space| !space.is_empty()) else {
                return Err(RequestFailure::HeadTooLarge);
            };
            let count = match timeout_at(deadline, self.stream.read(space)).await {
                Err(_) => return Err(RequestFailure::Timeout),
                Ok(Err(_)) => return Err(RequestFailure::Closed),
                Ok(Ok(0)) if filled == 0 => return Err(RequestFailure::NoRequest),
                Ok(Ok(0)) => return Err(RequestFailure::Closed),
                Ok(Ok(count)) => count,
            };
            self.count_received(count);
            let scanned = filled;
            filled = filled.saturating_add(count);
            let data = buffer.get(..filled).unwrap_or_default();
            if http::has_head_end(data, scanned) {
                // The decoy examines the headers one time only, when they are complete.
                let parsed =
                    http::parse_head(data, limits.max_headers).map_err(|error| match error {
                        HeadError::TooManyHeaders => RequestFailure::HeadTooLarge,
                        HeadError::Malformed => RequestFailure::Malformed,
                    });
                buffer.truncate(filled);
                return parsed;
            }
        }
    }

    /// Reads the request body. `leftover` holds the bytes that came with the headers.
    async fn read_body(
        &mut self,
        head: &RequestHead,
        leftover: &[u8],
    ) -> Result<Vec<u8>, RequestFailure> {
        let limits = &self.shared.config.limits;
        let length = http::body_length(head).map_err(|error| match error {
            FramingError::LengthRequired => RequestFailure::LengthRequired,
            FramingError::Invalid => RequestFailure::Malformed,
        })?;
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length <= limits.max_body_bytes)
            .ok_or(RequestFailure::BodyTooLarge)?;
        if length == 0 {
            return Ok(Vec::new());
        }
        self.record.grow(length);
        let mut body = vec![0_u8; length];
        let mut filled = length.min(leftover.len());
        if let (Some(target), Some(source)) = (body.get_mut(..filled), leftover.get(..filled)) {
            target.copy_from_slice(source);
        }
        if filled < length && http::expects_continue(head) {
            self.send(http::CONTINUE)
                .await
                .map_err(RequestFailure::Send)?;
        }
        let deadline = (Instant::now() + limits.body_read_timeout).min(self.deadline);
        while let Some(space) = body.get_mut(filled..).filter(|space| !space.is_empty()) {
            let count = match timeout_at(deadline, self.stream.read(space)).await {
                Err(_) => return Err(RequestFailure::Timeout),
                Ok(Err(_) | Ok(0)) => return Err(RequestFailure::Closed),
                Ok(Ok(count)) => count,
            };
            self.count_received(count);
            filled = filled.saturating_add(count);
        }
        Ok(body)
    }

    fn count_received(&mut self, count: usize) {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.record.received = self.record.received.saturating_add(count);
    }

    /// Writes what the decoy knows about the request into the record.
    ///
    /// Each text is clean and has a length limit. The text that is not a shared event
    /// field goes into the map for `raw`.
    fn describe(&mut self, head: &RequestHead) {
        let user_agent = head.header("user-agent").unwrap_or_default();
        let accept_encoding = head.header("accept-encoding").unwrap_or_default();
        let names: Vec<&str> = head
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        let fingerprint = client_fingerprint(
            head.version(),
            &names,
            &String::from_utf8_lossy(user_agent),
            &String::from_utf8_lossy(accept_encoding),
        );

        let mut truncated: Vec<&str> = Vec::new();
        let mut keep = |name: &'static str, cleaned: Cleaned| {
            if cleaned.truncated {
                truncated.push(name);
            }
            cleaned.text
        };
        let method = keep("method", clean(&head.method, MAX_METHOD_CHARACTERS));
        let path = keep("path", clean(head.path(), MAX_PATH_CHARACTERS));
        let agent = keep(
            "user_agent",
            clean_bytes(user_agent, MAX_USER_AGENT_CHARACTERS),
        );
        let mut text = Map::new();
        text.insert(
            "target".to_owned(),
            json!(keep("target", clean(&head.target, MAX_TARGET_CHARACTERS))),
        );
        text.insert("http_version".to_owned(), json!(head.version()));
        for (key, header, limit) in [
            ("host", "host", MAX_HOST_CHARACTERS),
            ("content_type", "content-type", MAX_CONTENT_TYPE_CHARACTERS),
            ("referer", "referer", MAX_REFERER_CHARACTERS),
        ] {
            if let Some(value) = head.header(header) {
                text.insert(key.to_owned(), json!(keep(key, clean_bytes(value, limit))));
            }
        }
        let header_names: Vec<Value> = names
            .iter()
            .take(MAX_HEADER_NAMES)
            .map(|name| json!(clean(name, MAX_HEADER_NAME_CHARACTERS).text))
            .collect();
        if names.len() > MAX_HEADER_NAMES {
            truncated.push("header_names");
        }
        text.insert("header_names".to_owned(), Value::Array(header_names));
        if !truncated.is_empty() {
            text.insert("truncated".to_owned(), json!(truncated));
        }

        let client = &mut self.record.client;
        client.fingerprint = Some(fingerprint);
        client.method = Some(method);
        client.path = Some(path);
        client.user_agent = (!agent.is_empty()).then_some(agent);
        client.request_text = text;
        let size = client.size();
        self.record.grow(size);
    }

    /// Returns `true` if the decoy can send `more` bytes below the byte limit.
    fn fits(&self, more: usize) -> bool {
        let limit = u64::try_from(self.shared.config.limits.max_response_bytes).unwrap_or(u64::MAX);
        let more = u64::try_from(more).unwrap_or(u64::MAX);
        self.record.sent.saturating_add(more) <= limit
    }

    /// Sends `bytes` to the client in the write time limit and below the byte limit.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), SendError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.fits(bytes.len()) {
            return Err(SendError::ByteLimit);
        }
        let deadline =
            (Instant::now() + self.shared.config.limits.write_timeout).min(self.last_write);
        let mut offset = 0;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            let count = match timeout_at(deadline, self.stream.write(rest)).await {
                Err(_) => return Err(SendError::Stalled),
                Ok(Err(_) | Ok(0)) => return Err(SendError::Closed),
                Ok(Ok(count)) => count,
            };
            offset += count;
            let count = u64::try_from(count).unwrap_or(u64::MAX);
            self.record.sent = self.record.sent.saturating_add(count);
        }
        match timeout_at(deadline, self.stream.flush()).await {
            Err(_) => Err(SendError::Stalled),
            Ok(Err(_)) => Err(SendError::Closed),
            Ok(Ok(())) => Ok(()),
        }
    }

    /// Waits until `until`. During the wait, reads and discards the bytes of the client.
    ///
    /// The decoy discards a limited number of bytes only. After the limit, it reads no
    /// more, and the flow control of the connection stops the client. With `end_at_eof`,
    /// the wait ends early when the client has no more data.
    async fn idle(&mut self, until: Instant, end_at_eof: bool) -> Idle {
        let sleep = tokio::time::sleep_until(until);
        tokio::pin!(sleep);
        let mut scratch = [0_u8; 1024];
        loop {
            if !self.client_open || self.spare_inbound == 0 {
                if end_at_eof {
                    return Idle::Ended;
                }
                sleep.as_mut().await;
                return Idle::Elapsed;
            }
            let want = self.spare_inbound.min(1024);
            let target = scratch.get_mut(..want).unwrap_or_default();
            tokio::select! {
                biased;
                () = sleep.as_mut() => return Idle::Elapsed,
                read = self.stream.read(target) => match read {
                    Ok(0) => self.client_open = false,
                    Ok(count) => {
                        self.count_received(count);
                        self.spare_inbound = self.spare_inbound.saturating_sub(count);
                    }
                    Err(_) => return Idle::Failed,
                },
            }
        }
    }

    /// Closes the write side of the connection in the write time limit.
    async fn shutdown(&mut self) {
        let deadline =
            (Instant::now() + self.shared.config.limits.write_timeout).min(self.last_write);
        match timeout_at(deadline, self.stream.shutdown()).await {
            Ok(Ok(())) => {}
            // The client is gone or does not read. The drop of the stream closes it.
            Ok(Err(error)) => tracing::trace!(%error, "decoy connection shutdown failed"),
            Err(_) => tracing::trace!("decoy connection shutdown timed out"),
        }
    }

    /// Sends one answer. Returns the `decoy_result` value of the send.
    ///
    /// `head_only` is for a `HEAD` request. `chunked` is `false` for an HTTP/1.0 client.
    async fn write_reply(&mut self, reply: Reply, head_only: bool, chunked: bool) -> &'static str {
        let Reply {
            status,
            content_type,
            headers,
            body,
        } = reply;
        match body {
            Body::Full { bytes, delay } => {
                self.record.grow(bytes.len());
                if !delay.is_zero() {
                    let until = (Instant::now() + delay).min(self.deadline);
                    if self.idle(until, false).await == Idle::Failed {
                        return result::CLIENT_CLOSED;
                    }
                }
                let mut message = ResponseHead {
                    status,
                    content_type,
                    length: BodyLength::Fixed(bytes.len()),
                    extra: &headers,
                }
                .encode(Utc::now());
                if !head_only {
                    message.extend_from_slice(&bytes);
                }
                match self.send(&message).await {
                    Ok(()) => {
                        self.record.status = Some(status);
                        result::COMPLETED
                    }
                    Err(error) => error.result(),
                }
            }
            Body::Paced {
                bytes,
                piece_bytes,
                interval,
            } => {
                self.record.grow(bytes.len());
                let head = ResponseHead {
                    status,
                    content_type,
                    length: BodyLength::Fixed(bytes.len()),
                    extra: &headers,
                }
                .encode(Utc::now());
                let body_bytes = if head_only { 0 } else { bytes.len() };
                // A body with a fixed length must be complete. Send it all or send nothing.
                if !self.fits(head.len().saturating_add(body_bytes)) {
                    return result::BYTE_LIMIT;
                }
                if let Err(error) = self.send(&head).await {
                    return error.result();
                }
                self.record.status = Some(status);
                if head_only {
                    return result::COMPLETED;
                }
                let piece_bytes = piece_bytes.max(1);
                let mut offset = 0;
                while offset < bytes.len() {
                    // The next piece goes one interval after the last write ended. Thus
                    // a slow reader gets no burst, and each turn examines the real time.
                    let tick = Instant::now() + interval;
                    let at_limit = tick >= self.deadline;
                    let until = tick.min(self.deadline);
                    if self.idle(until, false).await == Idle::Failed {
                        return result::CLIENT_CLOSED;
                    }
                    // At the hold limit, the remaining bytes go at one time.
                    let end = if at_limit {
                        bytes.len()
                    } else {
                        offset.saturating_add(piece_bytes).min(bytes.len())
                    };
                    let piece = bytes.get(offset..end).unwrap_or_default();
                    if let Err(error) = self.send(piece).await {
                        return error.result();
                    }
                    offset = end;
                    if at_limit {
                        return result::HOLD_LIMIT;
                    }
                }
                result::COMPLETED
            }
            Body::Stream {
                mut source,
                closing,
                interval,
            } => {
                self.record
                    .grow(STREAM_BUFFER_BYTES.saturating_add(closing.len()));
                let length = if chunked {
                    BodyLength::Chunked
                } else {
                    BodyLength::UntilClose
                };
                let head = ResponseHead {
                    status,
                    content_type,
                    length,
                    extra: &headers,
                }
                .encode(Utc::now());
                if let Err(error) = self.send(&head).await {
                    return error.result();
                }
                self.record.status = Some(status);
                if head_only {
                    return result::COMPLETED;
                }
                // The bytes that end the body early: the end of the content and, for a
                // chunked body, the last chunk. The byte limit always keeps space for them.
                let mut ending = frame(&closing, chunked);
                if chunked {
                    ending.extend_from_slice(http::LAST_CHUNK);
                }
                loop {
                    // The next piece goes one interval after the last write ended. Thus
                    // a slow reader gets no burst, and each turn examines the real time.
                    let tick = Instant::now() + interval;
                    if tick >= self.deadline {
                        if self.idle(self.deadline, false).await == Idle::Failed {
                            return result::CLIENT_CLOSED;
                        }
                        return match self.send(&ending).await {
                            Ok(()) => result::HOLD_LIMIT,
                            Err(error) => error.result(),
                        };
                    }
                    if self.idle(tick, false).await == Idle::Failed {
                        return result::CLIENT_CLOSED;
                    }
                    let Some(piece) = source.next_piece() else {
                        if chunked && let Err(error) = self.send(http::LAST_CHUNK).await {
                            return error.result();
                        }
                        return result::COMPLETED;
                    };
                    let framed = frame(&piece, chunked);
                    if !self.fits(framed.len().saturating_add(ending.len())) {
                        return match self.send(&ending).await {
                            Ok(()) => result::BYTE_LIMIT,
                            Err(error) => error.result(),
                        };
                    }
                    if let Err(error) = self.send(&framed).await {
                        return error.result();
                    }
                }
            }
        }
    }
}

/// Returns `piece` as it goes on the wire: one chunk, or the bytes with no frame.
fn frame(piece: &[u8], chunked: bool) -> Vec<u8> {
    if chunked {
        http::chunk(piece)
    } else {
        piece.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_request_failure_has_a_result_and_the_right_status() {
        for (failure, expected_result, expected_status) in [
            (RequestFailure::NoRequest, "no_request", None),
            (RequestFailure::Closed, "client_closed", None),
            (RequestFailure::Timeout, "read_timeout", Some(408)),
            (RequestFailure::HeadTooLarge, "header_too_large", Some(431)),
            (RequestFailure::Malformed, "bad_request", Some(400)),
            (RequestFailure::LengthRequired, "bad_request", Some(411)),
            (RequestFailure::BodyTooLarge, "body_too_large", Some(413)),
            (
                RequestFailure::Send(SendError::Stalled),
                "write_timeout",
                None,
            ),
        ] {
            assert_eq!(failure.result(), expected_result, "{failure}");
            assert_eq!(failure.status(), expected_status, "{failure}");
        }
    }

    #[test]
    fn each_send_error_has_a_result() {
        assert_eq!(SendError::Closed.result(), "client_closed");
        assert_eq!(SendError::Stalled.result(), "write_timeout");
        assert_eq!(SendError::ByteLimit.result(), "byte_limit");
    }

    #[test]
    fn a_piece_gets_a_chunk_frame_only_for_a_chunked_body() {
        assert_eq!(frame(b"abc", true), b"3\r\nabc\r\n");
        assert_eq!(frame(b"abc", false), b"abc");
        assert_eq!(frame(b"", true), b"");
    }
}
