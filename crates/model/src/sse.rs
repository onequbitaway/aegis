//! Server-sent events: the decoder and the stream that drives a provider assembler.

use std::collections::VecDeque;
use std::time::Duration;

use aegis_contracts::model::{ChatChunk, ChatStream};
use aegis_contracts::{Error, Result};
use futures::StreamExt;
use reqwest::Response;

/// The largest event that the decoder holds, in bytes.
pub(crate) const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseEvent {
    /// The `event` field.
    pub(crate) event: Option<String>,
    /// The `data` field. Many `data` lines are joined with a line feed.
    pub(crate) data: String,
}

/// The event is larger than [`MAX_EVENT_BYTES`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EventTooLarge;

/// A decoder for a byte stream of server-sent events.
///
/// The decoder accepts `LF` and `CRLF` line ends. It ignores comments and the `id` and
/// `retry` fields.
#[derive(Debug, Default)]
pub(crate) struct SseDecoder {
    line: Vec<u8>,
    event: Option<String>,
    data: String,
    has_data: bool,
}

impl SseDecoder {
    /// Adds bytes and appends each complete event to `events`.
    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
        events: &mut Vec<SseEvent>,
    ) -> Result<(), EventTooLarge> {
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.line(&line, events);
            } else {
                self.line.push(byte);
            }
            if self.line.len().saturating_add(self.data.len()) > MAX_EVENT_BYTES {
                return Err(EventTooLarge);
            }
        }
        Ok(())
    }

    /// Returns the event that the end of the body completes, if there is one.
    ///
    /// Some servers do not send the empty line after the last event.
    pub(crate) fn finish(&mut self) -> Option<SseEvent> {
        let mut events = Vec::new();
        if !self.line.is_empty() {
            let line = std::mem::take(&mut self.line);
            self.line(&line, &mut events);
        }
        self.dispatch(&mut events);
        events.pop()
    }

    fn line(&mut self, line: &[u8], events: &mut Vec<SseEvent>) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            self.dispatch(events);
            return;
        }
        let text = String::from_utf8_lossy(line);
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (text.as_ref(), ""),
        };
        match field {
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "event" => self.event = Some(value.to_owned()),
            // An empty field name is a comment. The adapters do not use other fields.
            _ => {}
        }
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        let event = self.event.take();
        if self.has_data {
            events.push(SseEvent {
                event,
                data: std::mem::take(&mut self.data),
            });
            self.has_data = false;
        }
    }
}

/// The output queue of an [`Assembler`].
pub(crate) type Chunks = VecDeque<Result<ChatChunk>>;

/// Converts the events of one provider to chat chunks.
pub(crate) trait Assembler: Send + 'static {
    /// Handles one event. Returns `false` when the answer is complete or has failed.
    fn event(&mut self, event: &SseEvent, chunks: &mut Chunks) -> bool;

    /// Handles the end of the body when no event completed the answer.
    fn end(&mut self, chunks: &mut Chunks);
}

struct Driver<A> {
    provider: String,
    idle: Duration,
    response: Option<Response>,
    decoder: SseDecoder,
    assembler: A,
    chunks: Chunks,
}

impl<A: Assembler> Driver<A> {
    /// Sends decoded events to the assembler. Returns `false` when the answer is complete.
    fn deliver(&mut self, events: Vec<SseEvent>) -> bool {
        for event in events {
            if !self.assembler.event(&event, &mut self.chunks) {
                return false;
            }
        }
        true
    }

    /// Closes the body and queues `error` as the last item.
    fn fail(&mut self, error: Error) {
        self.response = None;
        self.chunks.push_back(Err(error));
    }

    async fn next(&mut self) -> Option<Result<ChatChunk>> {
        loop {
            if let Some(chunk) = self.chunks.pop_front() {
                if chunk.is_err() {
                    // An error is the last item of the stream.
                    self.response = None;
                    self.chunks.clear();
                }
                return Some(chunk);
            }
            let response = self.response.as_mut()?;
            match tokio::time::timeout(self.idle, response.chunk()).await {
                Err(_) => self.fail(Error::Timeout(format!(
                    "the stream of provider {} sent no data for {:?}",
                    self.provider, self.idle
                ))),
                Ok(Err(error)) if error.is_timeout() => self.fail(Error::Timeout(format!(
                    "the stream of provider {} stopped before the answer was complete",
                    self.provider
                ))),
                Ok(Err(_)) => self.fail(Error::Unavailable(format!(
                    "the stream of provider {} broke before the answer was complete",
                    self.provider
                ))),
                Ok(Ok(Some(bytes))) => {
                    let mut events = Vec::new();
                    let fed = self.decoder.feed(&bytes, &mut events);
                    if !self.deliver(events) {
                        self.response = None;
                    } else if fed.is_err() {
                        self.fail(Error::Serialization(format!(
                            "provider {} sent a stream event that is larger than {MAX_EVENT_BYTES} bytes",
                            self.provider
                        )));
                    }
                }
                Ok(Ok(None)) => {
                    self.response = None;
                    let last = self.decoder.finish().into_iter().collect();
                    if self.deliver(last) {
                        self.assembler.end(&mut self.chunks);
                    }
                }
            }
        }
    }
}

/// Makes a chat stream from a streamed response.
///
/// The stream ends after the first error. The timeout `idle` applies to each read of the
/// body, not to the full answer.
pub(crate) fn chat_stream<A: Assembler>(
    provider: &str,
    idle: Duration,
    response: Response,
    assembler: A,
) -> ChatStream {
    let driver = Driver {
        provider: provider.to_owned(),
        idle,
        response: Some(response),
        decoder: SseDecoder::default(),
        assembler,
        chunks: Chunks::new(),
    };
    futures::stream::unfold(driver, |mut driver| async move {
        driver.next().await.map(|chunk| (chunk, driver))
    })
    .boxed()
}

/// Reads all chunks of an assembler for a list of events. For tests of the assemblers.
#[cfg(test)]
pub(crate) fn assemble<A: Assembler>(
    mut assembler: A,
    events: &[SseEvent],
) -> Vec<Result<ChatChunk>> {
    let mut chunks = Chunks::new();
    let mut open = true;
    for event in events {
        if !assembler.event(event, &mut chunks) {
            open = false;
            break;
        }
    }
    if open {
        assembler.end(&mut chunks);
    }
    let mut output = Vec::new();
    for chunk in chunks {
        let failed = chunk.is_err();
        output.push(chunk);
        if failed {
            break;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(parts: &[&[u8]]) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for part in parts {
            decoder.feed(part, &mut events).unwrap();
        }
        events.extend(decoder.finish());
        events
    }

    fn data(text: &str) -> SseEvent {
        SseEvent {
            event: None,
            data: text.to_owned(),
        }
    }

    #[test]
    fn decoder_reads_events_with_lf_and_crlf_line_ends() {
        let events = decode(&[b"data: one\n\ndata: two\r\n\r\nevent: ping\ndata: three\n\n"]);
        assert_eq!(
            events,
            vec![
                data("one"),
                data("two"),
                SseEvent {
                    event: Some("ping".to_owned()),
                    data: "three".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn decoder_gives_the_same_events_for_each_split_of_the_bytes() {
        let body = "event: a\ndata: {\"text\":\"h\u{e9}llo \u{1f512}\"}\n\n: comment\ndata: x\ndata: y\n\nid: 7\nretry: 5\ndata:no-space\n\n";
        let whole = decode(&[body.as_bytes()]);
        assert_eq!(
            whole,
            vec![
                SseEvent {
                    event: Some("a".to_owned()),
                    data: "{\"text\":\"h\u{e9}llo \u{1f512}\"}".to_owned(),
                },
                data("x\ny"),
                data("no-space"),
            ]
        );
        // A split inside a multi-byte character or inside a line end must not change the result.
        for split in 1..body.len() {
            let (left, right) = body.as_bytes().split_at(split);
            assert_eq!(decode(&[left, right]), whole, "split at byte {split}");
        }
        let bytes: Vec<&[u8]> = body.as_bytes().chunks(1).collect();
        assert_eq!(decode(&bytes), whole);
    }

    #[test]
    fn decoder_ignores_an_event_with_no_data_and_resets_the_event_name() {
        let events = decode(&[b"event: orphan\n\ndata: next\n\n"]);
        assert_eq!(events, vec![data("next")]);
    }

    #[test]
    fn decoder_completes_the_last_event_at_the_end_of_the_body() {
        let events = decode(&[b"data: first\n\ndata: [DONE]"]);
        assert_eq!(events, vec![data("first"), data("[DONE]")]);
        assert_eq!(decode(&[b""]), Vec::new());
    }

    #[test]
    fn decoder_rejects_an_event_that_is_too_large() {
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        let block = vec![b'a'; 1024 * 1024];
        decoder.feed(b"data: ", &mut events).unwrap();
        for _ in 0..7 {
            decoder.feed(&block, &mut events).unwrap();
        }
        assert_eq!(decoder.feed(&block, &mut events), Err(EventTooLarge));
        assert_eq!(events, Vec::new());
    }
}
