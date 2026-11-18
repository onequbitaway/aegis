//! The assembler for a streamed Messages answer.

use std::collections::BTreeMap;

use aegis_contracts::model::{ChatChunk, ToolCall, Usage};
use aegis_contracts::{Error, Result};

use super::wire::{self, AnswerBlock, BlockDelta, StreamEvent, WireUsage};
use crate::convert::parse_arguments;
use crate::http::{Secrets, json_fault};
use crate::sse::{Assembler, Chunks, SseEvent};

#[derive(Debug)]
struct PartialCall {
    id: String,
    name: String,
    input: String,
}

/// Collects the events of one streamed answer.
///
/// The assembler emits each text delta immediately. It emits a tool call when the API
/// closes the content block of the call. The last chunk has the finish reason and the usage.
pub(super) struct MessagesAssembler {
    provider: String,
    secrets: Secrets,
    calls: BTreeMap<u32, PartialCall>,
    stop_reason: Option<String>,
    usage: Option<Usage>,
}

impl MessagesAssembler {
    pub(super) fn new(provider: &str, secrets: Secrets) -> Self {
        Self {
            provider: provider.to_owned(),
            secrets,
            calls: BTreeMap::new(),
            stop_reason: None,
            usage: None,
        }
    }

    /// Adds the token counts of one event. The API sends cumulative counts.
    fn count(&mut self, update: WireUsage) {
        let usage = self.usage.get_or_insert_with(Usage::default);
        if let Some(input) = update.input() {
            usage.input_tokens = input;
        }
        if let Some(output) = update.output_tokens {
            usage.output_tokens = output;
        }
    }

    /// Handles one decoded event. Returns `Ok(false)` when the answer is complete.
    fn handle(&mut self, event: &SseEvent, chunks: &mut Chunks) -> Result<bool> {
        let parsed: StreamEvent = serde_json::from_str(&event.data).map_err(|error| {
            Error::Serialization(format!(
                "provider {} sent a stream event that could not be decoded: {}",
                self.provider,
                json_fault(&error)
            ))
        })?;
        match parsed {
            StreamEvent::MessageStart { message } => {
                if let Some(usage) = message.usage {
                    self.count(usage);
                }
            }
            StreamEvent::ContentBlockStart {
                index,
                content_block,
            } => match content_block {
                AnswerBlock::Text { text } if !text.is_empty() => {
                    chunks.push_back(Ok(ChatChunk {
                        delta: text,
                        ..ChatChunk::default()
                    }));
                }
                AnswerBlock::ToolUse { id, name, .. } => {
                    self.calls.insert(
                        index,
                        PartialCall {
                            id,
                            name,
                            input: String::new(),
                        },
                    );
                }
                AnswerBlock::Text { .. } | AnswerBlock::Other => {}
            },
            StreamEvent::ContentBlockDelta { index, delta } => match delta {
                BlockDelta::TextDelta { text } if !text.is_empty() => {
                    chunks.push_back(Ok(ChatChunk {
                        delta: text,
                        ..ChatChunk::default()
                    }));
                }
                BlockDelta::InputJsonDelta { partial_json } => {
                    if let Some(call) = self.calls.get_mut(&index) {
                        call.input.push_str(&partial_json);
                    }
                }
                BlockDelta::TextDelta { .. } | BlockDelta::Other => {}
            },
            StreamEvent::ContentBlockStop { index } => {
                if let Some(call) = self.calls.remove(&index) {
                    let arguments = parse_arguments(&self.provider, &call.name, &call.input)?;
                    chunks.push_back(Ok(ChatChunk {
                        tool_calls: vec![ToolCall {
                            id: call.id,
                            name: call.name,
                            arguments,
                        }],
                        ..ChatChunk::default()
                    }));
                }
            }
            StreamEvent::MessageDelta { delta, usage } => {
                if let Some(usage) = usage {
                    self.count(usage);
                }
                if let Some(reason) = delta.stop_reason {
                    if reason == "refusal" {
                        return Err(wire::refused(&self.provider));
                    }
                    self.stop_reason = Some(reason);
                }
            }
            StreamEvent::MessageStop => {
                chunks.push_back(Ok(ChatChunk {
                    delta: String::new(),
                    tool_calls: Vec::new(),
                    finish_reason: Some(wire::finish_reason(self.stop_reason.as_deref())),
                    usage: self.usage.take(),
                }));
                return Ok(false);
            }
            StreamEvent::Error { error } => {
                let labels = self.secrets.labels(Some(&error));
                return Err(wire::stream_error(&self.provider, &labels));
            }
            StreamEvent::Other => {}
        }
        Ok(true)
    }
}

impl Assembler for MessagesAssembler {
    fn event(&mut self, event: &SseEvent, chunks: &mut Chunks) -> bool {
        match self.handle(event, chunks) {
            Ok(open) => open,
            Err(error) => {
                chunks.push_back(Err(error));
                false
            }
        }
    }

    fn end(&mut self, chunks: &mut Chunks) {
        chunks.push_back(Err(Error::Unavailable(format!(
            "the stream of provider {} ended before the answer was complete",
            self.provider
        ))));
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::FinishReason;
    use serde_json::{Value, json};

    use super::*;
    use crate::sse::assemble;

    fn event(value: &Value) -> SseEvent {
        SseEvent {
            event: value["type"].as_str().map(str::to_owned),
            data: value.to_string(),
        }
    }

    fn run(events: &[Value]) -> Vec<Result<ChatChunk>> {
        let events: Vec<SseEvent> = events.iter().map(event).collect();
        assemble(MessagesAssembler::new("p", Secrets::default()), &events)
    }

    fn start() -> Value {
        json!({ "type": "message_start", "message": { "id": "msg_1", "role": "assistant", "content": [], "usage": { "input_tokens": 25, "output_tokens": 1 } } })
    }

    fn stop(reason: &str, output_tokens: u64) -> [Value; 2] {
        [
            json!({ "type": "message_delta", "delta": { "stop_reason": reason, "stop_sequence": null }, "usage": { "output_tokens": output_tokens } }),
            json!({ "type": "message_stop" }),
        ]
    }

    #[test]
    fn text_deltas_pass_through_and_the_last_chunk_has_the_reason_and_the_usage() {
        let [delta, end] = stop("end_turn", 15);
        let chunks = run(&[
            start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
            json!({ "type": "ping" }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "true " } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "positive" } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            delta,
            end,
        ]);
        let chunks: Vec<ChatChunk> = chunks.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            chunks,
            vec![
                ChatChunk {
                    delta: "true ".to_owned(),
                    ..ChatChunk::default()
                },
                ChatChunk {
                    delta: "positive".to_owned(),
                    ..ChatChunk::default()
                },
                ChatChunk {
                    delta: String::new(),
                    tool_calls: Vec::new(),
                    finish_reason: Some(FinishReason::Stop),
                    usage: Some(Usage {
                        input_tokens: 25,
                        output_tokens: 15,
                    }),
                },
            ]
        );
    }

    #[test]
    fn tool_call_is_emitted_only_when_its_block_stops() {
        let [delta, end] = stop("tool_use", 30);
        let events = [
            start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "Checking." } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            json!({ "type": "content_block_start", "index": 1, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": {} } }),
            json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "input_json_delta", "partial_json": "" } }),
            json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "input_json_delta", "partial_json": "{\"ip\": \"203.0" } }),
            json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "input_json_delta", "partial_json": ".113.7\"}" } }),
        ];
        // Before the block stops, the stream has only the text.
        let partial = run(&events);
        assert_eq!(partial.len(), 2);
        assert_eq!(partial[0].as_ref().unwrap().delta, "Checking.");
        assert!(matches!(&partial[1], Err(Error::Unavailable(_))));

        let mut complete = events.to_vec();
        complete.push(json!({ "type": "content_block_stop", "index": 1 }));
        complete.push(delta);
        complete.push(end);
        let chunks: Vec<ChatChunk> = run(&complete).into_iter().map(Result::unwrap).collect();
        assert_eq!(
            chunks,
            vec![
                ChatChunk {
                    delta: "Checking.".to_owned(),
                    ..ChatChunk::default()
                },
                ChatChunk {
                    tool_calls: vec![ToolCall {
                        id: "toolu_1".to_owned(),
                        name: "lookup_ip".to_owned(),
                        arguments: json!({ "ip": "203.0.113.7" }),
                    }],
                    ..ChatChunk::default()
                },
                ChatChunk {
                    delta: String::new(),
                    tool_calls: Vec::new(),
                    finish_reason: Some(FinishReason::ToolCalls),
                    usage: Some(Usage {
                        input_tokens: 25,
                        output_tokens: 30,
                    }),
                },
            ]
        );
    }

    #[test]
    fn tool_call_with_no_input_has_empty_arguments() {
        let [delta, end] = stop("tool_use", 5);
        let chunks = run(&[
            start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "list_alerts", "input": {} } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            delta,
            end,
        ]);
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0].as_ref().unwrap().tool_calls,
            vec![ToolCall {
                id: "toolu_1".to_owned(),
                name: "list_alerts".to_owned(),
                arguments: json!({}),
            }]
        );
    }

    #[test]
    fn invalid_tool_input_is_an_error_and_not_a_tool_call() {
        let chunks = run(&[
            start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": {} } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "input_json_delta", "partial_json": "{\"ip\": " } }),
            json!({ "type": "content_block_stop", "index": 0 }),
        ]);
        assert_eq!(chunks.len(), 1);
        assert!(
            matches!(&chunks[0], Err(Error::Serialization(text))
                if text == "provider p sent arguments for tool lookup_ip that are not a JSON object"),
            "{chunks:?}"
        );
    }

    #[test]
    fn refusal_stop_reason_ends_the_stream_with_refused() {
        let [delta, end] = stop("refusal", 2);
        let chunks = run(&[start(), delta, end]);
        assert_eq!(chunks.len(), 1);
        assert!(
            matches!(&chunks[0], Err(Error::Refused(text)) if text == "the model of provider p refused the task"),
            "{chunks:?}"
        );
    }

    #[test]
    fn error_event_maps_to_the_contract_error() {
        let chunks = run(&[
            start(),
            json!({ "type": "error", "error": { "type": "overloaded_error", "message": "Overloaded" } }),
        ]);
        assert_eq!(chunks.len(), 1);
        assert!(
            matches!(&chunks[0], Err(Error::Unavailable(text))
                if text == "provider p reported an error in the stream (type overloaded_error)"),
            "{chunks:?}"
        );
    }

    #[test]
    fn unknown_events_and_deltas_are_ignored() {
        let [delta, end] = stop("end_turn", 3);
        let chunks = run(&[
            start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "thinking", "thinking": "" } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "thinking_delta", "thinking": "private" } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            json!({ "type": "future_event", "data": 1 }),
            delta,
            end,
        ]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].as_ref().unwrap().finish_reason,
            Some(FinishReason::Stop)
        );
    }

    #[test]
    fn end_without_message_stop_is_unavailable() {
        let chunks = run(&[
            start(),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "partial" } }),
        ]);
        assert_eq!(chunks.len(), 2);
        assert!(
            matches!(&chunks[1], Err(Error::Unavailable(text))
                if text == "the stream of provider p ended before the answer was complete"),
            "{chunks:?}"
        );
    }
}
