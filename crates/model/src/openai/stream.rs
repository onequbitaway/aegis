//! The assembler for a streamed chat-completions answer.

use aegis_contracts::model::{ChatChunk, ToolCall, Usage};
use aegis_contracts::{Error, Result};
use serde_json::Value;

use super::wire::{self, CallFragment, StreamEvent};
use crate::convert::{call_id, parse_arguments};
use crate::http::{Secrets, json_fault};
use crate::sse::{Assembler, Chunks, SseEvent};

/// The marker that ends a streamed answer.
const DONE: &str = "[DONE]";

#[derive(Debug, Default)]
struct PartialCall {
    index: Option<u32>,
    id: String,
    name: String,
    arguments: String,
}

/// Collects the events of one streamed answer.
///
/// The assembler emits each text delta immediately. It holds the tool calls, the finish
/// reason, and the usage for the last chunk, because the provider sends them in separate
/// events.
pub(super) struct ChatAssembler {
    provider: String,
    secrets: Secrets,
    calls: Vec<PartialCall>,
    finish_reason: Option<String>,
    usage: Option<Usage>,
}

impl ChatAssembler {
    pub(super) fn new(provider: &str, secrets: Secrets) -> Self {
        Self {
            provider: provider.to_owned(),
            secrets,
            calls: Vec::new(),
            finish_reason: None,
            usage: None,
        }
    }

    /// Returns the position of the call that a fragment continues, if there is one.
    fn open_call(&self, index: Option<u32>, id: Option<&str>) -> Option<usize> {
        match (index, id) {
            // Some local servers give the same index to each call. A different identifier
            // then shows a different call.
            (Some(index), Some(id)) => self.calls.iter().rposition(|call| {
                call.index == Some(index) && (call.id.is_empty() || call.id == id)
            }),
            (Some(index), None) => self
                .calls
                .iter()
                .rposition(|call| call.index == Some(index)),
            // A server that sends no index sends a new identifier for each new call.
            (None, Some(id)) => self.calls.iter().rposition(|call| call.id == id),
            (None, None) => self.calls.len().checked_sub(1),
        }
    }

    fn fragment(&mut self, fragment: CallFragment) {
        let id = fragment.id.filter(|id| !id.is_empty());
        let position = match self.open_call(fragment.index, id.as_deref()) {
            Some(position) => position,
            None => {
                self.calls.push(PartialCall {
                    index: fragment.index,
                    ..PartialCall::default()
                });
                self.calls.len().saturating_sub(1)
            }
        };
        let Some(call) = self.calls.get_mut(position) else {
            return;
        };
        if let Some(id) = id {
            call.id = id;
        }
        let function = fragment.function.unwrap_or_default();
        if let Some(name) = function.name {
            call.name.push_str(&name);
        }
        match function.arguments {
            Value::String(text) => call.arguments.push_str(&text),
            Value::Null => {}
            // Some servers send the complete arguments as one JSON value.
            other => call.arguments = other.to_string(),
        }
    }

    fn tool_calls(&mut self) -> Result<Vec<ToolCall>> {
        let mut calls = std::mem::take(&mut self.calls);
        // The sort is stable, so calls with one index keep the order of arrival.
        calls.sort_by_key(|call| call.index);
        calls
            .into_iter()
            .enumerate()
            .map(|(position, call)| {
                let arguments = parse_arguments(&self.provider, &call.name, &call.arguments)?;
                Ok(ToolCall {
                    id: call_id(Some(call.id), position),
                    name: call.name,
                    arguments,
                })
            })
            .collect()
    }

    fn last_chunk(&mut self) -> Result<ChatChunk> {
        let tool_calls = self.tool_calls()?;
        let finish_reason =
            wire::finish_reason(self.finish_reason.as_deref(), !tool_calls.is_empty());
        Ok(ChatChunk {
            delta: String::new(),
            tool_calls,
            finish_reason: Some(finish_reason),
            usage: self.usage.take(),
        })
    }

    /// Handles one decoded event. Returns `Ok(false)` when the answer is complete.
    fn handle(&mut self, event: &SseEvent, chunks: &mut Chunks) -> Result<bool> {
        if event.data.trim() == DONE {
            chunks.push_back(Ok(self.last_chunk()?));
            return Ok(false);
        }
        let parsed: StreamEvent = serde_json::from_str(&event.data).map_err(|error| {
            Error::Serialization(format!(
                "provider {} sent a stream event that could not be decoded: {}",
                self.provider,
                json_fault(&error)
            ))
        })?;
        if let Some(error) = &parsed.error {
            let labels = self.secrets.labels(Some(error));
            return Err(Error::Unavailable(format!(
                "provider {} reported an error in the stream{labels}",
                self.provider
            )));
        }
        if let Some(usage) = parsed.usage {
            self.usage = Some(usage.into());
        }
        let Some(choice) = parsed.choices.into_iter().next() else {
            return Ok(true);
        };
        let delta = choice.delta.unwrap_or_default();
        if delta.refusal.is_some_and(|text| !text.is_empty()) {
            return Err(wire::refused(&self.provider));
        }
        if let Some(text) = delta.content.map(wire::Content::into_text)
            && !text.is_empty()
        {
            chunks.push_back(Ok(ChatChunk {
                delta: text,
                ..ChatChunk::default()
            }));
        }
        for fragment in delta.tool_calls.unwrap_or_default() {
            self.fragment(fragment);
        }
        if let Some(reason) = choice.finish_reason {
            if reason == "content_filter" {
                return Err(wire::filtered(&self.provider));
            }
            self.finish_reason = Some(reason);
        }
        Ok(true)
    }
}

impl Assembler for ChatAssembler {
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
        // A server can omit the end marker. The finish reason then shows a complete answer.
        let chunk = if self.finish_reason.is_some() {
            self.last_chunk()
        } else {
            Err(Error::Unavailable(format!(
                "the stream of provider {} ended before the answer was complete",
                self.provider
            )))
        };
        chunks.push_back(chunk);
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::FinishReason;
    use serde_json::json;

    use super::*;
    use crate::sse::assemble;

    fn event(value: &Value) -> SseEvent {
        SseEvent {
            event: None,
            data: value.to_string(),
        }
    }

    fn done() -> SseEvent {
        SseEvent {
            event: None,
            data: DONE.to_owned(),
        }
    }

    fn run(events: &[SseEvent]) -> Vec<Result<ChatChunk>> {
        assemble(ChatAssembler::new("p", Secrets::default()), events)
    }

    fn delta(delta: Value) -> SseEvent {
        event(
            &json!({ "choices": [{ "index": 0, "delta": delta, "finish_reason": null }], "usage": null }),
        )
    }

    fn finish(reason: &str) -> SseEvent {
        event(&json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }] }))
    }

    #[test]
    fn text_deltas_pass_through_and_the_last_chunk_has_the_reason_and_the_usage() {
        let chunks = run(&[
            delta(json!({ "role": "assistant", "content": "" })),
            delta(json!({ "content": "true " })),
            delta(json!({ "content": "positive" })),
            finish("stop"),
            event(
                &json!({ "choices": [], "usage": { "prompt_tokens": 12, "completion_tokens": 3 } }),
            ),
            done(),
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
                        input_tokens: 12,
                        output_tokens: 3,
                    }),
                },
            ]
        );
    }

    #[test]
    fn tool_call_fragments_become_complete_calls_in_the_last_chunk() {
        let chunks = run(&[
            delta(
                json!({ "tool_calls": [{ "index": 0, "id": "call_a", "type": "function", "function": { "name": "lookup_ip", "arguments": "" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 0, "function": { "arguments": "{\"ip\":" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 1, "id": "call_b", "type": "function", "function": { "name": "list_sessions", "arguments": "{\"user\"" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 0, "function": { "arguments": "\"203.0.113.7\"}" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 1, "function": { "arguments": ":\"amy\"}" } }] }),
            ),
            finish("tool_calls"),
            done(),
        ]);
        assert_eq!(chunks.len(), 1);
        let last = chunks.into_iter().next().unwrap().unwrap();
        assert_eq!(
            last,
            ChatChunk {
                delta: String::new(),
                tool_calls: vec![
                    ToolCall {
                        id: "call_a".to_owned(),
                        name: "lookup_ip".to_owned(),
                        arguments: json!({ "ip": "203.0.113.7" }),
                    },
                    ToolCall {
                        id: "call_b".to_owned(),
                        name: "list_sessions".to_owned(),
                        arguments: json!({ "user": "amy" }),
                    },
                ],
                finish_reason: Some(FinishReason::ToolCalls),
                usage: None,
            }
        );
    }

    #[test]
    fn fragments_without_an_index_start_a_new_call_at_each_identifier() {
        let chunks = run(&[
            delta(
                json!({ "tool_calls": [{ "id": "call_a", "function": { "name": "first", "arguments": "{\"a\"" } }] }),
            ),
            delta(json!({ "tool_calls": [{ "function": { "arguments": ":1}" } }] })),
            delta(
                json!({ "tool_calls": [{ "id": "call_b", "function": { "name": "second", "arguments": { "b": 2 } } }] }),
            ),
            finish("stop"),
        ]);
        assert_eq!(chunks.len(), 1);
        let last = chunks.into_iter().next().unwrap().unwrap();
        assert_eq!(
            last.tool_calls,
            vec![
                ToolCall {
                    id: "call_a".to_owned(),
                    name: "first".to_owned(),
                    arguments: json!({ "a": 1 }),
                },
                ToolCall {
                    id: "call_b".to_owned(),
                    name: "second".to_owned(),
                    arguments: json!({ "b": 2 }),
                },
            ]
        );
        assert_eq!(last.finish_reason, Some(FinishReason::ToolCalls));
    }

    #[test]
    fn calls_with_one_index_and_different_identifiers_stay_separate() {
        let chunks = run(&[
            delta(
                json!({ "tool_calls": [{ "index": 0, "id": "call_a", "type": "function", "function": { "name": "lookup_ip", "arguments": "{\"ip\":\"203.0.113.7\"}" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 0, "id": "call_b", "type": "function", "function": { "name": "list_sessions", "arguments": "{\"user\":" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 0, "function": { "arguments": "\"amy\"}" } }] }),
            ),
            finish("tool_calls"),
            done(),
        ]);
        assert_eq!(chunks.len(), 1);
        let last = chunks.into_iter().next().unwrap().unwrap();
        assert_eq!(
            last.tool_calls,
            vec![
                ToolCall {
                    id: "call_a".to_owned(),
                    name: "lookup_ip".to_owned(),
                    arguments: json!({ "ip": "203.0.113.7" }),
                },
                ToolCall {
                    id: "call_b".to_owned(),
                    name: "list_sessions".to_owned(),
                    arguments: json!({ "user": "amy" }),
                },
            ]
        );
    }

    #[test]
    fn fragments_that_repeat_the_identifier_continue_one_call() {
        for index in [json!(0), Value::Null] {
            let chunks = run(&[
                delta(
                    json!({ "tool_calls": [{ "index": index, "id": "call_a", "function": { "name": "lookup_ip", "arguments": "{\"ip\":" } }] }),
                ),
                delta(
                    json!({ "tool_calls": [{ "index": index, "id": "call_a", "function": { "arguments": "\"203.0.113.7\"}" } }] }),
                ),
                finish("tool_calls"),
                done(),
            ]);
            assert_eq!(chunks.len(), 1, "index {index}");
            let last = chunks.into_iter().next().unwrap().unwrap();
            assert_eq!(
                last.tool_calls,
                vec![ToolCall {
                    id: "call_a".to_owned(),
                    name: "lookup_ip".to_owned(),
                    arguments: json!({ "ip": "203.0.113.7" }),
                }],
                "index {index}"
            );
        }
    }

    #[test]
    fn calls_arrive_in_the_order_of_the_index() {
        let chunks = run(&[
            delta(
                json!({ "tool_calls": [{ "index": 1, "id": "call_b", "function": { "name": "second", "arguments": "{}" } }] }),
            ),
            delta(
                json!({ "tool_calls": [{ "index": 0, "id": "call_a", "function": { "name": "first", "arguments": "{}" } }] }),
            ),
            finish("tool_calls"),
            done(),
        ]);
        assert_eq!(chunks.len(), 1);
        let last = chunks.into_iter().next().unwrap().unwrap();
        let names: Vec<&str> = last
            .tool_calls
            .iter()
            .map(|call| call.name.as_str())
            .collect();
        assert_eq!(names, vec!["first", "second"]);
    }

    #[test]
    fn incomplete_arguments_are_an_error_and_not_a_tool_call() {
        let chunks = run(&[
            delta(
                json!({ "tool_calls": [{ "index": 0, "id": "call_a", "function": { "name": "lookup_ip", "arguments": "{\"ip\":" } }] }),
            ),
            finish("tool_calls"),
            done(),
        ]);
        assert_eq!(chunks.len(), 1);
        let error = chunks.into_iter().next().unwrap().unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(text)
                if text == "provider p sent arguments for tool lookup_ip that are not a JSON object"),
            "{error}"
        );
    }

    #[test]
    fn refusal_delta_and_content_filter_end_the_stream_with_refused() {
        let refusal = run(&[delta(json!({ "refusal": "I cannot help." })), done()]);
        assert_eq!(refusal.len(), 1);
        assert!(
            matches!(&refusal[0], Err(Error::Refused(text)) if text == "the model of provider p refused the task"),
            "{refusal:?}"
        );

        let filtered = run(&[
            delta(json!({ "content": "partial" })),
            finish("content_filter"),
            done(),
        ]);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].as_ref().unwrap().delta, "partial");
        assert!(
            matches!(&filtered[1], Err(Error::Refused(text)) if text == "a content filter of provider p stopped the answer"),
            "{filtered:?}"
        );
    }

    #[test]
    fn end_without_a_finish_reason_is_unavailable() {
        let chunks = run(&[delta(json!({ "content": "partial" }))]);
        assert_eq!(chunks.len(), 2);
        assert!(
            matches!(&chunks[1], Err(Error::Unavailable(text))
                if text == "the stream of provider p ended before the answer was complete"),
            "{chunks:?}"
        );
    }

    #[test]
    fn end_without_the_marker_is_complete_when_the_finish_reason_arrived() {
        let chunks = run(&[delta(json!({ "content": "done" })), finish("length")]);
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[1].as_ref().unwrap().finish_reason,
            Some(FinishReason::Length)
        );
    }

    #[test]
    fn error_event_and_invalid_event_end_the_stream() {
        let failed = run(&[event(
            &json!({ "error": { "message": "the prompt was: secret", "type": "server_error" } }),
        )]);
        assert_eq!(failed.len(), 1);
        assert!(
            matches!(&failed[0], Err(Error::Unavailable(text))
                if text == "provider p reported an error in the stream (type server_error)"),
            "{failed:?}"
        );

        let invalid = run(&[SseEvent {
            event: None,
            data: "{not json".to_owned(),
        }]);
        assert_eq!(invalid.len(), 1);
        assert!(
            matches!(&invalid[0], Err(Error::Serialization(text))
                if text == "provider p sent a stream event that could not be decoded: syntax error at line 1 column 2"),
            "{invalid:?}"
        );
    }
}
