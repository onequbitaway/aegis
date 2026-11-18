//! The wire types of the Anthropic Messages API, and their conversions.

use aegis_contracts::model::{
    ChatRequest, ChatResponse, FinishReason, Message, ResponseFormat, Role, ToolCall, ToolChoice,
    Usage,
};
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::convert::{
    JSON_INSTRUCTION, check_request, incoming_arguments, outgoing_arguments, strip_code_fence,
    tool_schema,
};
use crate::http::ErrorLabels;

/// The body of a Messages request.
#[derive(Debug, Serialize)]
pub(super) struct MessagesBody<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WireMessage<'a> {
    role: &'static str,
    content: Vec<Block<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Block<'a> {
    Text {
        text: &'a str,
    },
    ToolUse {
        id: &'a str,
        name: &'a str,
        input: Value,
    },
    ToolResult {
        tool_use_id: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        content: &'a str,
    },
}

#[derive(Debug, Serialize)]
struct WireTool<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    description: &'a str,
    input_schema: Value,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireToolChoice<'a> {
    Auto,
    None,
    Any,
    Tool { name: &'a str },
}

/// Converts one message to its role and its content blocks. A system message gives no blocks.
fn blocks(position: usize, message: &Message) -> Result<(&'static str, Vec<Block<'_>>)> {
    let text = (!message.content.is_empty()).then_some(Block::Text {
        text: &message.content,
    });
    match message.role {
        Role::System => Ok(("user", Vec::new())),
        Role::User => Ok(("user", text.into_iter().collect())),
        Role::Assistant => {
            let mut blocks: Vec<Block<'_>> = text.into_iter().collect();
            for call in &message.tool_calls {
                blocks.push(Block::ToolUse {
                    id: &call.id,
                    name: &call.name,
                    input: outgoing_arguments(&call.name, &call.arguments)?,
                });
            }
            Ok(("assistant", blocks))
        }
        Role::Tool => match message.tool_call_id.as_deref() {
            Some(id) if !id.is_empty() => Ok((
                "user",
                vec![Block::ToolResult {
                    tool_use_id: id,
                    content: &message.content,
                }],
            )),
            _ => Err(Error::InvalidInput(format!(
                "message {position} has the tool role but no tool_call_id"
            ))),
        },
    }
}

/// Converts a chat request to the body of a Messages request.
///
/// The API takes the system prompt as a separate field. It also requires that the roles
/// alternate, so the conversion joins adjacent messages of one role. All results of one
/// set of tool calls thus go into one `user` message.
pub(super) fn messages_body<'a>(
    request: &'a ChatRequest,
    model: &'a str,
    default_max_tokens: u32,
    stream: bool,
) -> Result<MessagesBody<'a>> {
    check_request(request)?;
    let mut system: Vec<&str> = request
        .messages
        .iter()
        .filter(|message| message.role == Role::System && !message.content.is_empty())
        .map(|message| message.content.as_str())
        .collect();
    if request.response_format == ResponseFormat::Json {
        system.push(JSON_INSTRUCTION);
    }
    let mut messages: Vec<WireMessage<'a>> = Vec::new();
    for (position, message) in request.messages.iter().enumerate() {
        let (role, blocks) = blocks(position, message)?;
        if blocks.is_empty() {
            continue;
        }
        match messages.last_mut() {
            Some(last) if last.role == role => last.content.extend(blocks),
            _ => messages.push(WireMessage {
                role,
                content: blocks,
            }),
        }
    }
    if messages.is_empty() {
        return Err(Error::InvalidInput(
            "the chat request has no user message and no assistant message with content".to_owned(),
        ));
    }
    let tools = request
        .tools
        .iter()
        .map(|tool| {
            Ok(WireTool {
                name: &tool.name,
                description: &tool.description,
                input_schema: tool_schema(tool)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some(match &request.tool_choice {
            ToolChoice::Auto => WireToolChoice::Auto,
            ToolChoice::None => WireToolChoice::None,
            ToolChoice::Required => WireToolChoice::Any,
            ToolChoice::Tool(name) => WireToolChoice::Tool { name },
        })
    };
    Ok(MessagesBody {
        model,
        max_tokens: request.max_output_tokens.unwrap_or(default_max_tokens),
        system: (!system.is_empty()).then(|| system.join("\n\n")),
        messages,
        tools,
        tool_choice,
        temperature: request.temperature,
        stream: stream.then_some(true),
    })
}

/// The token counts in an answer or in a stream event.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub(super) struct WireUsage {
    #[serde(default)]
    pub(super) input_tokens: Option<u64>,
    #[serde(default)]
    pub(super) output_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
}

impl WireUsage {
    /// Returns all input tokens. The API reports cached input tokens in separate fields.
    pub(super) fn input(&self) -> Option<u64> {
        self.input_tokens.map(|tokens| {
            tokens
                .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
                .saturating_add(self.cache_read_input_tokens.unwrap_or(0))
        })
    }
}

impl From<WireUsage> for Usage {
    fn from(usage: WireUsage) -> Self {
        Self {
            input_tokens: usage.input().unwrap_or(0),
            output_tokens: usage.output_tokens.unwrap_or(0),
        }
    }
}

/// One content block of an answer.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum AnswerBlock {
    Text {
        #[serde(default)]
        text: String,
    },
    ToolUse {
        #[serde(default)]
        id: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        input: Value,
    },
    /// A block type that the adapter does not use, for example a thinking block.
    #[serde(other)]
    Other,
}

/// The body of a Messages answer.
#[derive(Debug, Deserialize)]
pub(super) struct MessagesAnswer {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    content: Vec<AnswerBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

/// Makes the error for an answer in which the model refused the task.
pub(super) fn refused(provider: &str) -> Error {
    Error::Refused(format!("the model of provider {provider} refused the task"))
}

/// Maps the stop reason of the wire format. `refusal` is an error, not a reason.
pub(super) fn finish_reason(reason: Option<&str>) -> FinishReason {
    match reason {
        Some("end_turn" | "stop_sequence") => FinishReason::Stop,
        Some("max_tokens" | "model_context_window_exceeded") => FinishReason::Length,
        Some("tool_use") => FinishReason::ToolCalls,
        _ => FinishReason::Other,
    }
}

/// Converts a Messages answer to a chat response.
pub(super) fn chat_response(
    provider: &str,
    requested_model: &str,
    response_format: ResponseFormat,
    answer: MessagesAnswer,
) -> Result<ChatResponse> {
    if answer.stop_reason.as_deref() == Some("refusal") {
        return Err(refused(provider));
    }
    let mut content = String::new();
    let mut tool_calls = Vec::new();
    for block in answer.content {
        match block {
            AnswerBlock::Text { text } => content.push_str(&text),
            AnswerBlock::ToolUse { id, name, input } => {
                let arguments = incoming_arguments(provider, &name, input)?;
                tool_calls.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
            AnswerBlock::Other => {}
        }
    }
    if response_format == ResponseFormat::Json {
        content = strip_code_fence(&content).to_owned();
    }
    Ok(ChatResponse {
        provider: provider.to_owned(),
        model: answer
            .model
            .filter(|model| !model.is_empty())
            .unwrap_or_else(|| requested_model.to_owned()),
        message: Message {
            role: Role::Assistant,
            content,
            tool_calls,
            tool_call_id: None,
        },
        finish_reason: finish_reason(answer.stop_reason.as_deref()),
        usage: answer.usage.map(Usage::from).unwrap_or_default(),
    })
}

/// One event of a streamed Messages answer.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum StreamEvent {
    MessageStart {
        #[serde(default)]
        message: StartMessage,
    },
    ContentBlockStart {
        index: u32,
        content_block: AnswerBlock,
    },
    ContentBlockDelta {
        index: u32,
        delta: BlockDelta,
    },
    ContentBlockStop {
        index: u32,
    },
    MessageDelta {
        #[serde(default)]
        delta: MessageDelta,
        #[serde(default)]
        usage: Option<WireUsage>,
    },
    MessageStop,
    Error {
        #[serde(default)]
        error: Value,
    },
    /// A `ping` event, or an event type that the API added after this adapter.
    #[serde(other)]
    Other,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct StartMessage {
    #[serde(default)]
    pub(super) usage: Option<WireUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum BlockDelta {
    TextDelta {
        #[serde(default)]
        text: String,
    },
    InputJsonDelta {
        #[serde(default)]
        partial_json: String,
    },
    /// A delta type that the adapter does not use, for example a thinking delta.
    #[serde(other)]
    Other,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct MessageDelta {
    #[serde(default)]
    pub(super) stop_reason: Option<String>,
}

/// Maps the error identifiers of a stream event to a contract error.
pub(super) fn stream_error(provider: &str, labels: &ErrorLabels) -> Error {
    let message = format!("provider {provider} reported an error in the stream{labels}");
    match labels.kind.as_deref() {
        Some("rate_limit_error") => Error::RateLimited(message),
        Some("authentication_error" | "permission_error") => Error::Unauthorized(message),
        Some("invalid_request_error" | "request_too_large") => Error::InvalidInput(message),
        Some("not_found_error") => Error::NotFound(message),
        Some("timeout_error") => Error::Timeout(message),
        _ => Error::Unavailable(message),
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::{TaskKind, ToolSpec};
    use serde_json::json;

    use super::*;

    /// Returns the body as the provider reads it from the wire.
    fn body(request: &ChatRequest) -> Value {
        let text = serde_json::to_string(&messages_body(request, "c1", 1024, false).unwrap());
        serde_json::from_str(&text.unwrap()).unwrap()
    }

    #[test]
    fn minimal_request_has_the_model_the_limit_and_the_messages() {
        let request = ChatRequest::new(TaskKind::Analysis, vec![Message::user("hello")]);
        assert_eq!(
            body(&request),
            json!({
                "model": "c1",
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": [{ "type": "text", "text": "hello" }] }],
            })
        );
    }

    #[test]
    fn system_messages_move_to_the_system_field() {
        let request = ChatRequest {
            max_output_tokens: Some(64),
            temperature: Some(0.5),
            ..ChatRequest::new(
                TaskKind::Analysis,
                vec![
                    Message::system("You are a security analyst."),
                    Message::user("first"),
                    Message::system("Answer in one sentence."),
                    Message::user("second"),
                ],
            )
        };
        assert_eq!(
            body(&request),
            json!({
                "model": "c1",
                "max_tokens": 64,
                "system": "You are a security analyst.\n\nAnswer in one sentence.",
                "messages": [{
                    "role": "user",
                    "content": [{ "type": "text", "text": "first" }, { "type": "text", "text": "second" }],
                }],
                "temperature": 0.5,
            })
        );
    }

    #[test]
    fn json_format_adds_the_instruction_to_the_system_field() {
        let mut request = ChatRequest::new(TaskKind::Analysis, vec![Message::user("classify")]);
        request.response_format = ResponseFormat::Json;
        assert_eq!(body(&request)["system"], json!(JSON_INSTRUCTION));

        request
            .messages
            .insert(0, Message::system("You are a security analyst."));
        assert_eq!(
            body(&request)["system"],
            json!(format!("You are a security analyst.\n\n{JSON_INSTRUCTION}"))
        );
    }

    #[test]
    fn each_tool_choice_maps_to_the_wire_value() {
        let tool = ToolSpec {
            name: "lookup_ip".to_owned(),
            description: "Looks up an address.".to_owned(),
            parameters: json!({ "type": "object", "properties": { "ip": { "type": "string" } } }),
        };
        let cases = [
            (ToolChoice::Auto, json!({ "type": "auto" })),
            (ToolChoice::None, json!({ "type": "none" })),
            (ToolChoice::Required, json!({ "type": "any" })),
            (
                ToolChoice::Tool("lookup_ip".to_owned()),
                json!({ "type": "tool", "name": "lookup_ip" }),
            ),
        ];
        for (choice, expected) in cases {
            let request = ChatRequest {
                tools: vec![tool.clone()],
                tool_choice: choice.clone(),
                ..ChatRequest::new(TaskKind::Analysis, vec![Message::user("hello")])
            };
            let body = body(&request);
            assert_eq!(body["tool_choice"], expected, "{choice:?}");
            assert_eq!(
                body["tools"],
                json!([{
                    "name": "lookup_ip",
                    "description": "Looks up an address.",
                    "input_schema": { "type": "object", "properties": { "ip": { "type": "string" } } },
                }])
            );
        }
    }

    #[test]
    fn empty_messages_are_left_out_and_a_request_with_no_content_is_invalid() {
        let request = ChatRequest::new(
            TaskKind::Analysis,
            vec![
                Message::user("question"),
                Message::assistant(""),
                Message::user("again"),
            ],
        );
        assert_eq!(
            body(&request)["messages"],
            json!([{
                "role": "user",
                "content": [{ "type": "text", "text": "question" }, { "type": "text", "text": "again" }],
            }])
        );

        let only_system = ChatRequest::new(TaskKind::Analysis, vec![Message::system("rules")]);
        let error = messages_body(&only_system, "c1", 1024, false).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(text)
                if text == "the chat request has no user message and no assistant message with content"),
            "{error}"
        );
    }

    #[test]
    fn tool_message_without_a_call_identifier_is_invalid() {
        let mut message = Message::tool("toolu_1", "result");
        message.tool_call_id = None;
        let request = ChatRequest::new(TaskKind::Analysis, vec![Message::user("hello"), message]);
        let error = messages_body(&request, "c1", 1024, false).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(text) if text == "message 1 has the tool role but no tool_call_id"),
            "{error}"
        );
    }

    #[test]
    fn finish_reason_maps_each_wire_value() {
        assert_eq!(finish_reason(Some("end_turn")), FinishReason::Stop);
        assert_eq!(finish_reason(Some("stop_sequence")), FinishReason::Stop);
        assert_eq!(finish_reason(Some("max_tokens")), FinishReason::Length);
        assert_eq!(finish_reason(Some("tool_use")), FinishReason::ToolCalls);
        assert_eq!(finish_reason(Some("pause_turn")), FinishReason::Other);
        assert_eq!(finish_reason(None), FinishReason::Other);
    }

    #[test]
    fn usage_counts_cached_input_tokens_as_input() {
        let usage: WireUsage = serde_json::from_value(json!({
            "input_tokens": 10,
            "cache_creation_input_tokens": 5,
            "cache_read_input_tokens": 100,
            "output_tokens": 7,
        }))
        .unwrap();
        assert_eq!(
            Usage::from(usage),
            Usage {
                input_tokens: 115,
                output_tokens: 7,
            }
        );
    }

    #[test]
    fn unknown_blocks_are_ignored_and_json_answers_lose_the_code_fence() {
        let answer = || -> MessagesAnswer {
            serde_json::from_value(json!({
                "model": "c1-2025",
                "content": [
                    { "type": "thinking", "thinking": "private", "signature": "s" },
                    { "type": "text", "text": "```json\n{\"verdict\":\"benign\"}\n```" },
                ],
                "stop_reason": "end_turn",
                "usage": { "input_tokens": 9, "output_tokens": 4 },
            }))
            .unwrap()
        };
        let json = chat_response("p", "c1", ResponseFormat::Json, answer()).unwrap();
        assert_eq!(json.message.content, "{\"verdict\":\"benign\"}");
        assert_eq!(json.model, "c1-2025");
        let text = chat_response("p", "c1", ResponseFormat::Text, answer()).unwrap();
        assert_eq!(
            text.message.content,
            "```json\n{\"verdict\":\"benign\"}\n```"
        );
    }

    #[test]
    fn stream_error_maps_each_error_type() {
        let map = |kind: &str| {
            let labels = ErrorLabels {
                kind: Some(kind.to_owned()),
                code: None,
            };
            stream_error("p", &labels)
        };
        assert!(matches!(map("overloaded_error"), Error::Unavailable(_)));
        assert!(matches!(map("api_error"), Error::Unavailable(_)));
        assert!(matches!(map("rate_limit_error"), Error::RateLimited(_)));
        assert!(matches!(
            map("authentication_error"),
            Error::Unauthorized(_)
        ));
        assert!(matches!(map("permission_error"), Error::Unauthorized(_)));
        assert!(matches!(
            map("invalid_request_error"),
            Error::InvalidInput(_)
        ));
        assert!(matches!(map("not_found_error"), Error::NotFound(_)));
        assert!(matches!(map("timeout_error"), Error::Timeout(_)));
        assert_eq!(
            map("overloaded_error").to_string(),
            "unavailable: provider p reported an error in the stream (type overloaded_error)"
        );
        assert!(matches!(
            stream_error("p", &ErrorLabels::default()),
            Error::Unavailable(_)
        ));
    }
}
