//! The wire types of the OpenAI chat-completions format, and their conversions.

use std::borrow::Cow;

use aegis_contracts::model::{
    ChatRequest, ChatResponse, EmbeddingResponse, FinishReason, Message, ResponseFormat, Role,
    ToolCall, ToolChoice, Usage,
};
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::MaxTokensField;
use crate::convert::{
    JSON_INSTRUCTION, call_id, check_request, incoming_arguments, outgoing_arguments, tool_schema,
};

/// The body of a chat-completions request.
#[derive(Debug, Serialize)]
pub(super) struct ChatBody<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<WireResponseFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<StreamOptions>,
}

#[derive(Debug, Serialize)]
struct WireMessage<'a> {
    role: &'static str,
    content: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<WireToolCall<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct WireToolCall<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireFunctionCall<'a>,
}

#[derive(Debug, Serialize)]
struct WireFunctionCall<'a> {
    name: &'a str,
    arguments: String,
}

#[derive(Debug, Serialize)]
struct WireTool<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireFunction<'a>,
}

#[derive(Debug, Serialize)]
struct WireFunction<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    description: &'a str,
    parameters: Value,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WireToolChoice<'a> {
    Mode(&'static str),
    Function {
        #[serde(rename = "type")]
        kind: &'static str,
        function: WireFunctionName<'a>,
    },
}

#[derive(Debug, Serialize)]
struct WireFunctionName<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct WireResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct StreamOptions {
    include_usage: bool,
}

fn wire_message(position: usize, message: &Message) -> Result<WireMessage<'_>> {
    let role = match message.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };
    let tool_call_id = match (message.role, message.tool_call_id.as_deref()) {
        (Role::Tool, Some(id)) if !id.is_empty() => Some(id),
        (Role::Tool, _) => {
            return Err(Error::InvalidInput(format!(
                "message {position} has the tool role but no tool_call_id"
            )));
        }
        _ => None,
    };
    let tool_calls = if message.role == Role::Assistant {
        message
            .tool_calls
            .iter()
            .map(|call| {
                let arguments = outgoing_arguments(&call.name, &call.arguments)?;
                Ok(WireToolCall {
                    id: &call.id,
                    kind: "function",
                    function: WireFunctionCall {
                        name: &call.name,
                        arguments: arguments.to_string(),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    // The format uses `null` for an assistant message that has only tool calls.
    let content = if message.content.is_empty() && !tool_calls.is_empty() {
        None
    } else {
        Some(Cow::Borrowed(message.content.as_str()))
    };
    Ok(WireMessage {
        role,
        content,
        tool_calls,
        tool_call_id,
    })
}

/// Returns `true` if a message of the request has the word "JSON".
fn mentions_json(request: &ChatRequest) -> bool {
    request
        .messages
        .iter()
        .any(|message| message.content.to_ascii_lowercase().contains("json"))
}

/// Adds the JSON instruction to the first system message, or makes a system message.
///
/// Some chat templates of local models accept only one system message, at the start.
fn add_json_instruction(messages: &mut Vec<WireMessage<'_>>) {
    match messages.first_mut() {
        Some(first) if first.role == "system" => {
            let text = first.content.take().unwrap_or_default();
            first.content = Some(Cow::Owned(if text.is_empty() {
                JSON_INSTRUCTION.to_owned()
            } else {
                format!("{text}\n\n{JSON_INSTRUCTION}")
            }));
        }
        _ => messages.insert(
            0,
            WireMessage {
                role: "system",
                content: Some(Cow::Borrowed(JSON_INSTRUCTION)),
                tool_calls: Vec::new(),
                tool_call_id: None,
            },
        ),
    }
}

/// Converts a chat request to the body of a chat-completions request.
pub(super) fn chat_body<'a>(
    request: &'a ChatRequest,
    model: &'a str,
    max_tokens_field: MaxTokensField,
    stream: bool,
) -> Result<ChatBody<'a>> {
    check_request(request)?;
    let mut messages = request
        .messages
        .iter()
        .enumerate()
        .map(|(position, message)| wire_message(position, message))
        .collect::<Result<Vec<_>>>()?;
    // Hosted APIs reject JSON mode when no message has the word "JSON". A local model can
    // write only white space in JSON mode when no message tells it to write JSON.
    if request.response_format == ResponseFormat::Json && !mentions_json(request) {
        add_json_instruction(&mut messages);
    }
    let tools = request
        .tools
        .iter()
        .map(|tool| {
            Ok(WireTool {
                kind: "function",
                function: WireFunction {
                    name: &tool.name,
                    description: &tool.description,
                    parameters: tool_schema(tool)?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some(match &request.tool_choice {
            ToolChoice::Auto => WireToolChoice::Mode("auto"),
            ToolChoice::None => WireToolChoice::Mode("none"),
            ToolChoice::Required => WireToolChoice::Mode("required"),
            ToolChoice::Tool(name) => WireToolChoice::Function {
                kind: "function",
                function: WireFunctionName { name },
            },
        })
    };
    let (max_tokens, max_completion_tokens) = match max_tokens_field {
        MaxTokensField::MaxTokens => (request.max_output_tokens, None),
        MaxTokensField::MaxCompletionTokens => (None, request.max_output_tokens),
    };
    Ok(ChatBody {
        model,
        messages,
        tools,
        tool_choice,
        response_format: match request.response_format {
            ResponseFormat::Text => None,
            ResponseFormat::Json => Some(WireResponseFormat {
                kind: "json_object",
            }),
        },
        temperature: request.temperature,
        max_tokens,
        max_completion_tokens,
        stream: stream.then_some(true),
        stream_options: stream.then_some(StreamOptions {
            include_usage: true,
        }),
    })
}

/// The token counts in an answer.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub(super) struct WireUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

impl From<WireUsage> for Usage {
    fn from(usage: WireUsage) -> Self {
        Self {
            input_tokens: usage.prompt_tokens.unwrap_or(0),
            output_tokens: usage.completion_tokens.unwrap_or(0),
        }
    }
}

/// The text of a message. Some gateways send a list of parts.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum Content {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Deserialize)]
pub(super) struct ContentPart {
    #[serde(default)]
    text: Option<String>,
}

impl Content {
    pub(super) fn into_text(self) -> String {
        match self {
            Self::Text(text) => text,
            Self::Parts(parts) => parts.into_iter().filter_map(|part| part.text).collect(),
        }
    }
}

/// The body of a chat-completions answer.
#[derive(Debug, Deserialize)]
pub(super) struct Completion {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    #[serde(default)]
    message: Option<AnswerMessage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AnswerMessage {
    #[serde(default)]
    content: Option<Content>,
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<AnswerToolCall>>,
}

#[derive(Debug, Deserialize)]
struct AnswerToolCall {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<AnswerFunction>,
}

#[derive(Debug, Default, Deserialize)]
struct AnswerFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Value,
}

/// Makes the error for an answer that a content filter of the provider stopped.
pub(super) fn filtered(provider: &str) -> Error {
    Error::Refused(format!(
        "a content filter of provider {provider} stopped the answer"
    ))
}

/// Makes the error for an answer in which the model refused the task.
pub(super) fn refused(provider: &str) -> Error {
    Error::Refused(format!("the model of provider {provider} refused the task"))
}

/// Maps the finish reason of the wire format. `content_filter` is a refusal, not a reason.
pub(super) fn finish_reason(reason: Option<&str>, has_tool_calls: bool) -> FinishReason {
    match reason {
        // Some servers report `stop` for an answer that requests tool calls.
        Some("stop") | None if has_tool_calls => FinishReason::ToolCalls,
        Some("stop") => FinishReason::Stop,
        Some("length") => FinishReason::Length,
        Some("tool_calls" | "function_call") => FinishReason::ToolCalls,
        Some("content_filter") => FinishReason::ContentFilter,
        _ => FinishReason::Other,
    }
}

/// Converts a chat-completions answer to a chat response.
pub(super) fn chat_response(
    provider: &str,
    requested_model: &str,
    completion: Completion,
) -> Result<ChatResponse> {
    let choice = completion.choices.into_iter().next().ok_or_else(|| {
        Error::Serialization(format!("provider {provider} sent an answer with no choice"))
    })?;
    if choice.finish_reason.as_deref() == Some("content_filter") {
        return Err(filtered(provider));
    }
    let answer = choice.message.unwrap_or_default();
    if answer.refusal.is_some_and(|text| !text.is_empty()) {
        return Err(refused(provider));
    }
    let tool_calls = answer
        .tool_calls
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(position, call)| {
            let function = call.function.unwrap_or_default();
            let name = function.name.unwrap_or_default();
            let arguments = incoming_arguments(provider, &name, function.arguments)?;
            Ok(ToolCall {
                id: call_id(call.id, position),
                name,
                arguments,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let finish_reason = finish_reason(choice.finish_reason.as_deref(), !tool_calls.is_empty());
    Ok(ChatResponse {
        provider: provider.to_owned(),
        model: completion
            .model
            .filter(|model| !model.is_empty())
            .unwrap_or_else(|| requested_model.to_owned()),
        message: Message {
            role: Role::Assistant,
            content: answer.content.map(Content::into_text).unwrap_or_default(),
            tool_calls,
            tool_call_id: None,
        },
        finish_reason,
        usage: completion.usage.map(Usage::from).unwrap_or_default(),
    })
}

/// The body of an embeddings request.
#[derive(Debug, Serialize)]
pub(super) struct EmbeddingBody<'a> {
    pub(super) model: &'a str,
    pub(super) input: &'a [String],
}

/// The body of an embeddings answer.
#[derive(Debug, Deserialize)]
pub(super) struct EmbeddingAnswer {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    data: Vec<EmbeddingItem>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingItem {
    #[serde(default)]
    index: Option<usize>,
    embedding: Vec<f32>,
}

/// Converts an embeddings answer to an embedding response with the vectors in input order.
pub(super) fn embedding_response(
    provider: &str,
    requested_model: &str,
    inputs: usize,
    answer: EmbeddingAnswer,
) -> Result<EmbeddingResponse> {
    let mismatch = || {
        Error::Serialization(format!(
            "provider {provider} did not send one embedding for each of the {inputs} input texts"
        ))
    };
    if answer.data.len() != inputs {
        return Err(mismatch());
    }
    let mut slots: Vec<Option<Vec<f32>>> = vec![None; inputs];
    for (position, item) in answer.data.into_iter().enumerate() {
        let slot = slots
            .get_mut(item.index.unwrap_or(position))
            .ok_or_else(mismatch)?;
        if slot.replace(item.embedding).is_some() {
            return Err(mismatch());
        }
    }
    let embeddings = slots
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(mismatch)?;
    Ok(EmbeddingResponse {
        provider: provider.to_owned(),
        model: answer
            .model
            .filter(|model| !model.is_empty())
            .unwrap_or_else(|| requested_model.to_owned()),
        embeddings,
        usage: answer.usage.map(Usage::from).unwrap_or_default(),
    })
}

/// One event of a streamed chat-completions answer.
#[derive(Debug, Deserialize)]
pub(super) struct StreamEvent {
    #[serde(default)]
    pub(super) choices: Vec<StreamChoice>,
    #[serde(default)]
    pub(super) usage: Option<WireUsage>,
    #[serde(default)]
    pub(super) error: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StreamChoice {
    #[serde(default)]
    pub(super) delta: Option<Delta>,
    #[serde(default)]
    pub(super) finish_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct Delta {
    #[serde(default)]
    pub(super) content: Option<Content>,
    #[serde(default)]
    pub(super) refusal: Option<String>,
    #[serde(default)]
    pub(super) tool_calls: Option<Vec<CallFragment>>,
}

/// A part of one tool call in a streamed answer.
#[derive(Debug, Deserialize)]
pub(super) struct CallFragment {
    #[serde(default)]
    pub(super) index: Option<u32>,
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) function: Option<FunctionFragment>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct FunctionFragment {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) arguments: Value,
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::{TaskKind, ToolSpec};
    use serde_json::json;

    use super::*;

    /// Returns the body as the provider reads it from the wire.
    fn body(request: &ChatRequest, field: MaxTokensField, stream: bool) -> Value {
        let text = serde_json::to_string(&chat_body(request, "m1", field, stream).unwrap());
        serde_json::from_str(&text.unwrap()).unwrap()
    }

    #[test]
    fn minimal_request_has_only_the_model_and_the_messages() {
        let request = ChatRequest::new(TaskKind::Triage, vec![Message::user("hello")]);
        assert_eq!(
            body(&request, MaxTokensField::MaxTokens, false),
            json!({ "model": "m1", "messages": [{ "role": "user", "content": "hello" }] })
        );
    }

    #[test]
    fn stream_request_asks_for_the_usage() {
        let request = ChatRequest::new(TaskKind::Triage, vec![Message::user("hello")]);
        assert_eq!(
            body(&request, MaxTokensField::MaxTokens, true),
            json!({
                "model": "m1",
                "messages": [{ "role": "user", "content": "hello" }],
                "stream": true,
                "stream_options": { "include_usage": true },
            })
        );
    }

    #[test]
    fn json_format_adds_the_instruction_only_when_no_message_has_the_word_json() {
        let json_request = |messages: Vec<Message>| ChatRequest {
            response_format: ResponseFormat::Json,
            ..ChatRequest::new(TaskKind::Triage, messages)
        };
        let format = json!({ "type": "json_object" });

        let no_system = body(
            &json_request(vec![Message::user("classify")]),
            MaxTokensField::MaxTokens,
            false,
        );
        assert_eq!(
            no_system,
            json!({
                "model": "m1",
                "messages": [
                    { "role": "system", "content": JSON_INSTRUCTION },
                    { "role": "user", "content": "classify" },
                ],
                "response_format": format,
            })
        );

        let with_system = body(
            &json_request(vec![
                Message::system("You are a security analyst."),
                Message::user("classify"),
            ]),
            MaxTokensField::MaxTokens,
            false,
        );
        assert_eq!(
            with_system["messages"],
            json!([
                { "role": "system", "content": format!("You are a security analyst.\n\n{JSON_INSTRUCTION}") },
                { "role": "user", "content": "classify" },
            ])
        );

        let mentioned = body(
            &json_request(vec![
                Message::system("You are a security analyst."),
                Message::user("Classify. Answer in Json."),
            ]),
            MaxTokensField::MaxTokens,
            false,
        );
        assert_eq!(
            mentioned,
            json!({
                "model": "m1",
                "messages": [
                    { "role": "system", "content": "You are a security analyst." },
                    { "role": "user", "content": "Classify. Answer in Json." },
                ],
                "response_format": format,
            })
        );

        // A text request gets no instruction.
        let text = ChatRequest::new(TaskKind::Triage, vec![Message::user("classify")]);
        assert_eq!(
            body(&text, MaxTokensField::MaxTokens, false)["messages"],
            json!([{ "role": "user", "content": "classify" }])
        );
    }

    #[test]
    fn output_limit_uses_the_configured_field() {
        let request = ChatRequest {
            max_output_tokens: Some(256),
            temperature: Some(0.2),
            ..ChatRequest::new(TaskKind::Triage, vec![Message::user("hello")])
        };
        let old = body(&request, MaxTokensField::MaxTokens, false);
        assert_eq!(old["max_tokens"], json!(256));
        assert_eq!(old.get("max_completion_tokens"), None);
        // The wire has the short decimal form of the 32-bit temperature.
        assert_eq!(old["temperature"], json!(0.2));
        let new = body(&request, MaxTokensField::MaxCompletionTokens, false);
        assert_eq!(new["max_completion_tokens"], json!(256));
        assert_eq!(new.get("max_tokens"), None);
    }

    #[test]
    fn each_tool_choice_maps_to_the_wire_value() {
        let tool = ToolSpec {
            name: "lookup_ip".to_owned(),
            description: String::new(),
            parameters: Value::Null,
        };
        let cases = [
            (ToolChoice::Auto, json!("auto")),
            (ToolChoice::None, json!("none")),
            (ToolChoice::Required, json!("required")),
            (
                ToolChoice::Tool("lookup_ip".to_owned()),
                json!({ "type": "function", "function": { "name": "lookup_ip" } }),
            ),
        ];
        for (choice, expected) in cases {
            let request = ChatRequest {
                tools: vec![tool.clone()],
                tool_choice: choice.clone(),
                ..ChatRequest::new(TaskKind::Triage, vec![Message::user("hello")])
            };
            let body = body(&request, MaxTokensField::MaxTokens, false);
            assert_eq!(body["tool_choice"], expected, "{choice:?}");
            assert_eq!(
                body["tools"],
                json!([{
                    "type": "function",
                    "function": {
                        "name": "lookup_ip",
                        "parameters": { "type": "object", "properties": {} },
                    },
                }])
            );
        }
    }

    #[test]
    fn tool_message_without_a_call_identifier_is_invalid() {
        let mut message = Message::tool("call_1", "result");
        message.tool_call_id = None;
        let request = ChatRequest::new(TaskKind::Triage, vec![Message::user("hello"), message]);
        let error = chat_body(&request, "m1", MaxTokensField::MaxTokens, false).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(text) if text == "message 1 has the tool role but no tool_call_id"),
            "{error}"
        );
    }

    #[test]
    fn finish_reason_maps_each_wire_value() {
        assert_eq!(finish_reason(Some("stop"), false), FinishReason::Stop);
        assert_eq!(finish_reason(Some("stop"), true), FinishReason::ToolCalls);
        assert_eq!(finish_reason(None, true), FinishReason::ToolCalls);
        assert_eq!(finish_reason(None, false), FinishReason::Other);
        assert_eq!(finish_reason(Some("length"), false), FinishReason::Length);
        assert_eq!(finish_reason(Some("length"), true), FinishReason::Length);
        assert_eq!(
            finish_reason(Some("tool_calls"), false),
            FinishReason::ToolCalls
        );
        assert_eq!(
            finish_reason(Some("function_call"), false),
            FinishReason::ToolCalls
        );
        assert_eq!(
            finish_reason(Some("content_filter"), false),
            FinishReason::ContentFilter
        );
        assert_eq!(finish_reason(Some("eos"), false), FinishReason::Other);
    }

    #[test]
    fn answer_content_can_be_a_list_of_parts() {
        let completion: Completion = serde_json::from_value(json!({
            "choices": [{
                "message": { "content": [{ "type": "text", "text": "true " }, { "type": "text", "text": "positive" }] },
                "finish_reason": "stop",
            }],
        }))
        .unwrap();
        let response = chat_response("p", "m1", completion).unwrap();
        assert_eq!(response.message.content, "true positive");
        assert_eq!(response.model, "m1");
        assert_eq!(response.usage, Usage::default());
    }

    #[test]
    fn answer_with_no_choice_is_a_serialization_error() {
        let completion: Completion = serde_json::from_value(json!({ "choices": [] })).unwrap();
        let error = chat_response("p", "m1", completion).unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(text) if text == "provider p sent an answer with no choice"),
            "{error}"
        );
    }

    #[test]
    fn tool_call_without_an_identifier_gets_one() {
        let completion: Completion = serde_json::from_value(json!({
            "choices": [{
                "message": { "tool_calls": [{ "function": { "name": "lookup_ip", "arguments": { "ip": "203.0.113.7" } } }] },
                "finish_reason": "stop",
            }],
        }))
        .unwrap();
        let response = chat_response("p", "m1", completion).unwrap();
        assert_eq!(
            response.message.tool_calls,
            vec![ToolCall {
                id: "call_0".to_owned(),
                name: "lookup_ip".to_owned(),
                arguments: json!({ "ip": "203.0.113.7" }),
            }]
        );
        assert_eq!(response.finish_reason, FinishReason::ToolCalls);
    }

    fn embeddings(data: Value) -> Result<EmbeddingResponse> {
        let answer: EmbeddingAnswer = serde_json::from_value(json!({ "data": data })).unwrap();
        embedding_response("p", "e1", 2, answer)
    }

    #[test]
    fn embeddings_follow_the_index_and_not_the_position() {
        let response = embeddings(json!([
            { "index": 1, "embedding": [0.5, 0.5] },
            { "index": 0, "embedding": [1.0, 0.0] },
        ]))
        .unwrap();
        assert_eq!(response.embeddings, vec![vec![1.0, 0.0], vec![0.5, 0.5]]);
        assert_eq!(response.model, "e1");

        let no_index = embeddings(json!([{ "embedding": [1.0] }, { "embedding": [2.0] }])).unwrap();
        assert_eq!(no_index.embeddings, vec![vec![1.0], vec![2.0]]);
    }

    #[test]
    fn embeddings_must_match_the_inputs() {
        let cases = [
            json!([{ "index": 0, "embedding": [1.0] }]),
            json!([{ "index": 0, "embedding": [1.0] }, { "index": 0, "embedding": [2.0] }]),
            json!([{ "index": 0, "embedding": [1.0] }, { "index": 5, "embedding": [2.0] }]),
        ];
        for data in cases {
            let error = embeddings(data.clone()).unwrap_err();
            assert!(
                matches!(&error, Error::Serialization(text)
                    if text == "provider p did not send one embedding for each of the 2 input texts"),
                "{data}: {error}"
            );
        }
    }
}
