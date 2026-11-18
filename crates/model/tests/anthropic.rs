//! Integration tests for the Anthropic adapter against a mock HTTP server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::model::{
    ChatChunk, ChatRequest, ChatResponse, EmbeddingRequest, FinishReason, Message, ModelProvider,
    ResponseFormat, Role, TaskKind, ToolCall, ToolChoice, ToolSpec, Usage,
};
use aegis_model::{AnthropicConfig, AnthropicProvider};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    closed_address, collect, collect_ok, header, json_body, named_sse_body, only_request, requests,
    sse_response, within,
};

const API_KEY: &str = "sk-ant-test-8d2e6b1f90";
const PROMPT: &str = "Classify the sign-in burst from 203.0.113.7.";
const JSON_INSTRUCTION: &str =
    "Answer with one JSON object only. Do not write text before or after the JSON object.";

fn config(server: &MockServer) -> AnthropicConfig {
    AnthropicConfig::new("claude", API_KEY)
        .with_base_url(server.uri())
        .with_chat_model("claude-test")
        .with_timeout(Duration::from_secs(5))
}

fn provider(server: &MockServer) -> AnthropicProvider {
    AnthropicProvider::new(config(server)).unwrap()
}

fn request() -> ChatRequest {
    ChatRequest::new(TaskKind::Analysis, vec![Message::user(PROMPT)])
}

fn answer(content: Value, stop_reason: &str) -> Value {
    json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test-2025",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": { "input_tokens": 30, "output_tokens": 8 },
    })
}

async fn mount_messages(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(response)
        .mount(server)
        .await;
}

fn lookup_tool() -> ToolSpec {
    ToolSpec {
        name: "lookup_ip".to_owned(),
        description: "Returns the reputation of an IP address.".to_owned(),
        parameters: json!({
            "type": "object",
            "properties": { "ip": { "type": "string" } },
            "required": ["ip"],
        }),
    }
}

fn user_text(text: &str) -> Value {
    json!({ "role": "user", "content": [{ "type": "text", "text": text }] })
}

#[tokio::test]
async fn chat_sends_the_system_prompt_and_the_headers_and_returns_the_answer() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "text", "text": "true positive" }]),
            "end_turn",
        )),
    )
    .await;

    let response = provider(&server)
        .chat(ChatRequest {
            temperature: Some(0.5),
            max_output_tokens: Some(256),
            ..ChatRequest::new(
                TaskKind::Analysis,
                vec![
                    Message::system("You are a security analyst."),
                    Message::user(PROMPT),
                ],
            )
        })
        .await
        .unwrap();

    assert_eq!(
        response,
        ChatResponse {
            provider: "claude".to_owned(),
            model: "claude-test-2025".to_owned(),
            message: Message::assistant("true positive"),
            finish_reason: FinishReason::Stop,
            usage: Usage {
                input_tokens: 30,
                output_tokens: 8,
            },
        }
    );
    let sent = only_request(&server).await;
    assert_eq!(header(&sent, "x-api-key"), Some(API_KEY));
    assert_eq!(header(&sent, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(header(&sent, "content-type"), Some("application/json"));
    assert_eq!(header(&sent, "authorization"), None);
    assert_eq!(
        json_body(&sent),
        json!({
            "model": "claude-test",
            "max_tokens": 256,
            "system": "You are a security analyst.",
            "messages": [user_text(PROMPT)],
            "temperature": 0.5,
        })
    );
}

#[tokio::test]
async fn request_without_a_limit_uses_the_default_limit_of_the_provider() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "text", "text": "ok" }]),
            "max_tokens",
        )),
    )
    .await;
    let provider = AnthropicProvider::new(config(&server).with_max_output_tokens(512)).unwrap();
    let mut request = request();
    request.model = Some("claude-strong".to_owned());

    let response = provider.chat(request).await.unwrap();

    assert_eq!(response.finish_reason, FinishReason::Length);
    assert_eq!(
        json_body(&only_request(&server).await),
        json!({ "model": "claude-strong", "max_tokens": 512, "messages": [user_text(PROMPT)] })
    );
}

#[tokio::test]
async fn tool_use_and_tool_results_make_a_round_trip() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer(
            json!([
                { "type": "text", "text": "I will check both addresses." },
                { "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": { "ip": "203.0.113.7" } },
                { "type": "tool_use", "id": "toolu_2", "name": "lookup_ip", "input": { "ip": "198.51.100.9" } },
            ]),
            "tool_use",
        )))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "text", "text": "The first address is malicious." }]),
            "end_turn",
        )),
    )
    .await;
    let provider = provider(&server);
    let first_request = ChatRequest {
        tools: vec![lookup_tool()],
        tool_choice: ToolChoice::Required,
        ..request()
    };

    let first = provider.chat(first_request.clone()).await.unwrap();

    assert_eq!(first.finish_reason, FinishReason::ToolCalls);
    assert_eq!(
        first.message,
        Message {
            role: Role::Assistant,
            content: "I will check both addresses.".to_owned(),
            tool_calls: vec![
                ToolCall {
                    id: "toolu_1".to_owned(),
                    name: "lookup_ip".to_owned(),
                    arguments: json!({ "ip": "203.0.113.7" }),
                },
                ToolCall {
                    id: "toolu_2".to_owned(),
                    name: "lookup_ip".to_owned(),
                    arguments: json!({ "ip": "198.51.100.9" }),
                },
            ],
            tool_call_id: None,
        }
    );

    let mut second_request = first_request;
    second_request.tool_choice = ToolChoice::Auto;
    second_request.messages.push(first.message);
    second_request
        .messages
        .push(Message::tool("toolu_1", "{\"reputation\":\"malicious\"}"));
    second_request
        .messages
        .push(Message::tool("toolu_2", "{\"reputation\":\"clean\"}"));
    let second = provider.chat(second_request).await.unwrap();

    assert_eq!(
        second.message,
        Message::assistant("The first address is malicious.")
    );
    let sent = requests(&server).await;
    assert_eq!(sent.len(), 2);
    let tools = json!([{
        "name": "lookup_ip",
        "description": "Returns the reputation of an IP address.",
        "input_schema": {
            "type": "object",
            "properties": { "ip": { "type": "string" } },
            "required": ["ip"],
        },
    }]);
    assert_eq!(
        json_body(&sent[0]),
        json!({
            "model": "claude-test",
            "max_tokens": 4096,
            "messages": [user_text(PROMPT)],
            "tools": tools,
            "tool_choice": { "type": "any" },
        })
    );
    // The two tool results go into one user message, in the order of the calls.
    assert_eq!(
        json_body(&sent[1]),
        json!({
            "model": "claude-test",
            "max_tokens": 4096,
            "messages": [
                user_text(PROMPT),
                {
                    "role": "assistant",
                    "content": [
                        { "type": "text", "text": "I will check both addresses." },
                        { "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": { "ip": "203.0.113.7" } },
                        { "type": "tool_use", "id": "toolu_2", "name": "lookup_ip", "input": { "ip": "198.51.100.9" } },
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        { "type": "tool_result", "tool_use_id": "toolu_1", "content": "{\"reputation\":\"malicious\"}" },
                        { "type": "tool_result", "tool_use_id": "toolu_2", "content": "{\"reputation\":\"clean\"}" },
                    ],
                },
            ],
            "tools": tools,
            "tool_choice": { "type": "auto" },
        })
    );
}

#[tokio::test]
async fn tool_input_that_is_not_an_object_is_a_serialization_error() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": ["203.0.113.7"] }]),
            "tool_use",
        )),
    )
    .await;

    let error = provider(&server).chat(request()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Serialization(text)
            if text == "provider claude sent arguments for tool lookup_ip that are not a JSON object"),
        "{error}"
    );
}

#[tokio::test]
async fn json_mode_adds_the_instruction_and_removes_a_code_fence() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "text", "text": "```json\n{\"verdict\":\"malicious\"}\n```" }]),
            "end_turn",
        )),
    )
    .await;

    let response = provider(&server)
        .chat(ChatRequest {
            response_format: ResponseFormat::Json,
            ..request()
        })
        .await
        .unwrap();

    assert_eq!(
        serde_json::from_str::<Value>(&response.message.content).unwrap(),
        json!({ "verdict": "malicious" })
    );
    assert_eq!(
        json_body(&only_request(&server).await),
        json!({
            "model": "claude-test",
            "max_tokens": 4096,
            "system": JSON_INSTRUCTION,
            "messages": [user_text(PROMPT)],
        })
    );
}

fn message_start() -> Value {
    json!({
        "type": "message_start",
        "message": {
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test-2025",
            "content": [], "stop_reason": null,
            "usage": { "input_tokens": 30, "output_tokens": 1 },
        },
    })
}

fn message_end(stop_reason: &str, output_tokens: u64) -> [Value; 2] {
    [
        json!({
            "type": "message_delta",
            "delta": { "stop_reason": stop_reason, "stop_sequence": null },
            "usage": { "output_tokens": output_tokens },
        }),
        json!({ "type": "message_stop" }),
    ]
}

fn text_delta(index: u32, text: &str) -> Value {
    json!({ "type": "content_block_delta", "index": index, "delta": { "type": "text_delta", "text": text } })
}

fn json_delta(index: u32, partial_json: &str) -> Value {
    json!({ "type": "content_block_delta", "index": index, "delta": { "type": "input_json_delta", "partial_json": partial_json } })
}

#[tokio::test]
async fn stream_yields_the_text_the_tool_call_and_one_last_chunk() {
    let server = MockServer::start().await;
    let [delta, stop] = message_end("tool_use", 42);
    mount_messages(
        &server,
        sse_response(named_sse_body(&[
            message_start(),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
            json!({ "type": "ping" }),
            text_delta(0, "Checking "),
            text_delta(0, "the address."),
            json!({ "type": "content_block_stop", "index": 0 }),
            json!({ "type": "content_block_start", "index": 1, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "lookup_ip", "input": {} } }),
            json_delta(1, ""),
            json_delta(1, "{\"ip\": \"203"),
            json_delta(1, ".0.113.7\"}"),
            json!({ "type": "content_block_stop", "index": 1 }),
            delta,
            stop,
        ])),
    )
    .await;

    let stream = provider(&server)
        .chat_stream(ChatRequest {
            tools: vec![lookup_tool()],
            ..request()
        })
        .await
        .unwrap();
    let chunks = collect_ok(stream).await;

    assert_eq!(
        chunks,
        vec![
            ChatChunk {
                delta: "Checking ".to_owned(),
                ..ChatChunk::default()
            },
            ChatChunk {
                delta: "the address.".to_owned(),
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
                    input_tokens: 30,
                    output_tokens: 42,
                }),
            },
        ]
    );
    let sent = only_request(&server).await;
    assert_eq!(header(&sent, "accept"), Some("text/event-stream"));
    assert_eq!(header(&sent, "x-api-key"), Some(API_KEY));
    let body = json_body(&sent);
    assert_eq!(body["stream"], json!(true));
    assert_eq!(body["tool_choice"], json!({ "type": "auto" }));
    assert_eq!(body["messages"], json!([user_text(PROMPT)]));
}

#[tokio::test]
async fn refusal_maps_to_refused_for_chat_and_for_a_stream() {
    let expected = "the model of provider claude refused the task";
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200).set_body_json(answer(
            json!([{ "type": "text", "text": "I cannot help with that." }]),
            "refusal",
        )),
    )
    .await;
    let chat = provider(&server).chat(request()).await.unwrap_err();
    assert!(
        matches!(&chat, Error::Refused(text) if text == expected),
        "{chat}"
    );

    let stream_server = MockServer::start().await;
    let [delta, stop] = message_end("refusal", 3);
    mount_messages(
        &stream_server,
        sse_response(named_sse_body(&[message_start(), delta, stop])),
    )
    .await;
    let stream = provider(&stream_server)
        .chat_stream(request())
        .await
        .unwrap();
    let items = collect(stream).await;
    assert_eq!(items.len(), 1);
    assert!(
        matches!(&items[0], Err(Error::Refused(text)) if text == expected),
        "{items:?}"
    );
}

#[tokio::test]
async fn stream_error_event_maps_to_the_contract_error() {
    let cases = [
        ("overloaded_error", "Unavailable"),
        ("rate_limit_error", "RateLimited"),
        ("invalid_request_error", "InvalidInput"),
    ];
    for (kind, expected) in cases {
        let server = MockServer::start().await;
        mount_messages(
            &server,
            sse_response(named_sse_body(&[
                message_start(),
                json!({ "type": "error", "error": { "type": kind, "message": format!("{PROMPT} {API_KEY}") } }),
            ])),
        )
        .await;

        let stream = provider(&server).chat_stream(request()).await.unwrap();
        let items = collect(stream).await;

        assert_eq!(items.len(), 1, "{kind}");
        let error = items[0].as_ref().unwrap_err();
        assert_eq!(variant(error), expected, "{kind}: {error}");
        assert!(
            error.to_string().ends_with(&format!(
                "provider claude reported an error in the stream (type {kind})"
            )),
            "{error}"
        );
    }
}

#[tokio::test]
async fn stream_that_ends_before_message_stop_is_unavailable() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        sse_response(named_sse_body(&[message_start(), text_delta(0, "partial")])),
    )
    .await;

    let stream = provider(&server).chat_stream(request()).await.unwrap();
    let items = collect(stream).await;

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().delta, "partial");
    assert!(
        matches!(&items[1], Err(Error::Unavailable(text))
            if text == "the stream of provider claude ended before the answer was complete"),
        "{items:?}"
    );
}

/// Returns the name of the variant of a contract error.
fn variant(error: &Error) -> &'static str {
    match error {
        Error::InvalidInput(_) => "InvalidInput",
        Error::NotFound(_) => "NotFound",
        Error::Config(_) => "Config",
        Error::Unauthorized(_) => "Unauthorized",
        Error::Unsupported(_) => "Unsupported",
        Error::Unavailable(_) => "Unavailable",
        Error::RateLimited(_) => "RateLimited",
        Error::Timeout(_) => "Timeout",
        Error::Refused(_) => "Refused",
        Error::Serialization(_) => "Serialization",
        _ => "other",
    }
}

#[tokio::test]
async fn each_http_status_maps_to_one_error_for_chat_and_stream() {
    let cases = [
        (401, "authentication_error", "Unauthorized", false),
        (403, "permission_error", "Unauthorized", false),
        (429, "rate_limit_error", "RateLimited", true),
        (408, "timeout_error", "Timeout", true),
        (500, "api_error", "Unavailable", true),
        (529, "overloaded_error", "Unavailable", true),
        (400, "invalid_request_error", "InvalidInput", false),
        (413, "request_too_large", "InvalidInput", false),
        (404, "not_found_error", "NotFound", false),
    ];
    for (status, kind, expected, retryable) in cases {
        let server = MockServer::start().await;
        mount_messages(
            &server,
            ResponseTemplate::new(status).set_body_json(json!({
                "type": "error",
                "error": { "type": kind, "message": "The request failed." },
            })),
        )
        .await;
        let provider = provider(&server);
        let message = format!("provider claude returned HTTP {status} (type {kind})");

        let chat = provider.chat(request()).await.unwrap_err();
        let stream = provider.chat_stream(request()).await.err().unwrap();

        for error in [chat, stream] {
            assert_eq!(variant(&error), expected, "status {status}: {error}");
            assert_eq!(error.is_retryable(), retryable, "status {status}");
            assert!(
                error.to_string().ends_with(&message),
                "status {status}: {error}"
            );
        }
    }
}

#[tokio::test]
async fn slow_provider_is_a_timeout() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(answer(
                json!([{ "type": "text", "text": "late" }]),
                "end_turn",
            ))
            .set_delay(Duration::from_secs(30)),
    )
    .await;
    let provider =
        AnthropicProvider::new(config(&server).with_timeout(Duration::from_millis(200))).unwrap();

    let chat = within(provider.chat(request())).await.unwrap_err();
    let stream = within(provider.chat_stream(request())).await.err().unwrap();

    for error in [chat, stream] {
        assert!(
            matches!(&error, Error::Timeout(text) if text == "provider claude did not answer in 200ms"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn connection_failure_is_unavailable() {
    let address = closed_address().await;
    let provider = AnthropicProvider::new(
        AnthropicConfig::new("claude", API_KEY)
            .with_base_url(format!("http://{address}"))
            .with_chat_model("claude-test")
            .with_timeout(Duration::from_secs(5)),
    )
    .unwrap();

    let chat = within(provider.chat(request())).await.unwrap_err();
    let stream = within(provider.chat_stream(request())).await.err().unwrap();

    for error in [chat, stream] {
        assert!(
            matches!(&error, Error::Unavailable(text) if text.starts_with("provider claude is not reachable: ")),
            "{error}"
        );
        assert!(error.is_retryable());
        let text = format!("{error} {error:?}");
        assert!(!text.contains(&address.to_string()), "{text}");
        assert!(!text.contains(API_KEY), "{text}");
    }
}

#[tokio::test]
async fn embed_is_unsupported_and_sends_nothing() {
    let server = MockServer::start().await;
    let provider = provider(&server);

    let error = provider
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["text".to_owned()],
        })
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unsupported(text) if text == "provider claude does not make embeddings"),
        "{error}"
    );
    assert!(!provider.capabilities().embeddings);
    assert_eq!(requests(&server).await.len(), 0);
}

#[tokio::test]
async fn key_and_prompt_stay_out_of_errors_and_debug_output() {
    let echo = format!("invalid x-api-key {API_KEY}; prompt: {PROMPT}");
    let bodies = [
        json!({ "type": "error", "error": { "type": echo, "message": echo } }),
        json!({ "type": "error", "error": { "type": API_KEY, "message": echo } }),
        json!({ "type": "error", "error": { "type": PROMPT, "message": PROMPT } }),
    ];
    for status in [400, 401, 529] {
        for body in &bodies {
            let server = MockServer::start().await;
            mount_messages(&server, ResponseTemplate::new(status).set_body_json(body)).await;
            let provider = provider(&server);

            let errors = [
                provider.chat(request()).await.unwrap_err(),
                provider.chat_stream(request()).await.err().unwrap(),
            ];

            for error in errors {
                let text = format!("{error} {error:?}");
                assert!(
                    error
                        .to_string()
                        .ends_with(&format!("provider claude returned HTTP {status}")),
                    "{text}"
                );
                assert!(!text.contains(API_KEY), "{text}");
                assert!(!text.contains("Classify"), "{text}");
            }
            let debug = format!("{provider:?} {:?}", provider.config());
            assert!(debug.contains("claude-test"), "{debug}");
            assert!(!debug.contains(API_KEY), "{debug}");
        }
    }
}

#[tokio::test]
async fn chat_without_a_model_is_a_configuration_error_and_sends_nothing() {
    let server = MockServer::start().await;
    let no_default =
        AnthropicProvider::new(AnthropicConfig::new("claude", API_KEY).with_base_url(server.uri()))
            .unwrap();

    let error = no_default.chat(request()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(text)
            if text == "provider claude: the request names no model and the provider has no default chat model"),
        "{error}"
    );
    assert_eq!(requests(&server).await.len(), 0);
}
