//! Integration tests for the OpenAI-compatible adapter against a mock HTTP server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::model::{
    ChatChunk, ChatRequest, ChatResponse, EmbeddingRequest, FinishReason, Message, ModelProvider,
    ResponseFormat, Role, TaskKind, ToolCall, ToolChoice, ToolSpec, Usage,
};
use aegis_model::{MaxTokensField, OpenAiCompatibleConfig, OpenAiCompatibleProvider};
use futures::StreamExt;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    closed_address, collect, collect_ok, header, json_body, only_request, requests, sse_body,
    sse_response, stream_server, within,
};

const API_KEY: &str = "sk-test-4f9a1c7e2b";
const PROMPT: &str = "Classify the sign-in burst from 203.0.113.7.";
const JSON_INSTRUCTION: &str =
    "Answer with one JSON object only. Do not write text before or after the JSON object.";

fn config(base: &str) -> OpenAiCompatibleConfig {
    OpenAiCompatibleConfig::new("hosted", format!("{base}/v1"))
        .with_api_key(API_KEY)
        .with_chat_model("gpt-test")
        .with_embedding_model("embed-test")
        .with_timeout(Duration::from_secs(5))
}

fn provider(server: &MockServer) -> OpenAiCompatibleProvider {
    OpenAiCompatibleProvider::new(config(&server.uri())).unwrap()
}

fn request() -> ChatRequest {
    ChatRequest::new(TaskKind::Triage, vec![Message::user(PROMPT)])
}

fn completion(message: Value, finish_reason: &str) -> Value {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-test-2025",
        "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason }],
        "usage": { "prompt_tokens": 21, "completion_tokens": 4, "total_tokens": 25 },
    })
}

async fn mount_chat(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
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

#[tokio::test]
async fn chat_sends_the_request_and_returns_the_answer() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(
            json!({ "role": "assistant", "content": "true positive", "refusal": null }),
            "stop",
        )),
    )
    .await;

    let response = provider(&server)
        .chat(ChatRequest {
            temperature: Some(0.2),
            max_output_tokens: Some(128),
            ..ChatRequest::new(
                TaskKind::Triage,
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
            provider: "hosted".to_owned(),
            model: "gpt-test-2025".to_owned(),
            message: Message::assistant("true positive"),
            finish_reason: FinishReason::Stop,
            usage: Usage {
                input_tokens: 21,
                output_tokens: 4,
            },
        }
    );
    let sent = only_request(&server).await;
    assert_eq!(
        header(&sent, "authorization"),
        Some("Bearer sk-test-4f9a1c7e2b")
    );
    assert_eq!(header(&sent, "content-type"), Some("application/json"));
    assert_eq!(
        json_body(&sent),
        json!({
            "model": "gpt-test",
            "messages": [
                { "role": "system", "content": "You are a security analyst." },
                { "role": "user", "content": PROMPT },
            ],
            "temperature": 0.2,
            "max_tokens": 128,
        })
    );
}

#[tokio::test]
async fn local_provider_sends_no_authorization_header() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "model": "llama3.1",
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": "benign" }, "finish_reason": "stop" }],
        })),
    )
    .await;
    let local =
        OpenAiCompatibleProvider::local(format!("{}/v1", server.uri()), "llama3.1").unwrap();

    let response = local.chat(request()).await.unwrap();

    assert_eq!(response.provider, "local");
    assert_eq!(response.message.content, "benign");
    // The server sent no usage, so the counts are zero.
    assert_eq!(response.usage, Usage::default());
    let sent = only_request(&server).await;
    assert_eq!(header(&sent, "authorization"), None);
    assert_eq!(json_body(&sent)["model"], json!("llama3.1"));
}

#[tokio::test]
async fn key_header_carries_the_key_and_replaces_the_authorization_header() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(json!({ "content": "ok" }), "stop")),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{ "index": 0, "embedding": [1.0] }],
        })))
        .mount(&server)
        .await;
    let provider =
        OpenAiCompatibleProvider::new(config(&server.uri()).with_api_key_header("api-key"))
            .unwrap();

    provider.chat(request()).await.unwrap();
    provider.embed(embedding_request()).await.unwrap();

    let sent = requests(&server).await;
    assert_eq!(sent.len(), 2);
    for request in &sent {
        assert_eq!(header(request, "api-key"), Some(API_KEY));
        assert_eq!(header(request, "authorization"), None);
    }
    let debug = format!("{provider:?}");
    assert!(debug.contains("api-key"), "{debug}");
    assert!(!debug.contains(API_KEY), "{debug}");
}

#[tokio::test]
async fn request_model_overrides_the_default_model() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(json!({ "content": "ok" }), "stop")),
    )
    .await;
    let mut request = request();
    request.model = Some("gpt-strong".to_owned());

    provider(&server).chat(request).await.unwrap();

    assert_eq!(
        json_body(&only_request(&server).await)["model"],
        json!("gpt-strong")
    );
}

#[tokio::test]
async fn chat_without_a_model_is_a_configuration_error_and_sends_nothing() {
    let server = MockServer::start().await;
    let no_default = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig::new(
        "hosted",
        format!("{}/v1", server.uri()),
    ))
    .unwrap();

    let error = no_default.chat(request()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(text)
            if text == "provider hosted: the request names no model and the provider has no default chat model"),
        "{error}"
    );
    assert_eq!(requests(&server).await.len(), 0);
}

#[tokio::test]
async fn tool_call_makes_a_round_trip() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_abc",
                    "type": "function",
                    "function": { "name": "lookup_ip", "arguments": "{\"ip\":\"203.0.113.7\"}" },
                }],
            }),
            "tool_calls",
        )))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(
            json!({ "role": "assistant", "content": "The address is malicious." }),
            "stop",
        )),
    )
    .await;
    let provider = provider(&server);
    let first_request = ChatRequest {
        tools: vec![lookup_tool()],
        ..request()
    };

    let first = provider.chat(first_request.clone()).await.unwrap();

    assert_eq!(first.finish_reason, FinishReason::ToolCalls);
    assert_eq!(
        first.message,
        Message {
            role: Role::Assistant,
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: "call_abc".to_owned(),
                name: "lookup_ip".to_owned(),
                arguments: json!({ "ip": "203.0.113.7" }),
            }],
            tool_call_id: None,
        }
    );

    let mut second_request = first_request;
    second_request.messages.push(first.message);
    second_request
        .messages
        .push(Message::tool("call_abc", "{\"reputation\":\"malicious\"}"));
    let second = provider.chat(second_request).await.unwrap();

    assert_eq!(
        second.message,
        Message::assistant("The address is malicious.")
    );
    assert_eq!(second.finish_reason, FinishReason::Stop);
    let sent = requests(&server).await;
    assert_eq!(sent.len(), 2);
    let tools = json!([{
        "type": "function",
        "function": {
            "name": "lookup_ip",
            "description": "Returns the reputation of an IP address.",
            "parameters": {
                "type": "object",
                "properties": { "ip": { "type": "string" } },
                "required": ["ip"],
            },
        },
    }]);
    assert_eq!(
        json_body(&sent[0]),
        json!({
            "model": "gpt-test",
            "messages": [{ "role": "user", "content": PROMPT }],
            "tools": tools,
            "tool_choice": "auto",
        })
    );
    assert_eq!(
        json_body(&sent[1]),
        json!({
            "model": "gpt-test",
            "messages": [
                { "role": "user", "content": PROMPT },
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": { "name": "lookup_ip", "arguments": "{\"ip\":\"203.0.113.7\"}" },
                    }],
                },
                { "role": "tool", "content": "{\"reputation\":\"malicious\"}", "tool_call_id": "call_abc" },
            ],
            "tools": tools,
            "tool_choice": "auto",
        })
    );
}

#[tokio::test]
async fn named_tool_choice_goes_on_the_wire() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(json!({ "content": "ok" }), "stop")),
    )
    .await;

    provider(&server)
        .chat(ChatRequest {
            tools: vec![lookup_tool()],
            tool_choice: ToolChoice::Tool("lookup_ip".to_owned()),
            ..request()
        })
        .await
        .unwrap();

    assert_eq!(
        json_body(&only_request(&server).await)["tool_choice"],
        json!({ "type": "function", "function": { "name": "lookup_ip" } })
    );
}

#[tokio::test]
async fn tool_arguments_that_are_not_an_object_are_a_serialization_error() {
    for arguments in ["[\"203.0.113.7\"]", "{\"ip\": ", "\"203.0.113.7\""] {
        let server = MockServer::start().await;
        mount_chat(
            &server,
            ResponseTemplate::new(200).set_body_json(completion(
                json!({
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": { "name": "lookup_ip", "arguments": arguments },
                    }],
                }),
                "tool_calls",
            )),
        )
        .await;

        let error = provider(&server).chat(request()).await.unwrap_err();

        assert!(
            matches!(&error, Error::Serialization(text)
                if text == "provider hosted sent arguments for tool lookup_ip that are not a JSON object"),
            "{arguments}: {error}"
        );
    }
}

#[tokio::test]
async fn json_mode_asks_for_a_json_object() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(
            json!({ "content": "{\"verdict\":\"malicious\",\"confidence\":0.93}" }),
            "stop",
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
        json!({ "verdict": "malicious", "confidence": 0.93 })
    );
    // No message has the word "JSON", so the adapter adds the instruction.
    assert_eq!(
        json_body(&only_request(&server).await),
        json!({
            "model": "gpt-test",
            "messages": [
                { "role": "system", "content": JSON_INSTRUCTION },
                { "role": "user", "content": PROMPT },
            ],
            "response_format": { "type": "json_object" },
        })
    );
}

#[tokio::test]
async fn json_mode_keeps_the_messages_when_one_has_the_word_json() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(
            json!({ "content": "{\"verdict\":\"benign\"}" }),
            "stop",
        )),
    )
    .await;
    let prompt = "Classify the alert. Answer with a JSON object.";

    let response = provider(&server)
        .chat(ChatRequest {
            response_format: ResponseFormat::Json,
            ..ChatRequest::new(TaskKind::Triage, vec![Message::user(prompt)])
        })
        .await
        .unwrap();

    assert_eq!(response.message.content, "{\"verdict\":\"benign\"}");
    assert_eq!(
        json_body(&only_request(&server).await),
        json!({
            "model": "gpt-test",
            "messages": [{ "role": "user", "content": prompt }],
            "response_format": { "type": "json_object" },
        })
    );
}

fn text_delta(text: &str) -> String {
    json!({ "choices": [{ "index": 0, "delta": { "content": text }, "finish_reason": null }], "usage": null })
        .to_string()
}

fn finish(reason: &str) -> String {
    json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }], "usage": null })
        .to_string()
}

fn usage_event() -> String {
    json!({ "choices": [], "usage": { "prompt_tokens": 21, "completion_tokens": 6, "total_tokens": 27 } })
        .to_string()
}

#[tokio::test]
async fn stream_yields_the_text_and_one_last_chunk() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        sse_response(sse_body(&[
            json!({ "choices": [{ "index": 0, "delta": { "role": "assistant", "content": "" }, "finish_reason": null }] })
                .to_string(),
            text_delta("true "),
            text_delta("positive"),
            finish("stop"),
            usage_event(),
            "[DONE]".to_owned(),
        ])),
    )
    .await;

    let stream = provider(&server).chat_stream(request()).await.unwrap();
    let chunks = collect_ok(stream).await;

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
                    input_tokens: 21,
                    output_tokens: 6,
                }),
            },
        ]
    );
    let sent = only_request(&server).await;
    assert_eq!(header(&sent, "accept"), Some("text/event-stream"));
    assert_eq!(
        json_body(&sent),
        json!({
            "model": "gpt-test",
            "messages": [{ "role": "user", "content": PROMPT }],
            "stream": true,
            "stream_options": { "include_usage": true },
        })
    );
}

fn call_delta(fragment: Value) -> String {
    json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [fragment] }, "finish_reason": null }] })
        .to_string()
}

#[tokio::test]
async fn stream_emits_tool_calls_only_when_they_are_complete() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        sse_response(sse_body(&[
            text_delta("Checking."),
            call_delta(json!({ "index": 0, "id": "call_a", "type": "function", "function": { "name": "lookup_ip", "arguments": "" } })),
            call_delta(json!({ "index": 0, "function": { "arguments": "{\"ip\":\"203" } })),
            call_delta(json!({ "index": 0, "function": { "arguments": ".0.113.7\"}" } })),
            call_delta(json!({ "index": 1, "id": "call_b", "type": "function", "function": { "name": "list_sessions", "arguments": "{\"user\":" } })),
            call_delta(json!({ "index": 1, "function": { "arguments": "\"amy\"}" } })),
            finish("tool_calls"),
            usage_event(),
            "[DONE]".to_owned(),
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
                delta: "Checking.".to_owned(),
                ..ChatChunk::default()
            },
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
                usage: Some(Usage {
                    input_tokens: 21,
                    output_tokens: 6,
                }),
            },
        ]
    );
}

#[tokio::test]
async fn stream_delivers_each_part_when_it_arrives() {
    let (address, script) = stream_server().await;
    let provider = OpenAiCompatibleProvider::new(config(&format!("http://{address}"))).unwrap();
    let mut stream = within(provider.chat_stream(request())).await.unwrap();

    // The first event arrives in two parts. The split is inside a multi-byte character.
    let event = format!("data: {}\n\n", text_delta("caf\u{e9} "));
    let split = event.find('\u{e9}').unwrap() + 1;
    let (left, right) = event.as_bytes().split_at(split);
    assert!(std::str::from_utf8(left).is_err());
    script.send(left);
    script.send(right);
    let first = within(stream.next()).await.unwrap().unwrap();
    assert_eq!(first.delta, "caf\u{e9} ");

    script.send(format!(
        "data: {}\r\n\r\ndata: {}\r\n\r\ndata: [DONE]\r\n\r\n",
        text_delta("open"),
        finish("stop")
    ));
    let second = within(stream.next()).await.unwrap().unwrap();
    assert_eq!(second.delta, "open");
    let last = within(stream.next()).await.unwrap().unwrap();
    assert_eq!(last.finish_reason, Some(FinishReason::Stop));
    assert_eq!(last.usage, None);
    assert!(within(stream.next()).await.is_none());
}

#[tokio::test]
async fn stream_that_stops_sending_is_a_timeout() {
    let (address, script) = stream_server().await;
    let provider = OpenAiCompatibleProvider::new(
        config(&format!("http://{address}")).with_timeout(Duration::from_millis(500)),
    )
    .unwrap();
    let mut stream = within(provider.chat_stream(request())).await.unwrap();
    script.send(format!("data: {}\n\n", text_delta("partial")));

    let first = within(stream.next()).await.unwrap().unwrap();
    assert_eq!(first.delta, "partial");
    let error = within(stream.next()).await.unwrap().unwrap_err();

    assert!(
        matches!(&error, Error::Timeout(text)
            if text == "the stream of provider hosted sent no data for 500ms"),
        "{error}"
    );
    assert!(error.is_retryable());
    assert!(within(stream.next()).await.is_none());
    // The server kept the connection open until this point.
    drop(script);
}

#[tokio::test]
async fn stream_that_breaks_is_unavailable() {
    let (address, script) = stream_server().await;
    let provider = OpenAiCompatibleProvider::new(config(&format!("http://{address}"))).unwrap();
    let mut stream = within(provider.chat_stream(request())).await.unwrap();
    script.send(format!("data: {}\n\n", text_delta("partial")));
    let first = within(stream.next()).await.unwrap().unwrap();
    assert_eq!(first.delta, "partial");

    script.abort();
    let error = within(stream.next()).await.unwrap().unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(text)
            if text == "the stream of provider hosted broke before the answer was complete"),
        "{error}"
    );
    assert!(within(stream.next()).await.is_none());
}

#[tokio::test]
async fn stream_that_ends_before_the_finish_reason_is_unavailable() {
    let server = MockServer::start().await;
    mount_chat(&server, sse_response(sse_body(&[text_delta("partial")]))).await;

    let stream = provider(&server).chat_stream(request()).await.unwrap();
    let items = collect(stream).await;

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().delta, "partial");
    assert!(
        matches!(&items[1], Err(Error::Unavailable(text))
            if text == "the stream of provider hosted ended before the answer was complete"),
        "{items:?}"
    );
}

#[tokio::test]
async fn embed_sends_the_inputs_and_returns_the_vectors_in_input_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": "embed-test-v2",
            "data": [
                { "object": "embedding", "index": 1, "embedding": [0.0, 1.0, 0.0] },
                { "object": "embedding", "index": 0, "embedding": [0.25, -0.5, 1.0] },
            ],
            "usage": { "prompt_tokens": 9, "total_tokens": 9 },
        })))
        .mount(&server)
        .await;

    let response = provider(&server)
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["sign-in burst".to_owned(), "vault access".to_owned()],
        })
        .await
        .unwrap();

    assert_eq!(response.provider, "hosted");
    assert_eq!(response.model, "embed-test-v2");
    assert_eq!(
        response.embeddings,
        vec![vec![0.25, -0.5, 1.0], vec![0.0, 1.0, 0.0]]
    );
    assert_eq!(
        response.usage,
        Usage {
            input_tokens: 9,
            output_tokens: 0,
        }
    );
    let sent = only_request(&server).await;
    assert_eq!(
        header(&sent, "authorization"),
        Some("Bearer sk-test-4f9a1c7e2b")
    );
    assert_eq!(
        json_body(&sent),
        json!({ "model": "embed-test", "input": ["sign-in burst", "vault access"] })
    );
}

#[tokio::test]
async fn embed_without_a_model_is_unsupported_and_empty_input_sends_nothing() {
    let server = MockServer::start().await;
    let chat_only =
        OpenAiCompatibleProvider::local(format!("{}/v1", server.uri()), "llama3.1").unwrap();
    let unsupported = chat_only
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["text".to_owned()],
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&unsupported, Error::Unsupported(text) if text == "provider local has no embedding model"),
        "{unsupported}"
    );

    let empty = provider(&server)
        .embed(EmbeddingRequest {
            model: None,
            input: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(empty.embeddings, Vec::<Vec<f32>>::new());
    assert_eq!(empty.model, "embed-test");
    assert_eq!(requests(&server).await.len(), 0);
}

fn embedding_request() -> EmbeddingRequest {
    EmbeddingRequest {
        model: None,
        input: vec!["text".to_owned()],
    }
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
async fn each_http_status_maps_to_one_error_for_chat_stream_and_embed() {
    let cases = [
        (401, "Unauthorized", false),
        (403, "Unauthorized", false),
        (429, "RateLimited", true),
        (408, "Timeout", true),
        (500, "Unavailable", true),
        (502, "Unavailable", true),
        (503, "Unavailable", true),
        (400, "InvalidInput", false),
        (404, "NotFound", false),
    ];
    for (status, expected, retryable) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": { "message": "The request failed.", "type": "api_error", "code": "e42" },
            })))
            .mount(&server)
            .await;
        let provider = provider(&server);
        let message = format!("provider hosted returned HTTP {status} (type api_error, code e42)");

        let chat = provider.chat(request()).await.unwrap_err();
        let stream = provider.chat_stream(request()).await.err().unwrap();
        let embed = provider.embed(embedding_request()).await.unwrap_err();

        for error in [chat, stream, embed] {
            assert_eq!(variant(&error), expected, "status {status}: {error}");
            assert_eq!(error.is_retryable(), retryable, "status {status}");
            assert!(
                error.to_string().ends_with(&message),
                "status {status}: {error}"
            );
        }
        assert_eq!(requests(&server).await.len(), 3);
    }
}

#[tokio::test]
async fn slow_provider_is_a_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(completion(json!({ "content": "late" }), "stop"))
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&server)
        .await;
    let provider = OpenAiCompatibleProvider::new(
        config(&server.uri()).with_timeout(Duration::from_millis(200)),
    )
    .unwrap();

    let chat = within(provider.chat(request())).await.unwrap_err();
    let stream = within(provider.chat_stream(request())).await.err().unwrap();
    let embed = within(provider.embed(embedding_request()))
        .await
        .unwrap_err();

    for error in [chat, stream, embed] {
        assert!(
            matches!(&error, Error::Timeout(text) if text == "provider hosted did not answer in 200ms"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn connection_failure_is_unavailable() {
    let address = closed_address().await;
    let provider = OpenAiCompatibleProvider::new(config(&format!("http://{address}"))).unwrap();

    let chat = within(provider.chat(request())).await.unwrap_err();
    let stream = within(provider.chat_stream(request())).await.err().unwrap();

    for error in [chat, stream] {
        assert!(
            matches!(&error, Error::Unavailable(text) if text.starts_with("provider hosted is not reachable: ")),
            "{error}"
        );
        assert!(!error.to_string().contains(&address.to_string()), "{error}");
    }
}

#[tokio::test]
async fn refusals_map_to_refused() {
    let filtered = "a content filter of provider hosted stopped the answer";
    let refused = "the model of provider hosted refused the task";
    let cases = [
        (
            ResponseTemplate::new(200).set_body_json(completion(
                json!({ "role": "assistant", "content": "" }),
                "content_filter",
            )),
            filtered,
        ),
        (
            ResponseTemplate::new(200).set_body_json(completion(
                json!({ "role": "assistant", "content": null, "refusal": "I cannot help with that." }),
                "stop",
            )),
            refused,
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({
                "error": { "message": "The prompt triggered the content policy.", "type": null, "code": "content_filter" },
            })),
            "provider hosted returned HTTP 400 (code content_filter)",
        ),
    ];
    for (response, expected) in cases {
        let server = MockServer::start().await;
        mount_chat(&server, response).await;

        let error = provider(&server).chat(request()).await.unwrap_err();

        assert!(
            matches!(&error, Error::Refused(text) if text == expected),
            "{expected}: {error}"
        );
        assert!(!error.is_retryable());
    }
}

#[tokio::test]
async fn stream_refusals_map_to_refused() {
    let cases = [
        (
            vec![
                json!({ "choices": [{ "index": 0, "delta": { "refusal": "I cannot help." }, "finish_reason": null }] })
                    .to_string(),
                "[DONE]".to_owned(),
            ],
            "the model of provider hosted refused the task",
        ),
        (
            vec![finish("content_filter"), "[DONE]".to_owned()],
            "a content filter of provider hosted stopped the answer",
        ),
    ];
    for (events, expected) in cases {
        let server = MockServer::start().await;
        mount_chat(&server, sse_response(sse_body(&events))).await;

        let stream = provider(&server).chat_stream(request()).await.unwrap();
        let items = collect(stream).await;

        assert_eq!(items.len(), 1, "{expected}");
        assert!(
            matches!(&items[0], Err(Error::Refused(text)) if text == expected),
            "{items:?}"
        );
    }
}

#[tokio::test]
async fn key_and_prompt_stay_out_of_errors_and_debug_output() {
    // Some providers repeat the key or the prompt in the error body.
    let echo = format!("Incorrect API key provided: {API_KEY}. The prompt was: {PROMPT}");
    let bodies = [
        json!({ "error": { "message": echo, "type": echo, "code": echo } }),
        json!({ "error": { "message": echo, "type": API_KEY, "code": &API_KEY[..12] } }),
        json!({ "error": { "message": PROMPT, "type": PROMPT, "code": PROMPT } }),
        json!({ "error": echo }),
    ];
    for status in [400, 401, 500] {
        for body in &bodies {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let provider = provider(&server);

            let errors = [
                provider.chat(request()).await.unwrap_err(),
                provider.chat_stream(request()).await.err().unwrap(),
                provider.embed(embedding_request()).await.unwrap_err(),
            ];

            for error in errors {
                let text = format!("{error} {error:?}");
                assert!(
                    error
                        .to_string()
                        .ends_with(&format!("provider hosted returned HTTP {status}")),
                    "{text}"
                );
                assert!(!text.contains(API_KEY), "{text}");
                assert!(!text.contains(&API_KEY[..12]), "{text}");
                assert!(!text.contains("Classify"), "{text}");
                assert!(!text.contains("203.0.113.7"), "{text}");
            }
            let debug = format!("{provider:?} {:?}", provider.config());
            assert!(debug.contains("hosted"), "{debug}");
            assert!(!debug.contains(API_KEY), "{debug}");
        }
    }
}

#[tokio::test]
async fn stream_error_event_is_unavailable_without_the_message_or_the_key() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        sse_response(sse_body(&[
            text_delta("partial"),
            json!({ "error": { "message": format!("{PROMPT} {API_KEY}"), "type": "server_error", "code": API_KEY } })
                .to_string(),
        ])),
    )
    .await;

    let stream = provider(&server).chat_stream(request()).await.unwrap();
    let items = collect(stream).await;

    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(Error::Unavailable(text))
            if text == "provider hosted reported an error in the stream (type server_error)"),
        "{items:?}"
    );
}

#[tokio::test]
async fn answer_that_is_not_json_is_a_serialization_error_without_the_body() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_string(format!("<html>{PROMPT}</html>")),
    )
    .await;

    let error = provider(&server).chat(request()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Serialization(text)
            if text == "provider hosted sent an answer that could not be decoded: syntax error at line 1 column 1"),
        "{error}"
    );
}

#[tokio::test]
async fn extra_headers_and_the_new_limit_field_go_on_the_wire() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(200).set_body_json(completion(json!({ "content": "ok" }), "stop")),
    )
    .await;
    let provider = OpenAiCompatibleProvider::new(
        config(&server.uri())
            .with_header("x-team", "soc")
            .with_max_tokens_field(MaxTokensField::MaxCompletionTokens),
    )
    .unwrap();

    provider
        .chat(ChatRequest {
            max_output_tokens: Some(64),
            ..request()
        })
        .await
        .unwrap();

    let sent = only_request(&server).await;
    assert_eq!(header(&sent, "x-team"), Some("soc"));
    assert_eq!(
        json_body(&sent),
        json!({
            "model": "gpt-test",
            "messages": [{ "role": "user", "content": PROMPT }],
            "max_completion_tokens": 64,
        })
    );
}

#[tokio::test]
async fn redirect_is_a_configuration_error_and_the_target_gets_no_request() {
    let target = MockServer::start().await;
    let server = MockServer::start().await;
    mount_chat(
        &server,
        ResponseTemplate::new(307).insert_header(
            "location",
            format!("{}/v1/chat/completions", target.uri()).as_str(),
        ),
    )
    .await;

    let error = provider(&server).chat(request()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(text) if text.starts_with("provider hosted returned HTTP 307; ")),
        "{error}"
    );
    assert_eq!(requests(&server).await.len(), 1);
    assert_eq!(requests(&target).await.len(), 0);
}

#[tokio::test]
async fn invalid_request_is_rejected_before_a_request_is_sent() {
    let server = MockServer::start().await;
    let provider = provider(&server);

    let no_messages = provider
        .chat(ChatRequest::new(TaskKind::Triage, Vec::new()))
        .await
        .unwrap_err();
    let no_tools = provider
        .chat_stream(ChatRequest {
            tool_choice: ToolChoice::Required,
            ..request()
        })
        .await
        .err()
        .unwrap();

    assert!(
        matches!(&no_messages, Error::InvalidInput(text) if text == "the chat request has no messages"),
        "{no_messages}"
    );
    assert!(
        matches!(&no_tools, Error::InvalidInput(text)
            if text == "tool_choice requires a tool call, but the chat request has no tools"),
        "{no_tools}"
    );
    assert_eq!(requests(&server).await.len(), 0);
}
