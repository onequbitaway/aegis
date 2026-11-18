use std::collections::VecDeque;
use std::sync::Mutex;

use aegis_contracts::model::{
    ChatChunk, ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse,
    FinishReason, Message, ModelCapabilities, ModelProvider, Role, ToolCall, Usage,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;

use crate::lock;

/// The number of dimensions of the embeddings that [`ScriptedModel`] makes.
pub const EMBEDDING_DIMENSIONS: usize = 32;

/// A model provider that returns answers from a script and records each request.
///
/// Each chat request takes the next step of the script. When the script is empty, the
/// provider returns [`Error::Unavailable`].
pub struct ScriptedModel {
    name: String,
    script: Mutex<VecDeque<Result<Message>>>,
    requests: Mutex<Vec<ChatRequest>>,
}

impl ScriptedModel {
    /// Makes a provider with an empty script.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            script: Mutex::default(),
            requests: Mutex::default(),
        }
    }

    fn step(self, step: Result<Message>) -> Self {
        lock(&self.script).push_back(step);
        self
    }

    /// Adds a text answer to the script.
    #[must_use]
    pub fn reply(self, text: impl Into<String>) -> Self {
        self.step(Ok(Message::assistant(text)))
    }

    /// Adds a JSON answer to the script.
    #[must_use]
    pub fn reply_json(self, value: &serde_json::Value) -> Self {
        self.step(Ok(Message::assistant(value.to_string())))
    }

    /// Adds an answer that requests one tool call.
    #[must_use]
    pub fn reply_tool_call(self, name: impl Into<String>, arguments: serde_json::Value) -> Self {
        let position = lock(&self.script).len() + 1;
        self.step(Ok(Message {
            role: Role::Assistant,
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: format!("call-{position}"),
                name: name.into(),
                arguments,
            }],
            tool_call_id: None,
        }))
    }

    /// Adds a failure to the script.
    #[must_use]
    pub fn fail(self, error: Error) -> Self {
        self.step(Err(error))
    }

    /// Returns the chat requests that the provider received, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<ChatRequest> {
        lock(&self.requests).clone()
    }

    /// Returns the number of script steps that no request has used.
    #[must_use]
    pub fn remaining(&self) -> usize {
        lock(&self.script).len()
    }
}

/// Makes a deterministic embedding from the words of `text`.
///
/// Texts that share words have a larger cosine similarity. The vector has unit length,
/// or is all zeros for a text with no words.
#[must_use]
pub fn embed_text(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0_f32; EMBEDDING_DIMENSIONS];
    let words = text
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty());
    for word in words {
        // FNV-1a, so that the result is the same on each platform and each Rust version.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in word.to_lowercase().bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let dimensions = u64::try_from(EMBEDDING_DIMENSIONS).unwrap_or(u64::MAX);
        if let Some(slot) = usize::try_from(hash % dimensions)
            .ok()
            .and_then(|index| vector.get_mut(index))
        {
            *slot += 1.0;
        }
    }
    let length = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if length > 0.0 {
        for value in &mut vector {
            *value /= length;
        }
    }
    vector
}

#[async_trait]
impl ModelProvider for ScriptedModel {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            tools: true,
            streaming: true,
            embeddings: true,
        }
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = request
            .model
            .clone()
            .unwrap_or_else(|| "scripted".to_owned());
        lock(&self.requests).push(request);
        let message = lock(&self.script).pop_front().unwrap_or_else(|| {
            Err(Error::Unavailable(format!(
                "the script of model {} is empty",
                self.name
            )))
        })?;
        let finish_reason = if message.tool_calls.is_empty() {
            FinishReason::Stop
        } else {
            FinishReason::ToolCalls
        };
        Ok(ChatResponse {
            provider: self.name.clone(),
            model,
            message,
            finish_reason,
            usage: Usage::default(),
        })
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream> {
        let response = self.chat(request).await?;
        let mut chunks: Vec<Result<ChatChunk>> = response
            .message
            .content
            .split_inclusive(' ')
            .map(|word| {
                Ok(ChatChunk {
                    delta: word.to_owned(),
                    ..ChatChunk::default()
                })
            })
            .collect();
        chunks.push(Ok(ChatChunk {
            delta: String::new(),
            tool_calls: response.message.tool_calls,
            finish_reason: Some(response.finish_reason),
            usage: Some(response.usage),
        }));
        Ok(Box::pin(futures::stream::iter(chunks)))
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        Ok(EmbeddingResponse {
            provider: self.name.clone(),
            model: request.model.unwrap_or_else(|| "scripted-embed".to_owned()),
            embeddings: request.input.iter().map(|text| embed_text(text)).collect(),
            usage: Usage::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::TaskKind;
    use futures::StreamExt;
    use serde_json::json;

    use super::*;

    fn request(text: &str) -> ChatRequest {
        ChatRequest::new(TaskKind::Triage, vec![Message::user(text)])
    }

    #[tokio::test]
    async fn chat_returns_the_script_in_order_and_records_requests() {
        let model = ScriptedModel::new("fake")
            .reply("first")
            .reply_json(&json!({ "verdict": "malicious" }))
            .reply_tool_call("lookup_ip", json!({ "ip": "203.0.113.7" }));
        assert_eq!(model.remaining(), 3);

        let first = model.chat(request("a")).await.unwrap();
        assert_eq!(first.provider, "fake");
        assert_eq!(first.message, Message::assistant("first"));
        assert_eq!(first.finish_reason, FinishReason::Stop);

        let second = model.chat(request("b")).await.unwrap();
        assert_eq!(second.message.content, r#"{"verdict":"malicious"}"#);

        let third = model.chat(request("c")).await.unwrap();
        assert_eq!(third.finish_reason, FinishReason::ToolCalls);
        assert_eq!(third.message.tool_calls.len(), 1);
        assert_eq!(third.message.tool_calls[0].name, "lookup_ip");
        assert_eq!(third.message.tool_calls[0].id, "call-3");

        let requests = model.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].messages, vec![Message::user("b")]);
        assert_eq!(model.remaining(), 0);
    }

    #[tokio::test]
    async fn chat_returns_scripted_failures_and_then_reports_an_empty_script() {
        let model = ScriptedModel::new("fake").fail(Error::Refused("policy".to_owned()));
        let refused = model.chat(request("a")).await.unwrap_err();
        assert!(matches!(refused, Error::Refused(reason) if reason == "policy"));
        let empty = model.chat(request("b")).await.unwrap_err();
        assert!(
            matches!(&empty, Error::Unavailable(reason) if reason.contains("fake")),
            "{empty}"
        );
        assert_eq!(model.requests().len(), 2);
    }

    #[tokio::test]
    async fn chat_stream_yields_the_text_and_a_final_chunk() {
        let model = ScriptedModel::new("fake").reply("true positive now");
        let chunks: Vec<ChatChunk> = model
            .chat_stream(request("a"))
            .await
            .unwrap()
            .map(|chunk| chunk.unwrap())
            .collect()
            .await;
        assert_eq!(chunks.len(), 4);
        let text: String = chunks.iter().map(|chunk| chunk.delta.as_str()).collect();
        assert_eq!(text, "true positive now");
        assert!(
            chunks[..3]
                .iter()
                .all(|chunk| chunk.finish_reason.is_none())
        );
        assert_eq!(chunks[3].finish_reason, Some(FinishReason::Stop));
    }

    #[tokio::test]
    async fn embeddings_are_deterministic_unit_vectors_that_reflect_shared_words() {
        fn cosine(left: &[f32], right: &[f32]) -> f32 {
            left.iter().zip(right).map(|(a, b)| a * b).sum()
        }
        let model = ScriptedModel::new("fake");
        let response = model
            .embed(EmbeddingRequest {
                model: None,
                input: vec![
                    "sign-in burst from one address".to_owned(),
                    "Sign-In BURST from one address".to_owned(),
                    "burst of sign-in failures".to_owned(),
                    "rotate the vault secret".to_owned(),
                    String::new(),
                ],
            })
            .await
            .unwrap();
        let vectors = response.embeddings;
        assert_eq!(vectors.len(), 5);
        assert!(
            vectors
                .iter()
                .all(|vector| vector.len() == EMBEDDING_DIMENSIONS)
        );
        assert_eq!(vectors[0], vectors[1]);
        assert!((cosine(&vectors[0], &vectors[0]) - 1.0).abs() < 1e-5);
        assert!(cosine(&vectors[0], &vectors[2]) > cosine(&vectors[0], &vectors[3]));
        assert!(vectors[4].iter().all(|value| *value == 0.0));
    }
}
