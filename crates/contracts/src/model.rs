//! The contract for LLM access.
//!
//! Agents and detectors write requests in these types one time. Each provider adapter
//! converts the types to the wire format of its provider.

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// The author of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Instructions for the model.
    System,
    /// Input from the caller.
    User,
    /// Output from the model.
    Assistant,
    /// The result of a tool call.
    Tool,
}

/// A request from the model to call one tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// The identifier of the call. The tool result must carry the same identifier.
    pub id: String,
    /// The name of the tool.
    pub name: String,
    /// The arguments, as a JSON object that obeys the tool schema.
    pub arguments: serde_json::Value,
}

/// One message in a conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// The author of the message.
    pub role: Role,
    /// The text of the message.
    #[serde(default)]
    pub content: String,
    /// The tool calls that the model requests. Only an assistant message has tool calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// The identifier of the tool call that this message answers. Only a tool message has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    fn text(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    /// Makes a system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::text(Role::System, content)
    }

    /// Makes a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::text(Role::User, content)
    }

    /// Makes an assistant message with no tool calls.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::text(Role::Assistant, content)
    }

    /// Makes a tool message that answers the call `tool_call_id`.
    pub fn tool(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            tool_call_id: Some(tool_call_id.into()),
            ..Self::text(Role::Tool, content)
        }
    }
}

/// The description of one tool that the model can call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    /// The name of the tool.
    pub name: String,
    /// What the tool does. The model reads this text.
    pub description: String,
    /// The JSON Schema of the arguments.
    pub parameters: serde_json::Value,
}

/// How the model selects tools.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
    /// The model decides.
    #[default]
    Auto,
    /// The model must not call a tool.
    None,
    /// The model must call a tool.
    Required,
    /// The model must call the tool with this name.
    Tool(String),
}

/// The format of the model output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    /// Free text.
    #[default]
    Text,
    /// One JSON object.
    Json,
}

/// The type of work that a request does. The model router uses it to select a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Triage of many events or alerts. A fast, low-cost model is sufficient.
    Triage,
    /// Analysis of one incident. A strong model is necessary.
    #[default]
    Analysis,
    /// The division of a goal into tasks.
    Planning,
    /// The draft of a response for a new incident.
    ResponseDraft,
    /// Reports and summaries.
    Reporting,
    /// Embeddings.
    Embedding,
}

/// A chat request.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatRequest {
    /// The type of work. The model router uses it to select a model.
    #[serde(default)]
    pub task: TaskKind,
    /// The model to use. With `None`, the provider or the router selects the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The conversation, oldest message first.
    pub messages: Vec<Message>,
    /// The tools that the model can call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSpec>,
    /// How the model selects tools.
    #[serde(default)]
    pub tool_choice: ToolChoice,
    /// The format of the output.
    #[serde(default)]
    pub response_format: ResponseFormat,
    /// The sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// The maximum number of output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
}

impl ChatRequest {
    /// Makes a request with default settings for `task`.
    #[must_use]
    pub fn new(task: TaskKind, messages: Vec<Message>) -> Self {
        Self {
            task,
            messages,
            ..Self::default()
        }
    }
}

/// Why the model stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// The model completed its answer.
    Stop,
    /// The output reached the token limit.
    Length,
    /// The model requests tool calls.
    ToolCalls,
    /// A safety filter of the provider stopped the output.
    ContentFilter,
    /// A reason that has no more specific variant.
    Other,
}

/// Token counts for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// The number of input tokens.
    pub input_tokens: u64,
    /// The number of output tokens.
    pub output_tokens: u64,
}

/// The answer to a chat request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The name of the provider that answered.
    pub provider: String,
    /// The model that answered.
    pub model: String,
    /// The assistant message.
    pub message: Message,
    /// Why the model stopped.
    pub finish_reason: FinishReason,
    /// The token counts.
    #[serde(default)]
    pub usage: Usage,
}

/// One part of a streamed answer.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatChunk {
    /// New text since the last chunk.
    #[serde(default)]
    pub delta: String,
    /// Tool calls that are complete in this chunk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Why the model stopped. Only the last chunk has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<FinishReason>,
    /// The token counts. Only the last chunk has them, if the provider sends them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// A stream of parts of an answer.
pub type ChatStream = BoxStream<'static, Result<ChatChunk>>;

/// An embedding request.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    /// The model to use. With `None`, the provider or the router selects the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The texts to embed.
    pub input: Vec<String>,
}

/// The answer to an embedding request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// The name of the provider that answered.
    pub provider: String,
    /// The model that answered.
    pub model: String,
    /// One vector for each input text, in the same order.
    pub embeddings: Vec<Vec<f32>>,
    /// The token counts.
    #[serde(default)]
    pub usage: Usage,
}

/// What a provider can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ModelCapabilities {
    /// The provider supports tool calls.
    pub tools: bool,
    /// The provider supports streamed answers.
    pub streaming: bool,
    /// The provider supports embeddings.
    pub embeddings: bool,
}

/// Access to one LLM provider, or to a router that selects between providers.
///
/// An implementation must return [`Error::Refused`](crate::Error::Refused) when the model
/// refuses the task. The router uses this error to try a different model.
#[async_trait]
pub trait ModelProvider: Send + Sync {
    /// Returns the name of this provider.
    fn name(&self) -> &str;

    /// Returns what this provider can do.
    fn capabilities(&self) -> ModelCapabilities;

    /// Sends a chat request and returns the full answer.
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse>;

    /// Sends a chat request and returns the answer as a stream.
    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream>;

    /// Makes embeddings for the input texts.
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;
}
