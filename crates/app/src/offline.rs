//! The model provider of a process that has no model.

use aegis_contracts::model::{
    ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse, ModelCapabilities,
    ModelProvider,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;

/// The name of the offline provider.
pub const OFFLINE_PROVIDER: &str = "offline";

/// A model provider for a configuration that has no `[model]` section.
///
/// Each call returns [`Error::Unavailable`]. The provider uses no network. The agents then
/// use their deterministic paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OfflineModel;

impl OfflineModel {
    fn unavailable<T>() -> Result<T> {
        Err(Error::Unavailable(
            "no model is configured: add a [model] section to use a model".to_owned(),
        ))
    }
}

#[async_trait]
impl ModelProvider for OfflineModel {
    fn name(&self) -> &str {
        OFFLINE_PROVIDER
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities::default()
    }

    async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse> {
        Self::unavailable()
    }

    async fn chat_stream(&self, _request: ChatRequest) -> Result<ChatStream> {
        Self::unavailable()
    }

    async fn embed(&self, _request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        Self::unavailable()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_contracts::model::{Message, TaskKind};

    use super::*;

    #[tokio::test]
    async fn each_call_is_unavailable_and_retryable() {
        let model = OfflineModel;
        assert_eq!(model.name(), "offline");
        assert_eq!(model.capabilities(), ModelCapabilities::default());

        let request = ChatRequest::new(TaskKind::Triage, vec![Message::user("Assess this.")]);
        let chat = model.chat(request.clone()).await.unwrap_err();
        assert!(matches!(&chat, Error::Unavailable(_)), "{chat:?}");
        assert!(chat.is_retryable());
        let stream = model.chat_stream(request).await.err().unwrap();
        assert!(matches!(stream, Error::Unavailable(_)), "{stream:?}");
        let embed = model
            .embed(EmbeddingRequest {
                model: None,
                input: vec!["text".to_owned()],
            })
            .await
            .unwrap_err();
        assert!(matches!(embed, Error::Unavailable(_)), "{embed:?}");
    }
}
