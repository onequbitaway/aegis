//! The adapter for providers that use the OpenAI chat-completions format.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use aegis_contracts::model::{
    ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse, ModelCapabilities,
    ModelProvider, Usage,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::DEFAULT_TIMEOUT;
use crate::http::{
    Transport, endpoint, parse_base_url, secret_header, sends_credential_in_cleartext,
};
use crate::sse;

mod stream;
mod wire;

/// The base URL of a local Ollama server.
pub const OLLAMA_BASE_URL: &str = "http://localhost:11434/v1";

/// The error identifiers that mean "a content filter rejected the request".
const REFUSAL_CODES: &[&str] = &["content_filter", "content_policy_violation"];

/// The request field that carries the limit of output tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaxTokensField {
    /// The `max_tokens` field. Local servers and most gateways read this field.
    #[default]
    MaxTokens,
    /// The `max_completion_tokens` field. Some hosted reasoning models accept only this field.
    MaxCompletionTokens,
}

/// The settings of one [`OpenAiCompatibleProvider`].
#[derive(Clone)]
pub struct OpenAiCompatibleConfig {
    /// The name of the provider. The router and the answers use this name.
    pub name: String,
    /// The base URL of the API, for example `https://api.openai.com/v1`.
    pub base_url: String,
    /// The API key. A local server has no key.
    pub api_key: Option<SecretString>,
    /// The header that carries the API key, for example `api-key`. With `None`, the
    /// adapter sends `Authorization: Bearer <key>`.
    pub api_key_header: Option<String>,
    /// The chat model for a request that names no model.
    pub chat_model: Option<String>,
    /// The embedding model for a request that names no model.
    pub embedding_model: Option<String>,
    /// The timeout of one request. For a stream, the timeout applies to each read.
    pub timeout: Duration,
    /// Headers that each request carries in addition to the standard headers.
    pub headers: BTreeMap<String, String>,
    /// The request field that carries the limit of output tokens.
    pub max_tokens_field: MaxTokensField,
}

impl OpenAiCompatibleConfig {
    /// Makes settings with no API key, no default models, and the default timeout.
    pub fn new(name: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            api_key: None,
            api_key_header: None,
            chat_model: None,
            embedding_model: None,
            timeout: DEFAULT_TIMEOUT,
            headers: BTreeMap::new(),
            max_tokens_field: MaxTokensField::default(),
        }
    }

    /// Sets the API key.
    #[must_use]
    pub fn with_api_key(mut self, api_key: impl Into<SecretString>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Sets the header that carries the API key.
    ///
    /// Some gateways read the key from a header such as `api-key`. The header then holds
    /// the key only, without the `Bearer` prefix.
    #[must_use]
    pub fn with_api_key_header(mut self, header: impl Into<String>) -> Self {
        self.api_key_header = Some(header.into());
        self
    }

    /// Sets the default chat model.
    #[must_use]
    pub fn with_chat_model(mut self, model: impl Into<String>) -> Self {
        self.chat_model = Some(model.into());
        self
    }

    /// Sets the default embedding model.
    #[must_use]
    pub fn with_embedding_model(mut self, model: impl Into<String>) -> Self {
        self.embedding_model = Some(model.into());
        self
    }

    /// Sets the timeout of one request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Adds one header to each request.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Sets the request field that carries the limit of output tokens.
    #[must_use]
    pub fn with_max_tokens_field(mut self, field: MaxTokensField) -> Self {
        self.max_tokens_field = field;
        self
    }
}

impl fmt::Debug for OpenAiCompatibleConfig {
    /// Prints the settings without the API key and without the header values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiCompatibleConfig")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("api_key_header", &self.api_key_header)
            .field("chat_model", &self.chat_model)
            .field("embedding_model", &self.embedding_model)
            .field("timeout", &self.timeout)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("max_tokens_field", &self.max_tokens_field)
            .finish()
    }
}

/// A model provider that speaks the OpenAI chat-completions format.
///
/// One adapter covers hosted APIs, gateways, and local servers such as Ollama and vLLM.
/// The adapter sends `POST {base_url}/chat/completions` and `POST {base_url}/embeddings`.
pub struct OpenAiCompatibleProvider {
    config: OpenAiCompatibleConfig,
    key_header: Option<HeaderName>,
    chat_url: Url,
    embeddings_url: Url,
    transport: Transport,
}

impl OpenAiCompatibleProvider {
    /// Makes a provider from its settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the base URL, the API key, the key header, the
    /// timeout, or a header is not valid.
    pub fn new(config: OpenAiCompatibleConfig) -> Result<Self> {
        let name = &config.name;
        if name.is_empty() {
            return Err(Error::Config("a provider must have a name".to_owned()));
        }
        let base_url = parse_base_url(name, &config.base_url)?;
        let key_header = match &config.api_key_header {
            // A key header with no key shows that the key setting is missing.
            Some(_) if config.api_key.is_none() => {
                return Err(Error::Config(format!(
                    "provider {name}: api_key_header is set, but the provider has no API key"
                )));
            }
            Some(header) => Some(HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                Error::Config(format!(
                    "provider {name}: api_key_header is not a valid header name"
                ))
            })?),
            None => None,
        };
        if let Some(api_key) = &config.api_key {
            if api_key.expose_secret().is_empty() {
                return Err(Error::Config(format!(
                    "provider {name}: the API key is empty"
                )));
            }
            // This check finds a key that an HTTP header cannot hold before the first request.
            secret_header(name, api_key.expose_secret())?;
            if sends_credential_in_cleartext(&base_url) {
                tracing::warn!(
                    provider = %name,
                    "the API key goes to a remote host without TLS"
                );
            }
        }
        let transport = Transport::new(
            name,
            &base_url,
            config.timeout,
            &config.headers,
            config.api_key.as_ref(),
            REFUSAL_CODES,
        )?;
        Ok(Self {
            key_header,
            chat_url: endpoint(&base_url, "chat/completions"),
            embeddings_url: endpoint(&base_url, "embeddings"),
            transport,
            config,
        })
    }

    /// Makes a provider named `local` for a server on the network of the operator.
    ///
    /// The provider sends no API key. Use it for Ollama ([`OLLAMA_BASE_URL`]), vLLM, and
    /// other local servers when the system has no access to the internet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the base URL is not valid.
    pub fn local(base_url: impl Into<String>, chat_model: impl Into<String>) -> Result<Self> {
        Self::new(OpenAiCompatibleConfig::new("local", base_url).with_chat_model(chat_model))
    }

    /// Returns the settings of this provider.
    #[must_use]
    pub fn config(&self) -> &OpenAiCompatibleConfig {
        &self.config
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        if let Some(api_key) = &self.config.api_key {
            let name = &self.config.name;
            match &self.key_header {
                Some(header) => {
                    headers.insert(header, secret_header(name, api_key.expose_secret())?);
                }
                None => {
                    let bearer = format!("Bearer {}", api_key.expose_secret());
                    headers.insert(AUTHORIZATION, secret_header(name, &bearer)?);
                }
            }
        }
        Ok(headers)
    }

    fn chat_model(&self, request: &ChatRequest) -> Result<String> {
        request
            .model
            .clone()
            .or_else(|| self.config.chat_model.clone())
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                Error::Config(format!(
                    "provider {}: the request names no model and the provider has no default chat model",
                    self.config.name
                ))
            })
    }
}

impl fmt::Debug for OpenAiCompatibleProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiCompatibleProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ModelProvider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            tools: true,
            streaming: true,
            embeddings: self.config.embedding_model.is_some(),
        }
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = self.chat_model(&request)?;
        let body = wire::chat_body(&request, &model, self.config.max_tokens_field, false)?;
        let completion: wire::Completion = self
            .transport
            .post_json(self.chat_url.clone(), self.headers()?, &body)
            .await?;
        wire::chat_response(&self.config.name, &model, completion)
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream> {
        let model = self.chat_model(&request)?;
        let body = wire::chat_body(&request, &model, self.config.max_tokens_field, true)?;
        let response = self
            .transport
            .post_stream(self.chat_url.clone(), self.headers()?, &body)
            .await?;
        Ok(sse::chat_stream(
            &self.config.name,
            self.transport.timeout(),
            response,
            stream::ChatAssembler::new(&self.config.name, self.transport.secrets()),
        ))
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let model = request
            .model
            .clone()
            .or_else(|| self.config.embedding_model.clone())
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                Error::Unsupported(format!(
                    "provider {} has no embedding model",
                    self.config.name
                ))
            })?;
        if request.input.is_empty() {
            return Ok(EmbeddingResponse {
                provider: self.config.name.clone(),
                model,
                embeddings: Vec::new(),
                usage: Usage::default(),
            });
        }
        let body = wire::EmbeddingBody {
            model: &model,
            input: &request.input,
        };
        let answer: wire::EmbeddingAnswer = self
            .transport
            .post_json(self.embeddings_url.clone(), self.headers()?, &body)
            .await?;
        wire::embedding_response(&self.config.name, &model, request.input.len(), answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_key_and_the_header_values() {
        let config = OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1")
            .with_api_key("sk-unit-test-key")
            .with_header("x-gateway-token", "gw-unit-test-token");
        let config_text = format!("{config:?}");
        assert!(config_text.contains("x-gateway-token"), "{config_text}");
        assert!(config_text.contains("[REDACTED]"), "{config_text}");
        assert!(!config_text.contains("sk-unit-test-key"), "{config_text}");
        assert!(!config_text.contains("gw-unit-test-token"), "{config_text}");

        let provider = OpenAiCompatibleProvider::new(config).unwrap();
        let provider_text = format!("{provider:?}");
        assert!(provider_text.contains("hosted"), "{provider_text}");
        assert!(
            !provider_text.contains("sk-unit-test-key"),
            "{provider_text}"
        );
        assert!(
            !provider_text.contains("gw-unit-test-token"),
            "{provider_text}"
        );
    }

    #[test]
    fn local_provider_has_no_key_and_the_given_model() {
        let provider = OpenAiCompatibleProvider::local(OLLAMA_BASE_URL, "llama3.1").unwrap();
        assert_eq!(provider.name(), "local");
        assert!(provider.config().api_key.is_none());
        assert_eq!(provider.config().chat_model.as_deref(), Some("llama3.1"));
        assert!(provider.headers().unwrap().is_empty());
        assert_eq!(
            provider.chat_url.as_str(),
            "http://localhost:11434/v1/chat/completions"
        );
        assert_eq!(
            provider.embeddings_url.as_str(),
            "http://localhost:11434/v1/embeddings"
        );
    }

    #[test]
    fn capabilities_report_embeddings_only_with_an_embedding_model() {
        let chat_only = OpenAiCompatibleProvider::local(OLLAMA_BASE_URL, "llama3.1").unwrap();
        assert_eq!(
            chat_only.capabilities(),
            ModelCapabilities {
                tools: true,
                streaming: true,
                embeddings: false,
            }
        );
        let with_embeddings = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig::new("local", OLLAMA_BASE_URL)
                .with_embedding_model("nomic-embed-text"),
        )
        .unwrap();
        assert!(with_embeddings.capabilities().embeddings);
    }

    #[test]
    fn invalid_settings_are_configuration_errors() {
        let no_name = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig::new(
            "",
            "https://api.example.test/v1",
        ))
        .unwrap_err();
        assert!(
            matches!(&no_name, Error::Config(text) if text == "a provider must have a name"),
            "{no_name}"
        );

        let empty_key = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1").with_api_key(""),
        )
        .unwrap_err();
        assert!(
            matches!(&empty_key, Error::Config(text) if text == "provider hosted: the API key is empty"),
            "{empty_key}"
        );

        let bad_key = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1")
                .with_api_key("sk-line\nbreak"),
        )
        .unwrap_err();
        assert!(matches!(&bad_key, Error::Config(_)), "{bad_key}");
        assert!(!bad_key.to_string().contains("sk-line"), "{bad_key}");

        let bad_url =
            OpenAiCompatibleProvider::new(OpenAiCompatibleConfig::new("hosted", "localhost:11434"))
                .unwrap_err();
        assert!(matches!(&bad_url, Error::Config(_)), "{bad_url}");
    }

    #[test]
    fn key_header_carries_the_key_without_the_bearer_prefix() {
        let hosted = || {
            OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1")
                .with_api_key("sk-unit-test-key")
        };
        let bearer = OpenAiCompatibleProvider::new(hosted()).unwrap();
        let bearer_headers = bearer.headers().unwrap();
        assert_eq!(bearer_headers.len(), 1);
        assert_eq!(
            bearer_headers.get(AUTHORIZATION).unwrap(),
            "Bearer sk-unit-test-key"
        );

        let custom =
            OpenAiCompatibleProvider::new(hosted().with_api_key_header("api-key")).unwrap();
        let custom_headers = custom.headers().unwrap();
        assert_eq!(custom_headers.len(), 1);
        let value = custom_headers.get("api-key").unwrap();
        assert_eq!(value, "sk-unit-test-key");
        assert!(value.is_sensitive());
        let debug = format!("{custom:?} {custom_headers:?}");
        assert!(debug.contains("api-key"), "{debug}");
        assert!(!debug.contains("sk-unit-test-key"), "{debug}");
    }

    #[test]
    fn key_header_must_be_a_header_name_and_needs_a_key() {
        let invalid = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1")
                .with_api_key("sk-unit-test-key")
                .with_api_key_header("api key"),
        )
        .unwrap_err();
        assert!(
            matches!(&invalid, Error::Config(text)
                if text == "provider hosted: api_key_header is not a valid header name"),
            "{invalid}"
        );

        let no_key = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig::new("hosted", "https://api.example.test/v1")
                .with_api_key_header("api-key"),
        )
        .unwrap_err();
        assert!(
            matches!(&no_key, Error::Config(text)
                if text == "provider hosted: api_key_header is set, but the provider has no API key"),
            "{no_key}"
        );
    }
}
