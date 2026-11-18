//! The adapter for the Anthropic Messages API.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use aegis_contracts::model::{
    ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse, ModelCapabilities,
    ModelProvider,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use reqwest::Url;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};

use crate::DEFAULT_TIMEOUT;
use crate::http::{
    Transport, endpoint, parse_base_url, secret_header, sends_credential_in_cleartext,
};
use crate::sse;

mod stream;
mod wire;

/// The base URL of the Anthropic API.
pub const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// The API version that the adapter sends in the `anthropic-version` header.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The default limit of output tokens. The API requires a limit in each request.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4096;

const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");
const VERSION_HEADER: HeaderName = HeaderName::from_static("anthropic-version");

/// The settings of one [`AnthropicProvider`].
#[derive(Clone)]
pub struct AnthropicConfig {
    /// The name of the provider. The router and the answers use this name.
    pub name: String,
    /// The base URL of the API, without the `/v1/messages` path.
    pub base_url: String,
    /// The API key.
    pub api_key: SecretString,
    /// The chat model for a request that names no model.
    pub chat_model: Option<String>,
    /// The timeout of one request. For a stream, the timeout applies to each read.
    pub timeout: Duration,
    /// Headers that each request carries in addition to the standard headers.
    pub headers: BTreeMap<String, String>,
    /// The limit of output tokens for a request that sets no limit.
    pub max_output_tokens: u32,
}

impl AnthropicConfig {
    /// Makes settings for the public API with no default model and the default timeout.
    pub fn new(name: impl Into<String>, api_key: impl Into<SecretString>) -> Self {
        Self {
            name: name.into(),
            base_url: ANTHROPIC_BASE_URL.to_owned(),
            api_key: api_key.into(),
            chat_model: None,
            timeout: DEFAULT_TIMEOUT,
            headers: BTreeMap::new(),
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }

    /// Sets the base URL, for example the address of a gateway.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Sets the default chat model.
    #[must_use]
    pub fn with_chat_model(mut self, model: impl Into<String>) -> Self {
        self.chat_model = Some(model.into());
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

    /// Sets the limit of output tokens for a request that sets no limit.
    #[must_use]
    pub fn with_max_output_tokens(mut self, limit: u32) -> Self {
        self.max_output_tokens = limit;
        self
    }
}

impl fmt::Debug for AnthropicConfig {
    /// Prints the settings without the API key and without the header values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicConfig")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("chat_model", &self.chat_model)
            .field("timeout", &self.timeout)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

/// A model provider that speaks the Anthropic Messages API.
///
/// The adapter sends `POST {base_url}/v1/messages`. The API has no embeddings, so
/// [`ModelProvider::embed`] returns [`Error::Unsupported`].
pub struct AnthropicProvider {
    config: AnthropicConfig,
    messages_url: Url,
    transport: Transport,
}

impl AnthropicProvider {
    /// Makes a provider from its settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the base URL, the API key, the timeout, the limit of
    /// output tokens, or a header is not valid.
    pub fn new(config: AnthropicConfig) -> Result<Self> {
        let name = &config.name;
        if name.is_empty() {
            return Err(Error::Config("a provider must have a name".to_owned()));
        }
        let base_url = parse_base_url(name, &config.base_url)?;
        if config.api_key.expose_secret().is_empty() {
            return Err(Error::Config(format!(
                "provider {name}: the API key is empty"
            )));
        }
        // This check finds a key that an HTTP header cannot hold before the first request.
        secret_header(name, config.api_key.expose_secret())?;
        if config.max_output_tokens == 0 {
            return Err(Error::Config(format!(
                "provider {name}: max_output_tokens must be larger than zero"
            )));
        }
        if sends_credential_in_cleartext(&base_url) {
            tracing::warn!(
                provider = %name,
                "the API key goes to a remote host without TLS"
            );
        }
        let transport = Transport::new(
            name,
            &base_url,
            config.timeout,
            &config.headers,
            Some(&config.api_key),
            &[],
        )?;
        Ok(Self {
            messages_url: endpoint(&base_url, "v1/messages"),
            transport,
            config,
        })
    }

    /// Returns the settings of this provider.
    #[must_use]
    pub fn config(&self) -> &AnthropicConfig {
        &self.config
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            API_KEY_HEADER,
            secret_header(&self.config.name, self.config.api_key.expose_secret())?,
        );
        headers.insert(VERSION_HEADER, HeaderValue::from_static(ANTHROPIC_VERSION));
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

impl fmt::Debug for AnthropicProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ModelProvider for AnthropicProvider {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            tools: true,
            streaming: true,
            embeddings: false,
        }
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = self.chat_model(&request)?;
        let body = wire::messages_body(&request, &model, self.config.max_output_tokens, false)?;
        let answer: wire::MessagesAnswer = self
            .transport
            .post_json(self.messages_url.clone(), self.headers()?, &body)
            .await?;
        wire::chat_response(&self.config.name, &model, request.response_format, answer)
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream> {
        let model = self.chat_model(&request)?;
        let body = wire::messages_body(&request, &model, self.config.max_output_tokens, true)?;
        let response = self
            .transport
            .post_stream(self.messages_url.clone(), self.headers()?, &body)
            .await?;
        Ok(sse::chat_stream(
            &self.config.name,
            self.transport.timeout(),
            response,
            stream::MessagesAssembler::new(&self.config.name, self.transport.secrets()),
        ))
    }

    async fn embed(&self, _request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        Err(Error::Unsupported(format!(
            "provider {} does not make embeddings",
            self.config.name
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_key_and_the_header_values() {
        let config = AnthropicConfig::new("claude", "sk-ant-unit-test-key")
            .with_header("x-gateway-token", "gw-unit-test-token");
        let config_text = format!("{config:?}");
        assert!(config_text.contains("x-gateway-token"), "{config_text}");
        assert!(config_text.contains("[REDACTED]"), "{config_text}");
        assert!(
            !config_text.contains("sk-ant-unit-test-key"),
            "{config_text}"
        );
        assert!(!config_text.contains("gw-unit-test-token"), "{config_text}");

        let provider = AnthropicProvider::new(config).unwrap();
        let provider_text = format!("{provider:?}");
        assert!(provider_text.contains("claude"), "{provider_text}");
        assert!(
            !provider_text.contains("sk-ant-unit-test-key"),
            "{provider_text}"
        );
        let headers_text = format!("{:?}", provider.headers().unwrap());
        assert!(headers_text.contains("x-api-key"), "{headers_text}");
        assert!(
            !headers_text.contains("sk-ant-unit-test-key"),
            "{headers_text}"
        );
    }

    #[test]
    fn default_settings_use_the_public_api() {
        let provider = AnthropicProvider::new(AnthropicConfig::new("claude", "k")).unwrap();
        assert_eq!(
            provider.messages_url.as_str(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(provider.config().max_output_tokens, 4096);
        assert_eq!(
            provider.capabilities(),
            ModelCapabilities {
                tools: true,
                streaming: true,
                embeddings: false,
            }
        );
    }

    #[test]
    fn invalid_settings_are_configuration_errors() {
        let empty_key = AnthropicProvider::new(AnthropicConfig::new("claude", "")).unwrap_err();
        assert!(
            matches!(&empty_key, Error::Config(text) if text == "provider claude: the API key is empty"),
            "{empty_key}"
        );
        let no_limit =
            AnthropicProvider::new(AnthropicConfig::new("claude", "k").with_max_output_tokens(0))
                .unwrap_err();
        assert!(
            matches!(&no_limit, Error::Config(text) if text == "provider claude: max_output_tokens must be larger than zero"),
            "{no_limit}"
        );
        let no_name = AnthropicProvider::new(AnthropicConfig::new("", "k")).unwrap_err();
        assert!(
            matches!(&no_name, Error::Config(text) if text == "a provider must have a name"),
            "{no_name}"
        );
    }
}
