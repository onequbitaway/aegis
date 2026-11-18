//! The configuration of the model layer, and the function that builds a router from it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::model::{ModelProvider, TaskKind};
use aegis_contracts::{Error, Result};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::DEFAULT_TIMEOUT;
use crate::anthropic::{
    ANTHROPIC_BASE_URL, AnthropicConfig, AnthropicProvider, DEFAULT_MAX_OUTPUT_TOKENS,
};
use crate::openai::{MaxTokensField, OpenAiCompatibleConfig, OpenAiCompatibleProvider};
use crate::router::{Budget, Route, Router};

fn default_timeout() -> Duration {
    DEFAULT_TIMEOUT
}

fn default_anthropic_base_url() -> String {
    ANTHROPIC_BASE_URL.to_owned()
}

fn default_max_output_tokens() -> u32 {
    DEFAULT_MAX_OUTPUT_TOKENS
}

/// The settings of one provider. The `kind` field selects the adapter.
///
/// The configuration never holds an API key. It holds the name of the environment
/// variable that holds the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ProviderConfig {
    /// A provider that uses the OpenAI chat-completions format: `kind = "openai_compatible"`.
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible {
        /// The base URL of the API, for example `http://localhost:11434/v1`.
        base_url: String,
        /// The name of the environment variable that holds the API key. A local server
        /// has no key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key_env: Option<String>,
        /// The header that carries the API key, for example `api-key`. Without it, the
        /// adapter sends `Authorization: Bearer <key>`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key_header: Option<String>,
        /// The chat model for a request and a route that name no model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chat_model: Option<String>,
        /// The embedding model for a request and a route that name no model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        embedding_model: Option<String>,
        /// The timeout of one request, for example `60s`.
        #[serde(default = "default_timeout", with = "humantime_serde")]
        timeout: Duration,
        /// Headers that each request carries. Do not put a secret here.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        /// The request field that carries the limit of output tokens.
        #[serde(default)]
        max_tokens_field: MaxTokensField,
    },
    /// The Anthropic Messages API: `kind = "anthropic"`.
    #[serde(rename = "anthropic")]
    Anthropic {
        /// The base URL of the API, without the `/v1/messages` path.
        #[serde(default = "default_anthropic_base_url")]
        base_url: String,
        /// The name of the environment variable that holds the API key.
        api_key_env: String,
        /// The chat model for a request and a route that name no model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chat_model: Option<String>,
        /// The timeout of one request, for example `60s`.
        #[serde(default = "default_timeout", with = "humantime_serde")]
        timeout: Duration,
        /// Headers that each request carries. Do not put a secret here.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        /// The limit of output tokens for a request that sets no limit.
        #[serde(default = "default_max_output_tokens")]
        max_output_tokens: u32,
    },
}

/// The routes of the router: one ordered list for each task kind, and a default list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoutesConfig {
    /// The routes for each task kind that has no list of its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default: Vec<Route>,
    /// The routes for one task kind. The key is the name of the task kind, for example
    /// `triage`.
    #[serde(flatten)]
    pub tasks: HashMap<TaskKind, Vec<Route>>,
}

/// The configuration of the model layer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    /// The providers. The key is the name of the provider.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
    /// The routes.
    #[serde(default)]
    pub routes: RoutesConfig,
    /// The token budget. The default budget has no limits.
    #[serde(default)]
    pub budget: Budget,
}

/// Reads one variable from the environment of the process.
///
/// Give this function to [`build_router`] in a program. A variable that is not set, or
/// that is not valid Unicode, gives `None`.
#[must_use]
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Returns `true` if `name` has only the characters of an environment variable name.
fn is_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Reads the API key of `provider` from the environment variable `variable`.
fn api_key<F>(provider: &str, variable: &str, env: &F) -> Result<SecretString>
where
    F: Fn(&str) -> Option<String>,
{
    // A key that is in the place of the variable name must not go into the error message.
    if !is_variable_name(variable) {
        return Err(Error::Config(format!(
            "provider {provider}: api_key_env must be the name of an environment variable"
        )));
    }
    env(variable)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(SecretString::from)
        .ok_or_else(|| {
            Error::Config(format!(
                "provider {provider}: the environment variable {variable} is not set"
            ))
        })
}

impl ProviderConfig {
    /// Makes the provider `name` from these settings.
    fn build<F>(&self, name: &str, env: &F) -> Result<Arc<dyn ModelProvider>>
    where
        F: Fn(&str) -> Option<String>,
    {
        match self {
            Self::OpenAiCompatible {
                base_url,
                api_key_env,
                api_key_header,
                chat_model,
                embedding_model,
                timeout,
                headers,
                max_tokens_field,
            } => {
                let api_key = api_key_env
                    .as_deref()
                    .map(|variable| api_key(name, variable, env))
                    .transpose()?;
                let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
                    name: name.to_owned(),
                    base_url: base_url.clone(),
                    api_key,
                    api_key_header: api_key_header.clone(),
                    chat_model: chat_model.clone(),
                    embedding_model: embedding_model.clone(),
                    timeout: *timeout,
                    headers: headers.clone(),
                    max_tokens_field: *max_tokens_field,
                })?;
                Ok(Arc::new(provider))
            }
            Self::Anthropic {
                base_url,
                api_key_env,
                chat_model,
                timeout,
                headers,
                max_output_tokens,
            } => {
                let provider = AnthropicProvider::new(AnthropicConfig {
                    name: name.to_owned(),
                    base_url: base_url.clone(),
                    api_key: api_key(name, api_key_env, env)?,
                    chat_model: chat_model.clone(),
                    timeout: *timeout,
                    headers: headers.clone(),
                    max_output_tokens: *max_output_tokens,
                })?;
                Ok(Arc::new(provider))
            }
        }
    }
}

/// Builds the router that `config` describes.
///
/// `env` returns the value of an environment variable. The function calls it for each
/// `api_key_env` name. Use [`process_env`] in a program and a closure in a test.
///
/// # Errors
///
/// Returns [`Error::Config`] in these conditions:
///
/// - The configuration has no providers.
/// - The key variable of a provider is not set or is empty. The message names the variable.
/// - The settings of a provider are not valid.
/// - The routes are not valid. See [`RouterBuilder::build`](crate::RouterBuilder::build).
pub fn build_router<F>(config: &ModelConfig, env: F) -> Result<Router>
where
    F: Fn(&str) -> Option<String>,
{
    if config.providers.is_empty() {
        return Err(Error::Config(
            "the model configuration has no providers".to_owned(),
        ));
    }
    let mut builder = Router::builder()
        .budget(config.budget.clone())
        .default_routes(config.routes.default.clone());
    for (name, provider) in &config.providers {
        builder = builder.provider(provider.build(name, &env)?);
    }
    for (task, routes) in &config.routes.tasks {
        builder = builder.route(*task, routes.clone());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_names_have_only_letters_digits_and_underscores() {
        assert!(is_variable_name("OPENAI_API_KEY"));
        assert!(is_variable_name("_key2"));
        assert!(!is_variable_name(""));
        assert!(!is_variable_name("2KEY"));
        assert!(!is_variable_name("sk-proj-abc123"));
        assert!(!is_variable_name("KEY NAME"));
    }

    #[test]
    fn api_key_comes_from_the_named_variable_without_surrounding_space() {
        use secrecy::ExposeSecret;

        let env = |name: &str| (name == "AEGIS_KEY").then(|| " sk-from-env\n".to_owned());
        let key = api_key("hosted", "AEGIS_KEY", &env).unwrap();
        assert_eq!(key.expose_secret(), "sk-from-env");
    }

    #[test]
    fn missing_or_empty_variable_is_a_configuration_error_that_names_the_variable() {
        let expected = "provider hosted: the environment variable AEGIS_KEY is not set";
        let missing = api_key("hosted", "AEGIS_KEY", &|_: &str| None).unwrap_err();
        assert!(
            matches!(&missing, Error::Config(text) if text == expected),
            "{missing}"
        );
        let empty = api_key("hosted", "AEGIS_KEY", &|_: &str| Some("  ".to_owned())).unwrap_err();
        assert!(
            matches!(&empty, Error::Config(text) if text == expected),
            "{empty}"
        );
    }

    #[test]
    fn a_key_in_the_place_of_the_variable_name_stays_out_of_the_error() {
        let error = api_key("hosted", "sk-proj-abc123", &|_: &str| None).unwrap_err();
        assert!(
            matches!(&error, Error::Config(text)
                if text == "provider hosted: api_key_env must be the name of an environment variable"),
            "{error}"
        );
    }
}
