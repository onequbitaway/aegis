//! The HTTP transport that the provider adapters share.
//!
//! The transport sends JSON, applies the timeouts, and maps each failure to a contract
//! error. An error message from this module never holds a credential, a URL, a part of a
//! request body, or the message text of a provider. It can hold the short error
//! identifiers of the provider.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The largest answer body that an adapter reads, in bytes.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// The largest error body that an adapter reads, in bytes.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// The largest number of characters that an error message takes from provider data.
const MAX_LABEL_CHARS: usize = 64;

/// Parses and checks the base URL of a provider.
///
/// The error message does not show the URL, because a URL can hold a credential.
pub(crate) fn parse_base_url(provider: &str, base_url: &str) -> Result<Url> {
    let url = Url::parse(base_url.trim())
        .map_err(|_| Error::Config(format!("provider {provider}: base_url is not a valid URL")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config(format!(
            "provider {provider}: base_url must use the http or https scheme"
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Error::Config(format!(
            "provider {provider}: base_url has no host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(format!(
            "provider {provider}: base_url must not hold a credential; use an API key"
        )));
    }
    Ok(url)
}

/// Returns the URL of one endpoint below the base URL. The query of the base URL stays.
pub(crate) fn endpoint(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    let joined = format!(
        "{}/{}",
        base.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    url.set_path(&joined);
    url
}

/// Returns `true` if the host of `url` is this machine.
pub(crate) fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Returns `true` if a credential for `url` would cross a network without encryption.
pub(crate) fn sends_credential_in_cleartext(url: &Url) -> bool {
    url.scheme() == "http" && !is_loopback(url)
}

/// Makes a header value that `Debug` does not print.
pub(crate) fn secret_header(provider: &str, value: &str) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(value).map_err(|_| {
        Error::Config(format!(
            "provider {provider}: the API key has characters that an HTTP header cannot hold"
        ))
    })?;
    header.set_sensitive(true);
    Ok(header)
}

/// Keeps the characters of provider data that are safe in an error message.
///
/// Provider data can repeat a part of the prompt. Thus the result is short and has only
/// the characters of an identifier.
pub(crate) fn label(text: &str) -> String {
    text.chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':' | '/')
        })
        .take(MAX_LABEL_CHARS)
        .collect()
}

/// Describes where and why a JSON document is not valid, without its contents.
pub(crate) fn json_fault(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "read error",
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "unexpected structure",
        serde_json::error::Category::Eof => "unexpected end",
    };
    format!(
        "{category} at line {} column {}",
        error.line(),
        error.column()
    )
}

/// The shortest part of a secret that an error message must not show.
const MIN_SECRET_PART_CHARS: usize = 8;

/// Returns `true` if `text` has the form of an error identifier, for example `rate_limit_error`.
///
/// Text with a space or a different separator is not an identifier. It can be a sentence
/// that repeats a part of the prompt.
fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && text.len() <= MAX_LABEL_CHARS
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

/// The secrets of one provider. The adapter keeps them out of error messages.
#[derive(Clone, Default)]
pub(crate) struct Secrets(Arc<Vec<SecretString>>);

impl Secrets {
    /// Collects the API key and the header values that are long enough to be a secret.
    fn new(api_key: Option<&SecretString>, headers: &BTreeMap<String, String>) -> Self {
        let header_values = headers
            .values()
            .filter(|value| value.len() >= MIN_SECRET_PART_CHARS)
            .map(|value| SecretString::from(value.as_str()));
        Self(Arc::new(
            api_key.cloned().into_iter().chain(header_values).collect(),
        ))
    }

    /// Returns `true` if `text` shows a secret or a long part of a secret.
    fn exposes(&self, text: &str) -> bool {
        self.0.iter().any(|secret| {
            let secret = secret.expose_secret();
            !secret.is_empty()
                && (text.contains(secret)
                    || (text.len() >= MIN_SECRET_PART_CHARS && secret.contains(text)))
        })
    }

    /// Reads the error identifiers from an error body.
    pub(crate) fn labels_from_body(&self, body: &[u8]) -> ErrorLabels {
        match serde_json::from_slice::<Value>(body) {
            Ok(value) => self.labels(value.get("error")),
            Err(_) => ErrorLabels::default(),
        }
    }

    /// Reads the error identifiers from the `error` object of a provider.
    ///
    /// The human-readable message is not read. A value that is not an identifier, or that
    /// shows a secret, is not read.
    pub(crate) fn labels(&self, error: Option<&Value>) -> ErrorLabels {
        let field = |name: &str| match error?.get(name)? {
            Value::String(text) if is_identifier(text) && !self.exposes(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        };
        ErrorLabels {
            kind: field("type"),
            code: field("code"),
        }
    }
}

/// The machine-readable identifiers in the error body of a provider.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ErrorLabels {
    /// The `error.type` field.
    pub(crate) kind: Option<String>,
    /// The `error.code` field.
    pub(crate) code: Option<String>,
}

impl ErrorLabels {
    /// Returns `true` if one identifier is in `names`.
    pub(crate) fn is_one_of(&self, names: &[&str]) -> bool {
        [&self.kind, &self.code]
            .into_iter()
            .flatten()
            .any(|value| names.contains(&value.as_str()))
    }
}

impl fmt::Display for ErrorLabels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.kind, &self.code) {
            (Some(kind), Some(code)) => write!(formatter, " (type {kind}, code {code})"),
            (Some(kind), None) => write!(formatter, " (type {kind})"),
            (None, Some(code)) => write!(formatter, " (code {code})"),
            (None, None) => Ok(()),
        }
    }
}

/// Returns the text of the first cause of `error`.
fn root_cause(error: &(dyn StdError + 'static)) -> String {
    let mut cause = error;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// The HTTP client of one provider.
pub(crate) struct Transport {
    provider: String,
    client: Client,
    timeout: Duration,
    secrets: Secrets,
    refusal_codes: &'static [&'static str],
}

impl Transport {
    /// Makes the client of `provider`.
    ///
    /// `refusal_codes` are the error identifiers that mean "the provider refused the task".
    pub(crate) fn new(
        provider: &str,
        base_url: &Url,
        timeout: Duration,
        headers: &BTreeMap<String, String>,
        api_key: Option<&SecretString>,
        refusal_codes: &'static [&'static str],
    ) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::Config(format!(
                "provider {provider}: the timeout must be longer than zero"
            )));
        }
        let mut default_headers = HeaderMap::new();
        for (name, value) in headers {
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                Error::Config(format!(
                    "provider {provider}: {} is not a valid header name",
                    label(name)
                ))
            })?;
            let mut header_value = HeaderValue::from_str(value).map_err(|_| {
                Error::Config(format!(
                    "provider {provider}: the value of header {header_name} is not valid"
                ))
            })?;
            header_value.set_sensitive(true);
            default_headers.insert(header_name, header_value);
        }
        // A redirect could send the prompt and the credential to a different host.
        let mut builder = Client::builder()
            .default_headers(default_headers)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("aegis-model/", env!("CARGO_PKG_VERSION")));
        if is_loopback(base_url) {
            // A proxy from the environment must not receive the traffic to a local model.
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|error| {
            Error::Config(format!(
                "provider {provider}: the HTTP client did not start: {}",
                root_cause(&error.without_url())
            ))
        })?;
        Ok(Self {
            provider: provider.to_owned(),
            client,
            timeout,
            secrets: Secrets::new(api_key, headers),
            refusal_codes,
        })
    }

    /// Returns the secrets of the provider, for the checks of stream errors.
    pub(crate) fn secrets(&self) -> Secrets {
        self.secrets.clone()
    }

    /// Returns the timeout of one request.
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    fn request<B: Serialize>(
        &self,
        url: Url,
        headers: HeaderMap,
        body: &B,
    ) -> Result<RequestBuilder> {
        let body = serde_json::to_vec(body).map_err(|error| {
            Error::Serialization(format!(
                "the request to provider {} could not be encoded: {}",
                self.provider,
                json_fault(&error)
            ))
        })?;
        Ok(self
            .client
            .post(url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(body))
    }

    /// Sends a JSON body and decodes the JSON answer. The timeout covers the full exchange.
    pub(crate) async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: Url,
        headers: HeaderMap,
        body: &B,
    ) -> Result<T> {
        let response = self
            .request(url, headers, body)?
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|error| self.transport_error(error))?;
        let response = self.accept(response).await?;
        let bytes = self.read(response, MAX_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|error| {
            Error::Serialization(format!(
                "provider {} sent an answer that could not be decoded: {}",
                self.provider,
                json_fault(&error)
            ))
        })
    }

    /// Sends a JSON body and returns the answer when its status is a success.
    ///
    /// The timeout covers the time to the response headers. The caller reads the body.
    pub(crate) async fn post_stream<B: Serialize>(
        &self,
        url: Url,
        headers: HeaderMap,
        body: &B,
    ) -> Result<Response> {
        let request = self
            .request(url, headers, body)?
            .header(ACCEPT, "text/event-stream");
        let response = tokio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| self.timeout_error())?
            .map_err(|error| self.transport_error(error))?;
        self.accept(response).await
    }

    /// Returns the response if its status is a success. If not, returns the mapped error.
    async fn accept(&self, response: Response) -> Result<Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        // The identifiers are optional detail. A body that cannot be read gives none.
        let labels = match self.read(response, MAX_ERROR_BODY_BYTES).await {
            Ok(body) => self.secrets.labels_from_body(&body),
            Err(_) => ErrorLabels::default(),
        };
        Err(self.status_error(status, &labels))
    }

    /// Reads a body of `limit` bytes or fewer.
    async fn read(&self, mut response: Response, limit: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > limit {
                        return Err(Error::Serialization(format!(
                            "provider {} sent a body that is larger than {limit} bytes",
                            self.provider
                        )));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => return Ok(body),
                Err(error) => return Err(self.transport_error(error)),
            }
        }
    }

    /// Maps an HTTP status that is not a success to a contract error.
    pub(crate) fn status_error(&self, status: StatusCode, labels: &ErrorLabels) -> Error {
        let code = status.as_u16();
        let message = format!("provider {} returned HTTP {code}{labels}", self.provider);
        if status.is_client_error() && labels.is_one_of(self.refusal_codes) {
            return Error::Refused(message);
        }
        match code {
            401 | 403 => Error::Unauthorized(message),
            404 => Error::NotFound(message),
            408 => Error::Timeout(message),
            429 => Error::RateLimited(message),
            400..=499 => Error::InvalidInput(message),
            300..=399 => Error::Config(format!(
                "{message}; the adapter does not follow a redirect, so set base_url to the final address"
            )),
            _ => Error::Unavailable(message),
        }
    }

    /// Makes the error for a request that did not complete in the permitted time.
    pub(crate) fn timeout_error(&self) -> Error {
        Error::Timeout(format!(
            "provider {} did not answer in {:?}",
            self.provider, self.timeout
        ))
    }

    /// Maps a failure of the HTTP exchange to a contract error.
    pub(crate) fn transport_error(&self, error: reqwest::Error) -> Error {
        let error = error.without_url();
        if error.is_timeout() {
            return self.timeout_error();
        }
        let cause = root_cause(&error);
        if error.is_builder() {
            return Error::Config(format!(
                "provider {}: the request could not be built: {cause}",
                self.provider
            ));
        }
        if error.is_connect() {
            return Error::Unavailable(format!(
                "provider {} is not reachable: {cause}",
                self.provider
            ));
        }
        Error::Unavailable(format!(
            "the exchange with provider {} failed: {cause}",
            self.provider
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport(refusal_codes: &'static [&'static str]) -> Transport {
        let base = parse_base_url("p", "http://127.0.0.1:9/v1").unwrap();
        Transport::new(
            "p",
            &base,
            Duration::from_secs(5),
            &BTreeMap::new(),
            None,
            refusal_codes,
        )
        .unwrap()
    }

    #[test]
    fn base_url_must_be_http_with_a_host_and_no_credential() {
        let url = parse_base_url("p", " https://api.example.test/v1 ").unwrap();
        assert_eq!(url.as_str(), "https://api.example.test/v1");

        let scheme = parse_base_url("p", "ftp://example.test").unwrap_err();
        assert!(
            matches!(&scheme, Error::Config(text) if text == "provider p: base_url must use the http or https scheme"),
            "{scheme}"
        );
        let invalid = parse_base_url("p", "not a url").unwrap_err();
        assert!(
            matches!(&invalid, Error::Config(text) if text == "provider p: base_url is not a valid URL"),
            "{invalid}"
        );
        let credential = parse_base_url("p", "https://user:hunter2@example.test/v1").unwrap_err();
        assert!(
            matches!(&credential, Error::Config(text) if text.contains("must not hold a credential")),
            "{credential}"
        );
        assert!(!credential.to_string().contains("hunter2"));
    }

    #[test]
    fn endpoint_joins_the_path_and_keeps_the_query() {
        let plain = parse_base_url("p", "http://localhost:11434/v1").unwrap();
        assert_eq!(
            endpoint(&plain, "chat/completions").as_str(),
            "http://localhost:11434/v1/chat/completions"
        );
        let slash = parse_base_url("p", "http://localhost:11434/v1/").unwrap();
        assert_eq!(
            endpoint(&slash, "/embeddings").as_str(),
            "http://localhost:11434/v1/embeddings"
        );
        let root = parse_base_url("p", "https://api.example.test").unwrap();
        assert_eq!(
            endpoint(&root, "v1/messages").as_str(),
            "https://api.example.test/v1/messages"
        );
        let query = parse_base_url(
            "p",
            "https://gw.example.test/deployments/d1?api-version=2024-06-01",
        )
        .unwrap();
        assert_eq!(
            endpoint(&query, "chat/completions").as_str(),
            "https://gw.example.test/deployments/d1/chat/completions?api-version=2024-06-01"
        );
    }

    #[test]
    fn loopback_and_cleartext_checks_read_the_host_and_the_scheme() {
        let cases = [
            ("http://localhost:11434/v1", true, false),
            ("http://127.0.0.1:8000/v1", true, false),
            ("http://[::1]:8000/v1", true, false),
            ("http://vllm.internal:8000/v1", false, true),
            ("http://10.0.0.7:8000/v1", false, true),
            ("https://api.example.test/v1", false, false),
        ];
        for (text, loopback, cleartext) in cases {
            let url = parse_base_url("p", text).unwrap();
            assert_eq!(is_loopback(&url), loopback, "{text}");
            assert_eq!(sends_credential_in_cleartext(&url), cleartext, "{text}");
        }
    }

    #[test]
    fn labels_keep_identifiers_and_drop_the_message() {
        let secrets = Secrets::default();
        let body = br#"{"error":{"message":"the prompt said: secret plan","type":"invalid_request_error","code":"model_not_found"}}"#;
        let labels = secrets.labels_from_body(body);
        assert_eq!(
            labels,
            ErrorLabels {
                kind: Some("invalid_request_error".to_owned()),
                code: Some("model_not_found".to_owned()),
            }
        );
        assert_eq!(
            labels.to_string(),
            " (type invalid_request_error, code model_not_found)"
        );
        assert!(labels.is_one_of(&["model_not_found"]));
        assert!(!labels.is_one_of(&["content_filter"]));

        let numeric = secrets.labels_from_body(br#"{"error":{"code":429}}"#);
        assert_eq!(numeric.to_string(), " (code 429)");
        assert_eq!(
            secrets.labels_from_body(b"<html>bad gateway</html>"),
            ErrorLabels::default()
        );
        assert_eq!(
            secrets
                .labels_from_body(br#"{"error":"a plain message"}"#)
                .to_string(),
            ""
        );
        assert_eq!(secrets.labels(None), ErrorLabels::default());
    }

    #[test]
    fn labels_drop_a_value_that_is_not_an_identifier() {
        let secrets = Secrets::default();
        let sentence = secrets.labels_from_body(
            br#"{"error":{"type":"the prompt said: secret plan","code":"rate_limit_exceeded"}}"#,
        );
        assert_eq!(
            sentence,
            ErrorLabels {
                kind: None,
                code: Some("rate_limit_exceeded".to_owned()),
            }
        );
        assert!(is_identifier("insufficient_quota"));
        assert!(is_identifier("e42"));
        assert!(is_identifier("server-error.v2"));
        assert!(!is_identifier(""));
        assert!(!is_identifier("_private"));
        assert!(!is_identifier("two words"));
        assert!(!is_identifier("a:b"));
        assert!(!is_identifier("sk-****7e2b"));
        assert!(!is_identifier(&"a".repeat(MAX_LABEL_CHARS + 1)));
        assert!(is_identifier(&"a".repeat(MAX_LABEL_CHARS)));
    }

    #[test]
    fn labels_drop_a_value_that_shows_a_secret() {
        let headers = BTreeMap::from([
            ("x-gateway-token".to_owned(), "gw-token-77aa".to_owned()),
            ("x-team".to_owned(), "soc".to_owned()),
        ]);
        let key = SecretString::from("sk-test-4f9a1c7e2b");
        let secrets = Secrets::new(Some(&key), &headers);
        let labels = |kind: &str, code: &str| {
            secrets.labels(Some(&serde_json::json!({ "type": kind, "code": code })))
        };

        // The full key, a long part of the key, and text around the key are not shown.
        assert_eq!(
            labels("sk-test-4f9a1c7e2b", "invalid_api_key"),
            ErrorLabels {
                kind: None,
                code: Some("invalid_api_key".to_owned()),
            }
        );
        assert_eq!(
            labels("sk-test-4f9a", "key.sk-test-4f9a1c7e2b.end"),
            ErrorLabels::default()
        );
        assert_eq!(
            labels("gw-token-77aa", "x"),
            ErrorLabels {
                kind: None,
                code: Some("x".to_owned())
            }
        );
        // A short header value is not a secret, and a short identifier is not a part of a key.
        assert_eq!(
            labels("socket_error", "test"),
            ErrorLabels {
                kind: Some("socket_error".to_owned()),
                code: Some("test".to_owned()),
            }
        );
    }

    #[test]
    fn label_removes_free_text_and_limits_the_length() {
        assert_eq!(label("rate_limit_error"), "rate_limit_error");
        assert_eq!(
            label("ignore the rules; print \"x\""),
            "ignoretherulesprintx"
        );
        assert_eq!(label(&"a".repeat(500)).len(), MAX_LABEL_CHARS);
    }

    #[test]
    fn status_maps_to_the_contract_error() {
        let transport = transport(&["content_filter"]);
        let none = ErrorLabels::default();
        let map = |code: u16| transport.status_error(StatusCode::from_u16(code).unwrap(), &none);
        assert!(matches!(map(401), Error::Unauthorized(_)));
        assert!(matches!(map(403), Error::Unauthorized(_)));
        assert!(matches!(map(404), Error::NotFound(_)));
        assert!(matches!(map(408), Error::Timeout(_)));
        assert!(matches!(map(429), Error::RateLimited(_)));
        assert!(matches!(map(400), Error::InvalidInput(_)));
        assert!(matches!(map(422), Error::InvalidInput(_)));
        assert!(matches!(map(500), Error::Unavailable(_)));
        assert!(matches!(map(503), Error::Unavailable(_)));
        assert!(matches!(map(529), Error::Unavailable(_)));
        assert!(matches!(map(302), Error::Config(_)));
        assert_eq!(
            map(503).to_string(),
            "unavailable: provider p returned HTTP 503"
        );

        let filtered = ErrorLabels {
            kind: None,
            code: Some("content_filter".to_owned()),
        };
        let refused = transport.status_error(StatusCode::BAD_REQUEST, &filtered);
        assert!(
            matches!(&refused, Error::Refused(text) if text == "provider p returned HTTP 400 (code content_filter)"),
            "{refused}"
        );
        let server = transport.status_error(StatusCode::INTERNAL_SERVER_ERROR, &filtered);
        assert!(matches!(server, Error::Unavailable(_)));
    }

    #[test]
    fn transport_rejects_a_zero_timeout_and_an_invalid_header() {
        let base = parse_base_url("p", "http://127.0.0.1:9/v1").unwrap();
        let zero = Transport::new("p", &base, Duration::ZERO, &BTreeMap::new(), None, &[])
            .err()
            .unwrap();
        assert!(
            matches!(&zero, Error::Config(text) if text == "provider p: the timeout must be longer than zero"),
            "{zero}"
        );

        let name = BTreeMap::from([("bad name".to_owned(), "v".to_owned())]);
        let invalid_name = Transport::new("p", &base, Duration::from_secs(1), &name, None, &[])
            .err()
            .unwrap();
        assert!(
            matches!(&invalid_name, Error::Config(text) if text == "provider p: badname is not a valid header name"),
            "{invalid_name}"
        );

        let value = BTreeMap::from([("x-team".to_owned(), "secret\nvalue".to_owned())]);
        let invalid_value = Transport::new("p", &base, Duration::from_secs(1), &value, None, &[])
            .err()
            .unwrap();
        assert!(
            matches!(&invalid_value, Error::Config(text) if text == "provider p: the value of header x-team is not valid"),
            "{invalid_value}"
        );
    }

    #[test]
    fn secret_header_is_sensitive_and_rejects_control_characters() {
        let header = secret_header("p", "Bearer sk-test-123").unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("sk-test-123"));

        let invalid = secret_header("p", "sk-test\n123").unwrap_err();
        assert!(matches!(&invalid, Error::Config(_)), "{invalid}");
        assert!(!invalid.to_string().contains("sk-test"));
    }

    #[test]
    fn json_fault_gives_the_position_and_not_the_content() {
        let error = serde_json::from_str::<Vec<u64>>(r#"["secret prompt text"]"#).unwrap_err();
        let fault = json_fault(&error);
        assert_eq!(fault, "unexpected structure at line 1 column 21");
        let syntax = serde_json::from_str::<Value>("{").unwrap_err();
        assert_eq!(json_fault(&syntax), "unexpected end at line 1 column 1");
    }
}
