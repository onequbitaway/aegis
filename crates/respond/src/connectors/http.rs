//! HTTP functions that the connectors share.

use std::net::IpAddr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use reqwest::{Client, Response, StatusCode};
use url::{Host, Url};

const USER_AGENT: &str = concat!("aegis-respond/", env!("CARGO_PKG_VERSION"));

/// Makes an HTTP client that does not follow redirects.
///
/// A redirect can send a token or a signed document to a different host.
pub(crate) fn client(timeout: Duration) -> Result<Client> {
    if timeout.is_zero() {
        return Err(Error::Config(
            "the HTTP timeout must be more than zero".to_owned(),
        ));
    }
    Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT)
        .build()
        .map_err(|error| Error::Config(format!("cannot make the HTTP client: {error}")))
}

/// Returns `true` if the host of `url` is a loopback address or `localhost`.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Parses an endpoint URL and checks that it is safe to send a credential to it.
///
/// The URL must use `https`. Plain `http` is permitted only for a loopback host. `what`
/// names the setting in the error text. The error text does not contain the URL.
pub(crate) fn secure_url(text: &str, what: &str) -> Result<Url> {
    let url = Url::parse(text.trim())
        .map_err(|error| Error::Config(format!("{what} is not a valid URL: {error}")))?;
    if url.host().is_none() {
        return Err(Error::Config(format!("{what} must have a host")));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(format!(
            "{what} must not contain a user name or a password"
        )));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback(&url) => Ok(url),
        "http" => Err(Error::Config(format!(
            "{what} must use https; plain http is permitted only for a loopback host"
        ))),
        scheme => Err(Error::Config(format!(
            "{what} must use https, not the scheme {scheme:?}"
        ))),
    }
}

/// Returns the host and the port of a URL, for messages. The path can hold a secret.
pub(crate) fn host_label(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// Converts a transport failure to a contract error. The text does not contain the URL.
pub(crate) fn transport_error(error: reqwest::Error, what: &str) -> Error {
    let error = error.without_url();
    if error.is_timeout() {
        Error::Timeout(format!("{what}: the request timed out"))
    } else if error.is_connect() {
        Error::Unavailable(format!("{what}: cannot connect to the server"))
    } else if error.is_builder() {
        Error::InvalidInput(format!("{what}: cannot build the request: {error}"))
    } else {
        Error::Unavailable(format!("{what}: the request failed: {error}"))
    }
}

/// Converts an HTTP status that is not a success to a contract error.
///
/// `code` is a short error code from the response, if the server sent one.
pub(crate) fn status_error(status: StatusCode, what: &str, code: Option<&str>) -> Error {
    let detail = match code {
        Some(code) => format!("{what}: HTTP {} ({code})", status.as_u16()),
        None => format!("{what}: HTTP {}", status.as_u16()),
    };
    match status.as_u16() {
        401 | 403 => Error::Unauthorized(detail),
        404 => Error::NotFound(detail),
        408 => Error::Timeout(detail),
        429 => Error::RateLimited(detail),
        300..=399 => Error::Config(format!(
            "{detail}: the server sent a redirect; set the final URL in the configuration"
        )),
        400..=499 => Error::InvalidInput(detail),
        _ => Error::Unavailable(detail),
    }
}

/// Reads the body of a response, up to `limit` bytes. More bytes are ignored.
pub(crate) async fn read_limited(
    mut response: Response,
    limit: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while body.len() < limit {
        let chunk = response
            .chunk()
            .await
            .map_err(|error| transport_error(error, what))?;
        let Some(chunk) = chunk else { break };
        let room = limit - body.len();
        body.extend_from_slice(chunk.get(..room).unwrap_or(&chunk));
    }
    Ok(body)
}

/// Keeps only the characters of an error code that are safe to put in a message.
pub(crate) fn safe_code(code: &str) -> Option<String> {
    let cleaned: String = code
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
        })
        .take(64)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_and_loopback_http_are_permitted() {
        for text in [
            "https://hooks.example.com/aegis",
            "http://127.0.0.1:8080/hook",
            "http://127.8.9.10/hook",
            "http://[::1]:9000/hook",
            "http://localhost:3000/hook",
            "HTTP://LOCALHOST/hook",
        ] {
            let url = secure_url(text, "the endpoint").unwrap();
            assert!(url.host().is_some(), "{text}");
        }
    }

    #[test]
    fn plain_http_to_a_host_that_is_not_loopback_is_rejected() {
        for text in [
            "http://hooks.example.com/aegis",
            "http://192.0.2.10/hook",
            "http://localhost.example.com/hook",
            "http://[2001:db8::1]/hook",
        ] {
            let error = secure_url(text, "the endpoint").unwrap_err();
            assert!(
                matches!(&error, Error::Config(message) if message.contains("must use https")),
                "{text}: {error:?}"
            );
        }
    }

    #[test]
    fn other_schemes_credentials_and_bad_urls_are_rejected() {
        let scheme = secure_url("ftp://files.example.com/x", "the endpoint").unwrap_err();
        assert!(
            matches!(&scheme, Error::Config(message) if message.contains("not the scheme")),
            "{scheme:?}"
        );
        let credentials =
            secure_url("https://user:hunter2@hooks.example.com/x", "the endpoint").unwrap_err();
        assert!(
            matches!(&credentials, Error::Config(message) if message.contains("user name") && !message.contains("hunter2")),
            "{credentials:?}"
        );
        let invalid = secure_url("not a url", "the endpoint").unwrap_err();
        assert!(
            matches!(&invalid, Error::Config(message) if message.contains("not a valid URL")),
            "{invalid:?}"
        );
    }

    #[test]
    fn each_status_maps_to_its_contract_error() {
        let map = |status: u16| status_error(StatusCode::from_u16(status).unwrap(), "call", None);
        assert!(matches!(map(401), Error::Unauthorized(_)));
        assert!(matches!(map(403), Error::Unauthorized(_)));
        assert!(matches!(map(404), Error::NotFound(_)));
        assert!(matches!(map(408), Error::Timeout(_)));
        assert!(matches!(map(429), Error::RateLimited(_)));
        assert!(matches!(map(500), Error::Unavailable(_)));
        assert!(matches!(map(503), Error::Unavailable(_)));
        assert!(matches!(map(400), Error::InvalidInput(_)));
        assert!(matches!(map(302), Error::Config(_)));
        let with_code = status_error(
            StatusCode::NOT_FOUND,
            "call",
            Some("Request_ResourceNotFound"),
        );
        assert!(
            matches!(&with_code, Error::NotFound(message) if message == "call: HTTP 404 (Request_ResourceNotFound)"),
            "{with_code:?}"
        );
    }

    #[test]
    fn an_error_code_keeps_only_safe_characters() {
        assert_eq!(
            safe_code("Request_ResourceNotFound").as_deref(),
            Some("Request_ResourceNotFound")
        );
        assert_eq!(
            safe_code("bad code\n<script>").as_deref(),
            Some("badcodescript")
        );
        assert_eq!(safe_code("  "), None);
        assert_eq!(safe_code(&"x".repeat(200)).map(|code| code.len()), Some(64));
    }

    #[test]
    fn the_host_label_has_no_path() {
        let url = Url::parse("https://hooks.example.com:8443/services/T0/secret-token").unwrap();
        assert_eq!(host_label(&url), "hooks.example.com:8443");
        let url = Url::parse("https://hooks.example.com/services/T0/secret-token").unwrap();
        assert_eq!(host_label(&url), "hooks.example.com");
    }
}
