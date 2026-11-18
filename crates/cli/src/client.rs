//! A small client of the operator API of a running AEGIS service.
//!
//! The commands for timed reverts use this client. They do not read the revert store
//! file of a service: one scheduler uses one store, and a second writer can lose a
//! pending revert. The running service is the only component that changes the store.
//!
//! # Rules
//!
//! - The token comes from an environment variable. It is never an argument, so it is not
//!   in the process list and not in the shell history.
//! - The client sends the token only over HTTPS, or over HTTP to a loopback address.
//! - The client follows no redirect. A redirect would send the token to a different URL.
//! - No error message holds the token.

use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use reqwest::{Method, StatusCode, Url};
use serde_json::Value;

/// The default address of the operator API: the default of `api.bind`.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";

/// The environment variable that holds the address of the operator API.
pub const URL_VARIABLE: &str = "AEGIS_API_URL";

/// The default name of the environment variable that holds the API token.
pub const DEFAULT_TOKEN_VARIABLE: &str = "AEGIS_API_TOKEN";

/// The time limit of one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The largest number of characters of an error text of the server that the client shows.
const MAX_ERROR_CHARACTERS: usize = 300;

/// A client for the REST API of one running service.
pub struct ApiClient {
    base: Url,
    token: String,
    http: reqwest::Client,
}

/// Returns `true` if the host of `url` is a loopback address or the name `localhost`.
fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // The host of an IPv6 URL has brackets.
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// Reads and checks the address of the operator API.
///
/// # Errors
///
/// Returns an error if the text is not a URL with the scheme `http` or `https`, if it
/// holds a user name, a password, a query, or a fragment, or if it uses `http` for a host
/// that is not a loopback address.
pub fn parse_base_url(text: &str) -> anyhow::Result<Url> {
    // The message does not show the text: a URL can hold a password.
    let url =
        Url::parse(text.trim()).map_err(|error| anyhow!("the API URL is not valid: {error}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("the API URL must not hold a user name or a password");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("the API URL must not hold a query or a fragment");
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => bail!(
            "the API URL uses http for a host that is not a loopback address. The token \
             would go over the network with no encryption. Use https"
        ),
        other => bail!("the API URL must use https or http, not {other}"),
    }
    Ok(url)
}

/// Removes control characters from a text of the server and limits its length.
fn clean(text: &str) -> String {
    let mut clean: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_ERROR_CHARACTERS)
        .collect();
    if text.chars().count() > MAX_ERROR_CHARACTERS {
        clean.push_str("...");
    }
    clean
}

impl ApiClient {
    /// Makes a client for the service at `url`, with the token in the variable
    /// `token_variable`.
    ///
    /// `url` is the value of the command line. With `None`, the address comes from the
    /// variable `AEGIS_API_URL`, or it is the default address.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is not permitted, or if the token variable is not set
    /// or is empty. The message names the variable. It never shows the token.
    pub fn from_environment(url: Option<&str>, token_variable: &str) -> anyhow::Result<Self> {
        let from_environment = std::env::var(URL_VARIABLE).ok();
        let url = url
            .or(from_environment.as_deref())
            .filter(|text| !text.trim().is_empty())
            .unwrap_or(DEFAULT_URL);
        let token = std::env::var(token_variable).map_err(|_| {
            anyhow!(
                "the environment variable {token_variable} is not set. It must hold the API \
                 token of a principal with the permission approve_actions"
            )
        })?;
        Self::new(url, token.trim()).with_context(|| {
            format!("cannot use the API token of the environment variable {token_variable}")
        })
    }

    /// Makes a client for the service at `url` with `token`.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is not permitted, if the token is empty or has a
    /// character that an HTTP header cannot hold, or if the HTTP client cannot start.
    pub fn new(url: &str, token: &str) -> anyhow::Result<Self> {
        let base = parse_base_url(url)?;
        if token.is_empty() {
            bail!("the API token is empty");
        }
        if !token.chars().all(|character| character.is_ascii_graphic()) {
            bail!("the API token has a character that is not visible ASCII");
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("cannot start the HTTP client")?;
        Ok(Self {
            base,
            token: token.to_owned(),
            http,
        })
    }

    /// Returns the address of the service, with no path.
    pub fn address(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_owned()
    }

    /// Sends one request to a path below `/api/v1` and returns the JSON document of the
    /// answer.
    ///
    /// # Errors
    ///
    /// Returns an error if the service does not answer, if the status is not a success, or
    /// if the answer is not JSON. The message has the status, the error code, and the
    /// error text of the server.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> anyhow::Result<Value> {
        let url = self
            .base
            .join(&format!("/api/v1{path}"))
            .context("cannot make the URL of the request")?;
        let mut request = self
            .http
            .request(method.clone(), url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|error| {
            // The error of the client can show the URL. It never shows a header.
            anyhow!(
                "the operator API at {} did not answer: {}. Make sure that the service \
                 runs with the module `api`",
                self.address(),
                clean(&error.without_url().to_string())
            )
        })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("cannot read the answer of the operator API")?;
        if status.is_success() {
            return serde_json::from_str(&text)
                .context("the answer of the operator API is not JSON");
        }
        let document: Option<Value> = serde_json::from_str(&text).ok();
        let (code, message) = document
            .as_ref()
            .and_then(|document| document.get("error"))
            .map(|error| {
                (
                    error["code"].as_str().unwrap_or("error").to_owned(),
                    error["message"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .unwrap_or_else(|| ("error".to_owned(), String::new()));
        let hint = match status {
            StatusCode::UNAUTHORIZED => " The token is not a token of a principal of this service.",
            StatusCode::FORBIDDEN => {
                " The principal of the token needs the permission approve_actions."
            }
            _ => "",
        };
        bail!(
            "the operator API answered {method} {path} with the status {} ({}): {}{hint}",
            status.as_u16(),
            clean(&code),
            clean(&message)
        )
    }

    /// Sends a GET request.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ApiClient::send`].
    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.send(Method::GET, path, None).await
    }

    /// Sends a POST request with a JSON body.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ApiClient::send`].
    pub async fn post(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        self.send(Method::POST, path, Some(body)).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_token_goes_only_over_https_or_to_a_loopback_address() {
        for good in [
            "http://127.0.0.1:8080",
            "http://127.9.9.9:1",
            "http://[::1]:8080/",
            "http://localhost:8080",
            "http://LOCALHOST",
            "https://aegis.example.com",
            "https://192.0.2.10:8443/",
            " http://127.0.0.1:8080 ",
        ] {
            assert!(parse_base_url(good).is_ok(), "{good}");
        }
        for (bad, cause) in [
            (
                "http://192.0.2.10:8080",
                "uses http for a host that is not a loopback",
            ),
            (
                "http://aegis.example.com",
                "uses http for a host that is not a loopback",
            ),
            (
                "http://localhost.example.com",
                "uses http for a host that is not a loopback",
            ),
            ("ftp://127.0.0.1", "must use https or http, not ftp"),
            (
                "https://alice:secret@aegis.example.com",
                "user name or a password",
            ),
            (
                "https://aegis.example.com/?token=x",
                "a query or a fragment",
            ),
            ("https://aegis.example.com/#x", "a query or a fragment"),
            ("127.0.0.1:8080", "is not valid"),
            ("file:///etc/passwd", "must use https or http, not file"),
            ("not a url", "is not valid"),
        ] {
            let error = parse_base_url(bad).unwrap_err().to_string();
            assert!(error.contains(cause), "{bad}: {error}");
            assert!(!error.contains("secret"), "{error}");
        }
    }

    #[test]
    fn a_token_that_is_not_usable_is_refused_and_not_shown() {
        let error = ApiClient::new(DEFAULT_URL, "").err().unwrap().to_string();
        assert_eq!(error, "the API token is empty");
        let error = ApiClient::new(DEFAULT_URL, "abc def\r\nX-Evil: 1")
            .err()
            .unwrap()
            .to_string();
        assert_eq!(
            error,
            "the API token has a character that is not visible ASCII"
        );
        assert!(ApiClient::new(DEFAULT_URL, "0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn the_text_of_a_server_is_one_line_with_a_limit() {
        assert_eq!(clean("a\nb\u{1b}[31mc"), "a b [31mc");
        let long = clean(&"x".repeat(400));
        assert_eq!(long.chars().count(), 303);
        assert!(long.ends_with("..."));
    }
}
