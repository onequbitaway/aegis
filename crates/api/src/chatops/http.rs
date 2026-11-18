//! The HTTP client for webhooks, and the checks of webhook URLs.
//!
//! A webhook URL is a secret: a party that knows it can post messages. The functions in
//! this module never put a URL in an error or in a log line.

use std::net::IpAddr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use reqwest::redirect::Policy;
use url::{Host, Url};

/// Returns `true` if the host of `url` is a loopback address or `localhost`.
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Returns `true` if a request to `url` is permitted: HTTPS, or HTTP to a loopback
/// address. A URL with credentials is not permitted.
pub(crate) fn is_permitted_target(url: &Url) -> bool {
    let scheme_permitted = match url.scheme() {
        "https" => true,
        "http" => is_loopback(url),
        _ => false,
    };
    scheme_permitted
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
}

/// Parses the URL of a webhook from the environment variable `variable`.
///
/// # Errors
///
/// Returns [`Error::Config`] if the text is not a URL, or if the URL is not HTTPS and not
/// a loopback address. The message names the variable and does not show the URL.
pub(crate) fn webhook_url(text: &str, variable: &str) -> Result<Url> {
    let url = Url::parse(text.trim()).map_err(|_| {
        Error::Config(format!(
            "the webhook URL in the environment variable {variable} is not a valid URL"
        ))
    })?;
    if !is_permitted_target(&url) {
        return Err(Error::Config(format!(
            "the webhook URL in the environment variable {variable} must use HTTPS. Only a \
             loopback address can use HTTP. The URL must not hold credentials"
        )));
    }
    Ok(url)
}

/// The HTTP clients for webhook requests.
///
/// A request to a loopback address does not go through a proxy of the environment.
#[derive(Debug, Clone)]
pub(crate) struct Outbound {
    direct: reqwest::Client,
    proxied: reqwest::Client,
}

impl Outbound {
    /// Makes the clients. `timeout` is the maximum time for one request.
    pub(crate) fn new(timeout: Duration) -> Result<Self> {
        let builder = || {
            reqwest::Client::builder()
                // A redirect could send the message to a different host.
                .redirect(Policy::none())
                .timeout(timeout)
                .connect_timeout(timeout)
                .user_agent(concat!("aegis-api/", env!("CARGO_PKG_VERSION")))
        };
        let build = |builder: reqwest::ClientBuilder| {
            builder.build().map_err(|error| {
                Error::Config(format!(
                    "the webhook HTTP client did not start: {}",
                    error.without_url()
                ))
            })
        };
        Ok(Self {
            direct: build(builder().no_proxy())?,
            proxied: build(builder())?,
        })
    }

    /// Returns the client for a request to `url`.
    pub(crate) fn client_for(&self, url: &Url) -> &reqwest::Client {
        if is_loopback(url) {
            &self.direct
        } else {
            &self.proxied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_error(text: &str) -> String {
        match webhook_url(text, "AEGIS_HOOK") {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, found {other:?}"),
        }
    }

    #[test]
    fn https_and_loopback_http_are_permitted() {
        for text in [
            "https://hooks.slack.com/services/T000/B000/secret",
            "http://127.0.0.1:9000/hook",
            "http://localhost/hook",
            "http://[::1]:9000/hook",
            " https://example.webhook.office.com/webhookb2/abc \n",
        ] {
            assert!(webhook_url(text, "AEGIS_HOOK").is_ok(), "{text}");
        }
    }

    #[test]
    fn a_url_that_is_not_safe_is_an_error_that_does_not_show_the_url() {
        for text in [
            "http://hooks.slack.com/services/T000/B000/secret-part",
            "http://192.168.1.10/secret-part",
            "http://localhost.example.com/secret-part",
            "ftp://127.0.0.1/secret-part",
            "https://user:secret-part@example.com/hook",
            "file:///etc/secret-part",
        ] {
            let message = config_error(text);
            assert_eq!(
                message,
                "the webhook URL in the environment variable AEGIS_HOOK must use HTTPS. Only a \
                 loopback address can use HTTP. The URL must not hold credentials",
                "{text}"
            );
        }
        let message = config_error("not a url with secret-part");
        assert_eq!(
            message,
            "the webhook URL in the environment variable AEGIS_HOOK is not a valid URL"
        );
    }

    #[test]
    fn loopback_hosts_are_found() {
        let loopback = |text: &str| is_loopback(&Url::parse(text).unwrap());
        assert!(loopback("http://127.0.0.1/"));
        assert!(loopback("http://127.8.9.10:81/"));
        assert!(loopback("http://[::1]/"));
        assert!(loopback("http://LOCALHOST/"));
        assert!(!loopback("http://10.0.0.1/"));
        assert!(!loopback("http://localhost.evil.example/"));
        assert!(!loopback("http://0.0.0.0/"));
    }
}
