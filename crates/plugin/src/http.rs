//! Outbound HTTP for plugins.
//!
//! A plugin has no sockets. The host sends each HTTP request for the plugin, and this
//! module decides if the host sends it. The rules are deny by default:
//!
//! - The destination must be in `allowed_hosts` of the plugin manifest. The host and the
//!   port must match exactly.
//! - The scheme must be `https`. Plain `http` is permitted only for a loopback address.
//! - The host does not follow a redirect, because a redirect can point to a destination
//!   that is not permitted. The plugin gets the 3xx response.
//! - The host sends each request one time. It does not try again.
//! - A request to a loopback address goes directly to this computer. It does not use a
//!   proxy, and the name `localhost` does not use DNS.

use std::error::Error as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, ClientBuilder, Method};
use thiserror::Error;
use url::{Host, Url};

use crate::bindings::host::{Request, Response};
use crate::limits::HostLimits;
use crate::text::clean;

/// The methods that a plugin can use.
const METHODS: [Method; 6] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
];

/// The headers that control the connection. Only the host sets them.
const FORBIDDEN_HEADERS: [&str; 12] = [
    "connection",
    "content-length",
    "host",
    "http2-settings",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
/// The only DNS name that the host accepts as a loopback address.
const LOCALHOST: &str = "localhost";

/// Why the host did not complete an HTTP request of a plugin.
///
/// A message never contains the path or the query of a URL, a header value, or a body,
/// because each of them can hold a secret.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum HttpError {
    /// The URL has no valid syntax or no host.
    #[error("the URL is not valid")]
    InvalidUrl,
    /// The URL has a user name or a password.
    #[error("the URL must not contain credentials; send them in a header")]
    Credentials,
    /// The scheme is not `https` or `http`.
    #[error("the scheme {0} is not permitted; use https")]
    Scheme(String),
    /// The scheme is `http` and the host is not a loopback address.
    #[error("plain http is permitted only for a loopback address, and {0} is not one")]
    PlainHttp(String),
    /// The destination is not in `allowed_hosts`.
    #[error("the destination {0} is not in allowed_hosts")]
    NotAllowed(String),
    /// The method is not in the permitted list.
    #[error("the method {0} is not permitted")]
    Method(String),
    /// The header controls the connection.
    #[error("the header {0} is not permitted")]
    ForbiddenHeader(String),
    /// The header name or the header value has characters that are not valid.
    #[error("the header {0} is not valid")]
    InvalidHeader(String),
    /// The plugin used all the requests of one call. A refused request counts.
    #[error("the plugin made more than {0} HTTP requests in one call")]
    TooManyRequests(u32),
    /// The response body is larger than the limit.
    #[error("the response body is larger than {0} bytes")]
    ResponseTooLarge(usize),
    /// The request did not complete in the permitted time.
    #[error("the request did not complete in {0:?}")]
    Timeout(Duration),
    /// The connection or the transfer failed.
    #[error("the request failed: {0}")]
    Transport(String),
}

/// One destination that a plugin can send requests to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    host: Host<String>,
    /// `None` permits only the default port of the scheme.
    port: Option<u16>,
}

/// The destinations that one plugin can send requests to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HttpPolicy {
    destinations: Vec<Destination>,
}

/// A URL that the policy permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Permitted {
    /// The parsed URL.
    pub(crate) url: Url,
    /// `true` if the host of the URL is a loopback address or the name `localhost`.
    pub(crate) loopback: bool,
}

impl HttpPolicy {
    /// Parses the `allowed_hosts` entries of a manifest.
    ///
    /// Each entry is `host` or `host:port`. Write an IPv6 address in brackets. The error
    /// text names the entry that is not valid.
    pub(crate) fn parse(entries: &[String]) -> Result<Self, String> {
        let destinations = entries
            .iter()
            .map(|entry| parse_destination(entry))
            .collect::<Result<_, _>>()?;
        Ok(Self { destinations })
    }

    /// Returns the parsed URL if the policy permits a request to it.
    pub(crate) fn permit(&self, url: &str) -> Result<Permitted, HttpError> {
        let url = Url::parse(url).map_err(|_| HttpError::InvalidUrl)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpError::Credentials);
        }
        let (plain, default_port) = match url.scheme() {
            "https" => (false, HTTPS_PORT),
            "http" => (true, HTTP_PORT),
            other => return Err(HttpError::Scheme(other.to_owned())),
        };
        let host = url.host().ok_or(HttpError::InvalidUrl)?;
        let port = url.port().unwrap_or(default_port);
        let destination = format!("{host}:{port}");
        let loopback = is_loopback(&host);
        if plain && !loopback {
            return Err(HttpError::PlainHttp(destination));
        }
        let permitted = self
            .destinations
            .iter()
            .any(|allowed| allowed.host == host && allowed.port.unwrap_or(default_port) == port);
        if permitted {
            Ok(Permitted { url, loopback })
        } else {
            Err(HttpError::NotAllowed(destination))
        }
    }
}

fn parse_destination(entry: &str) -> Result<Destination, String> {
    let invalid =
        |reason: &str| format!("the allowed_hosts entry {entry:?} is not valid: {reason}");
    if entry.contains('*') {
        return Err(invalid("wildcards are not supported"));
    }
    if entry.contains('/') {
        return Err(invalid("write only the host and an optional port"));
    }
    let (host, port) = match entry.rsplit_once(':') {
        // The last colon of `[::1]` is a part of the address.
        Some((host, port)) if !port.ends_with(']') => {
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid("the port must be a number from 1 to 65535"))?;
            (host, Some(port))
        }
        _ => (entry, None),
    };
    let host = Host::parse(host).map_err(|error| invalid(&error.to_string()))?;
    Ok(Destination { host, port })
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => *name == LOCALHOST,
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

/// The HTTP clients that send the requests of all plugins of one host.
#[derive(Debug, Clone)]
pub(crate) struct HttpClients {
    /// Sends the requests to loopback addresses.
    loopback: Client,
    /// Sends all other requests. It refuses a URL that is not `https`.
    remote: Client,
}

impl HttpClients {
    /// Makes the clients with the time limit of `limits`.
    pub(crate) fn new(limits: &HostLimits) -> Result<Self, reqwest::Error> {
        Ok(Self {
            loopback: loopback_client(builder(limits))?,
            remote: builder(limits).https_only(true).build()?,
        })
    }
}

/// Returns the settings that the two clients share.
fn builder(limits: &HostLimits) -> ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .timeout(limits.http_timeout)
        .user_agent(concat!("aegis-plugin/", env!("CARGO_PKG_VERSION")))
}

/// Makes the client for loopback addresses from `builder`.
///
/// Plain `http` is permitted for a loopback address because the data stays on this
/// computer. Thus this client must connect directly:
///
/// - It uses no proxy. A proxy from the environment would get the request in plain text.
/// - It does not ask DNS for `localhost`. An answer could be an address on the network.
fn loopback_client(builder: ClientBuilder) -> Result<Client, reqwest::Error> {
    // With the port 0, the client uses the port of the URL.
    let localhost = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ];
    builder
        .no_proxy()
        .resolve_to_addrs(LOCALHOST, &localhost)
        .build()
}

/// The network path of one plugin call.
///
/// The gate counts the requests of the call and applies the policy of the plugin.
pub(crate) struct HttpGate {
    clients: HttpClients,
    policy: Arc<HttpPolicy>,
    timeout: Duration,
    max_response_bytes: usize,
    max_requests: u32,
    /// The requests that the plugin made in this call. A refused request counts.
    attempts: u32,
}

impl HttpGate {
    /// Makes the gate for one call.
    pub(crate) fn new(clients: HttpClients, policy: Arc<HttpPolicy>, limits: &HostLimits) -> Self {
        Self {
            clients,
            policy,
            timeout: limits.http_timeout,
            max_response_bytes: limits.max_http_response_bytes,
            max_requests: limits.max_http_requests_per_call,
            attempts: 0,
        }
    }

    /// Sends one request if the policy permits it, and reads the full response.
    pub(crate) async fn send(&mut self, request: Request) -> Result<Response, HttpError> {
        // A refused request also counts. Thus a plugin cannot make the host do the checks
        // and write a refusal to the log without end.
        if self.attempts >= self.max_requests {
            return Err(HttpError::TooManyRequests(self.max_requests));
        }
        self.attempts += 1;
        let Permitted { url, loopback } = self.policy.permit(&request.url)?;
        let method = METHODS
            .iter()
            .find(|method| method.as_str() == request.method)
            .cloned()
            .ok_or_else(|| HttpError::Method(clean(&request.method)))?;
        let headers = parse_headers(&request.headers)?;

        let client = if loopback {
            &self.clients.loopback
        } else {
            &self.clients.remote
        };
        let mut builder = client.request(method, url).headers(headers);
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|error| self.transport_error(error))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let limit = self.max_response_bytes;
        let too_large = HttpError::ResponseTooLarge(limit);
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(too_large);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| self.transport_error(error))?
        {
            if chunk.len() > limit - body.len() {
                return Err(too_large);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    fn transport_error(&self, error: reqwest::Error) -> HttpError {
        if error.is_timeout() {
            return HttpError::Timeout(self.timeout);
        }
        // The top message of `reqwest` holds the URL. The causes do not.
        let mut causes = Vec::new();
        let mut cause = error.source();
        while let Some(error) = cause {
            causes.push(error.to_string());
            cause = error.source();
        }
        let reason = if causes.is_empty() {
            error.without_url().to_string()
        } else {
            causes.join(": ")
        };
        HttpError::Transport(clean(&reason))
    }
}

fn parse_headers(headers: &[(String, String)]) -> Result<HeaderMap, HttpError> {
    let mut parsed = HeaderMap::new();
    for (name, value) in headers {
        let header = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpError::InvalidHeader(clean(name)))?;
        if FORBIDDEN_HEADERS.contains(&header.as_str()) {
            return Err(HttpError::ForbiddenHeader(header.as_str().to_owned()));
        }
        let value = HeaderValue::from_str(value)
            .map_err(|_| HttpError::InvalidHeader(header.as_str().to_owned()))?;
        parsed.append(header, value);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wiremock::matchers::{any, body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn policy(entries: &[&str]) -> HttpPolicy {
        let entries: Vec<String> = entries.iter().map(|entry| (*entry).to_owned()).collect();
        HttpPolicy::parse(&entries).unwrap()
    }

    fn request(method: &str, url: &str) -> Request {
        Request {
            method: method.to_owned(),
            url: url.to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Makes a gate that permits only `server`.
    fn gate(server: &MockServer, limits: &HostLimits) -> HttpGate {
        let entry = server.address().to_string();
        HttpGate::new(
            HttpClients::new(limits).unwrap(),
            Arc::new(policy(&[&entry])),
            limits,
        )
    }

    #[test]
    fn the_policy_permits_only_an_exact_host() {
        let policy = policy(&["api.example.com"]);
        let permitted = policy
            .permit("https://api.example.com/v1/items?page=2")
            .unwrap();
        assert_eq!(
            permitted.url.as_str(),
            "https://api.example.com/v1/items?page=2"
        );
        assert!(!permitted.loopback);
        // The match ignores the case of the host, as DNS does.
        let permitted = policy.permit("https://API.Example.COM/").unwrap();
        assert_eq!(permitted.url.as_str(), "https://api.example.com/");

        for url in [
            "https://example.com/",
            "https://evil.api.example.com/",
            "https://api.example.com.evil.test/",
            "https://api.example.com./",
            "https://api-example.com/",
        ] {
            let error = policy.permit(url).unwrap_err();
            assert!(
                matches!(error, HttpError::NotAllowed(_)),
                "{url}: {error:?}"
            );
        }
    }

    #[test]
    fn the_refusal_names_the_destination_and_hides_the_path() {
        let error = policy(&["api.example.com"])
            .permit("https://other.example.com/hooks/secret-token?key=secret-key")
            .unwrap_err();
        assert_eq!(
            error,
            HttpError::NotAllowed("other.example.com:443".to_owned())
        );
        assert_eq!(
            error.to_string(),
            "the destination other.example.com:443 is not in allowed_hosts"
        );
    }

    #[test]
    fn the_policy_matches_the_port_exactly() {
        let default_port = policy(&["api.example.com"]);
        default_port.permit("https://api.example.com:443/").unwrap();
        assert_eq!(
            default_port.permit("https://api.example.com:8443/"),
            Err(HttpError::NotAllowed("api.example.com:8443".to_owned()))
        );

        let custom_port = policy(&["api.example.com:8443"]);
        custom_port.permit("https://api.example.com:8443/").unwrap();
        assert_eq!(
            custom_port.permit("https://api.example.com/"),
            Err(HttpError::NotAllowed("api.example.com:443".to_owned()))
        );
    }

    #[test]
    fn the_policy_permits_plain_http_only_for_loopback() {
        let policy = policy(&[
            "api.example.com",
            "api.example.com:80",
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
        ]);
        for url in [
            "http://127.0.0.1:8080/hook",
            "http://localhost:8080/hook",
            "http://[::1]:8080/hook",
        ] {
            let permitted = policy.permit(url).unwrap();
            assert_eq!(permitted.url.as_str(), url);
            assert!(permitted.loopback, "{url}");
        }
        assert_eq!(
            policy.permit("http://api.example.com/"),
            Err(HttpError::PlainHttp("api.example.com:80".to_owned()))
        );
        // A loopback address is not permitted by itself. It must be in the list.
        assert_eq!(
            policy.permit("http://127.0.0.1:9090/"),
            Err(HttpError::NotAllowed("127.0.0.1:9090".to_owned()))
        );
        assert_eq!(
            policy.permit("http://127.0.0.2:8080/"),
            Err(HttpError::NotAllowed("127.0.0.2:8080".to_owned()))
        );
    }

    #[test]
    fn the_policy_sees_through_other_spellings_of_an_address() {
        let policy = policy(&["127.0.0.1:8080"]);
        // These URLs all name 127.0.0.1. The policy compares the parsed address.
        for url in ["http://2130706433:8080/", "http://0x7f.0.0.1:8080/"] {
            let permitted = policy.permit(url).unwrap();
            assert_eq!(permitted.url.as_str(), "http://127.0.0.1:8080/");
            assert!(permitted.loopback, "{url}");
        }
        // The text before `@` is a user name, and the real host is not permitted.
        assert_eq!(
            policy.permit("https://127.0.0.1:8080@evil.test/"),
            Err(HttpError::Credentials)
        );
    }

    #[test]
    fn the_policy_treats_only_loopback_addresses_and_localhost_as_loopback() {
        let policy = policy(&[
            "127.0.0.1:8443",
            "127.9.9.9",
            "localhost",
            "localhost.example.com:80",
            "[::ffff:127.0.0.1]:8080",
            "10.0.0.5",
        ]);
        for url in [
            "https://127.0.0.1:8443/",
            "https://127.9.9.9/",
            "https://localhost/",
        ] {
            assert!(policy.permit(url).unwrap().loopback, "{url}");
        }
        assert!(!policy.permit("https://10.0.0.5/").unwrap().loopback);
        // These names and addresses look like loopback, but they are not. Plain HTTP to
        // them can leave this computer.
        assert_eq!(
            policy.permit("http://localhost.example.com/"),
            Err(HttpError::PlainHttp("localhost.example.com:80".to_owned()))
        );
        assert_eq!(
            policy.permit("http://[::ffff:127.0.0.1]:8080/"),
            Err(HttpError::PlainHttp("[::ffff:7f00:1]:8080".to_owned()))
        );
        assert_eq!(
            policy.permit("http://10.0.0.5/"),
            Err(HttpError::PlainHttp("10.0.0.5:80".to_owned()))
        );
    }

    #[test]
    fn the_policy_refuses_other_schemes_credentials_and_bad_urls() {
        let policy = policy(&["api.example.com"]);
        assert_eq!(
            policy.permit("ftp://api.example.com/"),
            Err(HttpError::Scheme("ftp".to_owned()))
        );
        assert_eq!(
            policy.permit("file:///etc/passwd"),
            Err(HttpError::Scheme("file".to_owned()))
        );
        assert_eq!(
            policy.permit("https://user:password@api.example.com/"),
            Err(HttpError::Credentials)
        );
        assert_eq!(policy.permit("not a url"), Err(HttpError::InvalidUrl));
        assert_eq!(policy.permit("/relative/path"), Err(HttpError::InvalidUrl));
    }

    #[test]
    fn an_empty_policy_permits_nothing() {
        let policy = HttpPolicy::default();
        assert_eq!(
            policy.permit("https://api.example.com/"),
            Err(HttpError::NotAllowed("api.example.com:443".to_owned()))
        );
        assert_eq!(
            policy.permit("http://127.0.0.1/"),
            Err(HttpError::NotAllowed("127.0.0.1:80".to_owned()))
        );
    }

    #[test]
    fn parse_refuses_entries_that_are_not_a_host_and_an_optional_port() {
        for entry in [
            "*.example.com",
            "*",
            "https://api.example.com",
            "api.example.com/path",
            "api.example.com:",
            "api.example.com:0",
            "api.example.com:99999",
            "api.example.com:https",
            "api.example.com:80:90",
            "user@api.example.com",
            "api example.com",
            "::1",
            "[::1",
            "",
        ] {
            let error = HttpPolicy::parse(&[entry.to_owned()]).unwrap_err();
            assert!(
                error.contains(&format!("{entry:?}")) && error.contains("is not valid"),
                "{entry:?}: {error}"
            );
        }
    }

    #[test]
    fn parse_normalizes_the_host() {
        assert_eq!(policy(&["API.Example.COM"]), policy(&["api.example.com"]));
        assert_eq!(policy(&["[0:0:0:0:0:0:0:1]:443"]), policy(&["[::1]:443"]));
        assert_ne!(
            policy(&["api.example.com"]),
            policy(&["api.example.com:8443"])
        );
    }

    #[tokio::test]
    async fn the_gate_sends_the_request_and_returns_the_full_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("x-token", "abc"))
            .and(body_bytes(b"ping".to_vec()))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("x-reply", "yes")
                    .set_body_bytes(b"pong".to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut gate = gate(&server, &HostLimits::default());

        let mut request = request("POST", &format!("{}/hook", server.uri()));
        request.headers = vec![("X-Token".to_owned(), "abc".to_owned())];
        request.body = Some(b"ping".to_vec());
        let response = gate.send(request).await.unwrap();

        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"pong");
        assert!(
            response
                .headers
                .contains(&("x-reply".to_owned(), "yes".to_owned())),
            "{:?}",
            response.headers
        );
    }

    #[tokio::test]
    async fn the_gate_sends_nothing_to_a_destination_that_is_not_permitted() {
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        let mut gate = gate(&server, &HostLimits::default());

        let error = gate
            .send(request("GET", &format!("{}/data", other.uri())))
            .await
            .unwrap_err();

        assert_eq!(error, HttpError::NotAllowed(other.address().to_string()));
        assert_eq!(other.received_requests().await.unwrap().len(), 0);
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_gate_does_not_follow_a_redirect() {
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/secret", other.uri())),
            )
            .mount(&server)
            .await;
        let mut gate = gate(&server, &HostLimits::default());

        let response = gate
            .send(request("GET", &format!("{}/start", server.uri())))
            .await
            .unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(other.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_gate_refuses_a_response_that_declares_a_body_over_the_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7; 2048]))
            .mount(&server)
            .await;
        let limits = HostLimits {
            max_http_response_bytes: 1024,
            ..HostLimits::default()
        };
        let mut gate = gate(&server, &limits);

        let error = gate.send(request("GET", &server.uri())).await.unwrap_err();
        assert_eq!(error, HttpError::ResponseTooLarge(1024));

        let at_the_limit = HostLimits {
            max_http_response_bytes: 2048,
            ..HostLimits::default()
        };
        let response = self::gate(&server, &at_the_limit)
            .send(request("GET", &server.uri()))
            .await
            .unwrap();
        assert_eq!(response.body.len(), 2048);
    }

    #[tokio::test]
    async fn the_gate_stops_a_streamed_body_that_goes_over_the_limit() {
        // This server sends a chunked body, which has no declared length.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = [0; 1024];
            let _ = stream.read(&mut received).await.unwrap();
            let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
            stream.write_all(head.as_bytes()).await.unwrap();
            let chunk = format!("{:x}\r\n{}\r\n", 600, "a".repeat(600));
            for _ in 0..4 {
                // The client closes the connection when it has too much data.
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });
        let limits = HostLimits {
            max_http_response_bytes: 1024,
            ..HostLimits::default()
        };
        let mut gate = HttpGate::new(
            HttpClients::new(&limits).unwrap(),
            Arc::new(policy(&[&address.to_string()])),
            &limits,
        );

        let error = gate
            .send(request("GET", &format!("http://{address}/")))
            .await
            .unwrap_err();

        assert_eq!(error, HttpError::ResponseTooLarge(1024));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn the_gate_limits_the_number_of_requests_in_one_call() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let limits = HostLimits {
            max_http_requests_per_call: 2,
            ..HostLimits::default()
        };
        let mut gate = gate(&server, &limits);

        for _ in 0..2 {
            let response = gate.send(request("GET", &server.uri())).await.unwrap();
            assert_eq!(response.status, 204);
        }
        let error = gate.send(request("GET", &server.uri())).await.unwrap_err();

        assert_eq!(error, HttpError::TooManyRequests(2));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_refused_request_counts_as_a_request_of_the_call() {
        let server = MockServer::start().await;
        let limits = HostLimits {
            max_http_requests_per_call: 2,
            ..HostLimits::default()
        };
        let mut gate = gate(&server, &limits);

        for _ in 0..2 {
            let error = gate
                .send(request("GET", "https://other.example.com/"))
                .await
                .unwrap_err();
            assert_eq!(
                error,
                HttpError::NotAllowed("other.example.com:443".to_owned())
            );
        }
        // The destination of this request is permitted, but the call has no requests left.
        let error = gate.send(request("GET", &server.uri())).await.unwrap_err();
        assert_eq!(error, HttpError::TooManyRequests(2));
        let error = gate
            .send(request("GET", "https://other.example.com/"))
            .await
            .unwrap_err();
        assert_eq!(error, HttpError::TooManyRequests(2));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_loopback_client_connects_directly_when_a_proxy_is_configured() {
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&target)
            .await;
        // A client that uses this server as its proxy sends each plain request to it.
        let proxy = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(502))
            .mount(&proxy)
            .await;
        let with_proxy =
            builder(&HostLimits::default()).proxy(reqwest::Proxy::all(proxy.uri()).unwrap());

        let client = loopback_client(with_proxy).unwrap();
        let response = client
            .get(format!("{}/data", target.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 204);
        assert_eq!(target.received_requests().await.unwrap().len(), 1);
        assert_eq!(proxy.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_remote_client_refuses_a_url_that_is_not_https() {
        let server = MockServer::start().await;
        let clients = HttpClients::new(&HostLimits::default()).unwrap();

        let error = clients.remote.get(server.uri()).send().await.unwrap_err();

        assert!(error.is_builder(), "{error:?}");
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_gate_refuses_methods_and_headers_that_are_not_permitted() {
        let server = MockServer::start().await;
        let mut gate = gate(&server, &HostLimits::default());

        for method in ["CONNECT", "TRACE", "get", "GET /x HTTP/1.1\r\nHost: evil"] {
            let error = gate.send(request(method, &server.uri())).await.unwrap_err();
            assert!(matches!(error, HttpError::Method(_)), "{method}: {error:?}");
        }
        let error = gate
            .send(request("GET\r\nX-Injected: 1", &server.uri()))
            .await
            .unwrap_err();
        assert_eq!(error, HttpError::Method("GET  X-Injected: 1".to_owned()));

        for name in [
            "Host",
            "transfer-encoding",
            "Content-Length",
            "proxy-authorization",
        ] {
            let mut request = request("GET", &server.uri());
            request.headers = vec![(name.to_owned(), "value".to_owned())];
            let error = gate.send(request).await.unwrap_err();
            assert_eq!(error, HttpError::ForbiddenHeader(name.to_lowercase()));
        }

        let mut bad_name = request("GET", &server.uri());
        bad_name.headers = vec![("bad name".to_owned(), "value".to_owned())];
        assert_eq!(
            gate.send(bad_name).await.unwrap_err(),
            HttpError::InvalidHeader("bad name".to_owned())
        );
        let mut bad_value = request("GET", &server.uri());
        bad_value.headers = vec![("x-token".to_owned(), "secret\r\nx-injected: 1".to_owned())];
        let error = gate.send(bad_value).await.unwrap_err();
        // The error names the header and does not show the value.
        assert_eq!(error, HttpError::InvalidHeader("x-token".to_owned()));

        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_gate_reports_a_slow_server_as_a_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let limits = HostLimits {
            http_timeout: Duration::from_millis(100),
            ..HostLimits::default()
        };
        let mut gate = gate(&server, &limits);

        let error = gate.send(request("GET", &server.uri())).await.unwrap_err();

        assert_eq!(error, HttpError::Timeout(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn the_gate_reports_a_closed_port_as_a_transport_error_without_the_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let limits = HostLimits::default();
        let mut gate = HttpGate::new(
            HttpClients::new(&limits).unwrap(),
            Arc::new(policy(&[&address.to_string()])),
            &limits,
        );

        let error = gate
            .send(request(
                "GET",
                &format!("http://{address}/hooks/secret-token"),
            ))
            .await
            .unwrap_err();

        let HttpError::Transport(reason) = &error else {
            panic!("expected a transport error, got {error:?}");
        };
        assert!(!reason.is_empty());
        assert!(!reason.contains("secret-token"), "{reason}");
    }
}
