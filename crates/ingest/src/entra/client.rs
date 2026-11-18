//! The HTTP client for the token service and for Microsoft Graph.
//!
//! The client only sends `GET` requests to the log endpoints and one `POST` request to the
//! token endpoint. It does not change data in the tenant.

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use aegis_contracts::event::EventSource;
use aegis_contracts::{Error, Event, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use reqwest::{Response, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::config::Settings;
use super::normalize::{self, NormalizeError};

/// The largest body of a log page that the client accepts.
const PAGE_BODY_LIMIT: usize = 64 * 1024 * 1024;
/// The largest body of a token response or an error response that the client reads.
const SMALL_BODY_LIMIT: usize = 64 * 1024;
/// The time before the expiry at which the client gets a new token.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// The token lifetime that the client assumes if the token service gives none.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(300);
/// The largest number of pages in one read. More pages mean that the paging does not end.
const MAX_PAGES: usize = 100_000;
/// The longest time for which one `Retry-After` value stops the requests of the client.
const MAX_BLOCK: Duration = Duration::from_secs(60 * 60);

/// One log of Entra ID that the connector reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Feed {
    /// The user sign-in log.
    SignIns,
    /// The service principal sign-in log.
    ServicePrincipalSignIns,
    /// The directory audit log.
    DirectoryAudits,
}

impl Feed {
    /// Returns the name of the feed in cursors, log lines, and error messages.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::SignIns => "sign_ins",
            Self::ServicePrincipalSignIns => "service_principal_sign_ins",
            Self::DirectoryAudits => "directory_audits",
        }
    }

    /// Returns the path of the endpoint below the base URL of Microsoft Graph.
    fn path(self) -> &'static str {
        match self {
            Self::SignIns => "v1.0/auditLogs/signIns",
            Self::ServicePrincipalSignIns => "beta/auditLogs/signIns",
            Self::DirectoryAudits => "v1.0/auditLogs/directoryAudits",
        }
    }

    /// Returns the name of the time field of the records.
    fn time_field(self) -> &'static str {
        match self {
            Self::SignIns | Self::ServicePrincipalSignIns => "createdDateTime",
            Self::DirectoryAudits => "activityDateTime",
        }
    }

    /// Returns the OData filter for records from `lower` to `upper`, the two included.
    ///
    /// The log endpoints support only `ge` and `le` on the time field.
    pub(crate) fn filter(self, lower: DateTime<Utc>, upper: Option<DateTime<Utc>>) -> String {
        let field = self.time_field();
        let mut filter = format!("{field} ge {}", filter_time(lower));
        if let Some(upper) = upper {
            filter.push_str(&format!(" and {field} le {}", filter_time(upper)));
        }
        match self {
            Self::ServicePrincipalSignIns => {
                format!("({filter}) and signInEventTypes/any(t: t eq 'servicePrincipal')")
            }
            Self::SignIns | Self::DirectoryAudits => filter,
        }
    }

    /// Converts one record of this feed to an event.
    pub(crate) fn normalize(
        self,
        record: &Value,
        source: &EventSource,
    ) -> std::result::Result<Event, NormalizeError> {
        match self {
            Self::SignIns | Self::ServicePrincipalSignIns => normalize::sign_in(record, source),
            Self::DirectoryAudits => normalize::directory_audit(record, source),
        }
    }
}

/// Formats a time for an OData filter, in whole seconds.
fn filter_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// A condition of the HTTP exchange that has no more specific contract error.
#[derive(Debug, thiserror::Error)]
enum ProtocolError {
    #[error("the response body is larger than {0} bytes")]
    BodyTooLarge(usize),
    #[error("unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("the paging did not end after {0} pages")]
    EndlessPaging(usize),
    #[error("the HTTP client could not start: {0}")]
    ClientBuild(String),
}

/// One page of records from a log endpoint.
#[derive(Debug)]
pub(crate) struct Page {
    /// The records of the page.
    pub records: Vec<Value>,
    /// The link to the next page.
    pub next_link: Option<Url>,
}

#[derive(Deserialize)]
struct PageBody {
    #[serde(default)]
    value: Vec<Value>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<SecretString>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<Value>,
}

#[derive(Deserialize)]
struct TokenErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_codes: Vec<u64>,
}

#[derive(Clone)]
struct CachedToken {
    value: SecretString,
    refresh_at: Instant,
}

/// The HTTP client of one connector. It keeps the access token until shortly before the
/// expiry.
pub(crate) struct GraphClient {
    http: reqwest::Client,
    settings: Arc<Settings>,
    token: Mutex<Option<CachedToken>>,
    /// The instant before which Microsoft Graph asked for no more requests.
    blocked_until: std::sync::Mutex<Option<Instant>>,
}

impl GraphClient {
    pub(crate) fn new(settings: Arc<Settings>) -> Result<Self> {
        let https_only =
            settings.token_url.scheme() == "https" && settings.graph_origin.scheme() == "https";
        let http = reqwest::Client::builder()
            .user_agent(concat!("aegis-ingest/", env!("CARGO_PKG_VERSION")))
            .timeout(settings.request_timeout)
            // A redirect could send the client secret or the token to a different host.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https_only)
            .build()
            .map_err(|error| {
                Error::other(
                    format!("entra source {}: start the HTTP client", settings.name),
                    ProtocolError::ClientBuild(error.without_url().to_string()),
                )
            })?;
        Ok(Self {
            http,
            settings,
            token: Mutex::new(None),
            blocked_until: std::sync::Mutex::new(None),
        })
    }

    /// Records that Microsoft Graph asked for no more requests during `delay`.
    ///
    /// The record ends after [`MAX_BLOCK`] at the latest. Thus a value that is not sensible
    /// cannot stop the connector for a long time.
    fn block_for(&self, delay: Duration) {
        let now = Instant::now();
        let until = now.checked_add(delay.min(MAX_BLOCK)).unwrap_or(now);
        let mut blocked = self
            .blocked_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if blocked.is_none_or(|current| current < until) {
            *blocked = Some(until);
        }
    }

    /// Returns the time that remains of the wait that Microsoft Graph asked for.
    fn blocked_for(&self) -> Option<Duration> {
        let mut blocked = self
            .blocked_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let remaining = (*blocked)?.checked_duration_since(Instant::now());
        match remaining {
            Some(remaining) if !remaining.is_zero() => Some(remaining),
            _ => {
                *blocked = None;
                None
            }
        }
    }

    /// Returns the URL of the first page of `feed` for the time range.
    pub(crate) fn first_page(
        &self,
        feed: Feed,
        lower: DateTime<Utc>,
        upper: Option<DateTime<Utc>>,
        page_size: u32,
    ) -> Result<Url> {
        let text = format!(
            "{}/{}?$filter={}&$top={page_size}",
            self.settings.graph_base,
            feed.path(),
            percent_encode(&feed.filter(lower, upper)),
        );
        Url::parse(&text).map_err(|error| {
            Error::Config(format!(
                "entra source {}: the URL of {} is not valid: {error}",
                self.settings.name,
                feed.key()
            ))
        })
    }

    /// Parses a next-page link and checks that it stays on the Microsoft Graph host.
    ///
    /// The client sends the access token to this URL. Thus a link to a different host is
    /// rejected.
    pub(crate) fn checked_link(&self, link: &str) -> std::result::Result<Url, String> {
        let url = Url::parse(link).map_err(|error| format!("the link is not a URL: {error}"))?;
        let origin = &self.settings.graph_origin;
        let same_origin = url.scheme() == origin.scheme()
            && url.host_str() == origin.host_str()
            && url.port_or_known_default() == origin.port_or_known_default();
        if same_origin {
            Ok(url)
        } else {
            Err("the link does not address the configured Microsoft Graph host".to_owned())
        }
    }

    /// Reads all pages of `feed` for the time range and returns the records.
    pub(crate) async fn list(
        &self,
        feed: Feed,
        lower: DateTime<Utc>,
        upper: Option<DateTime<Utc>>,
    ) -> Result<Vec<Value>> {
        let mut url = self.first_page(feed, lower, upper, self.settings.page_size)?;
        let mut records = Vec::new();
        for _ in 0..MAX_PAGES {
            let page = self.get_page(feed, &url).await?;
            records.extend(page.records);
            match page.next_link {
                Some(next) if next != url => url = next,
                Some(_) => break,
                None => return Ok(records),
            }
        }
        Err(Error::other(
            self.operation(feed),
            ProtocolError::EndlessPaging(MAX_PAGES),
        ))
    }

    /// Reads one page of `feed`.
    ///
    /// The function gets a new token one time after status 401. After status 429 with a
    /// `Retry-After` header, it waits and sends the request again, up to the configured
    /// limits. Above the limits, it returns [`Error::RateLimited`] and sends no request to
    /// Microsoft Graph until the `Retry-After` time is over.
    pub(crate) async fn get_page(&self, feed: Feed, url: &Url) -> Result<Page> {
        let operation = self.operation(feed);
        if let Some(remaining) = self.blocked_for() {
            return Err(Error::RateLimited(format!(
                "{operation}: Microsoft Graph asked for no request during the next {} s",
                remaining.as_secs().max(1)
            )));
        }
        let mut token_renewed = false;
        let mut waits = 0_u32;
        loop {
            let token = self.token().await?;
            let response = self
                .http
                .get(url.clone())
                .bearer_auth(token.expose_secret())
                .header(ACCEPT, "application/json")
                .send()
                .await
                .map_err(|error| transport_error(&operation, error))?;
            let status = response.status();

            if status == StatusCode::OK {
                let body = read_body(response, PAGE_BODY_LIMIT, &operation).await?;
                let page: PageBody = serde_json::from_slice(&body).map_err(|error| {
                    Error::Serialization(format!("{operation}: the response is not valid: {error}"))
                })?;
                let next_link = page
                    .next_link
                    .map(|link| {
                        self.checked_link(&link)
                            .map_err(|problem| Error::Integrity(format!("{operation}: {problem}")))
                    })
                    .transpose()?;
                return Ok(Page {
                    records: page.value,
                    next_link,
                });
            }

            if status == StatusCode::UNAUTHORIZED && !token_renewed {
                // The token service can revoke a token before its expiry. Get a new one.
                self.forget(&token).await;
                token_renewed = true;
                continue;
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                let Some(delay) = retry_after(response.headers(), Utc::now()) else {
                    return Err(Error::RateLimited(format!(
                        "{operation}: Microsoft Graph gave no Retry-After time"
                    )));
                };
                // No request of this connector goes to Microsoft Graph before this time.
                self.block_for(delay);
                if delay > self.settings.max_retry_after
                    || waits >= self.settings.rate_limit_retries
                {
                    return Err(Error::RateLimited(format!(
                        "{operation}: Microsoft Graph asked for a retry after {} s",
                        delay.as_secs()
                    )));
                }
                waits += 1;
                tracing::warn!(
                    connector = %self.settings.name,
                    feed = feed.key(),
                    delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "Microsoft Graph limited the request rate: wait for Retry-After"
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            let code = graph_error_code(response).await;
            return Err(status_error(&operation, status, code.as_deref()));
        }
    }

    /// Gets a token from the token service. Use this to check the credentials.
    pub(crate) async fn authenticate(&self) -> Result<()> {
        self.token().await.map(|_| ())
    }

    fn operation(&self, feed: Feed) -> String {
        format!("entra source {}: read {}", self.settings.name, feed.key())
    }

    /// Returns the cached token, or a new token if the cached token is near its expiry.
    async fn token(&self) -> Result<SecretString> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && Instant::now() < token.refresh_at
        {
            return Ok(token.value.clone());
        }
        // Drop the old token first. A failed request must not leave it in place.
        *cached = None;
        let token = self.request_token().await?;
        let value = token.value.clone();
        *cached = Some(token);
        Ok(value)
    }

    /// Removes `rejected` from the cache, unless a different task already replaced it.
    async fn forget(&self, rejected: &SecretString) {
        let mut cached = self.token.lock().await;
        if cached
            .as_ref()
            .is_some_and(|token| token.value.expose_secret() == rejected.expose_secret())
        {
            *cached = None;
        }
    }

    /// Requests a token with the OAuth 2.0 client credentials grant.
    async fn request_token(&self) -> Result<CachedToken> {
        let operation = format!("entra source {}: get an access token", self.settings.name);
        let form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            percent_encode(&self.settings.client_id),
            percent_encode(self.settings.client_secret.expose_secret()),
            percent_encode(&self.settings.scope),
        );
        let requested_at = Instant::now();
        let response = self
            .http
            .post(self.settings.token_url.clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(form)
            .send()
            .await
            .map_err(|error| transport_error(&operation, error))?;
        let status = response.status();

        if status != StatusCode::OK {
            let body = read_body(response, SMALL_BODY_LIMIT, &operation)
                .await
                .unwrap_or_default();
            let detail: Option<TokenErrorBody> = serde_json::from_slice(&body).ok();
            return Err(token_error(&operation, status, detail.as_ref()));
        }

        let body = read_body(response, SMALL_BODY_LIMIT, &operation).await?;
        let token: TokenBody = serde_json::from_slice(&body).map_err(|_| {
            // The parser error can quote the body, and the body holds the token.
            Error::Serialization(format!("{operation}: the token response is not valid JSON"))
        })?;
        let is_bearer = token
            .token_type
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("bearer"));
        let value = token
            .access_token
            .filter(|value| !value.expose_secret().is_empty() && is_bearer)
            .ok_or_else(|| {
                Error::Serialization(format!(
                    "{operation}: the token response has no bearer access token"
                ))
            })?;
        let lifetime = match token.expires_in {
            Some(Value::Number(seconds)) => seconds.as_u64(),
            Some(Value::String(seconds)) => seconds.trim().parse().ok(),
            _ => None,
        }
        .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs);
        let margin = TOKEN_REFRESH_MARGIN.min(lifetime / 2);
        let refresh_at = requested_at
            .checked_add(lifetime.saturating_sub(margin))
            .unwrap_or(requested_at);
        Ok(CachedToken { value, refresh_at })
    }
}

/// Encodes text for a URL query or a form body. Only unreserved characters stay as they are.
fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Reads the body of a response up to `limit` bytes.
async fn read_body(mut response: Response, limit: usize, operation: &str) -> Result<Vec<u8>> {
    let too_large = || Error::other(operation, ProtocolError::BodyTooLarge(limit));
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_error(operation, error))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Converts an error of the HTTP transport. The message has no URL.
fn transport_error(operation: &str, error: reqwest::Error) -> Error {
    let error = error.without_url();
    if error.is_timeout() {
        Error::Timeout(format!("{operation}: the request did not complete in time"))
    } else if error.is_connect() {
        Error::Unavailable(format!("{operation}: could not connect: {error}"))
    } else {
        Error::Unavailable(format!("{operation}: {error}"))
    }
}

/// Reads the delay of a `Retry-After` header: a number of seconds or an HTTP date.
fn retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = DateTime::parse_from_rfc2822(value).ok()?;
    Some(
        date.with_timezone(&Utc)
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(Duration::ZERO),
    )
}

/// Keeps only the characters of an error code. The text comes from a remote system.
fn safe_code(code: &str) -> String {
    code.chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
        })
        .take(64)
        .collect()
}

/// Reads the `error.code` field of a Microsoft Graph error response.
async fn graph_error_code(response: Response) -> Option<String> {
    let body = read_body(response, SMALL_BODY_LIMIT, "").await.ok()?;
    let body: Value = serde_json::from_slice(&body).ok()?;
    let code = body.get("error")?.get("code")?.as_str().map(safe_code)?;
    (!code.is_empty()).then_some(code)
}

/// Maps a status of a log endpoint to a contract error.
fn status_error(operation: &str, status: StatusCode, code: Option<&str>) -> Error {
    let detail = code.map_or_else(
        || format!("HTTP {}", status.as_u16()),
        |code| format!("HTTP {} {code}", status.as_u16()),
    );
    match status {
        StatusCode::UNAUTHORIZED => Error::Unauthorized(format!(
            "{operation}: Microsoft Graph rejected the access token ({detail})"
        )),
        StatusCode::FORBIDDEN => Error::Unauthorized(format!(
            "{operation}: the application has no permission; grant AuditLog.Read.All ({detail})"
        )),
        StatusCode::BAD_REQUEST => Error::InvalidInput(format!(
            "{operation}: Microsoft Graph rejected the request ({detail})"
        )),
        StatusCode::NOT_FOUND => Error::NotFound(format!(
            "{operation}: the endpoint does not exist; check graph_base ({detail})"
        )),
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => {
            Error::Timeout(format!("{operation}: Microsoft Graph timed out ({detail})"))
        }
        status if status.is_server_error() => Error::Unavailable(format!(
            "{operation}: Microsoft Graph is not available ({detail})"
        )),
        status if status.is_redirection() => Error::Config(format!(
            "{operation}: Microsoft Graph sent a redirect; check graph_base ({detail})"
        )),
        status => Error::other(operation, ProtocolError::UnexpectedStatus(status.as_u16())),
    }
}

/// Maps a status of the token endpoint to a contract error.
fn token_error(operation: &str, status: StatusCode, body: Option<&TokenErrorBody>) -> Error {
    let code = body
        .and_then(|body| body.error.as_deref())
        .map(safe_code)
        .filter(|code| !code.is_empty());
    let mut detail = format!("HTTP {}", status.as_u16());
    if let Some(code) = &code {
        detail.push_str(&format!(" {code}"));
    }
    for number in body
        .map(|body| body.error_codes.as_slice())
        .unwrap_or_default()
    {
        detail.push_str(&format!(" AADSTS{number}"));
    }
    let rejected_credentials = matches!(
        code.as_deref(),
        Some("invalid_client" | "unauthorized_client" | "invalid_grant" | "access_denied")
    );
    match status {
        StatusCode::TOO_MANY_REQUESTS => Error::RateLimited(format!(
            "{operation}: the token service limited the request rate ({detail})"
        )),
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => Error::Timeout(format!(
            "{operation}: the token service timed out ({detail})"
        )),
        status if status.is_server_error() => Error::Unavailable(format!(
            "{operation}: the token service is not available ({detail})"
        )),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::Unauthorized(format!(
            "{operation}: the token service rejected the client credentials ({detail})"
        )),
        StatusCode::BAD_REQUEST if rejected_credentials => Error::Unauthorized(format!(
            "{operation}: the token service rejected the client credentials ({detail})"
        )),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => Error::Config(format!(
            "{operation}: the token service rejected the request; check tenant_id, scope, and login_base ({detail})"
        )),
        status if status.is_redirection() => Error::Config(format!(
            "{operation}: the token service sent a redirect; check login_base ({detail})"
        )),
        status => Error::other(operation, ProtocolError::UnexpectedStatus(status.as_u16())),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use reqwest::header::HeaderValue;

    use super::*;

    fn instant(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, second).unwrap()
    }

    fn client() -> GraphClient {
        let config = crate::EntraConfig::new(
            "entra-test",
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            SecretString::from("example-secret"),
        );
        GraphClient::new(Arc::new(config.validate(|_| None).unwrap())).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_that_microsoft_graph_asked_for_ends_and_has_an_upper_limit() {
        let client = client();
        assert_eq!(client.blocked_for(), None);

        client.block_for(Duration::from_secs(30));
        assert_eq!(client.blocked_for(), Some(Duration::from_secs(30)));
        // A shorter wait does not replace a longer wait.
        client.block_for(Duration::from_secs(5));
        assert_eq!(client.blocked_for(), Some(Duration::from_secs(30)));

        tokio::time::advance(Duration::from_secs(29)).await;
        assert_eq!(client.blocked_for(), Some(Duration::from_secs(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(client.blocked_for(), None);

        client.block_for(Duration::from_secs(u64::MAX));
        assert_eq!(client.blocked_for(), Some(MAX_BLOCK));
        tokio::time::advance(MAX_BLOCK).await;
        assert_eq!(client.blocked_for(), None);

        client.block_for(Duration::ZERO);
        assert_eq!(client.blocked_for(), None);
    }

    #[test]
    fn the_filter_uses_the_time_field_of_the_feed_in_whole_seconds() {
        let lower = instant(5) + chrono::Duration::milliseconds(750);
        assert_eq!(
            Feed::SignIns.filter(lower, None),
            "createdDateTime ge 2026-11-03T09:00:05Z"
        );
        assert_eq!(
            Feed::DirectoryAudits.filter(lower, Some(instant(59))),
            "activityDateTime ge 2026-11-03T09:00:05Z and activityDateTime le 2026-11-03T09:00:59Z"
        );
        assert_eq!(
            Feed::ServicePrincipalSignIns.filter(lower, Some(instant(59))),
            "(createdDateTime ge 2026-11-03T09:00:05Z and createdDateTime le 2026-11-03T09:00:59Z) \
             and signInEventTypes/any(t: t eq 'servicePrincipal')"
        );
    }

    #[test]
    fn percent_encoding_keeps_only_unreserved_characters() {
        assert_eq!(percent_encode("Az09-._~"), "Az09-._~");
        assert_eq!(
            percent_encode("a b&c=d+e/f:'é'"),
            "a%20b%26c%3Dd%2Be%2Ff%3A%27%C3%A9%27"
        );
    }

    #[test]
    fn retry_after_reads_seconds_and_http_dates() {
        let now = instant(0);
        let header = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            headers
        };
        assert_eq!(
            retry_after(&header("17"), now),
            Some(Duration::from_secs(17))
        );
        assert_eq!(retry_after(&header(" 0 "), now), Some(Duration::ZERO));
        assert_eq!(
            retry_after(&header("Tue, 03 Nov 2026 09:00:42 GMT"), now),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            retry_after(&header("Tue, 03 Nov 2026 08:00:00 GMT"), now),
            Some(Duration::ZERO),
            "a date in the past means no delay"
        );
        assert_eq!(retry_after(&header("soon"), now), None);
        assert_eq!(retry_after(&HeaderMap::new(), now), None);
    }

    #[test]
    fn a_remote_error_code_keeps_only_code_characters() {
        assert_eq!(
            safe_code("Authorization_RequestDenied"),
            "Authorization_RequestDenied"
        );
        assert_eq!(safe_code("bad code\n<script>"), "badcodescript");
        assert_eq!(safe_code(&"x".repeat(200)).len(), 64);
    }

    #[test]
    fn each_log_status_maps_to_the_matching_contract_error() {
        let error =
            |status: u16| status_error("read", StatusCode::from_u16(status).unwrap(), Some("Code"));
        assert!(
            matches!(error(401), Error::Unauthorized(message) if message.contains("HTTP 401 Code"))
        );
        assert!(
            matches!(error(403), Error::Unauthorized(message) if message.contains("AuditLog.Read.All"))
        );
        assert!(matches!(error(400), Error::InvalidInput(_)));
        assert!(matches!(error(404), Error::NotFound(_)));
        assert!(matches!(error(408), Error::Timeout(_)));
        assert!(matches!(error(504), Error::Timeout(_)));
        assert!(matches!(error(500), Error::Unavailable(_)));
        assert!(matches!(error(503), Error::Unavailable(_)));
        assert!(matches!(error(302), Error::Config(_)));
        assert!(matches!(error(418), Error::Other { .. }));
        assert!(error(503).is_retryable());
        assert!(!error(401).is_retryable());
    }

    #[test]
    fn each_token_status_maps_to_the_matching_contract_error() {
        let body = |code: &str| TokenErrorBody {
            error: Some(code.to_owned()),
            error_codes: vec![7_000_215],
        };
        let error = |status: u16, code: &str| {
            token_error(
                "token",
                StatusCode::from_u16(status).unwrap(),
                Some(&body(code)),
            )
        };
        assert!(matches!(
            error(401, "invalid_client"),
            Error::Unauthorized(message) if message.contains("HTTP 401 invalid_client AADSTS7000215")
        ));
        assert!(matches!(
            error(400, "invalid_client"),
            Error::Unauthorized(_)
        ));
        assert!(matches!(
            error(400, "unauthorized_client"),
            Error::Unauthorized(_)
        ));
        assert!(matches!(error(400, "invalid_request"), Error::Config(_)));
        assert!(matches!(error(400, "invalid_scope"), Error::Config(_)));
        assert!(matches!(error(404, ""), Error::Config(_)));
        assert!(matches!(error(429, ""), Error::RateLimited(_)));
        assert!(matches!(error(500, ""), Error::Unavailable(_)));
        assert!(matches!(
            error(503, "temporarily_unavailable"),
            Error::Unavailable(_)
        ));
        assert!(matches!(error(302, ""), Error::Config(_)));
        assert!(matches!(
            token_error("token", StatusCode::BAD_REQUEST, None),
            Error::Config(message) if message.ends_with("(HTTP 400)")
        ));
    }
}
