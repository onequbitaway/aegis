//! The security headers and the request time limit.

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderName, HeaderValue, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::routes::Ctx;

/// The Content-Security-Policy of each response that is not a console page. Such a
/// response is data, so a browser must load nothing for it.
pub const API_CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// The Content-Security-Policy of the web console.
///
/// The console loads scripts, styles, and images only from its own origin. It has no
/// inline script and no inline style. It connects only to its own origin.
pub const CONSOLE_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const PERMISSIONS_POLICY: &str =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()";

/// Puts the security headers on a response. A header that the handler set stays.
pub(crate) fn apply_security_headers(headers: &mut HeaderMap) {
    let defaults = [
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "no-referrer"),
        (CONTENT_SECURITY_POLICY, API_CONTENT_SECURITY_POLICY),
        (CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ),
    ];
    for (name, value) in defaults {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
}

/// Adds the security headers to each response, also to an error response.
pub(crate) async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_security_headers(response.headers_mut());
    response
}

/// Stops a request that takes more time than the limit.
///
/// The limit ends when the handler returns the response. It does not apply to the body of
/// a live feed.
pub(crate) async fn time_limit(State(ctx): State<Ctx>, request: Request, next: Next) -> Response {
    match tokio::time::timeout(ctx.limits.request_timeout(), next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::Timeout.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_that_the_handler_set_stays() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONSOLE_CONTENT_SECURITY_POLICY),
        );
        apply_security_headers(&mut headers);
        assert_eq!(
            headers.get(CONTENT_SECURITY_POLICY).unwrap(),
            CONSOLE_CONTENT_SECURITY_POLICY
        );
        assert_eq!(headers.get(X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(headers.get(X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(headers.get(REFERRER_POLICY).unwrap(), "no-referrer");
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
    }

    /// Returns the sources of one directive of a policy.
    fn directive<'a>(policy: &'a str, name: &str) -> Vec<&'a str> {
        policy
            .split(';')
            .map(str::trim)
            .find_map(|directive| directive.strip_prefix(name))
            .map(|sources| sources.split_whitespace().collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_console_policy_permits_only_its_own_origin() {
        let policy = CONSOLE_CONTENT_SECURITY_POLICY;
        for name in [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
        ] {
            assert_eq!(directive(policy, name), ["'self'"], "{name}");
        }
        for name in ["object-src", "base-uri", "form-action", "frame-ancestors"] {
            assert_eq!(directive(policy, name), ["'none'"], "{name}");
        }
        assert!(!policy.contains("unsafe"));
    }

    #[test]
    fn the_api_policy_loads_nothing() {
        assert_eq!(
            directive(API_CONTENT_SECURITY_POLICY, "default-src"),
            ["'none'"]
        );
    }
}
