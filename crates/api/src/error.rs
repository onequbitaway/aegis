//! The error responses of the API.
//!
//! Each error is a JSON document: `{ "error": { "code": "...", "message": "..." } }`.
//!
//! A response for a server fault has a fixed message. The cause goes to the log only, so
//! that a response never shows internal data.

use aegis_contracts::Error;
use axum::Json;
use axum::http::StatusCode;
use axum::http::header::{HeaderValue, WWW_AUTHENTICATE};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::text::one_line;

/// The maximum length of an error message from a different subsystem, in characters.
const MAX_MESSAGE_CHARACTERS: usize = 300;

/// The result type of the route handlers.
pub(crate) type ApiResult<T> = std::result::Result<T, ApiError>;

/// An error that a route returns to the caller.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// The request has no valid credential.
    Unauthenticated,
    /// The signature of a ChatOps request is not valid.
    BadSignature,
    /// The principal does not have the permission. The text is the message.
    Forbidden(String),
    /// The request is not valid. The text is the message.
    BadRequest(String),
    /// The resource does not exist. The text is the message.
    NotFound(String),
    /// The operation is not possible in the present state. The text is the message.
    Conflict(String),
    /// The method is not valid for the path.
    MethodNotAllowed,
    /// The request body is too large.
    PayloadTooLarge,
    /// The request body does not have the necessary content type.
    UnsupportedMediaType(&'static str),
    /// The request took more time than the limit.
    Timeout,
    /// Too many live feeds are open.
    TooManyStreams,
    /// A different subsystem returned an error.
    Contract(Error),
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Contract(error)
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

/// The status, the code, and the message of an error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ErrorView {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ErrorView {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

/// Returns the text of a different subsystem in a form that is safe to show.
fn shown(text: &str) -> String {
    one_line(text, MAX_MESSAGE_CHARACTERS)
}

/// Maps an error of a different subsystem to a response.
///
/// The message of a caller fault comes from the subsystem. The message of a server fault is
/// fixed.
pub(crate) fn contract_view(error: &Error) -> ErrorView {
    match error {
        Error::InvalidInput(text) => {
            ErrorView::new(StatusCode::BAD_REQUEST, "invalid_input", shown(text))
        }
        Error::NotFound(text) => ErrorView::new(StatusCode::NOT_FOUND, "not_found", shown(text)),
        Error::Unauthorized(text) => {
            ErrorView::new(StatusCode::FORBIDDEN, "forbidden", shown(text))
        }
        Error::Denied(text) => ErrorView::new(StatusCode::FORBIDDEN, "denied", shown(text)),
        Error::Unsupported(text) => {
            ErrorView::new(StatusCode::NOT_IMPLEMENTED, "unsupported", shown(text))
        }
        Error::BudgetExceeded(text) => ErrorView::new(
            StatusCode::TOO_MANY_REQUESTS,
            "budget_exceeded",
            shown(text),
        ),
        Error::RateLimited(_) => ErrorView::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "A service limited the request rate. Try again later.",
        ),
        Error::Unavailable(_) => ErrorView::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "A service is not available. Try again later.",
        ),
        Error::Timeout(_) => ErrorView::new(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout",
            "A service did not answer in time. Try again later.",
        ),
        Error::Refused(_) => ErrorView::new(
            StatusCode::BAD_GATEWAY,
            "model_refused",
            "The model refused the task.",
        ),
        Error::Config(_) => ErrorView::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "configuration",
            "The server configuration is not valid. Refer to the server log.",
        ),
        Error::Integrity(_) => ErrorView::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "integrity",
            "Stored data failed an integrity check. Refer to the server log.",
        ),
        Error::Serialization(_) | Error::Other { .. } => ErrorView::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "The server could not complete the request. Refer to the server log.",
        ),
    }
}

impl ApiError {
    /// Returns the status, the code, and the message of the response.
    pub(crate) fn view(&self) -> ErrorView {
        match self {
            Self::Unauthenticated => ErrorView::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "The request has no valid bearer token.",
            ),
            Self::BadSignature => ErrorView::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "The request signature is not valid.",
            ),
            Self::Forbidden(message) => {
                ErrorView::new(StatusCode::FORBIDDEN, "forbidden", message.as_str())
            }
            Self::BadRequest(message) => {
                ErrorView::new(StatusCode::BAD_REQUEST, "invalid_input", message.as_str())
            }
            Self::NotFound(message) => {
                ErrorView::new(StatusCode::NOT_FOUND, "not_found", message.as_str())
            }
            Self::Conflict(message) => {
                ErrorView::new(StatusCode::CONFLICT, "conflict", message.as_str())
            }
            Self::MethodNotAllowed => ErrorView::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "The method is not valid for this path.",
            ),
            Self::PayloadTooLarge => ErrorView::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "The request body is too large.",
            ),
            Self::UnsupportedMediaType(expected) => ErrorView::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                format!("The request body must have the content type {expected}."),
            ),
            Self::Timeout => ErrorView::new(
                StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "The request took more time than the limit.",
            ),
            Self::TooManyStreams => ErrorView::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many live feeds are open. Close one and try again.",
            ),
            Self::Contract(error) => contract_view(error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let view = self.view();
        if view.status.is_server_error() {
            if let Self::Contract(error) = &self {
                tracing::error!(code = view.code, %error, "a request failed");
            } else {
                tracing::error!(code = view.code, "a request failed");
            }
        }
        let body = Json(ErrorBody {
            error: ErrorDetail {
                code: view.code,
                message: &view.message,
            },
        });
        let mut response = (view.status, body).into_response();
        if matches!(self, Self::Unauthenticated) {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_contract_error_has_its_status_and_code() {
        let source = || Error::other("read the store", std::io::Error::other("disk /dev/sda1"));
        let cases = [
            (Error::InvalidInput("x".into()), 400, "invalid_input"),
            (Error::NotFound("x".into()), 404, "not_found"),
            (Error::Unauthorized("x".into()), 403, "forbidden"),
            (Error::Denied("x".into()), 403, "denied"),
            (Error::Unsupported("x".into()), 501, "unsupported"),
            (Error::BudgetExceeded("x".into()), 429, "budget_exceeded"),
            (Error::RateLimited("x".into()), 429, "rate_limited"),
            (Error::Unavailable("x".into()), 503, "unavailable"),
            (Error::Timeout("x".into()), 504, "timeout"),
            (Error::Refused("x".into()), 502, "model_refused"),
            (Error::Config("x".into()), 500, "configuration"),
            (Error::Integrity("x".into()), 500, "integrity"),
            (Error::Serialization("x".into()), 500, "internal"),
            (source(), 500, "internal"),
        ];
        assert_eq!(cases.len(), 14);
        for (error, status, code) in cases {
            let view = contract_view(&error);
            assert_eq!(view.status.as_u16(), status, "{error}");
            assert_eq!(view.code, code, "{error}");
        }
    }

    #[test]
    fn a_server_fault_does_not_show_its_cause() {
        let secret = "postgres://aegis:hunter2@db.internal/aegis";
        let faults = [
            Error::Unavailable(secret.to_owned()),
            Error::Timeout(secret.to_owned()),
            Error::RateLimited(secret.to_owned()),
            Error::Refused(secret.to_owned()),
            Error::Config(secret.to_owned()),
            Error::Integrity(secret.to_owned()),
            Error::Serialization(secret.to_owned()),
            Error::other(secret, std::io::Error::other(secret)),
        ];
        assert_eq!(faults.len(), 8);
        for fault in faults {
            let view = contract_view(&fault);
            assert!(!view.message.contains("hunter2"), "{}", view.message);
            assert!(!view.message.contains("db.internal"), "{}", view.message);
        }
    }

    #[test]
    fn a_caller_fault_shows_one_line_of_bounded_text() {
        let view = contract_view(&Error::InvalidInput(format!(
            "first line\nsecond\u{7} line {}",
            "x".repeat(400)
        )));
        assert!(view.message.starts_with("first line second line xxx"));
        assert_eq!(view.message.chars().count(), MAX_MESSAGE_CHARACTERS);
        assert!(view.message.ends_with('…'));
    }

    #[test]
    fn a_missing_credential_asks_for_a_bearer_token() {
        let response = ApiError::Unauthenticated.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer")
        );
    }
}
