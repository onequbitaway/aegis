//! Request parsing with JSON error responses.
//!
//! The extractors of `axum` answer a bad request with plain text. The functions in this
//! module return an [`ApiError`], so each error has the JSON form of the API.

use std::str::FromStr;

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::de::DeserializeOwned;
use url::form_urlencoded;

use crate::config::LimitsConfig;
use crate::error::{ApiError, ApiResult};
use crate::text::one_line;

/// The maximum length of a parse error in a response, in characters.
const MAX_PARSE_ERROR_CHARACTERS: usize = 200;

/// Returns `true` if the content type of the request is `expected`. Parameters, for
/// example `charset`, are ignored.
pub(crate) fn has_content_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(expected))
}

/// Reads the full request body. The body limit of the server applies.
pub(crate) async fn read_body(request: Request) -> ApiResult<Bytes> {
    Bytes::from_request(request, &())
        .await
        .map_err(|rejection| {
            if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::PayloadTooLarge
            } else {
                ApiError::BadRequest("The server could not read the request body.".to_owned())
            }
        })
}

/// A request body that is one JSON document of the type `T`.
pub(crate) struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> ApiResult<Self> {
        if !has_content_type(request.headers(), "application/json") {
            return Err(ApiError::UnsupportedMediaType("application/json"));
        }
        let body = read_body(request).await?;
        let invalid = |error: serde_json::Error| {
            ApiError::BadRequest(format!(
                "The request body is not valid: {}.",
                one_line(&error.to_string(), MAX_PARSE_ERROR_CHARACTERS)
            ))
        };
        let document: serde_json::Value = serde_json::from_slice(&body).map_err(invalid)?;
        // The parser would also read an array as the fields of a structure, in order.
        if !document.is_object() {
            return Err(ApiError::BadRequest(
                "The request body must be a JSON object.".to_owned(),
            ));
        }
        serde_json::from_value(document).map(Self).map_err(invalid)
    }
}

/// Parses an identifier from a path segment.
///
/// `name` is the name of the thing in the error message, for example `incident`.
pub(crate) fn path_id<T: FromStr>(text: &str, name: &str) -> ApiResult<T> {
    text.parse()
        .map_err(|_| ApiError::BadRequest(format!("The {name} identifier is not a valid UUID.")))
}

/// The parameters of a query string.
///
/// Each route names the parameters that it knows. A parameter that the route does not
/// know, and a parameter that occurs two times, are errors. A parameter with no text is
/// the same as no parameter.
pub(crate) struct Params {
    pairs: Vec<(String, String)>,
}

impl Params {
    /// Parses the query string of a request. `known` lists the parameters of the route.
    pub(crate) fn parse(query: Option<&str>, known: &[&str]) -> ApiResult<Self> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (name, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            if !known.contains(&name.as_ref()) {
                return Err(ApiError::BadRequest(format!(
                    "The query has a parameter that this route does not know. The known \
                     parameters are: {}.",
                    if known.is_empty() {
                        "none".to_owned()
                    } else {
                        known.join(", ")
                    }
                )));
            }
            if pairs.iter().any(|(existing, _)| *existing == name) {
                return Err(ApiError::BadRequest(format!(
                    "The query parameter {name} occurs more than one time."
                )));
            }
            pairs.push((name.into_owned(), value.into_owned()));
        }
        Ok(Self { pairs })
    }

    /// Returns the text of a parameter. An empty parameter gives `None`.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(existing, _)| existing == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
    }

    /// Returns a parameter that is one of the names of an enumeration, for example
    /// `status=open`. `expected` lists the names for the error message.
    pub(crate) fn variant<T: DeserializeOwned>(
        &self,
        name: &str,
        expected: &str,
    ) -> ApiResult<Option<T>> {
        let Some(text) = self.text(name) else {
            return Ok(None);
        };
        serde_json::from_value(serde_json::Value::String(text.to_owned()))
            .map(Some)
            .map_err(|_| {
                ApiError::BadRequest(format!(
                    "The query parameter {name} must be one of: {expected}."
                ))
            })
    }

    /// Returns a parameter that is a whole number.
    pub(crate) fn number(&self, name: &str) -> ApiResult<Option<u64>> {
        let Some(text) = self.text(name) else {
            return Ok(None);
        };
        // `u64::from_str` accepts a leading `+`. A query must have digits only.
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(not_a_number(name));
        }
        text.parse().map(Some).map_err(|_| not_a_number(name))
    }

    /// Returns the `limit` parameter, or the default page size.
    pub(crate) fn limit(&self, limits: &LimitsConfig) -> ApiResult<usize> {
        let largest = limits.max_page_size;
        match self.number("limit")? {
            None => Ok(limits.default_page_size),
            Some(limit) => usize::try_from(limit)
                .ok()
                .filter(|limit| (1..=largest).contains(limit))
                .ok_or_else(|| {
                    ApiError::BadRequest(format!(
                        "The query parameter limit must be from 1 to {largest}."
                    ))
                }),
        }
    }
}

fn not_a_number(name: &str) -> ApiError {
    ApiError::BadRequest(format!(
        "The query parameter {name} must be a whole number that is not negative."
    ))
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::IncidentId;
    use aegis_contracts::incident::IncidentStatus;

    use super::*;

    fn bad_request<T>(result: ApiResult<T>) -> String {
        match result {
            Err(ApiError::BadRequest(message)) => message,
            Err(other) => panic!("expected a bad request, found {other:?}"),
            Ok(_) => panic!("expected a bad request"),
        }
    }

    #[test]
    fn a_query_gives_its_parameters() {
        let params = Params::parse(
            Some("status=false_positive&limit=20&note="),
            &["status", "limit", "note"],
        )
        .unwrap();
        assert_eq!(
            params.variant::<IncidentStatus>("status", "open").unwrap(),
            Some(IncidentStatus::FalsePositive)
        );
        assert_eq!(params.limit(&LimitsConfig::default()).unwrap(), 20);
        assert_eq!(params.text("note"), None);
        assert_eq!(params.text("absent"), None);
    }

    #[test]
    fn no_query_gives_the_default_page_size() {
        let params = Params::parse(None, &["limit"]).unwrap();
        assert_eq!(params.limit(&LimitsConfig::default()).unwrap(), 50);
    }

    #[test]
    fn an_unknown_or_repeated_parameter_is_an_error() {
        assert_eq!(
            bad_request(Params::parse(Some("offset=3"), &["status", "limit"])),
            "The query has a parameter that this route does not know. The known parameters \
             are: status, limit."
        );
        assert_eq!(
            bad_request(Params::parse(Some("x=1"), &[])),
            "The query has a parameter that this route does not know. The known parameters \
             are: none."
        );
        assert_eq!(
            bad_request(Params::parse(Some("limit=1&limit=2"), &["limit"])),
            "The query parameter limit occurs more than one time."
        );
    }

    #[test]
    fn a_limit_out_of_range_is_an_error() {
        let limits = LimitsConfig::default();
        for query in ["limit=0", "limit=201", "limit=1000000"] {
            let params = Params::parse(Some(query), &["limit"]).unwrap();
            assert_eq!(
                bad_request(params.limit(&limits)),
                "The query parameter limit must be from 1 to 200.",
                "{query}"
            );
        }
        for query in [
            "limit=-1",
            "limit=%2B5",
            "limit=ten",
            "limit=1.5",
            "limit=99999999999999999999",
        ] {
            let params = Params::parse(Some(query), &["limit"]).unwrap();
            assert_eq!(
                bad_request(params.limit(&limits)),
                "The query parameter limit must be a whole number that is not negative.",
                "{query}"
            );
        }
    }

    #[test]
    fn an_unknown_variant_is_an_error_that_lists_the_names() {
        let params = Params::parse(Some("status=closed"), &["status"]).unwrap();
        assert_eq!(
            bad_request(params.variant::<IncidentStatus>("status", "open, resolved")),
            "The query parameter status must be one of: open, resolved."
        );
    }

    #[test]
    fn a_path_identifier_must_be_a_uuid() {
        let id = IncidentId::new();
        assert_eq!(
            path_id::<IncidentId>(&id.to_string(), "incident").unwrap(),
            id
        );
        assert_eq!(
            bad_request(path_id::<IncidentId>("42", "incident")),
            "The incident identifier is not a valid UUID."
        );
    }

    #[test]
    fn the_content_type_check_ignores_parameters_and_case() {
        let with = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, value.parse().unwrap());
            headers
        };
        assert!(has_content_type(
            &with("application/json"),
            "application/json"
        ));
        assert!(has_content_type(
            &with("Application/JSON; charset=utf-8"),
            "application/json"
        ));
        assert!(!has_content_type(&with("text/plain"), "application/json"));
        assert!(!has_content_type(&HeaderMap::new(), "application/json"));
    }
}
