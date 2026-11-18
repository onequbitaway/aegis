//! The live feed: bus messages as server-sent events.
//!
//! Each event has a type that comes from the bus subject. The data of an event is one JSON
//! document: `{ "subject": "...", "payload": ... }`. The payload is the bus payload. It
//! is untrusted data: a client must not interpret it as markup.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use aegis_contracts::bus::{BusMessage, subject};
use aegis_policy::Permission;
use axum::extract::{RawQuery, State};
use axum::http::header::{CACHE_CONTROL, HeaderName, HeaderValue};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::stream::{self, BoxStream, Stream, StreamExt};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;

use super::{Caller, Ctx};
use crate::error::{ApiError, ApiResult, contract_view};
use crate::extract::Params;
use crate::ops::READ_APPROVALS;

/// The maximum number of bus errors in sequence before the feed ends.
const MAX_ERRORS_IN_SEQUENCE: u32 = 8;

/// One bus subscription of the live feed.
struct Feed {
    /// The type of the server-sent events.
    event: &'static str,
    /// The subscription pattern.
    pattern: &'static str,
    /// The permissions that let a principal get these events. One is sufficient.
    any_of: &'static [Permission],
}

const DETECTIONS_PATTERN: &str = "aegis.detections.>";

const FEEDS: [Feed; 5] = [
    Feed {
        event: "detection",
        pattern: DETECTIONS_PATTERN,
        any_of: &[Permission::ViewIncidents],
    },
    Feed {
        event: "incident",
        pattern: subject::INCIDENTS,
        any_of: &[Permission::ViewIncidents],
    },
    Feed {
        event: "action_result",
        pattern: subject::ACTION_RESULTS,
        any_of: &[Permission::ViewIncidents],
    },
    Feed {
        event: "approval",
        pattern: subject::APPROVALS,
        any_of: READ_APPROVALS,
    },
    Feed {
        event: "audit",
        pattern: subject::AUDIT,
        any_of: &[Permission::ViewAudit],
    },
];

#[derive(Serialize)]
struct Ready {
    feeds: Vec<&'static str>,
}

#[derive(Serialize)]
struct FeedMessage<'a> {
    subject: &'a str,
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct FeedError<'a> {
    code: &'a str,
    message: &'a str,
}

fn json_event<T: Serialize>(event: &'static str, data: &T) -> Option<Event> {
    match Event::default().event(event).json_data(data) {
        Ok(event) => Some(event),
        Err(error) => {
            tracing::warn!(event, %error, "a live feed event could not be encoded");
            None
        }
    }
}

/// Makes the server-sent event for one bus message. A payload that is not JSON gives no
/// event.
fn message_event(event: &'static str, message: &BusMessage) -> Option<Event> {
    let payload = match serde_json::from_slice(&message.payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(
                subject = %message.subject,
                %error,
                "a bus message for the live feed is not JSON"
            );
            return None;
        }
    };
    json_event(
        event,
        &FeedMessage {
            subject: &message.subject,
            payload,
        },
    )
}

/// A stream that holds one live feed permit until the client closes the feed.
struct Permitted {
    events: BoxStream<'static, Event>,
    _permit: OwnedSemaphorePermit,
}

impl Stream for Permitted {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events
            .as_mut()
            .poll_next(context)
            .map(|item| item.map(Ok))
    }
}

/// `GET /stream`: the live feed.
///
/// The server subscribes to the bus before it answers. A message that the bus gets after
/// the response starts is thus in the feed. The first event has the type `ready`.
pub(crate) async fn stream(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    RawQuery(query): RawQuery,
) -> ApiResult<Response> {
    Params::parse(query.as_deref(), &[])?;
    let permit = ctx
        .streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::TooManyStreams)?;

    let parts = ctx.state.parts();
    let mut names = Vec::new();
    let mut subscriptions = Vec::new();
    for feed in &FEEDS {
        if !feed
            .any_of
            .iter()
            .any(|permission| parts.rbac.allows(&principal, *permission))
        {
            continue;
        }
        let messages = parts.bus.subscribe(feed.pattern, None).await?;
        let event = feed.event;
        names.push(event);
        subscriptions.push(messages.map(move |item| (event, item)));
    }

    let ready = json_event("ready", &Ready { feeds: names });
    let shutdown = ctx.shutdown.clone();
    let mut errors_in_sequence: u32 = 0;
    let messages = stream::select_all(subscriptions)
        .take_until(async move { shutdown.wait().await })
        .map(move |(event, item)| match item {
            Ok(message) => {
                errors_in_sequence = 0;
                (false, message_event(event, &message))
            }
            Err(error) => {
                errors_in_sequence += 1;
                tracing::warn!(event, %error, "a bus subscription of the live feed failed");
                let view = contract_view(&error);
                let event = json_event(
                    "error",
                    &FeedError {
                        code: view.code,
                        message: &view.message,
                    },
                );
                (errors_in_sequence >= MAX_ERRORS_IN_SEQUENCE, event)
            }
        })
        // The event that reaches the error limit is the last event of the feed.
        .scan(false, |ended, (last, event)| {
            let item = if *ended { None } else { Some(event) };
            *ended = *ended || last;
            std::future::ready(item)
        })
        .filter_map(std::future::ready);
    let events = Permitted {
        events: stream::iter(ready).chain(messages).boxed(),
        _permit: permit,
    };

    let keep_alive = KeepAlive::new()
        .interval(Duration::from_secs(ctx.limits.stream_keep_alive_seconds))
        .text("keep-alive");
    let mut response = Sse::new(events).keep_alive(keep_alive).into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // A proxy must not hold back the events.
    headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_detection_pattern_matches_each_tier() {
        use aegis_contracts::bus::subject_matches;
        assert!(DETECTIONS_PATTERN.starts_with(subject::DETECTIONS));
        assert!(subject_matches(
            DETECTIONS_PATTERN,
            "aegis.detections.deterministic"
        ));
        assert!(subject_matches(DETECTIONS_PATTERN, "aegis.detections.llm"));
        assert!(!subject_matches(DETECTIONS_PATTERN, "aegis.detections"));
    }

    #[test]
    fn a_payload_that_is_not_json_gives_no_event() {
        let message = BusMessage {
            subject: subject::INCIDENTS.to_owned(),
            payload: b"not json".to_vec(),
        };
        assert!(message_event("incident", &message).is_none());
        let message = BusMessage {
            subject: subject::INCIDENTS.to_owned(),
            payload: br#"{"a":1}"#.to_vec(),
        };
        assert!(message_event("incident", &message).is_some());
    }
}
