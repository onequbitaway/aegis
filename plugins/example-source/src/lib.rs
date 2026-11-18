//! An example AEGIS source connector plugin.
//!
//! The plugin emits five fixed sign-in events. It shows the three things that each source
//! plugin does: it reads its configuration, it builds normalized events as JSON, and it
//! pages with a cursor.
//!
//! The cursor is the number of events that the caller already has. The plugin keeps no
//! state between calls, because the host makes a new instance for each call.
//!
//! Configuration keys:
//!
//! | Key | Meaning | Default |
//! | --- | --- | --- |
//! | `page_size` | The largest number of events in one batch, from 1 to 100. | `2` |

/// The Rust form of the `source-connector` world in the `wit` directory.
mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "source-connector",
    });
}

use bindings::aegis::plugin::host::{self, LogLevel};
use bindings::aegis::plugin::types::Error;
use bindings::exports::aegis::plugin::source::Guest;
use chrono::{DateTime, FixedOffset};
use serde_json::{Value, json};

/// The name that the plugin reports. The host replaces it with the manifest name.
const NAME: &str = "example-source";
const DEFAULT_PAGE_SIZE: usize = 2;
const MAX_PAGE_SIZE: usize = 100;

/// One fixed record of the simulated source system.
struct Record {
    id: &'static str,
    time: &'static str,
    user: &'static str,
    ip: &'static str,
    success: bool,
}

/// The records of the simulated source system, in time order.
const RECORDS: [Record; 5] = [
    Record {
        id: "018f0000-0000-7000-8000-000000000001",
        time: "2026-01-02T03:00:00Z",
        user: "alice@example.com",
        ip: "198.51.100.10",
        success: true,
    },
    Record {
        id: "018f0000-0000-7000-8000-000000000002",
        time: "2026-01-02T03:01:00Z",
        user: "bob@example.com",
        ip: "203.0.113.7",
        success: false,
    },
    Record {
        id: "018f0000-0000-7000-8000-000000000003",
        time: "2026-01-02T03:02:00Z",
        user: "bob@example.com",
        ip: "203.0.113.7",
        success: false,
    },
    Record {
        id: "018f0000-0000-7000-8000-000000000004",
        time: "2026-01-02T03:03:00Z",
        user: "bob@example.com",
        ip: "203.0.113.7",
        success: true,
    },
    Record {
        id: "018f0000-0000-7000-8000-000000000005",
        time: "2026-01-02T03:04:00Z",
        user: "carol@example.com",
        ip: "198.51.100.11",
        success: true,
    },
];

struct ExampleSource;

impl Guest for ExampleSource {
    fn info() -> String {
        json!({
            "name": NAME,
            "vendor": "aegis",
            "product": "example",
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string()
    }

    fn check() -> Result<(), Error> {
        page_size().map(|_| ())
    }

    fn poll(cursor: Option<String>) -> Result<String, Error> {
        let batch = page(RECORDS.iter(), cursor.as_deref(), true)?;
        host::log(LogLevel::Debug, "The example source answered one poll.");
        Ok(batch)
    }

    fn fetch(start: String, end: String, cursor: Option<String>) -> Result<String, Error> {
        let start = parse_time(&start)?;
        let end = parse_time(&end)?;
        let mut in_range = Vec::new();
        for record in &RECORDS {
            let time = parse_time(record.time)?;
            if start <= time && time < end {
                in_range.push(record);
            }
        }
        page(in_range.into_iter(), cursor.as_deref(), false)
    }
}

/// Returns one page of `records` after `cursor`, as the JSON form of `EventBatch`.
///
/// A live read always gives the cursor for the next call. A read of past events gives no
/// cursor after the last page.
fn page<'a>(
    records: impl ExactSizeIterator<Item = &'a Record>,
    cursor: Option<&str>,
    live: bool,
) -> Result<String, Error> {
    let total = records.len();
    let offset = offset(cursor)?.min(total);
    let events: Vec<Value> = records.skip(offset).take(page_size()?).map(event).collect();
    let next = offset + events.len();
    let mut batch = json!({ "events": events });
    if live || next < total {
        batch["next_cursor"] = Value::String(next.to_string());
    }
    Ok(batch.to_string())
}

/// Builds the JSON form of a normalized `Event`.
fn event(record: &Record) -> Value {
    let mut event = json!({
        "id": record.id,
        "time": record.time,
        "source": { "connector": NAME, "vendor": "aegis", "product": "example" },
        "class": "authentication",
        "action": "sign_in",
        "outcome": if record.success { "success" } else { "failure" },
        "severity": "informational",
        "actor": { "kind": "user", "id": record.user, "name": record.user, "ip": record.ip },
        "attributes": { "auth_protocol": "password" },
    });
    if !record.success {
        event["attributes"]["failure_reason"] =
            Value::String("The password is not correct.".to_owned());
    }
    event
}

fn offset(cursor: Option<&str>) -> Result<usize, Error> {
    cursor.map_or(Ok(0), |text| {
        text.parse()
            .map_err(|_| Error::InvalidInput(format!("The cursor {text:?} is not a number.")))
    })
}

fn page_size() -> Result<usize, Error> {
    let Some(text) = host::config_get("page_size") else {
        return Ok(DEFAULT_PAGE_SIZE);
    };
    match text.parse() {
        Ok(size) if (1..=MAX_PAGE_SIZE).contains(&size) => Ok(size),
        _ => Err(Error::InvalidInput(format!(
            "The configuration value page_size must be a number from 1 to {MAX_PAGE_SIZE}."
        ))),
    }
}

fn parse_time(text: &str) -> Result<DateTime<FixedOffset>, Error> {
    DateTime::parse_from_rfc3339(text)
        .map_err(|_| Error::InvalidInput(format!("The time {text:?} is not an RFC 3339 time.")))
}

bindings::export!(ExampleSource with_types_in bindings);
