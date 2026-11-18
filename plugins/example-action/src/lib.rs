//! An example AEGIS action connector plugin.
//!
//! The plugin supports one action type, `notify`. It sends a JSON message to a webhook.
//! The plugin has no network access of its own. It asks the host to send the request. The
//! host permits only the destinations in `allowed_hosts` of the plugin manifest.
//!
//! The plugin obeys `dry_run`: it then reports what it would do and sends nothing.
//!
//! Configuration keys:
//!
//! | Key | Meaning | Default |
//! | --- | --- | --- |
//! | `webhook_url` | The URL that receives the notification. | None. The key is necessary. |

/// The Rust form of the `action-connector` world in the `wit` directory.
mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "action-connector",
    });
}

use std::time::SystemTime;

use bindings::aegis::plugin::host::{self, Request};
use bindings::aegis::plugin::types::Error;
use bindings::exports::aegis::plugin::action::Guest;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

/// The name that the plugin reports. The host replaces it with the manifest name.
const NAME: &str = "example-action";

struct ExampleAction;

impl Guest for ExampleAction {
    fn info() -> String {
        json!({
            "name": NAME,
            "vendor": "aegis",
            "product": "webhook",
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string()
    }

    fn supported_actions() -> String {
        json!(["notify"]).to_string()
    }

    fn execute(request_json: String) -> Result<String, Error> {
        let request: Value = serde_json::from_str(&request_json)
            .map_err(|_| Error::InvalidInput("The action request is not valid JSON.".to_owned()))?;
        if request["kind"] != "notify" {
            return Err(Error::Unsupported(
                "This plugin supports only the notify action.".to_owned(),
            ));
        }
        let action_id = text_field(&request, "id")?;
        let target = request["target"]["id"].as_str().ok_or_else(|| {
            Error::InvalidInput("The action request has no target identifier.".to_owned())
        })?;
        let url = host::config_get("webhook_url").ok_or_else(|| {
            Error::InvalidInput("The configuration value webhook_url is missing.".to_owned())
        })?;

        if request["dry_run"].as_bool().unwrap_or(false) {
            return Ok(outcome(
                action_id,
                "simulated",
                format!("Would send a notification about {target} to the webhook."),
                Value::Null,
            ));
        }

        let text = request["parameters"]["message"]
            .as_str()
            .map_or_else(|| text_field(&request, "reason"), Ok)?;
        let body = json!({
            "text": text,
            "action_id": action_id,
            "target": request["target"],
            "incident_id": request["incident_id"],
            "requested_by": request["requested_by"],
        });
        let response = host::http_request(&Request {
            method: "POST".to_owned(),
            url,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: Some(body.to_string().into_bytes()),
        })?;

        let status = response.status;
        match status {
            200..=299 => Ok(outcome(
                action_id,
                "succeeded",
                format!("Sent a notification about {target} to the webhook."),
                json!({ "http_status": status }),
            )),
            401 | 403 => Err(Error::Unauthorized(format!(
                "The webhook refused the request with HTTP {status}."
            ))),
            404 => Err(Error::NotFound(
                "The webhook does not exist (HTTP 404).".to_owned(),
            )),
            429 => Err(Error::RateLimited(
                "The webhook limited the request rate (HTTP 429).".to_owned(),
            )),
            500..=599 => Err(Error::Unavailable(format!(
                "The webhook is not available (HTTP {status})."
            ))),
            _ => Err(Error::Other(format!("The webhook returned HTTP {status}."))),
        }
    }

    fn revert(_request_json: String) -> Result<String, Error> {
        Err(Error::Unsupported(
            "A notification cannot be undone.".to_owned(),
        ))
    }
}

fn text_field<'a>(request: &'a Value, key: &str) -> Result<&'a str, Error> {
    request[key]
        .as_str()
        .ok_or_else(|| Error::InvalidInput(format!("The action request has no text field {key}.")))
}

/// Builds the JSON form of `ActionOutcome`.
fn outcome(action_id: &str, status: &str, message: String, details: Value) -> String {
    json!({
        "action_id": action_id,
        "status": status,
        "connector": NAME,
        "message": message,
        "details": details,
        "reversible": false,
        "completed_at": DateTime::<Utc>::from(SystemTime::now()).to_rfc3339(),
    })
    .to_string()
}

bindings::export!(ExampleAction with_types_in bindings);
