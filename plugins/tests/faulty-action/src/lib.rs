//! An action connector plugin that misbehaves on request.
//!
//! Only the tests of the plugin host use this plugin. It changes nothing outside the
//! sandbox.
//!
//! The configuration value `mode` selects the behavior:
//!
//! | Mode | Behavior |
//! | --- | --- |
//! | `bad-kinds` | `supported-actions` returns text that is not JSON. |
//! | `bad-json` | `execute` returns text that is not JSON. |
//! | `wrong-shape` | `execute` returns JSON that is not an action outcome. |
//! | `foreign-outcome` | `execute` returns an outcome for a different action and connector. |
//! | `simulated` | `execute` always returns the status `simulated`. |
//!
//! With no mode, `execute` and `revert` return the status `succeeded` and send nothing.
//! They do not look at `dry_run`.

/// The Rust form of the `action-connector` world in the `wit` directory.
mod bindings {
    wit_bindgen::generate!({
        path: "../../../wit",
        world: "action-connector",
    });
}

use bindings::aegis::plugin::host;
use bindings::aegis::plugin::types::Error;
use bindings::exports::aegis::plugin::action::Guest;
use serde_json::{Value, json};

const NAME: &str = "faulty-action";
const FOREIGN_ACTION_ID: &str = "018f0000-0000-7000-8000-0000000000ff";

struct FaultyAction;

impl Guest for FaultyAction {
    fn info() -> String {
        json!({ "name": NAME, "vendor": "aegis", "product": "faulty", "version": "0.0.0" })
            .to_string()
    }

    fn supported_actions() -> String {
        if mode() == "bad-kinds" {
            return "This text is not JSON.".to_owned();
        }
        json!(["tag", { "custom": "probe" }]).to_string()
    }

    fn execute(request_json: String) -> Result<String, Error> {
        match mode().as_str() {
            "bad-json" => Ok("<html>This text is not JSON.</html>".to_owned()),
            "wrong-shape" => Ok(json!({ "status": "done" }).to_string()),
            "foreign-outcome" => Ok(outcome(
                FOREIGN_ACTION_ID,
                "entra-prod",
                "succeeded",
                "Executed.",
            )),
            "simulated" => Ok(outcome(
                &action_id(&request_json)?,
                NAME,
                "simulated",
                "Would execute.",
            )),
            _ => Ok(outcome(
                &action_id(&request_json)?,
                NAME,
                "succeeded",
                "Executed.",
            )),
        }
    }

    fn revert(request_json: String) -> Result<String, Error> {
        Ok(outcome(
            &action_id(&request_json)?,
            NAME,
            "succeeded",
            "Reverted.",
        ))
    }
}

fn mode() -> String {
    host::config_get("mode").unwrap_or_default()
}

fn action_id(request_json: &str) -> Result<String, Error> {
    let request: Value = serde_json::from_str(request_json)
        .map_err(|_| Error::InvalidInput("The action request is not valid JSON.".to_owned()))?;
    request["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidInput("The action request has no identifier.".to_owned()))
}

fn outcome(action_id: &str, connector: &str, status: &str, message: &str) -> String {
    json!({
        "action_id": action_id,
        "status": status,
        "connector": connector,
        "message": message,
        "reversible": true,
        "completed_at": "2026-01-02T03:00:00Z",
    })
    .to_string()
}

bindings::export!(FaultyAction with_types_in bindings);
