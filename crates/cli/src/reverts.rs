//! The commands for the timed reverts of a running service.
//!
//! A timed revert is a containment action that AEGIS reverts at a set time, unless a
//! person confirms it. The running service holds the pending reverts in one store, and
//! one scheduler uses one store. Thus these commands do not read the store file. They
//! call the operator API of the running service. The service checks the token and the
//! permission `approve_actions`, and it writes each audit record with the principal of
//! the token.

use anyhow::{Context as _, bail};
use serde_json::{Value, json};

use crate::Format;
use crate::client::ApiClient;
use crate::output::{print, print_json};

/// The largest extension of a revert time, in seconds: 30 days.
const MAX_EXTENSION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Reads a time span: a number of seconds, or a number with the unit `s`, `m`, `h`, or
/// `d`, for example `90m`.
///
/// # Errors
///
/// Returns an error if the text has a different form, or if the span is not from one
/// second to 30 days.
pub fn parse_span(text: &str) -> anyhow::Result<u64> {
    let text = text.trim();
    let digits = text.trim_end_matches(|character: char| !character.is_ascii_digit());
    let scale: u64 = match text[digits.len()..].trim() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => bail!(
            "the time span is not valid. Use a number of seconds, or a number with the unit \
             s, m, h, or d, for example 4h"
        ),
    };
    let number: u64 = digits.parse().ok().with_context(|| {
        "the time span is not valid. Use a number of seconds, or a number with the unit s, m, \
         h, or d, for example 4h"
    })?;
    let seconds = number.saturating_mul(scale);
    if !(1..=MAX_EXTENSION_SECONDS).contains(&seconds) {
        bail!("the time span must be from 1 second to {MAX_EXTENSION_SECONDS} seconds (30 days)");
    }
    Ok(seconds)
}

/// Checks that `text` is the identifier of an action and returns one path segment.
fn action_segment(text: &str) -> anyhow::Result<String> {
    let id: aegis_contracts::common::ActionId = text
        .trim()
        .parse()
        .ok()
        .context("the action identifier is not a valid UUID")?;
    Ok(id.to_string())
}

/// Returns a JSON value as text: a string with no quotation marks, or the JSON text.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_owned(),
        // A custom action type is an object with one key.
        Value::Object(fields) => fields
            .iter()
            .next()
            .map(|(key, value)| format!("{key}:{}", text_of(value)))
            .unwrap_or_default(),
        other => other.to_string(),
    }
}

/// Removes control characters from a text of the service. A target name can hold text
/// from an attacker.
fn clean(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Returns one line for a pending revert.
fn revert_line(revert: &Value) -> String {
    let target = format!(
        "{} {}",
        text_of(&revert["target"]["kind"]),
        text_of(&revert["target"]["id"])
    );
    let mut line = format!(
        "{}  {:<26}  {:<38}  revert at {}  {}",
        text_of(&revert["action_id"]),
        text_of(&revert["kind"]),
        target,
        text_of(&revert["due_at"]),
        text_of(&revert["state"]),
    );
    let attempts = revert["attempts"].as_u64().unwrap_or(0);
    if attempts > 0 {
        line.push_str(&format!(
            "  {attempts} failed attempts, last error: {}",
            text_of(&revert["last_error"])
        ));
    }
    if !revert["approval_id"].is_null() {
        line.push_str(&format!(
            "  waits for the approval {}",
            text_of(&revert["approval_id"])
        ));
    }
    clean(&line)
}

/// Returns what the dispatcher did with a revert, in one sentence.
fn disposition_text(disposition: &Value) -> String {
    if let Some(outcome) = disposition.get("executed") {
        return clean(&format!(
            "The revert has the status {} (connector {}): {}",
            text_of(&outcome["status"]),
            text_of(&outcome["connector"]),
            text_of(&outcome["message"])
        ));
    }
    if let Some(pending) = disposition.get("pending_approval") {
        return clean(&format!(
            "Policy requires approval for the revert. It waits for the approval {}. The \
             containment stays until a person approves the revert.",
            text_of(&pending["approval_id"])
        ));
    }
    if let Some(denied) = disposition.get("denied") {
        let reasons: Vec<String> = denied["reasons"]
            .as_array()
            .map(|reasons| reasons.iter().map(text_of).collect())
            .unwrap_or_default();
        return clean(&format!(
            "Policy denied the revert. The containment stays. {}",
            reasons.join(" ")
        ));
    }
    "The service gave no result.".to_owned()
}

/// `aegis reverts list`: the timed reverts that wait in the running service.
pub async fn list(client: &ApiClient, format: Format) -> anyhow::Result<()> {
    let page = client.get("/reverts").await?;
    if format == Format::Json {
        return print_json(&page);
    }
    let address = client.address();
    if page["enabled"] == json!(false) {
        return print(&format!(
            "The timed revert is off in the service at {address}. The configuration has no \
             [response.revert] table.\n"
        ));
    }
    let items = page["items"].as_array().cloned().unwrap_or_default();
    let total = page["total"].as_u64().unwrap_or(items.len() as u64);
    let mut text = format!("Timed reverts ({total}) of the service at {address}\n");
    for revert in &items {
        text.push_str("  ");
        text.push_str(&revert_line(revert));
        text.push('\n');
    }
    if total > items.len() as u64 {
        text.push_str(&format!(
            "  The list shows the first {} reverts.\n",
            items.len()
        ));
    }
    if total == 0 {
        text.push_str("  No action waits for a timed revert.\n");
    } else {
        text.push_str(
            "AEGIS reverts each action at its time, unless a person confirms it:\n  aegis \
             reverts confirm <ACTION_ID>\n",
        );
    }
    print(&text)
}

/// `aegis reverts confirm`: the containment stays. AEGIS does not revert it.
pub async fn confirm(client: &ApiClient, action_id: &str, format: Format) -> anyhow::Result<()> {
    let id = action_segment(action_id)?;
    let answer = client
        .post(&format!("/reverts/{id}/confirm"), &json!({}))
        .await?;
    if format == Format::Json {
        return print_json(&answer);
    }
    let revert = &answer["revert"];
    let mut text = clean(&format!(
        "Confirmed the action {} ({} on {} {}). The containment stays. AEGIS does not revert \
         it.",
        text_of(&revert["action_id"]),
        text_of(&revert["kind"]),
        text_of(&revert["target"]["kind"]),
        text_of(&revert["target"]["id"]),
    ));
    text.push('\n');
    print(&text)
}

/// `aegis reverts extend`: moves the revert time of an action.
pub async fn extend(
    client: &ApiClient,
    action_id: &str,
    by: &str,
    format: Format,
) -> anyhow::Result<()> {
    let id = action_segment(action_id)?;
    let seconds = parse_span(by)?;
    let answer = client
        .post(
            &format!("/reverts/{id}/extend"),
            &json!({ "seconds": seconds }),
        )
        .await?;
    if format == Format::Json {
        return print_json(&answer);
    }
    let revert = &answer["revert"];
    let mut text = clean(&format!(
        "Moved the revert time of the action {} by {seconds} seconds. AEGIS reverts the action \
         at {}, unless a person confirms it.",
        text_of(&revert["action_id"]),
        text_of(&revert["due_at"]),
    ));
    text.push('\n');
    print(&text)
}

/// `aegis reverts cancel`: reverts an action now, before its revert time.
pub async fn cancel(client: &ApiClient, action_id: &str, format: Format) -> anyhow::Result<()> {
    let id = action_segment(action_id)?;
    let answer = client
        .post(&format!("/reverts/{id}/cancel"), &json!({}))
        .await?;
    if format == Format::Json {
        return print_json(&answer);
    }
    let mut text = format!(
        "Requested the revert of the action {id}. {}",
        disposition_text(&answer["disposition"])
    );
    text.push('\n');
    print(&text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_time_span_is_seconds_or_a_number_with_a_unit() {
        assert_eq!(parse_span("90").unwrap(), 90);
        assert_eq!(parse_span("90s").unwrap(), 90);
        assert_eq!(parse_span("30m").unwrap(), 1800);
        assert_eq!(parse_span(" 4h ").unwrap(), 14_400);
        assert_eq!(parse_span("2d").unwrap(), 172_800);
        assert_eq!(parse_span("30d").unwrap(), MAX_EXTENSION_SECONDS);
        for bad in ["", "h", "4 hours", "-4h", "1.5h", "4w", "0", "0h", "31d"] {
            assert!(parse_span(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_action_identifier_is_a_uuid() {
        let id = "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e";
        assert_eq!(action_segment(&format!(" {id} ")).unwrap(), id);
        for bad in [
            "",
            "1",
            "../audit",
            "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e/confirm",
        ] {
            let error = action_segment(bad).unwrap_err().to_string();
            assert_eq!(error, "the action identifier is not a valid UUID", "{bad}");
        }
    }

    #[test]
    fn one_line_shows_a_pending_revert_with_no_control_characters() {
        let revert = json!({
            "action_id": "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e",
            "kind": "block_ip",
            "target": { "kind": "ip_address", "id": "203.0.113.50\u{1b}[2J" },
            "due_at": "2026-11-03T13:10:00Z",
            "state": "waiting",
            "attempts": 2,
            "last_error": "the firewall\ndid not answer",
        });
        assert_eq!(
            revert_line(&revert),
            "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e  block_ip                    ip_address \
             203.0.113.50 [2J             revert at 2026-11-03T13:10:00Z  waiting  2 failed \
             attempts, last error: the firewall did not answer"
        );
        let custom = json!({
            "action_id": "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e",
            "kind": { "custom": "restrict_user_consent" },
            "target": { "kind": "tenant", "id": "tenant-contoso" },
            "due_at": "2026-11-03T11:10:00Z",
            "state": "waiting",
            "approval_id": "0190d5b0-7c3a-7e5b-9f6e-000000000001",
        });
        let line = revert_line(&custom);
        assert!(line.contains("custom:restrict_user_consent"), "{line}");
        assert!(
            line.ends_with("waits for the approval 0190d5b0-7c3a-7e5b-9f6e-000000000001"),
            "{line}"
        );
    }

    #[test]
    fn the_result_of_a_revert_is_one_sentence() {
        assert_eq!(
            disposition_text(&json!({ "executed": {
                "status": "succeeded", "connector": "firewall", "message": "Removed the block."
            } })),
            "The revert has the status succeeded (connector firewall): Removed the block."
        );
        assert!(
            disposition_text(&json!({ "pending_approval": { "approval_id": "a-1" } })).starts_with(
                "Policy requires approval for the revert. It waits for the approval a-1."
            )
        );
        assert_eq!(
            disposition_text(&json!({ "denied": { "reasons": ["No rule permits it."] } })),
            "Policy denied the revert. The containment stays. No rule permits it."
        );
    }
}
