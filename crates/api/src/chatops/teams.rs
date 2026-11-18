//! The Microsoft Teams endpoint and the Teams message formats.
//!
//! # Untrusted text
//!
//! Teams reads message text and card text as Markdown, and message text also as HTML.
//! Text from an incident or an action is untrusted. This module puts such text on one
//! line, with a length limit, and escapes it: `&`, `<`, and `>` become entities, and each
//! other ASCII punctuation character gets a backslash. The text thus cannot make a link,
//! a mention, an image, or a tag.

use std::collections::BTreeMap;

use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus, Principal};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretSlice};
use serde::Deserialize;
use serde_json::{Value, json};

use super::commands::{self, HELP_LINES, Reply};
use super::signature::{MAX_SKEW_SECONDS, verify_teams};
use super::view::{Card, approval_card, decision_lines, incident_card, wire_name};
use crate::error::ApiError;
use crate::extract::{has_content_type, read_body};
use crate::routes::Ctx;
use crate::text::one_line;

const JSON: &str = "application/json";
const ADAPTIVE_CARD: &str = "application/vnd.microsoft.card.adaptive";
/// The schema identifier of an Adaptive Card. It is a name. The server does not request it.
const ADAPTIVE_CARD_SCHEMA: &str = "http://adaptivecards.io/schemas/adaptive-card.json";
const ADAPTIVE_CARD_VERSION: &str = "1.4";

const MAX_HEADLINE_CHARACTERS: usize = 120;
const MAX_VALUE_CHARACTERS: usize = 400;
const MAX_REFUSAL_CHARACTERS: usize = 300;
/// The maximum length of the command text that the server examines, in characters.
const MAX_COMMAND_CHARACTERS: usize = 2_000;

/// The Teams secret and users, after the server read the environment.
pub(crate) struct TeamsRuntime {
    pub secret: SecretSlice<u8>,
    pub users: BTreeMap<String, Principal>,
    pub require_timestamp: bool,
}

/// Escapes text for Teams Markdown and HTML.
pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len() + 8);
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other if other.is_ascii_punctuation() => {
                escaped.push('\\');
                escaped.push(other);
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Returns untrusted text as one escaped line with a length limit.
fn clean(text: &str, max_characters: usize) -> String {
    escape(&one_line(text, max_characters))
}

fn text_block(text: String) -> Value {
    json!({ "type": "TextBlock", "text": text, "wrap": true })
}

/// Renders a card as an Adaptive Card in a Teams webhook message.
fn card_message(card: &Card, hint: Option<String>) -> Value {
    let mut body = vec![json!({
        "type": "TextBlock",
        "text": card.title,
        "weight": "Bolder",
        "size": "Medium",
        "wrap": true,
    })];
    if let Some(headline) = &card.headline {
        body.push(text_block(clean(headline, MAX_HEADLINE_CHARACTERS)));
    }
    let mut facts: Vec<Value> = card
        .facts
        .iter()
        .map(
            |(label, value)| json!({ "title": label, "value": clean(value, MAX_VALUE_CHARACTERS) }),
        )
        .collect();
    facts.push(json!({ "title": card.reference.0, "value": card.reference.1.to_string() }));
    body.push(json!({ "type": "FactSet", "facts": facts }));
    if let Some(hint) = hint {
        body.push(text_block(hint));
    }
    json!({
        "type": "message",
        "attachments": [{
            "contentType": ADAPTIVE_CARD,
            "contentUrl": null,
            "content": {
                "$schema": ADAPTIVE_CARD_SCHEMA,
                "type": "AdaptiveCard",
                "version": ADAPTIVE_CARD_VERSION,
                "body": body,
            },
        }],
    })
}

/// Makes the Teams message for one approval request.
///
/// With `interactive`, a pending request tells the reader which commands decide it. Use
/// `false` if the server has no Teams endpoint.
#[must_use]
pub fn approval_message(request: &ApprovalRequest, interactive: bool) -> Value {
    let hint = (interactive && request.status == ApprovalStatus::Pending).then(|| {
        // The identifier is a UUID. It has no character that Teams reads as markup.
        let id = request.id;
        format!("To decide, send: approve {id} or reject {id}")
    });
    card_message(&approval_card(request), hint)
}

/// Makes the Teams message for one incident.
#[must_use]
pub fn incident_message(incident: &Incident) -> Value {
    card_message(&incident_card(incident), None)
}

/// Renders the answer to a command as Teams message text. Lines end with `<br>`.
fn reply_text(reply: &Reply) -> String {
    let lines: Vec<String> = match reply {
        Reply::Help => std::iter::once("AEGIS commands:".to_owned())
            .chain(HELP_LINES.iter().map(|line| escape(line)))
            .collect(),
        Reply::Incidents(incidents) if incidents.is_empty() => {
            vec!["AEGIS has no incidents.".to_owned()]
        }
        Reply::Incidents(incidents) => {
            std::iter::once(format!("The newest incidents: {}", incidents.len()))
                .chain(incidents.iter().map(|incident| {
                    format!(
                        "{} | {} | {} | {}",
                        escape(&wire_name(&incident.severity)),
                        escape(&wire_name(&incident.status)),
                        clean(&incident.title, MAX_HEADLINE_CHARACTERS),
                        incident.id
                    )
                }))
                .collect()
        }
        Reply::Approvals { items, .. } if items.is_empty() => {
            vec!["No action waits for approval.".to_owned()]
        }
        Reply::Approvals { items, total } => std::iter::once(format!(
            "Actions that wait for approval: {total}. This message shows {}.",
            items.len()
        ))
        .chain(items.iter().map(|request| {
            let card = approval_card(request);
            let facts = card
                .facts
                .iter()
                .map(|(label, value)| format!("{label}: {}", clean(value, MAX_VALUE_CHARACTERS)))
                .collect::<Vec<_>>()
                .join(" | ");
            format!("{} | {facts}", request.id)
        }))
        .collect(),
        Reply::Decided(decision) => decision_lines(decision)
            .iter()
            .map(|line| clean(line, MAX_VALUE_CHARACTERS))
            .collect(),
        Reply::Refused(reason) => vec![clean(reason, MAX_REFUSAL_CHARACTERS)],
    };
    lines.join("<br>")
}

/// Makes the answer to a Teams outgoing webhook message.
pub(crate) fn command_response(reply: &Reply) -> Value {
    json!({ "type": "message", "text": reply_text(reply) })
}

#[derive(Debug, Deserialize)]
struct Sender {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "aadObjectId")]
    aad_object_id: Option<String>,
}

/// The fields of a Teams activity that the server reads. Teams sends more fields.
#[derive(Debug, Deserialize)]
struct Activity {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    from: Option<Sender>,
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
}

/// Returns the command in the text of a Teams message.
///
/// Teams puts the mention of the webhook in the text as `<at>name</at>`, and it can add
/// other tags and entities. The function removes the mention and each tag, and decodes
/// the entities that Teams writes.
pub(crate) fn command_text(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        plain.push_str(&rest[..start]);
        let tag = &rest[start..];
        let Some(end) = tag.find('>') else {
            // An open tag with no end is not a command.
            rest = "";
            break;
        };
        let name = tag[1..end].trim().to_ascii_lowercase();
        rest = &tag[end + 1..];
        if name == "at" || name.starts_with("at ") {
            // The text of a mention is not a part of the command.
            rest = match rest.to_ascii_lowercase().find("</at>") {
                Some(close) => &rest[close + "</at>".len()..],
                None => "",
            };
        }
        plain.push(' ');
    }
    plain.push_str(rest);
    let decoded = plain
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    one_line(&decoded, MAX_COMMAND_CHARACTERS)
}

fn reply(reply: &Reply) -> Response {
    Json(command_response(reply)).into_response()
}

const NOT_PERMITTED: &str = "You are not permitted to use AEGIS from this chat.";

/// `POST /chatops/teams/messages`: one message of a Teams outgoing webhook.
pub(crate) async fn message(State(ctx): State<Ctx>, request: Request) -> Response {
    let Some(teams) = &ctx.chat.teams else {
        return ApiError::NotFound("The path does not exist.".to_owned()).into_response();
    };
    let headers = request.headers().clone();
    let body = match read_body(request).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let mut authorizations = headers.get_all(AUTHORIZATION).iter();
    let authorization = match (authorizations.next(), authorizations.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    };
    if let Err(reason) = verify_teams(teams.secret.expose_secret(), authorization, &body) {
        tracing::warn!(%reason, "a Teams request was refused");
        return ApiError::BadSignature.into_response();
    }
    if !has_content_type(&headers, JSON) {
        return ApiError::UnsupportedMediaType(JSON).into_response();
    }
    // An activity is a JSON object. The parser would also read an array as the fields.
    let activity = serde_json::from_slice::<Value>(&body)
        .ok()
        .filter(Value::is_object)
        .and_then(|value| serde_json::from_value::<Activity>(value).ok());
    let Some(activity) = activity else {
        return ApiError::BadRequest("The message is not valid.".to_owned()).into_response();
    };
    if teams.require_timestamp {
        let fresh = activity.timestamp.is_some_and(|time| {
            (Utc::now() - time).num_milliseconds().abs() <= MAX_SKEW_SECONDS * 1_000
        });
        if !fresh {
            tracing::warn!("a Teams request with no timestamp or an old timestamp was refused");
            return ApiError::BadSignature.into_response();
        }
    }
    if activity
        .kind
        .as_deref()
        .is_some_and(|kind| kind != "message")
    {
        return ApiError::BadRequest("The message is not valid.".to_owned()).into_response();
    }
    let sender = activity.from.as_ref();
    let principal = sender
        .and_then(|sender| sender.aad_object_id.as_deref())
        .and_then(|id| teams.users.get(id))
        .or_else(|| {
            sender
                .and_then(|sender| sender.id.as_deref())
                .and_then(|id| teams.users.get(id))
        });
    let Some(principal) = principal else {
        tracing::warn!("a Teams request from an unknown user was refused");
        return reply(&Reply::Refused(NOT_PERMITTED.to_owned()));
    };
    let text = command_text(activity.text.as_deref().unwrap_or_default());
    let answer = match commands::parse(&text) {
        Ok(command) => commands::execute(&ctx.state, principal, command).await,
        Err(message) => Reply::Refused(message),
    };
    reply(&answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_characters_are_escaped() {
        assert_eq!(
            escape("[click](https://evil.example) <at>all</at> **bold** & _it_"),
            "\\[click\\]\\(https\\:\\/\\/evil\\.example\\) &lt;at&gt;all&lt;\\/at&gt; \
             \\*\\*bold\\*\\* &amp; \\_it\\_"
        );
        assert_eq!(
            escape("![x](y) `code` # ~"),
            "\\!\\[x\\]\\(y\\) \\`code\\` \\# \\~"
        );
        assert_eq!(escape("plain text 123 é"), "plain text 123 é");
        assert_eq!(escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn the_command_is_the_text_without_the_mention_and_the_tags() {
        let id = "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e";
        assert_eq!(command_text("<at>AEGIS</at> approvals"), "approvals");
        assert_eq!(
            command_text(&format!(
                "<div><at id=\"0\">AEGIS bot</at>&nbsp;approve {id} looks&nbsp;right</div>"
            )),
            format!("approve {id} looks right")
        );
        assert_eq!(command_text("  incidents\n"), "incidents");
        assert_eq!(command_text("<AT>AEGIS</AT> help"), "help");
        assert_eq!(command_text("<at>approve"), "");
        assert_eq!(command_text("approve <unclosed"), "approve");
        assert_eq!(
            command_text("reject x a &amp; b &lt;c&gt;"),
            "reject x a & b <c>"
        );
    }

    #[test]
    fn a_mention_cannot_hide_a_command_in_its_name() {
        // The name of the webhook is in the mention. It is not a part of the command.
        assert_eq!(command_text("<at>approve all</at> help"), "help");
    }
}
