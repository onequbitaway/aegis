//! The Slack endpoints and the Slack message format.
//!
//! # Untrusted text
//!
//! Text from an incident or an action is untrusted. This module puts such text only in
//! `plain_text` objects, on one line, with a length limit. It also converts `&`, `<`, and
//! `>` to entities, so that the text cannot make a mention, a link, or a channel
//! notification.

use std::collections::BTreeMap;
use std::time::Duration;

use aegis_contracts::common::ApprovalId;
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus, Principal};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use url::{Url, form_urlencoded};

use super::commands::{self, Command, HELP_LINES, Reply};
use super::http::{Outbound, is_permitted_target};
use super::signature::verify_slack;
use super::view::{Card, approval_card, decision_lines, incident_card, wire_name};
use crate::error::ApiError;
use crate::extract::{has_content_type, read_body};
use crate::routes::Ctx;
use crate::text::one_line;

/// The `action_id` of the approve button.
pub const APPROVE_ACTION_ID: &str = "aegis_approve";
/// The `action_id` of the reject button.
pub const REJECT_ACTION_ID: &str = "aegis_reject";

const TIMESTAMP_HEADER: &str = "x-slack-request-timestamp";
const SIGNATURE_HEADER: &str = "x-slack-signature";
const FORM: &str = "application/x-www-form-urlencoded";

/// The maximum time for the answer to a button. Slack waits three seconds for the server.
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_HEADLINE_CHARACTERS: usize = 120;
const MAX_VALUE_CHARACTERS: usize = 400;
const MAX_REFUSAL_CHARACTERS: usize = 300;

/// The Slack secrets and users, after the server read the environment.
pub(crate) struct SlackRuntime {
    pub signing_secret: SecretString,
    pub team_id: Option<String>,
    pub users: BTreeMap<String, Principal>,
    pub response_hosts: Vec<String>,
    pub outbound: Outbound,
}

/// Converts the three control characters of Slack text to entities.
pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Returns untrusted text as one escaped line with a length limit.
fn clean(text: &str, max_characters: usize) -> String {
    escape(&one_line(text, max_characters))
}

fn plain_text(text: String) -> Value {
    json!({ "type": "plain_text", "text": text, "emoji": false })
}

fn section(text: String) -> Value {
    json!({ "type": "section", "text": plain_text(text) })
}

/// Renders a card as blocks. Each untrusted value is in a `plain_text` object.
fn card_blocks(card: &Card) -> Vec<Value> {
    let mut blocks = vec![json!({ "type": "header", "text": plain_text(card.title.to_owned()) })];
    if let Some(headline) = &card.headline {
        blocks.push(section(clean(headline, MAX_HEADLINE_CHARACTERS)));
    }
    let facts = card
        .facts
        .iter()
        .map(|(label, value)| format!("{label}: {}", clean(value, MAX_VALUE_CHARACTERS)))
        .collect::<Vec<_>>()
        .join("\n");
    blocks.push(section(facts));
    blocks.push(json!({
        "type": "context",
        "elements": [plain_text(format!("{} {}", card.reference.0, card.reference.1))]
    }));
    blocks
}

/// Returns the fallback text of a card. Slack shows it in a notification.
fn card_fallback(card: &Card) -> String {
    match &card.headline {
        Some(headline) => format!(
            "{}: {}",
            card.title,
            clean(headline, MAX_HEADLINE_CHARACTERS)
        ),
        None => card.title.to_owned(),
    }
}

fn button(action_id: &str, label: &str, style: &str, id: ApprovalId) -> Value {
    json!({
        "type": "button",
        "action_id": action_id,
        "style": style,
        "text": plain_text(label.to_owned()),
        "value": id.to_string(),
    })
}

/// Returns the block with the approve button and the reject button for one request.
fn decision_buttons(id: ApprovalId) -> Value {
    let mut approve = button(APPROVE_ACTION_ID, "Approve", "primary", id);
    if let Some(fields) = approve.as_object_mut() {
        fields.insert(
            "confirm".to_owned(),
            json!({
                "title": plain_text("Approve the action?".to_owned()),
                "text": plain_text("AEGIS runs the action after the approval.".to_owned()),
                "confirm": plain_text("Approve".to_owned()),
                "deny": plain_text("Cancel".to_owned()),
            }),
        );
    }
    json!({
        "type": "actions",
        "block_id": format!("aegis_approval_{id}"),
        "elements": [approve, button(REJECT_ACTION_ID, "Reject", "danger", id)],
    })
}

/// Makes the Slack message for one approval request.
///
/// With `interactive`, a pending request gets an approve button and a reject button. Use
/// `false` if the server has no Slack endpoints.
#[must_use]
pub fn approval_message(request: &ApprovalRequest, interactive: bool) -> Value {
    let card = approval_card(request);
    let mut blocks = card_blocks(&card);
    if interactive && request.status == ApprovalStatus::Pending {
        blocks.push(decision_buttons(request.id));
    }
    json!({ "text": card_fallback(&card), "blocks": blocks })
}

/// Makes the Slack message for one incident.
#[must_use]
pub fn incident_message(incident: &Incident) -> Value {
    let card = incident_card(incident);
    json!({ "text": card_fallback(&card), "blocks": card_blocks(&card) })
}

fn incident_line(incident: &Incident) -> String {
    format!(
        "{} | {} | {}\n{}",
        wire_name(&incident.severity),
        wire_name(&incident.status),
        clean(&incident.title, MAX_HEADLINE_CHARACTERS),
        incident.id
    )
}

/// Renders the answer to a command. `interactive` adds the buttons to pending requests.
fn reply_content(reply: &Reply, interactive: bool) -> (String, Vec<Value>) {
    match reply {
        Reply::Help => {
            let lines: Vec<String> = HELP_LINES.iter().map(|line| escape(line)).collect();
            (format!("AEGIS commands:\n{}", lines.join("\n")), Vec::new())
        }
        Reply::Incidents(incidents) if incidents.is_empty() => {
            ("AEGIS has no incidents.".to_owned(), Vec::new())
        }
        Reply::Incidents(incidents) => {
            let text = format!("The newest incidents: {}", incidents.len());
            let mut blocks = vec![section(text.clone())];
            blocks.extend(
                incidents
                    .iter()
                    .map(|incident| section(incident_line(incident))),
            );
            (text, blocks)
        }
        Reply::Approvals { items, .. } if items.is_empty() => {
            ("No action waits for approval.".to_owned(), Vec::new())
        }
        Reply::Approvals { items, total } => {
            let text = format!(
                "Actions that wait for approval: {total}. This message shows {}.",
                items.len()
            );
            let mut blocks = vec![section(text.clone())];
            for request in items {
                // The first block of a card is its header. A list has one header only.
                blocks.extend(card_blocks(&approval_card(request)).into_iter().skip(1));
                if interactive {
                    blocks.push(decision_buttons(request.id));
                }
            }
            (text, blocks)
        }
        Reply::Decided(decision) => {
            let lines: Vec<String> = decision_lines(decision)
                .iter()
                .map(|line| clean(line, MAX_VALUE_CHARACTERS))
                .collect();
            (lines.join("\n"), Vec::new())
        }
        Reply::Refused(reason) => (clean(reason, MAX_REFUSAL_CHARACTERS), Vec::new()),
    }
}

/// Makes the answer to a slash command. Only the person who sent the command sees it.
pub(crate) fn command_response(reply: &Reply, interactive: bool) -> Value {
    let (text, blocks) = reply_content(reply, interactive);
    let mut message = json!({ "response_type": "ephemeral", "text": text });
    if !blocks.is_empty()
        && let Some(fields) = message.as_object_mut()
    {
        fields.insert("blocks".to_owned(), Value::Array(blocks));
    }
    message
}

/// Makes the answer to a button. A decision replaces the message with the buttons. A
/// refusal goes only to the person who used the button.
pub(crate) fn interaction_response(reply: &Reply) -> Value {
    let (text, _) = reply_content(reply, false);
    match reply {
        Reply::Decided(_) => json!({ "replace_original": true, "text": text }),
        _ => json!({ "response_type": "ephemeral", "replace_original": false, "text": text }),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    // Two headers with one name are ambiguous. Such a request is refused.
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn refusal(text: &str) -> Response {
    Json(command_response(&Reply::Refused(text.to_owned()), false)).into_response()
}

const NOT_PERMITTED: &str = "You are not permitted to use AEGIS from this chat.";

/// Reads a Slack request and checks its signature. Returns the body.
async fn verified_body(slack: &SlackRuntime, request: Request) -> Result<Vec<u8>, ApiError> {
    let headers = request.headers().clone();
    let body = read_body(request).await?;
    let now = chrono::Utc::now().timestamp();
    if let Err(reason) = verify_slack(
        slack.signing_secret.expose_secret().as_bytes(),
        header(&headers, TIMESTAMP_HEADER),
        header(&headers, SIGNATURE_HEADER),
        &body,
        now,
    ) {
        tracing::warn!(%reason, "a Slack request was refused");
        return Err(ApiError::BadSignature);
    }
    if !has_content_type(&headers, FORM) {
        return Err(ApiError::UnsupportedMediaType(FORM));
    }
    Ok(body.to_vec())
}

fn form_field(body: &[u8], name: &str) -> Option<String> {
    form_urlencoded::parse(body)
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Returns the principal of a Slack user, or `None` if the user is not permitted.
fn principal_of<'a>(
    slack: &'a SlackRuntime,
    team_id: Option<&str>,
    user_id: Option<&str>,
) -> Option<&'a Principal> {
    if let Some(expected) = &slack.team_id
        && team_id != Some(expected.as_str())
    {
        tracing::warn!("a Slack request from a different workspace was refused");
        return None;
    }
    let principal = user_id.and_then(|user| slack.users.get(user));
    if principal.is_none() {
        tracing::warn!("a Slack request from an unknown user was refused");
    }
    principal
}

/// `POST /chatops/slack/commands`: one slash command.
pub(crate) async fn command(State(ctx): State<Ctx>, request: Request) -> Response {
    let Some(slack) = &ctx.chat.slack else {
        return ApiError::NotFound("The path does not exist.".to_owned()).into_response();
    };
    let body = match verified_body(slack, request).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let team_id = form_field(&body, "team_id");
    let user_id = form_field(&body, "user_id");
    let Some(principal) = principal_of(slack, team_id.as_deref(), user_id.as_deref()) else {
        return refusal(NOT_PERMITTED);
    };
    let text = form_field(&body, "text").unwrap_or_default();
    let reply = match commands::parse(&text) {
        Ok(command) => commands::execute(&ctx.state, principal, command).await,
        Err(message) => Reply::Refused(message),
    };
    Json(command_response(&reply, true)).into_response()
}

#[derive(Debug, Deserialize)]
struct InteractionUser {
    id: String,
}

#[derive(Debug, Deserialize)]
struct InteractionTeam {
    id: String,
}

#[derive(Debug, Deserialize)]
struct InteractionAction {
    action_id: String,
    #[serde(default)]
    value: Option<String>,
}

/// The fields of a Slack interaction that the server reads. Slack sends more fields.
#[derive(Debug, Deserialize)]
struct Interaction {
    #[serde(rename = "type")]
    kind: String,
    user: InteractionUser,
    #[serde(default)]
    team: Option<InteractionTeam>,
    #[serde(default)]
    actions: Vec<InteractionAction>,
    #[serde(default)]
    response_url: Option<String>,
}

fn bad_interaction() -> Response {
    ApiError::BadRequest("The interaction is not valid.".to_owned()).into_response()
}

/// Returns the command of a button, or `None` if the button is not a button of AEGIS.
fn button_command(action: &InteractionAction) -> Option<Command> {
    let approve = match action.action_id.as_str() {
        APPROVE_ACTION_ID => true,
        REJECT_ACTION_ID => false,
        _ => return None,
    };
    let id = action.value.as_deref()?.parse().ok()?;
    Some(Command::Decide {
        id,
        approve,
        note: None,
    })
}

/// Returns the URL for the answer to a button, if the configuration permits its host.
fn response_target(slack: &SlackRuntime, response_url: Option<&str>) -> Option<Url> {
    let url = Url::parse(response_url?).ok()?;
    let host = url.host_str()?;
    let listed = slack
        .response_hosts
        .iter()
        .any(|permitted| permitted.eq_ignore_ascii_case(host));
    if listed && is_permitted_target(&url) {
        Some(url)
    } else {
        tracing::warn!("a Slack response URL has a host that the configuration does not permit");
        None
    }
}

/// Sends the answer to a button. A failure goes to the log: the decision is complete.
async fn send_response(slack: &SlackRuntime, url: Url, message: &Value) {
    let request = slack
        .outbound
        .client_for(&url)
        .post(url)
        .timeout(RESPONSE_TIMEOUT)
        .json(message);
    match request.send().await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(status = %response.status(), "Slack refused the answer to a button");
        }
        Err(error) => {
            tracing::warn!(error = %error.without_url(), "the answer to a Slack button failed");
        }
    }
}

/// `POST /chatops/slack/interactions`: one use of an approve button or a reject button.
pub(crate) async fn interaction(State(ctx): State<Ctx>, request: Request) -> Response {
    let Some(slack) = &ctx.chat.slack else {
        return ApiError::NotFound("The path does not exist.".to_owned()).into_response();
    };
    let body = match verified_body(slack, request).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let Some(interaction) = form_field(&body, "payload")
        .and_then(|payload| serde_json::from_str::<Value>(&payload).ok())
        .filter(Value::is_object)
        .and_then(|payload| serde_json::from_value::<Interaction>(payload).ok())
    else {
        return bad_interaction();
    };
    if interaction.kind != "block_actions" {
        return bad_interaction();
    }
    let Some(command) = interaction.actions.first().and_then(button_command) else {
        return bad_interaction();
    };
    let team_id = interaction.team.as_ref().map(|team| team.id.as_str());
    let reply = match principal_of(slack, team_id, Some(&interaction.user.id)) {
        Some(principal) => commands::execute(&ctx.state, principal, command).await,
        None => Reply::Refused(NOT_PERMITTED.to_owned()),
    };
    let message = interaction_response(&reply);
    if let Some(url) = response_target(slack, interaction.response_url.as_deref()) {
        send_response(slack, url, &message).await;
    }
    // Slack shows nothing from this body. It is here for a client that is not Slack.
    Json(message).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_control_characters_become_entities() {
        assert_eq!(
            escape("<!channel> <@U123> <https://evil.example|click> a & b"),
            "&lt;!channel&gt; &lt;@U123&gt; &lt;https://evil.example|click&gt; a &amp; b"
        );
        assert_eq!(escape("&amp;"), "&amp;amp;");
        assert_eq!(escape("plain *text*"), "plain *text*");
    }

    #[test]
    fn the_help_text_escapes_its_placeholders() {
        let (text, blocks) = reply_content(&Reply::Help, true);
        assert!(blocks.is_empty());
        assert!(text.contains("approve &lt;id&gt; [note]"), "{text}");
        assert!(!text.contains('<'));
    }

    #[test]
    fn a_response_url_must_have_a_permitted_host_and_https() {
        let slack = |hosts: &[&str]| SlackRuntime {
            signing_secret: SecretString::from("x".repeat(32)),
            team_id: None,
            users: BTreeMap::new(),
            response_hosts: hosts.iter().map(ToString::to_string).collect(),
            outbound: Outbound::new(RESPONSE_TIMEOUT).unwrap(),
        };
        let default = slack(&["hooks.slack.com"]);
        let target = |runtime: &SlackRuntime, url: &str| {
            response_target(runtime, Some(url)).map(|url| url.to_string())
        };
        assert_eq!(
            target(&default, "https://hooks.slack.com/actions/T1/2/abc"),
            Some("https://hooks.slack.com/actions/T1/2/abc".to_owned())
        );
        assert_eq!(
            target(&default, "https://HOOKS.SLACK.COM/a"),
            Some("https://hooks.slack.com/a".to_owned())
        );
        for refused in [
            "http://hooks.slack.com/actions/T1/2/abc",
            "https://hooks.slack.com.evil.example/a",
            "https://evil.example/hooks.slack.com",
            "https://user:pass@hooks.slack.com/a",
            "http://127.0.0.1:9000/a",
            "http://169.254.169.254/latest/meta-data",
            "not a url",
        ] {
            assert_eq!(target(&default, refused), None, "{refused}");
        }
        assert_eq!(response_target(&default, None), None);

        let local = slack(&["127.0.0.1"]);
        assert_eq!(
            target(&local, "http://127.0.0.1:9000/a"),
            Some("http://127.0.0.1:9000/a".to_owned())
        );
        assert_eq!(target(&local, "https://hooks.slack.com/a"), None);
    }

    #[test]
    fn only_the_buttons_of_aegis_give_a_command() {
        let id = ApprovalId::new();
        let action = |action_id: &str, value: Option<&str>| InteractionAction {
            action_id: action_id.to_owned(),
            value: value.map(str::to_owned),
        };
        assert_eq!(
            button_command(&action(APPROVE_ACTION_ID, Some(&id.to_string()))),
            Some(Command::Decide {
                id,
                approve: true,
                note: None
            })
        );
        assert_eq!(
            button_command(&action(REJECT_ACTION_ID, Some(&id.to_string()))),
            Some(Command::Decide {
                id,
                approve: false,
                note: None
            })
        );
        assert_eq!(
            button_command(&action("other", Some(&id.to_string()))),
            None
        );
        assert_eq!(button_command(&action(APPROVE_ACTION_ID, Some("42"))), None);
        assert_eq!(button_command(&action(APPROVE_ACTION_ID, None)), None);
    }
}
