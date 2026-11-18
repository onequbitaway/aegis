//! ChatOps: Slack and Microsoft Teams commands, buttons, and notifications.
//!
//! All parts are off until the configuration names a secret. Refer to
//! [`ChatOpsConfig`].
//!
//! | Endpoint | Function |
//! | --- | --- |
//! | `POST /chatops/slack/commands` | A Slack slash command. |
//! | `POST /chatops/slack/interactions` | A Slack approve button or reject button. |
//! | `POST /chatops/teams/messages` | A message of a Teams outgoing webhook. |
//!
//! The commands are `incidents`, `approvals`, `approve <id> [note]`, `reject <id> [note]`,
//! and `help`.
//!
//! # Security
//!
//! - The server checks the signature of each request with the shared secret, in constant
//!   time. Refer to [`signature`].
//! - The configuration maps each chat user to a principal. An unknown user is refused.
//! - Each command then uses the access rules and the approval path of the REST API.
//! - Message text from an incident is untrusted. Each format escapes it.
//!
//! # Notifications
//!
//! [`Notifier`] subscribes to `aegis.approvals` and `aegis.incidents`. It posts a Slack
//! Block Kit message and a Teams Adaptive Card to the webhook URLs of the configuration.

use std::collections::BTreeMap;

use aegis_contracts::policy::Principal;
use aegis_contracts::{Error, Result};
use axum::Router;
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use secrecy::{SecretSlice, SecretString};
use url::Url;

use crate::auth::Authenticator;
use crate::config::ChatOpsConfig;
use crate::routes::Ctx;
use crate::state::EnvLookup;

mod commands;
mod http;
mod notify;
pub mod signature;
pub mod slack;
pub mod teams;
pub(crate) mod view;

pub use notify::{Notifier, SubscribedNotifier};

use http::Outbound;
use slack::SlackRuntime;
use teams::TeamsRuntime;

/// The path of the Slack slash command endpoint.
pub const SLACK_COMMANDS_PATH: &str = "/chatops/slack/commands";
/// The path of the Slack interaction endpoint.
pub const SLACK_INTERACTIONS_PATH: &str = "/chatops/slack/interactions";
/// The path of the Teams outgoing webhook endpoint.
pub const TEAMS_MESSAGES_PATH: &str = "/chatops/teams/messages";

/// The minimum length of a ChatOps shared secret, in bytes.
pub const MIN_SECRET_BYTES: usize = 16;

/// The ChatOps secrets, users, and webhook URLs, after the server read the environment.
#[derive(Default)]
pub(crate) struct ChatOps {
    /// The Slack endpoints. `None` means that the server has no Slack endpoints.
    pub slack: Option<SlackRuntime>,
    /// The Teams endpoint. `None` means that the server has no Teams endpoint.
    pub teams: Option<TeamsRuntime>,
    /// The URL of the Slack incoming webhook for notifications.
    pub slack_webhook: Option<Url>,
    /// The URL of the Teams webhook for notifications.
    pub teams_webhook: Option<Url>,
}

/// Reads a secret from the environment variable `variable`.
fn secret(env: &EnvLookup, variable: &str, key: &str) -> Result<String> {
    env(variable)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::Config(format!(
                "api.chatops.{key}: the environment variable {variable} is not set"
            ))
        })
}

fn too_short(key: &str, variable: &str) -> Error {
    Error::Config(format!(
        "api.chatops.{key}: the secret in {variable} must have {MIN_SECRET_BYTES} bytes or more"
    ))
}

/// Maps each chat user to its principal. The configuration check made sure that each
/// principal exists.
fn users(
    key: &str,
    users: &BTreeMap<String, String>,
    auth: &Authenticator,
) -> Result<BTreeMap<String, Principal>> {
    users
        .iter()
        .map(|(user, principal)| {
            auth.principal(principal)
                .cloned()
                .map(|principal| (user.clone(), principal))
                .ok_or_else(|| {
                    Error::Config(format!(
                        "api.chatops.{key}.users: a user maps to a principal that \
                         api.principals does not have"
                    ))
                })
        })
        .collect()
}

fn webhook(env: &EnvLookup, variable: Option<&String>, key: &str) -> Result<Option<Url>> {
    variable
        .map(|variable| http::webhook_url(&secret(env, variable, key)?, variable))
        .transpose()
}

impl ChatOps {
    /// Reads each ChatOps secret through `env`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a secret is missing, too short, or not in the
    /// necessary form. The message names the variable. It never shows a secret.
    pub(crate) fn from_config(
        config: &ChatOpsConfig,
        auth: &Authenticator,
        env: &EnvLookup,
    ) -> Result<Self> {
        let mut chat = Self::default();
        if let Some(slack) = &config.slack {
            if let Some(variable) = &slack.signing_secret_env {
                let key = "slack.signing_secret_env";
                let signing_secret = secret(env, variable, key)?;
                if signing_secret.len() < MIN_SECRET_BYTES {
                    return Err(too_short(key, variable));
                }
                chat.slack = Some(SlackRuntime {
                    signing_secret: SecretString::from(signing_secret),
                    team_id: slack.team_id.clone(),
                    users: users("slack", &slack.users, auth)?,
                    response_hosts: slack.response_hosts.clone(),
                    outbound: Outbound::new(slack::RESPONSE_TIMEOUT)?,
                });
            }
            chat.slack_webhook =
                webhook(env, slack.webhook_url_env.as_ref(), "slack.webhook_url_env")?;
        }
        if let Some(teams) = &config.teams {
            if let Some(variable) = &teams.shared_secret_env {
                let key = "teams.shared_secret_env";
                let decoded = STANDARD.decode(secret(env, variable, key)?).map_err(|_| {
                    Error::Config(format!(
                        "api.chatops.{key}: the secret in {variable} must be base64 text"
                    ))
                })?;
                if decoded.len() < MIN_SECRET_BYTES {
                    return Err(too_short(key, variable));
                }
                chat.teams = Some(TeamsRuntime {
                    secret: SecretSlice::from(decoded),
                    users: users("teams", &teams.users, auth)?,
                    require_timestamp: teams.require_timestamp,
                });
            }
            chat.teams_webhook =
                webhook(env, teams.webhook_url_env.as_ref(), "teams.webhook_url_env")?;
        }
        Ok(chat)
    }
}

/// Builds the router of the ChatOps endpoints. A part with no secret has no route.
pub(crate) fn chatops_router(ctx: &Ctx) -> Router<Ctx> {
    let mut router = Router::new();
    if ctx.chat.slack.is_some() {
        router = router
            .route(SLACK_COMMANDS_PATH, post(slack::command))
            .route(SLACK_INTERACTIONS_PATH, post(slack::interaction));
    }
    if ctx.chat.teams.is_some() {
        router = router.route(TEAMS_MESSAGES_PATH, post(teams::message));
    }
    router
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::config::{PrincipalConfig, SlackConfig, TeamsConfig};

    use super::*;

    const SLACK_SECRET: &str = "slack-signing-secret-0123456789ab";

    fn env() -> EnvLookup {
        Arc::new(|name: &str| match name {
            "SLACK_SECRET" => Some(SLACK_SECRET.to_owned()),
            "SHORT_SECRET" => Some("short".to_owned()),
            "TEAMS_SECRET" => Some(STANDARD.encode([7_u8; 32])),
            "TEAMS_SHORT" => Some(STANDARD.encode([7_u8; 8])),
            "NOT_BASE64" => Some("not base64 at all !!!".to_owned()),
            "HOOK" => Some("https://hooks.slack.com/services/T0/B0/secret-part".to_owned()),
            "PLAIN_HOOK" => Some("http://example.com/secret-part".to_owned()),
            _ => None,
        })
    }

    fn auth() -> Authenticator {
        let principals = [PrincipalConfig {
            id: "alice".to_owned(),
            kind: aegis_contracts::policy::PrincipalKind::Human,
            roles: vec!["approver".to_owned()],
            token_env: None,
        }];
        Authenticator::from_config(&principals, &env()).unwrap()
    }

    fn config_error(config: &ChatOpsConfig) -> String {
        match ChatOps::from_config(config, &auth(), &env()) {
            Err(Error::Config(message)) => message,
            Err(other) => panic!("expected a configuration error, found {other:?}"),
            Ok(_) => panic!("expected a configuration error"),
        }
    }

    fn slack(change: impl FnOnce(&mut SlackConfig)) -> ChatOpsConfig {
        let mut slack = SlackConfig::default();
        change(&mut slack);
        ChatOpsConfig {
            slack: Some(slack),
            ..ChatOpsConfig::default()
        }
    }

    fn teams(change: impl FnOnce(&mut TeamsConfig)) -> ChatOpsConfig {
        let mut teams = TeamsConfig::default();
        change(&mut teams);
        ChatOpsConfig {
            teams: Some(teams),
            ..ChatOpsConfig::default()
        }
    }

    #[test]
    fn the_default_configuration_has_no_chat_part() {
        let chat = ChatOps::from_config(&ChatOpsConfig::default(), &auth(), &env()).unwrap();
        assert!(chat.slack.is_none());
        assert!(chat.teams.is_none());
        assert!(chat.slack_webhook.is_none());
        assert!(chat.teams_webhook.is_none());
    }

    #[test]
    fn a_section_with_no_secret_has_no_endpoint() {
        let config = slack(|slack| slack.webhook_url_env = Some("HOOK".to_owned()));
        let chat = ChatOps::from_config(&config, &auth(), &env()).unwrap();
        assert!(chat.slack.is_none());
        assert_eq!(
            chat.slack_webhook
                .map(|url| url.host_str().map(str::to_owned)),
            Some(Some("hooks.slack.com".to_owned()))
        );
    }

    #[test]
    fn the_secrets_and_the_users_come_from_the_environment_and_the_principals() {
        let config = ChatOpsConfig {
            slack: Some(SlackConfig {
                signing_secret_env: Some("SLACK_SECRET".to_owned()),
                users: BTreeMap::from([("U1".to_owned(), "alice".to_owned())]),
                ..SlackConfig::default()
            }),
            teams: Some(TeamsConfig {
                shared_secret_env: Some("TEAMS_SECRET".to_owned()),
                users: BTreeMap::from([("aad-1".to_owned(), "alice".to_owned())]),
                ..TeamsConfig::default()
            }),
            ..ChatOpsConfig::default()
        };
        let chat = ChatOps::from_config(&config, &auth(), &env()).unwrap();
        let slack = chat.slack.unwrap();
        assert_eq!(slack.users["U1"].id, "alice");
        assert_eq!(slack.users["U1"].roles, ["approver"]);
        let teams = chat.teams.unwrap();
        assert_eq!(teams.users["aad-1"].id, "alice");
        assert!(teams.require_timestamp);
    }

    #[test]
    fn a_secret_that_is_not_usable_is_a_configuration_error() {
        assert_eq!(
            config_error(&slack(|s| s.signing_secret_env = Some("MISSING".to_owned()))),
            "api.chatops.slack.signing_secret_env: the environment variable MISSING is not set"
        );
        assert_eq!(
            config_error(&slack(
                |s| s.signing_secret_env = Some("SHORT_SECRET".to_owned())
            )),
            "api.chatops.slack.signing_secret_env: the secret in SHORT_SECRET must have 16 bytes \
             or more"
        );
        assert_eq!(
            config_error(&teams(
                |t| t.shared_secret_env = Some("NOT_BASE64".to_owned())
            )),
            "api.chatops.teams.shared_secret_env: the secret in NOT_BASE64 must be base64 text"
        );
        assert_eq!(
            config_error(&teams(
                |t| t.shared_secret_env = Some("TEAMS_SHORT".to_owned())
            )),
            "api.chatops.teams.shared_secret_env: the secret in TEAMS_SHORT must have 16 bytes \
             or more"
        );
        let message = config_error(&teams(|t| {
            t.webhook_url_env = Some("PLAIN_HOOK".to_owned())
        }));
        assert!(message.starts_with("the webhook URL in the environment variable PLAIN_HOOK"));
        assert!(!message.contains("secret-part"));
    }

    #[test]
    fn a_user_of_an_unknown_principal_is_a_configuration_error() {
        let config = slack(|slack| {
            slack.signing_secret_env = Some("SLACK_SECRET".to_owned());
            slack.users = BTreeMap::from([("U1".to_owned(), "bob".to_owned())]);
        });
        assert_eq!(
            config_error(&config),
            "api.chatops.slack.users: a user maps to a principal that api.principals does not have"
        );
    }
}
