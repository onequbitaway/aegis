//! The configuration of the API.
//!
//! [`ApiConfig`] implements [`serde::Deserialize`], so a program can read it from one table
//! of the AEGIS configuration file, for example `[api]`. Each table rejects a key that it
//! does not know.
//!
//! The configuration holds no secret. It holds the names of the environment variables that
//! hold the secrets. Refer to [`ApiState::with_env`](crate::ApiState::with_env).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use aegis_contracts::common::Severity;
use aegis_contracts::policy::PrincipalKind;
use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

/// The default port of the API.
pub const DEFAULT_PORT: u16 = 8080;

/// The largest value of [`LimitsConfig::max_page_size`].
pub const PAGE_SIZE_LIMIT: usize = 1_000;
/// The largest value of [`LimitsConfig::max_body_bytes`].
pub const BODY_BYTES_LIMIT: usize = 1024 * 1024;
/// The largest value of [`LimitsConfig::request_timeout_seconds`].
pub const REQUEST_TIMEOUT_LIMIT_SECONDS: u64 = 300;
/// The largest value of [`LimitsConfig::max_streams`].
pub const STREAMS_LIMIT: usize = 1_024;

/// The configuration of the API server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    /// The address that the server listens on. The default is `127.0.0.1:8080`.
    pub bind: SocketAddr,
    /// With `false`, [`serve`](crate::serve) refuses an address that is not a loopback
    /// address. The server has no TLS. Set `true` only behind a proxy that adds TLS.
    pub allow_non_loopback: bool,
    /// With `true`, the server also serves the web console at `/`.
    pub console: bool,
    /// The principals that can use the API. With no principals, each protected route
    /// answers 401.
    pub principals: Vec<PrincipalConfig>,
    /// The limits that protect the server.
    pub limits: LimitsConfig,
    /// The ChatOps endpoints and notifications. All parts are off by default.
    pub chatops: ChatOpsConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
            allow_non_loopback: false,
            console: true,
            principals: Vec::new(),
            limits: LimitsConfig::default(),
            chatops: ChatOpsConfig::default(),
        }
    }
}

impl ApiConfig {
    /// Checks the values that do not need the environment.
    ///
    /// [`router`](crate::router) and [`serve`](crate::serve) call this function.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a limit is out of range, a principal is not valid, two
    /// principals have the same identifier, or a ChatOps user names an unknown principal.
    /// The message names the key. It does not show a secret.
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        let mut identifiers = BTreeSet::new();
        for (index, principal) in self.principals.iter().enumerate() {
            principal.validate(index)?;
            if !identifiers.insert(principal.id.as_str()) {
                return Err(Error::Config(format!(
                    "api.principals[{index}]: two principals have the same id"
                )));
            }
        }
        self.chatops.validate(&identifiers)
    }

    /// Checks that the server can listen on [`ApiConfig::bind`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the address is not a loopback address and
    /// [`ApiConfig::allow_non_loopback`] is `false`.
    pub fn validate_bind(&self) -> Result<()> {
        if self.bind.ip().is_loopback() || self.allow_non_loopback {
            return Ok(());
        }
        Err(Error::Config(
            "api.bind is not a loopback address. The server has no TLS. Put a proxy with TLS \
             before the server and set api.allow_non_loopback to true"
                .to_owned(),
        ))
    }
}

/// One principal that can use the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConfig {
    /// The identifier of the principal, for example `alice@example.com`.
    pub id: String,
    /// The type of the principal. The default is a person.
    #[serde(default = "default_kind")]
    pub kind: PrincipalKind,
    /// The roles of the principal. Role-based access control gives the permissions.
    #[serde(default)]
    pub roles: Vec<String>,
    /// The name of the environment variable that holds the bearer token of the principal.
    ///
    /// A principal with no variable cannot use a bearer token. A ChatOps user can still
    /// map to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
}

fn default_kind() -> PrincipalKind {
    PrincipalKind::Human
}

impl PrincipalConfig {
    /// Makes a person with a bearer token in the environment variable `token_env`.
    pub fn human(id: impl Into<String>, roles: &[&str], token_env: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: PrincipalKind::Human,
            roles: roles.iter().map(ToString::to_string).collect(),
            token_env: Some(token_env.into()),
        }
    }

    fn validate(&self, index: usize) -> Result<()> {
        if self.id.trim().is_empty() || self.id.chars().any(char::is_control) {
            return Err(Error::Config(format!(
                "api.principals[{index}].id must be text with no control characters"
            )));
        }
        if let Some(variable) = &self.token_env
            && !is_variable_name(variable)
        {
            // A token in the place of the variable name must not go into the message.
            return Err(Error::Config(format!(
                "api.principals[{index}].token_env must be the name of an environment variable"
            )));
        }
        Ok(())
    }
}

/// The limits that protect the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// The maximum size of a request body, in bytes. The default is 65536.
    pub max_body_bytes: usize,
    /// The maximum time for one request, in seconds. The default is 30. The live feed has
    /// no time limit after it starts.
    pub request_timeout_seconds: u64,
    /// The number of items in a list when the request gives no `limit`. The default is 50.
    pub default_page_size: usize,
    /// The largest `limit` that a request can give. The default is 200.
    pub max_page_size: usize,
    /// The maximum number of live feeds at the same time. The default is 32.
    pub max_streams: usize,
    /// The time between two keep-alive comments on a live feed, in seconds. The default
    /// is 15.
    pub stream_keep_alive_seconds: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            request_timeout_seconds: 30,
            default_page_size: 50,
            max_page_size: 200,
            max_streams: 32,
            stream_keep_alive_seconds: 15,
        }
    }
}

impl LimitsConfig {
    fn validate(&self) -> Result<()> {
        let in_range = |key: &str, value: u64, largest: u64| {
            if (1..=largest).contains(&value) {
                Ok(())
            } else {
                Err(Error::Config(format!(
                    "api.limits.{key} must be from 1 to {largest}"
                )))
            }
        };
        in_range(
            "max_body_bytes",
            self.max_body_bytes as u64,
            BODY_BYTES_LIMIT as u64,
        )?;
        in_range(
            "request_timeout_seconds",
            self.request_timeout_seconds,
            REQUEST_TIMEOUT_LIMIT_SECONDS,
        )?;
        in_range(
            "max_page_size",
            self.max_page_size as u64,
            PAGE_SIZE_LIMIT as u64,
        )?;
        in_range(
            "default_page_size",
            self.default_page_size as u64,
            self.max_page_size as u64,
        )?;
        in_range("max_streams", self.max_streams as u64, STREAMS_LIMIT as u64)?;
        in_range(
            "stream_keep_alive_seconds",
            self.stream_keep_alive_seconds,
            REQUEST_TIMEOUT_LIMIT_SECONDS,
        )
    }

    /// Returns the maximum time for one request.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }
}

/// The ChatOps configuration. Each part is off until the configuration names its secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChatOpsConfig {
    /// The Slack endpoints and the Slack notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack: Option<SlackConfig>,
    /// The Microsoft Teams endpoint and the Teams notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<TeamsConfig>,
    /// The settings of the notification task.
    pub notifications: NotificationConfig,
}

impl ChatOpsConfig {
    fn validate(&self, principals: &BTreeSet<&str>) -> Result<()> {
        if let Some(slack) = &self.slack {
            slack.validate(principals)?;
        }
        if let Some(teams) = &self.teams {
            teams.validate(principals)?;
        }
        self.notifications.validate()
    }
}

fn check_variable(key: &str, variable: Option<&String>) -> Result<()> {
    match variable {
        Some(variable) if !is_variable_name(variable) => Err(Error::Config(format!(
            "api.chatops.{key} must be the name of an environment variable"
        ))),
        _ => Ok(()),
    }
}

fn check_users(
    key: &str,
    users: &BTreeMap<String, String>,
    principals: &BTreeSet<&str>,
) -> Result<()> {
    for (user, principal) in users {
        if user.trim().is_empty() {
            return Err(Error::Config(format!(
                "api.chatops.{key}.users has an empty user identifier"
            )));
        }
        if !principals.contains(principal.as_str()) {
            return Err(Error::Config(format!(
                "api.chatops.{key}.users: a user maps to a principal that api.principals does \
                 not have"
            )));
        }
    }
    Ok(())
}

/// The Slack configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SlackConfig {
    /// The name of the environment variable that holds the signing secret of the Slack
    /// application. With no variable, the server has no Slack endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret_env: Option<String>,
    /// The identifier of the Slack workspace. With a value, the server refuses a request
    /// from a different workspace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// The Slack users that can use the commands. The key is the Slack user identifier,
    /// for example `U012ABCDEF`. The value is the `id` of a principal in
    /// [`ApiConfig::principals`].
    pub users: BTreeMap<String, String>,
    /// The name of the environment variable that holds the URL of the Slack incoming
    /// webhook. With no variable, the notification task sends nothing to Slack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url_env: Option<String>,
    /// The hosts that can receive the answer to a button. Slack gives the URL in each
    /// interaction. The default is `hooks.slack.com`.
    pub response_hosts: Vec<String>,
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            signing_secret_env: None,
            team_id: None,
            users: BTreeMap::new(),
            webhook_url_env: None,
            response_hosts: vec!["hooks.slack.com".to_owned()],
        }
    }
}

impl SlackConfig {
    fn validate(&self, principals: &BTreeSet<&str>) -> Result<()> {
        check_variable("slack.signing_secret_env", self.signing_secret_env.as_ref())?;
        check_variable("slack.webhook_url_env", self.webhook_url_env.as_ref())?;
        check_users("slack", &self.users, principals)
    }
}

/// The Microsoft Teams configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeamsConfig {
    /// The name of the environment variable that holds the security token of the Teams
    /// outgoing webhook, in base64. With no variable, the server has no Teams endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_secret_env: Option<String>,
    /// The Teams users that can use the commands. The key is the Microsoft Entra object
    /// identifier of the sender (`from.aadObjectId`) or the Teams identifier of the sender
    /// (`from.id`). The value is the `id` of a principal in [`ApiConfig::principals`].
    pub users: BTreeMap<String, String>,
    /// The name of the environment variable that holds the URL of the Teams webhook. With
    /// no variable, the notification task sends nothing to Teams.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url_env: Option<String>,
    /// With `true`, the server refuses a message that has no `timestamp`, or a `timestamp`
    /// that is more than five minutes from the present time. The default is `true`.
    pub require_timestamp: bool,
}

impl Default for TeamsConfig {
    fn default() -> Self {
        Self {
            shared_secret_env: None,
            users: BTreeMap::new(),
            webhook_url_env: None,
            require_timestamp: true,
        }
    }
}

impl TeamsConfig {
    fn validate(&self, principals: &BTreeSet<&str>) -> Result<()> {
        check_variable("teams.shared_secret_env", self.shared_secret_env.as_ref())?;
        check_variable("teams.webhook_url_env", self.webhook_url_env.as_ref())?;
        check_users("teams", &self.users, principals)
    }
}

/// The largest value of [`NotificationConfig::max_attempts`].
pub const NOTIFICATION_ATTEMPTS_LIMIT: u32 = 10;
/// The largest value of [`NotificationConfig::request_timeout_seconds`].
pub const NOTIFICATION_TIMEOUT_LIMIT_SECONDS: u64 = 60;
/// The largest value of [`NotificationConfig::retry_backoff_ms`].
pub const NOTIFICATION_BACKOFF_LIMIT_MS: u64 = 60_000;

/// The settings of the notification task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    /// The task sends a message only for an incident with this severity or a larger one.
    /// The default is `medium`. Approval requests are always sent.
    pub min_severity: Severity,
    /// The durable consumer name for the bus subscriptions. With no name, the task gets
    /// only new messages. With a name, the task continues after its last message when the
    /// process starts again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable_consumer: Option<String>,
    /// The maximum time for one webhook request, in seconds. The default is 10.
    pub request_timeout_seconds: u64,
    /// The maximum number of attempts for one message. The default is 3.
    pub max_attempts: u32,
    /// The time before the second attempt, in milliseconds. Each later attempt waits two
    /// times longer. The default is 500.
    pub retry_backoff_ms: u64,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Medium,
            durable_consumer: None,
            request_timeout_seconds: 10,
            max_attempts: 3,
            retry_backoff_ms: 500,
        }
    }
}

impl NotificationConfig {
    fn validate(&self) -> Result<()> {
        let in_range = |key: &str, value: u64, smallest: u64, largest: u64| {
            if (smallest..=largest).contains(&value) {
                Ok(())
            } else {
                Err(Error::Config(format!(
                    "api.chatops.notifications.{key} must be from {smallest} to {largest}"
                )))
            }
        };
        in_range(
            "request_timeout_seconds",
            self.request_timeout_seconds,
            1,
            NOTIFICATION_TIMEOUT_LIMIT_SECONDS,
        )?;
        in_range(
            "max_attempts",
            u64::from(self.max_attempts),
            1,
            u64::from(NOTIFICATION_ATTEMPTS_LIMIT),
        )?;
        in_range(
            "retry_backoff_ms",
            self.retry_backoff_ms,
            0,
            NOTIFICATION_BACKOFF_LIMIT_MS,
        )?;
        if let Some(name) = &self.durable_consumer
            && (name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character)))
        {
            return Err(Error::Config(
                "api.chatops.notifications.durable_consumer must have only ASCII letters, \
                 digits, `-`, and `_`"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Returns `true` if `name` has only the characters of an environment variable name.
pub(crate) fn is_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_error(config: &ApiConfig) -> String {
        match config.validate() {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, found {other:?}"),
        }
    }

    #[test]
    fn the_default_configuration_is_valid_and_listens_on_the_loopback_address() {
        let config = ApiConfig::default();
        assert_eq!(config.bind.to_string(), "127.0.0.1:8080");
        assert!(config.principals.is_empty());
        assert_eq!(config.chatops, ChatOpsConfig::default());
        assert!(config.validate().is_ok());
        assert!(config.validate_bind().is_ok());
    }

    #[test]
    fn an_address_that_is_not_loopback_needs_the_explicit_switch() {
        let mut config = ApiConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..ApiConfig::default()
        };
        assert!(
            matches!(config.validate_bind(), Err(Error::Config(message)) if message.starts_with("api.bind is not a loopback address"))
        );
        config.allow_non_loopback = true;
        assert!(config.validate_bind().is_ok());
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let error = serde_json::from_value::<ApiConfig>(serde_json::json!({ "open": true }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `open`"), "{error}");
    }

    #[test]
    fn a_configuration_gives_only_the_values_that_it_changes() {
        let config: ApiConfig = serde_json::from_value(serde_json::json!({
            "bind": "127.0.0.1:9000",
            "principals": [
                { "id": "alice@example.com", "roles": ["approver"], "token_env": "AEGIS_ALICE" },
                { "id": "ci", "kind": "system", "roles": ["viewer"] }
            ],
            "limits": { "max_page_size": 500 },
            "chatops": { "slack": { "users": { "U1": "alice@example.com" } } }
        }))
        .unwrap();
        assert_eq!(config.bind.port(), 9000);
        assert_eq!(config.principals[0].kind, PrincipalKind::Human);
        assert_eq!(config.principals[1].kind, PrincipalKind::System);
        assert_eq!(config.principals[1].token_env, None);
        assert_eq!(config.limits.max_page_size, 500);
        assert_eq!(config.limits.default_page_size, 50);
        let slack = config.chatops.slack.clone().unwrap();
        assert_eq!(slack.response_hosts, ["hooks.slack.com"]);
        assert_eq!(slack.signing_secret_env, None);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn two_principals_with_one_identifier_are_an_error() {
        let config = ApiConfig {
            principals: vec![
                PrincipalConfig::human("alice", &["a"], "TOKEN_A"),
                PrincipalConfig::human("alice", &["b"], "TOKEN_B"),
            ],
            ..ApiConfig::default()
        };
        assert_eq!(
            config_error(&config),
            "api.principals[1]: two principals have the same id"
        );
    }

    #[test]
    fn a_token_in_the_place_of_the_variable_name_does_not_go_into_the_error() {
        let config = ApiConfig {
            principals: vec![PrincipalConfig::human(
                "alice",
                &["a"],
                "s3cr3t-token-value!",
            )],
            ..ApiConfig::default()
        };
        assert_eq!(
            config_error(&config),
            "api.principals[0].token_env must be the name of an environment variable"
        );
    }

    #[test]
    fn a_chat_user_must_map_to_a_known_principal() {
        let mut config = ApiConfig {
            principals: vec![PrincipalConfig::human("alice", &["a"], "TOKEN_A")],
            ..ApiConfig::default()
        };
        config.chatops.teams = Some(TeamsConfig {
            users: BTreeMap::from([("29:1abc".to_owned(), "bob".to_owned())]),
            ..TeamsConfig::default()
        });
        assert_eq!(
            config_error(&config),
            "api.chatops.teams.users: a user maps to a principal that api.principals does not have"
        );
    }

    #[test]
    fn each_limit_has_a_range() {
        type Change = fn(&mut LimitsConfig);
        let cases: [(Change, &str); 5] = [
            (
                |limits| limits.max_body_bytes = 0,
                "api.limits.max_body_bytes must be from 1 to 1048576",
            ),
            (
                |limits| limits.request_timeout_seconds = 301,
                "api.limits.request_timeout_seconds must be from 1 to 300",
            ),
            (
                |limits| limits.max_page_size = 1_001,
                "api.limits.max_page_size must be from 1 to 1000",
            ),
            (
                |limits| limits.default_page_size = 201,
                "api.limits.default_page_size must be from 1 to 200",
            ),
            (
                |limits| limits.max_streams = 0,
                "api.limits.max_streams must be from 1 to 1024",
            ),
        ];
        for (change, expected) in cases {
            let mut config = ApiConfig::default();
            change(&mut config.limits);
            assert_eq!(config_error(&config), expected);
        }
    }
}
