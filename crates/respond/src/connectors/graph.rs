//! The action connector for Microsoft Entra ID. It uses the Microsoft Graph API.
//!
//! The connector signs in with the OAuth 2.0 client credentials flow. It changes only the
//! tenant in its configuration.
//!
//! | Action | Request | Reversible |
//! | --- | --- | --- |
//! | [`ActionKind::DisableServicePrincipal`] | `PATCH /servicePrincipals/{id}` with `accountEnabled: false` | Yes |
//! | [`ActionKind::DisableUser`] | `PATCH /users/{id}` with `accountEnabled: false` | Yes |
//! | [`ActionKind::KillSession`] | `POST /users/{id}/revokeSignInSessions` | No |
//! | [`ActionKind::RevokeCredential`] | `POST /{collection}/{id}/removePassword` | No |
//! | [`ActionKind::RotateCredential`] | `POST /{collection}/{id}/addPassword`, then `removePassword` | No |
//!
//! `{collection}` is `servicePrincipals` or `applications`. The type of the target selects it.
//!
//! # Application permissions
//!
//! Give the application registration only the permissions for the actions that you use:
//! `Application.ReadWrite.All` for service principals and credentials, and
//! `User.ReadWrite.All` (or `User.EnableDisableAccount.All` and
//! `User.RevokeSessions.All`) for users.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionKind, ActionOutcome, ActionRequest, ActionStatus,
};
use aegis_contracts::common::{ActionId, EntityKind, EntityRef};
use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::{Client, Method};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::Instant;
use url::Url;

use super::http;
use crate::lock;
use crate::names::{entity_label, same_kind, snake_name};

/// The names of the request parameters that this connector reads.
pub mod parameter {
    /// The identifier (`keyId`) of the password credential to remove.
    ///
    /// [`ActionKind::RevokeCredential`](aegis_contracts::ActionKind::RevokeCredential) and
    /// [`ActionKind::RotateCredential`](aegis_contracts::ActionKind::RotateCredential) need it.
    ///
    /// The connector also reads this value from [`CREDENTIAL_ID`], if `key_id` is not set.
    pub const KEY_ID: &str = "key_id";
    /// A second name for [`KEY_ID`]: the shared attribute name
    /// [`attr::CREDENTIAL_ID`](aegis_contracts::event::attr::CREDENTIAL_ID). The Responder
    /// agent copies the credential identifier of a detection to a request with this name.
    pub const CREDENTIAL_ID: &str = aegis_contracts::event::attr::CREDENTIAL_ID;
    /// The display name of the new password credential. This parameter is optional.
    pub const DISPLAY_NAME: &str = "display_name";
}

const VENDOR: &str = "microsoft";
const PRODUCT: &str = "entra_id";
const DEFAULT_NAME: &str = "entra-graph";
const DEFAULT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";
const DEFAULT_LOGIN_BASE_URL: &str = "https://login.microsoftonline.com";
const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/.default";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_TOKEN_SECONDS: u64 = 300;
const TOKEN_MARGIN: Duration = Duration::from_secs(60);
const MAX_ID_LENGTH: usize = 256;
const MAX_NAME_LENGTH: usize = 120;
const BODY_LIMIT: usize = 64 * 1024;
const REDACTED: &str = "[REDACTED]";

fn default_name() -> String {
    DEFAULT_NAME.to_owned()
}

fn default_graph_base_url() -> String {
    DEFAULT_GRAPH_BASE_URL.to_owned()
}

fn default_login_base_url() -> String {
    DEFAULT_LOGIN_BASE_URL.to_owned()
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_owned()
}

fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

/// The configuration of a [`GraphActionConnector`].
///
/// The `Debug` output does not show the client secret.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphConfig {
    /// The name of the connector instance. The default is `entra-graph`.
    #[serde(default = "default_name")]
    pub name: String,
    /// The identifier or the domain name of the tenant that the connector manages.
    pub tenant_id: String,
    /// Other names that the telemetry uses for the same tenant.
    ///
    /// The connector refuses a target that names a tenant that is not in this list and is
    /// not `tenant_id`.
    #[serde(default)]
    pub tenant_aliases: Vec<String>,
    /// The application (client) identifier of the application registration.
    pub client_id: String,
    /// The client secret of the application registration.
    pub client_secret: SecretString,
    /// The base URL of Microsoft Graph. The default is `https://graph.microsoft.com/v1.0`.
    #[serde(default = "default_graph_base_url")]
    pub graph_base_url: String,
    /// The base URL of the sign-in service. The default is
    /// `https://login.microsoftonline.com`.
    #[serde(default = "default_login_base_url")]
    pub login_base_url: String,
    /// The OAuth scope. The default is `https://graph.microsoft.com/.default`.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// The maximum time for one HTTP request, in seconds. The default is 30.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl GraphConfig {
    /// Makes a configuration for the public Microsoft cloud with the default settings.
    pub fn new(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: SecretString,
    ) -> Self {
        Self {
            name: default_name(),
            tenant_id: tenant_id.into(),
            tenant_aliases: Vec::new(),
            client_id: client_id.into(),
            client_secret,
            graph_base_url: default_graph_base_url(),
            login_base_url: default_login_base_url(),
            scope: default_scope(),
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }
}

/// A new secret that a rotation made. A [`SecretSink`] stores it.
///
/// The `Debug` output does not show the secret.
#[derive(Debug, Clone)]
pub struct RotatedSecret {
    /// The application or the service principal that owns the credential.
    pub owner: EntityRef,
    /// The identifier of the new credential.
    pub key_id: String,
    /// The action that made the credential.
    pub action_id: ActionId,
    /// The secret text.
    pub value: SecretString,
}

/// The place where a rotation puts the new secret, for example a vault of the operator.
///
/// The connector never returns a new secret to its caller. The sink is the only receiver.
#[async_trait]
pub trait SecretSink: Send + Sync {
    /// Stores one new secret.
    ///
    /// Returns a reference that tells the operator where the secret is. The reference must
    /// not contain the secret. An error must not contain the secret.
    async fn store(&self, secret: RotatedSecret) -> Result<String>;
}

/// A [`SecretSink`] that keeps the secrets in memory. Use it in tests.
#[derive(Default)]
pub struct MemorySecretSink {
    secrets: Mutex<Vec<RotatedSecret>>,
}

impl MemorySecretSink {
    /// Returns the secrets that the sink received, oldest first.
    #[must_use]
    pub fn stored(&self) -> Vec<RotatedSecret> {
        lock(&self.secrets).clone()
    }
}

#[async_trait]
impl SecretSink for MemorySecretSink {
    async fn store(&self, secret: RotatedSecret) -> Result<String> {
        let reference = format!("memory:{}", secret.key_id);
        lock(&self.secrets).push(secret);
        Ok(reference)
    }
}

/// One HTTP request to Microsoft Graph.
#[derive(Debug, Clone, PartialEq)]
struct Call {
    method: Method,
    segments: Vec<String>,
    body: Option<Value>,
}

impl Call {
    fn new(method: Method, segments: &[&str], body: Option<Value>) -> Self {
        Self {
            method,
            segments: segments.iter().map(ToString::to_string).collect(),
            body,
        }
    }

    fn remove_password(collection: &str, id: &str, key_id: &str) -> Self {
        Self::new(
            Method::POST,
            &[collection, id, "removePassword"],
            Some(json!({ "keyId": key_id })),
        )
    }

    fn path(&self) -> String {
        format!("/{}", self.segments.join("/"))
    }

    fn describe(&self) -> Value {
        json!({
            "method": self.method.as_str(),
            "path": self.path(),
            "body": self.body,
        })
    }
}

/// The change that one action request makes in the tenant.
#[derive(Debug, Clone, PartialEq)]
enum Operation {
    SetAccountEnabled {
        collection: &'static str,
        id: String,
        enabled: bool,
    },
    RevokeSessions {
        user_id: String,
    },
    RemovePassword {
        collection: &'static str,
        id: String,
        key_id: String,
    },
    RotatePassword {
        collection: &'static str,
        id: String,
        old_key_id: String,
        display_name: String,
    },
}

/// Returns the identifier of the target, after a check that it is safe in a URL path.
fn object_id(target: &EntityRef) -> Result<String> {
    let id = target.id.as_str();
    let unsafe_character = |character: char| {
        character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
    };
    if id.is_empty() || id == "." || id == ".." || id.chars().any(unsafe_character) {
        return Err(Error::InvalidInput(
            "the target identifier is empty or has a character that is not permitted".to_owned(),
        ));
    }
    if id.chars().count() > MAX_ID_LENGTH {
        return Err(Error::InvalidInput(format!(
            "the target identifier is longer than {MAX_ID_LENGTH} characters"
        )));
    }
    Ok(id.to_owned())
}

fn require_kind(request: &ActionRequest, permitted: &[EntityKind]) -> Result<()> {
    if permitted.contains(&request.target.kind) {
        return Ok(());
    }
    let names: Vec<String> = permitted.iter().map(snake_name).collect();
    Err(Error::InvalidInput(format!(
        "the action {} needs a target of the type {}, not {}",
        snake_name(&request.kind),
        names.join(" or "),
        snake_name(&request.target.kind)
    )))
}

/// Returns the Graph collection that holds the credentials of the target.
fn credential_collection(request: &ActionRequest) -> Result<&'static str> {
    require_kind(
        request,
        &[EntityKind::ServicePrincipal, EntityKind::Application],
    )?;
    Ok(if request.target.kind == EntityKind::Application {
        "applications"
    } else {
        "servicePrincipals"
    })
}

fn text_parameter(request: &ActionRequest, name: &str) -> Result<Option<String>> {
    match request.parameters.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            let text = text.trim();
            if text.is_empty()
                || text.chars().count() > MAX_NAME_LENGTH
                || text.chars().any(char::is_control)
            {
                return Err(Error::InvalidInput(format!(
                    "the parameter {name} must have 1 to {MAX_NAME_LENGTH} characters and no control characters"
                )));
            }
            Ok(Some(text.to_owned()))
        }
        Some(_) => Err(Error::InvalidInput(format!(
            "the parameter {name} must be a string"
        ))),
    }
}

fn key_id(request: &ActionRequest) -> Result<String> {
    let key_id = match text_parameter(request, parameter::KEY_ID)? {
        Some(key_id) => Some(key_id),
        None => text_parameter(request, parameter::CREDENTIAL_ID)?,
    };
    key_id.ok_or_else(|| {
        Error::InvalidInput(format!(
            "the action {} needs the parameter {}",
            snake_name(&request.kind),
            parameter::KEY_ID
        ))
    })
}

impl Operation {
    /// Reads the request. With `revert`, returns the inverse operation.
    fn plan(request: &ActionRequest, revert: bool) -> Result<Self> {
        let id = object_id(&request.target)?;
        match (&request.kind, revert) {
            (ActionKind::DisableServicePrincipal, _) => {
                require_kind(request, &[EntityKind::ServicePrincipal])?;
                Ok(Self::SetAccountEnabled {
                    collection: "servicePrincipals",
                    id,
                    enabled: revert,
                })
            }
            (ActionKind::DisableUser, _) => {
                require_kind(request, &[EntityKind::User])?;
                Ok(Self::SetAccountEnabled {
                    collection: "users",
                    id,
                    enabled: revert,
                })
            }
            (
                ActionKind::KillSession
                | ActionKind::RevokeCredential
                | ActionKind::RotateCredential,
                true,
            ) => Err(Error::Unsupported(format!(
                "the action {} has no inverse in Microsoft Graph",
                snake_name(&request.kind)
            ))),
            (ActionKind::KillSession, false) => {
                require_kind(request, &[EntityKind::User])?;
                Ok(Self::RevokeSessions { user_id: id })
            }
            (ActionKind::RevokeCredential, false) => Ok(Self::RemovePassword {
                collection: credential_collection(request)?,
                id,
                key_id: key_id(request)?,
            }),
            (ActionKind::RotateCredential, false) => Ok(Self::RotatePassword {
                collection: credential_collection(request)?,
                id,
                old_key_id: key_id(request)?,
                display_name: text_parameter(request, parameter::DISPLAY_NAME)?
                    .unwrap_or_else(|| format!("aegis rotation {}", request.id)),
            }),
            (kind, _) => Err(Error::Unsupported(format!(
                "the Microsoft Graph connector does not support the action {}",
                snake_name(kind)
            ))),
        }
    }

    /// Returns the HTTP requests of the operation, in order.
    fn calls(&self) -> Vec<Call> {
        match self {
            Self::SetAccountEnabled {
                collection,
                id,
                enabled,
            } => vec![Call::new(
                Method::PATCH,
                &[collection, id],
                Some(json!({ "accountEnabled": enabled })),
            )],
            Self::RevokeSessions { user_id } => vec![Call::new(
                Method::POST,
                &["users", user_id, "revokeSignInSessions"],
                None,
            )],
            Self::RemovePassword {
                collection,
                id,
                key_id,
            } => vec![Call::remove_password(collection, id, key_id)],
            Self::RotatePassword {
                collection,
                id,
                old_key_id,
                display_name,
            } => vec![
                Call::new(
                    Method::POST,
                    &[collection, id, "addPassword"],
                    Some(json!({ "passwordCredential": { "displayName": display_name } })),
                ),
                Call::remove_password(collection, id, old_key_id),
            ],
        }
    }

    fn reversible(&self) -> bool {
        matches!(self, Self::SetAccountEnabled { .. })
    }

    /// Returns the words that complete "Would ..." and "Did ...".
    fn verb(&self) -> &'static str {
        match self {
            Self::SetAccountEnabled { enabled: false, .. } => "disable the account of",
            Self::SetAccountEnabled { enabled: true, .. } => "enable the account of",
            Self::RevokeSessions { .. } => "revoke the sign-in sessions of",
            Self::RemovePassword { .. } => "remove one password credential from",
            Self::RotatePassword { .. } => "replace one password credential of",
        }
    }
}

struct CachedToken {
    value: SecretString,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretString,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TokenFailure {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct GraphFailure {
    error: GraphFailureBody,
}

#[derive(Deserialize)]
struct GraphFailureBody {
    #[serde(default)]
    code: Option<String>,
}

#[derive(Deserialize)]
struct AddedPassword {
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "secretText")]
    secret_text: SecretString,
}

/// Replaces each copy of `secret` in `text`.
fn scrub(text: &str, secret: &SecretString) -> String {
    let secret = secret.expose_secret();
    if secret.is_empty() {
        text.to_owned()
    } else {
        text.replace(secret, REDACTED)
    }
}

/// An action connector for one Microsoft Entra ID tenant.
pub struct GraphActionConnector {
    name: String,
    tenants: Vec<String>,
    client: Client,
    graph_base: Url,
    token_url: Url,
    client_id: String,
    client_secret: SecretString,
    scope: String,
    token: tokio::sync::Mutex<Option<CachedToken>>,
    secrets: Arc<dyn SecretSink>,
}

fn join(base: &Url, segments: &[String]) -> Result<Url> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| Error::Config("the base URL cannot hold a path".to_owned()))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

impl GraphActionConnector {
    /// Makes a connector. `secrets` receives the new secret of each credential rotation.
    ///
    /// Returns [`Error::Config`] if a setting is empty or a base URL is not safe. A base URL
    /// must use `https`. Plain `http` is permitted only for a loopback host.
    pub fn new(config: GraphConfig, secrets: Arc<dyn SecretSink>) -> Result<Self> {
        let required = [
            ("name", config.name.trim()),
            ("tenant_id", config.tenant_id.trim()),
            ("client_id", config.client_id.trim()),
            ("scope", config.scope.trim()),
        ];
        if let Some((setting, _)) = required.iter().find(|(_, value)| value.is_empty()) {
            return Err(Error::Config(format!(
                "the Microsoft Graph setting {setting} must not be empty"
            )));
        }
        if config.client_secret.expose_secret().is_empty() {
            return Err(Error::Config(
                "the Microsoft Graph setting client_secret must not be empty".to_owned(),
            ));
        }
        let tenant_id = config.tenant_id.trim();
        let tenant_is_safe = tenant_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
            && tenant_id != "."
            && tenant_id != "..";
        if !tenant_is_safe {
            return Err(Error::Config(
                "the Microsoft Graph setting tenant_id must be a tenant identifier or a domain name"
                    .to_owned(),
            ));
        }
        let graph_base = http::secure_url(&config.graph_base_url, "graph_base_url")?;
        let login_base = http::secure_url(&config.login_base_url, "login_base_url")?;
        let token_segments = [tenant_id, "oauth2", "v2.0", "token"].map(str::to_owned);
        let token_url = join(&login_base, &token_segments)?;
        let mut tenants = vec![tenant_id.to_owned()];
        tenants.extend(
            config
                .tenant_aliases
                .iter()
                .map(|alias| alias.trim().to_owned())
                .filter(|alias| !alias.is_empty()),
        );
        Ok(Self {
            name: config.name.trim().to_owned(),
            tenants,
            client: http::client(Duration::from_secs(config.timeout_seconds))?,
            graph_base,
            token_url,
            client_id: config.client_id.trim().to_owned(),
            client_secret: config.client_secret,
            scope: config.scope.trim().to_owned(),
            token: tokio::sync::Mutex::new(None),
            secrets,
        })
    }

    /// Refuses a target that the telemetry puts in a different tenant.
    fn check_tenant(&self, target: &EntityRef) -> Result<()> {
        let Some(tenant) = target.tenant.as_deref() else {
            return Ok(());
        };
        if self
            .tenants
            .iter()
            .any(|own| own.eq_ignore_ascii_case(tenant))
        {
            return Ok(());
        }
        Err(Error::InvalidInput(format!(
            "the target {} is in the tenant {tenant}; connector {} manages the tenant {} only",
            entity_label(target),
            self.name,
            self.tenants.first().map_or("", String::as_str)
        )))
    }

    /// Returns an access token. Gets a new token if the cache has none that is valid.
    async fn access_token(&self, refresh: bool) -> Result<SecretString> {
        let mut cached = self.token.lock().await;
        if !refresh
            && let Some(token) = cached.as_ref()
            && token.expires_at > Instant::now() + TOKEN_MARGIN
        {
            return Ok(token.value.clone());
        }
        *cached = None;
        let what = "Microsoft Entra ID token request";
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret()),
            ("scope", self.scope.as_str()),
        ];
        let response = self
            .client
            .post(self.token_url.clone())
            .form(&form)
            .send()
            .await
            .map_err(|error| http::transport_error(error, what))?;
        let status = response.status();
        let body = http::read_limited(response, BODY_LIMIT, what).await?;
        if !status.is_success() {
            let code = serde_json::from_slice::<TokenFailure>(&body)
                .ok()
                .and_then(|failure| failure.error)
                .and_then(|code| http::safe_code(&code));
            return Err(match (status.as_u16(), code.as_deref()) {
                (400, Some("invalid_client" | "unauthorized_client")) => Error::Unauthorized(
                    format!("{what}: HTTP 400 ({})", code.as_deref().unwrap_or_default()),
                ),
                (400, _) => Error::Config(format!(
                    "{what}: HTTP 400 ({}); examine tenant_id, client_id, and scope",
                    code.as_deref().unwrap_or("no error code")
                )),
                _ => http::status_error(status, what, code.as_deref()),
            });
        }
        let token: TokenResponse = serde_json::from_slice(&body).map_err(|_| {
            Error::Serialization(format!(
                "{what}: the response is not a valid token document"
            ))
        })?;
        if token.access_token.expose_secret().is_empty() {
            return Err(Error::Unauthorized(format!(
                "{what}: the response has an empty access token"
            )));
        }
        let lifetime = Duration::from_secs(token.expires_in.unwrap_or(DEFAULT_TOKEN_SECONDS));
        *cached = Some(CachedToken {
            value: token.access_token.clone(),
            expires_at: Instant::now() + lifetime,
        });
        Ok(token.access_token)
    }

    /// Sends one request to Microsoft Graph and returns the response body.
    ///
    /// If Graph answers 401, the connector gets a new token and sends the request one more
    /// time.
    async fn send(&self, call: &Call) -> Result<Vec<u8>> {
        let what = format!("Microsoft Graph {} {}", call.method, call.path());
        let url = join(&self.graph_base, &call.segments)?;
        let mut refresh = false;
        loop {
            let token = self.access_token(refresh).await?;
            let mut builder = self
                .client
                .request(call.method.clone(), url.clone())
                .bearer_auth(token.expose_secret());
            if let Some(body) = &call.body {
                builder = builder.json(body);
            }
            let response = builder
                .send()
                .await
                .map_err(|error| http::transport_error(error, &what))?;
            let status = response.status();
            if status.as_u16() == 401 && !refresh {
                refresh = true;
                continue;
            }
            let body = http::read_limited(response, BODY_LIMIT, &what).await?;
            if status.is_success() {
                return Ok(body);
            }
            let code = serde_json::from_slice::<GraphFailure>(&body)
                .ok()
                .and_then(|failure| failure.error.code)
                .and_then(|code| http::safe_code(&code));
            return Err(http::status_error(status, &what, code.as_deref()));
        }
    }

    fn outcome(
        &self,
        request: &ActionRequest,
        status: ActionStatus,
        message: String,
        details: Value,
        reversible: bool,
    ) -> ActionOutcome {
        ActionOutcome {
            action_id: request.id,
            status,
            connector: self.name.clone(),
            message,
            details,
            reversible,
            completed_at: Utc::now(),
        }
    }

    /// Adds a new password credential, stores its secret in the sink, then removes the old
    /// credential.
    ///
    /// If the sink fails, the connector removes the new credential again. A credential with
    /// a secret that nobody has must not stay in the tenant.
    async fn rotate(
        &self,
        request: &ActionRequest,
        calls: &[Call],
        old_key_id: &str,
    ) -> Result<Value> {
        let [add, remove] = calls else {
            return Err(Error::InvalidInput(
                "a credential rotation has two requests".to_owned(),
            ));
        };
        let label = entity_label(&request.target);
        let body = self.send(add).await?;
        let added: AddedPassword = serde_json::from_slice(&body).map_err(|_| {
            Error::Serialization(format!(
                "Microsoft Graph returned a password credential for {label} that is not valid"
            ))
        })?;
        let secret = added.secret_text;
        let new_key_id = scrub(&added.key_id, &secret);
        let stored = self
            .secrets
            .store(RotatedSecret {
                owner: request.target.clone(),
                key_id: added.key_id.clone(),
                action_id: request.id,
                value: secret.clone(),
            })
            .await;
        let reference = match stored {
            Ok(reference) => scrub(&reference, &secret),
            Err(error) => {
                let cause = scrub(&error.to_string(), &secret);
                let undo = Call::remove_password(
                    add.segments.first().map_or("", String::as_str),
                    &request.target.id,
                    &added.key_id,
                );
                return Err(match self.send(&undo).await {
                    Ok(_) => same_kind(
                        &error,
                        format!(
                            "the secret sink did not store the new credential of {label}, so the connector removed the new credential {new_key_id} again; nothing changed: {cause}"
                        ),
                    ),
                    Err(undo_error) => Error::Integrity(format!(
                        "the secret sink did not store the new credential of {label} ({cause}) and the connector could not remove the new credential {new_key_id} ({undo_error}); remove this credential by hand"
                    )),
                });
            }
        };
        if let Err(error) = self.send(remove).await {
            return Err(same_kind(
                &error,
                format!(
                    "the new credential {new_key_id} of {label} is active and its secret is in the secret sink ({reference}), but the old credential was not removed: {error}"
                ),
            ));
        }
        Ok(json!({
            "new_key_id": new_key_id,
            "removed_key_id": old_key_id,
            "secret_reference": reference,
        }))
    }

    async fn run(&self, request: &ActionRequest, revert: bool) -> Result<ActionOutcome> {
        self.check_tenant(&request.target)?;
        let operation = Operation::plan(request, revert)?;
        let calls = operation.calls();
        let label = entity_label(&request.target);
        let planned: Vec<Value> = calls.iter().map(Call::describe).collect();
        if request.dry_run {
            return Ok(self.outcome(
                request,
                ActionStatus::Simulated,
                format!(
                    "Would {} {label}. This was a dry run. Nothing changed.",
                    operation.verb()
                ),
                json!({ "planned_requests": planned }),
                operation.reversible(),
            ));
        }
        let rotation = if let Operation::RotatePassword { old_key_id, .. } = &operation {
            self.rotate(request, &calls, old_key_id).await?
        } else {
            for call in &calls {
                self.send(call).await?;
            }
            Value::Null
        };
        Ok(self.outcome(
            request,
            ActionStatus::Succeeded,
            format!("Did {} {label}.", operation.verb()),
            json!({ "requests": planned, "rotation": rotation }),
            operation.reversible(),
        ))
    }
}

#[async_trait]
impl ActionConnector for GraphActionConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: VENDOR.to_owned(),
            product: PRODUCT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn supported_actions(&self) -> Vec<ActionKind> {
        vec![
            ActionKind::DisableServicePrincipal,
            ActionKind::DisableUser,
            ActionKind::KillSession,
            ActionKind::RevokeCredential,
            ActionKind::RotateCredential,
        ]
    }

    async fn execute(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.run(request, false).await
    }

    /// Enables an account that [`execute`](Self::execute) disabled.
    ///
    /// Only [`ActionKind::DisableServicePrincipal`] and [`ActionKind::DisableUser`] have an
    /// inverse. All other actions return [`Error::Unsupported`].
    async fn revert(&self, request: &ActionRequest) -> Result<ActionOutcome> {
        self.run(request, true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: ActionKind, target: EntityRef) -> ActionRequest {
        ActionRequest::new(kind, target, "responder", "Test.")
    }

    fn principal(id: &str) -> EntityRef {
        EntityRef::new(EntityKind::ServicePrincipal, id)
    }

    #[test]
    fn disable_and_its_inverse_are_one_patch_request() {
        let disable = request(ActionKind::DisableServicePrincipal, principal("sp-1"));
        let operation = Operation::plan(&disable, false).unwrap();
        assert!(operation.reversible());
        assert_eq!(
            operation.calls(),
            [Call::new(
                Method::PATCH,
                &["servicePrincipals", "sp-1"],
                Some(json!({ "accountEnabled": false }))
            )]
        );
        let inverse = Operation::plan(&disable, true).unwrap();
        assert_eq!(
            inverse.calls(),
            [Call::new(
                Method::PATCH,
                &["servicePrincipals", "sp-1"],
                Some(json!({ "accountEnabled": true }))
            )]
        );
    }

    #[test]
    fn the_target_type_selects_the_credential_collection() {
        let mut on_application = request(
            ActionKind::RevokeCredential,
            EntityRef::new(EntityKind::Application, "app-1"),
        );
        on_application
            .parameters
            .insert(parameter::KEY_ID.to_owned(), json!("key-1"));
        let operation = Operation::plan(&on_application, false).unwrap();
        assert!(!operation.reversible());
        assert_eq!(
            operation.calls(),
            [Call::new(
                Method::POST,
                &["applications", "app-1", "removePassword"],
                Some(json!({ "keyId": "key-1" }))
            )]
        );

        let mut on_user = request(
            ActionKind::RevokeCredential,
            EntityRef::new(EntityKind::User, "user-1"),
        );
        on_user
            .parameters
            .insert(parameter::KEY_ID.to_owned(), json!("key-1"));
        let error = Operation::plan(&on_user, false).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("service_principal or application")),
            "{error:?}"
        );
    }

    #[test]
    fn a_target_identifier_that_can_change_the_path_is_rejected() {
        for id in [
            "",
            ".",
            "..",
            "sp-1/../../users/admin",
            "sp 1",
            "sp\n1",
            "a\\b",
        ] {
            let error = Operation::plan(
                &request(ActionKind::DisableServicePrincipal, principal(id)),
                false,
            )
            .unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message) if message.contains("target identifier")),
                "{id:?}: {error:?}"
            );
        }
        let long = "a".repeat(MAX_ID_LENGTH + 1);
        let error = Operation::plan(
            &request(ActionKind::DisableServicePrincipal, principal(&long)),
            false,
        )
        .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("longer than")),
            "{error:?}"
        );
    }

    #[test]
    fn a_path_segment_is_percent_encoded() {
        let base = Url::parse("https://graph.example.com/v1.0").unwrap();
        let url = join(
            &base,
            &[
                "users".to_owned(),
                "dana_fabrikam.example#EXT#@contoso.example?x=1".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://graph.example.com/v1.0/users/dana_fabrikam.example%23EXT%23@contoso.example%3Fx=1"
        );
        let slash = Url::parse("https://graph.example.com/v1.0/").unwrap();
        assert_eq!(
            join(&slash, &["users".to_owned()]).unwrap().as_str(),
            "https://graph.example.com/v1.0/users"
        );
    }

    #[test]
    fn scrub_removes_each_copy_of_the_secret() {
        let secret = SecretString::from("s3cr3t-value");
        assert_eq!(
            scrub("failed to write s3cr3t-value (s3cr3t-value)", &secret),
            "failed to write [REDACTED] ([REDACTED])"
        );
        assert_eq!(scrub("no secret here", &secret), "no secret here");
        assert_eq!(scrub("text", &SecretString::from("")), "text");
    }

    #[test]
    fn the_debug_output_of_the_configuration_hides_the_secret() {
        let config = GraphConfig::new("tenant", "client", SecretString::from("s3cr3t-value"));
        let text = format!("{config:?}");
        assert!(text.contains("tenant"), "{text}");
        assert!(!text.contains("s3cr3t-value"), "{text}");
    }
}
