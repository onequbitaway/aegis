//! The normalized event that all source connectors emit.
//!
//! The event is a small subset of the Open Cybersecurity Schema Framework (OCSF). Each
//! source connector converts vendor records to this type. Detection then operates on one
//! schema and does not know the vendor.
//!
//! The [`action`] and [`attr`] modules hold the shared vocabulary. Source connectors write
//! these names. Detectors read them.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{EntityKind, EntityRef, EventId, Severity};

/// Normalized values for [`Event::action`].
///
/// A connector can emit an action that is not in this list. Use lower case, with `.` between
/// the object and the verb.
pub mod action {
    /// An interactive or non-interactive sign-in.
    pub const SIGN_IN: &str = "sign_in";
    /// The end of a session.
    pub const SIGN_OUT: &str = "sign_out";
    /// A user or an administrator consents to permissions for an application.
    pub const OAUTH_CONSENT_GRANT: &str = "oauth.consent_grant";
    /// A new application registration.
    pub const APP_CREATE: &str = "app.create";
    /// A new secret or certificate on an application or a service principal.
    pub const APP_CREDENTIAL_ADD: &str = "app.credential_add";
    /// The removal of a secret or certificate from an application or a service principal.
    pub const APP_CREDENTIAL_REMOVE: &str = "app.credential_remove";
    /// A grant of an application permission (an app role) to a service principal.
    pub const APP_PERMISSION_GRANT: &str = "app.permission_grant";
    /// A new service principal.
    pub const SERVICE_PRINCIPAL_CREATE: &str = "service_principal.create";
    /// A change that disables a service principal.
    pub const SERVICE_PRINCIPAL_DISABLE: &str = "service_principal.disable";
    /// The assignment of a directory role to a principal.
    pub const ROLE_ASSIGN: &str = "role.assign";
    /// The removal of a directory role from a principal.
    pub const ROLE_REMOVE: &str = "role.remove";
    /// A new user account.
    pub const USER_CREATE: &str = "user.create";
    /// A change to a user account.
    pub const USER_UPDATE: &str = "user.update";
    /// A password reset or a password change.
    pub const USER_PASSWORD_RESET: &str = "user.password_reset";
    /// A change to a multi-factor authentication method.
    pub const MFA_METHOD_CHANGE: &str = "mfa.method_change";
    /// A call to a cloud control-plane or data-plane API.
    pub const API_CALL: &str = "api.call";
    /// A read of a secret from a vault.
    pub const SECRET_READ: &str = "secret.read";
    /// A network connection.
    pub const NETWORK_CONNECT: &str = "network.connect";
    /// The start of a process.
    pub const PROCESS_START: &str = "process.start";
    /// A read or a use of a honeytoken or a canary.
    pub const HONEYTOKEN_TRIP: &str = "honeytoken.trip";
    /// A client connected to a decoy service or sent a request to it.
    pub const DECOY_CONTACT: &str = "decoy.contact";
    /// A client followed a hidden instruction that only an automated agent reads.
    pub const DECOY_CANARY_HIT: &str = "decoy.canary_hit";
    /// A request to a web or API endpoint of the operator.
    pub const HTTP_REQUEST: &str = "http.request";
}

/// Normalized keys for [`Event::attributes`].
///
/// A connector can add keys that are not in this list. Use lower case with `_` between words.
pub mod attr {
    /// The application (client) identifier that the event refers to.
    pub const APP_ID: &str = "app_id";
    /// The display name of the application.
    pub const APP_NAME: &str = "app_name";
    /// The identifier of the directory role or the application permission.
    pub const ROLE_ID: &str = "role_id";
    /// The display name of the directory role or the application permission.
    pub const ROLE_NAME: &str = "role_name";
    /// `true` if the role or the permission gives privileged access.
    pub const PRIVILEGED: &str = "privileged";
    /// The type of a credential, for example `password` or `certificate`.
    pub const CREDENTIAL_TYPE: &str = "credential_type";
    /// The identifier of a credential.
    pub const CREDENTIAL_ID: &str = "credential_id";
    /// The permission scopes in a grant, as an array of strings.
    pub const SCOPES: &str = "scopes";
    /// The tenant that owns the resource that the actor accessed.
    pub const RESOURCE_TENANT: &str = "resource_tenant";
    /// The home tenant of the actor.
    pub const HOME_TENANT: &str = "home_tenant";
    /// The ISO 3166-1 alpha-2 country code of the actor.
    pub const COUNTRY: &str = "country";
    /// The city of the actor.
    pub const CITY: &str = "city";
    /// The latitude of the actor in degrees.
    pub const LATITUDE: &str = "latitude";
    /// The longitude of the actor in degrees.
    pub const LONGITUDE: &str = "longitude";
    /// The reason that the source system gives for a failure.
    pub const FAILURE_REASON: &str = "failure_reason";
    /// The error code that the source system gives for a failure.
    pub const ERROR_CODE: &str = "error_code";
    /// The authentication protocol or the client application type.
    pub const AUTH_PROTOCOL: &str = "auth_protocol";
    /// `true` if the sign-in satisfied multi-factor authentication.
    pub const MFA_SATISFIED: &str = "mfa_satisfied";
    /// The name of the API operation.
    pub const OPERATION: &str = "operation";
    /// The destination IP address of a network connection.
    pub const DESTINATION_IP: &str = "destination_ip";
    /// The destination port of a network connection.
    pub const DESTINATION_PORT: &str = "destination_port";
    /// The destination DNS name of a network connection.
    pub const DESTINATION_DOMAIN: &str = "destination_domain";
    /// The identifier of a honeytoken.
    pub const HONEYTOKEN_ID: &str = "honeytoken_id";
    /// The identifier of a decoy service.
    pub const DECOY_ID: &str = "decoy_id";
    /// The type of a decoy service, for example `tarpit`, `maze`, or `model_api`.
    pub const DECOY_KIND: &str = "decoy_kind";
    /// The identifier of a canary instruction.
    pub const CANARY_ID: &str = "canary_id";
    /// A stable fingerprint of a client, made from its headers and its behavior.
    pub const CLIENT_FINGERPRINT: &str = "client_fingerprint";
    /// The method of an HTTP request.
    pub const HTTP_METHOD: &str = "http_method";
    /// The path of an HTTP request, without the query.
    pub const HTTP_PATH: &str = "http_path";
    /// The status code of an HTTP response, as a number.
    pub const HTTP_STATUS: &str = "http_status";
    /// The time that a decoy held a client, in milliseconds.
    pub const HELD_MILLISECONDS: &str = "held_milliseconds";
    /// The number of bytes that a client sent.
    pub const BYTES_RECEIVED: &str = "bytes_received";
}

/// The class of activity that an event describes. The names follow OCSF classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    /// A sign-in, a sign-out, or a token operation.
    Authentication,
    /// A change to an account or its credentials.
    AccountChange,
    /// A change to roles, permissions, or consent.
    UserAccessManagement,
    /// The creation, change, or removal of a managed entity, for example an application.
    EntityManagement,
    /// A call to a cloud or service API.
    ApiActivity,
    /// A network connection or a network flow.
    NetworkActivity,
    /// Activity of a process on a host.
    ProcessActivity,
    /// Activity on a file.
    FileActivity,
    /// An alert that a vendor product made.
    DetectionFinding,
    /// Activity that has no more specific variant.
    Other,
}

/// The result of the activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The activity completed.
    Success,
    /// The activity failed or the source system blocked it.
    Failure,
    /// The source system gives no result.
    #[default]
    Unknown,
}

/// The connector and the product that supplied an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventSource {
    /// The name of the connector instance, for example `entra-prod`.
    pub connector: String,
    /// The vendor of the product, for example `microsoft`.
    pub vendor: String,
    /// The product, for example `entra_id`.
    pub product: String,
    /// The tenant or the account that the connector reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

impl EventSource {
    /// Makes a source with no tenant.
    pub fn new(
        connector: impl Into<String>,
        vendor: impl Into<String>,
        product: impl Into<String>,
    ) -> Self {
        Self {
            connector: connector.into(),
            vendor: vendor.into(),
            product: product.into(),
            tenant: None,
        }
    }

    /// Sets the tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }
}

/// The principal that did the activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The type of the principal.
    pub kind: EntityKind,
    /// The identifier that the source system gives to the principal.
    pub id: String,
    /// The display name or the user principal name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The home tenant of the principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The IP address that the activity came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// The user agent of the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// The identifier of the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl Actor {
    /// Makes an actor that has only a type and an identifier.
    pub fn new(kind: EntityKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            name: None,
            tenant: None,
            ip: None,
            user_agent: None,
            session_id: None,
        }
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the home tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Sets the session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Returns a reference to the actor as an entity.
    #[must_use]
    pub fn entity(&self) -> EntityRef {
        EntityRef {
            kind: self.kind,
            id: self.id.clone(),
            name: self.name.clone(),
            tenant: self.tenant.clone(),
        }
    }
}

/// One normalized record of activity in the environment of the operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The identifier that AEGIS gives to the event.
    pub id: EventId,
    /// The time at which the activity occurred.
    pub time: DateTime<Utc>,
    /// The connector and the product that supplied the event.
    pub source: EventSource,
    /// The class of the activity.
    pub class: EventClass,
    /// The normalized name of the activity. Refer to the [`action`] module.
    pub action: String,
    /// The result of the activity.
    #[serde(default)]
    pub outcome: Outcome,
    /// The severity that the source system or the connector gives to the event.
    #[serde(default)]
    pub severity: Severity,
    /// The principal that did the activity.
    pub actor: Actor,
    /// The entity that the activity changed or accessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EntityRef>,
    /// More normalized data. Refer to the [`attr`] module for the shared keys.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// The original record from the source system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl Event {
    /// Makes an event with a new identifier, the default outcome, and the default severity.
    pub fn new(
        time: DateTime<Utc>,
        source: EventSource,
        class: EventClass,
        action: impl Into<String>,
        actor: Actor,
    ) -> Self {
        Self {
            id: EventId::new(),
            time,
            source,
            class,
            action: action.into(),
            outcome: Outcome::default(),
            severity: Severity::default(),
            actor,
            target: None,
            attributes: BTreeMap::new(),
            raw: None,
        }
    }

    /// Sets the identifier. Use this for data that must be the same in each run.
    #[must_use]
    pub fn with_id(mut self, id: EventId) -> Self {
        self.id = id;
        self
    }

    /// Sets the outcome.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Sets the severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the target.
    #[must_use]
    pub fn with_target(mut self, target: EntityRef) -> Self {
        self.target = Some(target);
        self
    }

    /// Adds one attribute.
    #[must_use]
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Sets the original record.
    #[must_use]
    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = Some(raw);
        self
    }

    /// Returns the attribute `key` as a string, if it is a string.
    #[must_use]
    pub fn attribute_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(serde_json::Value::as_str)
    }

    /// Returns the attribute `key` as a boolean, if it is a boolean.
    #[must_use]
    pub fn attribute_bool(&self, key: &str) -> Option<bool> {
        self.attributes
            .get(key)
            .and_then(serde_json::Value::as_bool)
    }
}
