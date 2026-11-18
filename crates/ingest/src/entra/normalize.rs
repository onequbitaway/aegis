//! Pure functions that convert Microsoft Graph records to normalized events.
//!
//! The functions do no I/O. They read a record as loose JSON: a field that is absent or has
//! an unexpected type is the same as no data. Each event keeps the original record in
//! [`Event::raw`].
//!
//! # Identifiers
//!
//! Entra object identifiers are GUIDs. The functions write each GUID in lower case, so that
//! the same object has the same identifier in all events.
//!
//! The event identifier comes from the tenant, the record identifier, and the record time.
//! Thus the same record always gives the same event identifier, and a consumer can remove
//! a repeated event.

use std::net::IpAddr;

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{self, Actor, Event, EventClass, EventSource, Outcome};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The vendor name in [`EventSource::vendor`].
pub const VENDOR: &str = "microsoft";
/// The product name in [`EventSource::product`].
pub const PRODUCT: &str = "entra_id";

/// Attribute keys that this connector adds to the shared keys of
/// [`aegis_contracts::event::attr`].
pub mod attr {
    /// The identifier of the resource application that a sign-in or a grant refers to.
    pub const RESOURCE_ID: &str = "resource_id";
    /// The display name of the resource application.
    pub const RESOURCE_NAME: &str = "resource_name";
    /// The client application type of a sign-in, for example `browser` or `imap4`.
    pub const CLIENT_APP: &str = "client_app";
    /// `true` if a person did the sign-in interactively.
    pub const INTERACTIVE: &str = "interactive";
    /// The risk level that Entra ID gives to a sign-in: `low`, `medium`, or `high`.
    pub const RISK_LEVEL: &str = "risk_level";
    /// The result of Conditional Access for a sign-in, for example `success`.
    pub const CONDITIONAL_ACCESS_STATUS: &str = "conditional_access_status";
    /// The identifier that links records of one operation.
    pub const CORRELATION_ID: &str = "correlation_id";
    /// The category of a directory audit record, for example `RoleManagement`.
    pub const CATEGORY: &str = "category";
    /// `true` if an administrator consented for all users of the tenant.
    pub const ADMIN_CONSENT: &str = "admin_consent";
}

/// The reason why a record cannot become an event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    /// The record is not a JSON object.
    #[error("the record is not a JSON object")]
    NotAnObject,
    /// A field that each record must have is absent or empty.
    #[error("the record has no {0} field")]
    MissingField(&'static str),
    /// The time field is not an RFC 3339 time.
    #[error("the {0} field of the record is not an RFC 3339 time")]
    InvalidTime(&'static str),
}

impl From<NormalizeError> for aegis_contracts::Error {
    fn from(error: NormalizeError) -> Self {
        Self::Serialization(error.to_string())
    }
}

/// The directory roles that Microsoft labels as privileged, as (template identifier, name).
///
/// Source: the "Microsoft Entra built-in roles" reference, roles with the PRIVILEGED label.
const PRIVILEGED_ROLES: &[(&str, &str)] = &[
    ("d2562ede-74db-457e-a7b6-544e236ebb61", "AI Administrator"),
    ("1fe13547-53f6-408d-ac04-7f8eed167b38", "AI Reader"),
    (
        "db506228-d27e-4b7d-95e5-295956d6615f",
        "Agent ID Administrator",
    ),
    (
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "Application Administrator",
    ),
    (
        "cf1c38e5-3621-4004-a7cb-879624dced7c",
        "Application Developer",
    ),
    (
        "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe",
        "Attribute Provisioning Administrator",
    ),
    (
        "422218e4-db15-4ef9-bbe0-8afb41546d79",
        "Attribute Provisioning Reader",
    ),
    (
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
        "Authentication Administrator",
    ),
    (
        "25a516ed-2fa0-40ea-a2d0-12923a21473a",
        "Authentication Extensibility Administrator",
    ),
    (
        "0b00bede-4072-4d22-b441-e7df02a1ef63",
        "Authentication Extensibility Password Administrator",
    ),
    (
        "aaf43236-0c0d-4d5f-883a-6955382ac081",
        "B2C IEF Keyset Administrator",
    ),
    (
        "158c047a-c907-4556-b7ef-446551a6b5f7",
        "Cloud Application Administrator",
    ),
    (
        "7698a772-787b-4ac8-901f-60d6b08affd2",
        "Cloud Device Administrator",
    ),
    (
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "Conditional Access Administrator",
    ),
    ("9360feb5-f418-4baa-8175-e2a00bac4301", "Directory Writers"),
    (
        "8329153b-31d0-4727-b945-745eb3bc5f31",
        "Domain Name Administrator",
    ),
    (
        "58f930cc-fcf4-4152-852c-1d7dbf502139",
        "Entra SOC Identity Responder",
    ),
    (
        "be2f45a1-457d-42af-a067-6ec1fa63bc45",
        "External Identity Provider Administrator",
    ),
    (
        "62e90394-69f5-4237-9190-012177145e10",
        "Global Administrator",
    ),
    ("f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader"),
    (
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "Helpdesk Administrator",
    ),
    (
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
        "Hybrid Identity Administrator",
    ),
    (
        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e",
        "Identity Governance Administrator",
    ),
    (
        "3a2c62db-5318-420d-8d74-23affee5d9d5",
        "Intune Administrator",
    ),
    (
        "59d46f88-662b-457b-bceb-5c3809e5908f",
        "Lifecycle Workflows Administrator",
    ),
    (
        "4ba39ca4-527c-499a-b93d-d9b492c50246",
        "Partner Tier1 Support",
    ),
    (
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
        "Partner Tier2 Support",
    ),
    (
        "966707d0-3269-4727-9be2-8c3a10f19b9d",
        "Password Administrator",
    ),
    (
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "Privileged Authentication Administrator",
    ),
    (
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "Privileged Role Administrator",
    ),
    (
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "Security Administrator",
    ),
    ("5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "Security Operator"),
    ("5d6b6bb7-de71-4623-b4af-96380a352509", "Security Reader"),
    (
        "1981f584-96e9-4a6f-95b0-f522373f8fae",
        "Tenant Governance Administrator",
    ),
    ("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator"),
];

/// Earlier names of privileged roles. Old audit records can hold these names.
const PRIVILEGED_ROLE_ALIASES: &[&str] = &["Company Administrator", "TenantAdmins"];

/// Microsoft Graph and Exchange permissions that give control of the directory, of
/// credentials, or of the mail and the files of all users.
const PRIVILEGED_PERMISSIONS: &[&str] = &[
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "EWS.AccessAsUser.All",
    "Files.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Organization.ReadWrite.All",
    "Policy.ReadWrite.AuthenticationMethod",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.PermissionGrant",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleManagement.ReadWrite.Directory",
    "Sites.FullControl.All",
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "full_access_as_app",
];

/// Activities that assign a directory role. Requests and cancellations are not in the list.
const ROLE_ASSIGN_ACTIVITIES: &[&str] = &[
    "add member to role",
    "add eligible member to role",
    "add scoped member to role",
    "add member to role scoped over restricted management administrative unit",
    "add member to role outside of pim (permanent)",
    "add member to role completed (pim activation)",
    "add member to role in pim completed (permanent)",
    "add member to role in pim completed (timebound)",
    "add eligible member to role in pim completed (permanent)",
    "add eligible member to role in pim completed (timebound)",
];

/// Activities that remove a directory role.
const ROLE_REMOVE_ACTIVITIES: &[&str] = &[
    "remove member from role",
    "remove eligible member from role",
    "remove scoped member from role",
    "remove member from role scoped over restricted management administrative unit",
    "remove member from role (pim activation expired)",
    "remove member from role completed (pim deactivate)",
    "remove member from role in pim completed (permanent)",
    "remove member from role in pim completed (timebound)",
    "remove eligible member from role in pim completed (permanent)",
    "remove eligible member from role in pim completed (timebound)",
];

/// Activities that reset or change the password of a user.
const PASSWORD_RESET_ACTIVITIES: &[&str] = &[
    "reset user password",
    "reset password",
    "reset password (by admin)",
    "reset password (self-service)",
    "change user password",
    "change password (self-service)",
];

/// Activities that change a multi-factor authentication method of a user.
const MFA_METHOD_ACTIVITIES: &[&str] = &[
    "user registered security info",
    "user registered all required security info",
    "user deleted security info",
    "user updated security info",
    "user changed default security info",
    "admin registered security info",
    "admin deleted security info",
    "admin updated security info",
];

/// Returns `true` if a directory role gives privileged access.
///
/// The function knows the built-in roles that Microsoft labels as privileged, for example
/// Global Administrator and Privileged Role Administrator. It compares the role template
/// identifier first and the display name second. Both comparisons ignore the case.
#[must_use]
pub fn is_privileged_role(role_id: Option<&str>, role_name: Option<&str>) -> bool {
    let by_id = role_id.is_some_and(|id| {
        let id = id.trim();
        PRIVILEGED_ROLES
            .iter()
            .any(|(template_id, _)| template_id.eq_ignore_ascii_case(id))
    });
    let by_name = role_name.is_some_and(|name| {
        let name = name.trim();
        PRIVILEGED_ROLES
            .iter()
            .map(|(_, known)| *known)
            .chain(PRIVILEGED_ROLE_ALIASES.iter().copied())
            .any(|known| known.eq_ignore_ascii_case(name))
    });
    by_id || by_name
}

/// Returns `true` if an OAuth scope or an application permission gives privileged access.
///
/// The function knows the Microsoft Graph and Exchange permissions that give control of the
/// directory, of credentials, or of the mail and the files of all users. The comparison
/// ignores the case.
#[must_use]
pub fn is_privileged_permission(permission: &str) -> bool {
    let permission = permission.trim();
    PRIVILEGED_PERMISSIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(permission))
}

/// Makes an action name from an activity name that has no normalized action.
///
/// The result has the words of the activity in lower case with `.` between them. For
/// example, `Update conditional access policy` becomes `update.conditional.access.policy`.
/// An activity with no letters and no digits becomes `unknown`.
#[must_use]
pub fn action_from_activity(activity: &str) -> String {
    let words: Vec<String> = activity
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect();
    if words.is_empty() {
        "unknown".to_owned()
    } else {
        words.join(".")
    }
}

/// Converts one sign-in record (`microsoft.graph.signIn`) to an event.
///
/// The record can be a user sign-in or a service principal sign-in. `source` gives the
/// connector name and the tenant that the record comes from.
///
/// # Mapping
///
/// - The class is [`EventClass::Authentication`] and the action is
///   [`event::action::SIGN_IN`].
/// - The outcome is [`Outcome::Success`] if `status.errorCode` is 0, and
///   [`Outcome::Failure`] for all other codes.
/// - The actor is the user or the service principal. A failed sign-in for an account that
///   does not exist has no user identifier. Then the actor identifier is the sign-in name.
/// - The target is the application that the user signed in to. For a service principal, the
///   target is the resource that it requested a token for.
/// - `mfa_satisfied` is present only if the record shows the answer. It is `false` for a
///   failed sign-in and for a service principal. It is `true` if the record names an MFA
///   method, a Conditional Access policy that enforced MFA, or an MFA result in
///   `status.additionalDetails`.
///
/// # Errors
///
/// Returns an error if the record has no `id` or no valid `createdDateTime`.
pub fn sign_in(record: &Value, source: &EventSource) -> Result<Event, NormalizeError> {
    let fields = record.as_object().ok_or(NormalizeError::NotAnObject)?;
    let record_id = text(fields, "id").ok_or(NormalizeError::MissingField("id"))?;
    let time = time(fields, "createdDateTime")?;

    let user_id = text(fields, "userId").filter(|id| !is_nil_guid(id));
    let principal_id = text(fields, "servicePrincipalId").filter(|id| !is_nil_guid(id));
    let is_workload = user_id.is_none() && principal_id.is_some();
    let sign_in_name =
        text(fields, "userPrincipalName").or_else(|| text(fields, "signInIdentifier"));

    let mut actor = match (user_id, principal_id) {
        (Some(user_id), _) => Actor::new(EntityKind::User, object_id(user_id)),
        (None, Some(principal_id)) => {
            Actor::new(EntityKind::ServicePrincipal, object_id(principal_id))
        }
        (None, None) => match sign_in_name {
            Some(name) => Actor::new(EntityKind::User, name.to_lowercase()),
            None => Actor::new(EntityKind::Other, "unknown"),
        },
    };
    actor.name = if is_workload {
        text(fields, "servicePrincipalName").or_else(|| text(fields, "appDisplayName"))
    } else {
        sign_in_name.or_else(|| text(fields, "userDisplayName"))
    }
    .map(str::to_owned);
    actor.tenant = text(fields, "homeTenantId")
        .map(object_id)
        .or_else(|| source.tenant.clone());
    actor.ip = text(fields, "ipAddress").and_then(|address| address.parse::<IpAddr>().ok());
    actor.user_agent = text(fields, "userAgent").map(str::to_owned);
    actor.session_id = text(fields, "sessionId").map(str::to_owned);

    let status = fields.get("status").and_then(Value::as_object);
    let error_code = status
        .and_then(|status| status.get("errorCode"))
        .and_then(Value::as_i64);
    let outcome = match error_code {
        Some(0) => Outcome::Success,
        Some(_) => Outcome::Failure,
        None => Outcome::Unknown,
    };

    let mut event = Event::new(
        time,
        source.clone(),
        EventClass::Authentication,
        event::action::SIGN_IN,
        actor,
    )
    .with_id(event_id(source, "sign_in", record_id, time))
    .with_outcome(outcome)
    .with_severity(risk_severity(fields));

    let app_id = text(fields, "appId").map(object_id);
    let app_name = text(fields, "appDisplayName");
    let resource_id = text(fields, "resourceId").map(object_id);
    let resource_name = text(fields, "resourceDisplayName");
    let target = if is_workload {
        resource_id
            .as_deref()
            .map(|id| named(EntityRef::new(EntityKind::Application, id), resource_name))
    } else {
        app_id
            .as_deref()
            .map(|id| named(EntityRef::new(EntityKind::Application, id), app_name))
    };
    event.target = target;

    let attributes = &mut event.attributes;
    set(attributes, event::attr::APP_ID, app_id);
    set(attributes, event::attr::APP_NAME, app_name);
    set(attributes, attr::RESOURCE_ID, resource_id);
    set(attributes, attr::RESOURCE_NAME, resource_name);
    if outcome == Outcome::Failure {
        set(
            attributes,
            event::attr::ERROR_CODE,
            error_code.map(|code| code.to_string()),
        );
        set(
            attributes,
            event::attr::FAILURE_REASON,
            status.and_then(|status| text(status, "failureReason")),
        );
    }
    set(
        attributes,
        event::attr::MFA_SATISFIED,
        mfa_satisfied(fields, outcome, is_workload),
    );
    set(
        attributes,
        event::attr::HOME_TENANT,
        text(fields, "homeTenantId").map(object_id),
    );
    set(
        attributes,
        event::attr::RESOURCE_TENANT,
        text(fields, "resourceTenantId").map(object_id),
    );

    let client_app = text(fields, "clientAppUsed").map(snake_case);
    let protocol = text(fields, "authenticationProtocol")
        .filter(|protocol| !protocol.eq_ignore_ascii_case("none"))
        .map(snake_case);
    let auth_protocol = if is_workload {
        Some("client_credentials".to_owned())
    } else {
        protocol.or_else(|| client_app.clone())
    };
    set(attributes, event::attr::AUTH_PROTOCOL, auth_protocol);
    set(attributes, attr::CLIENT_APP, client_app);
    if is_workload {
        set(
            attributes,
            event::attr::CREDENTIAL_TYPE,
            text(fields, "clientCredentialType").map(client_credential_type),
        );
    }

    if let Some(location) = fields.get("location").and_then(Value::as_object) {
        set(
            attributes,
            event::attr::COUNTRY,
            text(location, "countryOrRegion").map(country_code),
        );
        set(attributes, event::attr::CITY, text(location, "city"));
        if let Some(coordinates) = location.get("geoCoordinates").and_then(Value::as_object) {
            let latitude = coordinates.get("latitude").and_then(Value::as_f64);
            let longitude = coordinates.get("longitude").and_then(Value::as_f64);
            // One coordinate without the other is not a position.
            if let (Some(latitude), Some(longitude)) = (latitude, longitude) {
                set(attributes, event::attr::LATITUDE, Some(latitude));
                set(attributes, event::attr::LONGITUDE, Some(longitude));
            }
        }
    }

    set(
        attributes,
        attr::INTERACTIVE,
        fields.get("isInteractive").and_then(Value::as_bool),
    );
    set(attributes, attr::RISK_LEVEL, risk_level(fields));
    set(
        attributes,
        attr::CONDITIONAL_ACCESS_STATUS,
        text(fields, "conditionalAccessStatus").map(snake_case),
    );
    set(
        attributes,
        attr::CORRELATION_ID,
        text(fields, "correlationId").map(object_id),
    );

    event.raw = Some(record.clone());
    Ok(event)
}

/// Converts one directory audit record (`microsoft.graph.directoryAudit`) to an event.
///
/// `source` gives the connector name and the tenant that the record comes from.
///
/// # Mapping
///
/// | Activity | Action | Class |
/// | --- | --- | --- |
/// | Consent to application | `oauth.consent_grant` | `UserAccessManagement` |
/// | Add service principal credentials | `app.credential_add` | `AccountChange` |
/// | Update application, certificates and secrets management | `app.credential_add` or `app.credential_remove` | `AccountChange` |
/// | Remove service principal credentials | `app.credential_remove` | `AccountChange` |
/// | Add member to role, and the completed PIM assignments | `role.assign` | `UserAccessManagement` |
/// | Remove member from role, and the completed PIM removals | `role.remove` | `UserAccessManagement` |
/// | Add app role assignment to service principal | `app.permission_grant` | `UserAccessManagement` |
/// | Add service principal | `service_principal.create` | `EntityManagement` |
/// | Add application | `app.create` | `EntityManagement` |
/// | Add user | `user.create` | `AccountChange` |
/// | Update user | `user.update` | `AccountChange` |
/// | Reset or change of a user password | `user.password_reset` | `AccountChange` |
/// | Registration, change, or removal of security info | `mfa.method_change` | `AccountChange` |
/// | All other activities | [`action_from_activity`] | `Other` |
///
/// The actor is the user or the application in `initiatedBy`. For a role assignment and a
/// permission grant, the target is the principal that gets the access. If one principal is
/// the actor and the target, the two have the same identifier, name, and tenant.
///
/// The `privileged` attribute is `true` for a privileged role ([`is_privileged_role`]) and
/// for a privileged scope or permission ([`is_privileged_permission`]).
///
/// # Errors
///
/// Returns an error if the record has no `id` or no valid `activityDateTime`.
pub fn directory_audit(record: &Value, source: &EventSource) -> Result<Event, NormalizeError> {
    let fields = record.as_object().ok_or(NormalizeError::NotAnObject)?;
    let record_id = text(fields, "id").ok_or(NormalizeError::MissingField("id"))?;
    let time = time(fields, "activityDateTime")?;
    let activity = text(fields, "activityDisplayName").unwrap_or("unknown");
    let audit = Audit {
        fields,
        targets: fields
            .get("targetResources")
            .and_then(Value::as_array)
            .map(|targets| targets.iter().filter_map(Value::as_object).collect())
            .unwrap_or_default(),
        tenant: source.tenant.as_deref(),
    };

    let mut actor = audit.actor();
    let Mapped {
        class,
        action,
        mut target,
        mut attributes,
    } = audit.map_activity(activity);

    if let Some(target) = target.as_mut()
        && target.kind == actor.kind
        && target.id == actor.id
    {
        // One principal is the actor and the target. Give both the same name and tenant.
        let name = actor.name.clone().or_else(|| target.name.clone());
        let tenant = actor.tenant.clone().or_else(|| target.tenant.clone());
        actor.name.clone_from(&name);
        actor.tenant.clone_from(&tenant);
        target.name = name;
        target.tenant = tenant;
        // The application of the initiator is then also the application of the target.
        if !attributes.contains_key(event::attr::APP_ID) {
            set(
                &mut attributes,
                event::attr::APP_ID,
                audit.initiator_app_id(),
            );
        }
    }

    let mut event = Event::new(time, source.clone(), class, action, actor)
        .with_id(event_id(source, "directory_audit", record_id, time))
        .with_outcome(match text(fields, "result") {
            Some(result) if result.eq_ignore_ascii_case("success") => Outcome::Success,
            Some(result)
                if result.eq_ignore_ascii_case("failure")
                    || result.eq_ignore_ascii_case("timeout") =>
            {
                Outcome::Failure
            }
            _ => Outcome::Unknown,
        });
    event.target = target;
    event.attributes = attributes;

    let attributes = &mut event.attributes;
    set(attributes, event::attr::OPERATION, Some(activity));
    set(attributes, attr::CATEGORY, text(fields, "category"));
    set(
        attributes,
        attr::CORRELATION_ID,
        text(fields, "correlationId").map(object_id),
    );
    if event.outcome == Outcome::Failure {
        set(
            attributes,
            event::attr::FAILURE_REASON,
            text(fields, "resultReason"),
        );
    }

    event.raw = Some(record.clone());
    Ok(event)
}

/// The normalized parts of a directory audit record that depend on the activity.
struct Mapped {
    class: EventClass,
    action: String,
    target: Option<EntityRef>,
    attributes: std::collections::BTreeMap<String, Value>,
}

impl Mapped {
    fn new(class: EventClass, action: &str, target: Option<EntityRef>) -> Self {
        Self {
            class,
            action: action.to_owned(),
            target,
            attributes: std::collections::BTreeMap::new(),
        }
    }
}

/// One credential in a `KeyDescription` property.
#[derive(Debug, PartialEq, Eq)]
struct KeyEntry {
    id: Option<String>,
    key_type: Option<String>,
}

/// A view of one directory audit record.
struct Audit<'a> {
    fields: &'a Map<String, Value>,
    targets: Vec<&'a Map<String, Value>>,
    tenant: Option<&'a str>,
}

impl Audit<'_> {
    /// Returns the principal in `initiatedBy`.
    fn actor(&self) -> Actor {
        let initiated_by = self.fields.get("initiatedBy").and_then(Value::as_object);
        let user = initiated_by
            .and_then(|initiator| initiator.get("user"))
            .and_then(Value::as_object);
        let app = initiated_by
            .and_then(|initiator| initiator.get("app"))
            .and_then(Value::as_object);

        let user_id = user.and_then(|user| {
            text(user, "id")
                .map(object_id)
                .or_else(|| text(user, "userPrincipalName").map(str::to_lowercase))
        });
        let mut actor = if let Some(user) = user
            && let Some(id) = user_id
        {
            let mut actor = Actor::new(EntityKind::User, id);
            actor.name = text(user, "userPrincipalName")
                .or_else(|| text(user, "displayName"))
                .map(str::to_owned);
            actor.ip = text(user, "ipAddress").and_then(|address| address.parse().ok());
            actor.tenant = text(user, "homeTenantId").map(object_id);
            actor
        } else if let Some(app) = app {
            let name = text(app, "displayName").or_else(|| text(app, "servicePrincipalName"));
            let mut actor = if let Some(id) = text(app, "servicePrincipalId") {
                Actor::new(EntityKind::ServicePrincipal, object_id(id))
            } else if let Some(id) = text(app, "appId") {
                Actor::new(EntityKind::Application, object_id(id))
            } else {
                Actor::new(EntityKind::Other, name.unwrap_or("unknown"))
            };
            actor.name = name.map(str::to_owned);
            actor
        } else {
            Actor::new(EntityKind::Other, "unknown")
        };
        if actor.tenant.is_none() {
            actor.tenant = self.tenant.map(str::to_owned);
        }
        actor.user_agent = self.detail("User-Agent").map(str::to_owned);
        actor
    }

    /// Returns the application identifier of the application in `initiatedBy`.
    fn initiator_app_id(&self) -> Option<String> {
        self.fields
            .get("initiatedBy")
            .and_then(Value::as_object)
            .and_then(|initiator| initiator.get("app"))
            .and_then(Value::as_object)
            .and_then(|app| text(app, "appId"))
            .map(object_id)
    }

    /// Returns the value of the entry `key` in `additionalDetails`.
    fn detail(&self, key: &str) -> Option<&str> {
        self.fields
            .get("additionalDetails")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(Value::as_object)
            .find(|entry| text(entry, "key").is_some_and(|name| name.eq_ignore_ascii_case(key)))
            .and_then(|entry| text(entry, "value"))
    }

    /// Returns the first target resource with one of the Graph types in `types`.
    fn target_of_type(&self, types: &[&str]) -> Option<&Map<String, Value>> {
        self.targets.iter().copied().find(|target| {
            text(target, "type")
                .is_some_and(|kind| types.iter().any(|wanted| wanted.eq_ignore_ascii_case(kind)))
        })
    }

    /// Returns the decoded value of the modified property `name` in any target resource.
    fn property(&self, name: &str) -> Option<String> {
        self.targets
            .iter()
            .find_map(|target| property(target, name))
    }

    /// Makes an entity reference from a target resource.
    fn entity(&self, target: &Map<String, Value>) -> Option<EntityRef> {
        let id = text(target, "id")?;
        let kind = match text(target, "type").map(str::to_ascii_lowercase).as_deref() {
            Some("user") => EntityKind::User,
            Some("serviceprincipal") => EntityKind::ServicePrincipal,
            Some("application" | "app") => EntityKind::Application,
            Some("device") => EntityKind::Device,
            Some("role") => EntityKind::Role,
            Some("directory") => EntityKind::Tenant,
            _ => EntityKind::Other,
        };
        let name = if kind == EntityKind::User {
            text(target, "userPrincipalName").or_else(|| text(target, "displayName"))
        } else {
            text(target, "displayName")
        };
        let mut entity = named(EntityRef::new(kind, object_id(id)), name);
        entity.tenant = self.tenant.map(str::to_owned);
        Some(entity)
    }

    /// Returns the first target resource as an entity.
    fn first_entity(&self) -> Option<EntityRef> {
        self.targets.iter().find_map(|target| self.entity(target))
    }

    /// Returns the application identifier that the record gives for the target.
    fn target_app_id(&self) -> Option<String> {
        self.property("TargetId.ServicePrincipalNames")
            .and_then(|names| first_guid(&names))
            .or_else(|| {
                self.property("AppPrincipalId")
                    .and_then(|id| first_guid(&id))
            })
            .or_else(|| self.property("AppId").and_then(|id| first_guid(&id)))
            .or_else(|| self.detail("AppId").and_then(first_guid))
    }

    fn map_activity(&self, activity: &str) -> Mapped {
        let name = activity.trim().to_lowercase();
        let name = name.as_str();
        if name == "consent to application" {
            self.consent_grant()
        } else if name == "add service principal credentials" {
            self.credential_change(Some(event::action::APP_CREDENTIAL_ADD))
        } else if name == "remove service principal credentials" {
            self.credential_change(Some(event::action::APP_CREDENTIAL_REMOVE))
        } else if name.starts_with("update application")
            && name.contains("certificates and secrets management")
        {
            self.credential_change(None)
        } else if ROLE_ASSIGN_ACTIVITIES.contains(&name) {
            self.role_change(event::action::ROLE_ASSIGN)
        } else if ROLE_REMOVE_ACTIVITIES.contains(&name) {
            self.role_change(event::action::ROLE_REMOVE)
        } else if name == "add app role assignment to service principal" {
            self.permission_grant()
        } else if name == "add service principal" {
            self.entity_change(
                EventClass::EntityManagement,
                event::action::SERVICE_PRINCIPAL_CREATE,
            )
        } else if name == "add application" {
            self.entity_change(EventClass::EntityManagement, event::action::APP_CREATE)
        } else if name == "add user" {
            self.entity_change(EventClass::AccountChange, event::action::USER_CREATE)
        } else if name == "update user" {
            self.entity_change(EventClass::AccountChange, event::action::USER_UPDATE)
        } else if PASSWORD_RESET_ACTIVITIES.contains(&name) {
            self.entity_change(
                EventClass::AccountChange,
                event::action::USER_PASSWORD_RESET,
            )
        } else if MFA_METHOD_ACTIVITIES.contains(&name) {
            self.entity_change(EventClass::AccountChange, event::action::MFA_METHOD_CHANGE)
        } else {
            Mapped::new(
                EventClass::Other,
                &action_from_activity(activity),
                self.first_entity(),
            )
        }
    }

    /// Maps an activity whose target is the first target resource.
    fn entity_change(&self, class: EventClass, action: &str) -> Mapped {
        let target = self.first_entity();
        let mut mapped = Mapped::new(class, action, target);
        let is_app = mapped.target.as_ref().is_some_and(|target| {
            matches!(
                target.kind,
                EntityKind::Application | EntityKind::ServicePrincipal
            )
        });
        if is_app {
            set(
                &mut mapped.attributes,
                event::attr::APP_ID,
                self.target_app_id(),
            );
            set(
                &mut mapped.attributes,
                event::attr::APP_NAME,
                mapped
                    .target
                    .as_ref()
                    .and_then(|target| target.name.clone()),
            );
        }
        mapped
    }

    fn consent_grant(&self) -> Mapped {
        let mut mapped = self.entity_change(
            EventClass::UserAccessManagement,
            event::action::OAUTH_CONSENT_GRANT,
        );
        let scopes = self
            .property("ConsentAction.Permissions")
            .map(|permissions| consent_scopes(&permissions))
            .unwrap_or_default();
        let privileged = scopes.iter().any(|scope| is_privileged_permission(scope));
        let attributes = &mut mapped.attributes;
        set(attributes, event::attr::PRIVILEGED, Some(privileged));
        if !scopes.is_empty() {
            set(attributes, event::attr::SCOPES, Some(json!(scopes)));
        }
        set(
            attributes,
            attr::ADMIN_CONSENT,
            self.property("ConsentContext.IsAdminConsent")
                .map(|value| value.eq_ignore_ascii_case("true")),
        );
        mapped
    }

    /// Maps a change to the credentials of an application or a service principal.
    ///
    /// With no `action`, the credentials before and after the change give the action.
    fn credential_change(&self, action: Option<&str>) -> Mapped {
        let holder = self
            .targets
            .iter()
            .copied()
            .find(|target| raw_property(target, "KeyDescription").is_some())
            .or_else(|| self.targets.first().copied());
        let (old_keys, new_keys) = holder
            .and_then(|target| raw_property(target, "KeyDescription"))
            .map(|(old, new)| (key_entries(old), key_entries(new)))
            .unwrap_or_default();
        let added: Vec<&KeyEntry> = new_keys
            .iter()
            .filter(|key| !old_keys.iter().any(|old| old.id == key.id))
            .collect();
        let removed: Vec<&KeyEntry> = old_keys
            .iter()
            .filter(|key| !new_keys.iter().any(|new| new.id == key.id))
            .collect();
        let action = action.unwrap_or(if added.is_empty() && !removed.is_empty() {
            event::action::APP_CREDENTIAL_REMOVE
        } else {
            event::action::APP_CREDENTIAL_ADD
        });
        let credential = if action == event::action::APP_CREDENTIAL_REMOVE {
            removed.first().copied().or(old_keys.first())
        } else {
            added.first().copied().or(new_keys.last())
        };

        let target = holder.and_then(|target| self.entity(target));
        let mut mapped = Mapped::new(EventClass::AccountChange, action, target);
        let attributes = &mut mapped.attributes;
        set(attributes, event::attr::APP_ID, self.target_app_id());
        set(
            attributes,
            event::attr::APP_NAME,
            mapped
                .target
                .as_ref()
                .and_then(|target| target.name.clone()),
        );
        if let Some(credential) = credential {
            set(
                attributes,
                event::attr::CREDENTIAL_ID,
                credential.id.clone(),
            );
            set(
                attributes,
                event::attr::CREDENTIAL_TYPE,
                credential.key_type.clone(),
            );
        }
        mapped
    }

    fn role_change(&self, action: &str) -> Mapped {
        let role = self.target_of_type(&["Role"]);
        let principal = self
            .target_of_type(&["User", "ServicePrincipal", "Group"])
            .and_then(|target| self.entity(target));
        let template_id = self.property("Role.TemplateId").map(|id| object_id(&id));
        let role_id = template_id
            .or_else(|| self.property("Role.ObjectID").map(|id| object_id(&id)))
            .or_else(|| role.and_then(|role| text(role, "id")).map(object_id));
        let role_name = self.property("Role.DisplayName").or_else(|| {
            role.and_then(|role| text(role, "displayName"))
                .map(str::to_owned)
        });
        let privileged = is_privileged_role(role_id.as_deref(), role_name.as_deref())
            || self
                .property("Role.WellKnownObjectName")
                .is_some_and(|name| is_privileged_role(None, Some(&name)));

        let is_app = principal
            .as_ref()
            .is_some_and(|principal| principal.kind == EntityKind::ServicePrincipal);
        let mut mapped = Mapped::new(EventClass::UserAccessManagement, action, principal);
        let attributes = &mut mapped.attributes;
        set(attributes, event::attr::ROLE_ID, role_id);
        set(attributes, event::attr::ROLE_NAME, role_name);
        set(attributes, event::attr::PRIVILEGED, Some(privileged));
        if is_app {
            set(attributes, event::attr::APP_ID, self.target_app_id());
        }
        mapped
    }

    fn permission_grant(&self) -> Mapped {
        let resource = self.targets.first().copied();
        let assignee_id = self.property("ServicePrincipal.ObjectID");
        let assignee = match assignee_id {
            Some(id) => {
                let id = object_id(&id);
                // Prefer the target resource of the assignee, because it has the type.
                let listed = self
                    .targets
                    .iter()
                    .filter_map(|target| self.entity(target))
                    .find(|entity| entity.id == id);
                let mut entity =
                    listed.unwrap_or_else(|| EntityRef::new(EntityKind::ServicePrincipal, id));
                entity.kind = EntityKind::ServicePrincipal;
                if entity.name.is_none() {
                    entity.name = self.property("ServicePrincipal.DisplayName");
                }
                entity.tenant = self.tenant.map(str::to_owned);
                Some(entity)
            }
            None => self
                .targets
                .get(1)
                .or(self.targets.first())
                .and_then(|target| self.entity(target)),
        };
        let permission = self.property("AppRole.Value");
        let privileged = permission.as_deref().is_some_and(is_privileged_permission);

        let mut mapped = Mapped::new(
            EventClass::UserAccessManagement,
            event::action::APP_PERMISSION_GRANT,
            assignee,
        );
        let attributes = &mut mapped.attributes;
        set(
            attributes,
            event::attr::APP_ID,
            self.property("ServicePrincipal.AppId")
                .map(|id| object_id(&id)),
        );
        set(
            attributes,
            event::attr::APP_NAME,
            mapped
                .target
                .as_ref()
                .and_then(|target| target.name.clone()),
        );
        set(
            attributes,
            event::attr::ROLE_ID,
            self.property("AppRole.Id").map(|id| object_id(&id)),
        );
        set(
            attributes,
            event::attr::ROLE_NAME,
            permission
                .clone()
                .or_else(|| self.property("AppRole.DisplayName")),
        );
        if let Some(permission) = permission {
            set(attributes, event::attr::SCOPES, Some(json!([permission])));
        }
        set(attributes, event::attr::PRIVILEGED, Some(privileged));
        set(
            attributes,
            attr::RESOURCE_ID,
            resource
                .and_then(|resource| text(resource, "id"))
                .map(object_id),
        );
        set(
            attributes,
            attr::RESOURCE_NAME,
            resource.and_then(|resource| text(resource, "displayName")),
        );
        mapped
    }
}

/// Inserts `value` at `key` if there is a value.
fn set<T: Into<Value>>(
    attributes: &mut std::collections::BTreeMap<String, Value>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        attributes.insert(key.to_owned(), value.into());
    }
}

/// Returns the string field `key`, without surrounding spaces. An empty string is no data.
fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn time(fields: &Map<String, Value>, key: &'static str) -> Result<DateTime<Utc>, NormalizeError> {
    let value = text(fields, key).ok_or(NormalizeError::MissingField(key))?;
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| NormalizeError::InvalidTime(key))
}

fn named(entity: EntityRef, name: Option<&str>) -> EntityRef {
    match name {
        Some(name) => entity.with_name(name),
        None => entity,
    }
}

/// Writes a GUID in lower case with hyphens. Other text stays the same.
fn object_id(id: &str) -> String {
    let id = id.trim();
    Uuid::parse_str(id).map_or_else(|_| id.to_owned(), |uuid| uuid.hyphenated().to_string())
}

fn is_nil_guid(id: &str) -> bool {
    Uuid::parse_str(id.trim()).is_ok_and(|uuid| uuid.is_nil())
}

/// Returns the first GUID in a list with `;`, `,`, `/`, or spaces between the items.
fn first_guid(list: &str) -> Option<String> {
    list.split(|character: char| matches!(character, ';' | ',' | '/') || character.is_whitespace())
        .find_map(|item| Uuid::parse_str(item.trim()).ok())
        .map(|uuid| uuid.hyphenated().to_string())
}

/// Makes the event identifier of a record. The same record always gives the same result.
///
/// The identifier has the layout of a version 7 UUID: the record time and then bits of a
/// SHA-256 digest. Thus the identifiers sort by time, like [`EventId::new`].
fn event_id(source: &EventSource, kind: &str, record_id: &str, time: DateTime<Utc>) -> EventId {
    let mut digest = Sha256::new();
    for part in [
        source.tenant.as_deref().unwrap_or(&source.connector),
        kind,
        record_id,
    ] {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    let digest = digest.finalize();
    let mut bits = [0_u8; 10];
    for (bit, byte) in bits.iter_mut().zip(digest.iter()) {
        *bit = *byte;
    }
    let milliseconds = u64::try_from(time.timestamp_millis()).unwrap_or(0);
    EventId(uuid::Builder::from_unix_timestamp_millis(milliseconds, &bits).into_uuid())
}

/// Changes a Graph value to lower case with `_` between the words.
///
/// `deviceCode` becomes `device_code` and `Mobile Apps and Desktop clients` becomes
/// `mobile_apps_and_desktop_clients`.
fn snake_case(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 4);
    let mut previous: Option<char> = None;
    for character in value.trim().chars() {
        if character.is_alphanumeric() {
            let starts_word = character.is_uppercase()
                && previous.is_some_and(|previous| previous.is_lowercase())
                && result.chars().count() > 1;
            if starts_word {
                result.push('_');
            }
            result.extend(character.to_lowercase());
        } else if !result.ends_with('_') && !result.is_empty() {
            result.push('_');
        }
        previous = Some(character);
    }
    result.trim_end_matches('_').to_owned()
}

fn country_code(country: &str) -> String {
    if country.len() == 2 {
        country.to_ascii_uppercase()
    } else {
        country.to_owned()
    }
}

fn client_credential_type(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "clientsecret" => "password".to_owned(),
        "clientassertion" | "certificate" => "certificate".to_owned(),
        _ => snake_case(value),
    }
}

fn key_credential_type(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "password" => "password".to_owned(),
        "asymmetricx509cert" | "x509certandpassword" => "certificate".to_owned(),
        "symmetric" => "symmetric_key".to_owned(),
        _ => snake_case(value),
    }
}

/// Returns the risk level of a sign-in, if Entra ID found a risk.
fn risk_level(fields: &Map<String, Value>) -> Option<String> {
    ["riskLevelDuringSignIn", "riskLevelAggregated"]
        .into_iter()
        .filter_map(|key| text(fields, key))
        .map(str::to_ascii_lowercase)
        .find(|level| matches!(level.as_str(), "low" | "medium" | "high"))
}

fn risk_severity(fields: &Map<String, Value>) -> Severity {
    match risk_level(fields).as_deref() {
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Returns `true` or `false` only if the record shows the answer.
fn mfa_satisfied(fields: &Map<String, Value>, outcome: Outcome, is_workload: bool) -> Option<bool> {
    if is_workload || outcome == Outcome::Failure {
        return Some(false);
    }
    let requirement = text(fields, "authenticationRequirement");
    if requirement.is_some_and(|value| value.eq_ignore_ascii_case("singleFactorAuthentication")) {
        return Some(false);
    }
    if outcome != Outcome::Success {
        return None;
    }
    let required =
        requirement.is_some_and(|value| value.eq_ignore_ascii_case("multiFactorAuthentication"));
    let method_used = fields
        .get("mfaDetail")
        .and_then(Value::as_object)
        .is_some_and(|detail| text(detail, "authMethod").is_some());
    let policy_enforced = fields
        .get("appliedConditionalAccessPolicies")
        .and_then(Value::as_array)
        .is_some_and(|policies| {
            policies.iter().filter_map(Value::as_object).any(|policy| {
                let succeeded = text(policy, "result")
                    .is_some_and(|result| result.eq_ignore_ascii_case("success"));
                let requires_mfa = policy
                    .get("enforcedGrantControls")
                    .and_then(Value::as_array)
                    .is_some_and(|controls| {
                        controls
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|control| control.eq_ignore_ascii_case("mfa"))
                    });
                succeeded && requires_mfa
            })
        });
    (required || method_used || policy_enforced || status_shows_mfa(fields)).then_some(true)
}

/// Returns `true` if `status.additionalDetails` says that the sign-in satisfied MFA.
///
/// The `v1.0` record has no `authenticationRequirement` field. There, Entra ID writes the
/// answer as text, for example `MFA completed in Azure AD` or `MFA requirement satisfied by
/// claim in the token`.
fn status_shows_mfa(fields: &Map<String, Value>) -> bool {
    fields
        .get("status")
        .and_then(Value::as_object)
        .and_then(|status| text(status, "additionalDetails"))
        .is_some_and(|detail| {
            let detail = detail.to_ascii_lowercase();
            detail.starts_with("mfa completed") || detail.starts_with("mfa requirement satisfied")
        })
}

/// Returns the old and the new raw value of the modified property `name`.
fn raw_property<'a>(
    target: &'a Map<String, Value>,
    name: &str,
) -> Option<(Option<&'a str>, Option<&'a str>)> {
    target
        .get("modifiedProperties")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_object)
        .find(|property| {
            text(property, "displayName").is_some_and(|display| display.eq_ignore_ascii_case(name))
        })
        .map(|property| (text(property, "oldValue"), text(property, "newValue")))
}

/// Returns the decoded value of the modified property `name`.
///
/// The new value has priority. A removal has only an old value.
fn property(target: &Map<String, Value>, name: &str) -> Option<String> {
    let (old, new) = raw_property(target, name)?;
    new.and_then(decode_property)
        .or_else(|| old.and_then(decode_property))
}

/// Decodes a modified property value. Graph writes these values as JSON in a string.
///
/// `"\"Global Administrator\""` becomes `Global Administrator` and `"[\"a\"]"` becomes `a`.
fn decode_property(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let decoded = match serde_json::from_str::<Value>(raw) {
        Ok(Value::String(value)) => value,
        Ok(Value::Array(items)) => match items.into_iter().next() {
            Some(Value::String(value)) => value,
            Some(Value::Null) | None => return None,
            Some(other) => other.to_string(),
        },
        Ok(Value::Null) => return None,
        Ok(other) => other.to_string(),
        Err(_) => raw.trim_matches('"').to_owned(),
    };
    let decoded = decoded.trim();
    (!decoded.is_empty()).then(|| decoded.to_owned())
}

/// Reads the credentials in a `KeyDescription` property value.
///
/// One credential has the form `[KeyIdentifier=...,KeyType=Password,KeyUsage=Verify,...]`.
fn key_entries(raw: Option<&str>) -> Vec<KeyEntry> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let items: Vec<String> = match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Ok(Value::String(item)) => vec![item],
        _ => vec![raw.to_owned()],
    };
    items
        .iter()
        .flat_map(|item| item.split("KeyIdentifier=").skip(1))
        .map(|entry| {
            let field_end = |text: &str| {
                text.split([',', ']'])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            };
            KeyEntry {
                id: Some(object_id(&field_end(entry))).filter(|id| !id.is_empty()),
                key_type: entry
                    .split_once("KeyType=")
                    .map(|(_, rest)| key_credential_type(&field_end(rest))),
            }
        })
        .collect()
}

/// Reads the scopes that a consent added from a `ConsentAction.Permissions` value.
///
/// The value has the form `[old grants] => [[..., Scope: User.Read Mail.Read, ...]]`.
fn consent_scopes(permissions: &str) -> Vec<String> {
    let granted = permissions
        .split_once("=>")
        .map_or(permissions, |(_, granted)| granted);
    let mut scopes: Vec<String> = Vec::new();
    for segment in granted.split("Scope:").skip(1) {
        let listed = segment.split([',', ']']).next().unwrap_or_default();
        for scope in listed.split_whitespace() {
            if !scopes.iter().any(|known| known.eq_ignore_ascii_case(scope)) {
                scopes.push(scope.to_owned());
            }
        }
    }
    scopes
}

#[cfg(test)]
mod tests;
