//! Tests for the conversion of Microsoft Graph records to events.
//!
//! The records have the shape of real Microsoft Graph responses. All identifiers, names,
//! and addresses are examples.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use chrono::TimeZone;
use serde_json::json;

use super::*;

const TENANT: &str = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
const OTHER_TENANT: &str = "ffff0000-aaaa-bbbb-cccc-111122223333";
const USER_ID: &str = "26be570a-ae82-4189-b4e2-a37c6808512d";
const ADMIN_ID: &str = "9d6c3c2c-5a5f-4c1e-8f43-0d2a6c3f1b10";
const APP_ID: &str = "de8bc8b5-d9f9-48b1-a8ad-b748da725064";
const PRINCIPAL_ID: &str = "7c2e9a40-51d3-4b9e-9f7a-3e1f0c6d2b55";
const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
const GRAPH_PRINCIPAL_ID: &str = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";

fn source() -> EventSource {
    EventSource::new("entra-test", VENDOR, PRODUCT).with_tenant(TENANT)
}

fn attributes(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// A successful interactive user sign-in, as `v1.0/auditLogs/signIns` returns it.
fn user_sign_in() -> Value {
    json!({
        "id": "66ea54eb-6301-4ee5-be62-ff5a759b0100",
        "createdDateTime": "2026-11-03T09:10:31.5Z",
        "userDisplayName": "Dana Example",
        "userPrincipalName": "dana@contoso.example",
        "userId": USER_ID,
        "appId": APP_ID,
        "appDisplayName": "Graph Explorer",
        "ipAddress": "203.0.113.50",
        "clientAppUsed": "Browser",
        "correlationId": "d79f5bee-5860-4832-928f-3133e22ae912",
        "conditionalAccessStatus": "notApplied",
        "isInteractive": true,
        "riskDetail": "none",
        "riskLevelAggregated": "none",
        "riskLevelDuringSignIn": "none",
        "riskState": "none",
        "riskEventTypes": [],
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": GRAPH_APP_ID,
        "status": { "errorCode": 0, "failureReason": null, "additionalDetails": null },
        "deviceDetail": {
            "deviceId": "",
            "displayName": null,
            "operatingSystem": "Windows 10",
            "browser": "Edge 80.0.361",
            "isCompliant": null,
            "isManaged": null,
            "trustType": null
        },
        "location": {
            "city": "Bucharest",
            "state": "Bucuresti",
            "countryOrRegion": "RO",
            "geoCoordinates": { "altitude": null, "latitude": 44.43, "longitude": 26.1 }
        },
        "appliedConditionalAccessPolicies": []
    })
}

/// A service principal sign-in, as `beta/auditLogs/signIns` returns it.
fn service_principal_sign_in() -> Value {
    json!({
        "id": "1691d37b-8579-43a7-966a-0f35583c1300",
        "createdDateTime": "2026-11-03T09:10:43Z",
        "userDisplayName": "",
        "userPrincipalName": "",
        "userId": "",
        "appId": APP_ID,
        "appDisplayName": "Sync Helper",
        "ipAddress": "203.0.113.51",
        "clientAppUsed": "",
        "clientCredentialType": "clientSecret",
        "correlationId": "5d295068-919b-4017-85d8-44be2f5f5483",
        "conditionalAccessStatus": "notApplied",
        "isInteractive": false,
        "homeTenantId": TENANT,
        "resourceTenantId": OTHER_TENANT,
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": GRAPH_APP_ID,
        "resourceServicePrincipalId": GRAPH_PRINCIPAL_ID,
        "signInEventTypes": ["servicePrincipal"],
        "servicePrincipalId": PRINCIPAL_ID,
        "servicePrincipalName": "Sync Helper",
        "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": null },
        "location": {
            "city": "Singapore",
            "state": "",
            "countryOrRegion": "SG",
            "geoCoordinates": { "latitude": 1.35, "longitude": 103.82 }
        }
    })
}

fn user_initiator() -> Value {
    json!({
        "app": null,
        "user": {
            "id": ADMIN_ID,
            "displayName": null,
            "userPrincipalName": "admin@contoso.example",
            "ipAddress": "203.0.113.50",
            "userType": null,
            "homeTenantId": null,
            "homeTenantName": null
        }
    })
}

fn app_initiator(principal_id: &str) -> Value {
    json!({
        "user": null,
        "app": {
            "appId": APP_ID,
            "displayName": "Sync Helper",
            "servicePrincipalId": principal_id,
            "servicePrincipalName": null
        }
    })
}

/// The common fields of a directory audit record.
fn audit(activity: &str, category: &str, initiated_by: Value, targets: Value) -> Value {
    json!({
        "id": "Directory_504a302a-8f2d-418d-b7df-bf77de6ed831_M1N6X_27777783",
        "category": category,
        "correlationId": "504a302a-8f2d-418d-b7df-bf77de6ed831",
        "result": "success",
        "resultReason": "",
        "activityDisplayName": activity,
        "activityDateTime": "2026-11-03T09:10:46.1458248Z",
        "loggedByService": "Core Directory",
        "operationType": "Assign",
        "initiatedBy": initiated_by,
        "targetResources": targets,
        "additionalDetails": [
            { "key": "User-Agent", "value": "python-httpx/0.27.0" }
        ]
    })
}

fn modified(name: &str, old: Value, new: Value) -> Value {
    json!({ "displayName": name, "oldValue": old, "newValue": new })
}

/// The target resources of an "Add member to role" record of the core directory.
fn role_targets(
    principal_type: &str,
    principal_id: &str,
    role_name: &str,
    template_id: &str,
) -> Value {
    json!([
        {
            "id": principal_id,
            "displayName": if principal_type == "User" { Value::Null } else { json!("Sync Helper") },
            "type": principal_type,
            "userPrincipalName": if principal_type == "User" { json!("dana@contoso.example") } else { Value::Null },
            "groupType": null,
            "modifiedProperties": [
                modified("Role.ObjectID", Value::Null, json!("\"0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01\"")),
                modified("Role.DisplayName", Value::Null, json!(format!("\"{role_name}\""))),
                modified("Role.TemplateId", Value::Null, json!(format!("\"{template_id}\""))),
                modified("Role.WellKnownObjectName", Value::Null, json!("\"TenantAdmins\""))
            ]
        },
        {
            "id": "0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01",
            "displayName": null,
            "type": "Role",
            "userPrincipalName": null,
            "groupType": null,
            "modifiedProperties": []
        }
    ])
}

fn consent_record(scopes: &str) -> Value {
    let permissions = format!(
        "\"[] => [[Id: Wc8Lq1XGcEmWb1J0xxxxxxxxxxxxxxxxxxxxxxxxxxx, ClientId: {PRINCIPAL_ID}, \
         PrincipalId: , ResourceId: {GRAPH_PRINCIPAL_ID}, ConsentType: AllPrincipals, \
         Scope: {scopes}, CreatedDateTime: , LastModifiedDateTime ]]; \""
    );
    audit(
        "Consent to application",
        "ApplicationManagement",
        user_initiator(),
        json!([{
            "id": PRINCIPAL_ID,
            "displayName": "Sync Helper",
            "type": "ServicePrincipal",
            "userPrincipalName": null,
            "groupType": null,
            "modifiedProperties": [
                modified("ConsentContext.IsAdminConsent", Value::Null, json!("\"True\"")),
                modified("ConsentContext.IsAppOnly", Value::Null, json!("\"False\"")),
                modified("ConsentContext.OnBehalfOfAll", Value::Null, json!("\"True\"")),
                modified("ConsentContext.Tags", Value::Null, json!("\"WindowsAzureActiveDirectoryIntegratedApp\"")),
                modified("ConsentAction.Permissions", Value::Null, json!(permissions)),
                modified("TargetId.ServicePrincipalNames", Value::Null, json!(format!("\"{APP_ID}\"")))
            ]
        }]),
    )
}

fn key(id: &str, key_type: &str, name: &str) -> String {
    format!("[KeyIdentifier={id},KeyType={key_type},KeyUsage=Verify,DisplayName={name}]")
}

fn key_list(keys: &[String]) -> Value {
    json!(serde_json::to_string(keys).unwrap())
}

// Sign-ins

#[test]
fn a_successful_user_sign_in_maps_to_an_authentication_event() {
    let record = user_sign_in();
    let event = sign_in(&record, &source()).unwrap();

    assert_eq!(event.class, EventClass::Authentication);
    assert_eq!(event.action, event::action::SIGN_IN);
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(event.severity, Severity::Informational);
    assert_eq!(
        event.time,
        Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 31).unwrap() + chrono::Duration::milliseconds(500)
    );
    assert_eq!(event.source, source());
    assert_eq!(
        event.actor,
        Actor::new(EntityKind::User, USER_ID)
            .with_name("dana@contoso.example")
            .with_tenant(TENANT)
            .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)))
    );
    assert_eq!(
        event.target,
        Some(EntityRef::new(EntityKind::Application, APP_ID).with_name("Graph Explorer"))
    );
    assert_eq!(
        event.attributes,
        attributes(&[
            (event::attr::APP_ID, json!(APP_ID)),
            (event::attr::APP_NAME, json!("Graph Explorer")),
            (event::attr::AUTH_PROTOCOL, json!("browser")),
            (event::attr::CITY, json!("Bucharest")),
            (event::attr::COUNTRY, json!("RO")),
            (event::attr::LATITUDE, json!(44.43)),
            (event::attr::LONGITUDE, json!(26.1)),
            (attr::CLIENT_APP, json!("browser")),
            (attr::CONDITIONAL_ACCESS_STATUS, json!("not_applied")),
            (
                attr::CORRELATION_ID,
                json!("d79f5bee-5860-4832-928f-3133e22ae912")
            ),
            (attr::INTERACTIVE, json!(true)),
            (attr::RESOURCE_ID, json!(GRAPH_APP_ID)),
            (attr::RESOURCE_NAME, json!("Microsoft Graph")),
        ])
    );
    assert_eq!(event.raw, Some(record));
}

#[test]
fn a_failed_sign_in_has_the_error_code_and_the_failure_reason() {
    let mut record = user_sign_in();
    record["status"] = json!({
        "errorCode": 50126,
        "failureReason": "Error validating credentials due to invalid username or password.",
        "additionalDetails": "The user didn't enter the right credentials."
    });
    record["authenticationProtocol"] = json!("ropc");
    record["userAgent"] = json!("python-httpx/0.27.0");
    let event = sign_in(&record, &source()).unwrap();

    assert_eq!(event.outcome, Outcome::Failure);
    assert_eq!(event.attribute_str(event::attr::ERROR_CODE), Some("50126"));
    assert_eq!(
        event.attribute_str(event::attr::FAILURE_REASON),
        Some("Error validating credentials due to invalid username or password.")
    );
    assert_eq!(
        event.attribute_bool(event::attr::MFA_SATISFIED),
        Some(false)
    );
    assert_eq!(
        event.attribute_str(event::attr::AUTH_PROTOCOL),
        Some("ropc")
    );
    assert_eq!(event.attribute_str(attr::CLIENT_APP), Some("browser"));
    assert_eq!(
        event.actor.user_agent.as_deref(),
        Some("python-httpx/0.27.0")
    );
}

#[test]
fn a_successful_sign_in_has_no_error_code_and_no_failure_reason() {
    let mut record = user_sign_in();
    record["status"] = json!({ "errorCode": 0, "failureReason": "Other." });
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(event.attributes.get(event::attr::ERROR_CODE), None);
    assert_eq!(event.attributes.get(event::attr::FAILURE_REASON), None);
}

#[test]
fn a_sign_in_without_a_status_has_an_unknown_outcome() {
    let mut record = user_sign_in();
    record.as_object_mut().unwrap().remove("status");
    record["authenticationRequirement"] = json!("multiFactorAuthentication");
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.outcome, Outcome::Unknown);
    assert_eq!(event.attributes.get(event::attr::MFA_SATISFIED), None);
}

#[test]
fn a_failed_sign_in_for_an_unknown_account_uses_the_sign_in_name_as_the_actor() {
    let mut first = user_sign_in();
    first["userId"] = json!("00000000-0000-0000-0000-000000000000");
    first["userPrincipalName"] = json!("Nobody.One@Contoso.Example");
    first["status"] =
        json!({ "errorCode": 50034, "failureReason": "The user account does not exist." });
    let mut second = first.clone();
    second["userPrincipalName"] = json!("nobody.two@contoso.example");

    let first = sign_in(&first, &source()).unwrap();
    let second = sign_in(&second, &source()).unwrap();
    assert_eq!(first.actor.kind, EntityKind::User);
    assert_eq!(first.actor.id, "nobody.one@contoso.example");
    assert_eq!(
        first.actor.name.as_deref(),
        Some("Nobody.One@Contoso.Example")
    );
    assert_eq!(second.actor.id, "nobody.two@contoso.example");
}

#[test]
fn a_sign_in_with_no_principal_has_an_unknown_actor() {
    let mut record = user_sign_in();
    for field in ["userId", "userPrincipalName", "userDisplayName"] {
        record.as_object_mut().unwrap().remove(field);
    }
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.actor.kind, EntityKind::Other);
    assert_eq!(event.actor.id, "unknown");
    assert_eq!(event.actor.name, None);
}

#[test]
fn mfa_satisfied_is_present_only_when_the_record_shows_the_answer() {
    let with = |change: fn(&mut Value)| {
        let mut record = user_sign_in();
        change(&mut record);
        sign_in(&record, &source())
            .unwrap()
            .attribute_bool(event::attr::MFA_SATISFIED)
    };

    assert_eq!(with(|_| {}), None, "the v1.0 record gives no answer");
    assert_eq!(
        with(|record| record["authenticationRequirement"] = json!("multiFactorAuthentication")),
        Some(true)
    );
    assert_eq!(
        with(|record| record["authenticationRequirement"] = json!("singleFactorAuthentication")),
        Some(false)
    );
    assert_eq!(
        with(|record| {
            record["mfaDetail"] =
                json!({ "authMethod": "Mobile app notification", "authDetail": null });
        }),
        Some(true)
    );
    assert_eq!(
        with(|record| record["mfaDetail"] = json!({ "authMethod": null, "authDetail": null })),
        None
    );
    assert_eq!(
        with(|record| {
            record["appliedConditionalAccessPolicies"] = json!([
                { "id": "p1", "displayName": "Block legacy", "enforcedGrantControls": ["Block"], "result": "notApplied" },
                { "id": "p2", "displayName": "Require MFA", "enforcedGrantControls": ["Mfa"], "result": "success" }
            ]);
        }),
        Some(true)
    );
    assert_eq!(
        with(|record| {
            record["appliedConditionalAccessPolicies"] = json!([
                { "id": "p2", "displayName": "Require MFA", "enforcedGrantControls": ["Mfa"], "result": "failure" }
            ]);
        }),
        None,
        "a policy that did not succeed is no proof"
    );
    assert_eq!(
        with(|record| {
            record["authenticationRequirement"] = json!("multiFactorAuthentication");
            record["status"] = json!({ "errorCode": 50074, "failureReason": "Strong authentication is required." });
        }),
        Some(false),
        "a failed sign-in did not satisfy MFA"
    );
}

#[test]
fn the_status_detail_of_a_v1_record_shows_that_mfa_was_satisfied() {
    let with = |detail: Value, error_code: i64| {
        let mut record = user_sign_in();
        record["status"] =
            json!({ "errorCode": error_code, "failureReason": null, "additionalDetails": detail });
        sign_in(&record, &source())
            .unwrap()
            .attribute_bool(event::attr::MFA_SATISFIED)
    };

    assert_eq!(with(json!("MFA completed in Azure AD"), 0), Some(true));
    assert_eq!(
        with(json!("MFA requirement satisfied by claim in the token"), 0),
        Some(true)
    );
    assert_eq!(
        with(
            json!("mfa requirement satisfied by strong authentication"),
            0
        ),
        Some(true),
        "the comparison ignores the case"
    );
    assert_eq!(
        with(json!("MFA requirement skipped due to remembered device"), 0),
        None,
        "a skipped requirement is no proof"
    );
    assert_eq!(with(json!("MFA required in Azure AD"), 0), None);
    assert_eq!(with(Value::Null, 0), None);
    assert_eq!(
        with(json!("MFA completed in Azure AD"), 50076),
        Some(false),
        "a failed sign-in did not satisfy MFA"
    );
}

#[test]
fn a_service_principal_sign_in_has_the_principal_as_the_actor_and_the_resource_as_the_target() {
    let record = service_principal_sign_in();
    let event = sign_in(&record, &source()).unwrap();

    assert_eq!(event.action, event::action::SIGN_IN);
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(
        event.actor,
        Actor::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
            .with_name("Sync Helper")
            .with_tenant(TENANT)
            .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51)))
    );
    assert_eq!(
        event.target,
        Some(EntityRef::new(EntityKind::Application, GRAPH_APP_ID).with_name("Microsoft Graph"))
    );
    assert_eq!(
        event.attributes,
        attributes(&[
            (event::attr::APP_ID, json!(APP_ID)),
            (event::attr::APP_NAME, json!("Sync Helper")),
            (event::attr::AUTH_PROTOCOL, json!("client_credentials")),
            (event::attr::CITY, json!("Singapore")),
            (event::attr::COUNTRY, json!("SG")),
            (event::attr::CREDENTIAL_TYPE, json!("password")),
            (event::attr::HOME_TENANT, json!(TENANT)),
            (event::attr::LATITUDE, json!(1.35)),
            (event::attr::LONGITUDE, json!(103.82)),
            (event::attr::MFA_SATISFIED, json!(false)),
            (event::attr::RESOURCE_TENANT, json!(OTHER_TENANT)),
            (attr::CONDITIONAL_ACCESS_STATUS, json!("not_applied")),
            (
                attr::CORRELATION_ID,
                json!("5d295068-919b-4017-85d8-44be2f5f5483")
            ),
            (attr::INTERACTIVE, json!(false)),
            (attr::RESOURCE_ID, json!(GRAPH_APP_ID)),
            (attr::RESOURCE_NAME, json!("Microsoft Graph")),
        ])
    );
}

#[test]
fn the_home_tenant_of_a_guest_is_the_tenant_of_the_actor() {
    let mut record = user_sign_in();
    record["homeTenantId"] = json!(OTHER_TENANT.to_uppercase());
    record["resourceTenantId"] = json!(TENANT);
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.actor.tenant.as_deref(), Some(OTHER_TENANT));
    assert_eq!(
        event.attribute_str(event::attr::HOME_TENANT),
        Some(OTHER_TENANT)
    );
    assert_eq!(
        event.attribute_str(event::attr::RESOURCE_TENANT),
        Some(TENANT)
    );
    assert_eq!(event.source.tenant.as_deref(), Some(TENANT));
}

#[test]
fn a_location_without_coordinates_has_no_latitude_and_no_longitude() {
    let mut record = user_sign_in();
    record["location"] = json!({
        "city": "Redmond",
        "state": "Washington",
        "countryOrRegion": "us",
        "geoCoordinates": {}
    });
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.attribute_str(event::attr::COUNTRY), Some("US"));
    assert_eq!(event.attribute_str(event::attr::CITY), Some("Redmond"));
    assert_eq!(event.attributes.get(event::attr::LATITUDE), None);
    assert_eq!(event.attributes.get(event::attr::LONGITUDE), None);

    record["location"]["geoCoordinates"] = json!({ "latitude": 47.68, "longitude": null });
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.attributes.get(event::attr::LATITUDE), None);
}

#[test]
fn the_address_can_be_ipv6_and_a_value_that_is_not_an_address_is_no_address() {
    let mut record = user_sign_in();
    record["ipAddress"] = json!("2001:db8::17");
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.actor.ip, Some("2001:db8::17".parse().unwrap()));

    record["ipAddress"] = json!("not-an-address");
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.actor.ip, None);
}

#[test]
fn the_risk_level_of_entra_sets_the_severity() {
    let severity = |during: &str, aggregated: &str| {
        let mut record = user_sign_in();
        record["riskLevelDuringSignIn"] = json!(during);
        record["riskLevelAggregated"] = json!(aggregated);
        let event = sign_in(&record, &source()).unwrap();
        (
            event.severity,
            event.attribute_str(attr::RISK_LEVEL).map(str::to_owned),
        )
    };
    assert_eq!(
        severity("high", "none"),
        (Severity::High, Some("high".to_owned()))
    );
    assert_eq!(
        severity("medium", "high"),
        (Severity::Medium, Some("medium".to_owned()))
    );
    assert_eq!(
        severity("none", "low"),
        (Severity::Low, Some("low".to_owned()))
    );
    assert_eq!(severity("hidden", "none"), (Severity::Informational, None));
}

#[test]
fn object_identifiers_are_in_lower_case() {
    let mut record = user_sign_in();
    record["userId"] = json!(USER_ID.to_uppercase());
    record["appId"] = json!(APP_ID.to_uppercase());
    let event = sign_in(&record, &source()).unwrap();
    assert_eq!(event.actor.id, USER_ID);
    assert_eq!(event.attribute_str(event::attr::APP_ID), Some(APP_ID));
    assert_eq!(event.target.unwrap().id, APP_ID);
}

#[test]
fn the_event_identifier_is_the_same_for_the_same_record_and_sorts_by_time() {
    let record = user_sign_in();
    let first = sign_in(&record, &source()).unwrap();
    let again = sign_in(&record, &source()).unwrap();
    assert_eq!(first.id, again.id);
    assert_eq!(first.id.0.get_version_num(), 7);
    let (seconds, nanoseconds) = first.id.0.get_timestamp().unwrap().to_unix();
    assert_eq!(
        (i64::try_from(seconds).unwrap(), nanoseconds),
        (first.time.timestamp(), 500_000_000)
    );

    let mut other_record = record.clone();
    other_record["id"] = json!("77fb65fc-7412-5ff6-cf73-006b860c1211");
    assert_ne!(sign_in(&other_record, &source()).unwrap().id, first.id);

    let other_tenant = EventSource::new("entra-test", VENDOR, PRODUCT).with_tenant(OTHER_TENANT);
    assert_ne!(sign_in(&record, &other_tenant).unwrap().id, first.id);

    let renamed = EventSource::new("renamed", VENDOR, PRODUCT).with_tenant(TENANT);
    assert_eq!(
        sign_in(&record, &renamed).unwrap().id,
        first.id,
        "the connector name does not change the identifier"
    );

    let mut later = record;
    later["createdDateTime"] = json!("2026-11-03T09:10:32Z");
    assert!(sign_in(&later, &source()).unwrap().id > first.id);
}

#[test]
fn a_sign_in_without_an_identifier_or_a_valid_time_is_an_error() {
    let mut no_id = user_sign_in();
    no_id["id"] = json!("  ");
    assert_eq!(
        sign_in(&no_id, &source()),
        Err(NormalizeError::MissingField("id"))
    );

    let mut no_time = user_sign_in();
    no_time.as_object_mut().unwrap().remove("createdDateTime");
    assert_eq!(
        sign_in(&no_time, &source()),
        Err(NormalizeError::MissingField("createdDateTime"))
    );

    let mut bad_time = user_sign_in();
    bad_time["createdDateTime"] = json!("03/11/2026 09:10");
    assert_eq!(
        sign_in(&bad_time, &source()),
        Err(NormalizeError::InvalidTime("createdDateTime"))
    );

    assert_eq!(
        sign_in(&json!(["a"]), &source()),
        Err(NormalizeError::NotAnObject)
    );
    let error: aegis_contracts::Error = NormalizeError::MissingField("id").into();
    assert!(
        matches!(&error, aegis_contracts::Error::Serialization(message) if message == "the record has no id field"),
        "{error}"
    );
}

// Directory audits

#[test]
fn a_consent_to_an_application_maps_to_a_consent_grant_with_the_scopes() {
    let record =
        consent_record("Directory.ReadWrite.All RoleManagement.ReadWrite.Directory offline_access");
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.class, EventClass::UserAccessManagement);
    assert_eq!(event.action, event::action::OAUTH_CONSENT_GRANT);
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(
        event.time,
        Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 46).unwrap()
            + chrono::Duration::nanoseconds(145_824_800)
    );
    assert_eq!(
        event.actor,
        Actor::new(EntityKind::User, ADMIN_ID)
            .with_name("admin@contoso.example")
            .with_tenant(TENANT)
            .with_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)))
            .with_user_agent("python-httpx/0.27.0")
    );
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
                .with_name("Sync Helper")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(
        event.attributes,
        attributes(&[
            (event::attr::APP_ID, json!(APP_ID)),
            (event::attr::APP_NAME, json!("Sync Helper")),
            (event::attr::OPERATION, json!("Consent to application")),
            (event::attr::PRIVILEGED, json!(true)),
            (
                event::attr::SCOPES,
                json!([
                    "Directory.ReadWrite.All",
                    "RoleManagement.ReadWrite.Directory",
                    "offline_access"
                ])
            ),
            (attr::ADMIN_CONSENT, json!(true)),
            (attr::CATEGORY, json!("ApplicationManagement")),
            (
                attr::CORRELATION_ID,
                json!("504a302a-8f2d-418d-b7df-bf77de6ed831")
            ),
        ])
    );
    assert_eq!(event.raw, Some(record));
}

#[test]
fn a_consent_to_low_scopes_is_not_privileged() {
    let event = directory_audit(&consent_record("User.Read openid profile"), &source()).unwrap();
    assert_eq!(event.action, event::action::OAUTH_CONSENT_GRANT);
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(false));
    assert_eq!(
        event.attributes.get(event::attr::SCOPES),
        Some(&json!(["User.Read", "openid", "profile"]))
    );
}

#[test]
fn a_new_service_principal_credential_maps_to_credential_add_with_the_new_key() {
    let old_key = key(
        "0a0a0a0a-1111-4222-8333-444444444444",
        "AsymmetricX509Cert",
        "old cert",
    );
    let new_key = key(
        "5B5B5B5B-6666-4777-8888-999999999999",
        "Password",
        "backdoor, v2",
    );
    let record = audit(
        "Add service principal credentials",
        "ApplicationManagement",
        user_initiator(),
        json!([{
            "id": PRINCIPAL_ID,
            "displayName": "Sync Helper",
            "type": "ServicePrincipal",
            "userPrincipalName": null,
            "groupType": null,
            "modifiedProperties": [
                modified("KeyDescription", key_list(std::slice::from_ref(&old_key)), key_list(&[old_key.clone(), new_key])),
                modified("Included Updated Properties", Value::Null, json!("\"KeyDescription\"")),
                modified("TargetId.ServicePrincipalNames", Value::Null, json!(format!("\"{APP_ID}\"")))
            ]
        }]),
    );
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.class, EventClass::AccountChange);
    assert_eq!(event.action, event::action::APP_CREDENTIAL_ADD);
    assert_eq!(event.actor.id, ADMIN_ID);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
                .with_name("Sync Helper")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(event.attribute_str(event::attr::APP_ID), Some(APP_ID));
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_TYPE),
        Some("password")
    );
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_ID),
        Some("5b5b5b5b-6666-4777-8888-999999999999")
    );
}

/// The real activity name has an en dash and a space at the end.
const UPDATE_APPLICATION_SECRETS: &str =
    "Update application \u{2013} Certificates and secrets management ";

fn application_secret_change(old: &[String], new: &[String]) -> Value {
    let mut record = audit(
        UPDATE_APPLICATION_SECRETS,
        "ApplicationManagement",
        user_initiator(),
        json!([{
            "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "displayName": "Sync Helper",
            "type": "Application",
            "userPrincipalName": null,
            "groupType": null,
            "modifiedProperties": [
                modified("KeyDescription", key_list(old), key_list(new)),
                modified("Included Updated Properties", Value::Null, json!("\"KeyDescription\""))
            ]
        }]),
    );
    record["additionalDetails"] = json!([
        { "key": "User-Agent", "value": "Mozilla/5.0" },
        { "key": "AppId", "value": APP_ID }
    ]);
    record
}

#[test]
fn a_new_application_secret_maps_to_credential_add() {
    let certificate = key(
        "0a0a0a0a-1111-4222-8333-444444444444",
        "AsymmetricX509Cert",
        "cert",
    );
    let record = application_secret_change(&[], std::slice::from_ref(&certificate));
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.class, EventClass::AccountChange);
    assert_eq!(event.action, event::action::APP_CREDENTIAL_ADD);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(
                EntityKind::Application,
                "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
            )
            .with_name("Sync Helper")
            .with_tenant(TENANT)
        )
    );
    assert_eq!(event.attribute_str(event::attr::APP_ID), Some(APP_ID));
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_TYPE),
        Some("certificate")
    );
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_ID),
        Some("0a0a0a0a-1111-4222-8333-444444444444")
    );
    assert_eq!(
        event.attribute_str(event::attr::OPERATION),
        Some("Update application \u{2013} Certificates and secrets management")
    );
}

#[test]
fn a_removed_application_secret_maps_to_credential_remove() {
    let kept = key(
        "0a0a0a0a-1111-4222-8333-444444444444",
        "AsymmetricX509Cert",
        "cert",
    );
    let removed = key("5b5b5b5b-6666-4777-8888-999999999999", "Password", "old");
    let record = application_secret_change(&[kept.clone(), removed], &[kept]);
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.action, event::action::APP_CREDENTIAL_REMOVE);
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_ID),
        Some("5b5b5b5b-6666-4777-8888-999999999999")
    );
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_TYPE),
        Some("password")
    );
}

#[test]
fn an_application_secret_change_without_key_data_maps_to_credential_add() {
    let mut record = application_secret_change(&[], &[]);
    record["targetResources"][0]["modifiedProperties"] = json!([]);
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.action, event::action::APP_CREDENTIAL_ADD);
    assert_eq!(event.attributes.get(event::attr::CREDENTIAL_ID), None);
}

#[test]
fn a_removed_service_principal_credential_maps_to_credential_remove() {
    let removed = key("5b5b5b5b-6666-4777-8888-999999999999", "Password", "old");
    let record = audit(
        "Remove service principal credentials",
        "ApplicationManagement",
        user_initiator(),
        json!([{
            "id": PRINCIPAL_ID,
            "displayName": "Sync Helper",
            "type": "ServicePrincipal",
            "modifiedProperties": [
                modified("KeyDescription", key_list(&[removed]), key_list(&[]))
            ]
        }]),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::AccountChange);
    assert_eq!(event.action, event::action::APP_CREDENTIAL_REMOVE);
    assert_eq!(
        event.attribute_str(event::attr::CREDENTIAL_ID),
        Some("5b5b5b5b-6666-4777-8888-999999999999")
    );
}

#[test]
fn a_privileged_role_for_a_user_maps_to_role_assign() {
    let record = audit(
        "Add member to role",
        "RoleManagement",
        user_initiator(),
        role_targets(
            "User",
            USER_ID,
            "Global Administrator",
            GLOBAL_ADMINISTRATOR,
        ),
    );
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.class, EventClass::UserAccessManagement);
    assert_eq!(event.action, event::action::ROLE_ASSIGN);
    assert_eq!(event.actor.kind, EntityKind::User);
    assert_eq!(event.actor.id, ADMIN_ID);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::User, USER_ID)
                .with_name("dana@contoso.example")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(
        event.attributes,
        attributes(&[
            (event::attr::OPERATION, json!("Add member to role")),
            (event::attr::PRIVILEGED, json!(true)),
            (event::attr::ROLE_ID, json!(GLOBAL_ADMINISTRATOR)),
            (event::attr::ROLE_NAME, json!("Global Administrator")),
            (attr::CATEGORY, json!("RoleManagement")),
            (
                attr::CORRELATION_ID,
                json!("504a302a-8f2d-418d-b7df-bf77de6ed831")
            ),
        ])
    );
}

#[test]
fn a_service_principal_that_assigns_a_privileged_role_to_itself_is_actor_and_target() {
    // The two fields of the record write the same GUID with a different case.
    let record = audit(
        "Add member to role",
        "RoleManagement",
        app_initiator(&PRINCIPAL_ID.to_uppercase()),
        role_targets(
            "ServicePrincipal",
            PRINCIPAL_ID,
            "Privileged Role Administrator",
            "e8611ab8-c189-46e8-94e1-60213ab1f814",
        ),
    );
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.action, event::action::ROLE_ASSIGN);
    assert_eq!(event.actor.kind, EntityKind::ServicePrincipal);
    assert_eq!(event.actor.id, PRINCIPAL_ID);
    let target = event.target.clone().unwrap();
    assert_eq!(target.kind, EntityKind::ServicePrincipal);
    assert_eq!(target.id, event.actor.id);
    assert_eq!(target, event.actor.entity());
    assert_eq!(event.actor.name.as_deref(), Some("Sync Helper"));
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(true));
    assert_eq!(
        event.attribute_str(event::attr::ROLE_NAME),
        Some("Privileged Role Administrator")
    );
    assert_eq!(
        event.attribute_str(event::attr::ROLE_ID),
        Some("e8611ab8-c189-46e8-94e1-60213ab1f814")
    );
    assert_eq!(event.attribute_str(event::attr::APP_ID), Some(APP_ID));
}

#[test]
fn a_service_principal_that_assigns_a_role_to_a_different_principal_is_not_the_target() {
    let record = audit(
        "Add member to role",
        "RoleManagement",
        app_initiator(GRAPH_PRINCIPAL_ID),
        role_targets(
            "ServicePrincipal",
            PRINCIPAL_ID,
            "Global Administrator",
            GLOBAL_ADMINISTRATOR,
        ),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.actor.id, GRAPH_PRINCIPAL_ID);
    assert_eq!(event.target.as_ref().unwrap().id, PRINCIPAL_ID);
    assert_eq!(
        event.attributes.get(event::attr::APP_ID),
        None,
        "the application of the initiator is not the application of the target"
    );
}

#[test]
fn a_role_that_is_not_privileged_maps_to_role_assign_without_the_privileged_flag() {
    let mut targets = role_targets(
        "User",
        USER_ID,
        "Directory Readers",
        "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
    );
    targets[0]["modifiedProperties"]
        .as_array_mut()
        .unwrap()
        .retain(|property| property["displayName"] != "Role.WellKnownObjectName");
    let record = audit(
        "Add member to role",
        "RoleManagement",
        user_initiator(),
        targets,
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.action, event::action::ROLE_ASSIGN);
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(false));
    assert_eq!(
        event.attribute_str(event::attr::ROLE_NAME),
        Some("Directory Readers")
    );
}

#[test]
fn a_completed_pim_activation_maps_to_role_assign_with_the_role_resource() {
    let mut record = audit(
        "Add member to role completed (PIM activation)",
        "RoleManagement",
        user_initiator(),
        json!([
            { "id": GLOBAL_ADMINISTRATOR, "displayName": "Global Administrator", "type": "Role", "modifiedProperties": [] },
            { "id": "2b1e7a55-0c41-4d0a-8e6b-1f7c3a9d4e22", "displayName": null, "type": "Request", "modifiedProperties": [] },
            { "id": USER_ID, "displayName": "Dana Example", "type": "User", "userPrincipalName": "dana@contoso.example", "modifiedProperties": [] },
            { "id": TENANT, "displayName": "Contoso", "type": "Directory", "modifiedProperties": [] }
        ]),
    );
    record["loggedByService"] = json!("PIM");
    let event = directory_audit(&record, &source()).unwrap();

    assert_eq!(event.action, event::action::ROLE_ASSIGN);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::User, USER_ID)
                .with_name("dana@contoso.example")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(
        event.attribute_str(event::attr::ROLE_ID),
        Some(GLOBAL_ADMINISTRATOR)
    );
    assert_eq!(
        event.attribute_str(event::attr::ROLE_NAME),
        Some("Global Administrator")
    );
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(true));
}

#[test]
fn a_removed_role_maps_to_role_remove_with_the_role_from_the_old_values() {
    let record = audit(
        "Remove member from role",
        "RoleManagement",
        user_initiator(),
        json!([
            {
                "id": USER_ID,
                "displayName": null,
                "type": "User",
                "userPrincipalName": "dana@contoso.example",
                "modifiedProperties": [
                    modified("Role.ObjectID", json!("\"0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01\""), Value::Null),
                    modified("Role.DisplayName", json!("\"Application Administrator\""), Value::Null),
                    modified("Role.TemplateId", json!("\"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3\""), Value::Null)
                ]
            },
            { "id": "0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01", "displayName": null, "type": "Role", "modifiedProperties": [] }
        ]),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::UserAccessManagement);
    assert_eq!(event.action, event::action::ROLE_REMOVE);
    assert_eq!(event.target.unwrap().id, USER_ID);
    assert_eq!(
        event.attributes.get(event::attr::ROLE_ID),
        Some(&json!("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"))
    );
    assert_eq!(
        event.attributes.get(event::attr::ROLE_NAME),
        Some(&json!("Application Administrator"))
    );
    assert_eq!(
        event.attributes.get(event::attr::PRIVILEGED),
        Some(&json!(true))
    );
}

fn app_role_assignment(permission: &str) -> Value {
    audit(
        "Add app role assignment to service principal",
        "ApplicationManagement",
        user_initiator(),
        json!([
            {
                "id": GRAPH_PRINCIPAL_ID,
                "displayName": "Microsoft Graph",
                "type": "ServicePrincipal",
                "userPrincipalName": null,
                "groupType": null,
                "modifiedProperties": [
                    modified("AppRole.Id", Value::Null, json!("\"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8\"")),
                    modified("AppRole.Value", Value::Null, json!(format!("\"{permission}\""))),
                    modified("AppRole.DisplayName", Value::Null, json!("\"Read and write all directory RBAC settings\"")),
                    modified("AppRoleAssignment.CreatedDateTime", Value::Null, json!("\"2026-11-03T09:10:46.1458248Z\"")),
                    modified("ServicePrincipal.ObjectID", Value::Null, json!(format!("\"{}\"", PRINCIPAL_ID.to_uppercase()))),
                    modified("ServicePrincipal.DisplayName", Value::Null, json!("\"Sync Helper\"")),
                    modified("ServicePrincipal.AppId", Value::Null, json!(format!("\"{APP_ID}\""))),
                    modified("ServicePrincipal.Name", Value::Null, json!(format!("\"{APP_ID}\""))),
                    modified(
                        "TargetId.ServicePrincipalNames",
                        Value::Null,
                        json!(format!("\"{GRAPH_APP_ID}/ags.windows.net;{GRAPH_APP_ID};https://graph.microsoft.com\""))
                    )
                ]
            },
            {
                "id": PRINCIPAL_ID,
                "displayName": "Sync Helper",
                "type": "ServicePrincipal",
                "userPrincipalName": null,
                "groupType": null,
                "modifiedProperties": []
            }
        ]),
    )
}

#[test]
fn an_app_role_assignment_maps_to_a_permission_grant_for_the_assignee() {
    let event = directory_audit(
        &app_role_assignment("RoleManagement.ReadWrite.Directory"),
        &source(),
    )
    .unwrap();

    assert_eq!(event.class, EventClass::UserAccessManagement);
    assert_eq!(event.action, event::action::APP_PERMISSION_GRANT);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
                .with_name("Sync Helper")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(
        event.attributes,
        attributes(&[
            (event::attr::APP_ID, json!(APP_ID)),
            (event::attr::APP_NAME, json!("Sync Helper")),
            (
                event::attr::OPERATION,
                json!("Add app role assignment to service principal")
            ),
            (event::attr::PRIVILEGED, json!(true)),
            (
                event::attr::ROLE_ID,
                json!("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8")
            ),
            (
                event::attr::ROLE_NAME,
                json!("RoleManagement.ReadWrite.Directory")
            ),
            (
                event::attr::SCOPES,
                json!(["RoleManagement.ReadWrite.Directory"])
            ),
            (attr::CATEGORY, json!("ApplicationManagement")),
            (
                attr::CORRELATION_ID,
                json!("504a302a-8f2d-418d-b7df-bf77de6ed831")
            ),
            (attr::RESOURCE_ID, json!(GRAPH_PRINCIPAL_ID)),
            (attr::RESOURCE_NAME, json!("Microsoft Graph")),
        ])
    );
}

#[test]
fn an_app_role_assignment_of_a_low_permission_is_not_privileged() {
    let event = directory_audit(&app_role_assignment("User.Read.All"), &source()).unwrap();
    assert_eq!(event.action, event::action::APP_PERMISSION_GRANT);
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(false));
    assert_eq!(
        event.attribute_str(event::attr::ROLE_NAME),
        Some("User.Read.All")
    );
}

#[test]
fn an_app_role_assignment_without_the_assignee_property_uses_the_second_target() {
    let mut record = app_role_assignment("Mail.Read");
    record["targetResources"][0]["modifiedProperties"]
        .as_array_mut()
        .unwrap()
        .retain(|property| property["displayName"] != "ServicePrincipal.ObjectID");
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.target.as_ref().unwrap().id, PRINCIPAL_ID);
    assert_eq!(event.attribute_bool(event::attr::PRIVILEGED), Some(true));
}

#[test]
fn a_new_service_principal_maps_to_service_principal_create() {
    let record = audit(
        "Add service principal",
        "ApplicationManagement",
        user_initiator(),
        json!([{
            "id": PRINCIPAL_ID,
            "displayName": "Sync Helper",
            "type": "ServicePrincipal",
            "userPrincipalName": null,
            "groupType": null,
            "modifiedProperties": [
                modified("AccountEnabled", json!("[]"), json!("[true]")),
                modified("AppPrincipalId", json!("[]"), json!(format!("[\"{APP_ID}\"]"))),
                modified("DisplayName", json!("[]"), json!("[\"Sync Helper\"]")),
                modified("ServicePrincipalName", json!("[]"), json!(format!("[\"{APP_ID}\"]"))),
                modified("Included Updated Properties", Value::Null, json!("\"AccountEnabled, AppPrincipalId, DisplayName\""))
            ]
        }]),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::EntityManagement);
    assert_eq!(event.action, event::action::SERVICE_PRINCIPAL_CREATE);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
                .with_name("Sync Helper")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(event.attribute_str(event::attr::APP_ID), Some(APP_ID));
    assert_eq!(
        event.attribute_str(event::attr::APP_NAME),
        Some("Sync Helper")
    );
}

#[test]
fn a_new_user_maps_to_user_create() {
    let record = audit(
        "Add user",
        "UserManagement",
        user_initiator(),
        json!([{
            "id": USER_ID,
            "displayName": null,
            "type": "User",
            "userPrincipalName": "dana@contoso.example",
            "groupType": null,
            "modifiedProperties": [
                modified("AccountEnabled", json!("[]"), json!("[true]")),
                modified("UserPrincipalName", json!("[]"), json!("[\"dana@contoso.example\"]")),
                modified("UserType", json!("[]"), json!("[\"Member\"]"))
            ]
        }]),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::AccountChange);
    assert_eq!(event.action, event::action::USER_CREATE);
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::User, USER_ID)
                .with_name("dana@contoso.example")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(event.attributes.get(event::attr::APP_ID), None);
}

#[test]
fn each_known_activity_maps_to_its_action_and_class() {
    let user_target =
        json!([{ "id": USER_ID, "type": "User", "userPrincipalName": "dana@contoso.example" }]);
    let cases = [
        (
            "Reset user password",
            event::action::USER_PASSWORD_RESET,
            EventClass::AccountChange,
        ),
        (
            "Reset password (by admin)",
            event::action::USER_PASSWORD_RESET,
            EventClass::AccountChange,
        ),
        (
            "Reset password (self-service)",
            event::action::USER_PASSWORD_RESET,
            EventClass::AccountChange,
        ),
        (
            "Change user password",
            event::action::USER_PASSWORD_RESET,
            EventClass::AccountChange,
        ),
        (
            "Change password (self-service)",
            event::action::USER_PASSWORD_RESET,
            EventClass::AccountChange,
        ),
        (
            "Update user",
            event::action::USER_UPDATE,
            EventClass::AccountChange,
        ),
        (
            "Add user",
            event::action::USER_CREATE,
            EventClass::AccountChange,
        ),
        (
            "User registered security info",
            event::action::MFA_METHOD_CHANGE,
            EventClass::AccountChange,
        ),
        (
            "Admin deleted security info",
            event::action::MFA_METHOD_CHANGE,
            EventClass::AccountChange,
        ),
        (
            "Add application",
            event::action::APP_CREATE,
            EventClass::EntityManagement,
        ),
        (
            "Add service principal",
            event::action::SERVICE_PRINCIPAL_CREATE,
            EventClass::EntityManagement,
        ),
        (
            "ADD MEMBER TO ROLE",
            event::action::ROLE_ASSIGN,
            EventClass::UserAccessManagement,
        ),
        (
            "Add eligible member to role",
            event::action::ROLE_ASSIGN,
            EventClass::UserAccessManagement,
        ),
        (
            "Add scoped member to role",
            event::action::ROLE_ASSIGN,
            EventClass::UserAccessManagement,
        ),
        (
            "Add member to role outside of PIM (permanent)",
            event::action::ROLE_ASSIGN,
            EventClass::UserAccessManagement,
        ),
        (
            "Add member to role in PIM completed (timebound)",
            event::action::ROLE_ASSIGN,
            EventClass::UserAccessManagement,
        ),
        (
            "Remove member from role",
            event::action::ROLE_REMOVE,
            EventClass::UserAccessManagement,
        ),
        (
            "Remove member from role (PIM activation expired)",
            event::action::ROLE_REMOVE,
            EventClass::UserAccessManagement,
        ),
        (
            "Consent to application",
            event::action::OAUTH_CONSENT_GRANT,
            EventClass::UserAccessManagement,
        ),
        (
            "Add app role assignment to service principal",
            event::action::APP_PERMISSION_GRANT,
            EventClass::UserAccessManagement,
        ),
        (
            "Add service principal credentials",
            event::action::APP_CREDENTIAL_ADD,
            EventClass::AccountChange,
        ),
        (
            "Remove service principal credentials",
            event::action::APP_CREDENTIAL_REMOVE,
            EventClass::AccountChange,
        ),
        (
            "Update application - Certificates and secrets management",
            event::action::APP_CREDENTIAL_ADD,
            EventClass::AccountChange,
        ),
        // A request and a cancellation do not change the access.
        (
            "Add member to role requested (PIM activation)",
            "add.member.to.role.requested.pim.activation",
            EventClass::Other,
        ),
        (
            "Add member to role canceled (PIM activation)",
            "add.member.to.role.canceled.pim.activation",
            EventClass::Other,
        ),
        (
            "Add member to role request denied (PIM activation)",
            "add.member.to.role.request.denied.pim.activation",
            EventClass::Other,
        ),
        (
            "Update application",
            "update.application",
            EventClass::Other,
        ),
        (
            "Add member to group",
            "add.member.to.group",
            EventClass::Other,
        ),
        // Entra ID writes this record and "Consent to application" for one consent.
        (
            "Add delegated permission grant",
            "add.delegated.permission.grant",
            EventClass::Other,
        ),
        (
            "Update conditional access policy",
            "update.conditional.access.policy",
            EventClass::Other,
        ),
    ];
    for (activity, action, class) in cases {
        let record = audit(activity, "Category", user_initiator(), user_target.clone());
        let event = directory_audit(&record, &source()).unwrap();
        assert_eq!(
            (event.action.as_str(), event.class),
            (action, class),
            "{activity}"
        );
        assert_eq!(event.attribute_str(event::attr::OPERATION), Some(activity));
    }
}

#[test]
fn an_unknown_activity_keeps_the_first_target_and_the_record() {
    let record = audit(
        "Update conditional access policy",
        "Policy",
        user_initiator(),
        json!([{ "id": "c0ffee00-1111-4222-8333-444455556666", "displayName": "Require MFA", "type": "Policy", "modifiedProperties": [] }]),
    );
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::Other);
    assert_eq!(event.action, "update.conditional.access.policy");
    assert_eq!(
        event.target,
        Some(
            EntityRef::new(EntityKind::Other, "c0ffee00-1111-4222-8333-444455556666")
                .with_name("Require MFA")
                .with_tenant(TENANT)
        )
    );
    assert_eq!(event.raw, Some(record));
}

#[test]
fn an_action_from_an_activity_is_lower_case_with_dots() {
    assert_eq!(
        action_from_activity("Set Company Information"),
        "set.company.information"
    );
    assert_eq!(
        action_from_activity("  Disable/pause provisioning configuration "),
        "disable.pause.provisioning.configuration"
    );
    assert_eq!(action_from_activity("Hard Delete user"), "hard.delete.user");
    assert_eq!(
        action_from_activity("Mise à jour — Stratégie"),
        "mise.à.jour.stratégie"
    );
    assert_eq!(action_from_activity(" -- "), "unknown");
    assert_eq!(action_from_activity(""), "unknown");
}

#[test]
fn the_result_of_the_record_sets_the_outcome_and_the_failure_reason() {
    let outcome = |result: Value, reason: &str| {
        let mut record = audit("Add user", "UserManagement", user_initiator(), json!([]));
        record["result"] = result;
        record["resultReason"] = json!(reason);
        let event = directory_audit(&record, &source()).unwrap();
        (
            event.outcome,
            event
                .attribute_str(event::attr::FAILURE_REASON)
                .map(str::to_owned),
        )
    };
    assert_eq!(outcome(json!("success"), ""), (Outcome::Success, None));
    assert_eq!(
        outcome(json!("success"), "ignored for a success"),
        (Outcome::Success, None)
    );
    assert_eq!(
        outcome(
            json!("failure"),
            "Insufficient privileges to complete the operation."
        ),
        (
            Outcome::Failure,
            Some("Insufficient privileges to complete the operation.".to_owned())
        )
    );
    assert_eq!(outcome(json!("timeout"), ""), (Outcome::Failure, None));
    assert_eq!(
        outcome(json!("unknownFutureValue"), ""),
        (Outcome::Unknown, None)
    );
    assert_eq!(outcome(Value::Null, ""), (Outcome::Unknown, None));
}

#[test]
fn the_initiator_can_be_an_application_with_or_without_identifiers() {
    let actor = |initiated_by: Value| {
        let record = audit("Update user", "UserManagement", initiated_by, json!([]));
        directory_audit(&record, &source()).unwrap().actor
    };

    let principal = actor(app_initiator(PRINCIPAL_ID));
    assert_eq!(
        principal,
        Actor::new(EntityKind::ServicePrincipal, PRINCIPAL_ID)
            .with_name("Sync Helper")
            .with_tenant(TENANT)
            .with_user_agent("python-httpx/0.27.0")
    );

    let application = actor(json!({
        "user": null,
        "app": { "appId": APP_ID.to_uppercase(), "displayName": "Sync Helper", "servicePrincipalId": null }
    }));
    assert_eq!(
        (application.kind, application.id.as_str()),
        (EntityKind::Application, APP_ID)
    );

    let service = actor(json!({
        "user": null,
        "app": { "appId": null, "displayName": "Microsoft Entra Connect", "servicePrincipalId": null }
    }));
    assert_eq!(
        (service.kind, service.id.as_str(), service.name.as_deref()),
        (
            EntityKind::Other,
            "Microsoft Entra Connect",
            Some("Microsoft Entra Connect")
        )
    );

    let nobody = actor(json!({ "user": null, "app": null }));
    assert_eq!(
        (nobody.kind, nobody.id.as_str()),
        (EntityKind::Other, "unknown")
    );
    assert_eq!(nobody.tenant.as_deref(), Some(TENANT));

    let guest = actor(json!({
        "app": null,
        "user": { "id": ADMIN_ID, "userPrincipalName": "guest@fabrikam.example", "homeTenantId": OTHER_TENANT }
    }));
    assert_eq!(guest.tenant.as_deref(), Some(OTHER_TENANT));

    let name_only = actor(json!({
        "app": null,
        "user": { "id": null, "userPrincipalName": "Sync@Contoso.Example" }
    }));
    assert_eq!(
        (name_only.kind, name_only.id.as_str()),
        (EntityKind::User, "sync@contoso.example")
    );
}

#[test]
fn a_directory_audit_without_an_identifier_or_a_valid_time_is_an_error() {
    let mut no_id = audit("Add user", "UserManagement", user_initiator(), json!([]));
    no_id.as_object_mut().unwrap().remove("id");
    assert_eq!(
        directory_audit(&no_id, &source()),
        Err(NormalizeError::MissingField("id"))
    );

    let mut bad_time = audit("Add user", "UserManagement", user_initiator(), json!([]));
    bad_time["activityDateTime"] = json!(1_793_696_400);
    assert_eq!(
        directory_audit(&bad_time, &source()),
        Err(NormalizeError::MissingField("activityDateTime"))
    );
    bad_time["activityDateTime"] = json!("today");
    assert_eq!(
        directory_audit(&bad_time, &source()),
        Err(NormalizeError::InvalidTime("activityDateTime"))
    );
    assert_eq!(
        directory_audit(&json!("text"), &source()),
        Err(NormalizeError::NotAnObject)
    );
}

#[test]
fn a_record_with_no_activity_and_no_targets_still_becomes_an_event() {
    let record = json!({
        "id": "Directory_1",
        "activityDateTime": "2026-11-03T09:10:46Z"
    });
    let event = directory_audit(&record, &source()).unwrap();
    assert_eq!(event.class, EventClass::Other);
    assert_eq!(event.action, "unknown");
    assert_eq!(event.outcome, Outcome::Unknown);
    assert_eq!(event.target, None);
    assert_eq!(event.actor.id, "unknown");
}

#[test]
fn sign_in_and_audit_records_with_the_same_identifier_have_different_event_identifiers() {
    let mut sign_in_record = user_sign_in();
    sign_in_record["id"] = json!("shared-id");
    sign_in_record["createdDateTime"] = json!("2026-11-03T09:10:46Z");
    let audit_record = json!({ "id": "shared-id", "activityDateTime": "2026-11-03T09:10:46Z" });
    assert_ne!(
        sign_in(&sign_in_record, &source()).unwrap().id,
        directory_audit(&audit_record, &source()).unwrap().id
    );
}

// Privileged roles and permissions

#[test]
fn the_well_known_privileged_roles_are_privileged_by_name_and_by_template() {
    let roles = [
        (
            "Global Administrator",
            "62e90394-69f5-4237-9190-012177145e10",
        ),
        (
            "Privileged Role Administrator",
            "e8611ab8-c189-46e8-94e1-60213ab1f814",
        ),
        (
            "Application Administrator",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        ),
        (
            "Cloud Application Administrator",
            "158c047a-c907-4556-b7ef-446551a6b5f7",
        ),
        (
            "Privileged Authentication Administrator",
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        ),
        ("User Administrator", "fe930be7-5e62-47db-91af-98c3a49a38b1"),
    ];
    for (name, template_id) in roles {
        assert!(is_privileged_role(None, Some(name)), "{name}");
        assert!(is_privileged_role(Some(template_id), None), "{name}");
        assert!(
            is_privileged_role(Some(&template_id.to_uppercase()), Some("renamed")),
            "{name}"
        );
        assert!(
            is_privileged_role(
                Some("0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01"),
                Some(&name.to_lowercase())
            ),
            "{name}"
        );
    }
    assert!(is_privileged_role(None, Some("Company Administrator")));
    assert!(is_privileged_role(None, Some(" Global Administrator ")));
}

#[test]
fn other_roles_are_not_privileged() {
    assert!(!is_privileged_role(None, None));
    assert!(!is_privileged_role(
        Some("88d8e3e3-8f55-4a1e-953a-9b9898b8876b"),
        Some("Directory Readers")
    ));
    assert!(!is_privileged_role(Some(""), Some("")));
    assert!(!is_privileged_role(
        None,
        Some("Global Administrator (custom copy)")
    ));
}

#[test]
fn directory_and_mail_permissions_are_privileged_and_basic_permissions_are_not() {
    for permission in [
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "mail.readwrite",
        " Mail.Send ",
        "full_access_as_app",
    ] {
        assert!(is_privileged_permission(permission), "{permission}");
    }
    for permission in [
        "User.Read",
        "openid",
        "offline_access",
        "profile",
        "User.Read.All",
        "",
    ] {
        assert!(!is_privileged_permission(permission), "{permission}");
    }
}

// Helpers

#[test]
fn a_modified_property_value_is_decoded_from_its_json_text() {
    assert_eq!(
        decode_property("\"Global Administrator\""),
        Some("Global Administrator".to_owned())
    );
    assert_eq!(
        decode_property("[\"first\",\"second\"]"),
        Some("first".to_owned())
    );
    assert_eq!(decode_property("[true]"), Some("true".to_owned()));
    assert_eq!(decode_property("plain text"), Some("plain text".to_owned()));
    assert_eq!(
        decode_property("\"unterminated"),
        Some("unterminated".to_owned())
    );
    assert_eq!(decode_property("[]"), None);
    assert_eq!(decode_property("\"\""), None);
    assert_eq!(decode_property("null"), None);
    assert_eq!(decode_property("  "), None);
}

#[test]
fn key_descriptions_give_the_identifier_and_the_type_of_each_credential() {
    let value = serde_json::to_string(&[
        key(
            "0A0A0A0A-1111-4222-8333-444444444444",
            "AsymmetricX509Cert",
            "cert, primary",
        ),
        key("5b5b5b5b-6666-4777-8888-999999999999", "Password", "secret"),
        key(
            "c0c0c0c0-aaaa-4bbb-8ccc-dddddddddddd",
            "Symmetric",
            "legacy",
        ),
    ])
    .unwrap();
    assert_eq!(
        key_entries(Some(&value)),
        [
            KeyEntry {
                id: Some("0a0a0a0a-1111-4222-8333-444444444444".to_owned()),
                key_type: Some("certificate".to_owned()),
            },
            KeyEntry {
                id: Some("5b5b5b5b-6666-4777-8888-999999999999".to_owned()),
                key_type: Some("password".to_owned()),
            },
            KeyEntry {
                id: Some("c0c0c0c0-aaaa-4bbb-8ccc-dddddddddddd".to_owned()),
                key_type: Some("symmetric_key".to_owned()),
            },
        ]
    );
    assert_eq!(key_entries(Some("[]")), []);
    assert_eq!(key_entries(None), []);
    assert_eq!(
        key_entries(Some("[KeyIdentifier=abc]")),
        [KeyEntry {
            id: Some("abc".to_owned()),
            key_type: None
        }]
    );
}

#[test]
fn consent_scopes_come_only_from_the_new_grants() {
    let value = "[[Id: a, ClientId: b, ConsentType: Principal, Scope: Files.Read, CreatedDateTime: ]] => \
                 [[Id: c, ClientId: b, ConsentType: Principal, Scope: User.Read Mail.Read, CreatedDateTime: ], \
                 [Id: d, ClientId: b, ConsentType: Principal, Scope: mail.read Calendars.Read]]; ";
    assert_eq!(
        consent_scopes(value),
        ["User.Read", "Mail.Read", "Calendars.Read"]
    );
    assert_eq!(consent_scopes("[] => []; "), Vec::<String>::new());
    assert_eq!(consent_scopes("Scope: openid"), ["openid"]);
}

#[test]
fn graph_values_change_to_snake_case() {
    assert_eq!(snake_case("deviceCode"), "device_code");
    assert_eq!(snake_case("oAuth2"), "oauth2");
    assert_eq!(snake_case("ropc"), "ropc");
    assert_eq!(snake_case("wsFederation"), "ws_federation");
    assert_eq!(snake_case("saml20"), "saml20");
    assert_eq!(snake_case("notApplied"), "not_applied");
    assert_eq!(
        snake_case("Mobile Apps and Desktop clients"),
        "mobile_apps_and_desktop_clients"
    );
    assert_eq!(snake_case("IMAP4"), "imap4");
    assert_eq!(snake_case(" Authenticated SMTP "), "authenticated_smtp");
}

#[test]
fn the_first_guid_of_a_name_list_is_the_application_identifier() {
    assert_eq!(
        first_guid(
            "00000003-0000-0000-C000-000000000000/ags.windows.net;https://graph.microsoft.com"
        ),
        Some(GRAPH_APP_ID.to_owned())
    );
    assert_eq!(first_guid("https://example.com; api://sync-helper"), None);
    assert_eq!(
        first_guid(&format!("api://x, {APP_ID}")),
        Some(APP_ID.to_owned())
    );
}
