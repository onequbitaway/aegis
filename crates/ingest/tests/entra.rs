//! Integration tests for [`EntraSource`] against a mock of the token service and of
//! Microsoft Graph.
//!
//! The mock server listens on a loopback address. The tests use no real tenant. All
//! identifiers, names, and secrets are examples.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_contracts::bus::MessageBus;
use aegis_contracts::common::{EntityKind, TimeRange};
use aegis_contracts::event::{EventClass, Outcome, action, attr};
use aegis_contracts::source::{EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use aegis_ingest::{
    CheckpointStore, EntraConfig, EntraSource, IngestRunner, MemoryCheckpointStore, RunOutcome,
};
use aegis_testkit::MemoryBus;
use chrono::{DateTime, DurationRound, SecondsFormat, TimeDelta, Utc};
use futures::StreamExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TENANT: &str = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
const CLIENT_ID: &str = "11111111-2222-3333-4444-555555555555";
const SECRET: &str = "example-client-secret/+=";
const TOKEN: &str = "example-access-token-1";
const SIGN_INS: &str = "/v1.0/auditLogs/signIns";
const PRINCIPAL_SIGN_INS: &str = "/beta/auditLogs/signIns";
const AUDITS: &str = "/v1.0/auditLogs/directoryAudits";
const PRINCIPAL_ID: &str = "7c2e9a40-51d3-4b9e-9f7a-3e1f0c6d2b55";

/// The longest time that a test waits for one batch.
const LIMIT: Duration = Duration::from_secs(20);

fn token_path() -> String {
    format!("/{TENANT}/oauth2/v2.0/token")
}

/// A configuration that sends all requests to the mock server.
fn config(server: &MockServer) -> EntraConfig {
    config_at(&server.uri())
}

/// A configuration that sends all requests to the base URL `base`.
fn config_at(base: &str) -> EntraConfig {
    let mut config = EntraConfig::new("entra-test", TENANT, CLIENT_ID, SecretString::from(SECRET));
    config.login_base = base.to_owned();
    config.graph_base = base.to_owned();
    config.poll_interval = Duration::from_millis(10);
    config.lookback = Duration::ZERO;
    config.request_timeout = Duration::from_secs(10);
    config
}

fn sign_ins_only(server: &MockServer) -> EntraConfig {
    let mut config = config(server);
    config.directory_audits = false;
    config
}

fn token_response(token: &str, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "token_type": "Bearer",
        "expires_in": expires_in,
        "ext_expires_in": expires_in,
        "access_token": token
    }))
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(token_response(TOKEN, 3599))
        .mount(server)
        .await;
}

fn page(records: &[Value], next_link: Option<String>) -> ResponseTemplate {
    let mut body = json!({
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
        "value": records
    });
    if let Some(link) = next_link {
        body["@odata.nextLink"] = json!(link);
    }
    ResponseTemplate::new(200).set_body_json(body)
}

fn graph_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({
        "error": {
            "code": code,
            "message": "An example message that the connector must not copy.",
            "innerError": { "date": "2026-11-03T09:00:00", "request-id": "5d295068-919b-4017-85d8-44be2f5f5483" }
        }
    }))
}

/// Responds with each template one time, in order, and then with `rest`.
fn sequence(first: Vec<ResponseTemplate>, rest: ResponseTemplate) -> impl Respond {
    let queue = Mutex::new(VecDeque::from(first));
    move |_: &Request| {
        queue
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| rest.clone())
    }
}

fn graph_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn filter_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// A time in the last minutes, in whole seconds. The live stream reads it in one range.
fn recent(minutes_ago: i64) -> DateTime<Utc> {
    (Utc::now() - TimeDelta::minutes(minutes_ago))
        .duration_trunc(TimeDelta::seconds(1))
        .unwrap()
}

/// The decoded form of a stream cursor: one time for each feed.
fn positions(pairs: &[(&str, DateTime<Utc>)]) -> Value {
    let positions: serde_json::Map<String, Value> = pairs
        .iter()
        .map(|(feed, time)| ((*feed).to_owned(), json!(graph_time(*time))))
        .collect();
    Value::Object(positions)
}

fn stream_cursor(pairs: &[(&str, DateTime<Utc>)]) -> String {
    positions(pairs).to_string()
}

/// Decodes the cursor of a batch. The order of the feeds in the cursor text has no meaning.
fn cursor_positions(cursor: Option<&str>) -> Value {
    serde_json::from_str(cursor.expect("the batch must have a cursor")).unwrap()
}

fn sign_in_record(id: &str, time: DateTime<Utc>, user: &str, error_code: i64) -> Value {
    json!({
        "id": id,
        "createdDateTime": graph_time(time),
        "userDisplayName": "Example User",
        "userPrincipalName": format!("{user}@contoso.example"),
        "userId": format!("26be570a-ae82-4189-b4e2-{:0>12}", id.len()),
        "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
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
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "status": {
            "errorCode": error_code,
            "failureReason": if error_code == 0 { Value::Null } else { json!("Error validating credentials due to invalid username or password.") },
            "additionalDetails": null
        },
        "deviceDetail": { "deviceId": "", "displayName": null, "operatingSystem": "Windows 10", "browser": "Edge 80.0.361" },
        "location": {
            "city": "Bucharest",
            "state": "Bucuresti",
            "countryOrRegion": "RO",
            "geoCoordinates": { "altitude": null, "latitude": 44.43, "longitude": 26.1 }
        },
        "appliedConditionalAccessPolicies": []
    })
}

/// A service principal that assigns the Global Administrator role to itself.
fn role_audit_record(id: &str, time: DateTime<Utc>) -> Value {
    json!({
        "id": id,
        "category": "RoleManagement",
        "correlationId": "504a302a-8f2d-418d-b7df-bf77de6ed831",
        "result": "success",
        "resultReason": "",
        "activityDisplayName": "Add member to role",
        "activityDateTime": graph_time(time),
        "loggedByService": "Core Directory",
        "operationType": "Assign",
        "initiatedBy": {
            "user": null,
            "app": {
                "appId": null,
                "displayName": "Sync Helper",
                "servicePrincipalId": PRINCIPAL_ID,
                "servicePrincipalName": null
            }
        },
        "targetResources": [
            {
                "id": PRINCIPAL_ID,
                "displayName": "Sync Helper",
                "type": "ServicePrincipal",
                "userPrincipalName": null,
                "groupType": null,
                "modifiedProperties": [
                    { "displayName": "Role.ObjectID", "oldValue": null, "newValue": "\"0f4d6b1e-7c1a-4f0e-9d53-2b8a6f7c9e01\"" },
                    { "displayName": "Role.DisplayName", "oldValue": null, "newValue": "\"Global Administrator\"" },
                    { "displayName": "Role.TemplateId", "oldValue": null, "newValue": "\"62e90394-69f5-4237-9190-012177145e10\"" },
                    { "displayName": "Role.WellKnownObjectName", "oldValue": null, "newValue": "\"TenantAdmins\"" }
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
        ],
        "additionalDetails": []
    })
}

fn query(request: &Request, key: &str) -> Option<String> {
    request
        .url
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// Returns the requests that the mock server received for `path`.
async fn requests_for(server: &MockServer, path: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == path)
        .collect()
}

async fn filters_for(server: &MockServer, path: &str) -> Vec<String> {
    requests_for(server, path)
        .await
        .iter()
        .map(|request| query(request, "$filter").unwrap())
        .collect()
}

async fn next(stream: &mut EventStream) -> Result<EventBatch> {
    tokio::time::timeout(LIMIT, stream.next())
        .await
        .expect("the stream must give a batch or an error")
        .expect("the stream must stay open")
}

fn record_ids(events: &[Event]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event.raw.as_ref().unwrap()["id"].as_str().unwrap())
        .collect()
}

fn hour_range(end: DateTime<Utc>) -> TimeRange {
    TimeRange {
        start: end - TimeDelta::hours(1),
        end,
    }
}

// Token

#[tokio::test]
async fn the_token_request_uses_the_client_credentials_grant_and_the_token_is_cached() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(token_response(TOKEN, 3599))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(page(&[], None))
        .expect(3)
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    for _ in 0..3 {
        let batch = source.fetch(hour_range(recent(0)), None).await.unwrap();
        assert_eq!(batch.events.len(), 0);
        assert_eq!(batch.next_cursor, None);
    }

    let token_requests = requests_for(&server, &token_path()).await;
    assert_eq!(token_requests.len(), 1);
    let scope = format!("{}/.default", server.uri())
        .replace(':', "%3A")
        .replace('/', "%2F");
    assert_eq!(
        String::from_utf8(token_requests[0].body.clone()).unwrap(),
        format!(
            "grant_type=client_credentials&client_id={CLIENT_ID}\
             &client_secret=example-client-secret%2F%2B%3D&scope={scope}"
        )
    );
}

#[tokio::test]
async fn a_token_at_its_expiry_is_replaced_before_the_next_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(sequence(
            vec![token_response("short-lived-token", 0)],
            token_response("second-token", 3599),
        ))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(&[], None))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    for _ in 0..3 {
        source.fetch(hour_range(recent(0)), None).await.unwrap();
    }

    let used: Vec<String> = requests_for(&server, SIGN_INS)
        .await
        .iter()
        .map(|request| {
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        used,
        [
            "Bearer short-lived-token",
            "Bearer second-token",
            "Bearer second-token"
        ]
    );
}

#[tokio::test]
async fn rejected_client_credentials_are_unauthorized_and_no_log_request_follows() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided. Trace ID: 0000 Correlation ID: 0000",
            "error_codes": [7000215],
            "timestamp": "2026-11-03 09:00:00Z"
        })))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message)
            if message.contains("HTTP 401 invalid_client AADSTS7000215")),
        "{error}"
    );
    assert!(
        !error.to_string().contains("example-client-secret"),
        "{error}"
    );
    assert!(!error.is_retryable());
    let error = source.check().await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)));
    let mut stream = source.stream(None).await.unwrap();
    let start = next(&mut stream).await.unwrap();
    assert_eq!(start.events.len(), 0, "the first batch has only the cursor");
    let error = next(&mut stream).await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)));

    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 0);
    assert_eq!(requests_for(&server, AUDITS).await.len(), 0);
}

#[tokio::test]
async fn token_service_failures_map_to_configuration_and_availability_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(sequence(
            vec![
                ResponseTemplate::new(400).set_body_json(json!({
                    "error": "invalid_request",
                    "error_description": "AADSTS90002: Tenant not found.",
                    "error_codes": [90002]
                })),
                ResponseTemplate::new(503).set_body_string("Service Unavailable"),
                ResponseTemplate::new(200).set_body_string("<html>not json</html>"),
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "token_type": "Bearer", "expires_in": 3599 })),
            ],
            ResponseTemplate::new(200).set_body_json(json!({
                "token_type": "MAC", "expires_in": 3599, "access_token": TOKEN
            })),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();
    let range = hour_range(recent(0));

    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("HTTP 400 invalid_request AADSTS90002")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("HTTP 503")),
        "{error}"
    );
    assert!(error.is_retryable());
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message) if message.contains("not valid JSON")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message) if message.contains("no bearer access token")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message) if message.contains("no bearer access token")),
        "a token that is not a bearer token is rejected: {error}"
    );
    assert!(!error.to_string().contains(TOKEN));
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 0);
}

// Live stream

#[tokio::test]
async fn the_stream_follows_next_links_and_gives_one_batch_of_all_feeds_in_time_order() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let at = |seconds: i64| start + TimeDelta::seconds(seconds);
    // Microsoft Graph returns the newest record first.
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param_is_missing("$skiptoken"))
        .respond_with(page(
            &[
                sign_in_record("sign-in-4", at(40), "dana", 0),
                sign_in_record(
                    "sign-in-3",
                    at(30) + TimeDelta::milliseconds(250),
                    "erin",
                    50126,
                ),
            ],
            Some(format!(
                "{}{SIGN_INS}?$top=2&$skiptoken=page-2",
                server.uri()
            )),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param("$skiptoken", "page-2"))
        .respond_with(page(
            &[sign_in_record("sign-in-1", at(10), "dana", 50126)],
            None,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(AUDITS))
        .respond_with(page(
            &[role_audit_record("Directory_audit-2", at(20))],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();
    let cursor = stream_cursor(&[("sign_ins", start), ("directory_audits", start)]);

    let mut stream = source.stream(Some(cursor)).await.unwrap();
    let batch = next(&mut stream).await.unwrap();

    assert_eq!(
        record_ids(&batch.events),
        ["sign-in-1", "Directory_audit-2", "sign-in-3", "sign-in-4"]
    );
    assert!(batch.events.is_sorted_by_key(|event| event.time));
    assert_eq!(
        cursor_positions(batch.next_cursor.as_deref()),
        positions(&[("sign_ins", at(40)), ("directory_audits", at(20))])
    );

    let failed = &batch.events[0];
    assert_eq!(failed.class, EventClass::Authentication);
    assert_eq!(failed.action, action::SIGN_IN);
    assert_eq!(failed.outcome, Outcome::Failure);
    assert_eq!(failed.attribute_str(attr::ERROR_CODE), Some("50126"));
    assert_eq!(failed.actor.name.as_deref(), Some("dana@contoso.example"));
    assert_eq!(failed.source.connector, "entra-test");
    assert_eq!(failed.source.vendor, "microsoft");
    assert_eq!(failed.source.product, "entra_id");
    assert_eq!(failed.source.tenant.as_deref(), Some(TENANT));
    assert_eq!(batch.events[3].outcome, Outcome::Success);

    let assignment = &batch.events[1];
    assert_eq!(assignment.action, action::ROLE_ASSIGN);
    assert_eq!(assignment.actor.kind, EntityKind::ServicePrincipal);
    assert_eq!(assignment.actor.id, PRINCIPAL_ID);
    assert_eq!(assignment.target, Some(assignment.actor.entity()));
    assert_eq!(assignment.attribute_bool(attr::PRIVILEGED), Some(true));
    assert_eq!(
        assignment.attribute_str(attr::ROLE_NAME),
        Some("Global Administrator")
    );

    let sign_in_requests = requests_for(&server, SIGN_INS).await;
    assert_eq!(sign_in_requests.len(), 2);
    assert_eq!(
        query(&sign_in_requests[0], "$filter").unwrap(),
        format!("createdDateTime ge {}", filter_time(start))
    );
    assert_eq!(query(&sign_in_requests[0], "$top").as_deref(), Some("500"));
    assert_eq!(
        query(&sign_in_requests[1], "$skiptoken").as_deref(),
        Some("page-2")
    );
    for request in &sign_in_requests {
        assert_eq!(
            request.headers["authorization"].to_str().unwrap(),
            format!("Bearer {TOKEN}")
        );
    }
    assert_eq!(
        filters_for(&server, AUDITS).await,
        [format!("activityDateTime ge {}", filter_time(start))]
    );
}

#[tokio::test]
async fn the_next_read_starts_at_the_newest_record_and_does_not_repeat_it() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let first = sign_in_record(
        "sign-in-1",
        start + TimeDelta::milliseconds(5_500),
        "dana",
        0,
    );
    let second = sign_in_record("sign-in-2", start + TimeDelta::seconds(9), "erin", 0);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(sequence(
            vec![
                page(std::slice::from_ref(&first), None),
                // No new record: the filter includes the time of the newest record.
                page(std::slice::from_ref(&first), None),
            ],
            page(&[second, first.clone()], None),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let first_batch = next(&mut stream).await.unwrap();
    let second_batch = next(&mut stream).await.unwrap();

    assert_eq!(record_ids(&first_batch.events), ["sign-in-1"]);
    assert_eq!(
        cursor_positions(first_batch.next_cursor.as_deref()),
        positions(&[("sign_ins", start + TimeDelta::milliseconds(5_500))])
    );
    assert_eq!(record_ids(&second_batch.events), ["sign-in-2"]);
    assert_eq!(
        cursor_positions(second_batch.next_cursor.as_deref()),
        positions(&[("sign_ins", start + TimeDelta::seconds(9))])
    );
    let filters = filters_for(&server, SIGN_INS).await;
    assert_eq!(
        filters.len(),
        3,
        "the read with no new record gives no batch"
    );
    assert_eq!(
        filters[0],
        format!("createdDateTime ge {}", filter_time(start))
    );
    // The filter has whole seconds. The newest record is at 5.5 seconds.
    let from_newest = format!(
        "createdDateTime ge {}",
        filter_time(start + TimeDelta::seconds(5))
    );
    assert_eq!(filters[1], from_newest);
    assert_eq!(filters[2], from_newest);
}

#[tokio::test]
async fn a_record_that_two_pages_of_one_read_return_is_emitted_one_time() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let older = sign_in_record("older", start + TimeDelta::seconds(3), "dana", 0);
    let newer = sign_in_record("newer", start + TimeDelta::seconds(6), "erin", 0);
    // A new record moves the pages while the connector reads them. Then the last record
    // of the first page is also the first record of the second page.
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param_is_missing("$skiptoken"))
        .respond_with(page(
            &[newer, older.clone()],
            Some(format!("{}{SIGN_INS}?$skiptoken=page-2", server.uri())),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param("$skiptoken", "page-2"))
        .respond_with(page(std::slice::from_ref(&older), None))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let batch = next(&mut stream).await.unwrap();

    assert_eq!(record_ids(&batch.events), ["older", "newer"]);
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 2);
}

#[tokio::test]
async fn each_read_starts_the_lookback_before_the_cursor_and_emits_a_late_record_one_time() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let cursor_time = recent(10);
    let late = sign_in_record("late", cursor_time - TimeDelta::seconds(60), "dana", 0);
    let new = sign_in_record("new", cursor_time + TimeDelta::seconds(5), "erin", 0);
    let newer = sign_in_record("newer", cursor_time + TimeDelta::seconds(10), "dana", 0);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(sequence(
            vec![page(&[new.clone(), late.clone()], None)],
            page(&[newer, new, late], None),
        ))
        .mount(&server)
        .await;
    let mut config = sign_ins_only(&server);
    config.lookback = Duration::from_secs(120);
    let source = EntraSource::new(config).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", cursor_time)])))
        .await
        .unwrap();
    let first_batch = next(&mut stream).await.unwrap();
    let second_batch = next(&mut stream).await.unwrap();

    assert_eq!(
        record_ids(&first_batch.events),
        ["late", "new"],
        "a record that Entra ID added late, before the cursor, is not lost"
    );
    assert_eq!(record_ids(&second_batch.events), ["newer"]);
    let filters = filters_for(&server, SIGN_INS).await;
    assert_eq!(filters.len(), 2);
    assert_eq!(
        filters[0],
        format!(
            "createdDateTime ge {}",
            filter_time(cursor_time - TimeDelta::seconds(120))
        )
    );
    assert_eq!(
        filters[1],
        format!(
            "createdDateTime ge {}",
            filter_time(cursor_time - TimeDelta::seconds(115))
        )
    );
}

#[tokio::test]
async fn with_no_cursor_the_stream_starts_at_the_present_time() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let before_open = recent(0);
    // The record is before the start of the stream, but in the lookback period.
    let old = sign_in_record("old", before_open - TimeDelta::seconds(60), "dana", 0);
    let calls = Arc::new(Mutex::new(0_u32));
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with({
            let calls = calls.clone();
            move |_: &Request| {
                let mut calls = calls.lock().unwrap();
                *calls += 1;
                if *calls == 1 {
                    page(std::slice::from_ref(&old), None)
                } else {
                    let fresh = sign_in_record("fresh", Utc::now(), "erin", 0);
                    page(&[fresh, old.clone()], None)
                }
            }
        })
        .mount(&server)
        .await;
    let mut config = sign_ins_only(&server);
    config.lookback = Duration::from_secs(120);
    let source = EntraSource::new(config).unwrap();

    let mut stream = source.stream(None).await.unwrap();
    let start = next(&mut stream).await.unwrap();
    let requests_before_the_first_read = server.received_requests().await.unwrap().len();
    let batch = next(&mut stream).await.unwrap();
    let after_first_batch = Utc::now();

    assert_eq!(start.events.len(), 0);
    assert_eq!(
        requests_before_the_first_read, 0,
        "the batch with the start position needs no request"
    );
    let position: DateTime<Utc> = cursor_positions(start.next_cursor.as_deref())["sign_ins"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (before_open..=after_first_batch).contains(&position),
        "the start position is {position}, the stream opened after {before_open}"
    );
    assert_eq!(
        record_ids(&batch.events),
        ["fresh"],
        "a record from before the start of the stream is not emitted"
    );
    let filters = filters_for(&server, SIGN_INS).await;
    assert_eq!(filters.len(), 2);
    let since = filters[0].strip_prefix("createdDateTime ge ").unwrap();
    let since: DateTime<Utc> = since.parse().unwrap();
    assert!(
        (before_open..=after_first_batch).contains(&since),
        "the first read starts at {since}, the stream opened after {before_open}"
    );
}

#[tokio::test]
async fn a_stream_that_opens_again_with_the_start_cursor_reads_from_the_first_start() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(|_: &Request| {
            // A record that Entra ID made after the first start.
            page(
                &[sign_in_record("after-start", Utc::now(), "dana", 0)],
                None,
            )
        })
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    // The first stream gives its start position and then stops before it reads a record.
    let mut first = source.stream(None).await.unwrap();
    let start = next(&mut first).await.unwrap();
    drop(first);
    let start_position: DateTime<Utc> = cursor_positions(start.next_cursor.as_deref())["sign_ins"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let mut second = source.stream(start.next_cursor).await.unwrap();
    let batch = next(&mut second).await.unwrap();

    assert_eq!(record_ids(&batch.events), ["after-start"]);
    assert_eq!(
        filters_for(&server, SIGN_INS).await,
        [format!(
            "createdDateTime ge {}",
            filter_time(start_position)
        )],
        "the second stream reads from the start of the first stream"
    );
}

#[tokio::test]
async fn after_a_long_stop_the_stream_reads_the_missed_time_in_ranges_without_a_wait() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(150);
    let in_last_range = sign_in_record("recent", start + TimeDelta::minutes(130), "dana", 0);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(move |request: &Request| {
            // A filter with an upper limit is a read of a past range. These ranges are empty.
            if query(request, "$filter").unwrap().contains(" le ") {
                page(&[], None)
            } else {
                page(std::slice::from_ref(&in_last_range), None)
            }
        })
        .mount(&server)
        .await;
    let mut config = sign_ins_only(&server);
    config.max_window = Duration::from_secs(3600);
    // A stream that waits for this interval between the ranges fails the test.
    config.poll_interval = Duration::from_secs(3600);
    let source = EntraSource::new(config).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let batches = [
        next(&mut stream).await.unwrap(),
        next(&mut stream).await.unwrap(),
        next(&mut stream).await.unwrap(),
    ];

    let cursor_at = |minutes: i64| positions(&[("sign_ins", start + TimeDelta::minutes(minutes))]);
    let cursor_of = |batch: &EventBatch| cursor_positions(batch.next_cursor.as_deref());
    assert_eq!(batches[0].events.len(), 0);
    assert_eq!(
        cursor_of(&batches[0]),
        cursor_at(60),
        "an empty range moves the cursor"
    );
    assert_eq!(batches[1].events.len(), 0);
    assert_eq!(cursor_of(&batches[1]), cursor_at(120));
    assert_eq!(record_ids(&batches[2].events), ["recent"]);
    assert_eq!(cursor_of(&batches[2]), cursor_at(130));

    let bound = |minutes: i64| filter_time(start + TimeDelta::minutes(minutes));
    assert_eq!(
        filters_for(&server, SIGN_INS).await,
        [
            format!(
                "createdDateTime ge {} and createdDateTime le {}",
                bound(0),
                bound(60)
            ),
            format!(
                "createdDateTime ge {} and createdDateTime le {}",
                bound(60),
                bound(120)
            ),
            format!("createdDateTime ge {}", bound(120)),
        ]
    );
}

#[tokio::test]
async fn an_error_in_a_read_changes_nothing_and_the_next_read_repeats_the_range() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[sign_in_record(
                "sign-in-1",
                start + TimeDelta::seconds(5),
                "dana",
                0,
            )],
            None,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(AUDITS))
        .respond_with(sequence(
            vec![graph_error(503, "ServiceUnavailable")],
            page(
                &[role_audit_record(
                    "Directory_audit-1",
                    start + TimeDelta::seconds(7),
                )],
                None,
            ),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();
    let cursor = stream_cursor(&[("sign_ins", start), ("directory_audits", start)]);

    let mut stream = source.stream(Some(cursor)).await.unwrap();
    let error = next(&mut stream).await.unwrap_err();
    let batch = next(&mut stream).await.unwrap();

    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.contains("read directory_audits") && message.contains("HTTP 503 ServiceUnavailable")),
        "{error}"
    );
    assert!(error.is_retryable());
    // The sign-in that the failed read already had is in the batch, one time.
    assert_eq!(
        record_ids(&batch.events),
        ["sign-in-1", "Directory_audit-1"]
    );
    let sign_in_filter = format!("createdDateTime ge {}", filter_time(start));
    assert_eq!(
        filters_for(&server, SIGN_INS).await,
        [sign_in_filter.clone(), sign_in_filter]
    );
}

#[tokio::test]
async fn a_bare_time_and_an_invalid_text_as_stream_cursor() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[sign_in_record(
                "sign-in-1",
                start + TimeDelta::seconds(5),
                "dana",
                0,
            )],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let mut stream = source.stream(Some(graph_time(start))).await.unwrap();
    let batch = next(&mut stream).await.unwrap();
    assert_eq!(record_ids(&batch.events), ["sign-in-1"]);
    assert_eq!(
        filters_for(&server, SIGN_INS).await,
        [format!("createdDateTime ge {}", filter_time(start))]
    );

    for cursor in ["not a cursor", "{\"feed\":\"sign_ins\"}", "17"] {
        let error = source.stream(Some(cursor.to_owned())).await.err().unwrap();
        assert!(matches!(error, Error::InvalidInput(_)), "{cursor}");
    }
}

#[tokio::test]
async fn the_service_principal_feed_reads_the_beta_endpoint_with_the_event_type_filter() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let record = json!({
        "id": "principal-sign-in-1",
        "createdDateTime": graph_time(start + TimeDelta::seconds(3)),
        "userId": "",
        "userPrincipalName": "",
        "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "appDisplayName": "Sync Helper",
        "ipAddress": "203.0.113.51",
        "clientCredentialType": "clientSecret",
        "servicePrincipalId": PRINCIPAL_ID,
        "servicePrincipalName": "Sync Helper",
        "signInEventTypes": ["servicePrincipal"],
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": null }
    });
    Mock::given(method("GET"))
        .and(path(PRINCIPAL_SIGN_INS))
        .respond_with(page(&[record], None))
        .mount(&server)
        .await;
    let mut config = config(&server);
    config.sign_ins = false;
    config.directory_audits = false;
    config.service_principal_sign_ins = true;
    let source = EntraSource::new(config).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[(
            "service_principal_sign_ins",
            start,
        )])))
        .await
        .unwrap();
    let batch = next(&mut stream).await.unwrap();

    assert_eq!(batch.events.len(), 1);
    let event = &batch.events[0];
    assert_eq!(event.action, action::SIGN_IN);
    assert_eq!(event.actor.kind, EntityKind::ServicePrincipal);
    assert_eq!(event.actor.id, PRINCIPAL_ID);
    assert_eq!(
        event.attribute_str(attr::AUTH_PROTOCOL),
        Some("client_credentials")
    );
    assert_eq!(
        filters_for(&server, PRINCIPAL_SIGN_INS).await,
        [format!(
            "(createdDateTime ge {}) and signInEventTypes/any(t: t eq 'servicePrincipal')",
            filter_time(start)
        )]
    );
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 0);
    assert_eq!(requests_for(&server, AUDITS).await.len(), 0);
}

#[tokio::test]
async fn a_record_that_cannot_become_an_event_is_counted_and_the_other_records_arrive() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let mut no_time = sign_in_record("no-time", start, "dana", 0);
    no_time.as_object_mut().unwrap().remove("createdDateTime");
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[
                sign_in_record("good", start + TimeDelta::seconds(2), "erin", 0),
                no_time,
                json!("not a record"),
            ],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();
    assert_eq!(source.rejected_records(), 0);

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let batch = next(&mut stream).await.unwrap();

    assert_eq!(record_ids(&batch.events), ["good"]);
    assert_eq!(source.rejected_records(), 2);
}

#[tokio::test]
async fn a_rejected_record_that_the_stream_reads_again_is_counted_one_time() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    let mut no_time = sign_in_record("no-time", start, "dana", 0);
    no_time.as_object_mut().unwrap().remove("createdDateTime");
    let mut no_id = sign_in_record("no-id", start + TimeDelta::seconds(1), "dana", 0);
    no_id.as_object_mut().unwrap().remove("id");
    let first = sign_in_record("first", start + TimeDelta::seconds(2), "erin", 0);
    let second = sign_in_record("second", start + TimeDelta::seconds(4), "erin", 0);
    let mut late_reject = sign_in_record("late-reject", start, "dana", 0);
    late_reject["createdDateTime"] = json!("not a time");
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(sequence(
            vec![page(&[first.clone(), no_id.clone(), no_time.clone()], None)],
            // The next reads return the two bad records again, and one new bad record.
            page(&[second, late_reject, first, no_id, no_time], None),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let first_batch = next(&mut stream).await.unwrap();
    assert_eq!(record_ids(&first_batch.events), ["first"]);
    assert_eq!(source.rejected_records(), 2);

    let second_batch = next(&mut stream).await.unwrap();
    assert_eq!(record_ids(&second_batch.events), ["second"]);
    assert_eq!(
        source.rejected_records(),
        3,
        "only the new bad record adds to the count"
    );
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 2);
}

// Backfill

#[tokio::test]
async fn fetch_pages_through_each_feed_with_the_next_link_as_the_cursor() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let end = recent(30);
    let range = TimeRange {
        start: end - TimeDelta::minutes(10),
        end: end + TimeDelta::milliseconds(500),
    };
    let at = |seconds: i64| range.start + TimeDelta::seconds(seconds);
    let next_link = format!("{}{SIGN_INS}?$top=2&$skiptoken=page-2", server.uri());
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param_is_missing("$skiptoken"))
        .respond_with(page(
            &[
                // The filter includes its end and has whole seconds. These two records are
                // after the end of the range.
                sign_in_record("after-end", end + TimeDelta::milliseconds(900), "dana", 0),
                sign_in_record("at-end", range.end, "dana", 0),
                sign_in_record("sign-in-3", at(30), "dana", 0),
                sign_in_record("sign-in-2", at(20), "erin", 50126),
            ],
            Some(next_link.clone()),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(query_param("$skiptoken", "page-2"))
        .respond_with(page(
            &[sign_in_record("sign-in-1", range.start, "dana", 0)],
            None,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(AUDITS))
        .respond_with(page(
            &[role_audit_record("Directory_audit-1", at(25))],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();

    let first = source.fetch(range, None).await.unwrap();
    let second = source
        .fetch(range, first.next_cursor.clone())
        .await
        .unwrap();
    let third = source
        .fetch(range, second.next_cursor.clone())
        .await
        .unwrap();

    assert_eq!(record_ids(&first.events), ["sign-in-2", "sign-in-3"]);
    assert_eq!(
        serde_json::from_str::<Value>(first.next_cursor.as_deref().unwrap()).unwrap(),
        json!({ "feed": "sign_ins", "link": next_link })
    );
    assert_eq!(record_ids(&second.events), ["sign-in-1"]);
    assert_eq!(
        serde_json::from_str::<Value>(second.next_cursor.as_deref().unwrap()).unwrap(),
        json!({ "feed": "directory_audits" })
    );
    assert_eq!(record_ids(&third.events), ["Directory_audit-1"]);
    assert_eq!(third.next_cursor, None);

    let upper = filter_time(end + TimeDelta::seconds(1));
    let sign_in_requests = requests_for(&server, SIGN_INS).await;
    assert_eq!(sign_in_requests.len(), 2);
    assert_eq!(
        query(&sign_in_requests[0], "$filter").unwrap(),
        format!(
            "createdDateTime ge {} and createdDateTime le {upper}",
            filter_time(range.start)
        )
    );
    // The second request is the next link as Microsoft Graph gave it.
    assert_eq!(query(&sign_in_requests[1], "$filter"), None);
    assert_eq!(
        query(&sign_in_requests[1], "$skiptoken").as_deref(),
        Some("page-2")
    );
    assert_eq!(
        filters_for(&server, AUDITS).await,
        [format!(
            "activityDateTime ge {} and activityDateTime le {upper}",
            filter_time(range.start)
        )]
    );
}

#[tokio::test]
async fn fetch_counts_a_record_that_cannot_become_an_event_and_returns_the_other_records() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let end = recent(0);
    let mut bad_time = sign_in_record("bad-time", end, "dana", 0);
    bad_time["createdDateTime"] = json!("03/11/2026 09:10");
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[
                bad_time,
                sign_in_record("good", end - TimeDelta::minutes(1), "erin", 0),
            ],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let batch = source.fetch(hour_range(end), None).await.unwrap();

    assert_eq!(record_ids(&batch.events), ["good"]);
    assert_eq!(batch.next_cursor, None);
    assert_eq!(source.rejected_records(), 1);
}

#[tokio::test]
async fn fetch_rejects_a_cursor_that_is_not_valid_and_reads_nothing_for_an_empty_range() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();
    let range = hour_range(recent(0));

    for cursor in [
        "not json",
        "{\"sign_ins\":\"2026-11-03T09:00:00Z\"}",
        "{\"feed\":\"unknown_feed\"}",
        "{\"feed\":\"directory_audits\"}",
        "{\"feed\":\"sign_ins\",\"link\":\"not a url\"}",
    ] {
        let error = source
            .fetch(range, Some(cursor.to_owned()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)), "{cursor}: {error}");
    }

    let empty = TimeRange {
        start: range.end,
        end: range.end,
    };
    let batch = source.fetch(empty, None).await.unwrap();
    assert_eq!((batch.events.len(), batch.next_cursor), (0, None));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

// Errors of the log endpoints

#[tokio::test]
async fn status_401_gets_one_new_token_and_then_is_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(sequence(
            vec![token_response("revoked-token", 3599)],
            token_response("second-token", 3599),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(graph_error(401, "InvalidAuthenticationToken"))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message)
            if message.contains("read sign_ins") && message.contains("HTTP 401 InvalidAuthenticationToken")),
        "{error}"
    );
    assert!(!error.is_retryable());
    let message = error.to_string();
    assert!(
        !message.contains("second-token") && !message.contains("example message"),
        "{message}"
    );
    let used: Vec<String> = requests_for(&server, SIGN_INS)
        .await
        .iter()
        .map(|request| {
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(used, ["Bearer revoked-token", "Bearer second-token"]);
    assert_eq!(requests_for(&server, &token_path()).await.len(), 2);
}

#[tokio::test]
async fn a_token_that_the_service_revoked_is_replaced_and_the_read_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(sequence(
            vec![token_response("revoked-token", 3599)],
            token_response("second-token", 3599),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(header("authorization", "Bearer revoked-token"))
        .respond_with(graph_error(401, "InvalidAuthenticationToken"))
        .mount(&server)
        .await;
    let end = recent(0);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .and(header("authorization", "Bearer second-token"))
        .respond_with(page(
            &[sign_in_record(
                "sign-in-1",
                end - TimeDelta::minutes(1),
                "dana",
                0,
            )],
            None,
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let batch = source.fetch(hour_range(end), None).await.unwrap();

    assert_eq!(record_ids(&batch.events), ["sign-in-1"]);
    assert_eq!(requests_for(&server, &token_path()).await.len(), 2);
}

#[tokio::test]
async fn other_statuses_map_to_the_matching_errors() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(sequence(
            vec![
                graph_error(403, "Authorization_RequestDenied"),
                graph_error(500, "InternalServerError"),
                ResponseTemplate::new(502).set_body_string("<html>Bad Gateway</html>"),
                graph_error(504, "GatewayTimeout"),
                graph_error(400, "BadRequest"),
                graph_error(404, "ResourceNotFound"),
            ],
            ResponseTemplate::new(200).set_body_string("{\"value\": \"not a list\"}"),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();
    let range = hour_range(recent(0));

    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message)
            if message.contains("AuditLog.Read.All") && message.contains("HTTP 403 Authorization_RequestDenied")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("HTTP 500 InternalServerError")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.ends_with("(HTTP 502)")),
        "{error}"
    );
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(matches!(error, Error::Timeout(_)), "{error}");
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)), "{error}");
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error}");
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(matches!(error, Error::Serialization(_)), "{error}");
    assert_eq!(
        requests_for(&server, &token_path()).await.len(),
        1,
        "only status 401 gets a new token"
    );
}

#[tokio::test]
async fn status_429_waits_for_retry_after_and_then_reads_the_page() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let end = recent(0);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(sequence(
            vec![graph_error(429, "TooManyRequests").insert_header("Retry-After", "1")],
            page(
                &[sign_in_record(
                    "sign-in-1",
                    end - TimeDelta::minutes(1),
                    "dana",
                    0,
                )],
                None,
            ),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let started = Instant::now();
    let batch = source.fetch(hour_range(end), None).await.unwrap();
    let waited = started.elapsed();

    assert_eq!(record_ids(&batch.events), ["sign-in-1"]);
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 2);
    assert!(
        waited >= Duration::from_secs(1),
        "the connector waited only {waited:?}"
    );
}

#[tokio::test]
async fn status_429_with_no_retry_after_time_is_rate_limited_immediately() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(graph_error(429, "TooManyRequests"))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();
    let range = hour_range(recent(0));

    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::RateLimited(message)
            if message.contains("read sign_ins") && message.contains("no Retry-After")),
        "{error}"
    );
    assert!(error.is_retryable());
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 1);

    // The response gave no time, so the connector has no time to wait for.
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(matches!(error, Error::RateLimited(_)), "{error}");
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 2);
}

#[tokio::test]
async fn a_retry_after_time_above_the_limit_is_rate_limited_and_stops_the_next_requests() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    for feed in [SIGN_INS, AUDITS] {
        Mock::given(method("GET"))
            .and(path(feed))
            .respond_with(sequence(
                vec![graph_error(429, "TooManyRequests").insert_header("Retry-After", "3600")],
                page(&[], None),
            ))
            .mount(&server)
            .await;
    }
    let mut config = config(&server);
    config.max_retry_after = Duration::from_secs(300);
    let source = EntraSource::new(config).unwrap();
    let range = hour_range(recent(0));

    let started = Instant::now();
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::RateLimited(message) if message.contains("retry after 3600 s")),
        "{error}"
    );
    assert!(error.is_retryable());
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 1);

    // Microsoft Graph asked for one hour with no request. A new read, of each feed, sends
    // no request, although the mock server now has a page for it.
    let error = source.fetch(range, None).await.unwrap_err();
    assert!(
        matches!(&error, Error::RateLimited(message)
            if message.contains("read sign_ins") && message.contains("no request during the next")),
        "{error}"
    );
    let audits = json!({ "feed": "directory_audits" }).to_string();
    let error = source.fetch(range, Some(audits)).await.unwrap_err();
    assert!(
        matches!(&error, Error::RateLimited(message) if message.contains("read directory_audits")),
        "{error}"
    );
    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", recent(10))])))
        .await
        .unwrap();
    let error = next(&mut stream).await.unwrap_err();
    assert!(matches!(error, Error::RateLimited(_)), "{error}");
    let error = source.check().await.unwrap_err();
    assert!(matches!(error, Error::RateLimited(_)), "{error}");

    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 1);
    assert_eq!(requests_for(&server, AUDITS).await.len(), 0);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the connector must not wait one hour"
    );
}

#[tokio::test]
async fn more_429_responses_than_the_retry_limit_is_rate_limited() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(graph_error(429, "TooManyRequests").insert_header("Retry-After", "0"))
        .mount(&server)
        .await;
    let mut config = sign_ins_only(&server);
    config.rate_limit_retries = 2;
    let source = EntraSource::new(config).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();

    assert!(
        matches!(&error, Error::RateLimited(message) if message.contains("retry after 0 s")),
        "{error}"
    );
    assert_eq!(
        requests_for(&server, SIGN_INS).await.len(),
        3,
        "the first request and two more after the waits"
    );
}

#[tokio::test]
async fn a_request_that_takes_longer_than_the_limit_is_a_timeout() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(&[], None).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let mut config = sign_ins_only(&server);
    config.request_timeout = Duration::from_millis(200);
    let source = EntraSource::new(config).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Timeout(message) if message.contains("read sign_ins")),
        "{error}"
    );
    assert!(error.is_retryable());
}

#[tokio::test]
async fn a_refused_connection_is_unavailable() {
    // Port 1 of the loopback address has no listener. The operating system refuses the
    // connection. A mock server that the test drops is not sufficient, because the mock
    // library keeps the listener of a dropped server for the next test.
    let source = EntraSource::new(config_at("http://127.0.0.1:1")).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.contains("get an access token: could not connect")),
        "{error}"
    );
    assert!(error.is_retryable());
    assert!(
        !error.to_string().contains("127.0.0.1"),
        "the message must have no URL: {error}"
    );
}

#[tokio::test]
async fn a_connection_that_closes_with_no_response_is_unavailable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(Mutex::new(0_u32));
    let server = tokio::spawn({
        let accepted = accepted.clone();
        async move {
            loop {
                let (connection, _) = listener.accept().await.unwrap();
                *accepted.lock().unwrap() += 1;
                drop(connection);
            }
        }
    });
    let source = EntraSource::new(config_at(&format!("http://{address}"))).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();
    server.abort();

    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("get an access token")),
        "{error}"
    );
    assert!(error.is_retryable());
    assert!(
        !error.to_string().contains(&address.to_string()),
        "the message must have no URL: {error}"
    );
    assert!(
        *accepted.lock().unwrap() >= 1,
        "the request must reach the server"
    );
}

// The token must stay on the configured host

#[tokio::test]
async fn a_next_link_to_a_different_host_is_rejected_and_gets_no_request() {
    let server = MockServer::start().await;
    let other = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[sign_in_record(
                "sign-in-1",
                start + TimeDelta::seconds(1),
                "dana",
                0,
            )],
            Some(format!("{}{SIGN_INS}?$skiptoken=page-2", other.uri())),
        ))
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();
    assert!(
        matches!(&error, Error::Integrity(message) if message.contains("configured Microsoft Graph host")),
        "{error}"
    );
    let mut stream = source
        .stream(Some(stream_cursor(&[("sign_ins", start)])))
        .await
        .unwrap();
    let error = next(&mut stream).await.unwrap_err();
    assert!(matches!(error, Error::Integrity(_)), "{error}");

    let cursor = json!({ "feed": "sign_ins", "link": format!("{}{SIGN_INS}", other.uri()) });
    let error = source
        .fetch(hour_range(recent(0)), Some(cursor.to_string()))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)), "{error}");

    assert_eq!(
        other.received_requests().await.unwrap().len(),
        0,
        "the token must not go to a different host"
    );
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    let other = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}{SIGN_INS}", other.uri())),
        )
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(message) if message.contains("redirect")),
        "{error}"
    );
    assert_eq!(other.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn a_redirect_of_the_token_request_is_not_followed() {
    let server = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(
            ResponseTemplate::new(307).insert_header("Location", format!("{}/token", other.uri())),
        )
        .mount(&server)
        .await;
    let source = EntraSource::new(sign_ins_only(&server)).unwrap();

    let error = source.fetch(hour_range(recent(0)), None).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(message) if message.contains("redirect")),
        "{error}"
    );
    assert_eq!(
        other.received_requests().await.unwrap().len(),
        0,
        "the client secret must not go to a different host"
    );
}

// Check, identity, and the runner

#[tokio::test]
async fn check_gets_a_token_and_reads_one_record_of_each_enabled_feed() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    for feed in [SIGN_INS, PRINCIPAL_SIGN_INS, AUDITS] {
        Mock::given(method("GET"))
            .and(path(feed))
            .and(query_param("$top", "1"))
            .respond_with(page(&[], None))
            .mount(&server)
            .await;
    }
    let mut all_feeds = config(&server);
    all_feeds.service_principal_sign_ins = true;
    let source = EntraSource::new(all_feeds).unwrap();

    source.check().await.unwrap();

    let info = source.info();
    assert_eq!(
        (
            info.name.as_str(),
            info.vendor.as_str(),
            info.product.as_str()
        ),
        ("entra-test", "microsoft", "entra_id")
    );
    assert_eq!(requests_for(&server, &token_path()).await.len(), 1);
    assert_eq!(requests_for(&server, SIGN_INS).await.len(), 1);
    assert_eq!(requests_for(&server, PRINCIPAL_SIGN_INS).await.len(), 1);
    assert_eq!(requests_for(&server, AUDITS).await.len(), 1);
}

#[tokio::test]
async fn check_fails_when_the_application_has_no_permission() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(&[], None))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(AUDITS))
        .respond_with(graph_error(403, "Authorization_RequestDenied"))
        .mount(&server)
        .await;
    let source = EntraSource::new(config(&server)).unwrap();

    let error = source.check().await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized(message) if message.contains("read directory_audits")),
        "{error}"
    );
}

#[tokio::test]
async fn the_runner_saves_the_start_position_of_a_stream_with_no_checkpoint() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    // The tenant has no records. Without the start position, the store stays empty.
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(&[], None))
        .mount(&server)
        .await;
    let before_start = recent(0);
    let source = Arc::new(EntraSource::new(sign_ins_only(&server)).unwrap());
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    let cancel = CancellationToken::new();
    let runner =
        Arc::new(IngestRunner::new(source, bus.clone(), store.clone(), cancel.clone()).unwrap());

    let task = tokio::spawn({
        let runner = runner.clone();
        async move { runner.run().await }
    });
    tokio::time::timeout(LIMIT, async {
        while runner.stats().batches == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the runner must get the batch with the start position");
    cancel.cancel();
    let outcome = tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();

    assert_eq!(outcome.unwrap(), RunOutcome::Cancelled);
    assert_eq!(bus.published().len(), 0);
    let saved = store.load("entra-test").await.unwrap();
    let position: DateTime<Utc> = cursor_positions(saved.as_deref())["sign_ins"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (before_start..=Utc::now()).contains(&position),
        "the saved start position is {position}"
    );
}

#[tokio::test]
async fn the_runner_publishes_entra_events_and_saves_the_stream_cursor() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    let start = recent(10);
    Mock::given(method("GET"))
        .and(path(SIGN_INS))
        .respond_with(page(
            &[
                sign_in_record("sign-in-2", start + TimeDelta::seconds(8), "erin", 0),
                sign_in_record("sign-in-1", start + TimeDelta::seconds(4), "dana", 50126),
            ],
            None,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(AUDITS))
        .respond_with(page(
            &[role_audit_record(
                "Directory_audit-1",
                start + TimeDelta::seconds(6),
            )],
            None,
        ))
        .mount(&server)
        .await;
    let source = Arc::new(EntraSource::new(config(&server)).unwrap());
    let bus = Arc::new(MemoryBus::default());
    let store = Arc::new(MemoryCheckpointStore::new());
    store
        .save(
            "entra-test",
            &stream_cursor(&[("sign_ins", start), ("directory_audits", start)]),
        )
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let runner =
        Arc::new(IngestRunner::new(source, bus.clone(), store.clone(), cancel.clone()).unwrap());
    let mut messages = bus
        .subscribe("aegis.events.entra-test", Some("test"))
        .await
        .unwrap();

    let task = tokio::spawn({
        let runner = runner.clone();
        async move { runner.run().await }
    });
    let mut events = Vec::new();
    for _ in 0..3 {
        let message = tokio::time::timeout(LIMIT, messages.next())
            .await
            .expect("the runner must publish the batch")
            .unwrap()
            .unwrap();
        events.push(message.decode::<Event>().unwrap());
    }
    // The runner saves the cursor after the last event of the batch. Wait for the batch count.
    tokio::time::timeout(LIMIT, async {
        while runner.stats().batches == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the runner must complete the batch");
    cancel.cancel();
    let outcome = tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();

    assert_eq!(outcome.unwrap(), RunOutcome::Cancelled);
    assert_eq!(
        record_ids(&events),
        ["sign-in-1", "Directory_audit-1", "sign-in-2"]
    );
    assert_eq!(
        bus.published().len(),
        3,
        "the live stream does not repeat a record"
    );
    assert_eq!(
        cursor_positions(store.load("entra-test").await.unwrap().as_deref()),
        positions(&[
            ("sign_ins", start + TimeDelta::seconds(8)),
            ("directory_audits", start + TimeDelta::seconds(6))
        ])
    );
}
