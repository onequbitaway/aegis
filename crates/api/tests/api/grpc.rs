//! The gRPC services. The tests write the gRPC frames themselves, so they need no gRPC
//! client.

use aegis_api::grpc::proto;
use aegis_contracts::common::{ApprovalId, IncidentId, Severity};
use aegis_contracts::incident::{IncidentStatus, IncidentStore};
use aegis_contracts::policy::{ApprovalQueue, Principal, PrincipalKind};
use aegis_core::Shutdown;
use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, TE};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use prost::Message;
use tokio::net::TcpListener;
use tower::ServiceExt;

use crate::support::{APPROVER, DecideCall, GUEST, TestApi, UNKNOWN, VIEWER, config, incident};

const LIST_INCIDENTS: &str = "/aegis.v1.IncidentService/ListIncidents";
const GET_INCIDENT: &str = "/aegis.v1.IncidentService/GetIncident";
const LIST_PENDING: &str = "/aegis.v1.ApprovalService/ListPending";
const DECIDE: &str = "/aegis.v1.ApprovalService/Decide";

// The gRPC status codes that the tests expect.
const INVALID_ARGUMENT: i32 = 3;
const NOT_FOUND: i32 = 5;
const PERMISSION_DENIED: i32 = 7;
const FAILED_PRECONDITION: i32 = 9;
const UNIMPLEMENTED: i32 = 12;
const UNAUTHENTICATED: i32 = 16;

/// Returns a message as one gRPC frame: no compression, the length, and the bytes.
fn frame(message: &impl Message) -> Vec<u8> {
    let payload = message.encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Reads the single message of a gRPC response body.
fn unframe<T: Message + Default>(body: &[u8]) -> T {
    assert!(
        body.len() >= 5,
        "a body of {} bytes has no frame",
        body.len()
    );
    assert_eq!(body[0], 0, "the frame is compressed");
    let length = usize::try_from(u32::from_be_bytes([body[1], body[2], body[3], body[4]])).unwrap();
    assert_eq!(body.len(), 5 + length, "the body has more than one frame");
    T::decode(&body[5..]).unwrap()
}

/// The gRPC status and message of a failed call.
#[derive(Debug, PartialEq, Eq)]
struct Failure {
    code: i32,
    message: String,
}

fn grpc_status(headers: &HeaderMap) -> Option<i32> {
    headers.get("grpc-status")?.to_str().ok()?.parse().ok()
}

fn grpc_message(headers: &HeaderMap) -> String {
    let raw = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    // gRPC encodes the message with percent escapes.
    url::form_urlencoded::parse(raw.replace('+', "%2B").as_bytes())
        .map(|(key, _)| key.into_owned())
        .collect()
}

/// Makes one unary call through the router.
async fn call<Req: Message, Res: Message + Default>(
    router: &Router,
    path: &str,
    token: Option<&str>,
    request: &Req,
) -> Result<Res, Failure> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(CONTENT_TYPE, "application/grpc")
        .header(TE, "trailers");
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(frame(request))).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap_or_default();
    let body = collected.to_bytes();
    // A failed call has its status in the headers. A call that worked has it in the trailers.
    let (code, source) = match grpc_status(&headers) {
        Some(code) => (code, &headers),
        None => (grpc_status(&trailers).expect("a grpc-status"), &trailers),
    };
    if code == 0 {
        Ok(unframe(&body))
    } else {
        Err(Failure {
            code,
            message: grpc_message(source),
        })
    }
}

fn failure(code: i32, message: &str) -> Failure {
    Failure {
        code,
        message: message.to_owned(),
    }
}

fn list_request(status: proto::IncidentStatus, limit: u32) -> proto::ListIncidentsRequest {
    proto::ListIncidentsRequest {
        status: status.into(),
        limit,
    }
}

#[tokio::test]
async fn list_incidents_has_each_field_of_the_incident() {
    let api = TestApi::new();
    let seeded = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();

    let response: proto::ListIncidentsResponse = call(
        &router,
        LIST_INCIDENTS,
        Some(VIEWER),
        &list_request(proto::IncidentStatus::Unspecified, 0),
    )
    .await
    .unwrap();
    assert_eq!(response.incidents.len(), 1);
    let incident = &response.incidents[0];
    let time = prost_types::Timestamp {
        seconds: seeded.created_at.timestamp(),
        nanos: 0,
    };
    let technique = proto::AttackTechnique {
        tactic: "credential-access".to_owned(),
        technique_id: "T1110.003".to_owned(),
        name: "Password Spraying".to_owned(),
    };
    let entities = vec![
        proto::EntityRef {
            kind: "ip_address".to_owned(),
            id: "203.0.113.50".to_owned(),
            name: None,
            tenant: None,
        },
        proto::EntityRef {
            kind: "user".to_owned(),
            id: "user-1".to_owned(),
            name: Some("victim@example.com".to_owned()),
            tenant: None,
        },
        proto::EntityRef {
            kind: "service_principal".to_owned(),
            id: "sp-1".to_owned(),
            name: Some("sync-helper".to_owned()),
            tenant: None,
        },
    ];
    assert_eq!(
        *incident,
        proto::Incident {
            id: seeded.id.to_string(),
            title: "Password spray".to_owned(),
            summary: "Many failed sign-ins from one address.".to_owned(),
            severity: proto::Severity::High.into(),
            status: proto::IncidentStatus::Open.into(),
            created_at: Some(time),
            updated_at: Some(time),
            tenant: Some("tenant-contoso".to_owned()),
            detections: vec![proto::Detection {
                id: seeded.detections[0].id.to_string(),
                rule_id: "aegis.signin.burst".to_owned(),
                title: "Password spray".to_owned(),
                description: "One address failed to sign in to many accounts.".to_owned(),
                severity: proto::Severity::High.into(),
                verdict: "malicious".to_owned(),
                tier: "deterministic".to_owned(),
                time: Some(time),
                attack: vec![technique.clone()],
                event_ids: Vec::new(),
                entities: entities.clone(),
                tenant: Some("tenant-contoso".to_owned()),
                attributes_json: "{}".to_owned(),
            }],
            entities,
            attack: vec![technique],
            timeline: vec![proto::TimelineEntry {
                time: Some(time),
                author: "correlator".to_owned(),
                description: "The correlator made the incident.".to_owned(),
                evidence: Vec::new(),
            }],
        }
    );
}

#[tokio::test]
async fn list_incidents_obeys_the_state_filter_and_the_limit() {
    let api = TestApi::new();
    let open = api.seed_incident("Password spray", Severity::High).await;
    let mut contained = incident("Rogue application", Severity::Critical);
    contained.created_at = open.created_at + chrono::Duration::minutes(5);
    contained.status = IncidentStatus::Contained;
    api.incidents.save(&contained).await.unwrap();
    let router = api.router();

    let ids = |status, limit| {
        let router = router.clone();
        async move {
            call::<_, proto::ListIncidentsResponse>(
                &router,
                LIST_INCIDENTS,
                Some(VIEWER),
                &list_request(status, limit),
            )
            .await
            .map(|response| {
                response
                    .incidents
                    .into_iter()
                    .map(|incident| incident.id)
                    .collect::<Vec<_>>()
            })
        }
    };
    assert_eq!(
        ids(proto::IncidentStatus::Unspecified, 0).await.unwrap(),
        [contained.id.to_string(), open.id.to_string()]
    );
    assert_eq!(
        ids(proto::IncidentStatus::Contained, 0).await.unwrap(),
        [contained.id.to_string()]
    );
    assert_eq!(
        ids(proto::IncidentStatus::Unspecified, 1).await.unwrap(),
        [contained.id.to_string()]
    );
    assert_eq!(
        ids(proto::IncidentStatus::Resolved, 0).await.unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        ids(proto::IncidentStatus::Unspecified, 201)
            .await
            .unwrap_err(),
        failure(INVALID_ARGUMENT, "limit must be from 0 to 200.")
    );
    let unknown_state = proto::ListIncidentsRequest {
        status: 99,
        limit: 0,
    };
    assert_eq!(
        call::<_, proto::ListIncidentsResponse>(
            &router,
            LIST_INCIDENTS,
            Some(VIEWER),
            &unknown_state
        )
        .await
        .unwrap_err(),
        failure(INVALID_ARGUMENT, "status is not a value of IncidentStatus.")
    );
}

#[tokio::test]
async fn get_incident_reads_one_incident() {
    let api = TestApi::new();
    let seeded = api.seed_incident("Password spray", Severity::High).await;
    let router = api.router();
    let get = |id: String| {
        let router = router.clone();
        async move {
            call::<_, proto::Incident>(
                &router,
                GET_INCIDENT,
                Some(VIEWER),
                &proto::GetIncidentRequest { id },
            )
            .await
        }
    };

    let found = get(seeded.id.to_string()).await.unwrap();
    assert_eq!(found.id, seeded.id.to_string());
    assert_eq!(found.title, "Password spray");
    assert_eq!(found.entities.len(), 3);

    assert_eq!(
        get(IncidentId::new().to_string()).await.unwrap_err(),
        failure(NOT_FOUND, "The incident does not exist.")
    );
    assert_eq!(
        get("42".to_owned()).await.unwrap_err(),
        failure(INVALID_ARGUMENT, "id is not a valid UUID.")
    );
}

#[tokio::test]
async fn each_call_needs_a_token_and_the_permission() {
    let api = TestApi::new();
    let incident = api.seed_incident("Password spray", Severity::High).await;
    let approval = api.seed_approval().await;
    let router = api.router();

    let list = list_request(proto::IncidentStatus::Unspecified, 0);
    let get = proto::GetIncidentRequest {
        id: incident.id.to_string(),
    };
    let pending = proto::ListPendingRequest { limit: 0 };
    let decide = proto::DecideRequest {
        id: approval.id.to_string(),
        approve: true,
        note: None,
    };

    let no_token = failure(UNAUTHENTICATED, "The request has no valid bearer token.");
    for token in [None, Some(UNKNOWN)] {
        assert_eq!(
            call::<_, proto::ListIncidentsResponse>(&router, LIST_INCIDENTS, token, &list).await,
            Err(failure(UNAUTHENTICATED, &no_token.message))
        );
        assert_eq!(
            call::<_, proto::Incident>(&router, GET_INCIDENT, token, &get).await,
            Err(failure(UNAUTHENTICATED, &no_token.message))
        );
        assert_eq!(
            call::<_, proto::ListPendingResponse>(&router, LIST_PENDING, token, &pending).await,
            Err(failure(UNAUTHENTICATED, &no_token.message))
        );
        assert_eq!(
            call::<_, proto::DecideResponse>(&router, DECIDE, token, &decide).await,
            Err(failure(UNAUTHENTICATED, &no_token.message))
        );
    }

    let view = "The principal does not have the permission view_incidents.";
    let read = "The principal does not have the permission view_incidents or approve_actions.";
    let approve = "The principal does not have the permission approve_actions.";
    assert_eq!(
        call::<_, proto::ListIncidentsResponse>(&router, LIST_INCIDENTS, Some(APPROVER), &list)
            .await,
        Err(failure(PERMISSION_DENIED, view))
    );
    assert_eq!(
        call::<_, proto::Incident>(&router, GET_INCIDENT, Some(GUEST), &get).await,
        Err(failure(PERMISSION_DENIED, view))
    );
    assert_eq!(
        call::<_, proto::ListPendingResponse>(&router, LIST_PENDING, Some(GUEST), &pending).await,
        Err(failure(PERMISSION_DENIED, read))
    );
    assert_eq!(
        call::<_, proto::DecideResponse>(&router, DECIDE, Some(VIEWER), &decide).await,
        Err(failure(PERMISSION_DENIED, approve))
    );
    assert!(api.actions.calls().is_empty());
}

#[tokio::test]
async fn list_pending_has_the_requests_oldest_first() {
    let api = TestApi::new();
    let first = api.seed_approval().await;
    let mut second = crate::support::approval_request();
    second.requested_at = first.requested_at + chrono::Duration::minutes(1);
    api.approvals.submit(second.clone()).await.unwrap();
    let router = api.router();

    for token in [VIEWER, APPROVER] {
        let response: proto::ListPendingResponse = call(
            &router,
            LIST_PENDING,
            Some(token),
            &proto::ListPendingRequest { limit: 0 },
        )
        .await
        .unwrap();
        assert_eq!(response.total, 2);
        let ids: Vec<&str> = response
            .requests
            .iter()
            .map(|request| request.id.as_str())
            .collect();
        assert_eq!(ids, [first.id.to_string(), second.id.to_string()]);
    }

    let response: proto::ListPendingResponse = call(
        &router,
        LIST_PENDING,
        Some(VIEWER),
        &proto::ListPendingRequest { limit: 1 },
    )
    .await
    .unwrap();
    assert_eq!(response.total, 2);
    assert_eq!(response.requests.len(), 1);
    let request = &response.requests[0];
    assert_eq!(request.id, first.id.to_string());
    assert_eq!(request.status, i32::from(proto::ApprovalStatus::Pending));
    assert_eq!(request.decided_by, None);
    assert_eq!(request.decided_at, None);
    let action = request.action.as_ref().unwrap();
    assert_eq!(action.id, first.action.id.to_string());
    assert_eq!(action.kind, "disable_user");
    assert_eq!(
        action.reason,
        "The account signed in from the spray address."
    );
    assert_eq!(action.parameters_json, "{}");
    assert!(!action.dry_run);
    assert_eq!(
        action.target,
        Some(proto::EntityRef {
            kind: "user".to_owned(),
            id: "user-1".to_owned(),
            name: Some("victim@example.com".to_owned()),
            tenant: None,
        })
    );
    assert_eq!(
        request.requested_by,
        Some(proto::Principal {
            id: "responder".to_owned(),
            kind: "agent".to_owned(),
            roles: vec!["responder".to_owned()],
        })
    );
    let decision = request.decision.as_ref().unwrap();
    assert_eq!(decision.effect, "require_approval");
    assert_eq!(decision.tier, "gated");
    assert_eq!(decision.reasons, ["The action is in the gated tier."]);
    assert_eq!(decision.policy.as_deref(), Some("aegis.response.decision"));
}

#[tokio::test]
async fn decide_calls_the_approval_path_with_the_principal_of_the_token() {
    let api = TestApi::new();
    let approval = api.seed_approval().await;
    let router = api.router();
    let decide = |approve: bool, note: Option<&str>| proto::DecideRequest {
        id: approval.id.to_string(),
        approve,
        note: note.map(str::to_owned),
    };

    let response: proto::DecideResponse = call(
        &router,
        DECIDE,
        Some(APPROVER),
        &decide(true, Some(" Looks right. ")),
    )
    .await
    .unwrap();
    assert_eq!(
        api.actions.calls(),
        [DecideCall {
            id: approval.id,
            approve: true,
            principal: Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]),
            note: Some("Looks right.".to_owned()),
        }]
    );
    let request = response.request.unwrap();
    assert_eq!(request.id, approval.id.to_string());
    assert_eq!(request.status, i32::from(proto::ApprovalStatus::Approved));
    assert_eq!(request.decided_by.as_deref(), Some("alice@example.com"));
    assert_eq!(request.note.as_deref(), Some("Looks right."));
    assert!(request.decided_at.is_some());
    let Some(proto::action_disposition::Result::Executed(outcome)) = response
        .disposition
        .and_then(|disposition| disposition.result)
    else {
        panic!("an approval has the outcome of the action");
    };
    assert_eq!(outcome.action_id, approval.action.id.to_string());
    assert_eq!(outcome.status, "succeeded");
    assert_eq!(outcome.connector, "test-connector");
    assert_eq!(outcome.message, "The connector did the action.");
    assert!(outcome.reversible);

    // A second decision does not reach the approval path.
    assert_eq!(
        call::<_, proto::DecideResponse>(&router, DECIDE, Some(APPROVER), &decide(false, None))
            .await,
        Err(failure(
            FAILED_PRECONDITION,
            "The approval request already has a decision."
        ))
    );
    assert_eq!(api.actions.calls().len(), 1);
}

#[tokio::test]
async fn a_rejection_has_no_disposition_and_a_bad_request_changes_nothing() {
    let api = TestApi::new();
    let approval = api.seed_approval().await;
    let router = api.router();
    let decide = |id: String, note: Option<String>| proto::DecideRequest {
        id,
        approve: false,
        note,
    };

    let unknown = decide(ApprovalId::new().to_string(), None);
    assert_eq!(
        call::<_, proto::DecideResponse>(&router, DECIDE, Some(APPROVER), &unknown).await,
        Err(failure(NOT_FOUND, "The approval request does not exist."))
    );
    let bad_id = decide("seven".to_owned(), None);
    assert_eq!(
        call::<_, proto::DecideResponse>(&router, DECIDE, Some(APPROVER), &bad_id).await,
        Err(failure(INVALID_ARGUMENT, "id is not a valid UUID."))
    );
    let long_note = decide(approval.id.to_string(), Some("x".repeat(1001)));
    assert_eq!(
        call::<_, proto::DecideResponse>(&router, DECIDE, Some(APPROVER), &long_note).await,
        Err(failure(
            INVALID_ARGUMENT,
            "The note must have 1000 characters or fewer."
        ))
    );
    assert!(api.actions.calls().is_empty());

    let response: proto::DecideResponse = call(
        &router,
        DECIDE,
        Some(APPROVER),
        &decide(approval.id.to_string(), None),
    )
    .await
    .unwrap();
    assert_eq!(
        response.request.map(|request| request.status),
        Some(i32::from(proto::ApprovalStatus::Rejected))
    );
    assert_eq!(response.disposition, None);
    assert_eq!(api.actions.calls().len(), 1);
    assert!(!api.actions.calls()[0].approve);
}

#[tokio::test]
async fn a_method_that_a_service_does_not_have_is_unimplemented() {
    let api = TestApi::new();
    let router = api.router();
    let result = call::<_, proto::Incident>(
        &router,
        "/aegis.v1.IncidentService/DeleteIncident",
        Some(VIEWER),
        &proto::GetIncidentRequest { id: String::new() },
    )
    .await;
    assert_eq!(result.unwrap_err().code, UNIMPLEMENTED);
}

#[tokio::test]
async fn the_server_answers_grpc_calls_over_http2() {
    let api = TestApi::new();
    let seeded = api.seed_incident("Password spray", Severity::High).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Shutdown::new();
    let server = tokio::spawn(aegis_api::serve_on(
        listener,
        api.state.clone(),
        config(),
        shutdown.clone(),
    ));

    // gRPC with no TLS uses HTTP/2 from the first byte.
    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let url = format!("http://{address}{GET_INCIDENT}");
    let request = frame(&proto::GetIncidentRequest {
        id: seeded.id.to_string(),
    });

    let response = client
        .post(&url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .bearer_auth(VIEWER)
        .body(request.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
    let incident: proto::Incident = unframe(&response.bytes().await.unwrap());
    assert_eq!(incident.id, seeded.id.to_string());
    assert_eq!(incident.title, "Password spray");

    // A call with no token is refused. The status of a refused call is in the headers.
    let refused = client
        .post(&url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(grpc_status(refused.headers()), Some(UNAUTHENTICATED));

    shutdown.trigger();
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("the server did not stop in time")
        .unwrap()
        .unwrap();
}
