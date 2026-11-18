//! The gRPC services `aegis.v1.IncidentService` and `aegis.v1.ApprovalService`.
//!
//! The Cargo feature `grpc` adds this module. [`router`](crate::router) then also serves
//! the two services, on the same port as the REST API. gRPC needs HTTP/2. The server
//! accepts HTTP/2 with prior knowledge on a connection with no TLS.
//!
//! The services use the authentication and the access rules of the REST API. A call sends
//! the bearer token in the metadata key `authorization`.
//!
//! | REST error | gRPC status |
//! | --- | --- |
//! | 400 | `INVALID_ARGUMENT` |
//! | 401 | `UNAUTHENTICATED` |
//! | 403 | `PERMISSION_DENIED` |
//! | 404 | `NOT_FOUND` |
//! | 409 | `FAILED_PRECONDITION` |
//! | 413, 429 | `RESOURCE_EXHAUSTED` |
//! | 501 | `UNIMPLEMENTED` |
//! | 503 | `UNAVAILABLE` |
//! | 504 | `DEADLINE_EXCEEDED` |
//! | Other | `INTERNAL` |

use aegis_contracts::action::{ActionDisposition, ActionOutcome, ActionRequest};
use aegis_contracts::common::{ApprovalId, EntityRef, EvidenceRef, IncidentId, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection};
use aegis_contracts::incident::{Incident, IncidentStatus, TimelineEntry};
use aegis_contracts::policy::{
    ApprovalRequest, ApprovalStatus, PolicyDecision, Principal as ContractPrincipal,
};
use axum::Router;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status};

use crate::chatops::view::{action_label, wire_name};
use crate::error::ApiError;
use crate::ops;
use crate::routes::Ctx;
use crate::state::ApprovalDecision;

/// The messages, the clients, and the server traits that the proto file
/// `proto/aegis/v1/aegis.proto` defines.
pub mod proto {
    #![allow(missing_docs)]
    tonic::include_proto!("aegis.v1");
}

use proto::approval_service_server::{ApprovalService, ApprovalServiceServer};
use proto::incident_service_server::{IncidentService, IncidentServiceServer};

/// Maps an API error to a gRPC status. The message is the message of the REST error.
fn status(error: &ApiError) -> Status {
    let view = error.view();
    let code = match view.status {
        StatusCode::BAD_REQUEST
        | StatusCode::METHOD_NOT_ALLOWED
        | StatusCode::UNSUPPORTED_MEDIA_TYPE => Code::InvalidArgument,
        StatusCode::UNAUTHORIZED => Code::Unauthenticated,
        StatusCode::FORBIDDEN => Code::PermissionDenied,
        StatusCode::NOT_FOUND => Code::NotFound,
        StatusCode::CONFLICT => Code::FailedPrecondition,
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::TOO_MANY_REQUESTS => Code::ResourceExhausted,
        StatusCode::NOT_IMPLEMENTED => Code::Unimplemented,
        StatusCode::SERVICE_UNAVAILABLE => Code::Unavailable,
        StatusCode::GATEWAY_TIMEOUT => Code::DeadlineExceeded,
        _ => Code::Internal,
    };
    if code == Code::Internal {
        tracing::error!(?error, "a gRPC call failed");
    }
    Status::new(code, view.message)
}

fn failed(error: ApiError) -> Status {
    status(&error)
}

/// Identifies the principal of a call from the bearer token in the metadata.
fn principal<T>(ctx: &Ctx, request: &Request<T>) -> Result<ContractPrincipal, Status> {
    ctx.auth
        .authenticate(request.metadata().as_ref())
        .ok_or_else(|| status(&ApiError::Unauthenticated))
}

/// Returns the page size for a request. The value 0 gives the default page size.
fn page_size(ctx: &Ctx, limit: u32) -> Result<usize, Status> {
    let largest = ctx.limits.max_page_size;
    if limit == 0 {
        return Ok(ctx.limits.default_page_size);
    }
    usize::try_from(limit)
        .ok()
        .filter(|limit| *limit <= largest)
        .ok_or_else(|| Status::invalid_argument(format!("limit must be from 0 to {largest}.")))
}

fn timestamp(time: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: time.timestamp(),
        nanos: i32::try_from(time.timestamp_subsec_nanos()).unwrap_or(i32::MAX),
    }
}

fn severity(value: Severity) -> i32 {
    let severity = match value {
        Severity::Informational => proto::Severity::Informational,
        Severity::Low => proto::Severity::Low,
        Severity::Medium => proto::Severity::Medium,
        Severity::High => proto::Severity::High,
        Severity::Critical => proto::Severity::Critical,
    };
    severity.into()
}

fn incident_status(value: IncidentStatus) -> i32 {
    let status = match value {
        IncidentStatus::Open => proto::IncidentStatus::Open,
        IncidentStatus::Investigating => proto::IncidentStatus::Investigating,
        IncidentStatus::Contained => proto::IncidentStatus::Contained,
        IncidentStatus::Resolved => proto::IncidentStatus::Resolved,
        IncidentStatus::FalsePositive => proto::IncidentStatus::FalsePositive,
    };
    status.into()
}

/// Returns the state filter of a request. `None` means all states.
fn status_filter(value: i32) -> Result<Option<IncidentStatus>, Status> {
    match proto::IncidentStatus::try_from(value) {
        Ok(proto::IncidentStatus::Unspecified) => Ok(None),
        Ok(proto::IncidentStatus::Open) => Ok(Some(IncidentStatus::Open)),
        Ok(proto::IncidentStatus::Investigating) => Ok(Some(IncidentStatus::Investigating)),
        Ok(proto::IncidentStatus::Contained) => Ok(Some(IncidentStatus::Contained)),
        Ok(proto::IncidentStatus::Resolved) => Ok(Some(IncidentStatus::Resolved)),
        Ok(proto::IncidentStatus::FalsePositive) => Ok(Some(IncidentStatus::FalsePositive)),
        Err(_) => Err(Status::invalid_argument(
            "status is not a value of IncidentStatus.",
        )),
    }
}

fn approval_status(value: ApprovalStatus) -> i32 {
    let status = match value {
        ApprovalStatus::Pending => proto::ApprovalStatus::Pending,
        ApprovalStatus::Approved => proto::ApprovalStatus::Approved,
        ApprovalStatus::Rejected => proto::ApprovalStatus::Rejected,
    };
    status.into()
}

fn json_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn entity(value: &EntityRef) -> proto::EntityRef {
    proto::EntityRef {
        kind: wire_name(&value.kind),
        id: value.id.clone(),
        name: value.name.clone(),
        tenant: value.tenant.clone(),
    }
}

fn technique(value: &AttackTechnique) -> proto::AttackTechnique {
    proto::AttackTechnique {
        tactic: value.tactic.clone(),
        technique_id: value.technique_id.clone(),
        name: value.name.clone(),
    }
}

fn evidence(value: &EvidenceRef) -> proto::EvidenceRef {
    proto::EvidenceRef {
        kind: wire_name(&value.kind),
        id: value.id.clone(),
        note: value.note.clone(),
    }
}

fn timeline_entry(value: &TimelineEntry) -> proto::TimelineEntry {
    proto::TimelineEntry {
        time: Some(timestamp(value.time)),
        author: value.author.clone(),
        description: value.description.clone(),
        evidence: value.evidence.iter().map(evidence).collect(),
    }
}

fn detection(value: &Detection) -> proto::Detection {
    proto::Detection {
        id: value.id.to_string(),
        rule_id: value.rule_id.clone(),
        title: value.title.clone(),
        description: value.description.clone(),
        severity: severity(value.severity),
        verdict: wire_name(&value.verdict),
        tier: wire_name(&value.tier),
        time: Some(timestamp(value.time)),
        attack: value.attack.iter().map(technique).collect(),
        event_ids: value.event_ids.iter().map(ToString::to_string).collect(),
        entities: value.entities.iter().map(entity).collect(),
        tenant: value.tenant.clone(),
        attributes_json: json_text(&value.attributes),
    }
}

fn incident(value: &Incident) -> proto::Incident {
    proto::Incident {
        id: value.id.to_string(),
        title: value.title.clone(),
        summary: value.summary.clone(),
        severity: severity(value.severity),
        status: incident_status(value.status),
        created_at: Some(timestamp(value.created_at)),
        updated_at: Some(timestamp(value.updated_at)),
        tenant: value.tenant.clone(),
        detections: value.detections.iter().map(detection).collect(),
        entities: value.entities.iter().map(entity).collect(),
        attack: value.attack.iter().map(technique).collect(),
        timeline: value.timeline.iter().map(timeline_entry).collect(),
    }
}

fn policy_decision(value: &PolicyDecision) -> proto::PolicyDecision {
    proto::PolicyDecision {
        effect: wire_name(&value.effect),
        tier: wire_name(&value.tier),
        reasons: value.reasons.clone(),
        policy: value.policy.clone(),
        evaluated_at: Some(timestamp(value.evaluated_at)),
    }
}

fn action_request(value: &ActionRequest) -> proto::ActionRequest {
    proto::ActionRequest {
        id: value.id.to_string(),
        kind: action_label(&value.kind),
        target: Some(entity(&value.target)),
        parameters_json: json_text(&value.parameters),
        incident_id: value.incident_id.map(|id| id.to_string()),
        requested_by: value.requested_by.clone(),
        reason: value.reason.clone(),
        evidence: value.evidence.iter().map(evidence).collect(),
        dry_run: value.dry_run,
        requested_at: Some(timestamp(value.requested_at)),
    }
}

fn approval_request(value: &ApprovalRequest) -> proto::ApprovalRequest {
    proto::ApprovalRequest {
        id: value.id.to_string(),
        action: Some(action_request(&value.action)),
        requested_by: Some(proto::Principal {
            id: value.requested_by.id.clone(),
            kind: wire_name(&value.requested_by.kind),
            roles: value.requested_by.roles.clone(),
        }),
        decision: Some(policy_decision(&value.decision)),
        status: approval_status(value.status),
        requested_at: Some(timestamp(value.requested_at)),
        decided_by: value.decided_by.clone(),
        decided_at: value.decided_at.map(timestamp),
        note: value.note.clone(),
    }
}

fn action_outcome(value: &ActionOutcome) -> proto::ActionOutcome {
    proto::ActionOutcome {
        action_id: value.action_id.to_string(),
        status: wire_name(&value.status),
        connector: value.connector.clone(),
        message: value.message.clone(),
        details_json: json_text(&value.details),
        reversible: value.reversible,
        completed_at: Some(timestamp(value.completed_at)),
    }
}

fn disposition(value: &ActionDisposition) -> proto::ActionDisposition {
    use proto::action_disposition::Result as Kind;
    let result = match value {
        ActionDisposition::Executed(outcome) => Kind::Executed(action_outcome(outcome)),
        ActionDisposition::PendingApproval {
            approval_id,
            decision,
        } => Kind::PendingApproval(proto::PendingApproval {
            approval_id: approval_id.to_string(),
            decision: Some(policy_decision(decision)),
        }),
        ActionDisposition::Denied(decision) => Kind::Denied(policy_decision(decision)),
    };
    proto::ActionDisposition {
        result: Some(result),
    }
}

fn decide_response(value: &ApprovalDecision) -> proto::DecideResponse {
    proto::DecideResponse {
        request: Some(approval_request(&value.request)),
        disposition: value.disposition.as_ref().map(disposition),
    }
}

struct Incidents {
    ctx: Ctx,
}

#[tonic::async_trait]
impl IncidentService for Incidents {
    async fn list_incidents(
        &self,
        request: Request<proto::ListIncidentsRequest>,
    ) -> Result<Response<proto::ListIncidentsResponse>, Status> {
        let principal = principal(&self.ctx, &request)?;
        let request = request.into_inner();
        let status = status_filter(request.status)?;
        let limit = page_size(&self.ctx, request.limit)?;
        let mut incidents = ops::list_incidents(&self.ctx.state, &principal, status, limit)
            .await
            .map_err(failed)?;
        incidents.truncate(limit);
        Ok(Response::new(proto::ListIncidentsResponse {
            incidents: incidents.iter().map(incident).collect(),
        }))
    }

    async fn get_incident(
        &self,
        request: Request<proto::GetIncidentRequest>,
    ) -> Result<Response<proto::Incident>, Status> {
        let principal = principal(&self.ctx, &request)?;
        let id: IncidentId = request
            .get_ref()
            .id
            .parse()
            .map_err(|_| Status::invalid_argument("id is not a valid UUID."))?;
        let found = ops::get_incident(&self.ctx.state, &principal, id)
            .await
            .map_err(failed)?;
        Ok(Response::new(incident(&found)))
    }
}

struct Approvals {
    ctx: Ctx,
}

#[tonic::async_trait]
impl ApprovalService for Approvals {
    async fn list_pending(
        &self,
        request: Request<proto::ListPendingRequest>,
    ) -> Result<Response<proto::ListPendingResponse>, Status> {
        let principal = principal(&self.ctx, &request)?;
        let limit = page_size(&self.ctx, request.get_ref().limit)?;
        let mut pending = ops::pending_approvals(&self.ctx.state, &principal)
            .await
            .map_err(failed)?;
        let total = u32::try_from(pending.len()).unwrap_or(u32::MAX);
        pending.truncate(limit);
        Ok(Response::new(proto::ListPendingResponse {
            requests: pending.iter().map(approval_request).collect(),
            total,
        }))
    }

    async fn decide(
        &self,
        request: Request<proto::DecideRequest>,
    ) -> Result<Response<proto::DecideResponse>, Status> {
        let principal = principal(&self.ctx, &request)?;
        let request = request.into_inner();
        let id: ApprovalId = request
            .id
            .parse()
            .map_err(|_| Status::invalid_argument("id is not a valid UUID."))?;
        let decision = ops::decide_approval(
            &self.ctx.state,
            &principal,
            id,
            request.approve,
            request.note,
        )
        .await
        .map_err(failed)?;
        Ok(Response::new(decide_response(&decision)))
    }
}

fn service_path<S: NamedService>() -> String {
    format!("/{}/{{*method}}", S::NAME)
}

/// Builds the router of the gRPC services.
pub(crate) fn grpc_router(ctx: &Ctx) -> Router<Ctx> {
    let limit = ctx.limits.max_body_bytes;
    let incidents =
        IncidentServiceServer::new(Incidents { ctx: ctx.clone() }).max_decoding_message_size(limit);
    let approvals =
        ApprovalServiceServer::new(Approvals { ctx: ctx.clone() }).max_decoding_message_size(limit);
    Router::new()
        .route_service(
            &service_path::<IncidentServiceServer<Incidents>>(),
            incidents,
        )
        .route_service(
            &service_path::<ApprovalServiceServer<Approvals>>(),
            approvals,
        )
}

#[cfg(test)]
mod tests {
    use aegis_contracts::Error;
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn each_api_error_has_its_grpc_status() {
        let cases = [
            (ApiError::Unauthenticated, Code::Unauthenticated),
            (ApiError::Forbidden("no".into()), Code::PermissionDenied),
            (ApiError::BadRequest("bad".into()), Code::InvalidArgument),
            (ApiError::NotFound("none".into()), Code::NotFound),
            (ApiError::Conflict("done".into()), Code::FailedPrecondition),
            (ApiError::PayloadTooLarge, Code::ResourceExhausted),
            (ApiError::TooManyStreams, Code::ResourceExhausted),
            (ApiError::Timeout, Code::DeadlineExceeded),
            (
                ApiError::Contract(Error::Unavailable("db".into())),
                Code::Unavailable,
            ),
            (
                ApiError::Contract(Error::Unsupported("x".into())),
                Code::Unimplemented,
            ),
            (
                ApiError::Contract(Error::Unauthorized("rule".into())),
                Code::PermissionDenied,
            ),
            (
                ApiError::Contract(Error::Integrity("chain".into())),
                Code::Internal,
            ),
        ];
        assert_eq!(cases.len(), 12);
        for (error, code) in cases {
            assert_eq!(status(&error).code(), code, "{error:?}");
        }
    }

    #[test]
    fn a_server_fault_keeps_its_cause_out_of_the_status() {
        let error = ApiError::Contract(Error::Unavailable(
            "postgres://aegis:hunter2@db.internal".to_owned(),
        ));
        let status = status(&error);
        assert_eq!(
            status.message(),
            "A service is not available. Try again later."
        );
    }

    #[test]
    fn a_time_keeps_its_seconds_and_its_nanoseconds() {
        let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 0).unwrap()
            + chrono::Duration::nanoseconds(123_456_789);
        assert_eq!(
            timestamp(time),
            prost_types::Timestamp {
                seconds: 1_793_696_400,
                nanos: 123_456_789
            }
        );
    }

    #[test]
    fn an_unknown_state_filter_is_an_error() {
        assert_eq!(status_filter(0).unwrap(), None);
        assert_eq!(status_filter(3).unwrap(), Some(IncidentStatus::Contained));
        assert_eq!(status_filter(99).unwrap_err().code(), Code::InvalidArgument);
    }
}
