//! The approval routes.

use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::ApprovalRequest;
use axum::Json;
use axum::extract::{RawQuery, State};
use serde::{Deserialize, Serialize};

use super::{Caller, Ctx, PathText};
use crate::error::ApiResult;
use crate::extract::{JsonBody, Params, path_id};
use crate::ops;
use crate::state::ApprovalDecision;

/// The pending approval requests. `total` counts the requests before the `limit` applies,
/// so a caller can see that the list is not complete.
#[derive(Debug, Serialize)]
pub(crate) struct PendingApprovals {
    items: Vec<ApprovalRequest>,
    total: usize,
}

/// `GET /approvals`: the approval requests that have no decision, oldest first.
pub(crate) async fn pending(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<PendingApprovals>> {
    let params = Params::parse(query.as_deref(), &["limit"])?;
    let limit = params.limit(&ctx.limits)?;
    let mut items = ops::pending_approvals(&ctx.state, &principal).await?;
    let total = items.len();
    items.truncate(limit);
    Ok(Json(PendingApprovals { items, total }))
}

/// `GET /approvals/{id}`: one approval request, with or without a decision.
pub(crate) async fn one(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
) -> ApiResult<Json<ApprovalRequest>> {
    let id: ApprovalId = path_id(&id, "approval")?;
    Ok(Json(ops::get_approval(&ctx.state, &principal, id).await?))
}

/// The body of a decision.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionRequest {
    approve: bool,
    #[serde(default)]
    note: Option<String>,
}

/// `POST /approvals/{id}/decision`: approves or rejects one gated action.
///
/// The principal of the token is the principal of the decision.
pub(crate) async fn decide(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
    JsonBody(request): JsonBody<DecisionRequest>,
) -> ApiResult<Json<ApprovalDecision>> {
    let id: ApprovalId = path_id(&id, "approval")?;
    let decision =
        ops::decide_approval(&ctx.state, &principal, id, request.approve, request.note).await?;
    Ok(Json(decision))
}
