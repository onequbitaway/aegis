//! The routes of the timed reverts, and the revert of one action.
//!
//! Each route calls [`RevertActions`](crate::RevertActions). The composition root writes
//! each audit record with the principal of the request, and it sends each revert through
//! the dispatcher: the policy, the approval queue, and the audit log.

use std::time::Duration;

use aegis_contracts::action::ActionDisposition;
use aegis_contracts::common::ActionId;
use aegis_respond::PendingRevert;
use axum::Json;
use axum::extract::{RawQuery, State};
use serde::{Deserialize, Serialize};

use super::{Caller, Ctx, PathText};
use crate::error::{ApiError, ApiResult};
use crate::extract::{JsonBody, Params, path_id};
use crate::ops;

/// The pending timed reverts. `total` counts the reverts before the `limit` applies.
#[derive(Debug, Serialize)]
pub(crate) struct PendingReverts {
    /// `false` if the process holds no timed reverts.
    enabled: bool,
    items: Vec<PendingRevert>,
    total: usize,
}

/// `GET /reverts`: the timed reverts that wait, earliest revert time first.
pub(crate) async fn pending(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<PendingReverts>> {
    let params = Params::parse(query.as_deref(), &["limit"])?;
    let limit = params.limit(&ctx.limits)?;
    let (enabled, mut items) = ops::pending_reverts(&ctx.state, &principal).await?;
    let total = items.len();
    items.truncate(limit);
    Ok(Json(PendingReverts {
        enabled,
        items,
        total,
    }))
}

/// A body with no field. The request names the action in its path.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoFields {}

/// The pending revert after a decision of a person.
#[derive(Debug, Serialize)]
pub(crate) struct RevertAnswer {
    revert: PendingRevert,
}

/// What the dispatcher did with a revert.
#[derive(Debug, Serialize)]
pub(crate) struct DispositionAnswer {
    disposition: ActionDisposition,
}

/// `POST /reverts/{action_id}/confirm`: the containment stays. AEGIS does not revert it.
///
/// The principal of the token is the principal of the audit record.
pub(crate) async fn confirm(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
    JsonBody(NoFields {}): JsonBody<NoFields>,
) -> ApiResult<Json<RevertAnswer>> {
    let action_id: ActionId = path_id(&id, "action")?;
    let revert = ops::confirm_revert(&ctx.state, &principal, action_id).await?;
    Ok(Json(RevertAnswer { revert }))
}

/// The body of an extension.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtendRequest {
    /// The time to add to the revert time, in seconds.
    seconds: u64,
}

/// `POST /reverts/{action_id}/extend`: moves the revert time.
pub(crate) async fn extend(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
    JsonBody(request): JsonBody<ExtendRequest>,
) -> ApiResult<Json<RevertAnswer>> {
    let action_id: ActionId = path_id(&id, "action")?;
    if request.seconds == 0 {
        return Err(ApiError::BadRequest(
            "The extension must be 1 second or more.".to_owned(),
        ));
    }
    let revert = ops::extend_revert(
        &ctx.state,
        &principal,
        action_id,
        Duration::from_secs(request.seconds),
    )
    .await?;
    Ok(Json(RevertAnswer { revert }))
}

/// `POST /reverts/{action_id}/cancel`: reverts the action now, before its revert time.
pub(crate) async fn cancel(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
    JsonBody(NoFields {}): JsonBody<NoFields>,
) -> ApiResult<Json<DispositionAnswer>> {
    let action_id: ActionId = path_id(&id, "action")?;
    let disposition = ops::cancel_revert(&ctx.state, &principal, action_id).await?;
    Ok(Json(DispositionAnswer { disposition }))
}

/// The body of a revert.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevertRequest {
    /// Why the person reverts the action. The audit log keeps the text.
    reason: String,
}

/// `POST /actions/{id}/revert`: reverts one action that a connector did before.
pub(crate) async fn revert_action(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
    JsonBody(request): JsonBody<RevertRequest>,
) -> ApiResult<Json<DispositionAnswer>> {
    let action_id: ActionId = path_id(&id, "action")?;
    let disposition =
        ops::revert_action(&ctx.state, &principal, action_id, &request.reason).await?;
    Ok(Json(DispositionAnswer { disposition }))
}
