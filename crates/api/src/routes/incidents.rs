//! The incident routes and the explanation routes.

use aegis_contracts::common::{ActionId, IncidentId};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_policy::{Explanation, explain_action, explain_incident};
use axum::Json;
use axum::extract::{RawQuery, State};
use serde::Serialize;

use super::{Caller, Ctx, PathText};
use crate::error::ApiResult;
use crate::extract::{Params, path_id};
use crate::ops;

const STATUS_NAMES: &str = "open, investigating, contained, resolved, false_positive";

/// A list of items. Each list route answers with this form.
#[derive(Debug, Serialize)]
pub(crate) struct Items<T> {
    pub items: Vec<T>,
}

/// `GET /incidents`: the incidents, newest first.
pub(crate) async fn list(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Items<Incident>>> {
    let params = Params::parse(query.as_deref(), &["status", "limit"])?;
    let status: Option<IncidentStatus> = params.variant("status", STATUS_NAMES)?;
    let limit = params.limit(&ctx.limits)?;
    let mut items = ops::list_incidents(&ctx.state, &principal, status, limit).await?;
    items.truncate(limit);
    Ok(Json(Items { items }))
}

/// `GET /incidents/{id}`: one incident.
pub(crate) async fn one(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(id): PathText,
) -> ApiResult<Json<Incident>> {
    let id: IncidentId = path_id(&id, "incident")?;
    Ok(Json(ops::get_incident(&ctx.state, &principal, id).await?))
}

/// `GET /incidents/{id}/explanation`: the audit records of one incident and its actions.
pub(crate) async fn explanation(
    State(ctx): State<Ctx>,
    PathText(id): PathText,
) -> ApiResult<Json<Explanation>> {
    let id: IncidentId = path_id(&id, "incident")?;
    Ok(Json(
        explain_incident(ctx.state.parts().audit.as_ref(), id).await?,
    ))
}

/// `GET /actions/{id}/explanation`: the audit records of one action.
pub(crate) async fn action_explanation(
    State(ctx): State<Ctx>,
    PathText(id): PathText,
) -> ApiResult<Json<Explanation>> {
    let id: ActionId = path_id(&id, "action")?;
    Ok(Json(
        explain_action(ctx.state.parts().audit.as_ref(), id).await?,
    ))
}
