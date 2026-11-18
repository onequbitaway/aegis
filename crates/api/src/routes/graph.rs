//! The Defensive Graph routes.

use aegis_contracts::graph::{Direction, GraphNode, NodeId, NodeKind};
use axum::Json;
use axum::extract::{RawQuery, State};
use serde::Serialize;

use super::incidents::Items;
use super::{Ctx, PathText};
use crate::error::{ApiError, ApiResult};
use crate::extract::Params;

const KIND_NAMES: &str = "asset, identity, alert, finding, incident";
const DIRECTION_NAMES: &str = "outgoing, incoming, both";

/// The maximum length of a node identifier and of a relation name, in bytes.
const MAX_NAME_BYTES: usize = 512;

fn node_id(text: String) -> ApiResult<NodeId> {
    if text.is_empty() || text.len() > MAX_NAME_BYTES {
        return Err(ApiError::BadRequest(format!(
            "The node identifier must have from 1 to {MAX_NAME_BYTES} bytes."
        )));
    }
    Ok(NodeId(text))
}

async fn existing_node(ctx: &Ctx, id: &NodeId) -> ApiResult<GraphNode> {
    ctx.state
        .parts()
        .graph
        .node(id)
        .await?
        .ok_or_else(|| ApiError::NotFound("The graph node does not exist.".to_owned()))
}

/// `GET /graph/nodes`: the nodes of one type, newest first.
pub(crate) async fn nodes(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Items<GraphNode>>> {
    let params = Params::parse(query.as_deref(), &["kind", "limit"])?;
    let kind: NodeKind = params.variant("kind", KIND_NAMES)?.ok_or_else(|| {
        ApiError::BadRequest(format!(
            "The query parameter kind is necessary. It must be one of: {KIND_NAMES}."
        ))
    })?;
    let limit = params.limit(&ctx.limits)?;
    let mut items = ctx.state.parts().graph.nodes_by_kind(kind, limit).await?;
    items.truncate(limit);
    Ok(Json(Items { items }))
}

/// `GET /graph/nodes/{id}`: one node.
pub(crate) async fn node(
    State(ctx): State<Ctx>,
    PathText(id): PathText,
) -> ApiResult<Json<GraphNode>> {
    let id = node_id(id)?;
    Ok(Json(existing_node(&ctx, &id).await?))
}

/// The neighbors of a node. `total` counts the neighbors before the `limit` applies.
#[derive(Debug, Serialize)]
pub(crate) struct Neighbors {
    node: GraphNode,
    items: Vec<GraphNode>,
    total: usize,
}

/// `GET /graph/nodes/{id}/neighbors`: the nodes that have a relation with one node.
pub(crate) async fn neighbors(
    State(ctx): State<Ctx>,
    PathText(id): PathText,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Neighbors>> {
    let id = node_id(id)?;
    let params = Params::parse(query.as_deref(), &["direction", "relation", "limit"])?;
    let direction: Direction = params
        .variant("direction", DIRECTION_NAMES)?
        .unwrap_or(Direction::Both);
    let relation = params.text("relation");
    if relation.is_some_and(|relation| relation.len() > MAX_NAME_BYTES) {
        return Err(ApiError::BadRequest(format!(
            "The query parameter relation must have {MAX_NAME_BYTES} bytes or fewer."
        )));
    }
    let limit = params.limit(&ctx.limits)?;
    let node = existing_node(&ctx, &id).await?;
    let mut items = ctx
        .state
        .parts()
        .graph
        .neighbors(&id, relation, direction)
        .await?;
    let total = items.len();
    items.truncate(limit);
    Ok(Json(Neighbors { node, items, total }))
}
