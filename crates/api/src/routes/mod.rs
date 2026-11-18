//! The REST routes under `/api/v1`, and the permission that each route needs.

use std::sync::Arc;

use aegis_contracts::policy::Principal;
use aegis_core::Shutdown;
use aegis_policy::Permission;
use axum::Router;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use tokio::sync::{Mutex, Semaphore};

use crate::auth::Authenticator;
use crate::chatops::ChatOps;
use crate::config::LimitsConfig;
use crate::error::{ApiError, ApiResult};
use crate::ops;
use crate::state::ApiState;

mod approvals;
mod audit;
mod graph;
mod incidents;
mod playbooks;
mod reverts;
mod stream;
mod system;

pub(crate) use audit::AuditHead;
pub(crate) use system::healthz;

/// The base path of the REST API.
pub const API_BASE: &str = "/api/v1";

/// The data that each request handler shares.
pub(crate) struct AppContext {
    /// The services.
    pub state: ApiState,
    /// The principals and their tokens.
    pub auth: Authenticator,
    /// The limits of the server.
    pub limits: LimitsConfig,
    /// One permit for each live feed that is open.
    pub streams: Arc<Semaphore>,
    /// The signal that ends the live feeds.
    pub shutdown: Shutdown,
    /// The last audit record that the status route found.
    pub audit_head: Mutex<Option<AuditHead>>,
    /// The ChatOps secrets and users.
    pub chat: ChatOps,
}

/// The shared handle to the request data.
pub(crate) type Ctx = Arc<AppContext>;

/// One REST route and the permissions that let a principal use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutePermission {
    /// The HTTP method, for example `GET`.
    pub method: &'static str,
    /// The path below `/api/v1`, for example `/incidents/{id}`.
    pub path: &'static str,
    /// The permissions. One of them is sufficient. An empty list means that each
    /// principal with a valid token can use the route.
    pub any_of: &'static [Permission],
}

struct Entry {
    permission: RoutePermission,
    handler: MethodRouter<Ctx>,
}

fn entry(
    method: &'static str,
    path: &'static str,
    any_of: &'static [Permission],
    handler: MethodRouter<Ctx>,
) -> Entry {
    Entry {
        permission: RoutePermission {
            method,
            path,
            any_of,
        },
        handler,
    }
}

const ANY_PRINCIPAL: &[Permission] = &[];
const VIEW_INCIDENTS: &[Permission] = &[Permission::ViewIncidents];
const VIEW_AUDIT: &[Permission] = &[Permission::ViewAudit];
const APPROVE: &[Permission] = &[Permission::ApproveActions];
const RUN_PLAYBOOKS: &[Permission] = &[Permission::RunPlaybooks];
const VIEW_PLAYBOOKS: &[Permission] = &[Permission::ViewIncidents, Permission::RunPlaybooks];
const ADMINISTER: &[Permission] = &[Permission::Administer];

/// The single list of the protected routes. The router and [`route_permissions`] both come
/// from this list, so a route cannot exist without a permission entry.
fn table() -> Vec<Entry> {
    vec![
        entry("GET", "/session", ANY_PRINCIPAL, get(system::session)),
        entry("GET", "/status", VIEW_INCIDENTS, get(system::status)),
        entry("GET", "/incidents", VIEW_INCIDENTS, get(incidents::list)),
        entry(
            "GET",
            "/incidents/{id}",
            VIEW_INCIDENTS,
            get(incidents::one),
        ),
        entry(
            "GET",
            "/incidents/{id}/explanation",
            VIEW_AUDIT,
            get(incidents::explanation),
        ),
        entry(
            "GET",
            "/actions/{id}/explanation",
            VIEW_AUDIT,
            get(incidents::action_explanation),
        ),
        entry(
            "GET",
            "/approvals",
            ops::READ_APPROVALS,
            get(approvals::pending),
        ),
        entry(
            "GET",
            "/approvals/{id}",
            ops::READ_APPROVALS,
            get(approvals::one),
        ),
        entry(
            "POST",
            "/approvals/{id}/decision",
            APPROVE,
            post(approvals::decide),
        ),
        entry(
            "GET",
            "/reverts",
            ops::READ_APPROVALS,
            get(reverts::pending),
        ),
        entry(
            "POST",
            "/reverts/{action_id}/confirm",
            APPROVE,
            post(reverts::confirm),
        ),
        entry(
            "POST",
            "/reverts/{action_id}/extend",
            APPROVE,
            post(reverts::extend),
        ),
        entry(
            "POST",
            "/reverts/{action_id}/cancel",
            APPROVE,
            post(reverts::cancel),
        ),
        entry(
            "POST",
            "/actions/{id}/revert",
            APPROVE,
            post(reverts::revert_action),
        ),
        entry("GET", "/graph/nodes", VIEW_INCIDENTS, get(graph::nodes)),
        entry("GET", "/graph/nodes/{id}", VIEW_INCIDENTS, get(graph::node)),
        entry(
            "GET",
            "/graph/nodes/{id}/neighbors",
            VIEW_INCIDENTS,
            get(graph::neighbors),
        ),
        entry("GET", "/audit", VIEW_AUDIT, get(audit::list)),
        entry(
            "GET",
            "/audit/verification",
            VIEW_AUDIT,
            get(audit::verification),
        ),
        entry("GET", "/agents", VIEW_INCIDENTS, get(system::agents)),
        entry("POST", "/goal", ADMINISTER, post(system::goal)),
        entry("GET", "/playbooks", VIEW_PLAYBOOKS, get(playbooks::list)),
        entry(
            "POST",
            "/playbooks/{name}/runs",
            RUN_PLAYBOOKS,
            post(playbooks::run),
        ),
        entry("GET", "/stream", VIEW_INCIDENTS, get(stream::stream)),
    ]
}

/// Returns each protected REST route with the permissions that it needs.
///
/// `GET /healthz` is the only route with no authentication. It is not in this list.
#[must_use]
pub fn route_permissions() -> Vec<RoutePermission> {
    table().into_iter().map(|entry| entry.permission).collect()
}

/// The principal of a request. The guard of the route puts it in the request.
#[derive(Debug, Clone)]
pub(crate) struct Caller(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = ApiError;

    /// A handler that runs without the guard has no principal. That request is refused.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> ApiResult<Self> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }
}

/// One path parameter as text.
pub(crate) struct PathText(pub String);

impl<S: Send + Sync> FromRequestParts<S> for PathText {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> ApiResult<Self> {
        Path::<String>::from_request_parts(parts, state)
            .await
            .map(|Path(text)| Self(text))
            .map_err(|_| ApiError::BadRequest("The path is not valid.".to_owned()))
    }
}

#[derive(Clone)]
struct Guard {
    ctx: Ctx,
    any_of: &'static [Permission],
}

/// Identifies the principal and checks its permission before the handler runs.
async fn guard(State(guard): State<Guard>, mut request: Request, next: Next) -> Response {
    let Some(principal) = guard.ctx.auth.authenticate(request.headers()) else {
        return ApiError::Unauthenticated.into_response();
    };
    if !guard.any_of.is_empty()
        && let Err(error) = ops::require(&guard.ctx.state, &principal, guard.any_of)
    {
        return error.into_response();
    }
    request.extensions_mut().insert(Caller(principal));
    next.run(request).await
}

/// Builds the router for the protected routes. The paths are relative to [`API_BASE`].
pub(crate) fn api_router(ctx: &Ctx) -> Router<Ctx> {
    let mut router = Router::new();
    for entry in table() {
        let guard_state = Guard {
            ctx: ctx.clone(),
            any_of: entry.permission.any_of,
        };
        let handler = entry
            .handler
            .route_layer(middleware::from_fn_with_state(guard_state, guard));
        router = router.route(entry.permission.path, handler);
    }
    router
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn each_route_is_in_the_list_one_time() {
        let routes = route_permissions();
        let unique: BTreeSet<(&str, &str)> = routes
            .iter()
            .map(|route| (route.method, route.path))
            .collect();
        assert!(!routes.is_empty());
        assert_eq!(unique.len(), routes.len());
    }

    #[test]
    fn only_the_session_route_needs_no_permission() {
        let open: Vec<&str> = route_permissions()
            .iter()
            .filter(|route| route.any_of.is_empty())
            .map(|route| route.path)
            .collect();
        assert_eq!(open, ["/session"]);
    }

    #[test]
    fn each_route_that_changes_state_needs_a_specific_permission() {
        let posts: Vec<(&str, &[Permission])> = route_permissions()
            .iter()
            .filter(|route| route.method == "POST")
            .map(|route| (route.path, route.any_of))
            .collect();
        assert_eq!(
            posts,
            [
                ("/approvals/{id}/decision", APPROVE),
                ("/reverts/{action_id}/confirm", APPROVE),
                ("/reverts/{action_id}/extend", APPROVE),
                ("/reverts/{action_id}/cancel", APPROVE),
                ("/actions/{id}/revert", APPROVE),
                ("/goal", ADMINISTER),
                ("/playbooks/{name}/runs", RUN_PLAYBOOKS),
            ]
        );
    }
}
