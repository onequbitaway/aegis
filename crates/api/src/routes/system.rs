//! The health, session, status, and agent routes.

use std::collections::BTreeSet;

use aegis_agents::{RunReport, RuntimeState, TaskRecord};
use aegis_contracts::agent::AgentRole;
use aegis_contracts::audit::{AuditEntry, AuditKind};
use aegis_contracts::common::TaskId;
use aegis_contracts::policy::Principal;
use aegis_policy::Permission;
use axum::Json;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::audit::{AuditHead, find_audit_head};
use super::{Caller, Ctx};
use crate::error::{ApiError, ApiResult};
use crate::extract::{JsonBody, Params};

/// The maximum length of a goal, in characters.
pub(crate) const MAX_GOAL_CHARACTERS: usize = 4_000;

/// The answer of the health route. It shows no detail.
#[derive(Debug, Serialize)]
pub(crate) struct Health {
    status: &'static str,
}

/// `GET /healthz`: tells a load balancer that the server answers.
pub(crate) async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

#[derive(Debug, Serialize)]
pub(crate) struct Session {
    principal: Principal,
    permissions: BTreeSet<Permission>,
}

/// `GET /session`: the principal of the token and its permissions.
pub(crate) async fn session(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Session>> {
    Params::parse(query.as_deref(), &[])?;
    let permissions = ctx.state.parts().rbac.permissions(&principal);
    Ok(Json(Session {
        principal,
        permissions,
    }))
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentCounters {
    state: RuntimeState,
    idle: bool,
    queued: usize,
    dry_run: bool,
    stats: RunReport,
}

fn agent_counters(ctx: &Ctx) -> AgentCounters {
    let agents = &ctx.state.parts().agents;
    AgentCounters {
        state: agents.state(),
        idle: agents.is_idle(),
        queued: agents.queued(),
        dry_run: agents.config().dry_run,
        stats: agents.stats(),
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AuditStatus {
    head: Option<AuditHead>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Status {
    version: &'static str,
    modules: Vec<&'static str>,
    agents: AgentCounters,
    audit: AuditStatus,
}

/// `GET /status`: the modules, the agent runtime, and the head of the audit log.
pub(crate) async fn status(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Status>> {
    Params::parse(query.as_deref(), &[])?;
    let head = {
        let mut known = ctx.audit_head.lock().await;
        let head = find_audit_head(ctx.state.parts().audit.as_ref(), known.clone()).await?;
        known.clone_from(&head);
        head
    };
    Ok(Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        modules: ctx
            .state
            .parts()
            .modules
            .iter()
            .map(|module| module.name())
            .collect(),
        agents: agent_counters(&ctx),
        audit: AuditStatus { head },
    }))
}

#[derive(Debug, Serialize)]
pub(crate) struct Agents {
    #[serde(flatten)]
    counters: AgentCounters,
    roster: Vec<AgentRole>,
    recent_tasks: Vec<TaskRecord>,
}

/// `GET /agents`: the roster, the state of the runtime, and the last tasks that ended.
pub(crate) async fn agents(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Agents>> {
    let params = Params::parse(query.as_deref(), &["limit"])?;
    let limit = params.limit(&ctx.limits)?;
    let runtime = &ctx.state.parts().agents;
    let mut recent_tasks = runtime.recent_tasks();
    // The runtime gives the oldest task first. Keep the newest tasks.
    let surplus = recent_tasks.len().saturating_sub(limit);
    recent_tasks.drain(..surplus);
    Ok(Json(Agents {
        counters: agent_counters(&ctx),
        roster: runtime.roster().roles().cloned().collect(),
        recent_tasks,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoalRequest {
    text: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GoalAccepted {
    task_id: TaskId,
}

/// `POST /goal`: gives a goal to the Supervisor agent.
///
/// The audit log gets the record before the runtime gets the goal. Thus no goal runs
/// without a record of the principal that set it.
pub(crate) async fn goal(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    JsonBody(request): JsonBody<GoalRequest>,
) -> ApiResult<(StatusCode, Json<GoalAccepted>)> {
    let text = request.text.trim();
    if text.is_empty() {
        return Err(ApiError::BadRequest("The goal has no text.".to_owned()));
    }
    if text.chars().count() > MAX_GOAL_CHARACTERS {
        return Err(ApiError::BadRequest(format!(
            "The goal must have {MAX_GOAL_CHARACTERS} characters or fewer."
        )));
    }
    let parts = ctx.state.parts();
    parts
        .audit
        .append(
            AuditEntry::new(
                AuditKind::Other,
                principal.id.clone(),
                "The operator gave a goal to the agents through the API.",
            )
            .with_payload(json!({ "operation": "submit_goal", "goal": text })),
        )
        .await?;
    match parts.agents.submit_goal(text) {
        Ok(task_id) => Ok((StatusCode::ACCEPTED, Json(GoalAccepted { task_id }))),
        Err(error) => {
            let entry = AuditEntry::new(
                AuditKind::Other,
                principal.id.clone(),
                "The agent runtime did not take the goal of the operator.",
            )
            .with_payload(json!({ "operation": "submit_goal", "accepted": false }));
            if let Err(audit_error) = parts.audit.append(entry).await {
                tracing::error!(error = %audit_error, "the audit log did not take a record");
            }
            Err(error.into())
        }
    }
}
