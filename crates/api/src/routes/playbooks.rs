//! The playbook routes.

use aegis_contracts::audit::{AuditEntry, AuditKind};
use aegis_contracts::common::{EvidenceKind, EvidenceRef, IncidentId};
use aegis_respond::{Playbook, PlaybookRun, RunMode};
use axum::Json;
use axum::extract::{RawQuery, State};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::incidents::Items;
use super::{Caller, Ctx, PathText};
use crate::error::{ApiError, ApiResult};
use crate::extract::{JsonBody, Params};

/// `GET /playbooks`: the playbooks of the engine.
pub(crate) async fn list(
    State(ctx): State<Ctx>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Items<Playbook>>> {
    Params::parse(query.as_deref(), &[])?;
    Ok(Json(Items {
        items: ctx.state.parts().playbooks.playbooks().to_vec(),
    }))
}

/// The body of a playbook run. The default mode is a dry run.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunRequest {
    incident_id: IncidentId,
    #[serde(default = "dry_run")]
    mode: RunMode,
}

fn dry_run() -> RunMode {
    RunMode::DryRun
}

/// The report of a playbook run.
#[derive(Debug, Serialize)]
pub(crate) struct RunResponse {
    /// `false` if the trigger of the playbook does not match the incident. The operator
    /// selected the playbook, so the engine ran it.
    trigger_matched: bool,
    run: PlaybookRun,
}

/// `POST /playbooks/{name}/runs`: runs one playbook for one incident.
///
/// The audit log gets the record of the principal before the engine runs the playbook.
/// Each action of the playbook then goes through the dispatcher and the policy.
pub(crate) async fn run(
    State(ctx): State<Ctx>,
    Caller(principal): Caller,
    PathText(name): PathText,
    JsonBody(request): JsonBody<RunRequest>,
) -> ApiResult<Json<RunResponse>> {
    let parts = ctx.state.parts();
    let playbook = parts
        .playbooks
        .playbook(&name)
        .ok_or_else(|| ApiError::NotFound("The playbook does not exist.".to_owned()))?;
    let incident = parts
        .incidents
        .get(request.incident_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("The incident does not exist.".to_owned()))?;
    let trigger_matched = playbook.matches(&incident);
    let summary = match request.mode {
        RunMode::DryRun => "The operator started a dry run of a playbook through the API.",
        RunMode::Live => "The operator started a live run of a playbook through the API.",
    };
    parts
        .audit
        .append(
            AuditEntry::new(AuditKind::Other, principal.id.clone(), summary)
                .with_payload(json!({
                    "operation": "run_playbook",
                    "playbook": playbook.name(),
                    "incident_id": incident.id,
                    "mode": request.mode,
                    "trigger_matched": trigger_matched,
                }))
                .with_evidence(vec![EvidenceRef::new(EvidenceKind::Incident, incident.id)]),
        )
        .await?;
    let run = parts
        .playbooks
        .run(playbook, &incident, request.mode)
        .await?;
    Ok(Json(RunResponse {
        trigger_matched,
        run,
    }))
}
