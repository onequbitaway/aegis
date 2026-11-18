//! The operations that the REST API, the gRPC API, and the ChatOps endpoints share.
//!
//! Each function takes the principal of the request and checks its permission first. Thus
//! each interface applies the same access rules.

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::action::ActionDisposition;
use aegis_contracts::common::{ActionId, ApprovalId, IncidentId};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus, Principal};
use aegis_policy::Permission;
use aegis_respond::PendingRevert;

use crate::error::{ApiError, ApiResult};
use crate::state::{ApiState, ApprovalDecision, RevertActions};

/// The maximum length of the note of an approval decision, in characters.
pub(crate) const MAX_NOTE_CHARACTERS: usize = 1_000;

/// The maximum length of the reason of a revert, in characters.
pub(crate) const MAX_REASON_CHARACTERS: usize = 1_000;

/// The permissions that let a principal read approval requests. One of them is sufficient.
pub(crate) const READ_APPROVALS: &[Permission] =
    &[Permission::ViewIncidents, Permission::ApproveActions];

/// Checks that `principal` has one or more of `any_of`. [`Rbac`](aegis_policy::Rbac)
/// decides.
pub(crate) fn require(
    state: &ApiState,
    principal: &Principal,
    any_of: &[Permission],
) -> ApiResult<()> {
    if state.parts().rbac.check_any(principal, any_of).is_ok() {
        return Ok(());
    }
    let names = any_of
        .iter()
        .map(|permission| permission.as_str())
        .collect::<Vec<_>>()
        .join(" or ");
    Err(ApiError::Forbidden(format!(
        "The principal does not have the permission {names}."
    )))
}

/// Lists incidents, newest first.
pub(crate) async fn list_incidents(
    state: &ApiState,
    principal: &Principal,
    status: Option<IncidentStatus>,
    limit: usize,
) -> ApiResult<Vec<Incident>> {
    require(state, principal, &[Permission::ViewIncidents])?;
    Ok(state.parts().incidents.list(status, limit).await?)
}

/// Reads one incident.
pub(crate) async fn get_incident(
    state: &ApiState,
    principal: &Principal,
    id: IncidentId,
) -> ApiResult<Incident> {
    require(state, principal, &[Permission::ViewIncidents])?;
    state
        .parts()
        .incidents
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound("The incident does not exist.".to_owned()))
}

/// Lists the approval requests that have no decision, oldest first.
pub(crate) async fn pending_approvals(
    state: &ApiState,
    principal: &Principal,
) -> ApiResult<Vec<ApprovalRequest>> {
    require(state, principal, READ_APPROVALS)?;
    Ok(state.parts().approvals.pending().await?)
}

/// Reads one approval request.
pub(crate) async fn get_approval(
    state: &ApiState,
    principal: &Principal,
    id: ApprovalId,
) -> ApiResult<ApprovalRequest> {
    require(state, principal, READ_APPROVALS)?;
    state
        .parts()
        .approvals
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound("The approval request does not exist.".to_owned()))
}

/// Returns the note in the form that the decision records. An empty note is no note.
pub(crate) fn normalize_note(note: Option<String>) -> ApiResult<Option<String>> {
    let Some(note) = note else {
        return Ok(None);
    };
    let note = note.trim();
    if note.is_empty() {
        return Ok(None);
    }
    if note.chars().count() > MAX_NOTE_CHARACTERS {
        return Err(ApiError::BadRequest(format!(
            "The note must have {MAX_NOTE_CHARACTERS} characters or fewer."
        )));
    }
    Ok(Some(note.to_owned()))
}

/// Records the decision of `principal` on one approval request.
///
/// The function checks the permission, then the state of the request, and then calls
/// [`ApprovalActions`](crate::ApprovalActions). It does not change the queue itself.
pub(crate) async fn decide_approval(
    state: &ApiState,
    principal: &Principal,
    id: ApprovalId,
    approve: bool,
    note: Option<String>,
) -> ApiResult<ApprovalDecision> {
    require(state, principal, &[Permission::ApproveActions])?;
    let note = normalize_note(note)?;
    let request = state
        .parts()
        .approvals
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound("The approval request does not exist.".to_owned()))?;
    if request.status != ApprovalStatus::Pending {
        return Err(ApiError::Conflict(
            "The approval request already has a decision.".to_owned(),
        ));
    }
    Ok(state
        .parts()
        .approval_actions
        .decide(id, approve, principal, note)
        .await?)
}

/// Returns the path for timed reverts, or the error for a state that has none.
fn revert_path(state: &ApiState) -> ApiResult<&Arc<dyn RevertActions>> {
    state.reverts().ok_or_else(|| {
        aegis_contracts::Error::Unsupported("this process has no timed revert".to_owned()).into()
    })
}

/// Lists the timed reverts that wait. The first value is `false` if the process holds no
/// timed reverts.
pub(crate) async fn pending_reverts(
    state: &ApiState,
    principal: &Principal,
) -> ApiResult<(bool, Vec<PendingRevert>)> {
    require(state, principal, READ_APPROVALS)?;
    match state.reverts() {
        Some(reverts) if reverts.enabled() => Ok((true, reverts.pending().await?)),
        _ => Ok((false, Vec::new())),
    }
}

/// Confirms an action with a timed revert. The containment stays.
pub(crate) async fn confirm_revert(
    state: &ApiState,
    principal: &Principal,
    action_id: ActionId,
) -> ApiResult<PendingRevert> {
    require(state, principal, &[Permission::ApproveActions])?;
    Ok(revert_path(state)?.confirm(action_id, principal).await?)
}

/// Moves the revert time of an action.
pub(crate) async fn extend_revert(
    state: &ApiState,
    principal: &Principal,
    action_id: ActionId,
    extension: Duration,
) -> ApiResult<PendingRevert> {
    require(state, principal, &[Permission::ApproveActions])?;
    Ok(revert_path(state)?
        .extend(action_id, principal, extension)
        .await?)
}

/// Reverts an action with a timed revert immediately.
pub(crate) async fn cancel_revert(
    state: &ApiState,
    principal: &Principal,
    action_id: ActionId,
) -> ApiResult<ActionDisposition> {
    require(state, principal, &[Permission::ApproveActions])?;
    Ok(revert_path(state)?.cancel(action_id, principal).await?)
}

/// Returns the reason of a revert in the form that the audit log records.
pub(crate) fn normalize_reason(reason: &str) -> ApiResult<String> {
    let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.is_empty() {
        return Err(ApiError::BadRequest(
            "The revert needs a reason.".to_owned(),
        ));
    }
    if reason.chars().count() > MAX_REASON_CHARACTERS {
        return Err(ApiError::BadRequest(format!(
            "The reason must have {MAX_REASON_CHARACTERS} characters or fewer."
        )));
    }
    Ok(reason)
}

/// Reverts one action that a connector did before.
pub(crate) async fn revert_action(
    state: &ApiState,
    principal: &Principal,
    action_id: ActionId,
    reason: &str,
) -> ApiResult<ActionDisposition> {
    require(state, principal, &[Permission::ApproveActions])?;
    let reason = normalize_reason(reason)?;
    Ok(revert_path(state)?
        .revert(action_id, principal, &reason)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_one_line_with_a_maximum_length() {
        assert_eq!(
            normalize_reason("  The block was\n wrong. ").unwrap(),
            "The block was wrong."
        );
        let error = normalize_reason(" \n ").unwrap_err();
        assert!(
            matches!(error, ApiError::BadRequest(message) if message == "The revert needs a reason.")
        );
        assert!(normalize_reason(&"x".repeat(MAX_REASON_CHARACTERS)).is_ok());
        let error = normalize_reason(&"x".repeat(MAX_REASON_CHARACTERS + 1)).unwrap_err();
        assert!(
            matches!(error, ApiError::BadRequest(message) if message == "The reason must have 1000 characters or fewer.")
        );
    }

    #[test]
    fn an_empty_note_is_no_note() {
        assert_eq!(normalize_note(None).unwrap(), None);
        assert_eq!(normalize_note(Some("  \n".to_owned())).unwrap(), None);
        assert_eq!(
            normalize_note(Some("  Looks right. ".to_owned())).unwrap(),
            Some("Looks right.".to_owned())
        );
    }

    #[test]
    fn a_note_has_a_maximum_length() {
        assert_eq!(
            normalize_note(Some("é".repeat(MAX_NOTE_CHARACTERS))).unwrap(),
            Some("é".repeat(MAX_NOTE_CHARACTERS))
        );
        let error = normalize_note(Some("x".repeat(MAX_NOTE_CHARACTERS + 1))).unwrap_err();
        assert!(
            matches!(error, ApiError::BadRequest(message) if message == "The note must have 1000 characters or fewer.")
        );
    }
}
