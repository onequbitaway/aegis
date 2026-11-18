//! The operations that the REST API, the gRPC API, and the ChatOps endpoints share.
//!
//! Each function takes the principal of the request and checks its permission first. Thus
//! each interface applies the same access rules.

use aegis_contracts::common::{ApprovalId, IncidentId};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus, Principal};
use aegis_policy::Permission;

use crate::error::{ApiError, ApiResult};
use crate::state::{ApiState, ApprovalDecision};

/// The maximum length of the note of an approval decision, in characters.
pub(crate) const MAX_NOTE_CHARACTERS: usize = 1_000;

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

#[cfg(test)]
mod tests {
    use super::*;

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
