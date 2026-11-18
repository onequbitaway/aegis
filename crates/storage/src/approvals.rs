//! The approval queue.
//!
//! The `request` column holds the request as JSON text, as the dispatcher submitted it.
//! The columns `status`, `decided_by`, `decided_at`, and `note` hold the decision.
//!
//! # One decision
//!
//! [`PgApprovals::decide`](aegis_contracts::ApprovalQueue::decide) changes the state with
//! one `UPDATE` statement that also checks that the request is pending. The database locks
//! the row for that statement, so only one of two decisions at the same time can succeed.
//! A trigger also rejects each change of a request that has a decision.
//!
//! # Differences from the in-memory queue
//!
//! The queue fails closed where the in-memory queue of the test kit accepts the input:
//!
//! - A request must be pending when it enters the queue.
//! - A request cannot replace a request that has the same identifier. A second submit
//!   thus cannot change an action that waits for a decision, and cannot remove a decision.
//!   A second submit of the same pending request is permitted and changes nothing, so a
//!   caller can submit again after a connection failure.

use aegis_contracts::common::ApprovalId;
use aegis_contracts::policy::{ApprovalQueue, ApprovalRequest, ApprovalStatus, Principal};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, SubsecRound, Utc};
use sqlx::postgres::PgPool;

use crate::error::{db_error, decode_error};
use crate::json::{split_time, variant_from_name, variant_name};

/// Writes a request only if no request has the same identifier.
const SUBMIT: &str = "INSERT INTO aegis.approvals \
         (id, status, requested_at, requested_at_nanos, request) \
     VALUES ($1, 'pending', $2, $3, $4) \
     ON CONFLICT (id) DO NOTHING";

const READ_SUBMITTED: &str = "SELECT status, request FROM aegis.approvals WHERE id = $1";

const GET: &str = "SELECT status, decided_by, decided_at, note, request \
     FROM aegis.approvals \
     WHERE id = $1";

const PENDING: &str = "SELECT status, decided_by, decided_at, note, request \
     FROM aegis.approvals \
     WHERE status = 'pending' \
     ORDER BY requested_at ASC, requested_at_nanos ASC, id ASC";

/// Records a decision only if the request is pending. The check and the change are one
/// statement.
const DECIDE: &str = "UPDATE aegis.approvals \
     SET status = $2, decided_by = $3, decided_at = $4, note = $5 \
     WHERE id = $1 AND status = 'pending' \
     RETURNING status, decided_by, decided_at, note, request";

const EXISTS: &str = "SELECT EXISTS (SELECT 1 FROM aegis.approvals WHERE id = $1)";

/// One row of the approval table, in column order.
type ApprovalRow = (
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
    String,
);

/// Makes a request from its stored document and its decision columns.
///
/// The decision columns are the source of truth for the decision.
fn request_from_row(row: ApprovalRow) -> Result<ApprovalRequest> {
    let (status, decided_by, decided_at, note, document) = row;
    let mut request: ApprovalRequest = serde_json::from_str(&document)
        .map_err(|error| decode_error("an approval request", error))?;
    request.status = variant_from_name("an approval status", &status)?;
    request.decided_by = decided_by;
    request.decided_at = decided_at;
    request.note = note;
    Ok(request)
}

/// Checks that a request can enter the queue.
fn check_new_request(request: &ApprovalRequest) -> Result<()> {
    let has_decision = request.status != ApprovalStatus::Pending
        || request.decided_by.is_some()
        || request.decided_at.is_some()
        || request.note.is_some();
    if has_decision {
        return Err(Error::InvalidInput(format!(
            "approval request {} must be pending and have no decision when it enters the queue",
            request.id
        )));
    }
    Ok(())
}

/// Checks a submit of a request whose identifier is already in the queue.
///
/// `stored` is the status and the document of the request in the queue.
fn check_second_submit(request: &ApprovalRequest, stored: Option<(String, String)>) -> Result<()> {
    let id = request.id;
    let Some((status, document)) = stored else {
        return Err(Error::Unavailable(format!(
            "write the approval request: approval request {id} was removed at the same time"
        )));
    };
    if status != "pending" {
        return Err(Error::InvalidInput(format!(
            "approval request {id} already has a decision"
        )));
    }
    // Compare the requests and not the text: the order of the keys in the text can change.
    let stored_request: ApprovalRequest = serde_json::from_str(&document)
        .map_err(|error| decode_error("an approval request", error))?;
    if &stored_request == request {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "a different approval request {id} is already in the queue"
        )))
    }
}

/// The approval queue in the table `aegis.approvals`.
///
/// Get a value from [`PgStore::approvals`](crate::PgStore::approvals).
#[derive(Debug, Clone)]
pub struct PgApprovals {
    pool: PgPool,
}

impl PgApprovals {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApprovalQueue for PgApprovals {
    /// Puts a request in the queue.
    ///
    /// A second submit of the same pending request changes nothing.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`]: the request is not pending, or a different request with
    /// the same identifier is already in the queue, or the request already has a decision.
    async fn submit(&self, request: ApprovalRequest) -> Result<()> {
        const OPERATION: &str = "write the approval request";
        check_new_request(&request)?;
        let document = serde_json::to_string(&request)?;
        let (requested_at, requested_at_nanos) = split_time(request.requested_at);
        let written = sqlx::query(SUBMIT)
            .bind(request.id.0)
            .bind(requested_at)
            .bind(requested_at_nanos)
            .bind(&document)
            .execute(&self.pool)
            .await
            .map_err(|error| db_error(OPERATION, error))?;
        if written.rows_affected() == 1 {
            return Ok(());
        }
        let stored: Option<(String, String)> = sqlx::query_as(READ_SUBMITTED)
            .bind(request.id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error(OPERATION, error))?;
        check_second_submit(&request, stored)
    }

    async fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRequest>> {
        let row: Option<ApprovalRow> = sqlx::query_as(GET)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error("read the approval request", error))?;
        row.map(request_from_row).transpose()
    }

    async fn pending(&self) -> Result<Vec<ApprovalRequest>> {
        let rows: Vec<ApprovalRow> = sqlx::query_as(PENDING)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db_error("list the pending approval requests", error))?;
        rows.into_iter().map(request_from_row).collect()
    }

    /// Records the decision of `decided_by`.
    ///
    /// The time of the decision has microsecond precision.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: the request does not exist.
    /// - [`Error::InvalidInput`]: the request already has a decision.
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        decided_by: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalRequest> {
        const OPERATION: &str = "record the approval decision";
        let status = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        let decided: Option<ApprovalRow> = sqlx::query_as(DECIDE)
            .bind(id.0)
            .bind(variant_name(&status)?)
            .bind(&decided_by.id)
            .bind(Utc::now().trunc_subsecs(6))
            .bind(note)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error(OPERATION, error))?;
        if let Some(row) = decided {
            return request_from_row(row);
        }
        let exists: bool = sqlx::query_scalar(EXISTS)
            .bind(id.0)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| db_error(OPERATION, error))?;
        if exists {
            Err(Error::InvalidInput(format!(
                "approval request {id} already has a decision"
            )))
        } else {
            Err(Error::NotFound(format!("approval request {id}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::{ActionKind, ActionRequest};
    use aegis_contracts::common::{EntityKind, EntityRef};
    use aegis_contracts::policy::{ActionTier, PolicyDecision, PolicyEffect, PrincipalKind};
    use chrono::TimeZone;

    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: ApprovalId::new(),
            action: ActionRequest::new(
                ActionKind::IsolateHost,
                EntityRef::new(EntityKind::Host, "host-1"),
                "responder",
                "The host runs a credential dump tool.",
            ),
            requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent"]),
            decision: PolicyDecision {
                effect: PolicyEffect::RequireApproval,
                tier: ActionTier::Gated,
                reasons: vec!["The action is in the gated tier.".to_owned()],
                policy: Some("aegis.response.decision".to_owned()),
                evaluated_at: Utc.with_ymd_and_hms(2026, 4, 5, 6, 7, 8).unwrap(),
            },
            status: ApprovalStatus::Pending,
            requested_at: Utc.with_ymd_and_hms(2026, 4, 5, 6, 7, 9).unwrap()
                + chrono::Duration::nanoseconds(987_654_321),
            decided_by: None,
            decided_at: None,
            note: None,
        }
    }

    fn row(request: &ApprovalRequest) -> ApprovalRow {
        (
            "pending".to_owned(),
            None,
            None,
            None,
            serde_json::to_string(request).unwrap(),
        )
    }

    #[test]
    fn a_pending_row_gives_back_the_submitted_request() {
        let request = request();
        assert_eq!(request_from_row(row(&request)).unwrap(), request);
    }

    #[test]
    fn the_decision_columns_replace_the_fields_of_the_document() {
        let request = request();
        let decided_at = Utc.with_ymd_and_hms(2026, 4, 5, 7, 0, 0).unwrap();
        let (_, _, _, _, document) = row(&request);
        let decided = request_from_row((
            "rejected".to_owned(),
            Some("alice@example.com".to_owned()),
            Some(decided_at),
            Some("Not now.".to_owned()),
            document,
        ))
        .unwrap();
        assert_eq!(
            decided,
            ApprovalRequest {
                status: ApprovalStatus::Rejected,
                decided_by: Some("alice@example.com".to_owned()),
                decided_at: Some(decided_at),
                note: Some("Not now.".to_owned()),
                ..request
            }
        );
    }

    #[test]
    fn a_row_with_an_unknown_status_is_a_serialization_error() {
        let (_, _, _, _, document) = row(&request());
        let error =
            request_from_row(("escalated".to_owned(), None, None, None, document)).unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(message) if message.contains("an approval status")),
            "{error:?}"
        );
    }

    #[test]
    fn a_row_with_a_broken_document_is_a_serialization_error() {
        let error =
            request_from_row(("pending".to_owned(), None, None, None, "{".to_owned())).unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(message) if message.contains("an approval request")),
            "{error:?}"
        );
    }

    #[test]
    fn a_second_submit_is_accepted_only_for_the_same_pending_request() {
        let mut request = request();
        request.action.parameters.insert(
            "scope".to_owned(),
            serde_json::json!({ "zone": "dmz", "ratio": 0.1 + 0.2, "all": true }),
        );
        let document = serde_json::to_string(&request).unwrap();
        let stored = |status: &str, document: &str| Some((status.to_owned(), document.to_owned()));

        assert!(check_second_submit(&request, stored("pending", &document)).is_ok());
        // The same request with the keys of an object in a different order.
        let scope = serde_json::to_string(&request.action.parameters["scope"]).unwrap();
        let reordered_scope = r#"{"zone":"dmz","all":true,"ratio":0.30000000000000004}"#;
        assert_ne!(scope, reordered_scope);
        let reordered = document.replace(&scope, reordered_scope);
        assert_ne!(reordered, document);
        assert!(check_second_submit(&request, stored("pending", &reordered)).is_ok());

        let mut changed = request.clone();
        changed.action.reason = "A different reason.".to_owned();
        let other = serde_json::to_string(&changed).unwrap();
        let error = check_second_submit(&request, stored("pending", &other)).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("a different approval request")),
            "{error:?}"
        );

        for status in ["approved", "rejected"] {
            let error = check_second_submit(&request, stored(status, &document)).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message) if message.contains("already has a decision")),
                "{error:?}"
            );
        }

        let error = check_second_submit(&request, stored("pending", "{")).unwrap_err();
        assert!(matches!(&error, Error::Serialization(_)), "{error:?}");

        let error = check_second_submit(&request, None).unwrap_err();
        assert!(matches!(&error, Error::Unavailable(_)), "{error:?}");
    }

    #[test]
    fn a_pending_request_can_enter_the_queue() {
        assert!(check_new_request(&request()).is_ok());
    }

    #[test]
    fn a_request_that_has_a_decision_cannot_enter_the_queue() {
        let approved = ApprovalRequest {
            status: ApprovalStatus::Approved,
            ..request()
        };
        let with_decider = ApprovalRequest {
            decided_by: Some("mallory".to_owned()),
            ..request()
        };
        let with_time = ApprovalRequest {
            decided_at: Some(Utc::now()),
            ..request()
        };
        let with_note = ApprovalRequest {
            note: Some("Approved before the request.".to_owned()),
            ..request()
        };
        for candidate in [approved, with_decider, with_time, with_note] {
            let error = check_new_request(&candidate).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message) if message.contains("must be pending")),
                "{error:?}"
            );
        }
    }
}
