//! Tests of the approval queue.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::common::{
    ApprovalId, EntityKind, EntityRef, EvidenceKind, EvidenceRef, IncidentId,
};
use aegis_contracts::policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    Principal, PrincipalKind,
};
use chrono::{SubsecRound, TimeZone, Utc};
use serde_json::json;
use sqlx::Connection;

use crate::support::{TestDb, message, sqlstate};

fn approval(age_seconds: i64) -> ApprovalRequest {
    ApprovalRequest {
        id: ApprovalId::new(),
        action: ActionRequest::new(
            ActionKind::IsolateHost,
            EntityRef::new(EntityKind::Host, "host-1"),
            "responder",
            "Test.",
        ),
        requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent"]),
        decision: PolicyDecision {
            effect: PolicyEffect::RequireApproval,
            tier: ActionTier::Gated,
            reasons: Vec::new(),
            policy: None,
            evaluated_at: Utc::now(),
        },
        status: ApprovalStatus::Pending,
        requested_at: Utc::now() - chrono::Duration::seconds(age_seconds),
        decided_by: None,
        decided_at: None,
        note: None,
    }
}

fn approver() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

async fn pending_ids(queue: &impl ApprovalQueue) -> Vec<ApprovalId> {
    queue
        .pending()
        .await
        .unwrap()
        .iter()
        .map(|request| request.id)
        .collect()
}

#[tokio::test]
async fn the_queue_lists_pending_requests_oldest_first() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    assert_eq!(queue.pending().await.unwrap(), Vec::new());

    let newer = approval(10);
    let older = approval(60);
    queue.submit(newer.clone()).await.unwrap();
    queue.submit(older.clone()).await.unwrap();

    assert_eq!(pending_ids(&queue).await, [older.id, newer.id]);
    assert_eq!(
        queue.pending().await.unwrap(),
        vec![older.clone(), newer.clone()]
    );
    assert_eq!(queue.get(newer.id).await.unwrap(), Some(newer));
    assert_eq!(queue.get(ApprovalId::new()).await.unwrap(), None);
}

#[tokio::test]
async fn requests_one_nanosecond_apart_are_in_time_order() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    let base = Utc.with_ymd_and_hms(2026, 4, 5, 6, 7, 8).unwrap();
    // The identifiers are in the opposite order of the times.
    let mut requests = [approval(0), approval(0), approval(0)];
    assert!(requests[0].id < requests[1].id && requests[1].id < requests[2].id);
    for (request, nanoseconds) in requests.iter_mut().zip([3, 2, 1]) {
        request.requested_at = base + chrono::Duration::nanoseconds(nanoseconds);
        queue.submit(request.clone()).await.unwrap();
    }
    assert_eq!(
        pending_ids(&queue).await,
        [requests[2].id, requests[1].id, requests[0].id]
    );
}

#[tokio::test]
async fn a_decision_is_recorded_one_time_only() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    let request = approval(1);
    let other = approval(0);
    queue.submit(request.clone()).await.unwrap();
    queue.submit(other.clone()).await.unwrap();
    let approver = approver();

    let before = Utc::now().trunc_subsecs(6);
    let decided = queue
        .decide(request.id, false, &approver, Some("Not now.".to_owned()))
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Rejected);
    assert_eq!(decided.decided_by.as_deref(), Some("alice@example.com"));
    assert_eq!(decided.note.as_deref(), Some("Not now."));
    let decided_at = decided.decided_at.unwrap();
    assert!(decided_at >= before && decided_at <= Utc::now());
    // All other fields are the fields of the request.
    assert_eq!(
        decided,
        ApprovalRequest {
            status: ApprovalStatus::Rejected,
            decided_by: Some("alice@example.com".to_owned()),
            decided_at: Some(decided_at),
            note: Some("Not now.".to_owned()),
            ..request.clone()
        }
    );
    // The queue gives back the same decision.
    assert_eq!(queue.get(request.id).await.unwrap(), Some(decided.clone()));
    assert_eq!(pending_ids(&queue).await, [other.id]);

    let again = queue
        .decide(request.id, true, &approver, None)
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(message) if message == &format!("approval request {} already has a decision", request.id)),
        "{again:?}"
    );
    assert_eq!(queue.get(request.id).await.unwrap(), Some(decided));

    let missing_id = ApprovalId::new();
    let missing = queue
        .decide(missing_id, true, &approver, None)
        .await
        .unwrap_err();
    assert!(
        matches!(&missing, Error::NotFound(message) if message == &format!("approval request {missing_id}")),
        "{missing:?}"
    );

    // An approval with no note.
    let approved = queue.decide(other.id, true, &approver, None).await.unwrap();
    assert_eq!(approved.status, ApprovalStatus::Approved);
    assert_eq!(approved.note, None);
    assert_eq!(queue.pending().await.unwrap(), Vec::new());
}

#[tokio::test]
async fn concurrent_decisions_have_exactly_one_winner() {
    const DECISIONS: usize = 24;

    let database = TestDb::new().await;
    // Each store has its own connection pool, as each process has.
    let stores = [database.store.clone(), database.second_store().await];
    let request = approval(1);
    stores[0].approvals().submit(request.clone()).await.unwrap();

    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..DECISIONS {
        let queue = stores[index % 2].approvals();
        let id = request.id;
        tasks.spawn(async move {
            let principal = Principal::new(
                format!("approver-{index}"),
                PrincipalKind::Human,
                &["approver"],
            );
            let approve = index.is_multiple_of(3);
            let note = Some(format!("Decision {index}."));
            queue.decide(id, approve, &principal, note).await
        });
    }
    let results = tokio::time::timeout(Duration::from_secs(120), tasks.join_all())
        .await
        .unwrap();
    assert_eq!(results.len(), DECISIONS);

    let mut winners = Vec::new();
    let mut losers = 0;
    for result in results {
        match result {
            Ok(decided) => winners.push(decided),
            Err(Error::InvalidInput(message)) => {
                assert_eq!(
                    message,
                    format!("approval request {} already has a decision", request.id)
                );
                losers += 1;
            }
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(losers, DECISIONS - 1);

    // The stored decision is the decision of the winner.
    let winner = &winners[0];
    let index: usize = winner
        .decided_by
        .as_deref()
        .and_then(|name| name.strip_prefix("approver-"))
        .unwrap()
        .parse()
        .unwrap();
    let expected_status = if index.is_multiple_of(3) {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Rejected
    };
    assert_eq!(winner.status, expected_status);
    assert_eq!(winner.note, Some(format!("Decision {index}.")));
    let stored = stores[1].approvals().get(request.id).await.unwrap();
    assert_eq!(stored.as_ref(), Some(winner));
    assert_eq!(stores[0].approvals().pending().await.unwrap(), Vec::new());
}

#[tokio::test]
async fn a_second_submit_cannot_replace_a_request_or_remove_a_decision() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    let request = approval(5);
    queue.submit(request.clone()).await.unwrap();

    // The same pending request again: accepted, and the queue has one request.
    queue.submit(request.clone()).await.unwrap();
    assert_eq!(queue.pending().await.unwrap(), vec![request.clone()]);

    // A different action with the same identifier: rejected.
    let mut swapped = request.clone();
    swapped.action.target = EntityRef::new(EntityKind::Host, "domain-controller");
    let error = queue.submit(swapped.clone()).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message == &format!("a different approval request {} is already in the queue", request.id)),
        "{error:?}"
    );
    assert_eq!(queue.get(request.id).await.unwrap(), Some(request.clone()));

    // A request that already has a decision cannot enter the queue.
    let mut approved_before = approval(1);
    approved_before.status = ApprovalStatus::Approved;
    approved_before.decided_by = Some("mallory".to_owned());
    approved_before.decided_at = Some(Utc::now());
    let error = queue.submit(approved_before.clone()).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("must be pending")),
        "{error:?}"
    );
    assert_eq!(queue.get(approved_before.id).await.unwrap(), None);

    // After a decision, a second submit does not make the request pending again.
    let decided = queue
        .decide(request.id, false, &approver(), None)
        .await
        .unwrap();
    for candidate in [request.clone(), swapped] {
        let error = queue.submit(candidate).await.unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message == &format!("approval request {} already has a decision", request.id)),
            "{error:?}"
        );
    }
    assert_eq!(queue.get(request.id).await.unwrap(), Some(decided));
    assert_eq!(queue.pending().await.unwrap(), Vec::new());
}

#[tokio::test]
async fn the_database_rejects_a_change_of_a_decision_from_each_client() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    let request = approval(5);
    let pending = approval(1);
    queue.submit(request.clone()).await.unwrap();
    queue.submit(pending.clone()).await.unwrap();
    let decided = queue
        .decide(request.id, false, &approver(), Some("No.".to_owned()))
        .await
        .unwrap();

    // The connection is a superuser, so only the trigger and the checks can reject.
    let mut sql = database.sql().await;
    let attempts = [
        (
            "UPDATE aegis.approvals SET status = 'approved' WHERE id = $1",
            request.id,
            format!("approval request {} already has a decision", request.id),
        ),
        (
            "UPDATE aegis.approvals SET status = 'pending', decided_by = NULL, \
             decided_at = NULL, note = NULL WHERE id = $1",
            request.id,
            format!("approval request {} already has a decision", request.id),
        ),
        (
            "UPDATE aegis.approvals SET request = '{}', status = 'approved', \
             decided_by = 'mallory', decided_at = now() WHERE id = $1",
            pending.id,
            format!(
                "the request data of approval request {} cannot change",
                pending.id
            ),
        ),
        (
            "UPDATE aegis.approvals SET note = NULL WHERE id = $1",
            pending.id,
            format!(
                "an update of approval request {} must record a decision",
                pending.id
            ),
        ),
    ];
    for (statement, id, expected) in attempts {
        let error = sqlx::query(statement)
            .bind(id.0)
            .execute(&mut sql)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&error), "23000", "{statement}");
        assert_eq!(message(&error), expected, "{statement}");
    }
    // A decision with no principal does not pass the checks of the table.
    let error = sqlx::query("UPDATE aegis.approvals SET status = 'approved' WHERE id = $1")
        .bind(pending.id.0)
        .execute(&mut sql)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&error), "23514");
    sql.close().await.unwrap();

    assert_eq!(queue.get(request.id).await.unwrap(), Some(decided));
    assert_eq!(queue.get(pending.id).await.unwrap(), Some(pending));
}

#[tokio::test]
async fn a_request_keeps_each_field() {
    let database = TestDb::new().await;
    let queue = database.store.approvals();
    let time = Utc.with_ymd_and_hms(2026, 4, 5, 6, 7, 8).unwrap()
        + chrono::Duration::nanoseconds(987_654_321);
    let mut action = ActionRequest::new(
        ActionKind::Custom("quarantine_mailbox".to_owned()),
        EntityRef::new(EntityKind::User, "user-1")
            .with_name("Alice \"Admin\"")
            .with_tenant("contoso"),
        "responder",
        "The account sends phishing mail.\nSecond line.",
    );
    action
        .parameters
        .insert("ratio".to_owned(), json!(0.1 + 0.2));
    action.parameters.insert(
        "scope".to_owned(),
        json!({ "folders": ["inbox", null], "limit": u64::MAX }),
    );
    action.incident_id = Some(IncidentId::new());
    action.evidence = vec![EvidenceRef::new(EvidenceKind::Detection, "det-1").with_note("Burst.")];
    action.dry_run = true;
    action.requested_at = time;
    let request = ApprovalRequest {
        id: ApprovalId::new(),
        action,
        requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent", "tier-2"]),
        decision: PolicyDecision {
            effect: PolicyEffect::RequireApproval,
            tier: ActionTier::Gated,
            reasons: vec![
                "The action is in the gated tier.".to_owned(),
                "The target is an administrator.".to_owned(),
            ],
            policy: Some("aegis.response.decision".to_owned()),
            evaluated_at: time,
        },
        status: ApprovalStatus::Pending,
        requested_at: time,
        decided_by: None,
        decided_at: None,
        note: None,
    };

    queue.submit(request.clone()).await.unwrap();
    assert_eq!(queue.get(request.id).await.unwrap(), Some(request.clone()));
    assert_eq!(queue.pending().await.unwrap(), vec![request.clone()]);

    let decided = queue
        .decide(
            request.id,
            true,
            &approver(),
            Some("Approved \u{2705} with a 'quoted' note.".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(decided.action, request.action);
    assert_eq!(decided.requested_by, request.requested_by);
    assert_eq!(decided.decision, request.decision);
    assert_eq!(decided.requested_at, time);
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(
        decided.note.as_deref(),
        Some("Approved \u{2705} with a 'quoted' note.")
    );
    assert_eq!(queue.get(request.id).await.unwrap(), Some(decided));
}
