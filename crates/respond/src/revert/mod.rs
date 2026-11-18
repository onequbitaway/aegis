//! The revert of actions and the timed revert.
//!
//! # Revert
//!
//! [`Dispatcher::revert`](crate::Dispatcher::revert) undoes one action that a connector
//! did before. The revert is a request of its own. It has the action type
//! `{custom: revert}` ([`REVERT_ACTION`]), so the policy can tell a revert from the initial
//! action. The parameter [`REVERTS_PARAMETER`] of the request names the action that the
//! revert undoes.
//!
//! # Contain first, with a timed revert
//!
//! A request with the parameter [`REVERT_AFTER_PARAMETER`] asks for a timed revert. The
//! action runs through the normal path: policy, approval, connector, and audit log. Then
//! the dispatcher holds a [`PendingRevert`] in a [`RevertStore`].
//!
//! - A person confirms the action with [`RevertScheduler::confirm`]. The containment stays.
//! - Nobody confirms before the time. The [`RevertScheduler`] then reverts the action
//!   through [`Dispatcher::revert`](crate::Dispatcher::revert).
//!
//! Only an action type with an inverse can have a timed revert. Refer to
//! [`kind_has_inverse`].
//!
//! # Failure rule
//!
//! If a revert fails, the containment stays. The scheduler writes an audit record and
//! tries again after a delay that grows with each attempt. The pending revert stays in the
//! store until the revert succeeds or a person confirms the action. The scheduler never
//! removes a pending revert without an audit record.

mod scheduler;
mod store;

use std::time::Duration;

use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::common::{ActionId, ApprovalId, EntityRef, IncidentId};
use aegis_contracts::{Error, Result};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;
use tokio::time::Instant;

pub use scheduler::{
    RevertAttempt, RevertProgress, RevertScheduler, RevertSchedulerConfig, RevertStats,
    SCHEDULER_ACTOR, event,
};
pub use store::{FileRevertStore, MemoryRevertStore, RevertStore};

use crate::names::snake_name;

/// The request parameter that asks for a timed revert. The value is a number of seconds.
///
/// The value must be a whole number from [`MIN_REVERT_AFTER_SECONDS`] to
/// [`MAX_REVERT_AFTER_SECONDS`].
pub const REVERT_AFTER_PARAMETER: &str = "revert_after_seconds";

/// The request parameter that holds the outcome details of the execution.
///
/// The dispatcher sets this parameter on the request that it gives to
/// [`ActionConnector::revert`](aegis_contracts::ActionConnector::revert). The value is
/// [`ActionOutcome::details`](aegis_contracts::ActionOutcome) from the audit record of the
/// execution. A connector reads the earlier state of the target from it.
pub const EXECUTION_DETAILS_PARAMETER: &str = "execution_details";

/// The name of the custom action type of a revert request.
///
/// Only [`Dispatcher::revert`](crate::Dispatcher::revert) makes a request of this type.
/// [`ActionDispatcher::dispatch`](aegis_contracts::ActionDispatcher::dispatch) refuses it.
pub const REVERT_ACTION: &str = "revert";

/// The parameter of a revert request that names the action that the revert undoes.
///
/// The value is an object with the fields `action_id`, `kind`, and `requested_by`. It also
/// has `connector` and `executed_at` if the action ran, and `revert_after_seconds` if the
/// action had a timed revert.
pub const REVERTS_PARAMETER: &str = "reverts";

/// The smallest value of [`REVERT_AFTER_PARAMETER`].
pub const MIN_REVERT_AFTER_SECONDS: u64 = 1;

/// The largest value of [`REVERT_AFTER_PARAMETER`]: 30 days.
pub const MAX_REVERT_AFTER_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The principal identifier of the reverts that the [`RevertScheduler`] requests.
///
/// The principal has the type `system` and the role `revert-scheduler`.
pub const SCHEDULER_PRINCIPAL_ID: &str = "revert-scheduler";

/// Returns `true` if an action of this type can have an inverse.
///
/// These types can have an inverse: `disable_service_principal`, `disable_user`,
/// `isolate_host`, `block_ip`, `tag`, `deploy_honeytoken`, and a custom type. The connector
/// decides if it can undo the action.
///
/// These types have no inverse: `enrich`, `notify`, `snapshot_evidence`, `open_ticket`,
/// `revoke_credential`, `rotate_credential`, `kill_session`, and `rotate_secret`.
#[must_use]
pub fn kind_has_inverse(kind: &ActionKind) -> bool {
    match kind {
        ActionKind::DisableServicePrincipal
        | ActionKind::DisableUser
        | ActionKind::IsolateHost
        | ActionKind::BlockIp
        | ActionKind::Tag
        | ActionKind::DeployHoneytoken => true,
        ActionKind::Custom(name) => name != REVERT_ACTION,
        ActionKind::Enrich
        | ActionKind::Notify
        | ActionKind::SnapshotEvidence
        | ActionKind::OpenTicket
        | ActionKind::RevokeCredential
        | ActionKind::RotateCredential
        | ActionKind::KillSession
        | ActionKind::RotateSecret => false,
    }
}

/// Returns `true` if the request is a revert request.
#[must_use]
pub fn is_revert_request(request: &ActionRequest) -> bool {
    matches!(&request.kind, ActionKind::Custom(name) if name == REVERT_ACTION)
}

/// Returns an error text if `seconds` is not a permitted revert time.
fn check_seconds(seconds: u64) -> std::result::Result<u64, String> {
    if (MIN_REVERT_AFTER_SECONDS..=MAX_REVERT_AFTER_SECONDS).contains(&seconds) {
        Ok(seconds)
    } else {
        Err(format!(
            "the revert time must be {MIN_REVERT_AFTER_SECONDS} to {MAX_REVERT_AFTER_SECONDS} seconds, not {seconds}"
        ))
    }
}

/// Returns an error text if an action of the type `kind` cannot have a timed revert.
pub(crate) fn check_kind(kind: &ActionKind) -> std::result::Result<(), String> {
    if kind_has_inverse(kind) {
        Ok(())
    } else {
        Err(format!(
            "the action {} has no inverse, so it cannot have a timed revert",
            snake_name(kind)
        ))
    }
}

/// Reads the timed revert of a request: the value of [`REVERT_AFTER_PARAMETER`].
///
/// Returns `None` if the request does not have the parameter.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the value is not a whole number of seconds in the
/// permitted range, or if the action type has no inverse. Refer to [`kind_has_inverse`].
pub fn revert_after(request: &ActionRequest) -> Result<Option<Duration>> {
    let Some(value) = request.parameters.get(REVERT_AFTER_PARAMETER) else {
        return Ok(None);
    };
    let invalid = |reason: String| {
        Error::InvalidInput(format!(
            "the parameter {REVERT_AFTER_PARAMETER} is not valid: {reason}"
        ))
    };
    let seconds = match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| invalid("the value must be a whole number of seconds".to_owned()))?,
        _ => {
            return Err(invalid(
                "the value must be a whole number of seconds".to_owned(),
            ));
        }
    };
    let seconds = check_seconds(seconds).map_err(invalid)?;
    check_kind(&request.kind).map_err(invalid)?;
    Ok(Some(Duration::from_secs(seconds)))
}

/// Checks the parts of a request that the revert functions use.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the request has the reserved action type
/// [`REVERT_ACTION`], or if its timed revert is not valid.
pub(crate) fn check_request(request: &ActionRequest) -> Result<()> {
    if is_revert_request(request) {
        return Err(Error::InvalidInput(format!(
            "the action type custom:{REVERT_ACTION} is reserved; call Dispatcher::revert to undo an action"
        )));
    }
    revert_after(request).map(|_| ())
}

/// Reads a revert time from a playbook: a number of seconds, or text with a unit.
///
/// The units are `s` (seconds), `m` (minutes), `h` (hours), and `d` (days), for example
/// `90s`, `30m`, `4h`, or `1d`.
pub(crate) fn parse_revert_after(value: &Value) -> std::result::Result<u64, String> {
    let form = "use a number of seconds, or a number with the unit s, m, h, or d, for example 4h";
    let seconds = match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| format!("the revert time {number} is not valid; {form}"))?,
        Value::String(text) => {
            let text = text.trim();
            let digits = text.trim_end_matches(|character: char| !character.is_ascii_digit());
            let unit = text[digits.len()..].trim();
            let scale: u64 = match unit {
                "" | "s" => 1,
                "m" => 60,
                "h" => 60 * 60,
                "d" => 24 * 60 * 60,
                _ => return Err(format!("the revert time {text:?} is not valid; {form}")),
            };
            let all_digits =
                !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit());
            let number = all_digits
                .then(|| digits.parse::<u64>().ok())
                .flatten()
                .ok_or_else(|| format!("the revert time {text:?} is not valid; {form}"))?;
            number.saturating_mul(scale)
        }
        _ => return Err(format!("the revert time is not valid; {form}")),
    };
    check_seconds(seconds)
}

/// Adds `duration` to `time`. The result stops at the largest time that the type can hold.
pub(crate) fn add_duration(time: DateTime<Utc>, duration: Duration) -> DateTime<Utc> {
    TimeDelta::from_std(duration)
        .ok()
        .and_then(|delta| time.checked_add_signed(delta))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Adds `seconds` to `time`. The result stops at the largest time that the type can hold.
pub(crate) fn add_seconds(time: DateTime<Utc>, seconds: u64) -> DateTime<Utc> {
    add_duration(time, Duration::from_secs(seconds))
}

/// The clock of the timed reverts.
///
/// The clock starts at a calendar time and then follows the Tokio clock. Thus a test can
/// drive the timed reverts with `tokio::time::pause` and `tokio::time::advance`.
///
/// A copy of a clock shows the same time as the clock.
#[derive(Debug, Clone)]
pub struct RevertClock {
    anchor: DateTime<Utc>,
    started: Instant,
}

impl RevertClock {
    /// Makes a clock that starts at the present time.
    #[must_use]
    pub fn new() -> Self {
        Self::starting_at(Utc::now())
    }

    /// Makes a clock that starts at `time`.
    #[must_use]
    pub fn starting_at(time: DateTime<Utc>) -> Self {
        Self {
            anchor: time,
            started: Instant::now(),
        }
    }

    /// Returns the time of the clock.
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        add_duration(self.anchor, self.started.elapsed())
    }
}

impl Default for RevertClock {
    fn default() -> Self {
        Self::new()
    }
}

/// The state of a [`PendingRevert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// The dispatcher stored the pending revert and then called the connector. The store
    /// does not have the result of the call.
    ///
    /// A pending revert stays in this state only if the process stopped during the call.
    Armed,
    /// The connector changed the target. The revert waits for its time.
    Waiting,
}

/// One timed revert that waits for its time or for the confirmation of a person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingRevert {
    /// The identifier of the action that the revert undoes.
    pub action_id: ActionId,
    /// The type of the action.
    pub kind: ActionKind,
    /// The entity that the action changed.
    pub target: EntityRef,
    /// The incident of the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<IncidentId>,
    /// The agent or the playbook that requested the action.
    pub requested_by: String,
    /// The revert time of the request, in seconds.
    pub revert_after_seconds: u64,
    /// The time at which the dispatcher stored the pending revert.
    pub armed_at: DateTime<Utc>,
    /// The time at which the scheduler reverts the action, if nobody confirms it.
    pub due_at: DateTime<Utc>,
    /// The state of the pending revert.
    pub state: PendingState,
    /// The number of revert attempts that failed.
    #[serde(default)]
    pub attempts: u32,
    /// The time of the next attempt, after an attempt that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// The error text of the last attempt that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The approval request that the revert waits for, if policy requires approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// The sequence number of the audit record that proposed the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_sequence: Option<u64>,
}

impl PendingRevert {
    /// Returns the time at which the scheduler examines this pending revert again.
    ///
    /// The time is [`due_at`](Self::due_at), or the time of the next attempt if that time
    /// is later.
    #[must_use]
    pub fn wake_at(&self) -> DateTime<Utc> {
        match self.next_attempt_at {
            Some(next) if next > self.due_at => next,
            _ => self.due_at,
        }
    }
}

/// The pending reverts of one dispatcher: the store, the clock, and the change signal.
///
/// The dispatcher and the scheduler share one ledger.
pub(crate) struct Ledger {
    pub(crate) store: std::sync::Arc<dyn RevertStore>,
    pub(crate) clock: RevertClock,
    pub(crate) changed: Notify,
}

impl Ledger {
    pub(crate) fn new(store: std::sync::Arc<dyn RevertStore>, clock: RevertClock) -> Self {
        Self {
            store,
            clock,
            changed: Notify::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::EntityKind;
    use serde_json::json;

    use super::*;

    fn request(kind: ActionKind, value: Value) -> ActionRequest {
        let mut request = ActionRequest::new(
            kind,
            EntityRef::new(EntityKind::User, "user-1"),
            "responder",
            "Test.",
        );
        request
            .parameters
            .insert(REVERT_AFTER_PARAMETER.to_owned(), value);
        request
    }

    #[test]
    fn a_request_with_no_parameter_has_no_timed_revert() {
        let request = ActionRequest::new(
            ActionKind::KillSession,
            EntityRef::new(EntityKind::User, "user-1"),
            "responder",
            "Test.",
        );
        assert_eq!(revert_after(&request).unwrap(), None);
        assert!(check_request(&request).is_ok());
    }

    #[test]
    fn the_revert_time_is_a_whole_number_of_seconds_in_the_range() {
        assert_eq!(
            revert_after(&request(ActionKind::DisableUser, json!(3600))).unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            revert_after(&request(
                ActionKind::BlockIp,
                json!(MAX_REVERT_AFTER_SECONDS)
            ))
            .unwrap(),
            Some(Duration::from_secs(MAX_REVERT_AFTER_SECONDS))
        );
        for bad in [
            json!(0),
            json!(MAX_REVERT_AFTER_SECONDS + 1),
            json!(-5),
            json!(1.5),
            json!("3600"),
            json!(null),
            json!(true),
            json!([3600]),
        ] {
            let error = revert_after(&request(ActionKind::DisableUser, bad.clone())).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message)
                    if message.starts_with("the parameter revert_after_seconds is not valid: ")),
                "{bad}: {error:?}"
            );
        }
    }

    #[test]
    fn only_an_action_type_with_an_inverse_can_have_a_timed_revert() {
        for kind in [
            ActionKind::DisableServicePrincipal,
            ActionKind::DisableUser,
            ActionKind::IsolateHost,
            ActionKind::BlockIp,
            ActionKind::Tag,
            ActionKind::DeployHoneytoken,
            ActionKind::Custom("restrict_user_consent".to_owned()),
        ] {
            assert!(kind_has_inverse(&kind), "{kind:?}");
            assert!(
                revert_after(&request(kind.clone(), json!(60))).is_ok(),
                "{kind:?}"
            );
        }
        for kind in [
            ActionKind::Enrich,
            ActionKind::Notify,
            ActionKind::SnapshotEvidence,
            ActionKind::OpenTicket,
            ActionKind::RevokeCredential,
            ActionKind::RotateCredential,
            ActionKind::KillSession,
            ActionKind::RotateSecret,
        ] {
            assert!(!kind_has_inverse(&kind), "{kind:?}");
            let error = revert_after(&request(kind.clone(), json!(60))).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message) if message.contains("has no inverse")),
                "{kind:?}: {error:?}"
            );
        }
    }

    #[test]
    fn the_revert_action_type_is_reserved() {
        let revert = ActionRequest::new(
            ActionKind::Custom(REVERT_ACTION.to_owned()),
            EntityRef::new(EntityKind::User, "user-1"),
            "responder",
            "Test.",
        );
        assert!(is_revert_request(&revert));
        assert!(!kind_has_inverse(&revert.kind));
        let error = check_request(&revert).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("is reserved")),
            "{error:?}"
        );
    }

    #[test]
    fn a_playbook_revert_time_is_seconds_or_a_number_with_a_unit() {
        assert_eq!(parse_revert_after(&json!(90)).unwrap(), 90);
        assert_eq!(parse_revert_after(&json!("90")).unwrap(), 90);
        assert_eq!(parse_revert_after(&json!("90s")).unwrap(), 90);
        assert_eq!(parse_revert_after(&json!("30m")).unwrap(), 1_800);
        assert_eq!(parse_revert_after(&json!(" 4 h ")).unwrap(), 14_400);
        assert_eq!(parse_revert_after(&json!("1d")).unwrap(), 86_400);
        assert_eq!(
            parse_revert_after(&json!("30d")).unwrap(),
            MAX_REVERT_AFTER_SECONDS
        );
        for bad in [
            json!("4 hours"),
            json!("h"),
            json!("-4h"),
            json!("4.5h"),
            json!("4h30m"),
            json!(""),
            json!(1.5),
            json!(true),
            json!(null),
        ] {
            let error = parse_revert_after(&bad).unwrap_err();
            assert!(error.contains("is not valid"), "{bad}: {error}");
        }
        for out_of_range in [
            json!(0),
            json!("0m"),
            json!("31d"),
            json!("99999999999999d"),
        ] {
            let error = parse_revert_after(&out_of_range).unwrap_err();
            assert!(
                error.starts_with("the revert time must be 1 to 2592000 seconds"),
                "{out_of_range}: {error}"
            );
        }
    }

    #[test]
    fn add_seconds_stops_at_the_largest_time() {
        let time = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(
            add_seconds(time, 60),
            DateTime::<Utc>::from_timestamp(1_800_000_060, 0).unwrap()
        );
        assert_eq!(add_seconds(time, u64::MAX), DateTime::<Utc>::MAX_UTC);
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_follows_the_tokio_clock() {
        let start = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = RevertClock::starting_at(start);
        let copy = clock.clone();
        assert_eq!(clock.now(), start);

        tokio::time::advance(Duration::from_secs(90)).await;

        assert_eq!(clock.now(), add_seconds(start, 90));
        assert_eq!(copy.now(), clock.now());
    }

    #[test]
    fn wake_at_is_the_later_of_the_due_time_and_the_next_attempt() {
        let due = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let mut pending = PendingRevert {
            action_id: ActionId::new(),
            kind: ActionKind::DisableUser,
            target: EntityRef::new(EntityKind::User, "user-1"),
            incident_id: None,
            requested_by: "responder".to_owned(),
            revert_after_seconds: 60,
            armed_at: due,
            due_at: due,
            state: PendingState::Waiting,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            approval_id: None,
            audit_sequence: None,
        };
        assert_eq!(pending.wake_at(), due);
        pending.next_attempt_at = Some(add_seconds(due, 30));
        assert_eq!(pending.wake_at(), add_seconds(due, 30));
        pending.due_at = add_seconds(due, 300);
        assert_eq!(pending.wake_at(), add_seconds(due, 300));
    }
}
