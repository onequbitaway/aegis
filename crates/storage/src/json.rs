//! Small conversions between contract values and column values.

use aegis_contracts::{Error, Result};
use chrono::{DateTime, SubsecRound, Timelike, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::decode_error;

/// Returns the serialized name of a unit enum variant, for example `false_positive`.
pub(crate) fn variant_name<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(Error::Serialization(format!(
            "storage: expected an enum name, found {other}"
        ))),
    }
}

/// Reads a unit enum variant from its serialized name.
pub(crate) fn variant_from_name<T: DeserializeOwned>(what: &str, name: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|error| decode_error(what, error))
}

/// Splits a time for a `timestamptz` column, which keeps microseconds.
///
/// The result is the time rounded down to microseconds, and the nanoseconds that remain
/// (0 to 999). A sort by the two values is a sort by the full time.
pub(crate) fn split_time(time: DateTime<Utc>) -> (DateTime<Utc>, i16) {
    let remainder = i16::try_from(time.nanosecond() % 1_000).unwrap_or_default();
    (time.trunc_subsecs(6), remainder)
}

/// Converts a row limit to the type of a `LIMIT` parameter.
pub(crate) fn sql_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use aegis_contracts::audit::AuditKind;
    use aegis_contracts::incident::IncidentStatus;

    use super::*;

    #[test]
    fn variant_names_are_the_serialized_names() {
        assert_eq!(
            variant_name(&IncidentStatus::FalsePositive).unwrap(),
            "false_positive"
        );
        assert_eq!(
            variant_name(&AuditKind::ApprovalDecided).unwrap(),
            "approval_decided"
        );
        assert_eq!(
            variant_from_name::<AuditKind>("audit kind", "policy_decision").unwrap(),
            AuditKind::PolicyDecision
        );
    }

    #[test]
    fn a_value_that_is_not_a_unit_variant_has_no_name() {
        let error = variant_name(&42_u8).unwrap_err();
        assert!(matches!(error, Error::Serialization(message) if message.contains("42")));
    }

    #[test]
    fn an_unknown_name_is_a_serialization_error() {
        let error = variant_from_name::<IncidentStatus>("incident status", "archived").unwrap_err();
        match error {
            Error::Serialization(message) => {
                assert!(message.starts_with("storage: incident status cannot be decoded"));
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn a_time_splits_into_microseconds_and_the_nanoseconds_that_remain() {
        use chrono::TimeZone;
        let second = Utc.with_ymd_and_hms(2026, 5, 6, 7, 8, 9).unwrap();
        let time = second + chrono::Duration::nanoseconds(123_456_789);
        assert_eq!(
            split_time(time),
            (second + chrono::Duration::microseconds(123_456), 789)
        );
        assert_eq!(split_time(second), (second, 0));

        // A time before the year 1970 also rounds down.
        let old = Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59).unwrap();
        let time = old + chrono::Duration::nanoseconds(999_999_999);
        assert_eq!(
            split_time(time),
            (old + chrono::Duration::microseconds(999_999), 999)
        );

        // The two parts sort as the full times sort.
        let earlier = second + chrono::Duration::nanoseconds(1_999);
        let later = second + chrono::Duration::nanoseconds(2_000);
        assert!(split_time(earlier) < split_time(later));
    }

    #[test]
    fn limits_stay_in_the_range_of_the_database_type() {
        assert_eq!(sql_limit(0), 0);
        assert_eq!(sql_limit(25), 25);
        assert_eq!(sql_limit(usize::MAX), i64::MAX);
    }
}
