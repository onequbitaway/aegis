//! The `agtype` parameter of an Apache AGE `cypher()` call.
//!
//! Apache AGE takes the parameters of a Cypher statement as one `agtype` map. The map must
//! be a bound parameter of the SQL statement. [`Agtype`] sends a JSON document as that
//! parameter, so each value in a Cypher statement is a bound value.

use aegis_contracts::{Error, Result};
use serde_json::Value;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, Postgres};

/// The version byte of the binary form of `agtype`.
const AGTYPE_BINARY_VERSION: u8 = 1;

/// A JSON document that goes to the database as an `agtype` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Agtype(String);

impl Agtype {
    /// Makes the parameter map of a Cypher statement.
    ///
    /// The function rejects a value that `agtype` cannot hold.
    pub(crate) fn parameters(value: &Value) -> Result<Self> {
        check_value(value)?;
        Ok(Self(serde_json::to_string(value)?))
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl sqlx::Type<Postgres> for Agtype {
    fn type_info() -> PgTypeInfo {
        // An extension type has no fixed identifier. The driver finds it by name.
        PgTypeInfo::with_name("ag_catalog.agtype")
    }
}

impl sqlx::Encode<'_, Postgres> for Agtype {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // The binary form of `agtype` is one version byte and then the text form.
        buffer.push(AGTYPE_BINARY_VERSION);
        buffer.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }
}

/// Checks that `agtype` can hold `value` with no change.
///
/// `agtype` has 64-bit signed integers and cannot hold the character U+0000.
pub(crate) fn check_value(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            if number.is_u64() && number.as_i64().is_none() {
                return Err(Error::InvalidInput(format!(
                    "graph: the integer {number} is larger than the largest 64-bit signed integer"
                )));
            }
            Ok(())
        }
        Value::String(text) => check_text(text),
        Value::Array(items) => items.iter().try_for_each(check_value),
        Value::Object(fields) => fields.iter().try_for_each(|(key, field)| {
            check_text(key)?;
            check_value(field)
        }),
    }
}

fn check_text(text: &str) -> Result<()> {
    if text.contains('\0') {
        return Err(Error::InvalidInput(
            "graph: a text value contains the character U+0000, which the database cannot hold"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parameters_are_the_json_text_of_the_value() {
        let value = json!({
            "id": "user:alice",
            "props": { "score": 0.5, "count": 3, "tags": ["a", null] }
        });
        let parameters = Agtype::parameters(&value).unwrap();
        // The order of the keys has no meaning. The text gives back the same value.
        let decoded: Value = serde_json::from_str(parameters.as_str()).unwrap();
        assert_eq!(decoded, value);
        assert!(parameters.as_str().starts_with('{'), "{parameters:?}");
        assert_eq!(
            Agtype::parameters(&json!({ "id": "user:alice" }))
                .unwrap()
                .as_str(),
            r#"{"id":"user:alice"}"#
        );
    }

    #[test]
    fn text_with_quotes_stays_inside_one_json_string() {
        let hostile = "x'}) DETACH DELETE (n) //\" $cypher$ \\";
        let parameters = Agtype::parameters(&json!({ "id": hostile })).unwrap();
        let decoded: Value = serde_json::from_str(parameters.as_str()).unwrap();
        assert_eq!(decoded, json!({ "id": hostile }));
    }

    #[test]
    fn the_largest_signed_integer_is_accepted() {
        assert!(check_value(&json!({ "n": i64::MAX, "m": i64::MIN })).is_ok());
    }

    #[test]
    fn an_integer_above_the_signed_range_is_rejected() {
        let error = check_value(&json!({ "outer": [{ "n": u64::MAX }] })).unwrap_err();
        match error {
            Error::InvalidInput(message) => {
                assert!(message.contains("18446744073709551615"), "{message}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn the_nul_character_is_rejected_in_values_and_in_keys() {
        for value in [json!({ "a": "b\0c" }), json!({ "a\0": 1 }), json!(["\0"])] {
            let error = check_value(&value).unwrap_err();
            assert!(
                matches!(&error, Error::InvalidInput(message) if message.contains("U+0000")),
                "{error:?}"
            );
        }
    }
}
