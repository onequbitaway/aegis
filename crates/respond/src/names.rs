//! Text names for contract enumerations.

use aegis_contracts::Error;
use aegis_contracts::common::EntityRef;
use serde::Serialize;
use serde_json::Value;

/// Returns the configuration name of an enumeration value, for example `block_ip`.
///
/// A variant with text, for example a custom action, gives `custom:name`.
pub(crate) fn snake_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        Ok(Value::Object(fields)) => fields
            .into_iter()
            .next()
            .map(|(tag, content)| match content {
                Value::String(text) => format!("{tag}:{text}"),
                _ => tag,
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Returns a short label for an entity, for example `service_principal sp-1`.
pub(crate) fn entity_label(entity: &EntityRef) -> String {
    format!("{} {}", snake_name(&entity.kind), entity.id)
}

/// Returns the name of the variant of an error, for example `unavailable`.
pub(crate) fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::InvalidInput(_) => "invalid_input",
        Error::NotFound(_) => "not_found",
        Error::Config(_) => "config",
        Error::Unauthorized(_) => "unauthorized",
        Error::Denied(_) => "denied",
        Error::Unsupported(_) => "unsupported",
        Error::Unavailable(_) => "unavailable",
        Error::RateLimited(_) => "rate_limited",
        Error::Timeout(_) => "timeout",
        Error::Refused(_) => "refused",
        Error::BudgetExceeded(_) => "budget_exceeded",
        Error::Serialization(_) => "serialization",
        Error::Integrity(_) => "integrity",
        Error::Other { .. } => "other",
    }
}

/// Returns the data of an error for an audit payload or a result message.
pub(crate) fn error_payload(error: &Error) -> Value {
    serde_json::json!({
        "kind": error_kind(error),
        "message": error.to_string(),
        "retryable": error.is_retryable(),
    })
}

/// Makes an error of the same variant as `error` with a new message.
///
/// Use this to add context and keep the retry state of the cause.
pub(crate) fn same_kind(error: &Error, message: String) -> Error {
    match error {
        Error::InvalidInput(_) => Error::InvalidInput(message),
        Error::NotFound(_) => Error::NotFound(message),
        Error::Config(_) => Error::Config(message),
        Error::Unauthorized(_) => Error::Unauthorized(message),
        Error::Denied(_) => Error::Denied(message),
        Error::Unsupported(_) => Error::Unsupported(message),
        Error::Unavailable(_) => Error::Unavailable(message),
        Error::RateLimited(_) => Error::RateLimited(message),
        Error::Timeout(_) => Error::Timeout(message),
        Error::Refused(_) => Error::Refused(message),
        Error::BudgetExceeded(_) => Error::BudgetExceeded(message),
        Error::Serialization(_) => Error::Serialization(message),
        Error::Integrity(_) => Error::Integrity(message),
        Error::Other { .. } => Error::other(message, "refer to the message"),
    }
}

/// Returns `text` with no more than `limit` characters.
pub(crate) fn truncate(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

/// Returns `text` as one line with no control characters and no more than `limit`
/// characters.
///
/// Use this for text from a caller that goes into an audit record or a message.
pub(crate) fn clean_text(text: &str, limit: usize) -> String {
    let line: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    truncate(line.trim(), limit)
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::ActionKind;
    use aegis_contracts::common::EntityKind;

    use super::*;

    #[test]
    fn names_are_the_configuration_names() {
        assert_eq!(snake_name(&ActionKind::BlockIp), "block_ip");
        assert_eq!(
            snake_name(&ActionKind::Custom("quarantine_mailbox".to_owned())),
            "custom:quarantine_mailbox"
        );
        assert_eq!(
            snake_name(&EntityKind::ServicePrincipal),
            "service_principal"
        );
        assert_eq!(
            entity_label(&EntityRef::new(EntityKind::IpAddress, "203.0.113.50")),
            "ip_address 203.0.113.50"
        );
    }

    #[test]
    fn an_error_payload_names_the_variant_and_the_retry_state() {
        let payload = error_payload(&Error::RateLimited("slow down".to_owned()));
        assert_eq!(payload["kind"], "rate_limited");
        assert_eq!(payload["retryable"], true);
        assert_eq!(payload["message"], "rate limited: slow down");
        assert_eq!(
            error_payload(&Error::Unauthorized("no".to_owned()))["retryable"],
            false
        );
    }

    #[test]
    fn same_kind_keeps_the_variant_and_replaces_the_message() {
        let timeout = same_kind(&Error::Timeout("old".to_owned()), "new".to_owned());
        assert!(
            matches!(&timeout, Error::Timeout(message) if message == "new"),
            "{timeout:?}"
        );
        assert!(timeout.is_retryable());
        let denied = same_kind(&Error::Unauthorized("old".to_owned()), "new".to_owned());
        assert!(
            matches!(&denied, Error::Unauthorized(message) if message == "new"),
            "{denied:?}"
        );
        assert!(!denied.is_retryable());
    }

    #[test]
    fn clean_text_removes_control_characters_and_limits_the_length() {
        assert_eq!(clean_text("  Undo it.\n", 100), "Undo it.");
        assert_eq!(
            clean_text("line one\nline\ttwo\u{7}", 100),
            "line one line two"
        );
        assert_eq!(clean_text("éàüö", 2), "éà...");
        assert_eq!(clean_text(" \r\n ", 100), "");
    }

    #[test]
    fn truncate_keeps_short_text_and_cuts_long_text_at_a_character() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("éàüö", 2), "éà...");
        assert_eq!(truncate("exact", 5), "exact");
    }
}
