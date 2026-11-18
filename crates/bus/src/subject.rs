//! Checks for subjects, subscription patterns, and durable names.
//!
//! The NATS bus and the in-process bus use the same checks. Thus, input that one bus
//! accepts is also valid for the other bus.

use aegis_contracts::bus::subject_matches;
use aegis_contracts::{Error, Result};

/// The largest subject or pattern, in bytes. A larger subject can break the NATS protocol line.
pub(crate) const MAX_SUBJECT_BYTES: usize = 255;
/// The largest durable name, in bytes.
pub(crate) const MAX_DURABLE_NAME_BYTES: usize = 64;

const ONE_TOKEN: &str = "*";
const REMAINING_TOKENS: &str = ">";

/// Checks the rules that subjects and patterns share.
fn check_tokens(kind: &str, text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::InvalidInput(format!("{kind} must not be empty")));
    }
    if text.len() > MAX_SUBJECT_BYTES {
        return Err(Error::InvalidInput(format!(
            "{kind} has {} bytes; the maximum is {MAX_SUBJECT_BYTES}",
            text.len()
        )));
    }
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(Error::InvalidInput(format!(
            "{kind} {text:?} must not have whitespace or control characters"
        )));
    }
    if text.split('.').any(str::is_empty) {
        return Err(Error::InvalidInput(format!(
            "{kind} {text:?} must not have empty tokens"
        )));
    }
    Ok(())
}

/// Checks a subject for a publish operation. A subject has no wildcards.
pub(crate) fn check_subject(subject: &str) -> Result<()> {
    check_tokens("subject", subject)?;
    if subject
        .split('.')
        .any(|token| token == ONE_TOKEN || token == REMAINING_TOKENS)
    {
        return Err(Error::InvalidInput(format!(
            "subject {subject:?} must not have wildcards"
        )));
    }
    Ok(())
}

/// Checks a subscription pattern. `>` is permitted only as the last token.
pub(crate) fn check_pattern(pattern: &str) -> Result<()> {
    check_tokens("pattern", pattern)?;
    let mut tokens = pattern.split('.');
    while let Some(token) = tokens.next() {
        if token == REMAINING_TOKENS && tokens.next().is_some() {
            return Err(Error::InvalidInput(format!(
                "pattern {pattern:?} can have `>` only as the last token"
            )));
        }
    }
    Ok(())
}

/// Checks a durable name. The name becomes the name of a JetStream consumer.
pub(crate) fn check_durable_name(name: &str) -> Result<()> {
    let has_valid_characters = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if name.is_empty() || name.len() > MAX_DURABLE_NAME_BYTES || !has_valid_characters {
        return Err(Error::InvalidInput(format!(
            "durable name {name:?} must have 1 to {MAX_DURABLE_NAME_BYTES} characters from \
             `A-Z`, `a-z`, `0-9`, `-`, and `_`"
        )));
    }
    Ok(())
}

/// Returns `true` if one subject or more can match the two patterns.
pub(crate) fn patterns_overlap(left: &str, right: &str) -> bool {
    let mut left_tokens = left.split('.');
    let mut right_tokens = right.split('.');
    loop {
        match (left_tokens.next(), right_tokens.next()) {
            (Some(REMAINING_TOKENS), Some(_)) | (Some(_), Some(REMAINING_TOKENS)) => return true,
            (Some(left_token), Some(right_token))
                if left_token == ONE_TOKEN
                    || right_token == ONE_TOKEN
                    || left_token == right_token => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// The subjects that the bus stores, and the checks that use them.
#[derive(Debug, Clone)]
pub(crate) struct SubjectPolicy {
    stored: Vec<String>,
}

impl SubjectPolicy {
    /// Makes a policy from the subjects of the stream.
    pub(crate) fn new(stored: &[String]) -> Self {
        Self {
            stored: stored.to_vec(),
        }
    }

    /// Checks that the bus can store a message with this subject.
    pub(crate) fn check_publish(&self, subject: &str) -> Result<()> {
        check_subject(subject)?;
        if !self
            .stored
            .iter()
            .any(|stored| subject_matches(stored, subject))
        {
            return Err(Error::InvalidInput(format!(
                "subject {subject:?} is not in the subjects that the bus stores ({})",
                self.stored.join(", ")
            )));
        }
        Ok(())
    }

    /// Checks a subscription request.
    pub(crate) fn check_subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<()> {
        check_pattern(pattern)?;
        if !self
            .stored
            .iter()
            .any(|stored| patterns_overlap(stored, pattern))
        {
            return Err(Error::InvalidInput(format!(
                "pattern {pattern:?} cannot match a subject that the bus stores ({})",
                self.stored.join(", ")
            )));
        }
        durable.map_or(Ok(()), check_durable_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_input(result: Result<()>) -> String {
        match result {
            Err(Error::InvalidInput(message)) => message,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn a_subject_with_plain_tokens_is_valid() {
        for subject in [
            "aegis",
            "aegis.events.entra-prod",
            "aegis.a*b.c>d",
            "a.b_c.D-1",
        ] {
            assert!(check_subject(subject).is_ok(), "{subject:?}");
        }
    }

    #[test]
    fn a_subject_with_wildcards_or_bad_tokens_is_not_valid() {
        let cases = [
            ("", "must not be empty"),
            ("aegis.*", "must not have wildcards"),
            ("aegis.>", "must not have wildcards"),
            ("*", "must not have wildcards"),
            ("aegis..events", "must not have empty tokens"),
            (".aegis", "must not have empty tokens"),
            ("aegis.", "must not have empty tokens"),
            ("aegis.ev ents", "whitespace or control"),
            ("aegis.events\n", "whitespace or control"),
            ("aegis.\u{0}", "whitespace or control"),
        ];
        for (subject, expected) in cases {
            let message = invalid_input(check_subject(subject));
            assert!(message.contains(expected), "{subject:?}: {message}");
        }
    }

    #[test]
    fn the_subject_length_limit_is_inclusive() {
        let longest = "a".repeat(MAX_SUBJECT_BYTES);
        assert!(check_subject(&longest).is_ok());
        let too_long = "a".repeat(MAX_SUBJECT_BYTES + 1);
        let message = invalid_input(check_subject(&too_long));
        assert_eq!(message, "subject has 256 bytes; the maximum is 255");
    }

    #[test]
    fn a_pattern_can_have_wildcards() {
        for pattern in [
            "aegis.>",
            "aegis.*.file",
            "*",
            ">",
            "aegis.events.file",
            "*.*.>",
        ] {
            assert!(check_pattern(pattern).is_ok(), "{pattern:?}");
        }
    }

    #[test]
    fn a_pattern_with_a_misplaced_tail_wildcard_is_not_valid() {
        let cases = [
            ("", "must not be empty"),
            ("aegis.>.events", "only as the last token"),
            (">.aegis", "only as the last token"),
            ("aegis..>", "must not have empty tokens"),
            ("aegis. >", "whitespace or control"),
        ];
        for (pattern, expected) in cases {
            let message = invalid_input(check_pattern(pattern));
            assert!(message.contains(expected), "{pattern:?}: {message}");
        }
    }

    #[test]
    fn a_durable_name_has_a_small_character_set() {
        for name in [
            "detect",
            "tier-1_detect",
            "A9",
            &"n".repeat(MAX_DURABLE_NAME_BYTES),
        ] {
            assert!(check_durable_name(name).is_ok(), "{name:?}");
        }
        for name in [
            "",
            "detect.tier1",
            "detect tier1",
            "detect*",
            "detect>",
            "detect/1",
            "détect",
            &"n".repeat(MAX_DURABLE_NAME_BYTES + 1),
        ] {
            let message = invalid_input(check_durable_name(name));
            assert!(message.contains("durable name"), "{name:?}: {message}");
        }
    }

    #[test]
    fn patterns_overlap_when_a_subject_can_match_the_two() {
        let overlapping = [
            ("aegis.>", "aegis.events.file"),
            ("aegis.>", "aegis.*"),
            ("aegis.>", ">"),
            ("aegis.>", "*.events.>"),
            ("aegis.*.file", "aegis.events.*"),
            ("aegis.events", "aegis.events"),
            ("*", "aegis"),
        ];
        for (left, right) in overlapping {
            assert!(patterns_overlap(left, right), "{left:?} and {right:?}");
            assert!(patterns_overlap(right, left), "{right:?} and {left:?}");
        }
    }

    #[test]
    fn patterns_do_not_overlap_when_no_subject_can_match_the_two() {
        let disjoint = [
            ("aegis.>", "aegis"),
            ("aegis.>", "other.>"),
            ("aegis.>", "other.events"),
            ("aegis.events", "aegis.events.file"),
            ("aegis.*", "aegis.events.file"),
            ("aegis.*.file", "aegis.events.entra"),
            ("*", "aegis.events"),
        ];
        for (left, right) in disjoint {
            assert!(!patterns_overlap(left, right), "{left:?} and {right:?}");
            assert!(!patterns_overlap(right, left), "{right:?} and {left:?}");
        }
    }

    #[test]
    fn the_policy_rejects_a_subject_that_the_bus_does_not_store() {
        let policy = SubjectPolicy::new(&["aegis.>".to_owned(), "audit".to_owned()]);
        assert!(policy.check_publish("aegis.events.file").is_ok());
        assert!(policy.check_publish("audit").is_ok());
        let message = invalid_input(policy.check_publish("other.events"));
        assert_eq!(
            message,
            "subject \"other.events\" is not in the subjects that the bus stores (aegis.>, audit)"
        );
        // `aegis.>` needs one token or more after `aegis`.
        let message = invalid_input(policy.check_publish("aegis"));
        assert_eq!(
            message,
            "subject \"aegis\" is not in the subjects that the bus stores (aegis.>, audit)"
        );
    }

    #[test]
    fn the_policy_rejects_a_pattern_that_can_never_match() {
        let policy = SubjectPolicy::new(&["aegis.>".to_owned()]);
        assert!(policy.check_subscribe("aegis.events.*", None).is_ok());
        assert!(policy.check_subscribe(">", Some("all")).is_ok());
        let message = invalid_input(policy.check_subscribe("other.>", None));
        assert_eq!(
            message,
            "pattern \"other.>\" cannot match a subject that the bus stores (aegis.>)"
        );
        let message = invalid_input(policy.check_subscribe("aegis.>", Some("bad name")));
        assert!(message.contains("durable name \"bad name\""), "{message}");
    }
}
