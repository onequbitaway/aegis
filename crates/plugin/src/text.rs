//! Text from a plugin is not trusted. This module makes it safe for a log line.

/// The largest number of characters that the host keeps from one plugin message.
pub(crate) const MAX_MESSAGE_CHARS: usize = 1024;

/// Returns `text` with unsafe characters replaced and with a limited length.
///
/// A plugin cannot use the result to start a new log line, to change the direction of
/// the text on a display, or to fill the log.
pub(crate) fn clean(text: &str) -> String {
    let mut cleaned: String = text
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .map(
            |character| {
                if is_unsafe(character) { ' ' } else { character }
            },
        )
        .collect();
    if text.chars().nth(MAX_MESSAGE_CHARS).is_some() {
        cleaned.push_str("...");
    }
    cleaned
}

/// Returns `true` for a character that can forge or hide text in a log.
fn is_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // The line separator and the paragraph separator.
            '\u{2028}' | '\u{2029}'
            // The marks, embeddings, overrides, and isolates that change text direction.
            | '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_keeps_normal_text() {
        assert_eq!(clean("The token is not valid."), "The token is not valid.");
    }

    #[test]
    fn clean_replaces_control_characters() {
        assert_eq!(
            clean("line one\nERROR forged line\r\u{1b}[31m"),
            "line one ERROR forged line  [31m"
        );
    }

    #[test]
    fn clean_replaces_line_separators_and_direction_changes() {
        assert_eq!(
            clean(
                "ok\u{2028}forged\u{2029}line \u{202E}desrever\u{202C} \u{2066}x\u{2069}\u{200F}"
            ),
            "ok forged line  desrever   x  "
        );
        // Text in a language that reads from right to left stays as it is.
        assert_eq!(clean("שלום עולם"), "שלום עולם");
    }

    #[test]
    fn clean_cuts_long_text_and_marks_the_cut() {
        let long = "é".repeat(MAX_MESSAGE_CHARS + 5);
        let cleaned = clean(&long);
        assert_eq!(cleaned.chars().count(), MAX_MESSAGE_CHARS + 3);
        assert!(cleaned.ends_with("é..."));

        let exact = "a".repeat(MAX_MESSAGE_CHARS);
        assert_eq!(clean(&exact), exact);
    }
}
