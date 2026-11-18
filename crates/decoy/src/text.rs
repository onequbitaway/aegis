//! Helpers for text that comes from a client.
//!
//! Text from a client is untrusted data. The decoy limits it and removes control
//! characters before the text goes into an event or a log line.

/// Text from a client after the decoy cleaned and limited it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Cleaned {
    /// The clean text.
    pub(crate) text: String,
    /// `true` if the decoy removed text because of the limit.
    pub(crate) truncated: bool,
}

/// Returns `text` with no control characters and with `max_characters` characters at most.
///
/// The function makes each run of white space one space. It removes each control
/// character and each character that shows nothing. It removes white space at the ends.
pub(crate) fn clean(text: &str, max_characters: usize) -> Cleaned {
    let mut cleaned = Cleaned::default();
    let mut count = 0_usize;
    let mut pending_space = false;
    for character in text.chars() {
        if character.is_whitespace() {
            pending_space = count > 0;
            continue;
        }
        if character.is_control() || is_invisible(character) {
            continue;
        }
        let needed = if pending_space { 2 } else { 1 };
        if count + needed > max_characters {
            cleaned.truncated = true;
            return cleaned;
        }
        if pending_space {
            cleaned.text.push(' ');
            pending_space = false;
        }
        cleaned.text.push(character);
        count += needed;
    }
    cleaned
}

/// Cleans bytes from a client. Bytes that are not valid UTF-8 become `U+FFFD`.
pub(crate) fn clean_bytes(bytes: &[u8], max_characters: usize) -> Cleaned {
    // One character has four bytes at most. A longer input cannot add to the result.
    let scan = max_characters
        .saturating_mul(4)
        .saturating_add(4)
        .min(bytes.len());
    let limited = bytes.get(..scan).unwrap_or(bytes);
    let mut cleaned = clean(&String::from_utf8_lossy(limited), max_characters);
    if scan < bytes.len() {
        cleaned.truncated = true;
    }
    cleaned
}

/// Returns `true` for a character that shows nothing or that changes the text direction.
///
/// Such a character can hide text from a person who reads an event.
fn is_invisible(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(input: &str, max: usize) -> String {
        clean(input, max).text
    }

    #[test]
    fn white_space_becomes_one_space_and_control_characters_go() {
        assert_eq!(
            text("  a\r\n\n b\tc\u{7}d\u{0}e\u{1b}[31m  ", 100),
            "a b cde[31m"
        );
        assert_eq!(text("", 100), "");
        assert_eq!(text(" \n ", 100), "");
        assert!(!clean("a b", 100).truncated);
    }

    #[test]
    fn characters_that_show_nothing_are_removed() {
        assert_eq!(text("abc\u{202E}def\u{200B}g\u{FEFF}h", 100), "abcdefgh");
        // The Unicode tag characters can hide an instruction in text.
        assert_eq!(text("a\u{E0041}\u{E0042}\u{E007F}b", 100), "ab");
        assert_eq!(text("a\u{00AD}b\u{2066}c\u{2069}", 100), "abc");
    }

    #[test]
    fn long_text_stops_at_the_limit_and_sets_the_mark() {
        let exact = clean("abcdef", 6);
        assert_eq!(exact.text, "abcdef");
        assert!(!exact.truncated);
        let cut = clean("abcdefg", 6);
        assert_eq!(cut.text, "abcdef");
        assert!(cut.truncated);
        // A space and the next character do not fit, so the text ends before the space.
        let cut_at_space = clean("abc def", 4);
        assert_eq!(cut_at_space.text, "abc");
        assert!(cut_at_space.truncated);
        let multibyte = clean("añb€cd", 4);
        assert_eq!(multibyte.text, "añb€");
        assert!(multibyte.truncated);
        let none = clean("abc", 0);
        assert_eq!(none.text, "");
        assert!(none.truncated);
    }

    #[test]
    fn bytes_that_are_not_utf8_become_the_replacement_character() {
        let cleaned = clean_bytes(b"ab\xff\xfecd\n", 100);
        assert_eq!(cleaned.text, "ab\u{FFFD}\u{FFFD}cd");
        assert!(!cleaned.truncated);
    }

    #[test]
    fn long_bytes_are_cut_before_the_conversion() {
        let input = vec![b'x'; 10_000];
        let cleaned = clean_bytes(&input, 10);
        assert_eq!(cleaned.text, "x".repeat(10));
        assert!(cleaned.truncated);
        // White space after the scanned part still counts as removed text.
        let mut padded = vec![b'y'; 3];
        padded.extend(std::iter::repeat_n(b' ', 100));
        let cleaned = clean_bytes(&padded, 3);
        assert_eq!(cleaned.text, "yyy");
        assert!(cleaned.truncated);
    }
}
