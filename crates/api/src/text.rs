//! Text helpers for data that comes from a different subsystem or from a caller.

/// Returns `text` as one line with at most `max_characters` characters.
///
/// The function removes control characters and makes each run of white space one space.
/// If the text is too long, the last character of the result is `…`.
pub(crate) fn one_line(text: &str, max_characters: usize) -> String {
    let mut line = String::with_capacity(text.len().min(max_characters * 4));
    let mut count = 0;
    let mut pending_space = false;
    for character in text.chars() {
        if character.is_whitespace() {
            pending_space = !line.is_empty();
            continue;
        }
        if character.is_control() || is_invisible(character) {
            continue;
        }
        let needed = if pending_space { 2 } else { 1 };
        if count + needed > max_characters {
            truncate_with_ellipsis(&mut line, max_characters);
            return line;
        }
        if pending_space {
            line.push(' ');
            pending_space = false;
        }
        line.push(character);
        count += needed;
    }
    line
}

/// Returns `true` for a character that changes the direction or the layout of text and
/// shows nothing. Such a character can make a message show different text than it holds.
fn is_invisible(character: char) -> bool {
    matches!(
        character,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Makes `line` at most `max_characters` long. The last character becomes `…`.
fn truncate_with_ellipsis(line: &mut String, max_characters: usize) {
    if max_characters == 0 {
        line.clear();
        return;
    }
    let keep = max_characters - 1;
    if let Some((offset, _)) = line.char_indices().nth(keep) {
        line.truncate(offset);
    }
    line.push('…');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn white_space_and_control_characters_become_single_spaces() {
        assert_eq!(one_line("  a\n\n b\tc\u{7}d  ", 100), "a b cd");
        assert_eq!(one_line("", 100), "");
        assert_eq!(one_line(" \n ", 100), "");
    }

    #[test]
    fn direction_overrides_are_removed() {
        assert_eq!(one_line("abc\u{202E}def\u{200B}g", 100), "abcdefg");
    }

    #[test]
    fn long_text_ends_with_an_ellipsis_at_the_limit() {
        assert_eq!(one_line("abcdef", 6), "abcdef");
        assert_eq!(one_line("abcdefg", 6), "abcde…");
        assert_eq!(one_line("ab cdefg", 4), "ab …");
        assert_eq!(one_line("añb€cd", 4), "añb…");
        assert_eq!(one_line("abc", 0), "");
    }
}
