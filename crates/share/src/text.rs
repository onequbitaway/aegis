//! Text cleaning and escaping for the documents.
//!
//! All text from an event is untrusted. An attacker can put markup, control characters,
//! or invisible characters in a user agent or a path. The functions in this module make
//! such text safe to show:
//!
//! - [`clean`] replaces each unsafe character with visible text and limits the length.
//! - [`md_code`] and [`md_text`] put cleaned text into Markdown.
//! - [`json_compact`] and [`json_pretty`] write JSON that contains only printable ASCII.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use serde_json::Value;

/// The text that replaces the end of a value that is too long.
pub(crate) const CUT_MARK: &str = "...[cut]";

/// The largest number of characters of a user agent that a document keeps.
pub(crate) const MAX_USER_AGENT_CHARS: usize = 256;

/// The largest number of characters of a free-text attribute that a document keeps.
pub(crate) const MAX_TEXT_CHARS: usize = 512;

/// The largest number of characters of a short token, for example an action name.
pub(crate) const MAX_TOKEN_CHARS: usize = 128;

/// Returns a time in UTC with milliseconds, for example `2026-11-03T09:10:00.000Z`.
pub(crate) fn time_text(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Encodes a time as [`time_text`] gives it.
pub(crate) fn serialize_time<S: Serializer>(
    time: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&time_text(*time))
}

/// Returns the name that serde gives to a value, for example `service_principal`.
pub(crate) fn token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Returns `true` for a character that a document must not hold as it is.
///
/// These are the control characters and the invisible format characters: soft hyphen,
/// zero-width characters, direction marks and overrides, line and paragraph separators,
/// and the tag characters. A reader cannot see them, but a display or a model obeys them.
pub(crate) fn is_unsafe_char(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Returns `text` with each unsafe character as visible text, for example `{U+001B}`.
///
/// The result has at most `max_chars` characters of `text`. If `text` is longer, the
/// result ends with [`CUT_MARK`]. The result is one line.
pub(crate) fn clean(text: &str, max_chars: usize) -> String {
    let mut cleaned = String::with_capacity(text.len().min(max_chars.saturating_mul(4)));
    for (position, character) in text.chars().enumerate() {
        if position >= max_chars {
            cleaned.push_str(CUT_MARK);
            break;
        }
        if is_unsafe_char(character) {
            cleaned.push_str(&format!("{{U+{:04X}}}", u32::from(character)));
        } else {
            cleaned.push(character);
        }
    }
    cleaned
}

/// Puts untrusted text into Markdown as a code span.
///
/// A code span shows its contents as they are. Markup, links, and HTML in the text have
/// no effect. The fence of the span is longer than each run of backticks in the text, so
/// the text cannot close the span.
pub(crate) fn md_code(text: &str, max_chars: usize) -> String {
    let cleaned = clean(text, max_chars);
    if cleaned.is_empty() {
        return "(empty)".to_owned();
    }
    let mut longest = 0_usize;
    let mut run = 0_usize;
    for character in cleaned.chars() {
        if character == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    let pad = cleaned.starts_with(['`', ' ']) || cleaned.ends_with(['`', ' ']);
    if pad {
        format!("{fence} {cleaned} {fence}")
    } else {
        format!("{fence}{cleaned}{fence}")
    }
}

/// Puts text from the operator or from a rule pack into Markdown as plain text.
///
/// The function puts a backslash before each character that starts markup, a link, an
/// image, a table cell, a heading, or HTML.
pub(crate) fn md_text(text: &str, max_chars: usize) -> String {
    let cleaned = clean(text, max_chars);
    let mut escaped = String::with_capacity(cleaned.len() + 8);
    for character in cleaned.chars() {
        if matches!(
            character,
            '\\' | '`'
                | '*'
                | '_'
                | '['
                | ']'
                | '<'
                | '>'
                | '|'
                | '#'
                | '!'
                | '('
                | ')'
                | '~'
                | '&'
                | '{'
                | '}'
                | ':'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Writes `value` as JSON on one line, with object keys in byte order.
///
/// The output holds only printable ASCII. Refer to [`json_pretty`] for the escapes.
pub(crate) fn json_compact(value: &Value) -> String {
    let mut output = String::new();
    write_value(value, None, 0, &mut output);
    output
}

/// Writes `value` as JSON with two spaces of indentation and object keys in byte order.
///
/// The output holds only printable ASCII. The writer escapes each character that is not
/// printable ASCII as `\uXXXX`. It also escapes `<`, `>`, `&`, and the backtick, so that
/// the text is safe in HTML and in a Markdown code block. A JSON parser returns the same
/// values.
pub(crate) fn json_pretty(value: &Value) -> String {
    let mut output = String::new();
    write_value(value, Some(2), 0, &mut output);
    output.push('\n');
    output
}

fn new_line(indent: Option<usize>, level: usize, output: &mut String) {
    if let Some(width) = indent {
        output.push('\n');
        output.push_str(&" ".repeat(width.saturating_mul(level)));
    }
}

fn write_value(value: &Value, indent: Option<usize>, level: usize, output: &mut String) {
    match value {
        Value::Object(fields) => {
            if fields.is_empty() {
                output.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort_unstable();
            output.push('{');
            for (position, key) in keys.into_iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                new_line(indent, level + 1, output);
                write_string(key, output);
                output.push(':');
                if indent.is_some() {
                    output.push(' ');
                }
                if let Some(field) = fields.get(key) {
                    write_value(field, indent, level + 1, output);
                }
            }
            new_line(indent, level, output);
            output.push('}');
        }
        Value::Array(items) => {
            if items.is_empty() {
                output.push_str("[]");
                return;
            }
            output.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                new_line(indent, level + 1, output);
                write_value(item, indent, level + 1, output);
            }
            new_line(indent, level, output);
            output.push(']');
        }
        Value::String(text) => write_string(text, output),
        scalar => output.push_str(&scalar.to_string()),
    }
}

fn write_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' | '>' | '&' | '`' => push_unicode_escape(character, output),
            ' '..='~' => output.push(character),
            other => push_unicode_escape(other, output),
        }
    }
    output.push('"');
}

fn push_unicode_escape(character: char, output: &mut String) {
    let mut units = [0_u16; 2];
    for unit in character.encode_utf16(&mut units) {
        output.push_str(&format!("\\u{unit:04x}"));
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::EntityKind;
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[test]
    fn times_are_utc_with_milliseconds() {
        let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 0).unwrap();
        assert_eq!(time_text(time), "2026-11-03T09:10:00.000Z");
        let later = time + chrono::TimeDelta::microseconds(450_999);
        assert_eq!(time_text(later), "2026-11-03T09:10:00.450Z");
    }

    #[test]
    fn tokens_use_the_serde_names() {
        assert_eq!(token(&EntityKind::ServicePrincipal), "service_principal");
        assert_eq!(token(&EntityKind::IpAddress), "ip_address");
    }

    #[test]
    fn clean_shows_control_and_invisible_characters_as_text() {
        assert_eq!(clean("a\u{1b}[31mb", 64), "a{U+001B}[31mb");
        assert_eq!(
            clean("line\r\nnext\ttab", 64),
            "line{U+000D}{U+000A}next{U+0009}tab"
        );
        assert_eq!(
            clean("a\u{202e}b\u{200b}c\u{feff}", 64),
            "a{U+202E}b{U+200B}c{U+FEFF}"
        );
        assert_eq!(clean("tag\u{e0041}", 64), "tag{U+E0041}");
        assert_eq!(clean("plain text é 漢", 64), "plain text é 漢");
    }

    #[test]
    fn clean_limits_the_length_and_marks_the_cut() {
        assert_eq!(clean("abcdef", 3), "abc...[cut]");
        assert_eq!(clean("abc", 3), "abc");
        assert_eq!(clean("", 3), "");
    }

    #[test]
    fn a_code_span_holds_markup_and_cannot_be_closed_by_its_text() {
        assert_eq!(md_code("python-httpx/0.27.0", 64), "`python-httpx/0.27.0`");
        assert_eq!(
            md_code("<script>alert(1)</script>", 64),
            "`<script>alert(1)</script>`"
        );
        assert_eq!(md_code("a`b", 64), "``a`b``");
        assert_eq!(md_code("a```b``c", 64), "````a```b``c````");
        assert_eq!(md_code("`edge`", 64), "`` `edge` ``");
        assert_eq!(md_code(" padded ", 64), "`  padded  `");
        assert_eq!(md_code("", 64), "(empty)");
        // A line break would end the paragraph of the span. It becomes visible text.
        assert_eq!(md_code("a\n\n# title", 64), "`a{U+000A}{U+000A}# title`");
    }

    #[test]
    fn plain_markdown_text_has_a_backslash_before_each_markup_character() {
        assert_eq!(
            md_text(
                "[x](http://a.example) <b> *c* _d_ `e` #f |g| !h ~i~ &amp; {j}",
                128
            ),
            "\\[x\\]\\(http\\://a.example\\) \\<b\\> \\*c\\* \\_d\\_ \\`e\\` \\#f \\|g\\| \\!h \\~i\\~ \\&amp; \\{j\\}"
        );
        assert_eq!(md_text("back\\slash", 64), "back\\\\slash");
        assert_eq!(md_text("two\nlines", 64), "two\\{U+000A\\}lines");
        assert_eq!(
            md_text("AS64500 Example Hosting", 64),
            "AS64500 Example Hosting"
        );
    }

    #[test]
    fn json_text_is_printable_ascii_and_parses_to_the_same_value() {
        let value = json!({
            "b": "<script>alert('x')</script> & `tick`",
            "a": "line\nnext\u{1b}\u{7f} \"quoted\" back\\slash",
            "c": ["é", "漢", "😀", 7, 1.5, true, null],
            "d": {},
            "e": [],
        });
        let compact = json_compact(&value);
        assert_eq!(
            compact,
            "{\"a\":\"line\\nnext\\u001b\\u007f \\\"quoted\\\" back\\\\slash\",\
             \"b\":\"\\u003cscript\\u003ealert('x')\\u003c/script\\u003e \\u0026 \\u0060tick\\u0060\",\
             \"c\":[\"\\u00e9\",\"\\u6f22\",\"\\ud83d\\ude00\",7,1.5,true,null],\
             \"d\":{},\"e\":[]}"
        );
        assert!(compact.bytes().all(|byte| (0x20..0x7f).contains(&byte)));
        assert_eq!(serde_json::from_str::<Value>(&compact).unwrap(), value);

        let pretty = json_pretty(&value);
        assert!(pretty.starts_with("{\n  \"a\": \"line"), "{pretty}");
        assert!(pretty.ends_with("\n}\n"), "{pretty}");
        assert!(
            pretty
                .bytes()
                .all(|byte| byte == b'\n' || (0x20..0x7f).contains(&byte))
        );
        assert_eq!(serde_json::from_str::<Value>(&pretty).unwrap(), value);
    }

    #[test]
    fn json_keys_are_in_byte_order_at_each_level() {
        let mut inner = serde_json::Map::new();
        inner.insert("z".to_owned(), json!(1));
        inner.insert("B".to_owned(), json!(2));
        inner.insert("a".to_owned(), json!(3));
        let mut outer = serde_json::Map::new();
        outer.insert("second".to_owned(), Value::Object(inner));
        outer.insert("first".to_owned(), json!([]));
        assert_eq!(
            json_compact(&Value::Object(outer)),
            "{\"first\":[],\"second\":{\"B\":2,\"a\":3,\"z\":1}}"
        );
    }
}
