//! Value tests: one rule value, with its modifiers, against one event value.

use std::net::IpAddr;

use ipnet::IpNet;
use regex::Regex;
use serde_json::Value;

use super::field::Leaf;
use crate::common::canonical_ip;

/// A number from a rule or an event. Integers compare exactly.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Number {
    Integer(i128),
    Float(f64),
}

impl Number {
    fn from_json(number: &serde_json::Number) -> Option<Self> {
        if let Some(integer) = number.as_i64() {
            Some(Self::Integer(integer.into()))
        } else if let Some(integer) = number.as_u64() {
            Some(Self::Integer(integer.into()))
        } else {
            number.as_f64().map(Self::Float)
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Ok(integer) = text.parse::<i128>() {
            return Some(Self::Integer(integer));
        }
        // Only digits can start a number, so that names such as "inf" and "nan" stay text.
        let first = text.trim_start_matches(['+', '-']).bytes().next()?;
        if !(first.is_ascii_digit() || first == b'.') {
            return None;
        }
        text.parse::<f64>()
            .ok()
            .filter(|float| float.is_finite())
            .map(Self::Float)
    }

    /// Returns the value as a float. An integer above 2^53 loses precision, which only a
    /// comparison with a fraction can see.
    fn as_f64(self) -> f64 {
        match self {
            Self::Integer(integer) => integer as f64,
            Self::Float(float) => float,
        }
    }

    fn equals(self, other: Self) -> bool {
        match (self, other) {
            (Self::Integer(left), Self::Integer(right)) => left == right,
            (left, right) => left.as_f64() == right.as_f64(),
        }
    }

    fn of_leaf(leaf: Leaf<'_>) -> Option<Self> {
        match leaf {
            Leaf::Number(number) => Self::from_json(number),
            Leaf::Text(text) => Self::parse(text),
            _ => None,
        }
    }
}

/// A numeric comparison from the `gt`, `gte`, `lt`, and `lte` modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comparison {
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

/// How a rule value compares with the text of an event value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextMode {
    /// The full text must match.
    Equals,
    /// The `contains` modifier.
    Contains,
    /// The `startswith` modifier.
    StartsWith,
    /// The `endswith` modifier.
    EndsWith,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// Text with no wildcard, in lower case. The comparison ignores case.
    Exact(String),
    /// Text with wildcards or a text modifier, as a regular expression that ignores case.
    Glob(Regex),
}

/// A string from a rule, with the Sigma wildcards `*` and `?`.
#[derive(Debug, Clone)]
pub(crate) struct TextMatcher {
    pattern: Pattern,
    /// The number that the rule text is. An event number then compares as a number.
    number: Option<Number>,
    /// The address that the rule text is. An event address then compares as an address.
    address: Option<IpAddr>,
}

fn lower(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

fn equals_ignore_case(text: &str, lower_expected: &str) -> bool {
    if text.is_ascii() && lower_expected.is_ascii() {
        text.eq_ignore_ascii_case(lower_expected)
    } else {
        text.chars()
            .flat_map(char::to_lowercase)
            .eq(lower_expected.chars())
    }
}

impl TextMatcher {
    /// Compiles a rule string.
    ///
    /// `*` matches zero or more characters and `?` matches one character. `\*` and `\?` are
    /// the literal characters, and `\\` is one backslash.
    pub(crate) fn new(text: &str, mode: TextMode) -> Result<Self, String> {
        let mut literal = String::with_capacity(text.len());
        let mut expression = String::with_capacity(text.len() + 8);
        let mut has_wildcard = false;
        let mut pending = String::new();
        let flush = |pending: &mut String, expression: &mut String| {
            expression.push_str(&regex::escape(pending));
            pending.clear();
        };
        let mut characters = text.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\\' => match characters.peek() {
                    Some(&next) if matches!(next, '*' | '?' | '\\') => {
                        characters.next();
                        literal.push(next);
                        pending.push(next);
                    }
                    _ => {
                        literal.push('\\');
                        pending.push('\\');
                    }
                },
                '*' => {
                    has_wildcard = true;
                    flush(&mut pending, &mut expression);
                    expression.push_str(".*");
                }
                '?' => {
                    has_wildcard = true;
                    flush(&mut pending, &mut expression);
                    expression.push('.');
                }
                other => {
                    literal.push(other);
                    pending.push(other);
                }
            }
        }
        flush(&mut pending, &mut expression);

        if mode == TextMode::Equals && !has_wildcard {
            return Ok(Self {
                number: Number::parse(&literal),
                address: literal.parse::<IpAddr>().ok().map(canonical_ip),
                pattern: Pattern::Exact(lower(&literal)),
            });
        }
        let start = matches!(mode, TextMode::Equals | TextMode::StartsWith);
        let end = matches!(mode, TextMode::Equals | TextMode::EndsWith);
        let full = format!(
            "(?is){}{expression}{}",
            if start { "^" } else { "" },
            if end { "$" } else { "" }
        );
        let glob = Regex::new(&full)
            .map_err(|error| format!("the value {text:?} is not a valid pattern: {error}"))?;
        Ok(Self {
            pattern: Pattern::Glob(glob),
            number: None,
            address: None,
        })
    }

    fn matches_text(&self, text: &str) -> bool {
        match &self.pattern {
            Pattern::Exact(expected) => equals_ignore_case(text, expected),
            Pattern::Glob(glob) => glob.is_match(text),
        }
    }

    fn matches(&self, leaf: Leaf<'_>) -> bool {
        match leaf {
            Leaf::Text(text) => self.matches_text(text),
            Leaf::Bool(flag) => self.matches_text(if flag { "true" } else { "false" }),
            Leaf::Number(number) => match (self.number, Number::from_json(number)) {
                (Some(expected), Some(found)) => expected.equals(found),
                _ => self.matches_text(&number.to_string()),
            },
            Leaf::Ip(ip) => match self.address {
                Some(expected) => expected == canonical_ip(ip),
                None => self.matches_text(&canonical_ip(ip).to_string()),
            },
            Leaf::Null | Leaf::Structure => false,
        }
    }
}

/// One compiled rule value.
#[derive(Debug, Clone)]
pub(crate) enum Matcher {
    /// The field is absent, or all its values are `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string, with wildcards.
    Text(TextMatcher),
    /// The `re` modifier. The expression can match at any position.
    Regex(Regex),
    /// The `cidr` modifier.
    Cidr(IpNet),
    /// The `gt`, `gte`, `lt`, and `lte` modifiers.
    Compare(Comparison, f64),
}

/// The modifier that selects the type of the test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueMode {
    /// No modifier, or a text modifier.
    Text(TextMode),
    /// The `re` modifier.
    Regex,
    /// The `cidr` modifier.
    Cidr,
    /// A numeric comparison.
    Compare(Comparison),
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

impl Matcher {
    /// Compiles one rule value for the given modifier.
    pub(crate) fn new(value: &Value, mode: ValueMode) -> Result<Self, String> {
        if matches!(value, Value::Array(_) | Value::Object(_)) {
            return Err("a value must be a string, a number, a boolean, or null".to_owned());
        }
        match mode {
            ValueMode::Text(TextMode::Equals) => Ok(match value {
                Value::Null => Self::Null,
                Value::Bool(flag) => Self::Bool(*flag),
                Value::Number(number) => Self::Number(
                    Number::from_json(number)
                        .ok_or_else(|| format!("the number {number} is not valid"))?,
                ),
                other => Self::Text(TextMatcher::new(
                    other.as_str().unwrap_or_default(),
                    TextMode::Equals,
                )?),
            }),
            ValueMode::Text(text_mode) => {
                let text = scalar_text(value)
                    .ok_or("a text modifier needs a string, not null".to_owned())?;
                if text.is_empty() {
                    return Err("a text modifier needs a value that is not empty".to_owned());
                }
                Ok(Self::Text(TextMatcher::new(&text, text_mode)?))
            }
            ValueMode::Regex => {
                let Value::String(text) = value else {
                    return Err("the re modifier needs a string".to_owned());
                };
                Regex::new(text).map(Self::Regex).map_err(|error| {
                    format!("the regular expression {text:?} is not valid: {error}")
                })
            }
            ValueMode::Cidr => {
                let Value::String(text) = value else {
                    return Err("the cidr modifier needs a string".to_owned());
                };
                let network = text
                    .parse::<IpNet>()
                    .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| format!("{text:?} is not a network in CIDR form"))?;
                Ok(Self::Cidr(network))
            }
            ValueMode::Compare(comparison) => {
                let number = match value {
                    Value::Number(number) => Number::from_json(number),
                    Value::String(text) => Number::parse(text),
                    _ => None,
                }
                .ok_or("a comparison modifier needs a number".to_owned())?;
                Ok(Self::Compare(comparison, number.as_f64()))
            }
        }
    }

    /// Returns `true` if the event value `leaf` passes the test.
    ///
    /// [`Matcher::Null`] never passes here. The caller tests it against the whole field.
    pub(crate) fn matches(&self, leaf: Leaf<'_>) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(expected) => match leaf {
                Leaf::Bool(found) => found == *expected,
                Leaf::Text(text) => {
                    text.eq_ignore_ascii_case(if *expected { "true" } else { "false" })
                }
                _ => false,
            },
            Self::Number(expected) => {
                Number::of_leaf(leaf).is_some_and(|found| expected.equals(found))
            }
            Self::Text(text) => text.matches(leaf),
            Self::Regex(expression) => match leaf {
                Leaf::Text(text) => expression.is_match(text),
                Leaf::Number(number) => expression.is_match(&number.to_string()),
                Leaf::Bool(flag) => expression.is_match(if flag { "true" } else { "false" }),
                Leaf::Ip(ip) => expression.is_match(&canonical_ip(ip).to_string()),
                Leaf::Null | Leaf::Structure => false,
            },
            Self::Cidr(network) => match leaf {
                Leaf::Ip(ip) => network.contains(&canonical_ip(ip)),
                Leaf::Text(text) => text
                    .trim()
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| network.contains(&canonical_ip(ip))),
                _ => false,
            },
            Self::Compare(comparison, expected) => Number::of_leaf(leaf).is_some_and(|found| {
                let found = found.as_f64();
                match comparison {
                    Comparison::Greater => found > *expected,
                    Comparison::GreaterOrEqual => found >= *expected,
                    Comparison::Less => found < *expected,
                    Comparison::LessOrEqual => found <= *expected,
                }
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use serde_json::json;

    use super::*;

    const EQUALS: ValueMode = ValueMode::Text(TextMode::Equals);

    fn matcher(value: Value, mode: ValueMode) -> Matcher {
        Matcher::new(&value, mode).unwrap()
    }

    /// Tests a rule value against a JSON event value.
    fn test(rule: Value, mode: ValueMode, found: Value) -> bool {
        let matcher = matcher(rule, mode);
        match &found {
            Value::Null => matcher.matches(Leaf::Null),
            Value::Bool(flag) => matcher.matches(Leaf::Bool(*flag)),
            Value::Number(number) => matcher.matches(Leaf::Number(number)),
            Value::String(text) => matcher.matches(Leaf::Text(text)),
            _ => matcher.matches(Leaf::Structure),
        }
    }

    fn ip(text: &str) -> Leaf<'static> {
        Leaf::Ip(text.parse().unwrap())
    }

    #[test]
    fn a_plain_string_matches_the_full_text_and_ignores_case() {
        assert!(test(json!("Sign_In"), EQUALS, json!("sign_in")));
        assert!(test(json!("sign_in"), EQUALS, json!("SIGN_IN")));
        assert!(!test(json!("sign_in"), EQUALS, json!("sign_in_extra")));
        assert!(!test(json!("sign_in"), EQUALS, json!("a sign_in")));
        assert!(!test(json!("sign_in"), EQUALS, json!("")));
        assert!(test(json!(""), EQUALS, json!("")));
        assert!(!test(json!(""), EQUALS, json!("x")));
    }

    #[test]
    fn a_plain_string_ignores_case_outside_ascii() {
        assert!(test(json!("MÜNCHEN"), EQUALS, json!("münchen")));
        assert!(test(json!("münchen"), EQUALS, json!("MÜNCHEN")));
        assert!(!test(json!("münchen"), EQUALS, json!("munchen")));
        assert!(test(json!("*ÜNCH*"), EQUALS, json!("münchen")));
    }

    #[test]
    fn the_wildcards_match_many_characters_and_one_character() {
        assert!(test(
            json!("*.ReadWrite.All"),
            EQUALS,
            json!("Directory.ReadWrite.All")
        ));
        assert!(!test(
            json!("*.ReadWrite.All"),
            EQUALS,
            json!("Directory.Read.All")
        ));
        assert!(test(json!("user-00?"), EQUALS, json!("user-007")));
        assert!(!test(json!("user-00?"), EQUALS, json!("user-0071")));
        assert!(!test(json!("user-00?"), EQUALS, json!("user-00")));
        assert!(test(json!("a*c"), EQUALS, json!("ac")));
        assert!(test(json!("a*c"), EQUALS, json!("a\nb\nc")));
        assert!(test(json!("*"), EQUALS, json!("")));
        assert!(!test(json!("?"), EQUALS, json!("")));
    }

    #[test]
    fn an_escaped_wildcard_is_a_literal_character() {
        assert!(test(json!(r"a\*b"), EQUALS, json!("a*b")));
        assert!(!test(json!(r"a\*b"), EQUALS, json!("axxb")));
        assert!(test(json!(r"a\?b"), EQUALS, json!("a?b")));
        assert!(!test(json!(r"a\?b"), EQUALS, json!("axb")));
        assert!(test(json!(r"a\\*"), EQUALS, json!(r"a\anything")));
        assert!(test(json!(r"C:\temp"), EQUALS, json!(r"c:\TEMP")));
        assert!(test(json!("a\\"), EQUALS, json!("a\\")));
    }

    #[test]
    fn characters_that_are_special_in_a_regular_expression_are_literal() {
        assert!(test(json!("a.b(c)*"), EQUALS, json!("a.b(c)xyz")));
        assert!(!test(json!("a.b(c)*"), EQUALS, json!("axb(c)xyz")));
        assert!(test(
            json!("[x]+"),
            ValueMode::Text(TextMode::Contains),
            json!("1[x]+2")
        ));
        assert!(!test(
            json!("[x]+"),
            ValueMode::Text(TextMode::Contains),
            json!("1xx2")
        ));
    }

    #[test]
    fn contains_matches_a_part_of_the_text() {
        let mode = ValueMode::Text(TextMode::Contains);
        assert!(test(json!("httpx"), mode, json!("Python-HTTPX/0.27.0")));
        assert!(test(json!("python"), mode, json!("python-httpx")));
        assert!(test(json!("0.27.0"), mode, json!("python-httpx/0.27.0")));
        assert!(!test(json!("curl"), mode, json!("python-httpx/0.27.0")));
        assert!(test(json!("py*x/"), mode, json!("python-httpx/0.27.0")));
    }

    #[test]
    fn startswith_and_endswith_fix_one_end_of_the_text() {
        let starts = ValueMode::Text(TextMode::StartsWith);
        assert!(test(json!("python-"), starts, json!("Python-httpx/0.27.0")));
        assert!(!test(json!("httpx"), starts, json!("python-httpx/0.27.0")));
        let ends = ValueMode::Text(TextMode::EndsWith);
        assert!(test(json!(".example"), ends, json!("mail.contoso.EXAMPLE")));
        assert!(!test(json!(".example"), ends, json!("example.org")));
    }

    #[test]
    fn a_text_modifier_needs_a_value() {
        let mode = ValueMode::Text(TextMode::Contains);
        let error = Matcher::new(&json!(""), mode).unwrap_err();
        assert!(error.contains("not empty"), "{error}");
        let error = Matcher::new(&Value::Null, mode).unwrap_err();
        assert!(error.contains("not null"), "{error}");
    }

    #[test]
    fn a_string_that_is_a_number_matches_an_event_number_and_the_reverse() {
        assert!(test(json!("50126"), EQUALS, json!(50126)));
        assert!(!test(json!("50126"), EQUALS, json!(50127)));
        assert!(test(json!(50126), EQUALS, json!("50126")));
        assert!(!test(json!(50126), EQUALS, json!("501260")));
        assert!(test(json!(50126), EQUALS, json!(50126)));
        assert!(test(json!(2), EQUALS, json!(2.0)));
        assert!(test(json!("2.50"), EQUALS, json!(2.5)));
        assert!(!test(json!(2), EQUALS, json!(true)));
        assert!(!test(json!(1), EQUALS, json!("one")));
        assert!(test(json!("5*"), EQUALS, json!(50126)));
    }

    #[test]
    fn large_integers_compare_exactly() {
        let large = 9_007_199_254_740_993_u64;
        assert!(test(json!(large), EQUALS, json!(large)));
        assert!(!test(json!(large), EQUALS, json!(large - 1)));
    }

    #[test]
    fn names_of_special_floats_stay_text() {
        assert!(test(json!("nan"), EQUALS, json!("NaN")));
        assert!(test(json!("inf"), EQUALS, json!("INF")));
        assert!(!test(json!("inf"), EQUALS, json!(1e300)));
    }

    #[test]
    fn a_boolean_matches_a_boolean_and_its_text() {
        assert!(test(json!(true), EQUALS, json!(true)));
        assert!(!test(json!(true), EQUALS, json!(false)));
        assert!(test(json!(false), EQUALS, json!("False")));
        assert!(!test(json!(true), EQUALS, json!(1)));
        assert!(test(json!("true"), EQUALS, json!(true)));
        assert!(!test(json!("true"), EQUALS, json!(false)));
    }

    #[test]
    fn no_value_test_matches_a_null_or_a_structure() {
        for rule in [
            json!("null"),
            json!(0),
            json!(false),
            json!("*"),
            Value::Null,
        ] {
            assert!(!test(rule.clone(), EQUALS, Value::Null), "{rule}");
            assert!(!test(rule.clone(), EQUALS, json!({ "a": 1 })), "{rule}");
        }
    }

    #[test]
    fn an_address_compares_as_an_address() {
        let rule = matcher(json!("203.0.113.50"), EQUALS);
        assert!(rule.matches(ip("203.0.113.50")));
        assert!(rule.matches(ip("::ffff:203.0.113.50")));
        assert!(!rule.matches(ip("203.0.113.51")));
        let v6 = matcher(json!("2001:DB8:0:0:0:0:0:1"), EQUALS);
        assert!(v6.matches(ip("2001:db8::1")));
        let glob = matcher(json!("203.0.113.*"), EQUALS);
        assert!(glob.matches(ip("203.0.113.50")));
        assert!(!glob.matches(ip("203.0.114.50")));
    }

    #[test]
    fn re_searches_the_text_and_keeps_the_case() {
        assert!(test(
            json!("^python-[a-z]+/"),
            ValueMode::Regex,
            json!("python-httpx/0.27.0")
        ));
        assert!(!test(
            json!("^python-[a-z]+/"),
            ValueMode::Regex,
            json!("Python-httpx/0.27.0")
        ));
        assert!(test(
            json!("(?i)^python-"),
            ValueMode::Regex,
            json!("Python-httpx")
        ));
        assert!(test(json!("http"), ValueMode::Regex, json!("python-httpx")));
        assert!(test(json!("^5\\d{4}$"), ValueMode::Regex, json!(50126)));
        assert!(!test(json!("."), ValueMode::Regex, Value::Null));
        assert!(matcher(json!(r"^203\.0\.113\."), ValueMode::Regex).matches(ip("203.0.113.9")));
    }

    #[test]
    fn re_rejects_an_expression_that_is_not_valid() {
        let error = Matcher::new(&json!("(unclosed"), ValueMode::Regex).unwrap_err();
        assert!(error.contains("\"(unclosed\""), "{error}");
        let error = Matcher::new(&json!(5), ValueMode::Regex).unwrap_err();
        assert_eq!(error, "the re modifier needs a string");
    }

    #[test]
    fn cidr_matches_addresses_in_the_network() {
        let network = matcher(json!("203.0.113.0/24"), ValueMode::Cidr);
        assert!(network.matches(ip("203.0.113.50")));
        assert!(network.matches(ip("::ffff:203.0.113.50")));
        assert!(!network.matches(ip("203.0.114.1")));
        assert!(!network.matches(ip("2001:db8::1")));
        assert!(network.matches(Leaf::Text("203.0.113.7")));
        assert!(!network.matches(Leaf::Text("not an address")));
        assert!(!network.matches(Leaf::Bool(true)));

        let v6 = matcher(json!("2001:db8::/32"), ValueMode::Cidr);
        assert!(v6.matches(ip("2001:db8:ffff::1")));
        assert!(!v6.matches(ip("2001:db9::1")));

        let single = matcher(json!("192.0.2.77"), ValueMode::Cidr);
        assert!(single.matches(Leaf::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)))));
        assert!(!single.matches(ip("192.0.2.78")));
    }

    #[test]
    fn cidr_rejects_text_that_is_not_a_network() {
        for value in [json!("203.0.113.0/33"), json!("office"), json!("")] {
            let error = Matcher::new(&value, ValueMode::Cidr).unwrap_err();
            assert!(error.contains("CIDR"), "{value}: {error}");
        }
        assert!(Matcher::new(&json!(24), ValueMode::Cidr).is_err());
    }

    #[test]
    fn the_comparisons_use_numbers_and_numeric_text() {
        let greater = ValueMode::Compare(Comparison::Greater);
        assert!(test(json!(5), greater, json!(6)));
        assert!(!test(json!(5), greater, json!(5)));
        assert!(test(json!(5), greater, json!("5.5")));
        assert!(!test(json!(5), greater, json!("many")));
        assert!(!test(json!(5), greater, json!(true)));
        assert!(!test(json!(5), greater, Value::Null));

        let at_least = ValueMode::Compare(Comparison::GreaterOrEqual);
        assert!(test(json!(5), at_least, json!(5)));
        assert!(!test(json!(5), at_least, json!(4.99)));

        let less = ValueMode::Compare(Comparison::Less);
        assert!(test(json!("5"), less, json!(4)));
        assert!(!test(json!("5"), less, json!(5)));

        let at_most = ValueMode::Compare(Comparison::LessOrEqual);
        assert!(test(json!(5), at_most, json!(5)));
        assert!(!test(json!(5), at_most, json!(5.01)));
    }

    #[test]
    fn a_comparison_needs_a_number() {
        let mode = ValueMode::Compare(Comparison::Greater);
        for value in [json!("many"), json!(true), Value::Null, json!("nan")] {
            let error = Matcher::new(&value, mode).unwrap_err();
            assert_eq!(error, "a comparison modifier needs a number", "{value}");
        }
    }

    #[test]
    fn a_list_or_a_map_is_not_a_value() {
        for value in [json!([1]), json!({ "a": 1 })] {
            assert!(Matcher::new(&value, EQUALS).is_err(), "{value}");
        }
    }
}
