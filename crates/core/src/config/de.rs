//! A deserializer for TOML values. Its error messages never contain a value.
//!
//! The deserializer of the `toml` crate puts the incorrect value in its error message. A
//! configuration value can be a secret. This module makes the messages again, without the
//! value. A message has two types of text:
//!
//! - Text that this module makes. It names only the type of the incorrect value, the names
//!   of fields and variants of the Rust type, and keys of the section.
//! - Text that a different crate makes. A visitor describes the value that it accepts, and a
//!   `Deserialize` implementation can write a full message. This text can contain a value.
//!   [`scrub`] replaces the values of the section in it with [`REDACTED`].
//!
//! Each message starts with the key path of the incorrect value. A key is not a secret.

use std::fmt::{self, Display, Write as _};

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, Expected, IntoDeserializer, MapAccess,
    SeqAccess, Unexpected, VariantAccess, Visitor,
};
use serde::forward_to_deserialize_any;
use toml::Value;

/// The text that replaces a configuration value in an error message.
pub(crate) const REDACTED: &str = "[redacted]";

/// The smallest number of characters that [`scrub`] always hides.
///
/// A shorter number stays in a message. A short number is not a secret, and it is part of
/// many type names, for example `u16`. A shorter string is hidden only as a full word.
const MIN_HIDDEN_LENGTH: usize = 4;

/// The largest number of bytes of text from a different crate that a message shows.
///
/// Longer text usually repeats a long value. A fixed text replaces it.
const MAX_FOREIGN_LENGTH: usize = 1024;

/// The text that replaces the description from a visitor that cannot be shown.
const HIDDEN_EXPECTATION: &str = "a different value";

/// The text that replaces a message from a `Deserialize` implementation that cannot be shown.
const HIDDEN_MESSAGE: &str = "the value is not valid";

/// Deserializes `value`. The error is a message that contains no value of `value`.
pub(crate) fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    let root = Path::Root;
    T::deserialize(ValueDeserializer { value, path: &root }).map_err(|error| error.render(value))
}

/// The position of a value in the section.
#[derive(Clone, Copy)]
enum Path<'p> {
    Root,
    Key { parent: &'p Path<'p>, key: &'p str },
    Index { parent: &'p Path<'p>, index: usize },
}

impl Display for Path<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => Ok(()),
            Self::Key { parent, key } => {
                parent.fmt(formatter)?;
                if !matches!(parent, Self::Root) {
                    formatter.write_char('.')?;
                }
                if is_bare_key(key) {
                    formatter.write_str(key)
                } else {
                    write!(formatter, "{key:?}")
                }
            }
            Self::Index { parent, index } => {
                parent.fmt(formatter)?;
                write!(formatter, "[{index}]")
            }
        }
    }
}

/// Returns `true` if TOML permits `key` without quotation marks.
fn is_bare_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Text that a different crate made. It can contain a value.
enum Foreign {
    /// The description that a visitor gives of the value that it accepts.
    Expectation(String),
    /// A message that a `Deserialize` implementation wrote.
    Message(String),
}

/// A deserialization error.
///
/// Only [`DeError::render`] makes text that can leave this module. The [`Display`] and
/// [`Debug`](fmt::Debug) forms do not show the text from a different crate.
struct DeError {
    /// The key path of the incorrect value.
    path: Option<String>,
    /// Text that this module made. It contains no value.
    text: String,
    /// Text that follows `text`.
    foreign: Option<Foreign>,
}

impl DeError {
    fn clean(text: impl Into<String>) -> Self {
        Self {
            path: None,
            text: text.into(),
            foreign: None,
        }
    }

    fn wrong_type(found: &str, expected: &str) -> Self {
        Self::clean(format!("invalid type: {found}, expected {expected}"))
    }

    /// Makes an error from `text` and the description that a visitor gives.
    fn with_expectation(text: String, expected: &dyn Expected) -> Self {
        Self {
            path: None,
            text,
            foreign: Some(Foreign::Expectation(expected.to_string())),
        }
    }

    /// Records the position of the error. The first, most specific position stays.
    fn at(mut self, path: &Path<'_>) -> Self {
        if self.path.is_none() {
            self.path = Some(path.to_string());
        }
        self
    }

    /// Makes the message for the caller. `section` supplies the values to hide.
    fn render(self, section: &Value) -> String {
        let mut message = self.text;
        match &self.foreign {
            None => {}
            Some(Foreign::Expectation(text)) => message.push_str(
                scrub(text, section, Hide::Values)
                    .as_deref()
                    .unwrap_or(HIDDEN_EXPECTATION),
            ),
            Some(Foreign::Message(text)) => message.push_str(
                scrub(text, section, Hide::ValuesAndParts)
                    .as_deref()
                    .unwrap_or(HIDDEN_MESSAGE),
            ),
        }
        match self.path {
            Some(path) if !path.is_empty() => format!("key `{path}`: {message}"),
            _ => message,
        }
    }
}

impl Display for DeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)?;
        match self.foreign {
            None => Ok(()),
            Some(Foreign::Expectation(_)) => formatter.write_str(HIDDEN_EXPECTATION),
            Some(Foreign::Message(_)) => formatter.write_str(HIDDEN_MESSAGE),
        }
    }
}

impl fmt::Debug for DeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeError")
            .field("path", &self.path)
            .field("message", &self.to_string())
            .finish()
    }
}

impl std::error::Error for DeError {}

impl de::Error for DeError {
    fn custom<T: Display>(message: T) -> Self {
        Self {
            path: None,
            text: String::new(),
            foreign: Some(Foreign::Message(message.to_string())),
        }
    }

    fn invalid_type(unexpected: Unexpected<'_>, expected: &dyn Expected) -> Self {
        Self::with_expectation(
            format!("invalid type: {}, expected ", unexpected_name(&unexpected)),
            expected,
        )
    }

    fn invalid_value(unexpected: Unexpected<'_>, expected: &dyn Expected) -> Self {
        Self::with_expectation(
            format!("invalid value: {}, expected ", unexpected_name(&unexpected)),
            expected,
        )
    }

    fn invalid_length(length: usize, expected: &dyn Expected) -> Self {
        Self::with_expectation(format!("invalid length {length}, expected "), expected)
    }

    fn unknown_variant(_variant: &str, expected: &'static [&'static str]) -> Self {
        Self::clean(format!("unknown variant, expected {}", OneOf(expected)))
    }

    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Self {
        Self::clean(format!(
            "unknown field `{field}`, expected {}",
            OneOf(expected)
        ))
    }

    fn missing_field(field: &'static str) -> Self {
        Self::clean(format!("missing field `{field}`"))
    }

    fn duplicate_field(field: &'static str) -> Self {
        Self::clean(format!("duplicate field `{field}`"))
    }
}

/// Shows a list of permitted names.
struct OneOf(&'static [&'static str]);

impl Display for OneOf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            [] => formatter.write_str("no name"),
            [only] => write!(formatter, "`{only}`"),
            names => {
                formatter.write_str("one of ")?;
                for (index, name) in names.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "`{name}`")?;
                }
                Ok(())
            }
        }
    }
}

/// Returns the name of the type of an unexpected value. The name does not show the value.
fn unexpected_name(unexpected: &Unexpected<'_>) -> &'static str {
    match unexpected {
        Unexpected::Bool(_) => "boolean",
        Unexpected::Unsigned(_) | Unexpected::Signed(_) => "integer",
        Unexpected::Float(_) => "float",
        Unexpected::Char(_) => "character",
        Unexpected::Str(_) => "string",
        Unexpected::Bytes(_) => "byte array",
        Unexpected::Unit => "unit value",
        Unexpected::Option => "optional value",
        Unexpected::NewtypeStruct => "newtype struct",
        Unexpected::Seq => "array",
        Unexpected::Map => "table",
        Unexpected::Enum => "enum",
        Unexpected::UnitVariant => "unit variant",
        Unexpected::NewtypeVariant => "newtype variant",
        Unexpected::TupleVariant => "tuple variant",
        Unexpected::StructVariant => "struct variant",
        _ => "value",
    }
}

/// Returns the name of the TOML type of `value`.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Boolean(_) => "boolean",
        Value::Datetime(_) => "date-time",
        Value::Array(_) => "array",
        Value::Table(_) => "table",
    }
}

/// How much of the values [`scrub`] hides.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hide {
    /// Each value of [`MIN_HIDDEN_LENGTH`] characters or more.
    Values,
    /// Each value, and each word that is a part of a value.
    ValuesAndParts,
}

/// Replaces the values of `section` that occur in `text` with [`REDACTED`].
///
/// `text` comes from a different crate. These rules apply:
///
/// - Each occurrence of a string, a date-time, or a number of the section is hidden, if the
///   value has [`MIN_HIDDEN_LENGTH`] characters or more. A string is also hidden in the
///   forms that `{:?}` formatting gives.
/// - With [`Hide::ValuesAndParts`], a shorter string is hidden where it is a full word.
/// - With [`Hide::ValuesAndParts`], a word of [`MIN_HIDDEN_LENGTH`] characters or more is
///   hidden if it is a part of a value. The comparison ignores case. A parser frequently
///   shows only the part of the value that it could not read.
/// - Punctuation between two hidden parts is also hidden.
///
/// Returns `None` if `text` is longer than [`MAX_FOREIGN_LENGTH`]. The caller must then
/// show a fixed text.
fn scrub(text: &str, section: &Value, hide: Hide) -> Option<String> {
    if text.len() > MAX_FOREIGN_LENGTH {
        return None;
    }
    let mut values = Vec::new();
    collect_values(section, &mut values);

    let mut hidden = Vec::new();
    for value in &values {
        mark_value(text, value, hide, &mut hidden);
    }
    if hide == Hide::ValuesAndParts {
        mark_parts(text, &values, &mut hidden);
    }
    replace(text, hidden)
}

/// Adds the text forms of each value below `value` to `values`. No form is empty.
fn collect_values(value: &Value, values: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let forms = [
                text.clone(),
                text.escape_debug().to_string(),
                text.escape_default().to_string(),
            ];
            for form in forms {
                if !form.is_empty() && !values.contains(&form) {
                    values.push(form);
                }
            }
        }
        Value::Integer(number) => collect_number(number.to_string(), values),
        Value::Float(number) => collect_number(number.to_string(), values),
        Value::Datetime(datetime) => values.push(datetime.to_string()),
        Value::Boolean(_) => {}
        Value::Array(items) => {
            for item in items {
                collect_values(item, values);
            }
        }
        Value::Table(table) => {
            for item in table.values() {
                collect_values(item, values);
            }
        }
    }
}

fn collect_number(text: String, values: &mut Vec<String>) {
    if is_long(&text) {
        values.push(text);
    }
}

/// Returns `true` if `text` has [`MIN_HIDDEN_LENGTH`] characters or more.
fn is_long(text: &str) -> bool {
    text.chars().nth(MIN_HIDDEN_LENGTH - 1).is_some()
}

/// Adds the byte range of each occurrence of `value` in `text` to `hidden`.
fn mark_value(text: &str, value: &str, hide: Hide, hidden: &mut Vec<(usize, usize)>) {
    let long = is_long(value);
    for (start, found) in text.match_indices(value) {
        let end = start + found.len();
        if long || (hide == Hide::ValuesAndParts && is_full_word(text, start, end)) {
            hidden.push((start, end));
        }
    }
}

/// Returns `true` if no letter and no digit touches the byte range `start..end` of `text`.
fn is_full_word(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).and_then(|head| head.chars().next_back());
    let after = text.get(end..).and_then(|tail| tail.chars().next());
    !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
}

/// Adds the byte range of each word of `text` that is a part of a value to `hidden`.
///
/// A word is a sequence of letters and digits with no other character in it.
fn mark_parts(text: &str, values: &[String], hidden: &mut Vec<(usize, usize)>) {
    let values: Vec<String> = values.iter().map(|value| value.to_lowercase()).collect();
    let mut word_start = None;
    let ends = text
        .char_indices()
        .map(|(index, character)| (index, character.is_alphanumeric()))
        .chain(std::iter::once((text.len(), false)));
    for (index, in_word) in ends {
        match (word_start, in_word) {
            (None, true) => word_start = Some(index),
            (Some(start), false) => {
                word_start = None;
                let Some(word) = text.get(start..index) else {
                    continue;
                };
                if !is_long(word) {
                    continue;
                }
                let word = word.to_lowercase();
                if values.iter().any(|value| value.contains(&word)) {
                    hidden.push((start, index));
                }
            }
            _ => {}
        }
    }
}

/// Returns `text` with [`REDACTED`] in the place of each byte range in `hidden`.
///
/// Returns `None` if a range is not on character boundaries.
fn replace(text: &str, mut hidden: Vec<(usize, usize)>) -> Option<String> {
    hidden.sort_unstable();
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(hidden.len());
    for (start, end) in hidden {
        match ranges.last_mut() {
            Some((_, last_end)) if start <= *last_end || is_joint(text.get(*last_end..start)?) => {
                *last_end = (*last_end).max(end);
            }
            _ => ranges.push((start, end)),
        }
    }

    let mut output = String::with_capacity(text.len());
    let mut position = 0;
    for (start, end) in ranges {
        output.push_str(text.get(position..start)?);
        output.push_str(REDACTED);
        position = end;
    }
    output.push_str(text.get(position..)?);
    Some(output)
}

/// Returns `true` if `gap` is only punctuation: it has no letter, no digit, and no white space.
fn is_joint(gap: &str) -> bool {
    !gap.chars()
        .any(|character| character.is_alphanumeric() || character.is_whitespace())
}

/// Reads one TOML value.
struct ValueDeserializer<'v, 'p> {
    value: &'v Value,
    path: &'p Path<'p>,
}

impl<'de> de::Deserializer<'de> for ValueDeserializer<'_, '_> {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        let path = self.path;
        let result = match self.value {
            Value::String(text) => visitor.visit_str(text),
            Value::Integer(number) => visitor.visit_i64(*number),
            Value::Float(number) => visitor.visit_f64(*number),
            Value::Boolean(flag) => visitor.visit_bool(*flag),
            Value::Datetime(datetime) => visitor.visit_string(datetime.to_string()),
            Value::Array(items) => {
                let mut access = ArrayAccess {
                    items: items.iter(),
                    index: 0,
                    path,
                };
                visitor.visit_seq(&mut access).and_then(|output| {
                    if access.items.len() == 0 {
                        Ok(output)
                    } else {
                        Err(DeError::clean(format!(
                            "invalid length {}, expected an array with fewer elements",
                            items.len()
                        )))
                    }
                })
            }
            Value::Table(table) => {
                let mut access = TableAccess {
                    entries: table.iter(),
                    pending: None,
                    path,
                };
                visitor.visit_map(&mut access).and_then(|output| {
                    if access.entries.len() == 0 {
                        Ok(output)
                    } else {
                        Err(DeError::clean(format!(
                            "invalid length {}, expected a table with fewer keys",
                            table.len()
                        )))
                    }
                })
            }
        };
        result.map_err(|error| error.at(path))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        let path = self.path;
        visitor.visit_some(self).map_err(|error| error.at(path))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError> {
        let path = self.path;
        visitor
            .visit_newtype_struct(self)
            .map_err(|error| error.at(path))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        const EXPECTED: &str = "a string or a table with one key";
        let path = self.path;
        let result = match self.value {
            Value::String(variant) => visitor.visit_enum(EnumReader {
                variant,
                content: None,
                path,
            }),
            Value::Table(table) => {
                let mut entries = table.iter();
                match (entries.next(), entries.next()) {
                    (Some((variant, content)), None) => visitor.visit_enum(EnumReader {
                        variant,
                        content: Some(content),
                        path,
                    }),
                    _ => Err(DeError::wrong_type("table", EXPECTED)),
                }
            }
            other => Err(DeError::wrong_type(type_name(other), EXPECTED)),
        };
        result.map_err(|error| error.at(path))
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}

/// Reads the elements of a TOML array.
struct ArrayAccess<'v, 'p> {
    items: std::slice::Iter<'v, Value>,
    index: usize,
    path: &'p Path<'p>,
}

impl<'de> SeqAccess<'de> for ArrayAccess<'_, '_> {
    type Error = DeError;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, DeError> {
        let Some(value) = self.items.next() else {
            return Ok(None);
        };
        let child = Path::Index {
            parent: self.path,
            index: self.index,
        };
        self.index += 1;
        seed.deserialize(ValueDeserializer {
            value,
            path: &child,
        })
        .map(Some)
        .map_err(|error| error.at(&child))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

/// Reads the entries of a TOML table.
struct TableAccess<'v, 'p> {
    entries: toml::map::Iter<'v, String, Value>,
    pending: Option<(&'v str, &'v Value)>,
    path: &'p Path<'p>,
}

impl<'de> MapAccess<'de> for TableAccess<'_, '_> {
    type Error = DeError;

    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, DeError> {
        let Some((key, value)) = self.entries.next() else {
            return Ok(None);
        };
        self.pending = Some((key, value));
        seed.deserialize(KeyDeserializer(key)).map(Some)
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, DeError> {
        let Some((key, value)) = self.pending.take() else {
            return Err(DeError::clean("a table value was read before its key"));
        };
        let child = Path::Key {
            parent: self.path,
            key,
        };
        seed.deserialize(ValueDeserializer {
            value,
            path: &child,
        })
        .map_err(|error| error.at(&child))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

/// Reads one key of a TOML table. A key is text. A number type or `bool` parses the text.
struct KeyDeserializer<'v>(&'v str);

macro_rules! parse_key {
    ($($method:ident => $visit:ident($type:ty);)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
            match self.0.parse::<$type>() {
                Ok(key) => visitor.$visit(key),
                Err(_) => Err(DeError::clean(format!(
                    "invalid key `{}`, expected {}",
                    self.0,
                    stringify!($type)
                ))),
            }
        }
    )*};
}

impl<'de> de::Deserializer<'de> for KeyDeserializer<'_> {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        visitor.visit_str(self.0)
    }

    parse_key! {
        deserialize_bool => visit_bool(bool);
        deserialize_i8 => visit_i8(i8);
        deserialize_i16 => visit_i16(i16);
        deserialize_i32 => visit_i32(i32);
        deserialize_i64 => visit_i64(i64);
        deserialize_i128 => visit_i128(i128);
        deserialize_u8 => visit_u8(u8);
        deserialize_u16 => visit_u16(u16);
        deserialize_u32 => visit_u32(u32);
        deserialize_u64 => visit_u64(u64);
        deserialize_u128 => visit_u128(u128);
        deserialize_f32 => visit_f32(f32);
        deserialize_f64 => visit_f64(f64);
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        let name: de::value::StrDeserializer<'_, DeError> = self.0.into_deserializer();
        visitor.visit_enum(name)
    }

    forward_to_deserialize_any! {
        char str string bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

/// Reads an enum. A string is a unit variant. A table with one key is a variant with data.
struct EnumReader<'v, 'p> {
    variant: &'v str,
    content: Option<&'v Value>,
    path: &'p Path<'p>,
}

impl EnumReader<'_, '_> {
    /// Deserializes the data of the variant with `read`.
    fn content<T>(
        self,
        expected: &str,
        read: impl FnOnce(ValueDeserializer<'_, '_>) -> Result<T, DeError>,
    ) -> Result<T, DeError> {
        let Some(value) = self.content else {
            return Err(DeError::wrong_type("unit variant", expected));
        };
        let child = Path::Key {
            parent: self.path,
            key: self.variant,
        };
        read(ValueDeserializer {
            value,
            path: &child,
        })
        .map_err(|error| error.at(&child))
    }
}

impl<'de> EnumAccess<'de> for EnumReader<'_, '_> {
    type Error = DeError;
    type Variant = Self;

    fn variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<(S::Value, Self), DeError> {
        let name: de::value::StrDeserializer<'_, DeError> = self.variant.into_deserializer();
        let variant = seed.deserialize(name)?;
        Ok((variant, self))
    }
}

impl<'de> VariantAccess<'de> for EnumReader<'_, '_> {
    type Error = DeError;

    fn unit_variant(self) -> Result<(), DeError> {
        match self.content {
            None => Ok(()),
            Some(content) => Err(DeError::wrong_type(type_name(content), "a unit variant")),
        }
    }

    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, DeError> {
        self.content("a newtype variant", |value| seed.deserialize(value))
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _length: usize,
        visitor: V,
    ) -> Result<V::Value, DeError> {
        self.content("a tuple variant", |value| {
            de::Deserializer::deserialize_any(value, visitor)
        })
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        self.content("a struct variant", |value| {
            de::Deserializer::deserialize_any(value, visitor)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::*;

    const SECRET: &str = "hunter2-s3cret";

    fn section(text: &str) -> Value {
        Value::Table(text.parse().unwrap())
    }

    fn read<T: DeserializeOwned>(text: &str) -> Result<T, String> {
        from_value(&section(text))
    }

    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        Fast,
        Slow,
    }

    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Sink {
        Discard,
        File { path: String },
        Port(u16),
        Pair(u8, u8),
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct Limits(u32);

    #[derive(Debug, PartialEq, Deserialize)]
    struct Provider {
        timeout: u64,
        #[serde(default)]
        key: Option<String>,
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct Service {
        name: String,
        port: u16,
        ratio: f64,
        enabled: bool,
        mode: Mode,
        tags: Vec<String>,
        limits: Limits,
        note: Option<String>,
        providers: BTreeMap<String, Provider>,
        sinks: Vec<Sink>,
        pair: (u8, u8),
    }

    const VALID: &str = r#"
        name = "edge"
        port = 8443
        ratio = 2
        enabled = true
        mode = "slow"
        tags = ["a", "b"]
        limits = 7
        pair = [1, 2]
        sinks = ["discard", { file = { path = "/var/log/x" } }, { port = 9 }, { pair = [3, 4] }]

        [providers.local]
        timeout = 30

        [providers.remote]
        timeout = 60
        key = "k"
    "#;

    /// A type whose error message shows the incorrect value, as some libraries do.
    #[derive(Debug)]
    struct Echo;

    impl<'de> Deserialize<'de> for Echo {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let text = String::deserialize(deserializer)?;
            Err(de::Error::custom(format!(
                "cannot use {text} or {text:?} here"
            )))
        }
    }

    #[test]
    fn reads_all_toml_types_into_a_struct() {
        let service: Service = read(VALID).unwrap();
        assert_eq!(
            service,
            Service {
                name: "edge".to_owned(),
                port: 8443,
                ratio: 2.0,
                enabled: true,
                mode: Mode::Slow,
                tags: vec!["a".to_owned(), "b".to_owned()],
                limits: Limits(7),
                note: None,
                providers: BTreeMap::from([
                    (
                        "local".to_owned(),
                        Provider {
                            timeout: 30,
                            key: None
                        }
                    ),
                    (
                        "remote".to_owned(),
                        Provider {
                            timeout: 60,
                            key: Some("k".to_owned())
                        }
                    ),
                ]),
                sinks: vec![
                    Sink::Discard,
                    Sink::File {
                        path: "/var/log/x".to_owned()
                    },
                    Sink::Port(9),
                    Sink::Pair(3, 4),
                ],
                pair: (1, 2),
            }
        );
    }

    #[test]
    fn reads_a_date_time_as_text() {
        #[derive(Deserialize)]
        struct Window {
            start: String,
        }
        let window: Window = read("start = 2026-01-02T03:04:05Z").unwrap();
        assert_eq!(window.start, "2026-01-02T03:04:05Z");
    }

    #[test]
    fn a_wrong_type_names_the_key_and_the_type_but_not_the_value() {
        let text = VALID.replace("port = 8443", &format!("port = \"{SECRET}\""));
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `port`: invalid type: string, expected u16"
        );
    }

    #[test]
    fn a_number_out_of_range_does_not_show_the_number() {
        let text = VALID.replace("port = 8443", "port = 7000012345");
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `port`: invalid value: integer, expected u16"
        );
    }

    #[test]
    fn an_error_in_a_nested_table_has_the_full_key_path() {
        let text = VALID.replace("timeout = 60", &format!("timeout = \"{SECRET}\""));
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `providers.remote.timeout`: invalid type: string, expected u64"
        );
    }

    #[test]
    fn an_error_in_an_array_has_the_index() {
        let text = VALID.replace("tags = [\"a\", \"b\"]", "tags = [\"a\", 5]");
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `tags[1]`: invalid type: integer, expected a string"
        );
    }

    #[test]
    fn a_key_that_needs_quotation_marks_has_them_in_the_path() {
        let error = read::<BTreeMap<String, Provider>>(&format!(
            "[\"api.example\"]\ntimeout = \"{SECRET}\"\n"
        ))
        .unwrap_err();
        assert_eq!(
            error,
            "key `\"api.example\".timeout`: invalid type: string, expected u64"
        );
    }

    #[test]
    fn an_unknown_variant_lists_the_names_but_not_the_value() {
        let text = VALID.replace("mode = \"slow\"", &format!("mode = \"{SECRET}\""));
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `mode`: unknown variant, expected one of `fast`, `slow`"
        );
    }

    #[test]
    fn a_missing_field_and_an_unknown_field_show_the_field_name() {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[expect(dead_code, reason = "the test reads only the error")]
            port: u16,
        }
        assert_eq!(read::<Strict>("").unwrap_err(), "missing field `port`");
        assert_eq!(
            read::<Strict>(&format!("port = 1\nextra = \"{SECRET}\"")).unwrap_err(),
            "unknown field `extra`, expected `port`"
        );
    }

    #[test]
    fn an_array_with_too_many_or_too_few_elements_is_an_error() {
        let long = VALID.replace("pair = [1, 2]", "pair = [1, 2, 3]");
        assert_eq!(
            read::<Service>(&long).unwrap_err(),
            "key `pair`: invalid length 3, expected an array with fewer elements"
        );
        let short = VALID.replace("pair = [1, 2]", "pair = [1]");
        assert_eq!(
            read::<Service>(&short).unwrap_err(),
            "key `pair`: invalid length 1, expected a tuple of size 2"
        );
    }

    #[test]
    fn an_enum_with_the_wrong_form_is_an_error() {
        #[derive(Debug, Deserialize)]
        struct Holder {
            #[expect(dead_code, reason = "the test reads only the error")]
            sink: Sink,
        }
        assert_eq!(
            read::<Holder>("sink = 5").unwrap_err(),
            "key `sink`: invalid type: integer, expected a string or a table with one key"
        );
        assert_eq!(
            read::<Holder>("sink = { port = 1, file = 2 }").unwrap_err(),
            "key `sink`: invalid type: table, expected a string or a table with one key"
        );
        assert_eq!(
            read::<Holder>("sink = \"port\"").unwrap_err(),
            "key `sink`: invalid type: unit variant, expected a newtype variant"
        );
        assert_eq!(
            read::<Holder>("sink = { discard = 1 }").unwrap_err(),
            "key `sink`: invalid type: integer, expected a unit variant"
        );
        assert_eq!(
            read::<Holder>(&format!("sink = {{ port = \"{SECRET}\" }}")).unwrap_err(),
            "key `sink.port`: invalid type: string, expected u16"
        );
    }

    #[test]
    fn a_table_key_can_be_a_number_a_boolean_an_enum_or_a_newtype() {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
        struct Port(u16);

        let ports: BTreeMap<u16, String> = read("8080 = \"web\"").unwrap();
        assert_eq!(ports, BTreeMap::from([(8080, "web".to_owned())]));
        let wrapped: BTreeMap<Port, String> = read("8080 = \"web\"").unwrap();
        assert_eq!(wrapped, BTreeMap::from([(Port(8080), "web".to_owned())]));
        let flags: BTreeMap<bool, u8> = read("true = 1").unwrap();
        assert_eq!(flags, BTreeMap::from([(true, 1)]));
        let modes: BTreeMap<String, Mode> = read("a = \"fast\"").unwrap();
        assert_eq!(modes, BTreeMap::from([("a".to_owned(), Mode::Fast)]));
    }

    #[test]
    fn a_table_key_of_the_wrong_type_names_the_key_and_the_table() {
        assert_eq!(
            read::<BTreeMap<u16, String>>(&format!("web = \"{SECRET}\"")).unwrap_err(),
            "invalid key `web`, expected u16"
        );
        #[derive(Debug, Deserialize)]
        struct Holder {
            #[expect(dead_code, reason = "the test reads only the error")]
            ports: BTreeMap<u16, String>,
        }
        assert_eq!(
            read::<Holder>(&format!("[ports]\n70000 = \"{SECRET}\"")).unwrap_err(),
            "key `ports`: invalid key `70000`, expected u16"
        );
    }

    #[test]
    fn an_enum_can_be_a_table_key() {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Tier {
            Auto,
            Gated,
        }
        let limits: BTreeMap<Tier, u32> = read("auto = 5\ngated = 1").unwrap();
        assert_eq!(limits, BTreeMap::from([(Tier::Auto, 5), (Tier::Gated, 1)]));
        assert_eq!(
            read::<BTreeMap<Tier, u32>>("manual = 5").unwrap_err(),
            "unknown variant, expected one of `auto`, `gated`"
        );
    }

    /// Reads `text` as a section with one key `url` of the type `T` and returns the error.
    fn url_error<T: DeserializeOwned + fmt::Debug>(text: &str) -> String {
        #[derive(Debug, Deserialize)]
        struct Holder<T> {
            #[expect(dead_code, reason = "the test reads only the error")]
            url: T,
        }
        read::<Holder<T>>(text).unwrap_err()
    }

    #[test]
    fn a_message_from_a_type_has_its_values_replaced() {
        assert_eq!(
            url_error::<Echo>(&format!("url = \"{SECRET}\"")),
            "key `url`: cannot use [redacted] or \"[redacted]\" here"
        );
    }

    #[test]
    fn a_value_that_debug_formatting_escapes_is_replaced_in_both_forms() {
        assert_eq!(
            url_error::<Echo>(r#"url = 'pass"word\with\slashes'"#),
            "key `url`: cannot use [redacted] or \"[redacted]\" here"
        );
    }

    #[test]
    fn a_part_of_a_value_in_a_message_from_a_type_is_replaced() {
        /// A type whose error message shows only the last part of the value, as a parser does.
        #[derive(Debug)]
        struct Unit;

        impl<'de> Deserialize<'de> for Unit {
            fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let part = text.rsplit(':').next().unwrap_or_default();
                Err(de::Error::custom(format!(
                    "unknown unit \"{part}\" ({})",
                    part.to_uppercase()
                )))
            }
        }

        assert_eq!(
            url_error::<Unit>(&format!("url = \"aegis:{SECRET}\"")),
            "key `url`: unknown unit \"[redacted]\" ([redacted])"
        );
    }

    #[test]
    fn a_value_in_the_description_from_a_visitor_is_replaced() {
        /// A type that shows the incorrect value in the description of what it accepts.
        #[derive(Debug)]
        struct Level;

        impl<'de> Deserialize<'de> for Level {
            fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Err(de::Error::invalid_value(
                    Unexpected::Str(&text),
                    &format!("a level, not {text}").as_str(),
                ))
            }
        }

        assert_eq!(
            url_error::<Level>(&format!("url = \"{SECRET}\"")),
            "key `url`: invalid value: string, expected a level, not [redacted]"
        );
    }

    #[test]
    fn a_value_does_not_change_the_text_that_this_module_makes() {
        let text = VALID.replace("name = \"edge\"", "name = \"invalid type: string\"");
        let text = text.replace("port = 8443", "port = \"expected\"");
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `port`: invalid type: string, expected u16"
        );
    }

    #[test]
    fn a_value_that_is_the_same_as_a_type_name_hides_that_name_in_the_description() {
        let text = VALID.replace("name = \"edge\"", "name = \"string\"");
        let text = text.replace("tags = [\"a\", \"b\"]", "tags = [\"a\", 5]");
        assert_eq!(
            read::<Service>(&text).unwrap_err(),
            "key `tags[1]`: invalid type: integer, expected a [redacted]"
        );
    }

    #[test]
    fn a_message_that_is_too_long_is_replaced_with_a_fixed_text() {
        /// A type whose error message repeats the value many times.
        #[derive(Debug)]
        struct Verbose;

        impl<'de> Deserialize<'de> for Verbose {
            fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Err(de::Error::custom(text.repeat(MAX_FOREIGN_LENGTH)))
            }
        }

        assert_eq!(
            url_error::<Verbose>("url = \"ab\""),
            "key `url`: the value is not valid"
        );
    }

    fn scrub_all(text: &str, section: &Value) -> String {
        scrub(text, section, Hide::ValuesAndParts).unwrap()
    }

    #[test]
    fn scrub_replaces_values_from_all_keys_of_the_section() {
        let section = section(&format!(
            "token = \"{SECRET}\"\nstart = 2026-01-02\npin = 123456\nratio = 1234.5\nsmall = 16\nflag = true\n[nested]\nlist = [\"inner-value\"]\n"
        ));
        assert_eq!(
            scrub_all(
                &format!("{SECRET} inner-value 2026-01-02 123456 1234.5 u16 true {SECRET}"),
                &section
            ),
            "[redacted] [redacted] [redacted] [redacted] [redacted] u16 true [redacted]"
        );
    }

    #[test]
    fn scrub_joins_values_that_overlap_or_touch() {
        let section = section("a = \"abcd\"\nb = \"cdef\"\nc = \"bc\"\nd = \"wxyz\"\n");
        assert_eq!(scrub_all("x abcdef y", &section), "x [redacted] y");
        assert_eq!(scrub_all("x abcdwxyz y", &section), "x [redacted] y");
    }

    #[test]
    fn scrub_hides_punctuation_between_two_hidden_parts_but_not_other_text() {
        let section = section("a = \"abcd\"\nb = \"wxyz\"\n");
        assert_eq!(scrub_all("<abcd:/-wxyz>", &section), "<[redacted]>");
        assert_eq!(scrub_all("abcd, wxyz", &section), "[redacted], [redacted]");
        assert_eq!(
            scrub_all("abcd=1;wxyz", &section),
            "[redacted]=1;[redacted]"
        );
    }

    #[test]
    fn scrub_hides_a_word_that_is_a_part_of_a_value_and_ignores_case() {
        let section = section("dsn = \"postgres://aegis:Tr0ub4dor@db.internal/events\"\n");
        assert_eq!(
            scrub_all("bad password TR0UB4DOR for host db", &section),
            "bad password [redacted] for host db"
        );
        // A word that is longer than its match in the value is not a part of the value.
        assert_eq!(
            scrub_all("eventsource is not a host", &section),
            "eventsource is not a host"
        );
    }

    #[test]
    fn scrub_hides_a_short_string_only_as_a_full_word() {
        let section = section("unit = \"xyz\"\nseparator = \" \"\npin = 123\n");
        assert_eq!(
            scrub_all("unknown unit 'xyz' in xyzzy, not 123", &section),
            "unknown unit '[redacted]' in xyzzy, not 123"
        );
    }

    #[test]
    fn scrub_of_a_description_hides_only_long_values() {
        let section = section(&format!(
            "token = \"{SECRET}\"\nkind = \"a\"\nhost = \"db\"\n"
        ));
        assert_eq!(
            scrub(
                &format!("a string, not {SECRET} or hunter2"),
                &section,
                Hide::Values
            )
            .unwrap(),
            "a string, not [redacted] or hunter2"
        );
    }

    #[test]
    fn scrub_keeps_text_that_has_no_value() {
        let section = section(&format!("token = \"{SECRET}\"\nempty = \"\"\n"));
        assert_eq!(
            scrub_all("invalid IPv4 address syntax", &section),
            "invalid IPv4 address syntax"
        );
    }

    #[test]
    fn scrub_refuses_text_that_is_too_long() {
        let section = section("a = 1\n");
        let longest = "x".repeat(MAX_FOREIGN_LENGTH);
        assert_eq!(
            scrub(&longest, &section, Hide::ValuesAndParts),
            Some(longest.clone())
        );
        assert_eq!(
            scrub(&format!("{longest}x"), &section, Hide::ValuesAndParts),
            None
        );
    }

    #[test]
    fn the_display_and_debug_forms_of_an_error_hide_text_from_a_different_crate() {
        let message = <DeError as de::Error>::custom(format!("bad value {SECRET}"));
        assert_eq!(message.to_string(), "the value is not valid");
        assert_eq!(
            format!("{message:?}"),
            r#"DeError { path: None, message: "the value is not valid" }"#
        );

        let description = format!("a level, not {SECRET}");
        let expectation =
            <DeError as de::Error>::invalid_type(Unexpected::Str(SECRET), &description.as_str());
        assert_eq!(
            expectation.to_string(),
            "invalid type: string, expected a different value"
        );
    }
}
