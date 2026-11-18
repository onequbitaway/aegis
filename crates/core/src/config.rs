//! Configuration loading.
//!
//! A [`Config`] holds one TOML document. Each top-level key of the document is a section.
//! Each subsystem crate defines the type of its section and reads it with
//! [`Config::section`]. This crate does not know those types.
//!
//! # Environment overrides
//!
//! An environment variable can set one key. The name of the variable is
//! `AEGIS__<SECTION>__<KEY>`. Put `__` between the parts of a key path. The name is not
//! case-sensitive. For example, `AEGIS__TELEMETRY__SERVICE_NAME=aegis-dev` sets
//! `telemetry.service_name`.
//!
//! The value of the variable becomes a TOML value:
//!
//! | Text of the variable | Result |
//! | --- | --- |
//! | `true`, `false` | A Boolean. |
//! | A TOML integer or a finite TOML float, for example `42` or `0.5` | A number. |
//! | A TOML string with quotation marks, for example `"42"` | The string in the quotation marks. |
//! | A TOML array, for example `["ingest", "detection"]` | An array. |
//! | All other text | A string with the same text. |
//!
//! Put quotation marks around digits that must stay a string.
//!
//! # Secrets
//!
//! A configuration value can be a secret. This module keeps the values out of its output:
//!
//! - An error for a document that is not valid TOML gives the line and the column. It does
//!   not show text from the document.
//! - An error for an override names the variable. It does not show the value.
//! - An error for a section that does not match its type names the section, the key path,
//!   and the types. [`Config::section`] gives the rules for text that comes from a
//!   `Deserialize` implementation.
//! - The [`Debug`](std::fmt::Debug) output of a [`Config`] shows only the section names.
//!
//! A key is not a secret. Error messages show keys. Do not use a secret as a key.

mod de;

use std::fmt;
use std::path::Path;

use aegis_contracts::{Error, Result};
use serde::de::DeserializeOwned;
use toml::{Table, Value};

/// The start of the name of each environment variable that overrides a configuration key.
pub const ENV_PREFIX: &str = "AEGIS__";

/// The text between the parts of a key path in the name of an environment variable.
pub const ENV_SEPARATOR: &str = "__";

/// The largest number of path parts in the name of an environment variable.
pub const MAX_OVERRIDE_DEPTH: usize = 16;

/// The text that replaces a configuration value in an error message.
pub const REDACTED: &str = de::REDACTED;

/// The configuration of one AEGIS process.
///
/// # Examples
///
/// ```
/// use aegis_core::Config;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Ingest {
///     batch_size: u32,
/// }
///
/// # fn main() -> aegis_contracts::Result<()> {
/// let overrides = vec![("AEGIS__INGEST__BATCH_SIZE".to_owned(), "500".to_owned())];
/// let config = Config::from_toml_str("[ingest]\nbatch_size = 100\n")?.with_overrides(overrides)?;
/// let ingest: Ingest = config.section("ingest")?;
/// assert_eq!(ingest.batch_size, 500);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, PartialEq)]
pub struct Config {
    root: Table,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("sections", &self.section_names())
            .finish()
    }
}

impl Config {
    /// Parses a TOML document.
    ///
    /// This function does not read environment variables. Use [`Config::with_overrides`] or
    /// [`Config::with_process_env`] to apply them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the line and the column if `text` is not valid TOML.
    pub fn from_toml_str(text: &str) -> Result<Self> {
        parse_document(text, "the configuration text")
    }

    /// Reads and parses a TOML file.
    ///
    /// This function does not read environment variables. Use [`Config::load_with_env`] to
    /// read the file and then apply the environment of the process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the file cannot be read or is not valid TOML. The message
    /// contains the path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| {
            Error::Config(format!(
                "cannot read the configuration file {}: {error}",
                path.display()
            ))
        })?;
        parse_document(&text, &format!("the configuration file {}", path.display()))
    }

    /// Reads a TOML file, then applies the environment variables of the process.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Config::load`] and of [`Config::with_process_env`].
    pub fn load_with_env(path: impl AsRef<Path>) -> Result<Self> {
        Self::load(path)?.with_process_env()
    }

    /// Applies the environment variables of the process as overrides.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the name or the value of an override variable is not
    /// valid Unicode. Returns the errors of [`Config::with_overrides`].
    pub fn with_process_env(self) -> Result<Self> {
        let mut variables = Vec::new();
        for (name, value) in std::env::vars_os() {
            let visible_name = name.to_string_lossy();
            if override_path(&visible_name).is_none() {
                continue;
            }
            let (Some(name), Some(value)) = (name.to_str(), value.to_str()) else {
                return Err(Error::Config(format!(
                    "the environment variable {visible_name} must have a name and a value in Unicode"
                )));
            };
            variables.push((name.to_owned(), value.to_owned()));
        }
        self.with_overrides(variables)
    }

    /// Applies overrides from `variables`. Each item is the name and the value of one
    /// environment variable.
    ///
    /// The function ignores a variable whose name does not start with [`ENV_PREFIX`]. An
    /// override replaces the value from the document. An override also makes the tables in
    /// its key path if they do not exist. The module documentation gives the value rules.
    ///
    /// The result does not change with the sequence of the variables.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the name of the variable in these conditions:
    ///
    /// - The name has fewer than two path parts, more than [`MAX_OVERRIDE_DEPTH`] path
    ///   parts, or an empty path part.
    /// - A path part matches two or more keys that are different only in case.
    /// - Two variables set the same key, or one sets a key below the key of the other.
    /// - A part of the key path, but not the last part, is a value that is not a table.
    ///
    /// The message does not contain the value of a variable.
    pub fn with_overrides<I>(mut self, variables: I) -> Result<Self>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut variables: Vec<(String, String)> = variables
            .into_iter()
            .filter(|(name, _)| override_path(name).is_some())
            .collect();
        variables.sort_unstable();

        // All key paths are found in the document before a value changes. Thus a conflict
        // between two variables gives the same error for each sequence of the variables.
        let mut overrides = Vec::with_capacity(variables.len());
        for (name, raw_value) in variables {
            overrides.push(Override::find(&self.root, name, &raw_value)?);
        }
        if let Some((first, second)) = find_conflict(&overrides) {
            let shorter = if first.depth() <= second.depth() {
                first
            } else {
                second
            };
            return Err(Error::Config(format!(
                "the environment variables {} and {} set the same key or a key below it: `{}`",
                first.name,
                second.name,
                shorter.key_path().collect::<Vec<_>>().join(".")
            )));
        }
        for item in overrides {
            item.apply(&mut self.root)?;
        }
        Ok(self)
    }

    /// Returns `true` if the document has a top-level key with this name.
    #[must_use]
    pub fn has_section(&self, name: &str) -> bool {
        self.root.contains_key(name)
    }

    /// Returns the names of all sections, in alphabetical order.
    #[must_use]
    pub fn section_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.root.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Deserializes one section into the type of the caller.
    ///
    /// A TOML date-time value deserializes as its RFC 3339 text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the section name if the section is missing.
    ///
    /// Returns [`Error::Config`] with the section name, the key path, and the cause if the
    /// section does not match `T`. The text that this crate writes names only types and
    /// keys. It does not contain a value of the section.
    ///
    /// A `Deserialize` implementation can put a value in the message that it writes, or in
    /// the description of the value that it accepts. In that text, [`REDACTED`] replaces:
    ///
    /// - Each string, date-time, and number of the section that has four or more
    ///   characters.
    /// - In a message: each shorter string of the section that is a full word.
    /// - In a message: each word of four or more characters that is a part of a value of
    ///   the section. The comparison ignores case.
    ///
    /// A fixed text replaces such text if it is longer than 1024 bytes.
    ///
    /// These rules cannot find a value that the implementation changed, for example an
    /// encoded form. If you write a `Deserialize` implementation, do not put the value in
    /// its error.
    pub fn section<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self
            .root
            .get(name)
            .ok_or_else(|| Error::Config(format!("the section `{name}` is missing")))?;
        de::from_value(value)
            .map_err(|cause| Error::Config(format!("the section `{name}` is not valid: {cause}")))
    }

    /// Deserializes one section, or returns the default value if the section is missing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the section is present but does not match `T`. Refer to
    /// [`Config::section`].
    pub fn section_or_default<T: Default + DeserializeOwned>(&self, name: &str) -> Result<T> {
        if self.has_section(name) {
            self.section(name)
        } else {
            Ok(T::default())
        }
    }
}

/// Parses a document. `origin` names the source of the text in an error message.
fn parse_document(text: &str, origin: &str) -> Result<Config> {
    let error = match text.parse::<Table>() {
        Ok(root) => return Ok(Config { root }),
        Err(error) => error,
    };
    // Only the syntax step of the parser makes messages that are known to contain no value.
    // The parser runs again to find which step failed.
    let (cause, span) = match toml::de::DeTable::parse(text) {
        Err(syntax_error) => (syntax_error.message().to_owned(), syntax_error.span()),
        Ok(_) => (
            "a value is not valid or is out of range".to_owned(),
            error.span(),
        ),
    };
    let message = match span {
        Some(span) => {
            let (line, column) = line_and_column(text, span.start);
            format!("{origin} is not valid TOML at line {line}, column {column}: {cause}")
        }
        None => format!("{origin} is not valid TOML: {cause}"),
    };
    Err(Error::Config(message))
}

/// Converts a byte offset in `text` to a line number and a column number. Both start at 1.
fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let before = bytes.get(..offset).unwrap_or(bytes);
    let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
    let line_start = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let column = before
        .get(line_start..)
        .map_or(0, |tail| String::from_utf8_lossy(tail).chars().count())
        + 1;
    (line, column)
}

/// Returns the key path part of the name of an override variable.
///
/// Returns `None` if the name does not start with [`ENV_PREFIX`].
fn override_path(name: &str) -> Option<&str> {
    let (prefix, path) = name.split_at_checked(ENV_PREFIX.len())?;
    prefix.eq_ignore_ascii_case(ENV_PREFIX).then_some(path)
}

/// One override: the variable, the key that it sets, and the new value.
struct Override {
    /// The name of the environment variable.
    name: String,
    /// The keys of the tables that hold the key, from the section down.
    tables: Vec<String>,
    /// The key that the override sets.
    key: String,
    /// The new value.
    value: Value,
}

impl Override {
    /// Finds the key in `root` that the variable `name` refers to.
    ///
    /// The function does not change `root`. Where the document has no table for a path
    /// part, the remaining keys are the lower-case forms of their path parts.
    fn find(root: &Table, name: String, raw_value: &str) -> Result<Self> {
        let invalid_name = |cause: &str| {
            Error::Config(format!(
                "the environment variable {name} is not a valid override: {cause}"
            ))
        };
        let parts: Vec<&str> = override_path(&name)
            .ok_or_else(|| invalid_name("the name must start with AEGIS__"))?
            .split(ENV_SEPARATOR)
            .collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(invalid_name(
                "use the form AEGIS__<SECTION>__<KEY> with no empty part",
            ));
        }
        if parts.len() > MAX_OVERRIDE_DEPTH {
            return Err(invalid_name("the key path has too many parts"));
        }
        let Some((last, parents)) = parts
            .split_last()
            .filter(|(_, parents)| !parents.is_empty())
        else {
            return Err(invalid_name(
                "use the form AEGIS__<SECTION>__<KEY> with a section and a key",
            ));
        };

        let mut table = Some(root);
        let mut tables = Vec::with_capacity(parents.len());
        for part in parents {
            let key = find_key(table, part, &name)?;
            table = match table.and_then(|table| table.get(&key)) {
                Some(Value::Table(child)) => Some(child),
                _ => None,
            };
            tables.push(key);
        }
        let key = find_key(table, last, &name)?;
        Ok(Self {
            name,
            tables,
            key,
            value: override_value(raw_value),
        })
    }

    /// Returns the number of keys in the key path.
    fn depth(&self) -> usize {
        self.tables.len() + 1
    }

    /// Returns the keys of the key path, from the section down.
    fn key_path(&self) -> impl Iterator<Item = &str> {
        self.tables
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(self.key.as_str()))
    }

    /// Returns `true` if the two overrides set the same key, or if one sets a key below the
    /// key of the other.
    fn conflicts_with(&self, other: &Self) -> bool {
        self.key_path()
            .zip(other.key_path())
            .all(|(own, their)| own == their)
    }

    /// Sets the key in `root`. Makes the tables in the key path that do not exist.
    fn apply(self, root: &mut Table) -> Result<()> {
        let mut table = root;
        for (index, key) in self.tables.iter().enumerate() {
            let child = table
                .entry(key.clone())
                .or_insert_with(|| Value::Table(Table::new()));
            table = match child {
                Value::Table(child) => child,
                _ => {
                    let parent: Vec<&str> = self.key_path().take(index + 1).collect();
                    return Err(Error::Config(format!(
                        "the environment variable {} cannot set a key below `{}`, because that key is not a table",
                        self.name,
                        parent.join(".")
                    )));
                }
            };
        }
        table.insert(self.key, self.value);
        Ok(())
    }
}

/// Returns the first two overrides that are in conflict, in the sequence of `overrides`.
fn find_conflict(overrides: &[Override]) -> Option<(&Override, &Override)> {
    overrides.iter().enumerate().find_map(|(index, first)| {
        overrides
            .iter()
            .skip(index + 1)
            .find(|second| first.conflicts_with(second))
            .map(|second| (first, second))
    })
}

/// Finds the key that the path part `part` refers to. With no table, the key is the
/// lower-case form of `part`.
fn find_key(table: Option<&Table>, part: &str, variable: &str) -> Result<String> {
    match table {
        Some(table) => resolve_key(table, part, variable),
        None => Ok(part.to_lowercase()),
    }
}

/// Finds the key in `table` that the path part `part` refers to.
///
/// The comparison ignores case. An exact match wins, then the lower-case form of `part`. If
/// no key matches, the result is the lower-case form of `part`.
fn resolve_key(table: &Table, part: &str, variable: &str) -> Result<String> {
    if table.contains_key(part) {
        return Ok(part.to_owned());
    }
    let lower = part.to_lowercase();
    if table.contains_key(&lower) {
        return Ok(lower);
    }
    let mut matches = table.keys().filter(|key| key.to_lowercase() == lower);
    match (matches.next(), matches.next()) {
        (None, _) => Ok(lower),
        (Some(key), None) => Ok(key.clone()),
        (Some(_), Some(_)) => Err(Error::Config(format!(
            "the environment variable {variable} is ambiguous: two or more keys match `{lower}` when case is ignored"
        ))),
    }
}

/// Converts the text of an override variable to a TOML value.
fn override_value(raw: &str) -> Value {
    match raw.parse::<Value>() {
        Ok(
            value @ (Value::Boolean(_) | Value::Integer(_) | Value::String(_) | Value::Array(_)),
        ) => value,
        Ok(Value::Float(number)) if number.is_finite() => Value::Float(number),
        _ => Value::String(raw.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_and_column_count_from_one() {
        assert_eq!(line_and_column("a = 1\nb = 2\n", 0), (1, 1));
        assert_eq!(line_and_column("a = 1\nb = 2\n", 6), (2, 1));
        assert_eq!(line_and_column("a = 1\nb = 2\n", 10), (2, 5));
    }

    #[test]
    fn line_and_column_count_characters_not_bytes() {
        assert_eq!(line_and_column("é = 1", 3), (1, 3));
    }

    #[test]
    fn line_and_column_accept_an_offset_after_the_end() {
        assert_eq!(line_and_column("a\nbc", 99), (2, 3));
    }

    #[test]
    fn override_path_ignores_the_case_of_the_prefix() {
        assert_eq!(override_path("AEGIS__A__B"), Some("A__B"));
        assert_eq!(override_path("aegis__a__b"), Some("a__b"));
        assert_eq!(override_path("AEGIS_A__B"), None);
        assert_eq!(override_path("PATH"), None);
        assert_eq!(override_path("AEGIS_é_"), None);
    }

    #[test]
    fn override_value_follows_the_value_rules() {
        assert_eq!(override_value("true"), Value::Boolean(true));
        assert_eq!(override_value("42"), Value::Integer(42));
        assert_eq!(override_value("-7"), Value::Integer(-7));
        assert_eq!(override_value("0.5"), Value::Float(0.5));
        assert_eq!(override_value("\"42\""), Value::String("42".to_owned()));
        assert_eq!(override_value("'true'"), Value::String("true".to_owned()));
        assert_eq!(
            override_value("[\"a\", \"b\"]"),
            Value::Array(vec![
                Value::String("a".to_owned()),
                Value::String("b".to_owned())
            ])
        );
    }

    #[test]
    fn override_value_keeps_other_text_as_a_string() {
        for text in [
            "aegis-dev",
            "",
            " 42 ",
            "nan",
            "inf",
            "-inf",
            "2026-01-02",
            "2026-01-02T03:04:05Z",
            "{ a = 1 }",
            "http://localhost:4318",
            "[::1]",
            "True",
        ] {
            assert_eq!(
                override_value(text),
                Value::String(text.to_owned()),
                "{text:?}"
            );
        }
    }
}
