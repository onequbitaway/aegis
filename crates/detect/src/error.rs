//! The error type of the detection subsystem.

use std::path::Path;

use thiserror::Error as ThisError;

/// An error from a rule, an indicator file, a rule pack, or a detector configuration.
///
/// Each variant names the file or the setting that is not valid. Convert the value to
/// [`aegis_contracts::Error`] with `?` at a contract boundary.
#[derive(Debug, ThisError)]
pub enum DetectError {
    /// A Sigma rule is not valid.
    #[error("rule {file}: {reason}")]
    Rule {
        /// The file, or the name, of the rule.
        file: String,
        /// Why the rule is not valid.
        reason: String,
    },
    /// An indicator file is not valid.
    #[error("indicator file {file}: {reason}")]
    Indicator {
        /// The file, or the name, of the indicator set.
        file: String,
        /// Why the indicator file is not valid.
        reason: String,
    },
    /// A rule pack is not valid.
    #[error("rule pack {path}: {reason}")]
    Pack {
        /// The directory, or the name, of the pack.
        path: String,
        /// Why the pack is not valid.
        reason: String,
    },
    /// A file or a directory could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: String,
        /// The cause of the failure.
        #[source]
        source: std::io::Error,
    },
    /// A detector setting is not valid.
    #[error("detector configuration: {0}")]
    Config(String),
}

impl DetectError {
    pub(crate) fn rule(file: &str, reason: impl Into<String>) -> Self {
        Self::Rule {
            file: file.to_owned(),
            reason: reason.into(),
        }
    }

    pub(crate) fn indicator(file: &str, reason: impl Into<String>) -> Self {
        Self::Indicator {
            file: file.to_owned(),
            reason: reason.into(),
        }
    }

    pub(crate) fn pack(path: &Path, reason: impl Into<String>) -> Self {
        Self::Pack {
            path: path.display().to_string(),
            reason: reason.into(),
        }
    }

    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

impl From<DetectError> for aegis_contracts::Error {
    fn from(error: DetectError) -> Self {
        match error {
            DetectError::Io { path, source } if source.kind() == std::io::ErrorKind::NotFound => {
                Self::NotFound(path)
            }
            DetectError::Io { path, source } => Self::other(format!("cannot read {path}"), source),
            other => Self::Config(other.to_string()),
        }
    }
}

/// Returns the first line of a YAML parser message, without the `error:` prefix.
///
/// The full message repeats the text of the file. The first line holds the position and
/// the cause, which is sufficient.
pub(crate) fn yaml_reason(error: &serde_saphyr::Error) -> String {
    let message = error.to_string();
    let first = message.lines().next().unwrap_or_default();
    first.strip_prefix("error: ").unwrap_or(first).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_error_names_the_file_and_the_reason() {
        let error = DetectError::rule("rules/a.yml", "the condition is empty");
        assert_eq!(
            error.to_string(),
            "rule rules/a.yml: the condition is empty"
        );
    }

    #[test]
    fn rule_errors_become_configuration_errors_that_are_not_retryable() {
        let error: aegis_contracts::Error = DetectError::rule("a.yml", "bad").into();
        assert!(
            matches!(&error, aegis_contracts::Error::Config(message) if message == "rule a.yml: bad"),
            "{error}"
        );
        assert!(!error.is_retryable());
    }

    #[test]
    fn a_missing_path_becomes_not_found() {
        let source = std::io::Error::from(std::io::ErrorKind::NotFound);
        let error: aegis_contracts::Error =
            DetectError::io(Path::new("/packs/none"), source).into();
        assert!(
            matches!(&error, aegis_contracts::Error::NotFound(path) if path == "/packs/none"),
            "{error}"
        );
    }

    #[test]
    fn other_read_failures_keep_their_cause() {
        let source = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let error: aegis_contracts::Error = DetectError::io(Path::new("/packs/x"), source).into();
        assert!(
            matches!(&error, aegis_contracts::Error::Other { context, .. } if context == "cannot read /packs/x"),
            "{error}"
        );
    }

    #[test]
    fn the_yaml_reason_is_one_line_with_the_position() {
        let error = serde_saphyr::from_str::<serde_json::Value>("a: 1\na: 2\n").unwrap_err();
        let reason = yaml_reason(&error);
        assert_eq!(reason.lines().count(), 1);
        assert!(
            reason.starts_with("line 2 column 1: duplicate mapping key"),
            "{reason}"
        );
    }
}
