//! The error type of the sharing crate.

use thiserror::Error as ThisError;

/// An error from a report builder, an indicator export, or a manifest check.
///
/// No variant holds event text, a masked value, or a secret. Convert the value to
/// [`aegis_contracts::Error`] with `?` at a contract boundary.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum ShareError {
    /// The incident must not go into an abuse report.
    #[error("the incident cannot be reported: {0}")]
    NotReportable(String),
    /// An option has a value that is not valid.
    #[error("option {name}: {reason}")]
    InvalidOption {
        /// The name of the option.
        name: &'static str,
        /// Why the value is not valid.
        reason: String,
    },
    /// An audit record does not have the hash of its contents.
    #[error("audit record {sequence} failed the hash check")]
    AuditIntegrity {
        /// The sequence number of the record.
        sequence: u64,
    },
    /// A claim has no evidence item. The builder stops and gives no report.
    #[error("the claim {claim} has no evidence item")]
    ClaimWithoutEvidence {
        /// The identifier of the claim.
        claim: String,
    },
    /// An evidence item does not agree with the manifest.
    #[error("manifest check failed for {item}: {reason}")]
    Manifest {
        /// The identifier of the item, or the name of the file.
        item: String,
        /// What does not agree.
        reason: String,
    },
    /// Data could not be encoded.
    #[error("cannot encode {what}: {reason}")]
    Encode {
        /// The data that could not be encoded.
        what: &'static str,
        /// The cause, as the encoder gives it.
        reason: String,
    },
}

impl ShareError {
    pub(crate) fn option(name: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidOption {
            name,
            reason: reason.into(),
        }
    }

    pub(crate) fn encode(what: &'static str, error: impl std::fmt::Display) -> Self {
        Self::Encode {
            what,
            reason: error.to_string(),
        }
    }

    pub(crate) fn manifest(item: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Manifest {
            item: item.into(),
            reason: reason.into(),
        }
    }
}

impl From<ShareError> for aegis_contracts::Error {
    fn from(error: ShareError) -> Self {
        let message = error.to_string();
        match error {
            ShareError::NotReportable(_) => Self::InvalidInput(message),
            ShareError::InvalidOption { .. } => Self::Config(message),
            ShareError::AuditIntegrity { .. }
            | ShareError::ClaimWithoutEvidence { .. }
            | ShareError::Manifest { .. } => Self::Integrity(message),
            ShareError::Encode { .. } => Self::Serialization(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_error_names_the_cause() {
        assert_eq!(
            ShareError::NotReportable("the state is false_positive".to_owned()).to_string(),
            "the incident cannot be reported: the state is false_positive"
        );
        assert_eq!(
            ShareError::option("valid_for", "must be more than zero").to_string(),
            "option valid_for: must be more than zero"
        );
        assert_eq!(
            ShareError::AuditIntegrity { sequence: 7 }.to_string(),
            "audit record 7 failed the hash check"
        );
        assert_eq!(
            ShareError::manifest("E0002", "the hash is different").to_string(),
            "manifest check failed for E0002: the hash is different"
        );
    }

    #[test]
    fn errors_convert_to_the_matching_contract_variant() {
        use aegis_contracts::Error;

        let invalid: Error = ShareError::NotReportable("x".to_owned()).into();
        assert!(matches!(invalid, Error::InvalidInput(_)), "{invalid}");
        let config: Error = ShareError::option("tlp", "bad").into();
        assert!(
            matches!(&config, Error::Config(message) if message == "option tlp: bad"),
            "{config}"
        );
        let integrity: Error = ShareError::AuditIntegrity { sequence: 3 }.into();
        assert!(
            matches!(&integrity, Error::Integrity(message) if message == "audit record 3 failed the hash check"),
            "{integrity}"
        );
        let claim: Error = ShareError::ClaimWithoutEvidence {
            claim: "C1".to_owned(),
        }
        .into();
        assert!(matches!(claim, Error::Integrity(_)), "{claim}");
        let manifest: Error = ShareError::manifest("E1", "bad").into();
        assert!(matches!(manifest, Error::Integrity(_)), "{manifest}");
        let encode: Error = ShareError::encode("report", "bad number").into();
        assert!(
            matches!(&encode, Error::Serialization(message) if message == "cannot encode report: bad number"),
            "{encode}"
        );
    }
}
