//! The error type that all contracts return.

use thiserror::Error as ThisError;

/// A source error that an [`Error::Other`] value can hold.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The error type that all AEGIS contracts return.
#[derive(Debug, ThisError)]
pub enum Error {
    /// The caller sent input that is not valid.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The configuration is missing or not valid.
    #[error("configuration error: {0}")]
    Config(String),
    /// The credentials are missing or not valid, or the caller has no permission.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// Policy denied the operation.
    #[error("denied by policy: {0}")]
    Denied(String),
    /// The implementation does not support the operation.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// An upstream system is not available. A retry can succeed.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// An upstream system limited the request rate. A retry can succeed.
    #[error("rate limited: {0}")]
    RateLimited(String),
    /// The operation did not complete in the permitted time. A retry can succeed.
    #[error("timeout: {0}")]
    Timeout(String),
    /// A model refused the task.
    #[error("model refused the task: {0}")]
    Refused(String),
    /// A budget limit stopped the operation.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
    /// Data could not be encoded or decoded.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Stored data failed an integrity check.
    #[error("integrity error: {0}")]
    Integrity(String),
    /// An error that has no more specific variant.
    #[error("{context}: {source}")]
    Other {
        /// The operation that failed.
        context: String,
        /// The cause of the failure.
        #[source]
        source: BoxError,
    },
}

impl Error {
    /// Wraps a source error with the name of the operation that failed.
    pub fn other(context: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Other {
            context: context.into(),
            source: source.into(),
        }
    }

    /// Returns `true` if a retry of the same operation can succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_) | Self::RateLimited(_) | Self::Timeout(_)
        )
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

/// The result type that all AEGIS contracts return.
pub type Result<T, E = Error> = std::result::Result<T, E>;
