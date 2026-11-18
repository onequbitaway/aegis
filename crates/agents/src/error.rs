//! The error type of the model helpers.

use aegis_contracts::Error;
use thiserror::Error as ThisError;

/// Why a model call gave no usable answer.
///
/// An agent uses this error to select its deterministic path. The error never changes an
/// incident to a false positive.
#[derive(Debug, ThisError)]
pub enum ModelCallError {
    /// The model provider returned an error.
    #[error("the model call failed: {0}")]
    Provider(#[source] Error),
    /// The model answered, but the answer does not obey the expected format.
    #[error("the model output is not valid: {0}")]
    InvalidOutput(String),
    /// The model did not stop its tool calls in the permitted number of steps.
    #[error("the tool loop did not complete in {0} steps")]
    StepLimit(usize),
    /// A tool failed for a reason that the model cannot correct.
    #[error("a tool failed: {0}")]
    Tool(#[source] Error),
}

impl From<ModelCallError> for Error {
    fn from(error: ModelCallError) -> Self {
        match error {
            ModelCallError::Provider(source) | ModelCallError::Tool(source) => source,
            ModelCallError::InvalidOutput(reason) => {
                Self::Serialization(format!("the model output is not valid: {reason}"))
            }
            ModelCallError::StepLimit(steps) => {
                Self::BudgetExceeded(format!("the tool loop did not complete in {steps} steps"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_error_keeps_its_variant_at_the_contract_boundary() {
        let error: Error =
            ModelCallError::Provider(Error::RateLimited("slow down".to_owned())).into();
        assert!(matches!(&error, Error::RateLimited(reason) if reason == "slow down"));
        assert!(error.is_retryable());
    }

    #[test]
    fn output_and_step_errors_map_to_errors_that_are_not_retryable() {
        let invalid: Error = ModelCallError::InvalidOutput("no JSON object".to_owned()).into();
        assert!(
            matches!(&invalid, Error::Serialization(reason) if reason.ends_with("no JSON object"))
        );
        let limit: Error = ModelCallError::StepLimit(4).into();
        assert!(matches!(&limit, Error::BudgetExceeded(reason) if reason.contains("4 steps")));
        assert!(!invalid.is_retryable());
        assert!(!limit.is_retryable());
    }
}
