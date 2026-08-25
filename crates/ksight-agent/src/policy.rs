use ksight_core::{validate_policy, PolicyError};
use ksight_protocol::UpdatePolicy;

/// Validated current capture policy.
#[derive(Debug, Default)]
pub struct PolicyStore {
    current: Option<UpdatePolicy>,
}

impl PolicyStore {
    /// Validate and install a strictly newer policy generation.
    ///
    /// # Errors
    ///
    /// Returns an invariant violation or [`PolicyInstallError::StaleGeneration`].
    pub fn replace(&mut self, policy: UpdatePolicy) -> Result<(), PolicyInstallError> {
        validate_policy(&policy)?;
        if self
            .current
            .as_ref()
            .is_some_and(|current| policy.generation <= current.generation)
        {
            return Err(PolicyInstallError::StaleGeneration);
        }
        self.current = Some(policy);
        Ok(())
    }

    /// Current validated policy.
    pub fn current(&self) -> Option<&UpdatePolicy> {
        self.current.as_ref()
    }
}

/// Failure to install an agent policy.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyInstallError {
    /// Core policy invariant failed.
    #[error(transparent)]
    Invalid(#[from] PolicyError),
    /// Policy generation did not increase.
    #[error("policy generation must increase")]
    StaleGeneration,
}
