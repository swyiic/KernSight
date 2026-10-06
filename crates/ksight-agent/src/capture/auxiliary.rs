//! Side-effect plan shared by the CLI and actual capture callbacks.

/// The lifecycle stage at which an auxiliary operation could run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryStage {
    /// Start retained by this evidence operation.
    Start,
    /// Poll retained by this evidence operation.
    Poll,
    /// Finish retained by this evidence operation.
    Finish,
}

/// Auxiliary capture operations, distinct from package-scoped TLS boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryAction {
    /// Pcap retained by this evidence operation.
    Pcap,
    /// Keylog retained by this evidence operation.
    Keylog,
    /// Infosec retained by this evidence operation.
    Infosec,
    /// Crypto Watch retained by this evidence operation.
    CryptoWatch,
    /// Memory Dump retained by this evidence operation.
    MemoryDump,
}

/// Mirror has no auxiliary operations. Key scanning requires explicit selection.
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "These independently selected flags are part of the existing CLI and evidence schema."
)]
pub struct AuxiliaryCapturePlan {
    mirror: bool,
    _code_only: bool,
    collect_keys: bool,
    automatic_dump: bool,
}

impl AuxiliaryCapturePlan {
    #[cfg(test)]
    pub(super) const fn new(mirror: bool) -> Self {
        Self {
            mirror,
            _code_only: false,
            collect_keys: false,
            automatic_dump: true,
        }
    }

    pub(super) const fn scoped(mirror: bool, code_only: bool, collect_keys: bool) -> Self {
        Self {
            mirror,
            _code_only: code_only,
            collect_keys,
            automatic_dump: true,
        }
    }

    /// Parent orchestration owns its explicit snapshot stage. Observation/inspect
    /// callbacks must not silently duplicate a code copy into their own quota.
    pub(super) const fn without_automatic_dump(mut self) -> Self {
        self.automatic_dump = false;
        self
    }

    /// No pcap, keylog or infosec path is selected by this minimal mode.
    #[must_use]
    pub fn enabled(self, action: AuxiliaryAction) -> bool {
        !self.mirror
            && match action {
                AuxiliaryAction::CryptoWatch => self.collect_keys,
                AuxiliaryAction::MemoryDump => self.automatic_dump,
                _ => false,
            }
    }

    /// Execute selected production callbacks. Failed exits never export memory.
    ///
    /// # Errors
    /// Propagates the selected backend's I/O error.
    pub fn dispatch<E>(
        self,
        stage: AuxiliaryStage,
        successful: bool,
        mut backend: impl FnMut(AuxiliaryAction) -> Result<(), E>,
    ) -> Result<(), E> {
        let action = match stage {
            AuxiliaryStage::Poll => Some(AuxiliaryAction::CryptoWatch),
            AuxiliaryStage::Finish if successful => Some(AuxiliaryAction::MemoryDump),
            AuxiliaryStage::Start | AuxiliaryStage::Finish => None,
        };
        if let Some(action) = action.filter(|action| self.enabled(*action)) {
            backend(action)?;
        }
        Ok(())
    }
}

