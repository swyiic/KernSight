use crate::policy::PolicyStore;

/// Coarse service lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// Created but not probed.
    Created,
    /// Read-only capabilities established.
    Probed,
    /// Capture session is active.
    Running,
    /// Service stopped cleanly.
    Stopped,
}

/// Top-level agent state machine. Concrete adapters are added by milestone.
#[derive(Debug, Default)]
pub struct AgentRuntime {
    state: Option<RuntimeState>,
    /// Validated policy store.
    pub policies: PolicyStore,
}

impl AgentRuntime {
    /// Create a runtime that makes no capture claim.
    pub fn new() -> Self {
        Self {
            state: Some(RuntimeState::Created),
            policies: PolicyStore::default(),
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> RuntimeState {
        self.state.unwrap_or(RuntimeState::Created)
    }

    /// Record completion of a read-only capability probe.
    pub fn mark_probed(&mut self) {
        self.state = Some(RuntimeState::Probed);
    }
}
