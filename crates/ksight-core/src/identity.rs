use std::collections::BTreeMap;

use ksight_model::{ProcessIdentity, ProcessKey};

/// In-memory process identity registry keyed by boot and start time, not PID alone.
#[derive(Debug, Default)]
pub struct IdentityRegistry {
    entries: BTreeMap<ProcessKey, ProcessIdentity>,
}

impl IdentityRegistry {
    /// Insert or replace the current knowledge for a process instance.
    pub fn upsert(&mut self, identity: ProcessIdentity) -> Option<ProcessIdentity> {
        self.entries.insert(identity.key.clone(), identity)
    }

    /// Resolve an exact process instance.
    pub fn get(&self, key: &ProcessKey) -> Option<&ProcessIdentity> {
        self.entries.get(key)
    }

    /// Remove an exited process instance after its terminal event is persisted.
    pub fn remove(&mut self, key: &ProcessKey) -> Option<ProcessIdentity> {
        self.entries.remove(key)
    }

    /// Number of active process instances.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
