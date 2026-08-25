//! Platform-independent `KernSight` logic.

mod identity;
mod policy;
mod sequence;

pub use identity::IdentityRegistry;
pub use policy::{validate_policy, PolicyError};
pub use sequence::{SequenceError, SequenceGap, SequenceTracker};
