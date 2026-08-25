//! Device-side `KernSight` orchestration boundaries.

/// Low-cost userspace aggregation.
pub mod aggregate;
/// Read-only platform capability discovery.
pub mod capabilities;
/// Bounded raw-record collection.
pub mod collector;
pub mod identity;
/// Capture and deployment integrity reporting.
pub mod integrity;
/// Sensor loading and attachment lifecycle.
pub mod loader;
/// Raw ABI normalization.
pub mod normalize;
/// Validated capture policy state.
pub mod policy;
/// Agent lifecycle orchestration.
pub mod runtime;
/// Durable disconnected-session buffering.
pub mod spool;
/// Authenticated local transport boundary.
pub mod transport;

pub use capabilities::{CapabilityProbe, HostCapabilityProbe, ProbeReport};
pub use runtime::{AgentRuntime, RuntimeState};
