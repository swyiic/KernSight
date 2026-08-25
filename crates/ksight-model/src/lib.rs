//! Stable, transport-independent `KernSight` domain types.

mod artifact;
mod event;
mod identity;
mod quality;

pub use artifact::{ArtifactKind, ArtifactProvenance, ArtifactRef};
pub use event::{
    CaptureMode, Event, EventHeader, EventPayload, ProcessLifecycle, ProcessLifecycleKind,
    SchemaVersion, SensorKind,
};
pub use identity::{PackageCandidate, ProcessIdentity, ProcessKey};
pub use quality::{Confidence, DataQuality};

/// Current normalized event schema.
pub const CURRENT_SCHEMA: SchemaVersion = SchemaVersion { major: 1, minor: 0 };
