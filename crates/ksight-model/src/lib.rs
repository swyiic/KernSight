//! Stable, transport-independent `KernSight` domain types.

mod artifact;
mod event;
mod identity;
mod quality;

pub use artifact::{ArtifactKind, ArtifactProvenance, ArtifactRef};
pub use event::{
    BaselineFd, BaselineFdKind, BaselineVma, BinderCodeKind, BinderTargetKind, BinderTransaction,
    BinderTransactionDirection, BinderTransactionFlag, BinderTransactionStage, CaptureMode,
    CaptureStopReason, CollectorMode, EnvironmentState, Event, EventHeader, EventPayload,
    FileDescriptorChange, FileDescriptorOperation, FileOpen, InspectObservation, InspectPlaintext,
    MemoryOperation, MemoryRegionChange, ProcessIdentityChange, ProcessIdentityChangeKind,
    ProcessLifecycle, ProcessLifecycleKind, SchedWakeup, SchemaVersion, SensorKind,
    SessionCompletion, SessionEnvironment, SessionFdBaseline, SessionVmaBaseline, SocketAccept,
    SocketConnect, SocketIo, SocketIoOperation,
};
pub use identity::{PackageCandidate, ProcessIdentity, ProcessKey};
pub use quality::{Confidence, DataQuality};

/// Current normalized event schema.
pub const CURRENT_SCHEMA: SchemaVersion = SchemaVersion {
    major: 1,
    minor: 19,
};
