//! Platform-independent `KernSight` logic.

mod capability;
mod dex;
mod graph;
mod identity;
mod inspect;
mod native_rules;
mod policy;
mod provenance;
mod report;
mod sequence;
mod sm4;

pub use capability::{
    current_capabilities, semantic_keypoints, CapabilityArea, CapabilityStage, ObservationTier,
    SemanticKeypoint, VisibilityRisk,
};
pub use dex::{
    decrypt_secneo_dexdata, extract_apk_dex, extract_apk_packed_native, find_secneo_key,
    is_dex_magic, is_vdex_magic, key_unlocks_secneo, parse_dex_semantics, parse_secneo_dexdata,
    publish_readable_dex, repair_dex, repair_dex_dir, repair_package_dir, scan_sm4_haystack,
    scan_sm4_one_block, secneo_cipher_probes, split_concatenated_dex, try_decrypt_secneo,
    ApkPackedFile, DexExtract, DexRepair, DexSemanticSummary, DexSlice, SecNeoDexData,
};
pub use graph::{
    ranges_overlap, EdgeStrength, GraphEdge, GraphEntity, GraphEntityKind, GraphQuery, SessionGraph,
};
pub use identity::IdentityRegistry;
pub use inspect::{InspectAuditEvent, InspectPolicy};
pub use native_rules::{
    classify_native_frameworks, native_framework_rule_version, NativeFrameworkEvidence,
    NativeFrameworkMatch,
};
pub use policy::{validate_policy, PolicyError};
pub use provenance::{
    anonymous_executable, hashed_file, path_candidate, CodeArtifact, DexArtifactObservation,
    DexArtifactSet, DexClassConflict, DumpArtifact, PackageDexIndex, ProvenanceClass,
};
pub use report::{
    rank_observed_mappings, ArtifactActivity, BinderLifecycleSummary, BinderRelation,
    FdLifecycleSummary, LoopbackScanActivity, MappingSource, MemoryLifecycleSummary, MergedDumpRef,
    NetworkPeerActivity, ObservedMapping, PlaintextActivity, ProcessActivity, QualitySummary,
    SchedWakeupActivity, SessionReport, SessionReportBuilder, SocketLifecycleSummary,
};
pub use sequence::{SequenceError, SequenceGap, SequenceTracker};
pub use sm4::{
    decrypt_block as sm4_decrypt_block, decrypt_ecb as sm4_decrypt_ecb,
    encrypt_ecb as sm4_encrypt_ecb,
};
