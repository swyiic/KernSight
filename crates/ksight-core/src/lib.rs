//! Platform-independent `KernSight` logic.

mod capability;
mod dex;
mod dns;
mod graph;
mod handshake;
mod http2;
mod http_mirror;
mod http_plain;
mod identity;
mod inflate;
mod inspect;
mod native_rules;
mod pcap_decrypt;
mod policy;
mod provenance;
mod quic_initial;
mod report;
mod sequence;
mod sm4;
mod stack_rules;

pub use capability::{
    current_capabilities, semantic_keypoints, CapabilityArea, CapabilityStage, ObservationTier,
    SemanticKeypoint, VisibilityRisk,
};
pub use dex::{
    decrypt_secneo_dexdata, extract_apk_dex, extract_apk_native_libs, extract_apk_packed_native,
    find_secneo_key, is_dex_magic, is_vdex_magic, key_unlocks_secneo, parse_dex_semantics,
    parse_secneo_dexdata, publish_readable_dex, repair_dex, repair_dex_dir, repair_package_dir,
    scan_sm4_haystack, scan_sm4_one_block, secneo_cipher_probes, split_concatenated_dex,
    try_decrypt_secneo, ApkPackedFile, DexExtract, DexRepair, DexSemanticSummary, DexSlice,
    SecNeoDexData,
};
pub use dns::{parse_dns_message, DnsRecord};
pub use graph::{
    ranges_overlap, EdgeStrength, GraphEdge, GraphEntity, GraphEntityKind, GraphQuery, SessionGraph,
};
pub use handshake::{parse_handshake, HandshakeMeta};
pub use http2::looks_like_http2;
pub use http_mirror::{
    fragment_bytes, parse_mirror_endpoint, request_from_http_url, requests_from_embedded_http_urls,
    MirroredMessage, StreamReassembler, BURP_PLAYBACK_PORT, BURP_UPSTREAM_PORT,
};
pub use http_plain::{
    format_inspect_url, is_kept_inspect_url, is_third_party_host, parse_http_plain,
    parse_http_plain_all, parse_http_plain_all_bytes, parse_http_plain_bytes, ParsedHttpPlain,
};
pub use identity::IdentityRegistry;
pub use inflate::{
    decode_hex_bytes, inflate_gzip_bounded, inflate_inspect_buffer, looks_like_gzip,
    looks_like_zlib,
};
pub use inspect::{InspectAuditEvent, InspectPolicy};
pub use native_rules::{
    classify_native_frameworks, classify_tls_library_path, native_framework_rule_version,
    NativeFrameworkEvidence, NativeFrameworkMatch, TlsLibraryKind,
};
pub use pcap_decrypt::{decrypt_flows, parse_keylog, parse_pcap_tcp_flows, DecryptedFlow};
pub use policy::{validate_policy, PolicyError};
pub use provenance::{
    anonymous_executable, hashed_file, path_candidate, CodeArtifact, DexArtifactObservation,
    DexArtifactSet, DexClassConflict, DumpArtifact, PackageDexIndex, ProvenanceClass,
};
pub use quic_initial::{decrypt_initial, QuicInitialHello, QuicInitialTable};
pub use report::{
    correlate_http_calls_to_dex, http_calls_from_plaintext_dir, http_calls_from_private_dir,
    rank_observed_mappings, sort_http_catalog, ArtifactActivity, BinderFdTransfer,
    BinderLifecycleSummary, BinderRelation, BinderReplyPair, DnsNameActivity, FdLifecycleSummary,
    HandshakeNameActivity, HttpCallActivity, HttpCodeRef, InspectHitActivity, LoopbackScanActivity,
    MappingSource, MemoryLifecycleSummary, MergedDumpRef, NetworkPeerActivity, ObservedMapping,
    PlaintextActivity, ProcessActivity, ProcessInstanceRef, QualitySummary, SchedWakeupActivity,
    SessionReport, SessionReportBuilder, SocketLifecycleSummary,
};
pub use sequence::{SequenceError, SequenceGap, SequenceTracker};
pub use sm4::{
    decrypt_block as sm4_decrypt_block, decrypt_ecb as sm4_decrypt_ecb,
    encrypt_ecb as sm4_encrypt_ecb,
};
pub use stack_rules::{
    boundary_rule_for_symbol, boundary_symbols, keylog_entries, load as load_stack_rules,
    stack_for_path, tls_symbol_names,
};
