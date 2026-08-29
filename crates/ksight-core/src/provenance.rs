//! DEX/ELF provenance classification built on path and mapping facts.
//!
//! This layer does not reconstruct file contents. It assigns a provenance class so `MobileE` can
//! distinguish a package path guess from a hashed, format-validated artifact.

use ksight_model::{ArtifactKind, ArtifactProvenance, ArtifactRef};
use serde::{Deserialize, Serialize};

/// How strongly a code path or mapping has been identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceClass {
    /// Path string observed, no hash or format check.
    PathCandidate,
    /// File bytes hashed but format not validated.
    Hashed,
    /// Magic/header matched DEX or ELF.
    FormatValidated,
    /// Mapping linked to a hashed file identity.
    MappingLinked,
    /// Anonymous or memfd executable mapping without a backing file.
    AnonymousExecutable,
}

/// One code-artifact candidate derived from file or memory observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeArtifact {
    /// Artifact class when known.
    pub kind: Option<ArtifactKind>,
    /// Provenance class.
    pub class: ProvenanceClass,
    /// Observed path or mapping label.
    pub path: String,
    /// Content-addressed reference once bytes have been hashed.
    pub artifact: Option<ArtifactRef>,
    /// Provenance enum used by the evidence store.
    pub provenance: ArtifactProvenance,
}

/// Classify a path-only L0 observation.
pub fn path_candidate(path: &str) -> CodeArtifact {
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    let kind = if extension.eq_ignore_ascii_case("dex") || path.contains("/oat/") {
        Some(ArtifactKind::Dex)
    } else if extension.eq_ignore_ascii_case("so") || extension.eq_ignore_ascii_case("apk") {
        Some(ArtifactKind::Elf)
    } else {
        None
    };
    CodeArtifact {
        kind,
        class: ProvenanceClass::PathCandidate,
        path: path.to_owned(),
        artifact: None,
        provenance: ArtifactProvenance::Inferred,
    }
}

/// Classify an executable mapping with no backing path.
pub fn anonymous_executable(label: impl Into<String>) -> CodeArtifact {
    CodeArtifact {
        kind: Some(ArtifactKind::Elf),
        class: ProvenanceClass::AnonymousExecutable,
        path: label.into(),
        artifact: None,
        provenance: ArtifactProvenance::Loaded,
    }
}

/// One DEX/ELF file taken from a package dump, bound to process and optional VMA.
///
/// Edges built from these records are correlated: the dump observed the bytes in a
/// live mapping or on disk, but that is not a kernel mmap/open fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpArtifact {
    /// `dex` or `elf`.
    pub kind: String,
    /// `heap-blob`, `apk-dex`, `apk-assets`, `install-lib`, or `runtime-so`.
    pub source: String,
    /// Path relative to the package dump root.
    pub relative_path: String,
    /// File size in bytes.
    pub bytes: u64,
    /// Short magic label (`dex`, `elf`, or `unknown`).
    pub magic: String,
    /// Live process that owned the mapping, when known.
    pub pid: Option<u32>,
    /// Inclusive mapping start, when the file was copied from `/proc/<pid>/mem`.
    pub vma_start: Option<u64>,
    /// Exclusive mapping end.
    pub vma_end: Option<u64>,
    /// `/proc/<pid>/maps` pathname or anon label.
    pub map_path: Option<String>,
    /// Byte offset of this DEX image inside the harvested mapping.
    pub dex_offset: Option<u64>,
    /// SHA-256 of the exact catalogued bytes.
    ///
    /// Older dump reports did not contain a digest and deserialize this as
    /// `None`; a recatalog operation upgrades them without changing the raw
    /// artifact.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// One observation of a content-identical DEX artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexArtifactObservation {
    /// Acquisition class such as `apk-dex`, `heap-blob`, or `memory-dex`.
    pub source: String,
    /// Evidence path retained under the package dump root.
    pub relative_path: String,
    /// Process that owned the memory observation, when known.
    pub pid: Option<u32>,
    /// Inclusive VMA start, when known.
    pub vma_start: Option<u64>,
    /// Exclusive VMA end, when known.
    pub vma_end: Option<u64>,
    /// Mapping pathname or anonymous label, when known.
    pub map_path: Option<String>,
    /// Byte offset of the image inside the captured mapping.
    pub dex_offset: Option<u64>,
}

/// Content-addressed logical DEX with all of its retained observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexArtifactSet {
    /// SHA-256 identity of the exact DEX bytes.
    pub sha256: String,
    /// Exact byte length shared by the observations.
    pub bytes: u64,
    /// Stable representative path; original files are never rewritten or deleted.
    pub canonical_relative_path: String,
    /// Distinct acquisition classes represented by this set.
    pub sources: Vec<String>,
    /// Every path/PID/VMA observation of these bytes.
    pub observations: Vec<DexArtifactObservation>,
    /// Bounded header/class/method index when the standard DEX parsed safely.
    pub semantic: Option<crate::DexSemanticSummary>,
}

/// One class descriptor that appears in more than one distinct DEX identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexClassConflict {
    /// Dalvik class descriptor.
    pub descriptor: String,
    /// Distinct DEX SHA-256 values declaring the class.
    pub dex_sha256: Vec<String>,
}

/// Package-level logical view over physically independent DEX files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageDexIndex {
    /// Number of content-distinct DEX files.
    pub unique_dex: usize,
    /// Number of retained file/memory observations before SHA-256 aggregation.
    pub observations: usize,
    /// Number of distinct class descriptors in the published bounded samples.
    pub indexed_class_samples: usize,
    /// Number of distinct `class->method` names in the published bounded samples.
    /// Overload prototypes are not yet distinguished.
    pub indexed_method_name_samples: usize,
    /// Classes declared by multiple content-distinct DEX files.
    pub class_conflicts: Vec<DexClassConflict>,
    /// DEX sets whose semantic table could not be safely parsed.
    pub semantic_parse_failures: usize,
    /// True when any per-DEX class or method list reached its publication bound.
    pub semantic_index_truncated: bool,
}

/// Attach a SHA-256 digest to a path candidate.
pub fn hashed_file(path: &str, sha256: String, size: u64, kind: ArtifactKind) -> CodeArtifact {
    CodeArtifact {
        kind: Some(kind),
        class: ProvenanceClass::Hashed,
        path: path.to_owned(),
        artifact: Some(ArtifactRef {
            kind,
            provenance: ArtifactProvenance::Original,
            sha256,
            size,
            label: Some(path.to_owned()),
        }),
        provenance: ArtifactProvenance::Original,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_dex_index_accepts_earlier_v2_field_names() {
        let index: PackageDexIndex = serde_json::from_str(
            r#"{"unique_dex":2,"observations":5,"indexed_unique_classes":4,"indexed_unique_method_names":3}"#,
        )
        .expect("earlier v2 index");
        assert_eq!(index.unique_dex, 2);
        assert_eq!(index.observations, 5);
        assert_eq!(index.indexed_class_samples, 0);
        assert_eq!(index.indexed_method_name_samples, 0);
    }
}
