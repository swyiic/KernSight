//! DEX/ELF provenance classification built on path and mapping facts.
//!
//! This layer does not reconstruct file contents. It assigns a provenance class so `MobileE` can
//! distinguish a package path guess from a hashed, format-validated artifact.

use ksight_model::{ArtifactKind, ArtifactProvenance, ArtifactRef};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    pub indexed_method_name_samples: usize,
    /// Number of distinct `class->name(params)return` prototypes when `proto_ids` parsed.
    #[serde(default)]
    pub indexed_method_prototype_samples: usize,
    /// Classes declared by multiple content-distinct DEX files.
    pub class_conflicts: Vec<DexClassConflict>,
    /// DEX sets whose semantic table could not be safely parsed.
    pub semantic_parse_failures: usize,
    /// True when any per-DEX class or method list reached its publication bound.
    pub semantic_index_truncated: bool,
}

/// Deterministic ownership class for one content-distinct DEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DexOwnershipCategory {
    /// Product screens, requests, models, and other first-party application code.
    Business,
    /// Code sharing the organization's namespace but not the exact app package.
    InternalComponent,
    /// Recognized platform or third-party library namespaces.
    ThirdPartySdk,
    /// Runtime-only DEX without a matching APK observation.
    DynamicPayload,
    /// Material first-party and SDK class populations coexist in the same DEX.
    Mixed,
    /// Published semantic evidence is insufficient for a reliable assignment.
    Unknown,
}

impl DexOwnershipCategory {
    /// Stable ordered directory used by device and desktop evidence browsers.
    pub fn directory(self) -> &'static str {
        match self {
            Self::Business => "01-business",
            Self::InternalComponent => "02-internal-components",
            Self::DynamicPayload => "03-dynamic-payloads",
            Self::ThirdPartySdk => "04-third-party-sdks",
            Self::Mixed => "05-mixed",
            Self::Unknown => "06-unknown",
        }
    }
}

/// Explainable ownership result for one SHA-256 DEX identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexOwnershipEntry {
    /// Exact DEX content identity.
    pub sha256: String,
    /// Existing evidence path; classification folders contain references, not copies.
    pub canonical_relative_path: String,
    /// Final deterministic category.
    pub category: DexOwnershipCategory,
    /// Evidence-based confidence from 0 to 100.
    pub confidence: u8,
    /// Declared classes sampled from this DEX.
    pub sampled_classes: usize,
    /// Classes assigned to the exact application namespace or business vocabulary.
    pub business_classes: usize,
    /// Classes sharing the organization namespace.
    pub internal_classes: usize,
    /// Classes matching stable platform/SDK namespaces.
    pub third_party_classes: usize,
    /// Classes that remain unattributed.
    pub unknown_classes: usize,
    /// Most frequent declared namespaces, never inferred from references alone.
    pub dominant_namespaces: Vec<String>,
    /// Human-readable reasons used to reach the result.
    pub reasons: Vec<String>,
}

/// Package-wide, token-free DEX ownership report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexOwnershipReport {
    /// Classification schema independent from the package dump schema.
    pub schema_version: String,
    /// Application package used as the first-party seed.
    pub package: String,
    /// First-party namespace roots inferred from this package's registered components.
    #[serde(default)]
    pub inferred_internal_namespaces: Vec<DexOwnershipNamespaceSeed>,
    /// One result per content-distinct DEX.
    pub entries: Vec<DexOwnershipEntry>,
    /// Number of business DEX sets.
    pub business: usize,
    /// Number of organization-shared component DEX sets.
    pub internal_components: usize,
    /// Number of known third-party SDK DEX sets.
    pub third_party_sdks: usize,
    /// Number of runtime-only payload DEX sets.
    pub dynamic_payloads: usize,
    /// Number of mixed-ownership DEX sets.
    pub mixed: usize,
    /// Number of unattributed DEX sets.
    pub unknown: usize,
    /// Exact application-namespace class samples across every DEX, including mixed DEX files.
    #[serde(default)]
    pub business_class_samples: usize,
    /// DEX files containing at least one exact application-namespace class.
    #[serde(default)]
    pub business_dex_sets: usize,
    /// Organization-local component class samples across every DEX.
    #[serde(default)]
    pub internal_class_samples: usize,
    /// Stable third-party SDK class samples across every DEX.
    #[serde(default)]
    pub third_party_class_samples: usize,
    /// Class samples that remain unattributed across every DEX.
    #[serde(default)]
    pub unknown_class_samples: usize,
}

/// Explainable namespace seed inferred for the current application only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexOwnershipNamespaceSeed {
    /// Slash-separated namespace root, for example `com/example`.
    pub namespace: String,
    /// Registered Android components found in sampled DEX class declarations.
    pub registered_components: usize,
    /// Declared class samples under this namespace across all indexed DEX files.
    pub sampled_classes: usize,
    /// Deterministic admission explanation.
    pub reason: String,
}

/// Package-local evidence used to infer ownership without application-specific rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexOwnershipContext {
    /// Fully-qualified component classes obtained from Android package metadata.
    pub registered_component_classes: Vec<String>,
}

/// Classify content-distinct DEX sets without a model call.
pub fn classify_dex_ownership(package: &str, sets: &[DexArtifactSet]) -> DexOwnershipReport {
    classify_dex_ownership_with_context(package, sets, &DexOwnershipContext::default())
}

/// Classify DEX sets using package-local component evidence.
pub fn classify_dex_ownership_with_context(
    package: &str,
    sets: &[DexArtifactSet],
    context: &DexOwnershipContext,
) -> DexOwnershipReport {
    let package_path = package.to_ascii_lowercase().replace('.', "/");
    let organization_path = package_path
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");
    let inferred_internal_namespaces = infer_internal_namespace_seeds(&package_path, sets, context);
    let inferred_roots = inferred_internal_namespaces
        .iter()
        .map(|seed| seed.namespace.as_str())
        .collect::<Vec<_>>();
    let mut entries = sets
        .iter()
        .map(|set| classify_dex_set(set, &package_path, &organization_path, &inferred_roots))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(right.confidence.cmp(&left.confidence))
            .then(left.sha256.cmp(&right.sha256))
    });
    let mut report = DexOwnershipReport {
        schema_version: "mobilee.kernsight-dex-ownership/v3".to_owned(),
        package: package.to_owned(),
        inferred_internal_namespaces,
        entries,
        ..DexOwnershipReport::default()
    };
    for entry in &report.entries {
        report.business_class_samples += entry.business_classes;
        report.internal_class_samples += entry.internal_classes;
        report.third_party_class_samples += entry.third_party_classes;
        report.unknown_class_samples += entry.unknown_classes;
        if entry.business_classes > 0 {
            report.business_dex_sets += 1;
        }
        match entry.category {
            DexOwnershipCategory::Business => report.business += 1,
            DexOwnershipCategory::InternalComponent => report.internal_components += 1,
            DexOwnershipCategory::ThirdPartySdk => report.third_party_sdks += 1,
            DexOwnershipCategory::DynamicPayload => report.dynamic_payloads += 1,
            DexOwnershipCategory::Mixed => report.mixed += 1,
            DexOwnershipCategory::Unknown => report.unknown += 1,
        }
    }
    report
}

fn classify_dex_set(
    set: &DexArtifactSet,
    package_path: &str,
    organization_path: &str,
    inferred_internal_roots: &[&str],
) -> DexOwnershipEntry {
    let descriptors = set
        .semantic
        .as_ref()
        .map(|semantic| semantic.class_descriptors.as_slice())
        .unwrap_or_default();
    let mut business = 0_usize;
    let mut internal = 0_usize;
    let mut sdk = 0_usize;
    let mut unknown = 0_usize;
    let mut namespaces = BTreeMap::<String, usize>::new();
    for descriptor in descriptors {
        let normalized = descriptor
            .trim_start_matches('[')
            .trim_start_matches('L')
            .trim_end_matches(';')
            .to_ascii_lowercase();
        *namespaces.entry(class_namespace(&normalized)).or_default() += 1;
        if !package_path.is_empty() && namespace_contains(package_path, &normalized) {
            business += 1;
        } else if is_sdk_namespace(&normalized) {
            sdk += 1;
        } else if inferred_internal_roots
            .iter()
            .any(|root| namespace_contains(root, &normalized))
        {
            internal += 1;
        } else if organization_path.contains('/')
            && namespace_contains(organization_path, &normalized)
        {
            internal += 1;
        } else {
            unknown += 1;
        }
    }
    let total = descriptors.len();
    let classified = business + internal + sdk;
    let runtime_only = set
        .sources
        .iter()
        .any(|source| matches!(source.as_str(), "memory-dex" | "heap-blob"))
        && !set.sources.iter().any(|source| source == "apk-dex");
    let business_share = percent(business, total);
    let internal_share = percent(internal, total);
    let sdk_share = percent(sdk, total);
    let has_first_party = business + internal > 0;
    let has_non_first_party = sdk + unknown > 0;
    let category = if total == 0 {
        DexOwnershipCategory::Unknown
    } else if business_share >= 55 {
        DexOwnershipCategory::Business
    } else if internal_share >= 55 {
        DexOwnershipCategory::InternalComponent
    } else if has_first_party && has_non_first_party {
        // A multidex file is a container, not an ownership boundary. Preserve even a
        // small exact package-namespace contribution instead of allowing a large SDK
        // or obfuscated namespace to erase the application's own classes.
        DexOwnershipCategory::Mixed
    } else if business > 0 {
        DexOwnershipCategory::Business
    } else if internal > 0 {
        DexOwnershipCategory::InternalComponent
    } else if sdk_share >= 60 {
        DexOwnershipCategory::ThirdPartySdk
    } else if runtime_only {
        DexOwnershipCategory::DynamicPayload
    } else if classified * 100 >= total * 65 {
        if business >= internal && business >= sdk {
            DexOwnershipCategory::Business
        } else if internal >= sdk {
            DexOwnershipCategory::InternalComponent
        } else {
            DexOwnershipCategory::ThirdPartySdk
        }
    } else {
        DexOwnershipCategory::Unknown
    };
    let dominant = match category {
        DexOwnershipCategory::Business => business_share,
        DexOwnershipCategory::InternalComponent => internal_share,
        DexOwnershipCategory::ThirdPartySdk => sdk_share,
        DexOwnershipCategory::DynamicPayload => percent(unknown + business + internal, total),
        DexOwnershipCategory::Mixed => percent(classified, total),
        DexOwnershipCategory::Unknown => percent(unknown, total),
    };
    let coverage = percent(classified, total);
    let confidence = if total == 0 {
        0
    } else {
        u8::try_from((dominant * 2 + coverage) / 3)
            .unwrap_or(100)
            .min(100)
    };
    let mut namespace_rows = namespaces.into_iter().collect::<Vec<_>>();
    namespace_rows.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    let dominant_namespaces = namespace_rows
        .into_iter()
        .take(6)
        .map(|(name, count)| format!("{name} ({count})"))
        .collect();
    let mut reasons = vec![format!(
        "类样本 {total}：业务 {business}、内部组件 {internal}、第三方 SDK {sdk}、未知 {unknown}"
    )];
    if runtime_only {
        reasons.push("仅在内存/堆载荷中观察到，APK DEX 中没有相同 SHA-256".to_owned());
    }
    if set
        .semantic
        .as_ref()
        .is_some_and(|semantic| semantic.class_descriptors_truncated)
    {
        reasons.push("类索引达到发布上限，结论基于有界样本".to_owned());
    }
    let matched_roots = inferred_internal_roots
        .iter()
        .filter(|root| {
            descriptors
                .iter()
                .any(|descriptor| namespace_contains(root, &normalize_class_name(descriptor)))
        })
        .map(|root| root.replace('/', "."))
        .take(4)
        .collect::<Vec<_>>();
    if !matched_roots.is_empty() {
        reasons.push(format!(
            "当前应用注册组件动态推导的内部命名空间：{}",
            matched_roots.join("、")
        ));
    }
    DexOwnershipEntry {
        sha256: set.sha256.clone(),
        canonical_relative_path: set.canonical_relative_path.clone(),
        category,
        confidence,
        sampled_classes: total,
        business_classes: business,
        internal_classes: internal,
        third_party_classes: sdk,
        unknown_classes: unknown,
        dominant_namespaces,
        reasons,
    }
}

fn percent(value: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        value.saturating_mul(100) / total
    }
}

fn class_namespace(path: &str) -> String {
    let mut parts = path.split('/');
    let first = parts.next().unwrap_or("unknown");
    let second = parts.next();
    let third = parts.next();
    match (second, third) {
        (Some(second), Some(third)) => format!("{first}.{second}.{third}"),
        (Some(second), None) => format!("{first}.{second}"),
        _ => first.to_owned(),
    }
}

fn normalize_class_name(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('[')
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('.', "/")
        .to_ascii_lowercase()
}

fn namespace_root(path: &str) -> String {
    path.split('/').take(2).collect::<Vec<_>>().join("/")
}

fn namespace_contains(root: &str, path: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn infer_internal_namespace_seeds(
    package_path: &str,
    sets: &[DexArtifactSet],
    context: &DexOwnershipContext,
) -> Vec<DexOwnershipNamespaceSeed> {
    let declared_classes = sets
        .iter()
        .filter_map(|set| set.semantic.as_ref())
        .flat_map(|semantic| semantic.class_descriptors.iter())
        .map(|descriptor| normalize_class_name(descriptor))
        .collect::<BTreeSet<_>>();
    let mut sampled_by_root = BTreeMap::<String, usize>::new();
    for class_name in &declared_classes {
        let root = namespace_root(class_name);
        if root.contains('/') {
            *sampled_by_root.entry(root).or_default() += 1;
        }
    }
    let package_root = namespace_root(package_path);
    let mut components_by_root = BTreeMap::<String, usize>::new();
    for component in &context.registered_component_classes {
        let class_name = normalize_class_name(component);
        if !declared_classes.contains(&class_name) {
            continue;
        }
        let root = namespace_root(&class_name);
        if !root.contains('/')
            || root == package_root
            || is_sdk_namespace(&class_name)
            || is_external_vendor_root(&root)
        {
            continue;
        }
        *components_by_root.entry(root).or_default() += 1;
    }
    components_by_root
        .into_iter()
        .filter_map(|(namespace, registered_components)| {
            let sampled_classes = sampled_by_root.get(&namespace).copied().unwrap_or(0);
            let admitted =
                registered_components >= 2 || (registered_components >= 1 && sampled_classes >= 64);
            admitted.then(|| DexOwnershipNamespaceSeed {
                reason: if registered_components >= 2 {
                    format!("{registered_components} 个系统注册组件与 DEX 声明一致")
                } else {
                    format!(
                        "1 个系统注册组件与 DEX 声明一致，且该命名空间采样 {sampled_classes} 个类"
                    )
                },
                namespace,
                registered_components,
                sampled_classes,
            })
        })
        .collect()
}

fn is_sdk_namespace(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "android/",
        "androidx/",
        "com/airbnb/",
        "com/alibaba/fastjson/",
        "com/bumptech/glide/",
        "com/facebook/",
        "com/github/",
        "com/google/",
        "com/huawei/hms/",
        "com/tenpay/",
        "com/tencent/bugly/",
        "com/tencent/mapsdk/",
        "com/tencent/mm/opensdk/",
        "com/tencent/qqmail/",
        "com/tencent/smtt/",
        "com/tencent/tencentmap/",
        "com/tencent/wework/",
        "com/tencent/weworklocal/",
        "com/tencent/wemeet/",
        "com/tencent/wwapi/",
        "com/tencent/xweb/",
        "com/tencent/xwebsdk/",
        "com/tencent/youtu/",
        "com/umeng/",
        "com/vivo/push/",
        "com/xiaomi/push/",
        "io/reactivex/",
        "java/",
        "javax/",
        "kotlin/",
        "kotlinx/",
        "okhttp3/",
        "okio/",
        "org/apache/",
        "org/chromium/",
        "org/greenrobot/",
        "org/jetbrains/",
        "org/json/",
        "retrofit2/",
    ];
    PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

fn is_external_vendor_root(root: &str) -> bool {
    const ROOTS: &[&str] = &[
        "com/alibaba",
        "com/baidu",
        "com/facebook",
        "com/google",
        "com/huawei",
        "com/microsoft",
        "com/qq",
        "com/taobao",
        "com/tenpay",
        "com/tencent",
        "com/umeng",
        "com/vivo",
        "com/xiaomi",
        "org/apache",
        "org/chromium",
        "org/jetbrains",
    ];
    ROOTS.contains(&root)
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

    fn dex_set(classes: &[&str], sources: &[&str]) -> DexArtifactSet {
        DexArtifactSet {
            sha256: "a".repeat(64),
            bytes: 4096,
            canonical_relative_path: "apk-dex/split/classes.dex".to_owned(),
            sources: sources.iter().map(|value| (*value).to_owned()).collect(),
            observations: Vec::new(),
            semantic: Some(crate::DexSemanticSummary {
                class_descriptors: classes.iter().map(|value| (*value).to_owned()).collect(),
                ..crate::DexSemanticSummary::default()
            }),
        }
    }

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

    #[test]
    fn ownership_prefers_exact_app_namespace_over_generic_vocabulary() {
        let set = dex_set(
            &[
                "Lcom/acme/mobile/HostActivity;",
                "Lcom/acme/mobile/order/OrderRepository;",
                "Lcom/acme/mobile/api/AccountRequest;",
            ],
            &["apk-dex"],
        );
        let report = classify_dex_ownership("com.acme.mobile", &[set]);
        assert_eq!(report.business, 1);
        assert_eq!(report.entries[0].category, DexOwnershipCategory::Business);

        let vendor_app = dex_set(
            &[
                "Lcom/google/myproduct/MainActivity;",
                "Lcom/google/myproduct/api/AccountRequest;",
            ],
            &["apk-dex"],
        );
        let vendor_report = classify_dex_ownership("com.google.myproduct", &[vendor_app]);
        assert_eq!(vendor_report.business, 1);
    }

    #[test]
    fn ownership_recognizes_sdk_and_runtime_only_payloads() {
        let sdk = dex_set(
            &[
                "Lokhttp3/Request;",
                "Lokio/Buffer;",
                "Lcom/google/gson/Gson;",
            ],
            &["apk-dex"],
        );
        let dynamic = dex_set(&["La/b/c;", "Lx/y/z;"], &["memory-dex"]);
        let report = classify_dex_ownership("com.acme.mobile", &[sdk, dynamic]);
        assert_eq!(report.third_party_sdks, 1);
        assert_eq!(report.dynamic_payloads, 1);
    }

    #[test]
    fn ownership_does_not_promote_vendor_components_from_generic_class_names() {
        let vendor = dex_set(
            &[
                "Lcom/tencent/wework/HostActivity;",
                "Lcom/tencent/qqmail/AccountService;",
                "Lcom/vivo/push/PushRequest;",
                "Lcom/tenpay/ndk/PaymentController;",
            ],
            &["apk-dex"],
        );
        let report = classify_dex_ownership("com.example.app", &[vendor]);
        assert_eq!(report.third_party_sdks, 1);
        assert_eq!(report.business, 0);
    }

    #[test]
    fn ownership_preserves_exact_app_classes_inside_sdk_heavy_multidex() {
        let mut classes = vec![
            "Lcom/example/app/MainActivity;",
            "Lcom/example/app/account/SessionRepository;",
        ];
        classes.extend(std::iter::repeat_n("Lcom/tencent/wework/Api;", 98));
        let mixed = dex_set(&classes, &["apk-dex"]);
        let report = classify_dex_ownership("com.example.app", &[mixed]);

        assert_eq!(report.entries[0].category, DexOwnershipCategory::Mixed);
        assert_eq!(report.entries[0].business_classes, 2);
        assert_eq!(report.business_class_samples, 2);
        assert_eq!(report.business_dex_sets, 1);
        assert_eq!(report.mixed, 1);
    }

    #[test]
    fn ownership_package_match_respects_namespace_boundary() {
        let unrelated = dex_set(&["Lcom/example/appextra/NotTheApplication;"], &["apk-dex"]);
        let report = classify_dex_ownership("com.example.app", &[unrelated]);

        assert_eq!(report.entries[0].business_classes, 0);
    }

    #[test]
    fn ownership_infers_internal_namespaces_from_current_app_components() {
        let enterprise_modules = dex_set(
            &[
                "Lcorp/maps/api/MapService;",
                "Lcorp/grid/ApprovalActivity;",
                "Lcorp/grid/ApprovalProvider;",
                "Lcorp/grid/ApprovalService;",
            ],
            &["apk-dex"],
        );
        let context = DexOwnershipContext {
            registered_component_classes: vec![
                "corp.grid.ApprovalActivity".to_owned(),
                "corp.grid.ApprovalProvider".to_owned(),
                "corp.grid.ApprovalService".to_owned(),
            ],
        };
        let report = classify_dex_ownership_with_context(
            "com.example.shell",
            &[enterprise_modules.clone()],
            &context,
        );
        assert_eq!(report.internal_components, 1);
        assert_eq!(
            report.inferred_internal_namespaces[0].namespace,
            "corp/grid"
        );

        let unrelated = classify_dex_ownership("com.example.wrapper", &[enterprise_modules]);
        assert_eq!(unrelated.internal_components, 0);
        assert_eq!(unrelated.business, 0);
        assert_eq!(unrelated.unknown, 1);
    }

    #[test]
    fn ownership_never_promotes_registered_third_party_vendor_components() {
        let vendor = dex_set(
            &[
                "Lcom/tencent/wework/HostActivity;",
                "Lcom/tencent/wework/SyncService;",
                "Lcom/vivo/push/PushService;",
            ],
            &["apk-dex"],
        );
        let context = DexOwnershipContext {
            registered_component_classes: vec![
                "com.tencent.wework.HostActivity".to_owned(),
                "com.tencent.wework.SyncService".to_owned(),
                "com.vivo.push.PushService".to_owned(),
            ],
        };
        let report = classify_dex_ownership_with_context("com.example.app", &[vendor], &context);
        assert!(report.inferred_internal_namespaces.is_empty());
        assert_eq!(report.third_party_sdks, 1);
    }
}
