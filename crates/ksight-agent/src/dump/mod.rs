//! Copy an installed package's APK, native libraries, and live DEX images.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::dexdump::{keep_heap_blob_map_path, pids_for_package, poll_followed_keys, read_region};

const MAX_APK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub(super) const MAX_PRIVATE_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_PRIVATE_FILES: usize = 512;
pub(super) const APP_PRIVATE_DIRS: [&str; 7] = [
    "shared_prefs",
    "databases",
    "files",
    "no_backup",
    "app_webview",
    "app_webview_chromium",
    "cache",
];
/// Versioned package-dump document consumed by `MobileE`.
pub const PACKAGE_DUMP_SCHEMA: &str = "mobilee.kernsight-package-dump/v2";
const PRIVATE_PACKAGE_ROOT: &str = "/data/local/tmp/ksight/packages";
const PUBLIC_PACKAGE_ROOT: &str = "/storage/emulated/0/Download/dexDump";

/// Plaintext `L...;` names found inside a `dexdata0` body.
///
/// The sidecar holds the names. They are not `class_defs` and not decrypted methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedPlaintextNames {
    /// SHA-256 of the DEX image that contained the names.
    pub sha256: String,
    /// Path of the name list, relative to the dump root.
    pub sidecar: String,
    /// Unique names written.
    pub count: usize,
    /// True when the scan stopped at the name cap.
    pub truncated: bool,
    /// Names containing `SplashActivity`, kept in the report so the launcher is visible without the sidecar.
    #[serde(default)]
    pub splash_names: Vec<String>,
    /// What this list is, and what it is not.
    pub note: String,
}

/// Defined dynamic functions parsed from a retained ELF mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicSymbolIndex {
    /// Path relative to the dump root.
    pub relative_path: String,
    /// Defined functions whose dynsym entry and string were inside the retained bytes.
    pub defined_function_count: usize,
    /// Bounded name sample. The count is the full parsed set.
    #[serde(default)]
    pub names: Vec<String>,
    /// `defined_dynsym_functions_in_retained_bytes` or `dynsym_not_in_retained_bytes`.
    pub status: String,
}

/// Exported JNI symbols observed in a dumped ELF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpJniExport {
    /// Path relative to the dump root.
    pub relative_path: String,
    /// `Java_*` and `JNI_OnLoad` dynamic symbols. Empty means stripped / RegisterNatives-only.
    #[serde(default)]
    pub names: Vec<String>,
}

/// One sensitive evidence file intentionally retained for operator review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpEvidenceFile {
    /// Path relative to the package dump root.
    pub relative_path: String,
    /// `plaintext_candidate` or `key_candidate`.
    pub content_class: String,
    /// Exact file size.
    pub bytes: u64,
    /// SHA-256 of the retained bytes.
    pub sha256: String,
    /// Candidates are never promoted to confirmed secrets by the collector.
    pub confirmed: bool,
}

/// One paused `/proc/<pid>/mem` copy recorded by dump-package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Target process.
    pub pid: u32,
    /// True when `SIGSTOP` was applied for the copy.
    #[serde(default)]
    pub paused: bool,
    /// True when the copy ran without a pause (pages may tear).
    #[serde(default)]
    pub torn: bool,
    /// Wall milliseconds of the copy window.
    #[serde(default)]
    pub elapsed_ms: u64,
    /// Adjacent same-path maps joined before a DEX/blob copy.
    #[serde(default)]
    pub stitched_spans: u32,
    /// In-memory DEX/CDEX images copied in this snapshot.
    #[serde(default)]
    pub memory_images: u32,
    /// Heap-blob DEX images copied in this snapshot.
    #[serde(default)]
    pub blob_dex: u32,
}

/// One mapped TLS/crypto library and whether Inspect will try `SSL_write`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsStackObservation {
    /// `conscrypt_system`, `cronet`, `app_libssl`, `flutter`, ...
    pub kind: String,
    /// Mapped or dumped ELF path.
    pub path: String,
    /// True when `--inspect-tls` will look for exported `SSL_write` on this ELF.
    pub inspect_tries_ssl_write: bool,
}

/// One file-backed DEX/APK/JAR/SO row from `/proc/<pid>/maps` order.
///
/// This is mapped order, not `ClassLoader` load order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedCodeEntry {
    /// Process that owned the mapping.
    pub pid: u32,
    /// 1-based order among code mappings of that process.
    pub order: u32,
    /// Inclusive mapping start.
    pub start: u64,
    /// Exclusive mapping end.
    pub end: u64,
    /// `/proc/<pid>/maps` pathname.
    pub path: String,
}

/// One DEX/APK/JAR observation with a path-derived `ClassLoader` role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeLoaderEntry {
    /// Process that owned the mapping or fd.
    pub pid: u32,
    /// 1-based order within `origin`.
    pub order: u32,
    /// `boot`, `install`, `secondary`, `in_memory`, or `unknown`.
    pub role: String,
    /// `maps`, `fd`, or `art_open`.
    pub origin: String,
    /// Path, memfd label, or ART Open path hint.
    pub path: String,
    /// Inclusive mapping start, when origin is `maps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<u64>,
    /// Exclusive mapping end, when origin is `maps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
    /// maps inode, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    /// `/proc/<pid>/fd` number, when origin is `fd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    /// Size argument from ART `Open(uint8_t*, size_t)`, when origin is `art_open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_bytes: Option<u64>,
    /// Dump artifact path joined to this ART Open (correlated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_relative_path: Option<String>,
    /// SHA-256 of the joined dump artifact, when hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_sha256: Option<String>,
}

/// Result of bounded package-root retention.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageRetentionReport {
    /// Bytes before pruning.
    pub before_bytes: u64,
    /// Bytes after pruning.
    pub after_bytes: u64,
    /// Package directories removed, oldest first.
    pub removed: Vec<String>,
}

/// Keep a bounded number of recent package dumps under one approved device root.
///
/// At least the newest package is retained even when it alone exceeds the byte
/// policy. This makes capacity pressure visible without deleting the dump that
/// the operator just requested.
///
/// # Errors
///
/// Returns for an unapproved root or when inventory/deletion I/O fails.
pub fn prune_package_dumps(
    root: &Path,
    max_total_bytes: u64,
    keep: usize,
) -> Result<PackageRetentionReport> {
    let root_text = root.to_string_lossy();
    if root_text != PRIVATE_PACKAGE_ROOT && root_text != PUBLIC_PACKAGE_ROOT {
        bail!("package retention root is not approved: {}", root.display());
    }
    if !root.exists() {
        return Ok(PackageRetentionReport::default());
    }
    let mut entries = std::fs::read_dir(root)?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| {
            let path = entry.path();
            let bytes = tree_bytes(&path);
            let created = package_created_ms(&path);
            (path, bytes, created)
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, _, created)| *created);
    let before_bytes = entries
        .iter()
        .fold(0_u64, |total, (_, bytes, _)| total.saturating_add(*bytes));
    let mut after_bytes = before_bytes;
    let mut removed = Vec::new();
    let keep = keep.max(1);
    while entries.len() > 1
        && (entries.len() > keep || (max_total_bytes != 0 && after_bytes > max_total_bytes))
    {
        let (path, bytes, _) = entries.remove(0);
        std::fs::remove_dir_all(&path)?;
        after_bytes = after_bytes.saturating_sub(bytes);
        removed.push(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_owned(),
        );
    }
    Ok(PackageRetentionReport {
        before_bytes,
        after_bytes,
        removed,
    })
}

fn package_created_ms(path: &Path) -> u64 {
    std::fs::read_to_string(path.join("dump-report.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("created_unix_ms")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            path.metadata()
                .ok()?
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        })
        .unwrap_or(0)
}

/// Summary written by `ksightd dump-package`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageDumpReport {
    /// Schema identifier; absent in legacy reports.
    #[serde(default)]
    pub schema_version: String,
    /// Agent semantic version that produced or recatalogued this document.
    #[serde(default)]
    pub agent_version: String,
    /// Unix milliseconds when this document was created or recatalogued.
    #[serde(default)]
    pub created_unix_ms: u64,
    /// Android package name.
    pub package: String,
    /// `/data/app/...` directory that owned the base APK.
    #[serde(default)]
    pub install_dir: Option<String>,
    /// Copied APK files.
    #[serde(default)]
    pub apk_files: usize,
    /// Copied files under `lib/`.
    #[serde(default)]
    pub native_libs: usize,
    /// Copied oat/vdex/odex files.
    #[serde(default)]
    pub oat_files: usize,
    /// `classes*.dex` extracted from the APK.
    #[serde(default)]
    pub apk_dex: usize,
    /// Whether the package was force-stopped and launched.
    #[serde(default)]
    pub launched: bool,
    /// Live PIDs dumped after copy/launch.
    #[serde(default)]
    pub pids: Vec<u32>,
    /// In-memory DEX/CDEX images.
    #[serde(default)]
    pub memory_images: usize,
    /// In-memory VDEX images.
    #[serde(default)]
    pub vdex_images: usize,
    /// Files copied from `/proc/<pid>/fd`.
    #[serde(default)]
    pub fd_images: usize,
    /// Loaded app/packer `.so` copies.
    #[serde(default)]
    pub runtime_libs: usize,
    /// Packer/VMP writable/executable regions copied from live maps.
    #[serde(default)]
    pub packer_regions: usize,
    /// HTTP/JSON-looking windows copied from anonymous process memory.
    #[serde(default)]
    pub plaintext_windows: usize,
    /// Signing/crypto marker windows under `runtime/crypto-windows/` (local only).
    #[serde(default)]
    pub crypto_windows: usize,
    /// Window evidence writes that failed; not included in retained window counts.
    #[serde(default)]
    pub memory_window_write_failures: usize,
    /// IO failures in bounded memory window scans.
    #[serde(default)]
    pub memory_window_read_failures: usize,
    /// EOF short reads in window scans; IO errors are counted separately.
    #[serde(default)]
    pub memory_window_short_reads: usize,
    /// Followed packer BSS/heap key slots.
    #[serde(default)]
    pub key_slots: usize,
    /// `dexdata0` images that decrypted to DEX magic.
    #[serde(default)]
    pub secneo_decrypted: usize,
    /// Jadxable DEX files written under `apk-dex/split` and `readable-dex`.
    #[serde(default)]
    pub readable_dex: usize,
    /// Hex-encoded 16-byte SM4 key recovered from GOT/heap, if any.
    #[serde(default)]
    pub recovered_sm4_key: Option<String>,
    /// DEX images harvested from payload-sized process heaps.
    #[serde(default)]
    pub runtime_blob_dex: usize,
    /// Native/DEX files taken from APK `assets/` (ijiami `libexec`, etc.).
    #[serde(default)]
    pub asset_files: usize,
    /// Bounded CE app-private files (`shared_prefs` / `databases` / `files` / `no_backup`).
    #[serde(default)]
    pub private_files: usize,
    /// UUID for this dump; graph nodes are keyed under it.
    #[serde(default)]
    pub dump_id: String,
    /// DEX/SO files bound to the process instance and optional VMA.
    #[serde(default)]
    pub artifacts: Vec<ksight_core::DumpArtifact>,
    /// Content-addressed DEX identities with every retained path/PID/VMA observation.
    #[serde(default)]
    pub dex_sets: Vec<ksight_core::DexArtifactSet>,
    /// Package-wide logical DEX index; physical evidence files remain independent.
    #[serde(default)]
    pub dex_index: ksight_core::PackageDexIndex,
    /// Deterministic class-level ownership summary and per-DEX explanations.
    #[serde(default)]
    pub dex_ownership: ksight_core::DexOwnershipReport,
    /// Android-registered component classes that were also found in collected DEX declarations.
    #[serde(default)]
    pub registered_component_classes: Vec<String>,
    /// Version of the embedded SO/framework identification rules.
    #[serde(default)]
    pub native_rule_version: String,
    /// Candidate shell/packer and crypto-framework matches from native artifacts.
    #[serde(default)]
    pub native_framework_matches: Vec<ksight_core::NativeFrameworkMatch>,
    /// Correlated process→artifact graph for this dump (not L0 syscall proof).
    #[serde(default)]
    pub graph: ksight_core::SessionGraph,
    /// Sensitive candidate files retained by explicit package-dump operation.
    #[serde(default)]
    pub sensitive_files: Vec<DumpEvidenceFile>,
    /// HTTP/1, HTTP/2 HPACK, JSON, and URL rows parsed from `runtime/plaintext` heap windows. Token values redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_calls: Vec<ksight_core::HttpCallActivity>,
    /// DEX string/method names that match HTTP catalog paths. Correlated, not JNI execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_code_refs: Vec<ksight_core::HttpCodeRef>,
    /// Exported `Java_*` / `JNI_OnLoad` names from dumped ELF. Empty when the SO is stripped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jni_exports: Vec<DumpJniExport>,
    /// Plaintext type names inside `dexdata0`. Not a class table and not decrypted code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packed_plaintext_names: Vec<PackedPlaintextNames>,
    /// Defined dynsym functions from retained ELF mappings. A torn read stays torn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_symbols: Vec<DynamicSymbolIndex>,
    /// Total bytes under this package dump root at catalog time.
    #[serde(default)]
    pub total_bytes: u64,
    /// Unique allocated bytes after exact-content hard-link deduplication.
    #[serde(default)]
    pub physical_bytes: u64,
    /// Logical bytes saved by exact-content hard links.
    #[serde(default)]
    pub deduplicated_bytes: u64,
    /// Accounting semantics; absent in legacy reports. This is inode sharing, not content uniqueness.
    #[serde(default)]
    pub storage_accounting: Option<String>,
    /// Logical lengths counted once per inode, independent of allocated blocks.
    #[serde(default)]
    pub unique_inode_bytes: Option<u64>,
    /// Bounded complete-byte APK member observations; absent in old reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apk_member_evidence: Option<serde_json::Value>,
    /// Honest interpretation and compatibility warnings for clients.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Paused live-memory copies taken during this dump.
    #[serde(default)]
    pub snapshots: Vec<MemorySnapshot>,
    /// `/proc/<pid>/maps` order of apk/dex/jar/so; not `ClassLoader` order.
    #[serde(default)]
    pub mapped_code: Vec<MappedCodeEntry>,
    /// Path/fd/ART-Open derived `ClassLoader` role, not a Java `ClassLoader` instance.
    #[serde(default)]
    pub code_loaders: Vec<CodeLoaderEntry>,
    /// Mapped TLS/crypto stacks. `--inspect-tls` only tries exported `SSL_write`.
    #[serde(default)]
    pub tls_stacks: Vec<TlsStackObservation>,
    /// Adjacent same-path VMAs joined across all live copies.
    #[serde(default)]
    pub stitched_spans: usize,
    /// USB/root environment at dump start. Not proof the app ignored these switches.
    #[serde(default)]
    pub observation_env: crate::dump_guard::DumpObservationEnv,
}

/// Operator flags for [`dump_package_with`].
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct DumpOptions {
    /// Code-only scope disables implicit key probes, generic windows, private stores.
    pub code_only: bool,
    /// New parent contract uses live copies without pausing; standalone CLI retains its explicit policy.
    pub parent_owned: bool,
    /// Exact source from the preceding capture; raw tuple alone grants nothing.
    pub expected_code_sources: Option<Vec<crate::qualified_code::SourceIdentity>>,
    /// Collect keys retained by this evidence operation.
    pub collect_keys: bool,
    /// Collect private retained by this evidence operation.
    pub collect_private: bool,
    /// Collect memory windows retained by this evidence operation.
    pub collect_memory_windows: bool,
    /// Force-stop and launch before live harvest.
    pub launch: bool,
    /// Skip APK/lib/oat install trees; the dest folder is evidence to pull.
    pub runtime_only: bool,
    /// Write dump-ready and yield so a hide-debug wrapper can clear `adb_enabled` before launch.
    pub hide_debug: bool,
    /// If Magisk is present, add the package to `DenyList` for this dump window.
    pub denylist: bool,
}

/// Copy APK/native artifacts and, when the process is live, decrypted images.
///
/// # Errors
///
/// Returns if the package name is invalid, the APK cannot be found, or writes fail.
#[allow(clippy::too_many_lines)]
pub fn dump_package(
    package: &str,
    dest: &Path,
    launch: bool,
    runtime_only: bool,
) -> Result<PackageDumpReport> {
    dump_package_with(
        package,
        dest,
        &DumpOptions {
            launch,
            runtime_only,
            ..DumpOptions::default()
        },
    )
}

fn static_hash(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    if f.metadata()?.len() > 512 * 1024 * 1024 {
        bail!("static hash size bound");
    }
    let mut hash = Sha256::new();
    let mut block = vec![0_u8; 65_536];
    loop {
        let n = f.read(&mut block)?;
        if n == 0 {
            break;
        }
        hash.update(&block[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn reuse_static_apk(source: &Path, destination: &Path, size: u64, hash: &str) -> Result<()> {
    if source
        .ancestors()
        .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
        || std::fs::metadata(source)?.len() != size
        || static_hash(source)? != hash
    {
        bail!("static cache complete bytes mismatch");
    }
    ksight_core::output_budget::charge(destination, 0)?;
    std::fs::create_dir_all(destination.parent().context("static destination parent")?)?;
    std::fs::hard_link(source, destination)?;
    if static_hash(destination)? != hash {
        bail!("static cache changed during reuse");
    }
    Ok(())
}
fn static_cache_for_package(v: serde_json::Value, package: &str) -> Result<serde_json::Value> {
    if v["schema"] != "kernsight.static-evidence-cache/v1"
        || v["apks"].as_array().is_none_or(|a| a.len() > 16)
    {
        bail!("static cache manifest identity/count invalid");
    }
    if v["package"] != package {
        return Ok(serde_json::json!({"apks":[]}));
    }
    Ok(v)
}
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "Android ZIP member names are intentionally case-sensitive."
)]
fn reference_static_apks(package: &str, apks: &[PathBuf], dest: &Path) -> Result<usize> {
    let config = crate::runtime_paths::root().join("static-evidence-cache.json");
    let cache: serde_json::Value = if config.exists() {
        if std::fs::symlink_metadata(&config)?.file_type().is_symlink()
            || std::fs::metadata(&config)?.len() > 16384
        {
            bail!("static cache manifest bound");
        }
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&config)?)?;
        static_cache_for_package(v, package)?
    } else {
        serde_json::json!({"apks":[]})
    };
    if apks.len() > 16 {
        bail!("static APK count bound");
    }
    let mut refs = Vec::new();
    let mut retained = 0;
    for apk in apks {
        let bytes = std::fs::metadata(apk)?.len();
        if bytes > 512 * 1024 * 1024 {
            let mut members = Vec::new();
            let mut eligible = 0usize;
            if let Ok(mut archive) = zip::ZipArchive::new(std::fs::File::open(apk)?) {
                for index in 0..archive.len() {
                    let Ok(entry) = archive.by_index(index) else {
                        continue;
                    };
                    if entry.name().ends_with(".dex")
                        || (entry.name().starts_with("lib/") && entry.name().ends_with(".so"))
                    {
                        eligible += 1;
                        if members.len() < 256 {
                            members.push(serde_json::json!({"name":entry.name().chars().take(256).collect::<String>(),"bytes":entry.size(),"crc32":entry.crc32(),"state":"zip_metadata_only_not_extracted","memory_read":false}));
                        }
                    }
                }
            }
            refs.push(serde_json::json!({"source":apk,"bytes":bytes,"sha256":null,"retained_raw":null,"status":"installed_reference_hash_not_computed_over_512mib","memory_read":false,"members":members,"omitted_members":eligible.saturating_sub(256),"not_extracted_reason":"static hash size bound; runtime copy continues"}));
            continue;
        }
        let hash = static_hash(apk)?;
        let matched = cache["apks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["bytes"] == bytes && v["sha256"] == hash);
        let mut raw = None;
        if let Some(entry) = matched {
            let source = PathBuf::from(
                entry["path"]
                    .as_str()
                    .context("static cache source missing")?,
            );
            if !source.starts_with("/data/local/tmp")
                || !source.to_string_lossy().contains("/captures/")
                || source
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("static cache outside explicit retained capture");
            }
            let name = apk.file_name().context("static APK name")?;
            let target = dest.join("apk").join(name);
            reuse_static_apk(&source, &target, bytes, &hash)?;
            raw = Some(format!("apk/{}", name.to_string_lossy()));
            retained += 1;
        }
        let mut z = zip::ZipArchive::new(std::fs::File::open(apk)?)?;
        let mut members = Vec::new();
        let mut eligible = 0usize;
        for i in 0..z.len() {
            let e = z.by_index(i)?;
            if e.name().ends_with(".dex")
                || (e.name().starts_with("lib/") && e.name().ends_with(".so"))
            {
                eligible += 1;
                if members.len() < 256 {
                    members.push(serde_json::json!({"name":e.name().chars().take(256).collect::<String>(),"bytes":e.size(),"crc32":e.crc32(),"state":"zip_metadata_only_not_extracted","memory_read":false}));
                }
            }
        }
        refs.push(serde_json::json!({"source":apk,"bytes":bytes,"sha256":hash,"retained_raw":raw,"status":if raw.is_some(){"retained_complete_apk_hard_link"}else{"installed_reference_not_retained_snapshot"},"memory_read":false,"members":members,"omitted_members":eligible.saturating_sub(256)}));
    }
    let note = serde_json::json!({"schema":"kernsight.static-references/v1","package":package,"policy":"parent_code_only_reserves_payload_for_runtime; no_bulk_static_extraction","objects":refs,"not_extracted_reason":"runtime_output_budget_reserved","complete_collection":false});
    let bytes = serde_json::to_vec(&note)?;
    if bytes.len() > 256 * 1024 {
        bail!("static reference metadata bound");
    }
    ksight_core::output_budget::write(dest.join("static-references.json"), bytes)?;
    Ok(retained)
}

/// Copy APK/native artifacts with USB-hide / `DenyList` opt-in.
///
/// # Errors
///
/// Returns if the package name is invalid, the APK cannot be found, or writes fail.
#[allow(clippy::too_many_lines)]
pub fn dump_package_with(
    package: &str,
    dest: &Path,
    options: &DumpOptions,
) -> Result<PackageDumpReport> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let qualified_backend = if options.code_only || options.parent_owned {
        Some(crate::qualified_code::Backend::open()?)
    } else {
        None
    };
    if options.parent_owned
        && options
            .expected_code_sources
            .as_ref()
            .is_none_or(Vec::is_empty)
    {
        bail!("parent dump source qualification missing; old/missing source is unknown, not current live PID");
    }
    let launch = options.launch;
    let runtime_only = options.runtime_only;
    validate_package(package)?;
    let window =
        crate::dump_guard::DumpWindow::enter(package, options.hide_debug, options.denylist);
    let observation_env = window.observation_env();
    std::fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    if runtime_only {
        prune_install_trees(dest);
    }
    let apk_paths = apk_paths(package);
    if apk_paths.is_empty() {
        bail!("package {package} is not installed (pm path returned no APK)");
    }
    let mut report = PackageDumpReport {
        schema_version: PACKAGE_DUMP_SCHEMA.to_owned(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_unix_ms: unix_ms(),
        package: package.to_owned(),
        install_dir: apk_paths
            .first()
            .and_then(|path| path.parent())
            .map(|path| path.to_string_lossy().into_owned()),
        apk_files: 0,
        native_libs: 0,
        oat_files: 0,
        apk_dex: 0,
        launched: false,
        pids: Vec::new(),
        memory_images: 0,
        vdex_images: 0,
        fd_images: 0,
        runtime_libs: 0,
        packer_regions: 0,
        plaintext_windows: 0,
        crypto_windows: 0,
        memory_window_write_failures: 0,
        memory_window_read_failures: 0,
        memory_window_short_reads: 0,
        key_slots: 0,
        secneo_decrypted: 0,
        readable_dex: 0,
        recovered_sm4_key: None,
        runtime_blob_dex: 0,
        asset_files: 0,
        private_files: 0,
        dump_id: uuid::Uuid::new_v4().to_string(),
        artifacts: Vec::new(),
        dex_sets: Vec::new(),
        dex_index: ksight_core::PackageDexIndex::default(),
        dex_ownership: ksight_core::DexOwnershipReport::default(),
        registered_component_classes: Vec::new(),
        native_rule_version: String::new(),
        native_framework_matches: Vec::new(),
        graph: ksight_core::SessionGraph::l0_placeholder(),
        sensitive_files: Vec::new(),
        http_calls: Vec::new(),
        http_code_refs: Vec::new(),
        jni_exports: Vec::new(),
        packed_plaintext_names: Vec::new(),
        dynamic_symbols: Vec::new(),
        total_bytes: 0,
        physical_bytes: 0,
        deduplicated_bytes: 0,
        storage_accounting: None,
        unique_inode_bytes: None,
        apk_member_evidence: None,
        warnings: default_dump_warnings(),
        snapshots: Vec::new(),
        mapped_code: Vec::new(),
        code_loaders: Vec::new(),
        tls_stacks: Vec::new(),
        stitched_spans: 0,
        observation_env,
    };

    report.warnings.push(format!("explicit extra capabilities: keys={}, private_stores={}, generic_memory_windows={}; disabled capabilities were not collected",options.collect_keys,options.collect_private,options.collect_memory_windows));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let (Some(backend), Some(sources)) = (&qualified_backend, &options.expected_code_sources) {
        if sources.len() > 8 {
            bail!("candidate source count bound");
        }
        for source in sources {
            source.validate()?;
            if source.package != package {
                bail!("cross-package candidate source");
            }
            backend.record_candidates(source, &dest.join("runtime"))?;
        }
    }
    let static_referenced = options.parent_owned && options.code_only && !runtime_only;
    if static_referenced {
        report.apk_files = reference_static_apks(package, &apk_paths, dest)?;
        report.warnings.push("Static DEX/SO members referenced, not bulk-extracted; runtime payload budget preserved; references are not memory recovery".into());
    }
    if !runtime_only && !static_referenced {
        let apk_dir = dest.join("apk");
        std::fs::create_dir_all(&apk_dir)?;
        let mut install_dirs = Vec::<PathBuf>::new();
        for apk in &apk_paths {
            let name = apk
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("base.apk");
            copy_capped_path(apk, &apk_dir.join(name), MAX_APK_BYTES)?;
            report.apk_files = report.apk_files.saturating_add(1);
            if let Some(parent) = apk.parent() {
                if !install_dirs.iter().any(|existing| existing == parent) {
                    install_dirs.push(parent.to_path_buf());
                }
            }
            let extracted = ksight_core::extract_apk_dex(apk, &dest.join("apk-dex"))?;
            report.apk_dex = report.apk_dex.saturating_add(extracted.len());
            let packed = ksight_core::extract_apk_packed_native(apk, &dest.join("apk-assets"))?;
            report.asset_files = report.asset_files.saturating_add(packed.len());
        }
        for dir in &install_dirs {
            report.native_libs = report.native_libs.saturating_add(copy_tree(
                &dir.join("lib"),
                &dest.join("lib"),
                MAX_TREE_FILE_BYTES,
            )?);
            report.oat_files = report.oat_files.saturating_add(copy_tree(
                &dir.join("oat"),
                &dest.join("oat"),
                MAX_TREE_FILE_BYTES,
            )?);
        }
        // After the install tree so split-APK `lib/<abi>` fills gaps instead of
        // duplicating `arm64-v8a/` next to the extracted `arm64/` ISA dir.
        for apk in &apk_paths {
            let from_apk = ksight_core::extract_apk_native_libs(apk, &dest.join("lib"))?;
            report.native_libs = report.native_libs.saturating_add(from_apk.len());
        }
        report.native_libs = report
            .native_libs
            .saturating_add(copy_data_code_cache(package, &dest.join("data-cache"))?);
    }

    let runtime = dest.join("runtime");
    let _ = std::fs::remove_dir_all(runtime.join("packer-keys"));
    let mut art_watch = None;
    let (pids, live_key) = if !options.collect_keys {
        window.mark_ready_and_yield();
        report.observation_env = window.observation_env();
        if launch {
            start_package(package);
            report.launched = true;
        }
        (pids_for_package(package), LiveKeyPoll::default())
    } else if launch {
        force_stop_package(package);
        std::thread::sleep(Duration::from_millis(250));
        let stale = pids_for_package(package);
        let package_name = package.to_owned();
        let runtime_path = runtime.clone();
        let handle = std::thread::spawn(move || {
            poll_fresh_package_keys(&package_name, &runtime_path, &stale)
        });
        let watch_package = package.to_owned();
        let watch_runtime = runtime.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        art_watch = Some(std::thread::spawn(move || {
            crate::inspect_runtime::record_art_dex_opens_with_ready(
                &watch_package,
                &watch_runtime,
                Path::new("/data/local/tmp/ksight/uprobe_regs.bpf.o"),
                Duration::from_secs(45),
                Some(ready_tx),
            )
        }));
        let _ = ready_rx.recv_timeout(Duration::from_secs(20));
        window.mark_ready_and_yield();
        report.observation_env = window.observation_env();
        start_package(package);
        report.launched = true;
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("SM4 poll thread panicked"))?
    } else {
        window.mark_ready_and_yield();
        report.observation_env = window.observation_env();
        poll_package_keys(package, &runtime)
    };
    let mut pids = rank_package_pids(package, pids);
    if launch {
        std::thread::sleep(Duration::from_millis(800));
        pids = merge_live_package_pids(package, pids);
    }
    if let Some(sources) = &options.expected_code_sources {
        for source in sources {
            source.validate()?;
            if source.package != package {
                bail!("cross-package qualified dump source");
            }
        }
        pids.retain(|pid| sources.iter().any(|s| s.pid == *pid));
        if pids.is_empty() {
            bail!("previous qualified task absent; no numeric replacement");
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if qualified_backend.is_some() && options.expected_code_sources.is_none() {
        pids = qualified_backend
            .as_ref()
            .unwrap()
            .main_pid(package)?
            .into_iter()
            .collect();
    }
    report.pids.clone_from(&pids);
    report.key_slots = report.key_slots.saturating_add(live_key.slots);
    report.runtime_blob_dex = report.runtime_blob_dex.saturating_add(live_key.blob_dex);
    if let Some(key) = live_key.recovered {
        report.recovered_sm4_key = Some(hex_key(key));
    }
    #[allow(unused_mut)]
    let mut budget_closed = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    for pid in pids.iter().copied().take(8) {
        if Instant::now() >= deadline {
            break;
        }
        let live = {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if let Some(backend) = &qualified_backend {
                let expected = match &options.expected_code_sources {
                    Some(s) => s.iter().find(|s| s.pid == pid).cloned().ok_or_else(|| {
                        anyhow::anyhow!("dump PID absent from preceding qualified source")
                    })?,
                    None => backend.qualify(package, pid, false)?.identity,
                };
                match copy_qualified_or_stop(backend, &expected, &runtime, deadline)? {
                    Some(copied) => copied,
                    None => {
                        budget_closed = true;
                        break;
                    }
                }
            } else {
                crate::dexdump::dump_live_process_with_pause(
                    pid,
                    &runtime,
                    deadline,
                    options.collect_keys,
                    options.collect_memory_windows,
                    !(options.code_only || options.parent_owned),
                )
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                crate::dexdump::dump_live_process_with_pause(
                    pid,
                    &runtime,
                    deadline,
                    options.collect_keys,
                    options.collect_memory_windows,
                    !(options.code_only || options.parent_owned),
                )
            }
        };
        accumulate_live(&mut report, live);
    }
    if !budget_closed && !pids.is_empty() {
        std::thread::sleep(Duration::from_millis(500));
        pids = merge_live_package_pids(package, pids);
        report.pids.clone_from(&pids);
        let mid = Instant::now() + Duration::from_secs(8);
        for pid in pids.iter().copied().take(8) {
            if Instant::now() >= mid {
                break;
            }
            let live = {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if let Some(backend) = &qualified_backend {
                    let expected = match &options.expected_code_sources {
                        Some(s) => s.iter().find(|s| s.pid == pid).cloned().ok_or_else(|| {
                            anyhow::anyhow!("dump PID absent from preceding qualified source")
                        })?,
                        None => backend.qualify(package, pid, false)?.identity,
                    };
                    match copy_qualified_or_stop(backend, &expected, &runtime, mid)? {
                        Some(copied) => copied,
                        None => {
                            budget_closed = true;
                            break;
                        }
                    }
                } else {
                    crate::dexdump::dump_live_process_with_pause(
                        pid,
                        &runtime,
                        mid,
                        options.collect_keys,
                        options.collect_memory_windows,
                        !(options.code_only || options.parent_owned),
                    )
                }
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                {
                    crate::dexdump::dump_live_process_with_pause(
                        pid,
                        &runtime,
                        mid,
                        options.collect_keys,
                        options.collect_memory_windows,
                        !(options.code_only || options.parent_owned),
                    )
                }
            };
            accumulate_live(&mut report, live);
        }
        if budget_closed {
            // Payload budget is closed. The next pass would only read more memory.
        } else {
            std::thread::sleep(Duration::from_secs(2));
            let second = Instant::now() + Duration::from_secs(15);
            for pid in pids.iter().copied().take(8) {
                if Instant::now() >= second {
                    break;
                }
                let live = {
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    if let Some(backend) = &qualified_backend {
                        let expected = match &options.expected_code_sources {
                            Some(s) => {
                                s.iter().find(|s| s.pid == pid).cloned().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "dump PID absent from preceding qualified source"
                                    )
                                })?
                            }
                            None => backend.qualify(package, pid, false)?.identity,
                        };
                        match copy_qualified_or_stop(backend, &expected, &runtime, second)? {
                            Some(copied) => copied,
                            None => {
                                budget_closed = true;
                                break;
                            }
                        }
                    } else {
                        crate::dexdump::dump_live_process_with_pause(
                            pid,
                            &runtime,
                            second,
                            options.collect_keys,
                            options.collect_memory_windows,
                            !(options.code_only || options.parent_owned),
                        )
                    }
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    {
                        crate::dexdump::dump_live_process_with_pause(
                            pid,
                            &runtime,
                            second,
                            options.collect_keys,
                            options.collect_memory_windows,
                            !(options.code_only || options.parent_owned),
                        )
                    }
                };
                accumulate_live(&mut report, live);
            }
        }
    }
    if let Some(watch) = art_watch {
        let _ = watch.join();
    }
    if options.collect_private {
        report.private_files = copy_app_private(package, &dest.join("data-private")).unwrap_or(0);
    }
    let (decrypted, recovered_key) = if options.collect_keys {
        unpack_secneo(dest)
    } else {
        (0, None)
    };
    report.secneo_decrypted = decrypted;
    if report.recovered_sm4_key.is_none() {
        report.recovered_sm4_key = recovered_key.map(hex_key);
    }
    report.readable_dex = ksight_core::publish_readable_dex(dest).unwrap_or(0);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !budget_closed {
        harvest_admitted_anonymous_dex(
            dest,
            qualified_backend.as_ref(),
            options.expected_code_sources.as_deref(),
            deadline,
        );
    }
    recover_secneo_payload(dest, package, &report.pids);
    deduplicate_code_evidence(dest)?;
    if runtime_only {
        prune_install_trees(dest);
    }
    finalize_catalog(&mut report, dest)?;
    write_evidence_index(dest, &report);
    if !report.observation_env.denylist_detail.is_empty() {
        report
            .warnings
            .push(report.observation_env.denylist_detail.clone());
    }
    drop(window);
    if static_referenced {
        ksight_core::output_budget::record_failure(dest, "static_members_referenced_not_extracted");
    }
    Ok(report)
}

/// Rebuild artifacts and the correlated graph from files already on disk.
///
/// This path does not open a live process, does not harvest anonymous memory,
/// and does not start a qualified copy.
///
/// # Errors
///
/// Returns if the dump directory cannot be read or `dump-report.json` cannot be written.
pub fn recatalog_package(dest: &Path) -> Result<PackageDumpReport> {
    let report_path = dest.join("dump-report.json");
    let mut report = if report_path.exists() {
        let text = std::fs::read_to_string(&report_path)
            .with_context(|| format!("read {}", report_path.display()))?;
        serde_json::from_str::<PackageDumpReport>(&text)
            .with_context(|| format!("parse {}", report_path.display()))?
    } else {
        let package = dest
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("dump directory has no package name"))?;
        validate_package(package)?;
        PackageDumpReport {
            schema_version: PACKAGE_DUMP_SCHEMA.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_unix_ms: unix_ms(),
            package: package.to_owned(),
            install_dir: None,
            apk_files: 0,
            native_libs: 0,
            oat_files: 0,
            apk_dex: 0,
            launched: false,
            pids: Vec::new(),
            memory_images: 0,
            vdex_images: 0,
            fd_images: 0,
            runtime_libs: 0,
            packer_regions: 0,
            plaintext_windows: 0,
            crypto_windows: 0,
            memory_window_write_failures: 0,
            memory_window_read_failures: 0,
            memory_window_short_reads: 0,
            key_slots: 0,
            secneo_decrypted: 0,
            readable_dex: 0,
            recovered_sm4_key: None,
            runtime_blob_dex: 0,
            asset_files: 0,
            private_files: 0,
            dump_id: uuid::Uuid::new_v4().to_string(),
            artifacts: Vec::new(),
            dex_sets: Vec::new(),
            dex_index: ksight_core::PackageDexIndex::default(),
            dex_ownership: ksight_core::DexOwnershipReport::default(),
            registered_component_classes: Vec::new(),
            native_rule_version: String::new(),
            native_framework_matches: Vec::new(),
            graph: ksight_core::SessionGraph::l0_placeholder(),
            sensitive_files: Vec::new(),
            http_calls: Vec::new(),
            http_code_refs: Vec::new(),
            jni_exports: Vec::new(),
            packed_plaintext_names: Vec::new(),
            dynamic_symbols: Vec::new(),
            total_bytes: 0,
            physical_bytes: 0,
            deduplicated_bytes: 0,
            storage_accounting: None,
            unique_inode_bytes: None,
            apk_member_evidence: None,
            warnings: default_dump_warnings(),
            snapshots: Vec::new(),
            mapped_code: Vec::new(),
            code_loaders: Vec::new(),
            tls_stacks: Vec::new(),
            stitched_spans: 0,
            observation_env: crate::dump_guard::DumpObservationEnv::default(),
        }
    };
    PACKAGE_DUMP_SCHEMA.clone_into(&mut report.schema_version);
    env!("CARGO_PKG_VERSION").clone_into(&mut report.agent_version);
    report.created_unix_ms = unix_ms();
    if report.dump_id.is_empty() {
        report.dump_id = uuid::Uuid::new_v4().to_string();
    }
    deduplicate_code_evidence(dest)?;
    finalize_catalog(&mut report, dest)?;
    Ok(report)
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
fn finalize_catalog(report: &mut PackageDumpReport, dest: &Path) -> Result<()> {
    recount_static_trees(report, dest);
    report.artifacts = catalog_dump(dest);
    attach_artifact_hashes(dest, &mut report.artifacts);
    (report.dex_sets, report.dex_index) = build_dex_sets(dest, &report.artifacts);
    report.registered_component_classes =
        catalog_registered_component_classes(&report.package, &report.dex_sets, dest);
    let ownership_context = ksight_core::DexOwnershipContext {
        registered_component_classes: report.registered_component_classes.clone(),
    };
    report.dex_ownership = ksight_core::classify_dex_ownership_with_context(
        &report.package,
        &report.dex_sets,
        &ownership_context,
    );
    write_dex_classification_index(dest, &report.dex_ownership)?;
    report.native_rule_version = ksight_core::native_framework_rule_version();
    report.native_framework_matches = ksight_core::classify_native_frameworks(&report.artifacts);
    report.sensitive_files = catalog_sensitive_files(dest);
    report.http_calls = catalog_plaintext_http_calls(dest, &report.package);
    report
        .http_calls
        .extend(ksight_core::http_calls_from_private_dir(
            &dest.join("data-private"),
            &report.package,
        ));
    ksight_core::sort_http_catalog(&mut report.http_calls);
    report.http_code_refs =
        ksight_core::correlate_http_calls_to_dex(&report.http_calls, &report.dex_sets);
    report.jni_exports = catalog_jni_exports(dest, &report.artifacts);
    report.packed_plaintext_names = write_packed_plaintext_names(dest, &report.dex_sets);
    report.dynamic_symbols = catalog_dynamic_symbols(dest, &report.artifacts);
    report.snapshots = catalog_snapshots(dest);
    report.mapped_code = catalog_mapped_code(dest);
    report.code_loaders = catalog_code_loaders(dest);
    report.tls_stacks = catalog_tls_stacks(&report.mapped_code, &report.artifacts);
    if report
        .tls_stacks
        .iter()
        .any(|row| !row.inspect_tries_ssl_write)
    {
        report.warnings.push(
            "a mapped TLS stack is not a Conscrypt/libssl/libcronet SSL_write target; --inspect-tls will not copy that plaintext"
                .to_owned(),
        );
    }
    join_art_opens(&mut report.code_loaders, &report.artifacts);
    if report.stitched_spans == 0 {
        report.stitched_spans = report.snapshots.iter().fold(0_usize, |total, row| {
            total.saturating_add(usize::try_from(row.stitched_spans).unwrap_or(0))
        });
    }
    let mut member_notes = Vec::new();
    let mut omitted_notes = 0_u64;
    if let Ok(entries) = std::fs::read_dir(dest.join("code-evidence")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if member_notes.len() >= 256
                || !path.is_file()
                || path.metadata().map_or(true, |m| m.len() > 32768)
            {
                omitted_notes += 1;
                continue;
            }
            match std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            {
                Some(note) if note["schema"] == "kernsight.apk-member-evidence/v1" => {
                    member_notes.push(note);
                }
                _ => omitted_notes += 1,
            }
        }
    }
    if !member_notes.is_empty() || omitted_notes > 0 {
        report.apk_member_evidence = Some(
            serde_json::json!({"schema":"kernsight.apk-member-index/v1","observations":member_notes,"omitted_observations":omitted_notes,"status":if omitted_notes>0{"bounded_incomplete"}else{"producer_observations"}}),
        );
    }
    report.total_bytes = tree_bytes(dest);
    report.physical_bytes = tree_physical_bytes(dest);
    report.unique_inode_bytes = Some(tree_unique_inode_bytes(dest));
    report.storage_accounting = Some("kernsight.inode-accounting/v1".to_owned());
    report.deduplicated_bytes = report
        .total_bytes
        .saturating_sub(report.unique_inode_bytes.unwrap_or(report.total_bytes));
    PACKAGE_DUMP_SCHEMA.clone_into(&mut report.schema_version);
    env!("CARGO_PKG_VERSION").clone_into(&mut report.agent_version);
    if report.created_unix_ms == 0 {
        report.created_unix_ms = unix_ms();
    }
    report.warnings = default_dump_warnings();
    for name in ["truncated-dex.json", "dexdata-live.json"] {
        if let Ok(text) = std::fs::read_to_string(dest.join("runtime").join(name)) {
            if let Ok(notes) = serde_json::from_str::<Vec<String>>(&text) {
                report.warnings.extend(notes);
            }
        }
    }
    let dump_uuid = uuid::Uuid::parse_str(&report.dump_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let mut graph = ksight_core::SessionGraph::from_package_dump(
        dump_uuid,
        &report.package,
        &report.pids,
        &report.artifacts,
    );
    heal_blob_sidecars(dest, &report.artifacts);
    let maps = maps_as_observed(dest, &report.artifacts);
    graph.correlate_dump_vmas(dump_uuid, &report.artifacts, &maps);
    graph.attach_art_open_joins(
        dump_uuid,
        &report.package,
        &art_open_joins(&report.code_loaders, &report.artifacts),
    );
    report.graph = graph;
    write_dump_howto(dest, &report.package);
    let report_path = dest.join("dump-report.json");
    let body = serde_json::to_vec_pretty(&report)?;
    // A closed budget refuses the catalog write. Do not fall back to an unbudgeted write.
    ksight_core::output_budget::write(&report_path, &body)?;
    Ok(())
}

fn default_dump_warnings() -> Vec<String> {
    vec![
        "plaintext_windows, crypto_windows, and key_slots are bounded candidate counts, not confirmed secrets"
            .to_owned(),
        "runtime/crypto-windows are signing/header-encrypt heap cuts (X-Sign/OpenPlatformEncrypt/appKey/…); local dump artifacts only — not mirrored to Burp"
            .to_owned(),
        "dump http_calls are parsed from runtime/plaintext heap windows and data-private CE/DE copies (HTTP/1, JSON, embedded URLs, or HTTP/2 HEADERS HPACK; NUL or CRLF). Heap rows are correlated, not Inspect SSL_write. Responses have no URL path. Windows are an 8192-byte cut around HTTP/1.1, GET/POST, https://, \"url\", /api/, /login, /mbfront, or :path/:authority then trimmed of trailing NULs; mostly-zero slices are not written."
            .to_owned(),
        "http_code_refs match HTTP host/path to DEX string-pool and class->method names. That is correlated identifier overlap, not an ART/JNI call stack. jni_exports lists dynsym Java_*/JNI_OnLoad; empty names mean the SO is stripped. Inspect --inspect-adapter jni_plaintext attaches JNINativeInterface GetStringUTFChars/NewStringUTF/GetByteArray* via exported GetFunctionTable and jni.h slots, not Java_* exports."
            .to_owned(),
        "package dump uses root procfs memory access and is L2 forensic evidence, not eBPF Observe"
            .to_owned(),
        "each live copy records paused/torn; unpaused discovery races live pages and does not attest stability"
            .to_owned(),
        "stitched VMAs are adjacent same-path maps, not proof of a single mmap"
            .to_owned(),
        "mapped_code is /proc/pid/maps order of apk/dex/jar/so, not ClassLoader load order"
            .to_owned(),
        "code_loaders.role is inferred from maps/fd/ART DexFile Open paths (boot/install/secondary/in_memory), not a Java ClassLoader instance"
            .to_owned(),
        "art_open joined_relative_path/sha256 is correlated (path or size), not proof that a ClassLoader object produced the bytes"
            .to_owned(),
        "packer-keys remain gated on a mapped packer/VMP SO; plaintext windows also scan large anonymous heaps"
            .to_owned(),
        "sensitive candidate files are intentionally retained and published for operator review"
            .to_owned(),
        "hide-debug only clears adb_enabled/developer options; it does not hide root or an unlocked bootloader".to_owned(),
        "denylist is Magisk DenyList add/remove for this dump window when Magisk is present; it is not a root-hide claim".to_owned(),
        "data-private is a bounded copy of CE/DE shared_prefs/databases/files/no_backup (≤512 files, ≤8 MiB each), not a full /data/data image. http(s):// hosts in those XML/JSON/SQLite copies are cataloged as origin=private http_calls; token values are not copied as secrets.".to_owned(),
        "tls_stacks is mapped/dumped ELF classification; --inspect-tls attaches exported SSL_write on libssl.so and libcronet.so only. Cronet/Flutter/mbedTLS without that export stay uncovered".to_owned(),
    ]
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn attach_artifact_hashes(dest: &Path, artifacts: &mut [ksight_core::DumpArtifact]) {
    for artifact in artifacts {
        let path = dest.join(&artifact.relative_path);
        artifact.sha256 = if let Some(offset) = artifact.dex_offset {
            sha256_range(&path, offset, artifact.bytes)
        } else {
            sha256_file(&path)
        };
    }
}

fn build_dex_sets(
    dest: &Path,
    artifacts: &[ksight_core::DumpArtifact],
) -> (
    Vec<ksight_core::DexArtifactSet>,
    ksight_core::PackageDexIndex,
) {
    let mut groups = BTreeMap::<(String, u64), Vec<&ksight_core::DumpArtifact>>::new();
    for artifact in artifacts.iter().filter(|artifact| artifact.kind == "dex") {
        if let Some(sha256) = artifact.sha256.as_ref() {
            groups
                .entry((sha256.clone(), artifact.bytes))
                .or_default()
                .push(artifact);
        }
    }

    let mut sets = Vec::new();
    for ((sha256, bytes), mut observations) in groups {
        observations.sort_by(|left, right| {
            dex_source_priority(right)
                .cmp(&dex_source_priority(left))
                .then(left.relative_path.cmp(&right.relative_path))
        });
        let canonical = observations
            .first()
            .map(|artifact| artifact.relative_path.clone())
            .unwrap_or_default();
        let mut sources = observations
            .iter()
            .map(|artifact| artifact.source.clone())
            .collect::<Vec<_>>();
        sources.sort();
        sources.dedup();
        let semantic = std::fs::read(dest.join(&canonical))
            .ok()
            .and_then(|content| {
                let body = if let Some(offset) = observations
                    .first()
                    .and_then(|artifact| artifact.dex_offset)
                {
                    let start = usize::try_from(offset).ok()?;
                    let end = start.checked_add(usize::try_from(bytes).ok()?)?;
                    content.get(start..end)?
                } else {
                    content.as_slice()
                };
                ksight_core::parse_dex_semantics(body)
            });
        sets.push(ksight_core::DexArtifactSet {
            sha256,
            bytes,
            canonical_relative_path: canonical,
            sources,
            observations: observations
                .into_iter()
                .map(|artifact| ksight_core::DexArtifactObservation {
                    source: artifact.source.clone(),
                    relative_path: artifact.relative_path.clone(),
                    pid: artifact.pid,
                    vma_start: artifact.vma_start,
                    vma_end: artifact.vma_end,
                    map_path: artifact.map_path.clone(),
                    dex_offset: artifact.dex_offset,
                })
                .collect(),
            semantic,
        });
    }
    sets.sort_by(|left, right| {
        right
            .observations
            .len()
            .cmp(&left.observations.len())
            .then(right.bytes.cmp(&left.bytes))
            .then(left.sha256.cmp(&right.sha256))
    });

    let mut class_owners = BTreeMap::<String, BTreeSet<String>>::new();
    let mut method_names = BTreeSet::new();
    let mut method_prototypes = BTreeSet::new();
    let mut semantic_parse_failures = 0_usize;
    let mut semantic_index_truncated = false;
    for set in &sets {
        let Some(semantic) = set.semantic.as_ref() else {
            semantic_parse_failures = semantic_parse_failures.saturating_add(1);
            continue;
        };
        semantic_index_truncated |= semantic.class_descriptors_truncated
            || semantic.method_names_truncated
            || semantic.method_prototypes_truncated;
        for descriptor in &semantic.class_descriptors {
            class_owners
                .entry(descriptor.clone())
                .or_default()
                .insert(set.sha256.clone());
        }
        method_names.extend(semantic.method_names.iter().cloned());
        method_prototypes.extend(semantic.method_prototypes.iter().cloned());
    }
    let class_conflicts = class_owners
        .iter()
        .filter(|(_, owners)| owners.len() > 1)
        .take(512)
        .map(|(descriptor, owners)| ksight_core::DexClassConflict {
            descriptor: descriptor.clone(),
            dex_sha256: owners.iter().cloned().collect(),
        })
        .collect();
    let index = ksight_core::PackageDexIndex {
        unique_dex: sets.len(),
        observations: sets.iter().map(|set| set.observations.len()).sum(),
        indexed_class_samples: class_owners.len(),
        indexed_method_name_samples: method_names.len(),
        indexed_method_prototype_samples: method_prototypes.len(),
        class_conflicts,
        semantic_parse_failures,
        semantic_index_truncated,
    };
    (sets, index)
}

fn dex_source_priority(artifact: &ksight_core::DumpArtifact) -> u8 {
    match artifact.source.as_str() {
        "memory-dex" => 5,
        "heap-blob" => 4,
        "apk-dex" => 3,
        _ => 1,
    }
}

fn catalog_sensitive_files(dest: &Path) -> Vec<DumpEvidenceFile> {
    let mut files = Vec::<DumpEvidenceFile>::new();
    for (relative, class) in [
        ("runtime/plaintext", "plaintext_candidate"),
        ("runtime/crypto-windows", "key_candidate"),
        ("runtime/packer-keys", "key_candidate"),
        ("data-private", "private_store"),
    ] {
        visit_files(&dest.join(relative), &mut |path| {
            // Raw copies and observation notes are catalogued by the evidence
            // browser, but are not additional plaintext/key candidates.
            if (relative == "runtime/plaintext" || relative == "runtime/crypto-windows")
                && path.extension().and_then(|ext| ext.to_str()) != Some("txt")
            {
                return;
            }
            let Ok(relative_path) = path.strip_prefix(dest) else {
                return;
            };
            let Ok(metadata) = path.metadata() else {
                return;
            };
            let Some(sha256) = sha256_file(path) else {
                return;
            };
            if files
                .iter()
                .filter(|file| file.content_class == class)
                .count()
                >= 32
            {
                return;
            }
            files.push(DumpEvidenceFile {
                relative_path: relative_path.to_string_lossy().replace('\\', "/"),
                content_class: class.to_owned(),
                bytes: metadata.len(),
                sha256,
                confirmed: false,
            });
        });
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    files
}

fn catalog_plaintext_http_calls(dest: &Path, package: &str) -> Vec<ksight_core::HttpCallActivity> {
    ksight_core::http_calls_from_plaintext_dir(&dest.join("runtime/plaintext"), package)
}

fn write_packed_plaintext_names(
    dest: &Path,
    sets: &[ksight_core::DexArtifactSet],
) -> Vec<PackedPlaintextNames> {
    let mut out = Vec::new();
    for set in sets {
        let Ok(content) = std::fs::read(dest.join(&set.canonical_relative_path)) else {
            continue;
        };
        let Some(spot) = ksight_core::locate_dexdata0(&content) else {
            continue;
        };
        let start = usize::try_from(spot.header_offset).unwrap_or(0);
        let body = content.get(start..).unwrap_or(&[]);
        let found = ksight_core::plaintext_type_descriptors(body, 100_000);
        if found.names.is_empty() {
            continue;
        }
        let sidecar = format!(
            "metadata/packed-type-descriptors-{}.txt",
            &set.sha256[..16.min(set.sha256.len())]
        );
        let directory = dest.join("metadata");
        if std::fs::create_dir_all(&directory).is_err() {
            continue;
        }
        let text = found.names.join("\n") + "\n";
        if std::fs::write(dest.join(&sidecar), text).is_err() {
            continue;
        }
        let splash_names = found
            .names
            .iter()
            .filter(|name| name.contains("SplashActivity"))
            .take(32)
            .cloned()
            .collect();
        out.push(PackedPlaintextNames {
            sha256: set.sha256.clone(),
            sidecar,
            count: found.names.len(),
            truncated: found.truncated,
            splash_names,
            note: "plaintext L...; names inside dexdata0; not class_defs; bytecode not decrypted"
                .to_owned(),
        });
    }
    out
}

fn catalog_dynamic_symbols(
    dest: &Path,
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<DynamicSymbolIndex> {
    let mut paths = Vec::new();
    for artifact in artifacts.iter().filter(|row| row.kind == "elf") {
        paths.push(dest.join(&artifact.relative_path));
    }
    // Live mappings are stored as runtime/bound-*.code, not *.so.
    if let Ok(entries) = std::fs::read_dir(dest.join("runtime")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if !name.ends_with(".code") || paths.contains(&path) {
                continue;
            }
            let too_big = path.metadata().map_or(true, |meta| {
                meta.len() > 32 * 1024 * 1024 || meta.len() < 64
            });
            if too_big || peek_magic(&path) != "elf" {
                continue;
            }
            paths.push(path);
        }
    }
    let mut out = Vec::new();
    for path in paths.into_iter().take(48) {
        let relative_path = path
            .strip_prefix(dest)
            .map(|value| value.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path.display().to_string());
        if path
            .metadata()
            .map_or(true, |meta| meta.len() > 32 * 1024 * 1024)
        {
            continue;
        }
        let Ok(elf) = crate::elf::inspect_elf(&path) else {
            out.push(DynamicSymbolIndex {
                relative_path,
                defined_function_count: 0,
                names: Vec::new(),
                status: "dynsym_not_in_retained_bytes".to_owned(),
            });
            continue;
        };
        let mut names = elf
            .symbols
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        let status = if names.is_empty() {
            "dynsym_not_in_retained_bytes"
        } else {
            "defined_dynsym_functions_in_retained_bytes"
        };
        let shown = names.iter().take(128).cloned().collect();
        out.push(DynamicSymbolIndex {
            relative_path,
            defined_function_count: names.len(),
            names: shown,
            status: status.to_owned(),
        });
        if out.len() >= 32 {
            break;
        }
    }
    out
}

fn catalog_jni_exports(dest: &Path, artifacts: &[ksight_core::DumpArtifact]) -> Vec<DumpJniExport> {
    let mut out = Vec::new();
    for artifact in artifacts.iter().filter(|row| row.kind == "elf").take(48) {
        let path = dest.join(&artifact.relative_path);
        let Ok(elf) = crate::elf::inspect_elf(&path) else {
            continue;
        };
        let names = elf
            .symbols
            .iter()
            .map(|(name, _)| name.as_str())
            .filter(|name| name.starts_with("Java_") || *name == "JNI_OnLoad")
            .take(24)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if names.is_empty() && !artifact.relative_path.contains("runtime-so") {
            continue;
        }
        if out.len() >= 32 {
            break;
        }
        out.push(DumpJniExport {
            relative_path: artifact.relative_path.clone(),
            names,
        });
    }
    out
}

fn recount_static_trees(report: &mut PackageDumpReport, dest: &Path) {
    report.apk_files = count_regular_files(&dest.join("apk"));
    report.native_libs = count_ext_files(&dest.join("lib"), "so");
    report.oat_files = count_regular_files(&dest.join("oat"));
    report.asset_files = count_regular_files(&dest.join("apk-assets"));
    report.apk_dex = count_shallow_ext(&dest.join("apk-dex"), "dex");
    report.readable_dex = count_ext_files(&dest.join("readable-dex"), "dex");
    report.private_files = count_regular_files(&dest.join("data-private"));
}

fn count_regular_files(root: &Path) -> usize {
    let mut count = 0_usize;
    visit_files(root, &mut |_| {
        count = count.saturating_add(1);
    });
    count
}

fn count_ext_files(root: &Path, ext: &str) -> usize {
    let mut count = 0_usize;
    visit_files(root, &mut |path| {
        if has_ext(path, ext) {
            count = count.saturating_add(1);
        }
    });
    count
}

fn count_shallow_ext(dir: &Path, ext: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| entry.path().is_file() && has_ext(&entry.path(), ext))
        .count()
}

fn tree_bytes(root: &Path) -> u64 {
    let mut bytes = 0_u64;
    visit_files(root, &mut |path| {
        if let Ok(metadata) = path.metadata() {
            bytes = bytes.saturating_add(metadata.len());
        }
    });
    bytes
}

#[cfg(unix)]
fn tree_unique_inode_bytes(root: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    let mut seen = BTreeSet::new();
    let mut bytes = 0_u64;
    visit_files(root, &mut |path| {
        if let Ok(metadata) = path.metadata() {
            if seen.insert((metadata.dev(), metadata.ino())) {
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    });
    bytes
}

#[cfg(not(unix))]
fn tree_unique_inode_bytes(root: &Path) -> u64 {
    tree_bytes(root)
}

#[cfg(unix)]
fn tree_physical_bytes(root: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    let mut seen = BTreeSet::<(u64, u64)>::new();
    let mut bytes = 0_u64;
    visit_files(root, &mut |path| {
        if let Ok(metadata) = path.metadata() {
            if seen.insert((metadata.dev(), metadata.ino())) {
                bytes = bytes.saturating_add(metadata.blocks().saturating_mul(512));
            }
        }
    });
    bytes
}

#[cfg(not(unix))]
fn tree_physical_bytes(root: &Path) -> u64 {
    tree_bytes(root)
}

fn visit_files(root: &Path, visitor: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            visit_files(&path, visitor);
        } else if file_type.is_file() {
            visitor(&path);
        }
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    sha256_range(path, 0, std::fs::metadata(path).ok()?.len())
}

fn sha256_range(path: &Path, offset: u64, len: u64) -> Option<String> {
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut digest = Sha256::new();
    let mut left = len;
    let mut buffer = vec![0_u8; 64 * 1024];
    while left > 0 {
        let want = buffer.len().min(usize::try_from(left).ok()?);
        let read = file.read(&mut buffer[..want]).ok()?;
        if read == 0 {
            return None;
        }
        digest.update(&buffer[..read]);
        left -= u64::try_from(read).ok()?;
    }
    Some(format!("{:x}", digest.finalize()))
}

fn deduplicate_code_evidence(dest: &Path) -> Result<(usize, u64)> {
    let mut candidates = Vec::<PathBuf>::new();
    for root in ["apk-dex", "readable-dex", "runtime", "lib", "apk-assets"] {
        visit_files(&dest.join(root), &mut |path| {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(extension.as_str(), "dex" | "so" | "vdex" | "oat" | "art") {
                candidates.push(path.to_path_buf());
            }
        });
    }
    candidates.sort();
    let mut canonical = BTreeMap::<(String, u64), PathBuf>::new();
    let mut linked = 0_usize;
    let mut saved = 0_u64;
    for path in candidates {
        let metadata = path.metadata()?;
        let bytes = metadata.len();
        let Some(sha256) = sha256_file(&path) else {
            continue;
        };
        let key = (sha256, bytes);
        let Some(source) = canonical.get(&key) else {
            canonical.insert(key, path);
            continue;
        };
        if source == &path {
            continue;
        }
        std::fs::remove_file(&path)?;
        if let Err(link_error) = std::fs::hard_link(source, &path) {
            ksight_core::output_budget::copy(source, &path).with_context(|| {
                format!(
                    "restore {} after hard-link failure ({link_error})",
                    path.display()
                )
            })?;
            continue;
        }
        linked = linked.saturating_add(1);
        saved = saved.saturating_add(bytes);
    }
    Ok((linked, saved))
}

fn write_catalog_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    ksight_core::output_budget::write(path, bytes)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn copy_qualified_or_stop(
    backend: &crate::qualified_code::Backend,
    expected: &crate::qualified_code::SourceIdentity,
    runtime: &Path,
    deadline: Instant,
) -> Result<Option<crate::dexdump::LiveDump>> {
    match backend.copy_code(expected, runtime, deadline) {
        Ok(live) => Ok(Some(live)),
        Err(error) if closed_output_budget(&error) => {
            eprintln!(
                "live copy stopped: {error:#}; retained files will be catalogued and no further process memory will be read"
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn closed_output_budget(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}");
    text.contains("output_budget_exhausted")
        || text.contains("time_budget_exhausted")
        || text.contains("parent_deadline_or_output_exhausted")
}

fn write_dex_classification_index(
    dest: &Path,
    report: &ksight_core::DexOwnershipReport,
) -> Result<()> {
    let root = dest.join("dex-classification");
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    write_catalog_bytes(
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(report)?,
    )?;
    for category in [
        ksight_core::DexOwnershipCategory::Business,
        ksight_core::DexOwnershipCategory::InternalComponent,
        ksight_core::DexOwnershipCategory::DynamicPayload,
        ksight_core::DexOwnershipCategory::ThirdPartySdk,
        ksight_core::DexOwnershipCategory::Mixed,
        ksight_core::DexOwnershipCategory::Unknown,
    ] {
        let directory = root.join(category.directory());
        std::fs::create_dir_all(&directory)?;
        let rows = report
            .entries
            .iter()
            .filter(|entry| entry.category == category)
            .collect::<Vec<_>>();
        write_catalog_bytes(
            &directory.join("index.json"),
            &serde_json::to_vec_pretty(&rows)?,
        )?;
    }
    Ok(())
}

fn write_dump_howto(dest: &Path, package: &str) {
    let text = format!(
        "KernSight package dump: {package}\n\
         \n\
         可读 DEX（jadx）:\n\
         - readable-dex/\n\
         - apk-dex/split/          （含 APK 内 DEX 和冷启动从堆切开的 blob-*.dex）\n\
         \n\
         SO:\n\
         - lib/                    安装目录 .so，以及 APK/split zip 的 lib/<abi>（arm64-v8a→arm64，已有文件不重复）\n\
         - apk-assets/             APK assets 里的壳 SO（爱加密 libexec/libexecmain 等）\n\
         - runtime/runtime-so/     冷启动时进程已加载的 .so 磁盘副本（可写映射里的明文 DEX 在 heap-blob）\n\
         \n\
         其它:\n\
         - apk/                    原始 APK\n\
         - apk-dex/                APK 里的 classes*.dex（可能只是壳 stub）\n\
         - data-private/ce|de/     冷启动后 credential/device-encrypted shared_prefs/databases/files/no_backup（有界，不是完整 /data/data）\n\
         - dump-report.json        计数、artifacts 清单、进程图（correlated；dump VMA overlaps_mmap 对齐 maps，不是 mmap 证明）\n\
         \n\
         主机拉取（整个包名目录就是这一次搜集，不含安装 APK/lib）:\n\
         ksightctl device --serial <SERIAL> pull-package --package {package} --launch --evidence-only\n\
         USB 调试检测: 加 --hide-debug --launch（只关 adb_enabled，不隐 root）\n\
         Root 检测且机上有 Magisk: 加 --denylist（DenyList 窗口，不是隐 root）\n\
         或: adb pull /data/local/tmp/ksight/packages/{package}\n"
    );
    let _ = ksight_core::output_budget::write(dest.join("HOWTO.txt"), text);
}

fn prune_install_trees(dest: &Path) {
    for name in ["apk", "lib", "oat", "apk-assets"] {
        let _ = std::fs::remove_dir_all(dest.join(name));
    }
}

fn write_evidence_index(dest: &Path, report: &PackageDumpReport) {
    let joined = report
        .code_loaders
        .iter()
        .filter(|loader| loader.origin == "art_open" && loader.joined_sha256.is_some())
        .count();
    let mut lines = vec![
        format!("package: {}", report.package),
        format!("dump_id: {}", report.dump_id),
        format!("launched: {}", report.launched),
        format!("pids: {:?}", report.pids),
        format!("readable_dex: {}", report.readable_dex),
        format!("runtime_blob_dex: {}", report.runtime_blob_dex),
        format!("private_files: {}", report.private_files),
        format!("art_open_joined: {joined}"),
        format!("usb_debugging: {}", report.observation_env.usb_debugging),
        String::new(),
        "This folder is one package's collected evidence (no install APK/lib).".to_owned(),
        format!(
            "pull: adb pull /data/local/tmp/ksight/packages/{}",
            report.package
        ),
        String::new(),
        "contents:".to_owned(),
    ];
    for name in [
        "dump-report.json",
        "EVIDENCE.txt",
        "HOWTO.txt",
        "data-private",
        "runtime",
        "readable-dex",
        "apk-dex",
        "dex-classification",
    ] {
        if dest.join(name).exists() {
            lines.push(format!("  {name}"));
        }
    }
    let _ = ksight_core::output_budget::write(dest.join("EVIDENCE.txt"), lines.join("\n") + "\n");
}

fn catalog_snapshots(dest: &Path) -> Vec<MemorySnapshot> {
    let Ok(entries) = std::fs::read_dir(dest.join("runtime")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("snapshot-")
            || !Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if let Ok(row) = serde_json::from_str::<MemorySnapshot>(&text) {
            out.push(row);
        }
    }
    out.sort_by_key(|row| row.pid);
    out
}

fn catalog_code_loaders(dest: &Path) -> Vec<CodeLoaderEntry> {
    #[derive(Deserialize, Default)]
    struct LoaderFile {
        #[serde(default)]
        entries: Vec<CodeLoaderEntry>,
    }
    let runtime = dest.join("runtime");
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&runtime) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let loader = name.starts_with("code-loader-") || name.starts_with("open-code-");
            if !loader
                || !Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            if let Ok(file) = serde_json::from_str::<LoaderFile>(&text) {
                out.extend(file.entries);
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(runtime.join("dex-open-order.json")) {
        if let Ok(file) = serde_json::from_str::<LoaderFile>(&text) {
            out.extend(file.entries);
        }
    }
    out.sort_by(|left, right| {
        left.origin
            .cmp(&right.origin)
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.order.cmp(&right.order))
    });
    out.dedup_by(|left, right| {
        left.origin == right.origin && left.pid == right.pid && left.path == right.path
    });
    out
}

fn catalog_tls_stacks(
    mapped: &[MappedCodeEntry],
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<TlsStackObservation> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let paths = mapped.iter().map(|row| row.path.as_str()).chain(
        artifacts
            .iter()
            .filter(|artifact| artifact.kind == "elf")
            .map(|artifact| artifact.relative_path.as_str()),
    );
    let mut sizes = BTreeMap::new();
    for artifact in artifacts {
        if artifact.kind != "elf" {
            continue;
        }
        sizes.insert(artifact.relative_path.as_str(), artifact.bytes);
        if let Some(map_path) = artifact.map_path.as_deref() {
            sizes.insert(map_path, artifact.bytes);
        }
    }
    for path in paths {
        let Some(kind) = ksight_core::classify_tls_library_path(path) else {
            continue;
        };
        if !seen.insert((kind.as_str(), path)) {
            continue;
        }
        let size = sizes.get(path).copied().or_else(|| {
            mapped
                .iter()
                .find(|row| row.path == path)
                .map(|row| row.end.saturating_sub(row.start))
        });
        let inspect_tries_ssl_write = ksight_core::ssl_write_attach_allowed(path, size, None);
        out.push(TlsStackObservation {
            kind: kind.as_str().to_owned(),
            path: path.to_owned(),
            inspect_tries_ssl_write,
        });
    }
    out.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    out
}

fn catalog_mapped_code(dest: &Path) -> Vec<MappedCodeEntry> {
    #[derive(Deserialize)]
    struct MappedCodeFile {
        entries: Vec<MappedCodeEntry>,
    }
    let Ok(entries) = std::fs::read_dir(dest.join("runtime")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("mapped-code-")
            || !Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if let Ok(file) = serde_json::from_str::<MappedCodeFile>(&text) {
            out.extend(file.entries);
        }
    }
    out.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.order.cmp(&right.order))
    });
    out
}

fn catalog_dump(dest: &Path) -> Vec<ksight_core::DumpArtifact> {
    let mut artifacts = Vec::new();
    catalog_blob_records(dest, &mut artifacts);
    catalog_blob_filenames(dest, &mut artifacts);
    catalog_memory_dex(dest, &mut artifacts);
    catalog_bound_code_dex(dest, &mut artifacts);
    catalog_named_dex(
        dest,
        &dest.join("apk-dex").join("split"),
        "apk-dex",
        &mut artifacts,
    );
    catalog_named_dex(dest, &dest.join("apk-dex"), "apk-dex", &mut artifacts);
    catalog_so_tree(
        dest,
        &dest.join("apk-assets"),
        "apk-assets",
        None,
        &mut artifacts,
    );
    catalog_so_tree(dest, &dest.join("lib"), "install-lib", None, &mut artifacts);
    catalog_runtime_so(dest, &mut artifacts);
    catalog_private_files(dest, &mut artifacts);
    enrich_artifacts_from_maps(dest, &mut artifacts);
    artifacts.retain(keep_catalog_artifact);
    rank_dump_artifacts(&mut artifacts);
    artifacts.truncate(512);
    artifacts
}

fn keep_catalog_artifact(artifact: &ksight_core::DumpArtifact) -> bool {
    if artifact.source == "heap-blob" {
        return match artifact.map_path.as_deref() {
            Some(path) if path.starts_with('/') => keep_heap_blob_map_path(path),
            _ => true,
        };
    }
    if artifact.source == "memory-dex" {
        return artifact.bytes >= 1024 && artifact.magic == "dex";
    }
    true
}

fn rank_dump_artifacts(artifacts: &mut [ksight_core::DumpArtifact]) {
    artifacts.sort_by(|left, right| {
        artifact_keep_score(right)
            .cmp(&artifact_keep_score(left))
            .then(left.relative_path.cmp(&right.relative_path))
    });
}

fn artifact_keep_score(artifact: &ksight_core::DumpArtifact) -> (u8, u64) {
    let source = match artifact.source.as_str() {
        "heap-blob" => 6,
        "memory-dex" => 5,
        "runtime-so" => 4,
        "apk-assets" => 3,
        "apk-dex" | "app-private" => 2,
        "install-lib" => 1,
        _ => 0,
    };
    (source, artifact.bytes)
}

mod maps;
use maps::*;
mod art_open;
use art_open::*;
mod private_copy;
use private_copy::*;

fn heal_blob_sidecars(dest: &Path, artifacts: &[ksight_core::DumpArtifact]) {
    let dir = dest.join("runtime").join("blob-dex");
    let _ = std::fs::create_dir_all(&dir);
    for artifact in artifacts {
        if artifact.source != "heap-blob" {
            continue;
        }
        let (Some(pid), Some(start)) = (artifact.pid, artifact.vma_start) else {
            continue;
        };
        let json_path = dir.join(format!("{pid}-{start:x}.json"));
        if json_path.exists() {
            continue;
        }
        let files = Path::new(&artifact.relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| vec![name.to_owned()])
            .unwrap_or_default();
        let meta = serde_json::json!({
            "pid": pid,
            "vma_start": start,
            "vma_end": artifact.vma_end,
            "map_path": artifact.map_path,
            "files": files,
        });
        let _ = ksight_core::output_budget::write(json_path, meta.to_string());
    }
}

fn catalog_blob_records(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let dir = dest.join("runtime").join("blob-dex");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let pid = value
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let vma_start = value.get("vma_start").and_then(serde_json::Value::as_u64);
        let vma_end = value.get("vma_end").and_then(serde_json::Value::as_u64);
        let map_path = value
            .get("map_path")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        let files = value
            .get("files")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for file in files {
            let Some(name) = file.as_str() else {
                continue;
            };
            let rel = format!("apk-dex/split/{name}");
            let bytes = dest.join(&rel).metadata().map_or(0, |meta| meta.len());
            out.push(ksight_core::DumpArtifact {
                kind: "dex".to_owned(),
                source: "heap-blob".to_owned(),
                relative_path: rel,
                bytes,
                magic: "dex".to_owned(),
                pid,
                vma_start,
                vma_end,
                map_path: map_path.clone(),
                dex_offset: parse_blob_name(name).and_then(|(_, _, offset)| offset),
                sha256: None,
            });
        }
    }
}

fn catalog_blob_filenames(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let split = dest.join("apk-dex").join("split");
    let Ok(entries) = std::fs::read_dir(&split) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some((pid, start, dex_offset)) = parse_blob_name(name) else {
            continue;
        };
        let rel = format!("apk-dex/split/{name}");
        if out.iter().any(|existing| existing.relative_path == rel) {
            continue;
        }
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        let vma_end = blob_ok_end(dest, pid, start);
        out.push(ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid: Some(pid),
            vma_start: Some(start),
            vma_end,
            map_path: None,
            dex_offset,
            sha256: None,
        });
    }
}

fn blob_ok_end(dest: &Path, pid: u32, start: u64) -> Option<u64> {
    let text = std::fs::read_to_string(
        dest.join("runtime")
            .join("blob-dex")
            .join(format!("{pid}-{start:x}.ok")),
    )
    .ok()?;
    let bytes = text.split_whitespace().find_map(|part| {
        part.strip_prefix("bytes=")
            .and_then(|value| value.parse::<u64>().ok())
    })?;
    (bytes > 0).then_some(start.saturating_add(bytes))
}

fn recover_secneo_payload(dest: &Path, package: &str, recorded: &[u32]) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    recover_secneo_payload_live(dest, package, recorded);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (dest, package, recorded);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn recover_secneo_payload_live(dest: &Path, package: &str, recorded: &[u32]) {
    let Some((path, spot)) = first_dexdata_file(dest) else {
        return;
    };
    let Ok(prefix) = read_file_window(&path, spot.header_offset, 256) else {
        return;
    };
    let probes = ksight_core::secneo_cipher_probes(&prefix);
    if probes.is_empty() {
        return;
    }
    let Some(pid) = secneo_probe_pid(package, recorded) else {
        write_live_note(
            dest,
            format!("dexdata0 payload has no live {package} process; DexHelper BSS was not read"),
        );
        return;
    };
    let Some(key) = scan_dexhelper_bss(pid, &probes) else {
        write_live_note(
            dest,
            format!(
                "dexdata0 payload: live pid {pid} DexHelper BSS and nearby heap windows did not yield an SM4 key; ciphertext retained"
            ),
        );
        return;
    };
    let key_dir = dest.join("runtime").join("packer-keys");
    let _ = std::fs::create_dir_all(&key_dir);
    let _ = write_catalog_bytes(&key_dir.join("recovered-sm4.bin"), &key);
    let Some(plain) = decrypt_retained_dexdata(&path, &spot, &key) else {
        write_live_note(
            dest,
            format!(
                "SM4 key from pid {pid} DexHelper BSS did not decrypt the retained dexdata0 body"
            ),
        );
        return;
    };
    let class_defs = plain
        .get(96..100)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    let out = dest.join("apk-dex").join("secneo-decrypted.dex");
    let _ = std::fs::create_dir_all(dest.join("apk-dex"));
    if write_catalog_bytes(&out, &plain).is_err() {
        write_live_note(dest, "decrypted SecNeo DEX could not be written".to_owned());
        return;
    }
    write_live_note(
        dest,
        format!(
            "decrypted dexdata0 with an SM4 key read from pid {pid} DexHelper BSS; derived apk-dex/secneo-decrypted.dex ({} bytes, class_defs {class_defs})",
            plain.len()
        ),
    );
    eprintln!(
        "secneo decrypted pid={pid} bytes={} class_defs={class_defs}",
        plain.len()
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn first_dexdata_file(dest: &Path) -> Option<(PathBuf, ksight_core::DexDataSpot)> {
    let runtime = dest.join("runtime");
    let entries = std::fs::read_dir(&runtime).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.ends_with(".code") || !path.is_file() {
            continue;
        }
        let Ok(meta) = path.metadata() else {
            continue;
        };
        if meta.len() as usize > ksight_core::DEX_IMAGE_LIMIT {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if let Some(spot) = ksight_core::locate_dexdata0(&bytes) {
            return Some((path, spot));
        }
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_file_window(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0_u8; len];
    let read = file.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn decrypt_retained_dexdata(
    path: &Path,
    spot: &ksight_core::DexDataSpot,
    key: &[u8; 16],
) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let start = usize::try_from(spot.header_offset).ok()?;
    let end = start
        .saturating_add(20)
        .saturating_add(usize::try_from(spot.declared_bytes).unwrap_or(0))
        .min(bytes.len());
    if end <= start {
        return None;
    }
    let plain = ksight_core::try_decrypt_secneo(&bytes[start..end], &[*key])?;
    if plain.len() < 0x70
        || plain.len() > ksight_core::DEX_IMAGE_LIMIT
        || !plain.starts_with(b"dex\n")
    {
        return None;
    }
    Some(plain)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn secneo_probe_pid(package: &str, recorded: &[u32]) -> Option<u32> {
    for pid in recorded.iter().copied().take(4) {
        if cmdline_is_package(pid, package) {
            return Some(pid);
        }
    }
    pids_for_package(package)
        .into_iter()
        .find(|pid| cmdline_is_package(*pid, package) && maps_have_dexhelper(*pid))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cmdline_is_package(pid: u32, package: &str) -> bool {
    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    bytes.split(|byte| *byte == 0).next() == Some(package.as_bytes())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn maps_have_dexhelper(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .is_ok_and(|text| text.to_ascii_lowercase().contains("dexhelper"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnonReadIdentity {
    package: String,
    pid: u32,
    uid: u32,
    birth_ns: u64,
    exec_id: u64,
    boot_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnonReadRefusal {
    RestartedInstance,
    ExecChanged,
    BudgetExhausted,
    DeadlineReached,
}

struct AnonReadRequest {
    expected: AnonReadIdentity,
    observed: AnonReadIdentity,
    deadline_reached: bool,
    budget_closed: bool,
}

fn admit_anonymous_read(request: &AnonReadRequest) -> Result<(), AnonReadRefusal> {
    if request.deadline_reached {
        return Err(AnonReadRefusal::DeadlineReached);
    }
    if request.budget_closed {
        return Err(AnonReadRefusal::BudgetExhausted);
    }
    let same_process = request.expected.package == request.observed.package
        && request.expected.pid == request.observed.pid
        && request.expected.uid == request.observed.uid
        && request.expected.birth_ns == request.observed.birth_ns
        && request.expected.boot_id == request.observed.boot_id;
    if !same_process {
        return Err(AnonReadRefusal::RestartedInstance);
    }
    if request.expected.exec_id != request.observed.exec_id {
        return Err(AnonReadRefusal::ExecChanged);
    }
    Ok(())
}

/// Payload reads and writes happen only after admission. A refusal does neither.
fn anonymous_payload_effect(request: &AnonReadRequest) -> (u32, u32) {
    if admit_anonymous_read(request).is_err() {
        return (0, 0);
    }
    (1, 1)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn anon_identity(source: &crate::qualified_code::SourceIdentity) -> AnonReadIdentity {
    AnonReadIdentity {
        package: source.package.clone(),
        pid: source.pid,
        uid: source.uid,
        birth_ns: source.birth_ns,
        exec_id: source.exec_id,
        boot_id: source.boot_id.clone(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn harvest_admitted_anonymous_dex(
    dest: &Path,
    backend: Option<&crate::qualified_code::Backend>,
    sources: Option<&[crate::qualified_code::SourceIdentity]>,
    deadline: Instant,
) {
    let (Some(backend), Some(sources)) = (backend, sources) else {
        return;
    };
    for expected in sources.iter().take(4) {
        if Instant::now() >= deadline || ksight_core::output_budget::should_stop(dest) {
            return;
        }
        let Ok(current) = backend.qualify(&expected.package, expected.pid, false) else {
            return;
        };
        let request = AnonReadRequest {
            expected: anon_identity(expected),
            observed: anon_identity(&current.identity),
            deadline_reached: Instant::now() >= deadline,
            budget_closed: ksight_core::output_budget::should_stop(dest),
        };
        if admit_anonymous_read(&request).is_err() {
            return;
        }
        let _ = harvest_anonymous_dex(dest, expected.pid, deadline);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn harvest_anonymous_dex(dest: &Path, pid: u32, deadline: Instant) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    if text.len() > 2 * 1024 * 1024 {
        return None;
    }
    let mut rows = crate::dexdump::parse_maps(&text);
    rows.retain(|row| {
        anonymous_dex_region(&row.path, &row.perms, row.end.saturating_sub(row.start))
    });
    rows.sort_by_key(|row| std::cmp::Reverse(row.end.saturating_sub(row.start)));
    let mut mem = File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut saved = Vec::new();
    let mut read_total = 0_u64;
    let mut largest = 0_u64;
    for row in rows {
        if saved.len() >= 4
            || read_total >= ANON_DEX_READ_CAP
            || Instant::now() >= deadline
            || ksight_core::output_budget::should_stop(dest)
        {
            break;
        }
        let len = row.end.saturating_sub(row.start);
        largest = largest.max(len);
        let want = len.min(ANON_DEX_READ_CAP.saturating_sub(read_total));
        if want < 0x70 {
            continue;
        }
        if Instant::now() >= deadline || ksight_core::output_budget::should_stop(dest) {
            break;
        }
        let Some(bytes) = read_region(&mut mem, row.start, want) else {
            continue;
        };
        read_total = read_total.saturating_add(want);
        for (offset, declared) in unpacked_dex_ranges(&bytes, 4_usize.saturating_sub(saved.len())) {
            if saved.len() >= 4
                || Instant::now() >= deadline
                || ksight_core::output_budget::should_stop(dest)
            {
                break;
            }
            let end = offset.saturating_add(declared);
            let slice = &bytes[offset..end];
            let vma = row.start.saturating_add(offset as u64);
            let name = format!("anon-{pid}-{vma:x}.dex");
            let out = dest.join("apk-dex").join(&name);
            if out.is_file() {
                continue;
            }
            let _ = std::fs::create_dir_all(dest.join("apk-dex"));
            if write_catalog_bytes(&out, slice).is_err() {
                break;
            }
            let classes = slice
                .get(96..100)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0);
            saved.push(format!("{name} ({declared} bytes, class_defs {classes})"));
            eprintln!("anonymous dex pid={pid} vma={vma:#x} bytes={declared} class_defs={classes}");
        }
    }
    if saved.is_empty() {
        return Some(format!(
            "anonymous DEX scan pid {pid}: read {read_total} bytes, largest region {largest} bytes, writable anon/scudo {ANON_DEX_REGION_MIN}..={ANON_DEX_REGION_MAX}, cap {ANON_DEX_READ_CAP}; no dex image with class_defs>=200 whose declared length fit the read"
        ));
    }
    Some(format!(
        "unpacked DEX from pid {pid} anonymous memory: {}",
        saved.join("; ")
    ))
}

/// One scudo secondary can hold a SecNeo payload larger than 32MiB.
/// BOC dexdata0 is 92,160,020 bytes inside a 92,168,192-byte region.
/// The cap matches the DEX image limit and does not include dalvik heaps.
const ANON_DEX_REGION_MIN: u64 = 512 * 1024;
const ANON_DEX_REGION_MAX: u64 = 128 * 1024 * 1024;
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
const ANON_DEX_READ_CAP: u64 = 128 * 1024 * 1024;

fn anonymous_dex_region(path: &str, perms: &str, len: u64) -> bool {
    if !perms.contains('r')
        || !perms.contains('w')
        || !(ANON_DEX_REGION_MIN..=ANON_DEX_REGION_MAX).contains(&len)
    {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("dalvik")
        || lower.contains("jit")
        || lower.contains("stack")
        || lower.starts_with("/system/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/data/app/")
    {
        return false;
    }
    path.is_empty()
        || lower.starts_with("[anon")
        || lower.starts_with("anon")
        || lower.contains("scudo")
        || lower.contains("partition_alloc")
}

fn unpacked_class_table_fits(image: &[u8], declared: usize) -> bool {
    if image.len() < 112 || declared < 112 || declared > image.len() {
        return false;
    }
    let Ok(classes_raw) = image[96..100].try_into() else {
        return false;
    };
    let Ok(off_raw) = image[100..104].try_into() else {
        return false;
    };
    let classes = u32::from_le_bytes(classes_raw);
    let off = u32::from_le_bytes(off_raw) as usize;
    if !(200..=100_000).contains(&classes) || off < 0x70 {
        return false;
    }
    let Some(table_bytes) = (classes as usize).checked_mul(32) else {
        return false;
    };
    let Some(end) = off.checked_add(table_bytes) else {
        return false;
    };
    end <= declared
}

fn unpacked_dex_ranges(bytes: &[u8], limit: usize) -> Vec<(usize, usize)> {
    // Same step-by-4 nested walk as embedded_dex_images. Do not jump to the
    // outer declared end, or a shell with class_defs>=200 hides the inner image.
    embedded_dex_images(bytes)
        .into_iter()
        .filter_map(|(offset, declared)| {
            let at = usize::try_from(offset).ok()?;
            let image = bytes.get(at..at.saturating_add(declared))?;
            unpacked_class_table_fits(image, declared).then_some((at, declared))
        })
        .take(limit)
        .collect()
}

fn find_unpacked_dex(bytes: &[u8]) -> Option<(usize, usize)> {
    unpacked_dex_ranges(bytes, 1).into_iter().next()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn scan_dexhelper_bss(pid: u32, probes: &[Vec<u8>]) -> Option<[u8; 16]> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    if text.len() > 2 * 1024 * 1024 {
        return None;
    }
    let rows = crate::dexdump::parse_maps(&text);
    let mut mem = File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut read_total = 0_u64;
    const TOTAL_CAP: u64 = 16 * 1024 * 1024;
    const REGION_CAP: u64 = 12 * 1024 * 1024;
    for row in &rows {
        if read_total >= TOTAL_CAP || !dexhelper_key_region(&row.path, &row.perms, row.start, &rows)
        {
            continue;
        }
        let len = row.end.saturating_sub(row.start).min(REGION_CAP);
        if len < 16 || read_total.saturating_add(len) > TOTAL_CAP {
            continue;
        }
        let Some(bytes) = read_region(&mut mem, row.start, len) else {
            continue;
        };
        read_total = read_total.saturating_add(len);
        if let Some(key) = ksight_core::scan_sm4_haystack(&bytes, probes, 8, 2_000_000) {
            return Some(key);
        }
        if let Some(key) = scan_pointer_windows(&mut mem, &rows, &bytes, probes) {
            return Some(key);
        }
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn scan_pointer_windows(
    mem: &mut File,
    rows: &[crate::dexdump::MapRow],
    bytes: &[u8],
    probes: &[Vec<u8>],
) -> Option<[u8; 16]> {
    let mut seen = Vec::<u64>::new();
    let mut offset = 0_usize;
    while offset.saturating_add(8) <= bytes.len() && seen.len() < 8 {
        let ptr = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
        offset = offset.saturating_add(8);
        if ptr < 0x1_0000 || ptr > 0x00ff_ffff_ffff || !ptr.is_multiple_of(8) || seen.contains(&ptr)
        {
            continue;
        }
        let Some(row) = rows.iter().find(|row| ptr >= row.start && ptr < row.end) else {
            continue;
        };
        let path = row.path.to_ascii_lowercase();
        if !row.perms.contains('w')
            || path.contains("dalvik")
            || path.contains("jit")
            || path.starts_with("/system/")
            || path.starts_with("/apex/")
        {
            continue;
        }
        seen.push(ptr);
        let at = ptr.saturating_sub(128 * 1024).max(row.start);
        let want = row.end.saturating_sub(at).min(256 * 1024);
        let Some(window) = read_region(mem, at, want) else {
            continue;
        };
        if let Some(key) = ksight_core::scan_sm4_haystack(&window, probes, 8, 2_000_000) {
            return Some(key);
        }
    }
    None
}

fn dexhelper_key_region(
    path: &str,
    perms: &str,
    start: u64,
    rows: &[crate::dexdump::MapRow],
) -> bool {
    if !perms.contains('r') || !perms.contains('w') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("dexhelper") {
        return true;
    }
    if !path.contains("anon:.bss") {
        return false;
    }
    rows.iter().any(|row| {
        row.path.to_ascii_lowercase().contains("dexhelper")
            && (start.abs_diff(row.end) < 0x4_0000 || start.abs_diff(row.start) < 0x4_0000)
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn write_live_note(dest: &Path, note: String) {
    let path = dest.join("runtime").join("dexdata-live.json");
    let mut notes = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
        .unwrap_or_default();
    notes.push(note);
    if let Ok(body) = serde_json::to_vec(&notes) {
        let _ = std::fs::write(path, body);
    }
}

fn catalog_bound_code_dex(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let runtime = dest.join("runtime");
    let Ok(entries) = std::fs::read_dir(&runtime) else {
        return;
    };
    let mut notes = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.ends_with(".code") || !path.is_file() {
            continue;
        }
        let file_len = path.metadata().map_or(0, |meta| meta.len()) as usize;
        if file_len > ksight_core::DEX_IMAGE_LIMIT {
            notes.push(format!(
                "runtime/{name} is {file_len} bytes, over the {0} byte image bound; not read again",
                ksight_core::DEX_IMAGE_LIMIT
            ));
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let (pid, start) = parse_bound_code_name(name).unwrap_or((0, 0));
        let mut seen_offsets = BTreeSet::new();
        for slice in ksight_core::split_concatenated_dex(&bytes) {
            if slice.bytes.len() < 1024 || !seen_offsets.insert(slice.offset) {
                continue;
            }
            out.push(bound_dex_artifact(
                name,
                pid,
                start,
                slice.offset,
                slice.bytes.len(),
            ));
        }
        // A shell DEX can declare a size that covers later plaintext images.
        // Those inner headers are separate DEX files, not a second copy of the shell.
        for (offset, declared) in embedded_dex_images(&bytes) {
            if declared < 1024 || !seen_offsets.insert(offset) {
                continue;
            }
            out.push(bound_dex_artifact(name, pid, start, offset, declared));
        }
        note_truncated_dex(&bytes, name, &mut notes);
        if let Some(spot) = ksight_core::locate_dexdata0(&bytes) {
            notes.push(format!(
                "dexdata0 in runtime/{name} at offset {}: count {}, declared {} bytes; encrypted SecNeo payload; retained DexHelper file bytes did not contain the SM4 key",
                spot.header_offset, spot.count, spot.declared_bytes
            ));
        }
    }
    if let Ok(body) = serde_json::to_vec(&notes) {
        let _ = std::fs::write(runtime.join("truncated-dex.json"), body);
    }
}

fn bound_dex_artifact(
    name: &str,
    pid: u32,
    start: u64,
    offset: u64,
    len: usize,
) -> ksight_core::DumpArtifact {
    ksight_core::DumpArtifact {
        kind: "dex".to_owned(),
        source: "memory-dex".to_owned(),
        relative_path: format!("runtime/{name}"),
        bytes: u64::try_from(len).unwrap_or(0),
        magic: "dex".to_owned(),
        pid: (pid != 0).then_some(pid),
        vma_start: (start != 0).then_some(start),
        vma_end: None,
        map_path: None,
        dex_offset: Some(offset),
        sha256: None,
    }
}

fn embedded_dex_images(bytes: &[u8]) -> Vec<(u64, usize)> {
    let mut found = Vec::new();
    let mut search = 0_usize;
    while search.saturating_add(0x70) <= bytes.len() && found.len() < 32 {
        let Some(rel) = bytes[search..]
            .windows(8)
            .position(|window| window == b"dex\n035\0")
        else {
            break;
        };
        let at = search.saturating_add(rel);
        let Some(declared) = ksight_core::peek_declared_dex_len(&bytes[at..]) else {
            search = at.saturating_add(4);
            continue;
        };
        let classes = bytes
            .get(at + 96..at + 100)
            .and_then(|raw| raw.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        if declared >= 0x70
            && at.saturating_add(declared) <= bytes.len()
            && (1..=100_000).contains(&classes)
        {
            found.push((u64::try_from(at).unwrap_or(0), declared));
        }
        // Step past this magic. The next image may sit inside this declared size.
        search = at.saturating_add(4);
    }
    found
}

fn note_truncated_dex(bytes: &[u8], name: &str, notes: &mut Vec<String>) {
    let mut search = 0_usize;
    while search.saturating_add(0x70) <= bytes.len() && notes.len() < 32 {
        let Some(rel) = bytes[search..]
            .windows(4)
            .position(|window| window == b"dex\n")
        else {
            break;
        };
        let at = search.saturating_add(rel);
        let Some(declared) = ksight_core::peek_declared_dex_len(&bytes[at..]) else {
            search = at.saturating_add(4);
            continue;
        };
        let retained = bytes.len().saturating_sub(at);
        if declared > retained {
            notes.push(format!(
                "incomplete dex image in runtime/{name} at offset {at}: declared {declared} bytes, retained {retained}; not a complete DEX"
            ));
        }
        search = at.saturating_add(4);
    }
}

fn parse_anon_dex_name(name: &str) -> Option<(u32, u64)> {
    let rest = name.strip_prefix("anon-")?.strip_suffix(".dex")?;
    let (pid, vma) = rest.split_once('-')?;
    Some((pid.parse().ok()?, u64::from_str_radix(vma, 16).ok()?))
}

fn parse_bound_code_name(name: &str) -> Option<(u32, u64)> {
    let rest = name.strip_prefix("bound-")?.strip_suffix(".code")?;
    let (pid_text, rest) = rest.split_once('-')?;
    let (start_text, _) = rest.split_once('-')?;
    Some((
        pid_text.parse().ok()?,
        u64::from_str_radix(start_text, 16).ok()?,
    ))
}

fn catalog_memory_dex(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let runtime = dest.join("runtime");
    let Ok(entries) = std::fs::read_dir(&runtime) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some((pid, start, dex_offset)) = parse_mem_name(name) else {
            continue;
        };
        let rel = format!("runtime/{name}");
        if out.iter().any(|existing| existing.relative_path == rel) {
            continue;
        }
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        if bytes < 1024 {
            continue;
        }
        out.push(ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "memory-dex".to_owned(),
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid: Some(pid),
            vma_start: Some(start),
            vma_end: None,
            map_path: None,
            dex_offset,
            sha256: None,
        });
    }
}

fn parse_mem_name(name: &str) -> Option<(u32, u64, Option<u64>)> {
    let rest = name.strip_prefix("mem-")?;
    let rest = rest
        .strip_suffix(".dex")
        .or_else(|| rest.strip_suffix(".cdex"))?;
    let (pid_s, rest) = rest.split_once('-')?;
    let pid = pid_s.parse().ok()?;
    if let Some((start_s, offset_s)) = rest.split_once('+') {
        let start = u64::from_str_radix(start_s, 16).ok()?;
        let offset = u64::from_str_radix(offset_s, 16).ok()?;
        Some((pid, start, Some(offset)))
    } else {
        let start = u64::from_str_radix(rest, 16).ok()?;
        Some((pid, start, None))
    }
}

fn parse_blob_name(name: &str) -> Option<(u32, u64, Option<u64>)> {
    let rest = name.strip_prefix("blob-")?;
    let (pid_s, rest) = rest.split_once('-')?;
    let (start_s, rest) = rest.split_once('_')?;
    let pid = pid_s.parse().ok()?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let dex_offset = rest
        .rsplit_once('_')
        .and_then(|(_, last)| last.strip_suffix(".dex"))
        .and_then(|offset| offset.parse().ok());
    Some((pid, start, dex_offset))
}

fn catalog_named_dex(
    dest: &Path,
    dir: &Path,
    source: &str,
    out: &mut Vec<ksight_core::DumpArtifact>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"))
        {
            continue;
        }
        if name.starts_with("blob-") {
            continue;
        }
        let rel = match path.strip_prefix(dest) {
            Ok(stripped) => stripped.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if out.iter().any(|existing| existing.relative_path == rel) {
            continue;
        }
        if out.iter().any(|existing| {
            Path::new(&existing.relative_path)
                .file_name()
                .and_then(|value| value.to_str())
                == Some(name)
        }) {
            continue;
        }
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        let anon = parse_anon_dex_name(name);
        out.push(ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: if anon.is_some() {
                "memory-dex".to_owned()
            } else {
                source.to_owned()
            },
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid: anon.map(|(pid, _)| pid),
            vma_start: anon.map(|(_, vma)| vma),
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: None,
        });
    }
}

fn catalog_so_tree(
    dest: &Path,
    dir: &Path,
    source: &str,
    pid: Option<u32>,
    out: &mut Vec<ksight_core::DumpArtifact>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            catalog_so_tree(dest, &path, source, pid, out);
            continue;
        }
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            continue;
        }
        if out.len() >= 256 {
            return;
        }
        let Ok(rel) = path.strip_prefix(dest) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        out.push(ksight_core::DumpArtifact {
            kind: "elf".to_owned(),
            source: source.to_owned(),
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid,
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: None,
        });
    }
}

fn catalog_private_files(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let root = dest.join("data-private");
    let mut added = 0_usize;
    visit_files(&root, &mut |path| {
        if added >= 256 {
            return;
        }
        let Ok(rel) = path.strip_prefix(dest) else {
            return;
        };
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        out.push(ksight_core::DumpArtifact {
            kind: "file".to_owned(),
            source: "app-private".to_owned(),
            relative_path: rel.to_string_lossy().replace('\\', "/"),
            bytes,
            magic: peek_magic(path),
            pid: None,
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: None,
        });
        added = added.saturating_add(1);
    });
}

fn catalog_runtime_so(dest: &Path, out: &mut Vec<ksight_core::DumpArtifact>) {
    let dir = dest.join("runtime").join("runtime-so");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            continue;
        }
        let pid = name
            .split_once('-')
            .and_then(|(prefix, _)| prefix.parse::<u32>().ok());
        let rel = format!("runtime/runtime-so/{name}");
        let bytes = path.metadata().map_or(0, |meta| meta.len());
        out.push(ksight_core::DumpArtifact {
            kind: "elf".to_owned(),
            source: "runtime-so".to_owned(),
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid,
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: None,
        });
    }
}

fn peek_magic(path: &Path) -> String {
    let mut buf = [0_u8; 8];
    let Ok(mut file) = File::open(path) else {
        return "unknown".to_owned();
    };
    let Ok(read) = file.read(&mut buf) else {
        return "unknown".to_owned();
    };
    if ksight_core::is_dex_magic(&buf[..read]) {
        "dex".to_owned()
    } else if buf.starts_with(&[0x7f, b'E', b'L', b'F']) {
        "elf".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn hex_key(key: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in key {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn accumulate_live(report: &mut PackageDumpReport, live: crate::dexdump::LiveDump) {
    report.memory_images = report.memory_images.saturating_add(live.memory_images);
    report.vdex_images = report.vdex_images.saturating_add(live.vdex_images);
    report.fd_images = report.fd_images.saturating_add(live.fd_images);
    report.runtime_libs = report.runtime_libs.saturating_add(live.native_libs);
    report.packer_regions = report.packer_regions.saturating_add(live.packer_regions);
    report.plaintext_windows = report
        .plaintext_windows
        .saturating_add(live.plaintext_windows);
    report.crypto_windows = report.crypto_windows.saturating_add(live.crypto_windows);
    report.memory_window_write_failures = report
        .memory_window_write_failures
        .saturating_add(live.memory_window_write_failures);
    report.memory_window_read_failures = report
        .memory_window_read_failures
        .saturating_add(live.memory_window_read_failures);
    report.memory_window_short_reads = report
        .memory_window_short_reads
        .saturating_add(live.memory_window_short_reads);
    report.key_slots = report.key_slots.saturating_add(live.key_slots);
    report.runtime_blob_dex = report.runtime_blob_dex.saturating_add(live.blob_dex);
    report.stitched_spans = report.stitched_spans.saturating_add(live.stitched_spans);
}

fn unpack_secneo(dest: &Path) -> (usize, Option<[u8; 16]>) {
    let apk_dex = dest.join("apk-dex");
    let Ok(entries) = std::fs::read_dir(&apk_dex) else {
        return (0, None);
    };
    let mut keys = collect_key_candidates(dest);
    let haystack = collect_key_haystack(dest);
    let mut recovered = None;
    let mut unpacked = 0_usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !lower.contains("payload") && !lower.contains("dexdata") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if recovered.is_none() && !haystack.is_empty() {
            if let Some(key) = ksight_core::find_secneo_key(&bytes, &haystack) {
                recovered = Some(key);
                if !keys.contains(&key) {
                    keys.insert(0, key);
                }
                let key_path = dest
                    .join("runtime")
                    .join("packer-keys")
                    .join("recovered-sm4.bin");
                let _ = std::fs::create_dir_all(dest.join("runtime").join("packer-keys"));
                let _ = ksight_core::output_budget::write(&key_path, key);
                eprintln!("recovered SecNeo SM4 key -> {}", key_path.display());
            }
        }
        if keys.is_empty() {
            continue;
        }
        let Some(plain) = ksight_core::try_decrypt_secneo(&bytes, &keys) else {
            continue;
        };
        let out = apk_dex.join(format!("{name}.decrypted.dex"));
        if ksight_core::output_budget::write(&out, &plain).is_err() {
            continue;
        }
        if let Some(repaired) = ksight_core::repair_dex(&plain) {
            let _ = ksight_core::output_budget::write(
                apk_dex
                    .join("repaired")
                    .join(out.file_name().unwrap_or_default()),
                repaired.bytes,
            );
        }
        let slices = ksight_core::split_concatenated_dex(&plain);
        if slices.len() > 1 {
            let split_dir = apk_dex.join(format!("{name}-split"));
            let _ = std::fs::create_dir_all(&split_dir);
            for (index, slice) in slices.iter().enumerate() {
                let _ = ksight_core::output_budget::write(
                    split_dir.join(format!("part{index:02}.dex")),
                    &slice.bytes,
                );
            }
        }
        unpacked = unpacked.saturating_add(1);
        eprintln!(
            "decrypted SecNeo {} -> {} ({} bytes)",
            name,
            out.display(),
            plain.len()
        );
    }
    (unpacked, recovered)
}

fn collect_key_candidates(dest: &Path) -> Vec<[u8; 16]> {
    let mut keys = Vec::new();
    for path in key_search_files(dest, false) {
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let mut offset = 0_usize;
        let max = if name.contains("slot-") || name.contains("got-") {
            bytes.len().min(128)
        } else {
            64
        };
        while offset.saturating_add(16) <= bytes.len() && offset < max {
            let mut key = [0_u8; 16];
            key.copy_from_slice(&bytes[offset..offset + 16]);
            if key.iter().any(|byte| *byte != 0) && !keys.contains(&key) {
                keys.push(key);
            }
            offset = offset.saturating_add(8);
        }
        if keys.len() >= 64 {
            break;
        }
    }
    keys
}

fn collect_key_haystack(dest: &Path) -> Vec<u8> {
    const CAP: usize = 1024 * 1024;
    const PER_FILE: usize = 24 * 1024;
    let mut haystack = Vec::new();
    for path in key_search_files(dest, true) {
        if haystack.len() >= CAP {
            break;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let remain = CAP.saturating_sub(haystack.len());
        let prefix = if name.contains("slot-") || name.contains("got-") || name.contains("poll-") {
            bytes.len()
        } else {
            bytes.len().min(PER_FILE)
        };
        let take = prefix.min(remain);
        haystack.extend_from_slice(&bytes[..take]);
    }
    haystack
}

fn key_search_files(dest: &Path, include_heap: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let key_dir = dest.join("runtime").join("packer-keys");
    if let Ok(entries) = std::fs::read_dir(&key_dir) {
        files.extend(entries.flatten().map(|entry| entry.path()));
    }
    let packer_dir = dest.join("runtime").join("packer-mem");
    if let Ok(entries) = std::fs::read_dir(&packer_dir) {
        files.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.contains("bss") || name.contains("DexHelper"))
        }));
    }
    files.sort_by_key(|path| {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if name.contains("got-") || name.contains("recovered") {
            0_u8
        } else if name.contains("slot-") || name.contains("poll-bss-") {
            1
        } else if name.contains("poll-heap-") {
            2
        } else if name.contains("heap-") {
            4
        } else {
            3
        }
    });
    if !include_heap {
        files.retain(|path| {
            !path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.contains("heap-"))
        });
    }
    files
}

fn validate_package(package: &str) -> Result<()> {
    if !crate::identity::valid_package_name(package) {
        bail!("Android package name contains unsupported characters");
    }
    Ok(())
}

pub(crate) fn apk_paths(package: &str) -> Vec<PathBuf> {
    let mut paths = parse_pm_paths(&run_optional(
        "/system/bin/cmd",
        &["package", "path", package],
    ));
    if paths.is_empty() {
        paths = parse_pm_paths(&run_optional("/system/bin/pm", &["path", package]));
    }
    if paths.is_empty() {
        paths = walk_data_app(package);
    }
    paths.retain(|path| path.is_file());
    paths
}

fn parse_pm_paths(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("package:")
                .map(|path| PathBuf::from(path.trim()))
        })
        .collect()
}

fn run_optional(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or_default()
}

fn catalog_registered_component_classes(
    package: &str,
    sets: &[ksight_core::DexArtifactSet],
    dest: &Path,
) -> Vec<String> {
    let declared = sets
        .iter()
        .filter_map(|set| set.semantic.as_ref())
        .flat_map(|semantic| semantic.class_descriptors.iter())
        .filter_map(|descriptor| normalize_dex_class_descriptor(descriptor))
        .collect::<BTreeMap<_, _>>();
    if declared.is_empty() {
        return Vec::new();
    }
    let package_dump = run_optional("/system/bin/dumpsys", &["package", package]);
    let mut classes = package_dump
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '$'))
        })
        .filter(|token| token.contains('.'))
        .filter_map(|token| declared.get(&token.replace('.', "/").to_ascii_lowercase()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(4096)
        .collect::<Vec<_>>();
    classes.sort();
    if !classes.is_empty() {
        let metadata_dir = dest.join("metadata");
        if std::fs::create_dir_all(&metadata_dir).is_ok() {
            let _ = ksight_core::output_budget::write(
                metadata_dir.join("registered-components.json"),
                serde_json::to_vec_pretty(&classes).unwrap_or_default(),
            );
        }
    }
    classes
}

fn normalize_dex_class_descriptor(descriptor: &str) -> Option<(String, String)> {
    let class_name = descriptor
        .trim()
        .trim_start_matches('[')
        .trim_start_matches('L')
        .trim_end_matches(';');
    if !class_name.contains('/') {
        return None;
    }
    Some((
        class_name.to_ascii_lowercase(),
        class_name.replace('/', "."),
    ))
}

fn walk_data_app(package: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(top) = std::fs::read_dir("/data/app") else {
        return found;
    };
    for entry in top.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if name.contains(package) {
            push_apks(&path, &mut found);
            continue;
        }
        let Ok(children) = std::fs::read_dir(&path) else {
            continue;
        };
        for child in children.flatten() {
            let child_path = child.path();
            let child_name = child_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if child_name.contains(package) {
                push_apks(&child_path, &mut found);
            }
        }
    }
    found
}

fn push_apks(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if has_ext(&path, "apk") {
            out.push(path);
        }
    }
}

fn copy_tree(src: &Path, dest: &Path, cap: u64) -> Result<usize> {
    if !src.is_dir() {
        return Ok(0);
    }
    let mut copied = 0_usize;
    copy_tree_inner(src, dest, cap, &mut copied, 0)?;
    Ok(copied)
}

fn copy_tree_inner(
    src: &Path,
    dest: &Path,
    cap: u64,
    copied: &mut usize,
    depth: u32,
) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)?.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let target = dest.join(&name);
        if path.is_dir() {
            copy_tree_inner(&path, &target, cap, copied, depth.saturating_add(1))?;
            continue;
        }
        copy_capped_path(&path, &target, cap)?;
        *copied = copied.saturating_add(1);
    }
    Ok(())
}

fn copy_data_code_cache(package: &str, dest: &Path) -> Result<usize> {
    let mut copied = 0_usize;
    for root in [
        PathBuf::from(format!("/data/user/0/{package}")),
        PathBuf::from(format!("/data/data/{package}")),
    ] {
        copied = copied.saturating_add(copy_matching_files(&root, dest, 0)?);
    }
    Ok(copied)
}

fn copy_matching_files(src: &Path, dest: &Path, depth: u32) -> Result<usize> {
    if depth > 5 || !src.is_dir() {
        return Ok(0);
    }
    let mut copied = 0_usize;
    let Ok(entries) = std::fs::read_dir(src) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            copied =
                copied.saturating_add(copy_matching_files(&path, dest, depth.saturating_add(1))?);
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let keep = has_ext(&path, "dex")
            || has_ext(&path, "vdex")
            || has_ext(&path, "odex")
            || has_ext(&path, "oat")
            || has_ext(&path, "dve")
            || name.eq_ignore_ascii_case("info.y")
            || crate::file::is_interesting_native(&path.to_string_lossy());
        if !keep {
            continue;
        }
        std::fs::create_dir_all(dest)?;
        let target = dest.join(name);
        if target.exists() {
            continue;
        }
        let cap = if has_ext(&path, "dex") || has_ext(&path, "vdex") {
            MAX_TREE_FILE_BYTES
        } else {
            12 * 1024 * 1024
        };
        if copy_capped_path(&path, &target, cap).is_ok() {
            copied = copied.saturating_add(1);
        }
    }
    Ok(copied)
}

fn force_stop_package(package: &str) {
    let _ = Command::new("/system/bin/am")
        .args(["force-stop", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn start_package(package: &str) {
    let resolved = run_optional(
        "/system/bin/cmd",
        &["package", "resolve-activity", "--brief", package],
    );
    let activity = resolved
        .lines()
        .map(str::trim)
        .find(|line| line.contains('/') && !line.contains('='));
    if let Some(activity) = activity {
        let _ = Command::new("/system/bin/am")
            .args(["start", "-n", activity])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return;
    }
    let _ = Command::new("/system/bin/monkey")
        .args(["-p", package, "-c", "android.intent.category.LAUNCHER", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(super) fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(ext))
}

#[derive(Default)]
struct LiveKeyPoll {
    slots: usize,
    recovered: Option<[u8; 16]>,
    blob_dex: usize,
}

fn poll_fresh_package_keys(
    package: &str,
    runtime: &Path,
    stale: &[u32],
) -> (Vec<u32>, LiveKeyPoll) {
    let pids = wait_for_fresh_pids(package, stale, Duration::from_secs(8));
    poll_pids(pids, runtime)
}

fn poll_package_keys(package: &str, runtime: &Path) -> (Vec<u32>, LiveKeyPoll) {
    let mut pids = wait_for_pids(package, Duration::from_secs(8));
    if pids.is_empty() {
        pids = pids_for_package(package);
    }
    poll_pids(pids, runtime)
}

fn poll_pids(pids: Vec<u32>, runtime: &Path) -> (Vec<u32>, LiveKeyPoll) {
    let mut live = LiveKeyPoll {
        slots: 0,
        recovered: None,
        blob_dex: 0,
    };
    let Some(pid) = pids.first().copied() else {
        return (pids, live);
    };
    let poll_until = Instant::now() + Duration::from_millis(2500);
    let mut seq = 0_u32;
    while Instant::now() < poll_until && seq < 12 {
        let snap = poll_followed_keys(pid, runtime, seq);
        live.slots = live.slots.saturating_add(snap.dumped);
        live.blob_dex = live.blob_dex.saturating_add(snap.blob_dex);
        if let Some(key) = snap.recovered_key {
            live.recovered = Some(key);
            eprintln!("live SM4 key at poll seq {seq}");
        }
        seq = seq.saturating_add(1);
        std::thread::sleep(Duration::from_millis(80));
    }
    (pids, live)
}

fn wait_for_pids(package: &str, timeout: Duration) -> Vec<u32> {
    wait_for_fresh_pids(package, &[], timeout)
}

fn wait_for_fresh_pids(package: &str, stale: &[u32], timeout: Duration) -> Vec<u32> {
    let started = Instant::now();
    loop {
        let mut pids: Vec<u32> = pids_for_package(package)
            .into_iter()
            .filter(|pid| !stale.contains(pid))
            .collect();
        pids = rank_package_pids(package, pids);
        let has_main = pids.iter().any(|pid| package_cmdline(*pid) == package);
        if has_main || started.elapsed() >= timeout {
            return pids;
        }
        if !pids.is_empty() && started.elapsed() >= Duration::from_secs(3) {
            return pids;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn rank_package_pids(package: &str, mut pids: Vec<u32>) -> Vec<u32> {
    pids.sort_by_key(|pid| crate::dump_guard::cmdline_dump_rank(package, &package_cmdline(*pid)));
    pids
}

fn merge_live_package_pids(package: &str, mut pids: Vec<u32>) -> Vec<u32> {
    for pid in pids_for_package(package) {
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    }
    rank_package_pids(package, pids)
}

fn package_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map_or_else(String::new, |bytes| {
            bytes
                .split(|byte| *byte == 0)
                .next()
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .into_owned()
        })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(all(test, unix))]
mod inode_accounting_tests {
    use super::*;
    #[test]
    fn shared_inode_savings_ignore_allocation_rounding_and_equal_copies() {
        let root = std::env::temp_dir().join(format!("ksight-inodes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        ksight_core::output_budget::write(root.join("a"), [7_u8; 17]).unwrap();
        std::fs::hard_link(root.join("a"), root.join("link")).unwrap();
        ksight_core::output_budget::write(root.join("copy"), [7_u8; 17]).unwrap();
        assert_eq!(tree_bytes(&root), 51);
        assert_eq!(tree_unique_inode_bytes(&root), 34);
        assert_eq!(tree_bytes(&root) - tree_unique_inode_bytes(&root), 17);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod static_reuse_budget_tests {
    use super::*;
    #[test]
    fn declared_cache_does_not_change_other_packages_or_accept_unknown_schema() {
        let v = serde_json::json!({"schema":"kernsight.static-evidence-cache/v1","package":"org.example.fixture","apks":[{"path":"not-read-for-other-package"}]});
        assert_eq!(
            static_cache_for_package(v.clone(), "other.package").unwrap()["apks"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            static_cache_for_package(v, "org.example.fixture").unwrap()["apks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            static_cache_for_package(serde_json::json!({"apks":[]}), "org.example.fixture")
                .is_err()
        );
    }
    #[test]
    fn complete_static_reuse_preserves_runtime_budget_and_rejects_same_prefix_tail() {
        let root = std::env::temp_dir().join(format!("static-reuse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("source.apk");
        let mut bytes = vec![7u8; 128];
        bytes[127] = 1;
        std::fs::write(&source, &bytes).unwrap();
        let hash = static_hash(&source).unwrap();
        let dest = root.join("output");
        std::fs::create_dir(&dest).unwrap();
        let budget =
            ksight_core::output_budget::Guard::install(vec![dest.clone()], 1, 5000).unwrap();
        reuse_static_apk(&source, &dest.join("apk/base.apk"), 128, &hash).unwrap();
        assert_eq!(budget.receipt().admitted_write_bytes, 0);
        ksight_core::output_budget::write(dest.join("runtime-byte"), b"x").unwrap();
        assert_eq!(budget.receipt().admitted_write_bytes, 1);
        bytes[127] = 2;
        std::fs::write(&source, &bytes).unwrap();
        assert!(reuse_static_apk(&source, &dest.join("different.apk"), 128, &hash).is_err());
        assert!(!dest.join("different.apk").exists());
        assert!(reuse_static_apk(
            &source,
            &dest.join("short.apk"),
            129,
            &static_hash(&source).unwrap()
        )
        .is_err());
        assert!(source.exists());
    }
}
