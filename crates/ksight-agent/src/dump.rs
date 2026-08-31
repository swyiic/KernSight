//! Copy an installed package's APK, native libraries, and live DEX images.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::dexdump::{
    dump_live_process, keep_heap_blob_map_path, pids_for_package, poll_followed_keys,
};

const MAX_APK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PRIVATE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PRIVATE_FILES: usize = 512;
const APP_PRIVATE_DIRS: [&str; 4] = ["shared_prefs", "databases", "files", "no_backup"];
/// Versioned package-dump document consumed by `MobileE`.
pub const PACKAGE_DUMP_SCHEMA: &str = "mobilee.kernsight-package-dump/v2";
const PRIVATE_PACKAGE_ROOT: &str = "/data/local/tmp/ksight/packages";
const PUBLIC_PACKAGE_ROOT: &str = "/storage/emulated/0/Download/dexDump";

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
    /// Total bytes under this package dump root at catalog time.
    #[serde(default)]
    pub total_bytes: u64,
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
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct DumpOptions {
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
        native_rule_version: String::new(),
        native_framework_matches: Vec::new(),
        graph: ksight_core::SessionGraph::l0_placeholder(),
        sensitive_files: Vec::new(),
        total_bytes: 0,
        warnings: default_dump_warnings(),
        snapshots: Vec::new(),
        mapped_code: Vec::new(),
        code_loaders: Vec::new(),
        tls_stacks: Vec::new(),
        stitched_spans: 0,
        observation_env,
    };

    if !runtime_only {
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
    let (pids, live_key) = if launch {
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
    report.pids.clone_from(&pids);
    report.key_slots = report.key_slots.saturating_add(live_key.slots);
    report.runtime_blob_dex = report.runtime_blob_dex.saturating_add(live_key.blob_dex);
    if let Some(key) = live_key.recovered {
        report.recovered_sm4_key = Some(hex_key(key));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    for pid in pids.iter().copied().take(8) {
        if Instant::now() >= deadline {
            break;
        }
        let live = dump_live_process(pid, &runtime, deadline);
        accumulate_live(&mut report, live);
    }
    if !pids.is_empty() {
        std::thread::sleep(Duration::from_millis(500));
        pids = merge_live_package_pids(package, pids);
        report.pids.clone_from(&pids);
        let mid = Instant::now() + Duration::from_secs(8);
        for pid in pids.iter().copied().take(8) {
            if Instant::now() >= mid {
                break;
            }
            let live = dump_live_process(pid, &runtime, mid);
            accumulate_live(&mut report, live);
        }
        std::thread::sleep(Duration::from_secs(2));
        let second = Instant::now() + Duration::from_secs(15);
        for pid in pids.iter().copied().take(8) {
            if Instant::now() >= second {
                break;
            }
            let live = dump_live_process(pid, &runtime, second);
            accumulate_live(&mut report, live);
        }
    }
    if let Some(watch) = art_watch {
        let _ = watch.join();
    }
    report.private_files = copy_app_private(package, &dest.join("data-private")).unwrap_or(0);
    let (decrypted, recovered_key) = unpack_secneo(dest);
    report.secneo_decrypted = decrypted;
    if report.recovered_sm4_key.is_none() {
        report.recovered_sm4_key = recovered_key.map(hex_key);
    }
    report.readable_dex = ksight_core::publish_readable_dex(dest).unwrap_or(0);
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
    Ok(report)
}

/// Rebuild artifacts and the correlated graph from files already on disk.
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
            native_rule_version: String::new(),
            native_framework_matches: Vec::new(),
            graph: ksight_core::SessionGraph::l0_placeholder(),
            sensitive_files: Vec::new(),
            total_bytes: 0,
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
    finalize_catalog(&mut report, dest)?;
    Ok(report)
}

fn finalize_catalog(report: &mut PackageDumpReport, dest: &Path) -> Result<()> {
    recount_static_trees(report, dest);
    report.artifacts = catalog_dump(dest);
    attach_artifact_hashes(dest, &mut report.artifacts);
    (report.dex_sets, report.dex_index) = build_dex_sets(dest, &report.artifacts);
    report.native_rule_version = ksight_core::native_framework_rule_version();
    report.native_framework_matches = ksight_core::classify_native_frameworks(&report.artifacts);
    report.sensitive_files = catalog_sensitive_files(dest);
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
    report.total_bytes = tree_bytes(dest);
    PACKAGE_DUMP_SCHEMA.clone_into(&mut report.schema_version);
    env!("CARGO_PKG_VERSION").clone_into(&mut report.agent_version);
    if report.created_unix_ms == 0 {
        report.created_unix_ms = unix_ms();
    }
    report.warnings = default_dump_warnings();
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
    std::fs::write(
        dest.join("dump-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}

fn default_dump_warnings() -> Vec<String> {
    vec![
        "plaintext_windows and key_slots are bounded candidate counts, not confirmed secrets"
            .to_owned(),
        "package dump uses root procfs memory access and is L2 forensic evidence, not eBPF Observe"
            .to_owned(),
        "live dump SIGSTOPs selected PIDs while copying /proc/pid/mem; torn=true means the copy raced"
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
        "data-private is a bounded copy of CE shared_prefs/databases/files/no_backup after live harvest; not a full /data/data image".to_owned(),
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
        artifact.sha256 = sha256_file(&dest.join(&artifact.relative_path));
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
            .and_then(|content| ksight_core::parse_dex_semantics(&content));
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
    let mut semantic_parse_failures = 0_usize;
    let mut semantic_index_truncated = false;
    for set in &sets {
        let Some(semantic) = set.semantic.as_ref() else {
            semantic_parse_failures = semantic_parse_failures.saturating_add(1);
            continue;
        };
        semantic_index_truncated |=
            semantic.class_descriptors_truncated || semantic.method_names_truncated;
        for descriptor in &semantic.class_descriptors {
            class_owners
                .entry(descriptor.clone())
                .or_default()
                .insert(set.sha256.clone());
        }
        method_names.extend(semantic.method_names.iter().cloned());
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
        ("runtime/packer-keys", "key_candidate"),
        ("data-private", "private_store"),
    ] {
        visit_files(&dest.join(relative), &mut |path| {
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
    let mut file = File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(format!("{:x}", digest.finalize()))
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
    let _ = std::fs::write(dest.join("HOWTO.txt"), text);
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
    ] {
        if dest.join(name).exists() {
            lines.push(format!("  {name}"));
        }
    }
    let _ = std::fs::write(dest.join("EVIDENCE.txt"), lines.join("\n") + "\n");
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

fn join_art_opens(loaders: &mut [CodeLoaderEntry], artifacts: &[ksight_core::DumpArtifact]) {
    for loader in loaders
        .iter_mut()
        .filter(|loader| loader.origin == "art_open")
    {
        let Some(artifact) = match_art_open_artifact(loader, artifacts) else {
            continue;
        };
        loader.joined_relative_path = Some(artifact.relative_path.clone());
        loader.joined_sha256.clone_from(&artifact.sha256);
    }
}

fn art_open_joins(
    loaders: &[CodeLoaderEntry],
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<(u32, String, String)> {
    let mut joins = Vec::new();
    for loader in loaders.iter().filter(|loader| loader.origin == "art_open") {
        for artifact in artifacts
            .iter()
            .filter(|artifact| art_open_matches(loader, artifact))
        {
            joins.push((
                loader.pid,
                loader.path.clone(),
                artifact_graph_key(artifact),
            ));
        }
    }
    joins
}

fn artifact_graph_key(artifact: &ksight_core::DumpArtifact) -> String {
    artifact.sha256.as_ref().map_or_else(
        || format!("artifact:{}", artifact.relative_path),
        |sha256| format!("artifact:sha256:{sha256}"),
    )
}

fn match_art_open_artifact<'a>(
    loader: &CodeLoaderEntry,
    artifacts: &'a [ksight_core::DumpArtifact],
) -> Option<&'a ksight_core::DumpArtifact> {
    artifacts
        .iter()
        .filter(|artifact| art_open_matches(loader, artifact))
        .max_by_key(|artifact| artifact.bytes)
}

fn art_open_matches(loader: &CodeLoaderEntry, artifact: &ksight_core::DumpArtifact) -> bool {
    if artifact.kind != "dex" {
        return false;
    }
    if let Some((base, size)) = parse_memory_open(&loader.path) {
        if let (Some(start), Some(end)) = (artifact.vma_start, artifact.vma_end) {
            if base >= start && base < end {
                return true;
            }
        }
        let opened = loader.opened_bytes.unwrap_or(size);
        return artifact.bytes.abs_diff(opened) <= 4096;
    }
    let open = loader.path.trim();
    if open.is_empty() {
        return false;
    }
    if artifact.map_path.as_deref() == Some(open) {
        return true;
    }
    if artifact
        .map_path
        .as_deref()
        .is_some_and(|path| path.ends_with(open) || open.ends_with(path))
    {
        return true;
    }
    let open_name = std::path::Path::new(open)
        .file_name()
        .and_then(|name| name.to_str());
    let artifact_name = std::path::Path::new(&artifact.relative_path)
        .file_name()
        .and_then(|name| name.to_str());
    if open_name.is_some() && open_name == artifact_name {
        return true;
    }
    let open_ext = std::path::Path::new(open).extension();
    if open_ext
        .is_some_and(|ext| ext.eq_ignore_ascii_case("apk") || ext.eq_ignore_ascii_case("jar"))
        && artifact.source == "apk-dex"
    {
        let lower = open.to_ascii_lowercase();
        return lower.contains("/data/app")
            || lower.contains("/priv-app/")
            || lower.contains("split_config")
            || open_name == Some("base.apk");
    }
    false
}

fn parse_memory_open(path: &str) -> Option<(u64, u64)> {
    let rest = path.strip_prefix("memory:")?;
    let (base, size) = rest.split_once('+')?;
    let base = u64::from_str_radix(base.trim_start_matches("0x"), 16).ok()?;
    let size = size.parse().ok()?;
    Some((base, size))
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
    for path in paths {
        let Some(kind) = ksight_core::classify_tls_library_path(path) else {
            continue;
        };
        if !seen.insert((kind.as_str(), path)) {
            continue;
        }
        out.push(TlsStackObservation {
            kind: kind.as_str().to_owned(),
            path: path.to_owned(),
            inspect_tries_ssl_write: kind.inspect_tries_ssl_write(),
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

#[derive(Debug, Clone)]
struct MapRange {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

impl MapRange {
    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn readable(&self) -> bool {
        self.perms.contains('r')
    }

    fn executable(&self) -> bool {
        self.perms.contains('x')
    }
}

fn load_maps_file(dest: &Path) -> std::collections::BTreeMap<u32, Vec<MapRange>> {
    let runtime = dest.join("runtime");
    let Ok(entries) = std::fs::read_dir(&runtime) else {
        return std::collections::BTreeMap::new();
    };
    let mut maps = std::collections::BTreeMap::<u32, Vec<MapRange>>::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(pid_s) = name
            .strip_prefix("maps-")
            .and_then(|rest| rest.strip_suffix(".txt"))
        else {
            continue;
        };
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        maps.insert(pid, parse_maps_ranges(&text));
    }
    maps
}

fn maps_as_observed(
    dest: &Path,
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<ksight_core::ObservedMapping> {
    let mut mappings = Vec::new();
    for (pid, ranges) in load_maps_file(dest) {
        for range in ranges {
            if range.end <= range.start || !mapping_needed(pid, &range, artifacts) {
                continue;
            }
            mappings.push(ksight_core::ObservedMapping {
                process_id: pid,
                start: range.start,
                end: range.end,
                backing_path: nonempty_path(&range.path),
                source: ksight_core::MappingSource::ProcMaps,
                mapping_generation: 0,
            });
        }
    }
    ksight_core::rank_observed_mappings(&mut mappings);
    mappings.truncate(512);
    mappings
}

fn mapping_needed(pid: u32, range: &MapRange, artifacts: &[ksight_core::DumpArtifact]) -> bool {
    artifacts.iter().any(|artifact| {
        if artifact.pid != Some(pid) {
            return false;
        }
        if let (Some(start), Some(end)) = (artifact.vma_start, artifact.vma_end) {
            if ksight_core::ranges_overlap(start, end, range.start, range.end) {
                return true;
            }
        } else if let Some(start) = artifact.vma_start {
            if range.contains(start) {
                return true;
            }
        }
        so_file_name(artifact).is_some_and(|name| so_map_matches(range, &name))
    })
}

fn enrich_artifacts_from_maps(dest: &Path, artifacts: &mut [ksight_core::DumpArtifact]) {
    let maps = load_maps_file(dest);
    for artifact in artifacts.iter_mut() {
        if artifact.map_path.as_deref().is_some_and(str::is_empty) {
            artifact.map_path = None;
        }
        let Some(pid) = artifact.pid else {
            continue;
        };
        let Some(ranges) = maps.get(&pid) else {
            continue;
        };
        if artifact.vma_start.is_none() {
            if let Some(name) = so_file_name(artifact) {
                if let Some(range) = so_map(ranges, &name) {
                    artifact.vma_start = Some(range.start);
                    artifact.vma_end = Some(range.end);
                    if artifact.map_path.is_none() {
                        artifact.map_path = nonempty_path(&range.path);
                    }
                }
            }
        }
        let Some(start) = artifact.vma_start else {
            continue;
        };
        let prefer_anon = artifact.source == "heap-blob";
        let Some(range) = covering_map(ranges, start, prefer_anon) else {
            continue;
        };
        if artifact.vma_end.is_none() && range.readable() {
            artifact.vma_end = Some(range.end);
        }
        if artifact.map_path.is_none() {
            artifact.map_path = nonempty_path(&range.path);
        }
    }
}

fn covering_map(ranges: &[MapRange], start: u64, prefer_anon: bool) -> Option<&MapRange> {
    ranges
        .iter()
        .filter(|range| range.contains(start))
        .max_by_key(|range| {
            (
                range.readable(),
                prefer_anon && map_is_anon(&range.path),
                !range.path.starts_with('/'),
                u64::MAX - range.end.saturating_sub(range.start),
            )
        })
}

fn map_is_anon(path: &str) -> bool {
    path.is_empty() || path.starts_with('[') || path.starts_with("anon:")
}

fn so_map<'a>(ranges: &'a [MapRange], so_name: &str) -> Option<&'a MapRange> {
    ranges
        .iter()
        .filter(|range| so_map_matches(range, so_name))
        .max_by_key(|range| {
            (
                range.executable(),
                range.readable(),
                range.end.saturating_sub(range.start),
            )
        })
}

fn so_map_matches(range: &MapRange, so_name: &str) -> bool {
    Path::new(&range.path)
        .file_name()
        .and_then(|name| name.to_str())
        == Some(so_name)
}

fn so_file_name(artifact: &ksight_core::DumpArtifact) -> Option<String> {
    if artifact.source != "runtime-so" {
        return None;
    }
    let name = Path::new(&artifact.relative_path)
        .file_name()
        .and_then(|name| name.to_str())?;
    if let Some(pid) = artifact.pid {
        let prefix = format!("{pid}-");
        if let Some(stripped) = name.strip_prefix(&prefix) {
            return Some(stripped.to_owned());
        }
    }
    Some(name.to_owned())
}

fn nonempty_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn parse_maps_ranges(text: &str) -> Vec<MapRange> {
    let mut ranges = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end_s, 16) else {
            continue;
        };
        let Some(perms) = fields.next() else {
            continue;
        };
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let path = fields.collect::<Vec<_>>().join(" ");
        ranges.push(MapRange {
            start,
            end,
            perms: perms.to_owned(),
            path,
        });
    }
    ranges
}

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
        let _ = std::fs::write(json_path, meta.to_string());
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
        out.push(ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: source.to_owned(),
            relative_path: rel,
            bytes,
            magic: peek_magic(&path),
            pid: None,
            vma_start: None,
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
                let _ = std::fs::write(&key_path, key);
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
        if std::fs::write(&out, &plain).is_err() {
            continue;
        }
        if let Some(repaired) = ksight_core::repair_dex(&plain) {
            let _ = std::fs::write(
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
                let _ = std::fs::write(split_dir.join(format!("part{index:02}.dex")), &slice.bytes);
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
    if package.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        bail!("Android package name contains unsupported characters");
    }
    Ok(())
}

fn apk_paths(package: &str) -> Vec<PathBuf> {
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

fn copy_app_private(package: &str, dest: &Path) -> Result<usize> {
    let mut copied = 0_usize;
    let mut seen = BTreeSet::new();
    for (label, root) in [
        ("ce", format!("/data/user/0/{package}")),
        ("de", format!("/data/user_de/0/{package}")),
        ("ce", format!("/data/data/{package}")),
    ] {
        for dir in APP_PRIVATE_DIRS {
            copied = copied.saturating_add(copy_private_tree(
                &PathBuf::from(&root).join(dir),
                &dest.join(label).join(dir),
                dest,
                &mut seen,
                0,
            )?);
            if copied >= MAX_PRIVATE_FILES {
                return Ok(copied);
            }
        }
    }
    Ok(copied)
}

#[cfg_attr(not(test), allow(dead_code))]
fn copy_app_private_from(roots: &[PathBuf], dest: &Path) -> Result<usize> {
    let mut copied = 0_usize;
    let mut seen = BTreeSet::new();
    for root in roots {
        for dir in APP_PRIVATE_DIRS {
            copied = copied.saturating_add(copy_private_tree(
                &root.join(dir),
                &dest.join(dir),
                dest,
                &mut seen,
                0,
            )?);
            if copied >= MAX_PRIVATE_FILES {
                return Ok(copied);
            }
        }
    }
    Ok(copied)
}

fn copy_private_tree(
    src: &Path,
    dest: &Path,
    dest_root: &Path,
    seen: &mut BTreeSet<String>,
    depth: u32,
) -> Result<usize> {
    if depth > 6 || !src.is_dir() {
        return Ok(0);
    }
    let mut copied = 0_usize;
    let Ok(entries) = std::fs::read_dir(src) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        if seen.len() >= MAX_PRIVATE_FILES {
            break;
        }
        let path = entry.path();
        if path.is_dir() {
            copied = copied.saturating_add(copy_private_tree(
                &path,
                &dest.join(entry.file_name()),
                dest_root,
                seen,
                depth.saturating_add(1),
            )?);
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if skip_private_file(&path) {
            continue;
        }
        let target = dest.join(entry.file_name());
        let Ok(rel) = target.strip_prefix(dest_root) else {
            continue;
        };
        let key = rel.to_string_lossy().replace('\\', "/");
        if !seen.insert(key) {
            continue;
        }
        if copy_capped_path(&path, &target, MAX_PRIVATE_FILE_BYTES).is_ok() && target.is_file() {
            copied = copied.saturating_add(1);
        }
    }
    Ok(copied)
}

fn skip_private_file(path: &Path) -> bool {
    ["jpg", "jpeg", "png", "webp", "mp4", "webm", "gif"]
        .iter()
        .any(|ext| has_ext(path, ext))
}

fn copy_capped_path(src: &Path, dest: &Path, cap: u64) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let meta = src.metadata()?;
    if meta.len() > cap {
        return Ok(());
    }
    let mut input = File::open(src)?;
    let mut output = File::create(dest)?;
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if total.saturating_add(u64::try_from(read).unwrap_or(0)) > cap {
            break;
        }
        output.write_all(&buffer[..read])?;
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
    }
    Ok(())
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

fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(ext))
}

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
mod tests {
    use super::*;

    #[test]
    fn dex_sets_deduplicate_bytes_and_preserve_observations() {
        let dir = std::env::temp_dir().join(format!("ksight-dex-set-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("runtime")).expect("runtime");
        let mut dex = vec![0_u8; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&0x70_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        std::fs::write(dir.join("runtime/a.dex"), &dex).expect("dex");
        let artifacts = vec![
            ksight_core::DumpArtifact {
                kind: "dex".to_owned(),
                source: "memory-dex".to_owned(),
                relative_path: "runtime/a.dex".to_owned(),
                bytes: 0x70,
                magic: "dex".to_owned(),
                pid: Some(7),
                vma_start: Some(0x1000),
                vma_end: Some(0x2000),
                map_path: Some("[anon:dalvik-classes.dex]".to_owned()),
                dex_offset: Some(0),
                sha256: Some("same".to_owned()),
            },
            ksight_core::DumpArtifact {
                kind: "dex".to_owned(),
                source: "apk-dex".to_owned(),
                relative_path: "apk-dex/classes.dex".to_owned(),
                bytes: 0x70,
                magic: "dex".to_owned(),
                pid: None,
                vma_start: None,
                vma_end: None,
                map_path: None,
                dex_offset: None,
                sha256: Some("same".to_owned()),
            },
        ];
        let (sets, index) = build_dex_sets(&dir, &artifacts);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].observations.len(), 2);
        assert_eq!(sets[0].canonical_relative_path, "runtime/a.dex");
        assert!(sets[0].semantic.is_some());
        assert_eq!(index.unique_dex, 1);
        assert_eq!(index.observations, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recatalog_accepts_legacy_dump_reports() {
        let report: PackageDumpReport = serde_json::from_str(
            r#"{"package":"com.icbc","install_dir":null,"apk_files":0,"native_libs":0,"oat_files":0,"apk_dex":0,"launched":false,"pids":[1],"memory_images":0,"vdex_images":0,"fd_images":0,"runtime_libs":0,"packer_regions":32}"#,
        )
        .expect("legacy");
        assert_eq!(report.package, "com.icbc");
        assert_eq!(report.packer_regions, 32);
        assert_eq!(report.asset_files, 0);
        assert!(report.artifacts.is_empty());
        assert!(report.schema_version.is_empty());
        assert!(!report.observation_env.hide_debug_requested);
        assert!(!report.observation_env.denylist_applied);
    }

    #[test]
    fn sensitive_catalog_hashes_plaintext_and_key_candidates() {
        let dir = std::env::temp_dir().join(format!("ksight-sensitive-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("runtime/plaintext")).expect("plaintext dir");
        std::fs::create_dir_all(dir.join("runtime/packer-keys")).expect("key dir");
        std::fs::write(dir.join("runtime/plaintext/http.txt"), b"GET / HTTP/1.1")
            .expect("plaintext");
        std::fs::write(dir.join("runtime/packer-keys/slot.bin"), [7_u8; 16]).expect("key");
        let files = catalog_sensitive_files(&dir);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.sha256.len() == 64));
        assert!(files.iter().all(|file| !file.confirmed));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parses_pm_path_lines() {
        let paths = parse_pm_paths(
            "package:/data/app/~~x==/com.sgcc.wsgw.cn-y==/base.apk\npackage:/data/app/~~x==/com.sgcc.wsgw.cn-y==/split_config.apk\n",
        );
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("base.apk"));
    }

    #[test]
    fn prune_install_trees_keeps_evidence_dirs() {
        let dir = std::env::temp_dir().join(format!("ksight-prune-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("apk")).expect("apk");
        std::fs::create_dir_all(dir.join("lib")).expect("lib");
        std::fs::create_dir_all(dir.join("runtime")).expect("runtime");
        std::fs::create_dir_all(dir.join("data-private")).expect("private");
        std::fs::write(dir.join("apk/base.apk"), b"apk").expect("apk file");
        std::fs::write(dir.join("runtime/maps.txt"), b"maps").expect("maps");
        prune_install_trees(&dir);
        assert!(!dir.join("apk").exists());
        assert!(!dir.join("lib").exists());
        assert!(dir.join("runtime/maps.txt").is_file());
        assert!(dir.join("data-private").is_dir());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn copies_bounded_app_private_prefs_and_skips_media() {
        let root = std::env::temp_dir().join(format!("ksight-private-{}", uuid::Uuid::new_v4()));
        let dest =
            std::env::temp_dir().join(format!("ksight-private-out-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("shared_prefs")).expect("prefs");
        std::fs::create_dir_all(root.join("databases")).expect("db");
        std::fs::create_dir_all(root.join("files")).expect("files");
        std::fs::write(
            root.join("shared_prefs/token.xml"),
            b"<map><string name=\"t\">x</string></map>",
        )
        .expect("xml");
        std::fs::write(root.join("databases/app.db"), b"SQLite format 3\0").expect("db");
        std::fs::write(root.join("files/photo.jpg"), b"not-a-jpeg").expect("jpg");
        let copied = copy_app_private_from(std::slice::from_ref(&root), &dest).expect("copy");
        assert_eq!(copied, 2);
        assert!(dest.join("shared_prefs/token.xml").is_file());
        assert!(dest.join("databases/app.db").is_file());
        assert!(!dest.join("files/photo.jpg").exists());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(dest);
    }

    #[test]
    fn ranks_main_pid_before_service_processes() {
        assert_eq!(crate::dump_guard::cmdline_dump_rank("pkg", "pkg"), 0);
        assert_eq!(crate::dump_guard::cmdline_dump_rank("pkg", "pkg:push"), 1);
    }

    #[test]
    fn rejects_unsafe_package_names() {
        assert!(validate_package("com.sgcc.wsgw.cn").is_ok());
        assert!(validate_package("com.foo; rm -rf /").is_err());
    }

    #[test]
    fn catalogs_heap_blob_sidecars_as_correlated_artifacts() {
        let dir = std::env::temp_dir().join(format!("ksight-catalog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let split = dir.join("apk-dex").join("split");
        let blob = dir.join("runtime").join("blob-dex");
        std::fs::create_dir_all(&split).expect("split");
        std::fs::create_dir_all(&blob).expect("blob");
        let name = "blob-9-abc_part00_0.dex";
        let mut dex = vec![0_u8; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        std::fs::write(split.join(name), &dex).expect("dex");
        std::fs::write(
            blob.join("9-abc.json"),
            r#"{"pid":9,"vma_start":2748,"vma_end":4096,"map_path":"[anon:scudo:secondary]","files":["blob-9-abc_part00_0.dex"]}"#,
        )
        .expect("json");
        std::fs::write(
            dir.join("runtime").join("maps-9.txt"),
            "00000abc-00001000 rw-p 00000000 00:00 0 [anon:scudo:secondary]\n",
        )
        .expect("maps");
        let artifacts = catalog_dump(&dir);
        let heap = artifacts
            .iter()
            .find(|row| row.source == "heap-blob")
            .expect("heap");
        assert_eq!(heap.pid, Some(9));
        assert_eq!(heap.vma_start, Some(2748));
        assert_eq!(heap.map_path.as_deref(), Some("[anon:scudo:secondary]"));
        assert_eq!(
            parse_blob_name("blob-17628-6e61c7b000_part00_2344.dex"),
            Some((17628, 0x006e_61c7_b000, Some(2344)))
        );
        assert_eq!(
            parse_mem_name("mem-28735-6ec9458c90.dex"),
            Some((28735, 0x006e_c945_8c90, None))
        );
        assert_eq!(
            parse_mem_name("mem-2706-6ec9587000+5cd0.dex"),
            Some((2706, 0x006e_c958_7000, Some(0x5cd0)))
        );
        let mut graph = ksight_core::SessionGraph::from_package_dump(
            uuid::Uuid::nil(),
            "demo.pkg",
            &[9],
            &artifacts,
        );
        graph.correlate_dump_vmas(
            uuid::Uuid::nil(),
            &artifacts,
            &maps_as_observed(&dir, &artifacts),
        );
        assert!(graph
            .edges
            .iter()
            .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.relation == "overlaps_mmap"
                && edge.strength == ksight_core::EdgeStrength::Correlated
                && edge.to.starts_with("proc_maps:9:")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ok_marker_survives_guard_maps_and_high_address_noise() {
        let dir = std::env::temp_dir().join(format!("ksight-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let split = dir.join("apk-dex").join("split");
        let blob = dir.join("runtime").join("blob-dex");
        let so_dir = dir.join("runtime").join("runtime-so");
        std::fs::create_dir_all(&split).expect("split");
        std::fs::create_dir_all(&blob).expect("blob");
        std::fs::create_dir_all(&so_dir).expect("so");
        let name = "blob-9-6e5f3f1000_part00_40.dex";
        let mut dex = vec![0_u8; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        std::fs::write(split.join(name), &dex).expect("dex");
        std::fs::write(
            blob.join("9-6e5f3f1000.ok"),
            "seq=56 bytes=53604352 slices=1\n",
        )
        .expect("ok");
        std::fs::write(
            so_dir.join("9-libexec.so"),
            [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
        )
        .expect("so");
        let mut maps = String::new();
        for index in 0..600_u32 {
            let start = index * 0x1000;
            let _ = std::fmt::Write::write_fmt(
                &mut maps,
                format_args!(
                    "{start:08x}-{:08x} rw-p 00000000 00:00 0 [anon:pad]\n",
                    start + 0x1000
                ),
            );
        }
        maps.push_str("6e5de00000-6e60c00000 ---p 00000000 00:00 0 \n");
        maps.push_str(
            "6ec9464000-6ec94a4000 r-xp 00000000 fe:37 1 /data/data/demo/files/libexec.so\n",
        );
        std::fs::write(dir.join("runtime").join("maps-9.txt"), maps).expect("maps");

        let artifacts = catalog_dump(&dir);
        let heap = artifacts
            .iter()
            .find(|row| row.source == "heap-blob")
            .expect("heap");
        assert_eq!(heap.vma_start, Some(0x006e_5f3f_1000));
        assert_eq!(heap.vma_end, Some(0x006e_5f3f_1000 + 53_604_352));
        assert_eq!(heap.map_path, None);
        let so = artifacts
            .iter()
            .find(|row| row.source == "runtime-so")
            .expect("so");
        assert_eq!(so.vma_start, Some(0x006e_c946_4000));
        assert_eq!(so.vma_end, Some(0x006e_c94a_4000));
        assert_eq!(
            so.map_path.as_deref(),
            Some("/data/data/demo/files/libexec.so")
        );

        let mut graph = ksight_core::SessionGraph::from_package_dump(
            uuid::Uuid::nil(),
            "demo.pkg",
            &[9],
            &artifacts,
        );
        graph.correlate_dump_vmas(
            uuid::Uuid::nil(),
            &artifacts,
            &maps_as_observed(&dir, &artifacts),
        );
        assert!(graph
            .edges
            .iter()
            .filter(|edge| edge.relation == "overlaps_mmap")
            .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
        assert!(graph.edges.iter().any(|edge| {
            edge.relation == "overlaps_mmap" && edge.from.starts_with("vma:9:6e5f3f1000-")
        }));
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.relation == "extracted_from" && edge.from.contains("libexec.so") }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalogs_live_memory_dex_with_vma() {
        let dir = std::env::temp_dir().join(format!("ksight-memdex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let runtime = dir.join("runtime");
        std::fs::create_dir_all(&runtime).expect("runtime");
        let mut dex = vec![0_u8; 2048];
        dex[..8].copy_from_slice(b"dex\n035\0");
        std::fs::write(runtime.join("mem-11-6ec9458c90.dex"), &dex).expect("dex");
        std::fs::write(
            runtime.join("maps-11.txt"),
            "6ec9458000-6ec9460000 r--p 00000000 00:00 0 [anon:dalvik-classes.dex]\n",
        )
        .expect("maps");
        let artifacts = catalog_dump(&dir);
        let mem = artifacts
            .iter()
            .find(|row| row.source == "memory-dex")
            .expect("memory-dex");
        assert_eq!(mem.pid, Some(11));
        assert_eq!(mem.vma_start, Some(0x006e_c945_8c90));
        assert_eq!(mem.vma_end, Some(0x006e_c946_0000));
        assert_eq!(mem.map_path.as_deref(), Some("[anon:dalvik-classes.dex]"));
        let graph = ksight_core::SessionGraph::from_package_dump(
            uuid::Uuid::nil(),
            "com.icbc",
            &[11],
            &artifacts,
        );
        assert!(graph.edges.iter().any(|edge| edge.relation == "produced"));
        assert!(graph
            .edges
            .iter()
            .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_skips_duplicate_apk_dex_and_file_backed_heaps() {
        let dir = std::env::temp_dir().join(format!("ksight-dedupe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let split = dir.join("apk-dex").join("split");
        let blob = dir.join("runtime").join("blob-dex");
        std::fs::create_dir_all(&split).expect("split");
        std::fs::create_dir_all(&blob).expect("blob");
        let mut dex = vec![0_u8; 2048];
        dex[..8].copy_from_slice(b"dex\n035\0");
        std::fs::write(split.join("classes.dex"), &dex).expect("split");
        std::fs::write(dir.join("apk-dex").join("classes.dex"), &dex).expect("root");
        std::fs::write(split.join("blob-8-abc_part00_0.dex"), &dex).expect("heap");
        std::fs::write(
            blob.join("8-abc.json"),
            r#"{"pid":8,"vma_start":2748,"vma_end":4096,"map_path":"/data/app/x/oat/arm64/base.vdex","files":["blob-8-abc_part00_0.dex"]}"#,
        )
        .expect("json");
        std::fs::write(
            dir.join("runtime").join("maps-8.txt"),
            "00000abc-00001000 r--p 00000000 00:00 0 /data/app/x/oat/arm64/base.vdex\n",
        )
        .expect("maps");
        std::fs::write(dir.join("runtime").join("mem-8-1000.dex"), vec![0_u8; 200]).expect("tiny");
        let artifacts = catalog_dump(&dir);
        assert_eq!(
            artifacts
                .iter()
                .filter(|row| row.source == "apk-dex")
                .count(),
            1
        );
        assert!(artifacts.iter().all(|row| row.source != "heap-blob"));
        assert!(artifacts.iter().all(|row| row.source != "memory-dex"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_keeps_writable_app_so_blobs() {
        let dir = std::env::temp_dir().join(format!("ksight-so-blob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let split = dir.join("apk-dex").join("split");
        let blob = dir.join("runtime").join("blob-dex");
        std::fs::create_dir_all(&split).expect("split");
        std::fs::create_dir_all(&blob).expect("blob");
        let mut dex = vec![0_u8; 2048];
        dex[..8].copy_from_slice(b"dex\n035\0");
        std::fs::write(split.join("blob-8-aaa_part00_0.dex"), &dex).expect("so blob");
        std::fs::write(split.join("blob-8-bbb_part00_0.dex"), &dex).expect("vdex blob");
        std::fs::write(
            blob.join("8-aaa.json"),
            r#"{"pid":8,"vma_start":1000,"vma_end":2000,"map_path":"/data/app/x/lib/arm64/libpayload.so","files":["blob-8-aaa_part00_0.dex"]}"#,
        )
        .expect("so json");
        std::fs::write(
            blob.join("8-bbb.json"),
            r#"{"pid":8,"vma_start":3000,"vma_end":4000,"map_path":"/data/app/x/oat/arm64/base.vdex","files":["blob-8-bbb_part00_0.dex"]}"#,
        )
        .expect("vdex json");
        std::fs::write(split.join("blob-8-ccc_part00_0.dex"), &dex).expect("memfd blob");
        std::fs::write(
            blob.join("8-ccc.json"),
            r#"{"pid":8,"vma_start":5000,"vma_end":6000,"map_path":"/memfd:classes","files":["blob-8-ccc_part00_0.dex"]}"#,
        )
        .expect("memfd json");
        let artifacts = catalog_dump(&dir);
        let kept: Vec<_> = artifacts
            .iter()
            .filter(|row| row.source == "heap-blob")
            .collect();
        assert_eq!(kept.len(), 2);
        assert!(kept
            .iter()
            .any(|row| { row.map_path.as_deref() == Some("/data/app/x/lib/arm64/libpayload.so") }));
        assert!(kept
            .iter()
            .any(|row| row.map_path.as_deref() == Some("/memfd:classes")));
        assert!(kept.iter().all(|row| {
            row.map_path.as_deref().is_none_or(|path| {
                std::path::Path::new(path)
                    .extension()
                    .is_none_or(|ext| !ext.eq_ignore_ascii_case("vdex"))
            })
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn art_file_open_joins_apk_dex_from_data_app() {
        let mut loaders = vec![CodeLoaderEntry {
            pid: 9,
            order: 1,
            role: "install".to_owned(),
            origin: "art_open".to_owned(),
            path: "/data/app/~~x==/pkg-y==/base.apk".to_owned(),
            ..CodeLoaderEntry::default()
        }];
        let artifacts = vec![ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "apk-dex".to_owned(),
            relative_path: "apk-dex/classes.dex".to_owned(),
            bytes: 128,
            magic: "dex".to_owned(),
            pid: None,
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: Some("abc".to_owned()),
        }];
        join_art_opens(&mut loaders, &artifacts);
        assert_eq!(
            loaders[0].joined_relative_path.as_deref(),
            Some("apk-dex/classes.dex")
        );
        assert_eq!(loaders[0].joined_sha256.as_deref(), Some("abc"));
        let joins = art_open_joins(&loaders, &artifacts);
        assert_eq!(joins[0].2, "artifact:sha256:abc");
    }

    #[test]
    fn art_memory_open_joins_containing_vma() {
        let mut loaders = vec![CodeLoaderEntry {
            pid: 4,
            order: 1,
            role: "in_memory".to_owned(),
            origin: "art_open".to_owned(),
            path: "memory:0x1200+64".to_owned(),
            opened_bytes: Some(64),
            ..CodeLoaderEntry::default()
        }];
        let artifacts = vec![ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: "apk-dex/split/blob.dex".to_owned(),
            bytes: 64,
            magic: "dex".to_owned(),
            pid: Some(4),
            vma_start: Some(0x1000),
            vma_end: Some(0x2000),
            map_path: Some("[anon:scudo:secondary]".to_owned()),
            dex_offset: Some(0),
            sha256: Some("heap".to_owned()),
        }];
        join_art_opens(&mut loaders, &artifacts);
        assert_eq!(
            loaders[0].joined_relative_path.as_deref(),
            Some("apk-dex/split/blob.dex")
        );
    }
}
