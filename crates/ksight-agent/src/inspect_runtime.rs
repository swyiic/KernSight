//! Inspect adapter orchestration. Default-off, auditable, exported-symbol only.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use ksight_core::InspectPolicy;
use ksight_model::{InspectObservation, InspectPlaintext, ProcessIdentity, ProcessKey};
#[cfg(any(target_os = "android", target_os = "linux"))]
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::elf::{inspect_elf, symbol_match};

const LINKER_NAMES: [&str; 3] = ["__loader_dlopen", "do_dlopen", "android_dlopen_ext"];
const LINKER_PATHS: [&str; 2] = [
    "/apex/com.android.runtime/bin/linker64",
    "/system/bin/linker64",
];
const TLS_NAMES: [&str; 1] = ["SSL_write"];
const TLS_PATHS: [&str; 2] = [
    "/apex/com.android.conscrypt/lib64/libssl.so",
    "/system/lib64/libssl.so",
];
const ART_DEX_NAMES: [&str; 1] = ["_ZNK3art16ArtDexFileLoader4OpenEPKc"];
/// Exported `ArtDexFileLoader::Open(uint8_t const*, size_t, ...)` on Android 14 `libdexfile.so`.
/// There is no `OpenMemory` symbol; this exact dynsym name is required.
const ART_DEX_MEMORY_NAMES: [&str; 1] = [
    "_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE",
];
const ART_DEX_PATHS: [&str; 1] = ["/apex/com.android.art/lib64/libdexfile.so"];
const BINDER_NAMES: [&str; 1] = ["_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j"];
const BINDER_PATHS: [&str; 1] = ["/system/lib64/libbinder.so"];
#[cfg(any(target_os = "android", target_os = "linux"))]
const REMOTE_PATH_BYTES: usize = 256;
#[cfg(any(target_os = "android", target_os = "linux"))]
const MAX_PAYLOAD_BYTES: usize = 4096;

/// Named Inspect adapter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InspectAdapterKind {
    /// linker64 SO load boundary.
    #[default]
    LinkerSoLoad,
    /// ART DEX load via exported `ArtDexFileLoader::Open(const char*)`.
    ArtDexLoad,
    /// ART in-memory DEX via exported `Open(uint8_t const*, size_t, ...)`.
    ArtDexMemory,
    /// JNI native registration. No exported JNI table boundary on this build.
    JniRegistration,
    /// Userspace Binder `IPCThreadState::transact`.
    BinderUserspace,
    /// BoringSSL/Conscrypt `SSL_write` plaintext (outbound).
    TlsSslWrite,
}

impl InspectAdapterKind {
    /// Stable adapter identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinkerSoLoad => "linker_so_load",
            Self::ArtDexLoad => "art_dex_load",
            Self::ArtDexMemory => "art_dex_memory",
            Self::JniRegistration => "jni_registration",
            Self::BinderUserspace => "binder_userspace",
            Self::TlsSslWrite => "tls_ssl_write",
        }
    }

    fn libraries(self) -> &'static [&'static str] {
        match self {
            Self::LinkerSoLoad => &LINKER_PATHS,
            Self::ArtDexLoad | Self::ArtDexMemory => &ART_DEX_PATHS,
            Self::JniRegistration => &[],
            Self::BinderUserspace => &BINDER_PATHS,
            Self::TlsSslWrite => &TLS_PATHS,
        }
    }

    fn symbols(self) -> &'static [&'static str] {
        match self {
            Self::LinkerSoLoad => &LINKER_NAMES,
            Self::ArtDexLoad => &ART_DEX_NAMES,
            Self::ArtDexMemory => &ART_DEX_MEMORY_NAMES,
            Self::JniRegistration => &[],
            Self::BinderUserspace => &BINDER_NAMES,
            Self::TlsSslWrite => &TLS_NAMES,
        }
    }

    fn map_needles(self) -> &'static [&'static str] {
        match self {
            Self::TlsSslWrite => &["libssl.so"],
            Self::ArtDexLoad | Self::ArtDexMemory => &["libdexfile.so"],
            Self::BinderUserspace => &["libbinder.so"],
            Self::LinkerSoLoad => &["/bin/linker64"],
            Self::JniRegistration => &[],
        }
    }

    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    fn hit_once(self) -> bool {
        matches!(self, Self::LinkerSoLoad)
    }

    fn default_max_hits(self) -> u32 {
        match self {
            Self::ArtDexLoad | Self::ArtDexMemory => 64,
            Self::BinderUserspace => 256,
            Self::TlsSslWrite => 1024,
            Self::LinkerSoLoad | Self::JniRegistration => 1,
        }
    }

    /// Adapters recorded as audited stubs when another adapter is selected.
    pub const fn audited_stubs(self) -> &'static [Self] {
        match self {
            Self::TlsSslWrite | Self::LinkerSoLoad => &[
                Self::ArtDexLoad,
                Self::ArtDexMemory,
                Self::JniRegistration,
                Self::BinderUserspace,
            ],
            _ => &[],
        }
    }
}

impl FromStr for InspectAdapterKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linker_so_load" => Ok(Self::LinkerSoLoad),
            "art_dex_load" => Ok(Self::ArtDexLoad),
            "art_dex_memory" => Ok(Self::ArtDexMemory),
            "jni_registration" => Ok(Self::JniRegistration),
            "binder_userspace" => Ok(Self::BinderUserspace),
            "tls_ssl_write" => Ok(Self::TlsSslWrite),
            other => Err(format!(
                "unknown inspect adapter {other}; expected linker_so_load, art_dex_load, art_dex_memory, jni_registration, binder_userspace, or tls_ssl_write"
            )),
        }
    }
}

/// Runtime Inspect plan produced before capture starts.
#[derive(Debug, Clone)]
pub struct InspectPlan {
    /// Policy used for this session.
    pub policy: InspectPolicy,
    /// Adapter selected by the operator.
    pub adapter: InspectAdapterKind,
    /// Uprobe object path when a probe may attach.
    pub uprobe_object: PathBuf,
    /// Resolved ELF path.
    pub elf_path: Option<String>,
    /// Resolved file offset.
    pub offset: Option<u64>,
    /// Observed GNU build-id.
    pub build_id: Option<String>,
    /// Decision emitted into the session.
    pub observation: InspectObservation,
}

impl InspectPlan {
    /// Evaluate adapter policy without attaching.
    pub fn evaluate(
        policy: InspectPolicy,
        adapter: InspectAdapterKind,
        uprobe_object: PathBuf,
    ) -> Vec<Self> {
        let libraries = resolve_libraries(&policy, adapter);
        if libraries.is_empty() {
            let elf_path = policy.elf_path.clone();
            vec![evaluate_one(policy, adapter, uprobe_object, elf_path)]
        } else {
            libraries
                .into_iter()
                .map(|library| {
                    evaluate_one(
                        policy.clone(),
                        adapter,
                        uprobe_object.clone(),
                        Some(library),
                    )
                })
                .collect()
        }
    }

    /// Whether a live probe should be attempted.
    pub fn should_attach(&self) -> bool {
        self.adapter != InspectAdapterKind::JniRegistration
            && self.policy.may_attach()
            && self.offset.is_some()
            && self.elf_path.is_some()
            && Path::new(&self.uprobe_object).is_file()
    }
}

/// A live Inspect decision or a plaintext fragment.
pub enum InspectOutput {
    /// Adapter attach/refuse/hit audit.
    Observation(InspectObservation),
    /// Bounded TLS write copy attributed to `pid`.
    Plaintext {
        /// Process that executed `SSL_write`.
        pid: u32,
        /// Thread that executed `SSL_write`.
        tid: u32,
        /// Copied fragment.
        fragment: InspectPlaintext,
    },
}

/// Live Inspect session: evaluate, optionally attach, poll, and expire.
pub struct InspectRuntime {
    plans: Vec<InspectPlan>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    selected: InspectAdapterKind,
    started: Instant,
    max_duration: Duration,
    max_hits: u32,
    hits: u32,
    expired: bool,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    sessions: Vec<LiveProbe>,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
struct LiveProbe {
    plan: InspectPlan,
    session: ksight_hwbp::UprobeSession,
}

impl InspectRuntime {
    /// Evaluate the selected adapter and any registered audited stubs.
    pub fn prepare(
        policy: &InspectPolicy,
        adapter: InspectAdapterKind,
        uprobe_object: &Path,
    ) -> Self {
        let mut policy = policy.clone();
        if policy.max_hits == 0 {
            policy.max_hits = adapter.default_max_hits();
        }
        if policy.whole_device {
            policy.detectability_notice = format!(
                "{}; whole-device {} inspect is detectable by every process mapping the target ELF",
                policy.detectability_notice,
                adapter.as_str()
            );
        }
        let max_duration = if policy.max_duration_secs == 0 {
            Duration::from_secs(u64::MAX / 4)
        } else {
            Duration::from_secs(u64::from(policy.max_duration_secs))
        };
        let max_hits = policy.max_hits.max(1);
        let uprobe_object = uprobe_object.to_path_buf();
        let mut plans = InspectPlan::evaluate(policy.clone(), adapter, uprobe_object.clone());
        for stub in adapter.audited_stubs() {
            plans.extend(InspectPlan::evaluate(
                policy.clone(),
                *stub,
                uprobe_object.clone(),
            ));
        }
        Self {
            plans,
            selected: adapter,
            started: Instant::now(),
            max_duration,
            max_hits,
            hits: 0,
            expired: false,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            sessions: Vec::new(),
        }
    }

    /// Decisions that must be recorded before live collection.
    pub fn initial_observations(&self) -> Vec<InspectObservation> {
        self.plans
            .iter()
            .map(|plan| plan.observation.clone())
            .collect()
    }

    /// Attach every plan that is allowed to probe.
    pub fn attach(&mut self) -> Vec<InspectObservation> {
        attach_all(self)
    }

    /// Poll authorized hits.
    pub fn poll(&mut self) -> Vec<InspectOutput> {
        if self.expired {
            return Vec::new();
        }
        poll_all(self)
    }

    /// Revoke unused probes after the authorized window or hit budget.
    pub fn expire_if_needed(&mut self) -> Option<InspectObservation> {
        let over_time = self.started.elapsed() >= self.max_duration;
        let over_hits = self.hits >= self.max_hits;
        if self.expired || (!over_time && !over_hits) {
            return None;
        }
        self.expired = true;
        if !take_attached_sessions(self) {
            return None;
        }
        let mut observation = self.plans.first()?.observation.clone();
        observation.attached = false;
        observation.hit = self.hits > 0;
        observation.detail = if over_hits {
            format!("inspect hit budget reached ({})", self.hits)
        } else {
            "inspect window elapsed; probe revoked".to_owned()
        };
        Some(observation)
    }
}

#[allow(clippy::too_many_lines)]
fn evaluate_one(
    policy: InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: PathBuf,
    elf_path: Option<String>,
) -> InspectPlan {
    let mut observation = InspectObservation {
        adapter: adapter.as_str().to_owned(),
        attached: false,
        hit: false,
        library: elf_path.clone().unwrap_or_default(),
        build_id: policy.build_id.clone(),
        offset: policy.offset,
        path_hint: None,
        detail: String::new(),
        detectability_notice: policy.detectability_notice.clone(),
    };
    if !policy.enabled {
        "inspect disabled by policy".clone_into(&mut observation.detail);
        return plan(
            policy,
            adapter,
            uprobe_object,
            None,
            None,
            None,
            observation,
        );
    }
    if adapter == InspectAdapterKind::JniRegistration {
        "jni_registration has no exported JNI RegisterNatives boundary on this Android build; refusing to guess"
            .clone_into(&mut observation.detail);
        return plan(
            policy,
            adapter,
            uprobe_object,
            None,
            None,
            None,
            observation,
        );
    }
    if !policy.may_attach() {
        "inspect enabled but no app selector; pass --package, --pid, or --uid"
            .clone_into(&mut observation.detail);
        return plan(
            policy,
            adapter,
            uprobe_object,
            None,
            None,
            None,
            observation,
        );
    }
    let Some(elf_path) =
        elf_path.or_else(|| adapter.libraries().first().map(|path| (*path).to_owned()))
    else {
        "no candidate ELF for this adapter".clone_into(&mut observation.detail);
        return plan(
            policy,
            adapter,
            uprobe_object,
            None,
            None,
            None,
            observation,
        );
    };
    observation.library.clone_from(&elf_path);
    match inspect_elf(&elf_path) {
        Ok(elf) => {
            if let Some(required) = policy.build_id.as_deref() {
                match elf.build_id.as_deref() {
                    Some(actual) if actual == required => {}
                    Some(actual) => {
                        observation.build_id = Some(actual.to_owned());
                        observation.detail =
                            format!("build-id mismatch: required {required}, found {actual}");
                        return plan(
                            policy,
                            adapter,
                            uprobe_object,
                            Some(elf_path),
                            None,
                            elf.build_id,
                            observation,
                        );
                    }
                    None => {
                        "ELF has no GNU build-id".clone_into(&mut observation.detail);
                        return plan(
                            policy,
                            adapter,
                            uprobe_object,
                            Some(elf_path),
                            None,
                            None,
                            observation,
                        );
                    }
                }
            }
            let matched = policy
                .offset
                .map(|offset| (String::new(), offset))
                .or_else(|| {
                    symbol_match(&elf, adapter.symbols())
                        .map(|(name, offset)| (name.to_owned(), offset))
                });
            observation.build_id.clone_from(&elf.build_id);
            observation.offset = matched.as_ref().map(|(_, offset)| *offset);
            if matched.is_none() {
                observation.detail = format!(
                    "{} symbol/offset not found in {}; adapter not attached",
                    adapter.as_str(),
                    elf_path
                );
            } else if Path::new(&uprobe_object).is_file() {
                observation.detail = format!(
                    "ready to attach {} uprobe{}{}",
                    adapter.as_str(),
                    matched
                        .as_ref()
                        .filter(|(name, _)| !name.is_empty())
                        .map_or_else(String::new, |(name, _)| format!(" symbol={name}")),
                    matched
                        .as_ref()
                        .map_or_else(String::new, |(_, offset)| format!(" offset={offset:#x}"))
                );
            } else {
                observation.detail = format!("uprobe object missing: {}", uprobe_object.display());
            }
            plan(
                policy,
                adapter,
                uprobe_object,
                Some(elf_path),
                observation.offset,
                elf.build_id,
                observation,
            )
        }
        Err(error) => {
            observation.detail = error;
            plan(
                policy,
                adapter,
                uprobe_object,
                Some(elf_path),
                None,
                None,
                observation,
            )
        }
    }
}

fn plan(
    policy: InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: PathBuf,
    elf_path: Option<String>,
    offset: Option<u64>,
    build_id: Option<String>,
    observation: InspectObservation,
) -> InspectPlan {
    InspectPlan {
        policy,
        adapter,
        uprobe_object,
        elf_path,
        offset,
        build_id,
        observation,
    }
}

fn resolve_libraries(policy: &InspectPolicy, adapter: InspectAdapterKind) -> Vec<String> {
    if let Some(path) = policy.elf_path.clone() {
        return vec![path];
    }
    let mut found = BTreeSet::new();
    for path in adapter.libraries() {
        if Path::new(path).is_file() {
            found.insert((*path).to_owned());
        }
    }
    for path in discover_mapped_libraries(adapter.map_needles()) {
        found.insert(path);
    }
    found.into_iter().take(8).collect()
}

fn discover_mapped_libraries(needles: &[&str]) -> Vec<String> {
    if needles.is_empty() {
        return Vec::new();
    }
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = BTreeSet::new();
    for entry in proc.flatten().take(2048) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().last() else {
                continue;
            };
            if !path.starts_with('/') {
                continue;
            }
            if needles.iter().any(|needle| path.contains(needle)) {
                found.insert(path.to_owned());
            }
            if found.len() >= 8 {
                return found.into_iter().collect();
            }
        }
    }
    found.into_iter().collect()
}

fn take_attached_sessions(runtime: &mut InspectRuntime) -> bool {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let had = !runtime.sessions.is_empty();
        runtime.sessions.clear();
        had
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = runtime;
        false
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn attach_all(runtime: &mut InspectRuntime) -> Vec<InspectObservation> {
    let mut out = Vec::new();
    let selected = runtime.selected;
    let plans = runtime
        .plans
        .iter()
        .filter(|plan| plan.adapter == selected && plan.should_attach())
        .cloned()
        .collect::<Vec<_>>();
    for plan in plans {
        // Kernel uprobe `pid` is a thread id. Attach globally and filter TGID in userspace.
        let Some(elf) = plan.elf_path.as_ref().map(PathBuf::from) else {
            continue;
        };
        let Some(offset) = plan.offset else {
            continue;
        };
        let hit_once = plan.adapter.hit_once() && !plan.policy.whole_device;
        match ksight_hwbp::UprobeSession::start(&plan.uprobe_object, &elf, offset, None, hit_once) {
            Ok(session) => {
                let mut observation = plan.observation.clone();
                observation.attached = true;
                let scope = if plan.policy.whole_device {
                    "all-apps".to_owned()
                } else if let Some(package) = plan.policy.package.as_deref() {
                    format!("package={package}")
                } else if let Some(pid) = plan.policy.pid {
                    format!("pid={pid}")
                } else if let Some(uid) = plan.policy.uid {
                    format!("uid={uid}")
                } else {
                    "unscoped".to_owned()
                };
                observation.detail = format!(
                    "attached {} uprobe filter={scope} offset={offset:#x} hit_once={hit_once} max_hits={}",
                    plan.adapter.as_str(),
                    runtime.max_hits
                );
                runtime.sessions.push(LiveProbe { plan, session });
                out.push(observation);
            }
            Err(error) => {
                let mut observation = plan.observation.clone();
                observation.attached = false;
                observation.detail = format!("attach failed: {error:#}");
                out.push(observation);
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn attach_all(_runtime: &mut InspectRuntime) -> Vec<InspectObservation> {
    Vec::new()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn poll_all(runtime: &mut InspectRuntime) -> Vec<InspectOutput> {
    let mut out = Vec::new();
    let max_payload = usize::try_from(
        runtime
            .plans
            .first()
            .map_or(256, |plan| plan.policy.max_payload_bytes.max(1)),
    )
    .unwrap_or(256)
    .min(MAX_PAYLOAD_BYTES);
    for probe in &mut runtime.sessions {
        if runtime.hits >= runtime.max_hits {
            break;
        }
        let Ok(hits) = probe.session.poll_hits() else {
            continue;
        };
        for hit in hits {
            if runtime.hits >= runtime.max_hits {
                break;
            }
            if let Some(output) = decode_hit(&probe.plan, &hit, max_payload) {
                runtime.hits = runtime.hits.saturating_add(1);
                out.push(output);
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn poll_all(_runtime: &mut InspectRuntime) -> Vec<InspectOutput> {
    Vec::new()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_hit(
    plan: &InspectPlan,
    hit: &ksight_hwbp::RegisterContext,
    max_payload: usize,
) -> Option<InspectOutput> {
    let pid = if hit.pid == 0 {
        plan.policy.pid.unwrap_or(0)
    } else {
        hit.pid
    };
    let identity = process_identity(pid, hit.tid, Uuid::nil());
    if !hit_matches_policy(&plan.policy, &identity) {
        return None;
    }
    match plan.adapter {
        InspectAdapterKind::TlsSslWrite => {
            let requested = i32::try_from(hit.regs[2] as i64).unwrap_or(0);
            if requested <= 0 {
                return None;
            }
            let requested_bytes = u64::try_from(requested).unwrap_or(0);
            let want = usize::try_from(requested_bytes)
                .unwrap_or(0)
                .min(max_payload);
            let bytes = read_remote_bytes(pid, hit.regs[1], want).unwrap_or_default();
            let truncated = requested_bytes > u64::try_from(bytes.len()).unwrap_or(0);
            let content_class = classify_buffer(&bytes);
            let (preview, preview_encoding) = if content_class == "tls_record" {
                (tls_record_preview(&bytes), "tls_record".to_owned())
            } else {
                preview_bytes(&bytes)
            };
            Some(InspectOutput::Plaintext {
                pid,
                tid: hit.tid,
                fragment: InspectPlaintext {
                    adapter: plan.adapter.as_str().to_owned(),
                    direction: "send".to_owned(),
                    library: plan.elf_path.clone().unwrap_or_default(),
                    build_id: plan.build_id.clone(),
                    offset: plan.offset,
                    requested_bytes,
                    captured_bytes: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                    truncated,
                    sha256: hex_sha256(&bytes),
                    preview,
                    preview_encoding,
                    content_class: content_class.to_owned(),
                },
            })
        }
        InspectAdapterKind::LinkerSoLoad => {
            let path_hint = read_remote_cstring(pid, hit.regs[0], REMOTE_PATH_BYTES);
            let mut observation = plan.observation.clone();
            observation.attached = true;
            observation.hit = true;
            observation.path_hint = path_hint;
            observation.detail = format!(
                "linker SO-load hit pid={pid} pc={:#x} x0={}",
                hit.pc,
                observation.path_hint.as_deref().unwrap_or("unreadable")
            );
            Some(InspectOutput::Observation(observation))
        }
        InspectAdapterKind::ArtDexLoad => {
            let path_hint = read_remote_cstring(pid, hit.regs[1], REMOTE_PATH_BYTES);
            let mut observation = plan.observation.clone();
            observation.attached = true;
            observation.hit = true;
            observation.path_hint = path_hint;
            observation.detail = format!(
                "ART DEX Open hit pid={pid} path={}",
                observation.path_hint.as_deref().unwrap_or("unreadable")
            );
            Some(InspectOutput::Observation(observation))
        }
        InspectAdapterKind::ArtDexMemory => {
            let base = hit.regs[1];
            let size = hit.regs[2];
            let header = read_remote_bytes(pid, base, 8).unwrap_or_default();
            let magic = if ksight_core::is_dex_magic(&header) {
                "dex"
            } else {
                "unknown"
            };
            let mut observation = plan.observation.clone();
            observation.attached = true;
            observation.hit = true;
            observation.path_hint = Some(format!("memory:{base:#x}+{size}"));
            observation.detail = format!(
                "ART DEX Open(memory) hit pid={pid} base={base:#x} size={size} magic={magic} (no OpenMemory symbol; exported Open(uint8_t*, size_t) only)"
            );
            Some(InspectOutput::Observation(observation))
        }
        InspectAdapterKind::BinderUserspace => {
            let handle = hit.regs[1] as u32;
            let code = hit.regs[2] as u32;
            let mut observation = plan.observation.clone();
            observation.attached = true;
            observation.hit = true;
            observation.detail = format!(
                "binder transact hit pid={pid} handle={handle} code={code:#x} (descriptor not decoded)"
            );
            Some(InspectOutput::Observation(observation))
        }
        InspectAdapterKind::JniRegistration => None,
    }
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn classify_buffer(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 3 {
        let record = bytes[0];
        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        if matches!(record, 0x14..=0x17) && matches!(version, 0x0301..=0x0304) {
            return "tls_record";
        }
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if !bytes.is_empty() && printable.saturating_mul(4) >= bytes.len().saturating_mul(3) {
        "text"
    } else {
        "binary"
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn tls_record_preview(bytes: &[u8]) -> String {
    let record = bytes.first().copied().unwrap_or(0);
    let kind = match record {
        0x14 => "change_cipher_spec",
        0x15 => "alert",
        0x16 => "handshake",
        0x17 => "application_data",
        _ => "record",
    };
    let length = bytes
        .get(3..5)
        .and_then(|slice| slice.try_into().ok())
        .map_or(0_u16, u16::from_be_bytes);
    format!(
        "TLS {kind} version=0x{:04x} record_len={length} (ciphertext, not HTTP)",
        bytes
            .get(1..3)
            .and_then(|slice| slice.try_into().ok())
            .map_or(0_u16, u16::from_be_bytes)
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn preview_bytes(bytes: &[u8]) -> (String, String) {
    if bytes.is_empty() {
        return (String::new(), "utf8_lossy".to_owned());
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if printable * 4 >= bytes.len() * 3 {
        (
            String::from_utf8_lossy(bytes).into_owned(),
            "utf8_lossy".to_owned(),
        )
    } else {
        {
            let mut out = String::with_capacity(bytes.len().saturating_mul(2));
            for byte in bytes {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
            }
            (out, "hex".to_owned())
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn hit_matches_policy(policy: &InspectPolicy, identity: &ProcessIdentity) -> bool {
    if policy.whole_device {
        return true;
    }
    crate::scope::CaptureScope {
        target_tgid: policy.pid,
        target_uid: policy.uid,
        target_package: policy.package.clone(),
    }
    .matches(identity)
}

/// Best-effort process identity for an Inspect hit.
pub fn process_identity(pid: u32, tid: u32, boot_id: Uuid) -> ProcessIdentity {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map_or_else(|| format!("pid-{pid}"), |value| value.trim().to_owned());
    let command_line = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|bytes| {
            let first = bytes.split(|byte| *byte == 0).next()?;
            let value = String::from_utf8_lossy(first).into_owned();
            (!value.is_empty()).then_some(value)
        });
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let parse = |prefix: &str| {
        status
            .lines()
            .find(|line| line.starts_with(prefix))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    ProcessIdentity {
        key: ProcessKey {
            boot_id,
            pid,
            start_time_ns: 0,
        },
        tid: if tid == 0 { pid } else { tid },
        tgid: pid,
        uid: parse("Uid:"),
        gid: parse("Gid:"),
        comm,
        command_line,
        selinux_context: None,
        packages: Vec::new(),
    }
}

/// Read a bounded C string from another process address space.
pub fn read_remote_cstring(pid: u32, address: u64, max_bytes: usize) -> Option<String> {
    let buffer = read_remote_bytes(pid, address, max_bytes)?;
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let value = String::from_utf8_lossy(&buffer[..end]).into_owned();
    (!value.is_empty()).then_some(value)
}

/// Read bounded bytes from another process address space.
pub fn read_remote_bytes(pid: u32, address: u64, max_bytes: usize) -> Option<Vec<u8>> {
    if address == 0 || max_bytes == 0 || pid == 0 {
        return None;
    }
    let mut file = File::open(format!("/proc/{pid}/mem")).ok()?;
    file.seek(SeekFrom::Start(address)).ok()?;
    let mut buffer = vec![0_u8; max_bytes];
    let read = file.read(&mut buffer).ok()?;
    buffer.truncate(read);
    (!buffer.is_empty()).then_some(buffer)
}

#[cfg(test)]
mod tests {
    use ksight_model::ProcessKey;

    use super::*;

    #[test]
    fn disabled_policy_does_not_attach() {
        let plans = InspectPlan::evaluate(
            InspectPolicy::default(),
            InspectAdapterKind::LinkerSoLoad,
            PathBuf::from("/nonexistent"),
        );
        assert!(plans.iter().all(|plan| !plan.should_attach()));
        assert!(plans[0].observation.detail.contains("disabled"));
    }

    #[test]
    fn art_dex_memory_is_a_named_exported_symbol_adapter() {
        let kind = "art_dex_memory"
            .parse::<InspectAdapterKind>()
            .expect("parse");
        assert_eq!(kind.as_str(), "art_dex_memory");
        assert!(kind.symbols()[0].contains("OpenEPKhm"));
    }

    #[test]
    fn jni_adapter_refuses_without_exported_boundary() {
        let policy = InspectPolicy {
            enabled: true,
            pid: Some(1),
            ..InspectPolicy::default()
        };
        let plans = InspectPlan::evaluate(
            policy,
            InspectAdapterKind::JniRegistration,
            PathBuf::from("/nonexistent"),
        );
        assert!(plans.iter().all(|plan| !plan.should_attach()));
        assert!(plans[0].observation.detail.contains("refusing to guess"));
    }

    #[test]
    fn tls_without_app_selector_does_not_attach() {
        let policy = InspectPolicy {
            enabled: true,
            ..InspectPolicy::default()
        };
        let plans = InspectPlan::evaluate(
            policy,
            InspectAdapterKind::TlsSslWrite,
            PathBuf::from("/nonexistent"),
        );
        assert!(plans.iter().all(|plan| !plan.should_attach()));
        assert!(plans[0].observation.detail.contains("no app selector"));
    }

    #[test]
    fn tls_package_selector_is_enough_to_attach() {
        let policy = InspectPolicy {
            enabled: true,
            package: Some("com.example.app".to_owned()),
            ..InspectPolicy::default()
        };
        assert!(policy.may_attach());
        let identity = ProcessIdentity {
            key: ProcessKey {
                boot_id: Uuid::nil(),
                pid: 42,
                start_time_ns: 0,
            },
            tid: 42,
            tgid: 42,
            uid: 10_123,
            gid: 10_123,
            comm: "app".to_owned(),
            command_line: Some("com.example.app:push".to_owned()),
            selinux_context: None,
            packages: Vec::new(),
        };
        assert!(hit_matches_policy(&policy, &identity));
        let mut other = identity.clone();
        other.command_line = Some("com.other.app".to_owned());
        assert!(!hit_matches_policy(&policy, &other));
    }

    #[test]
    fn linker_session_records_audited_stubs() {
        let policy = InspectPolicy {
            enabled: true,
            pid: Some(1),
            ..InspectPolicy::default()
        };
        let runtime = InspectRuntime::prepare(
            &policy,
            InspectAdapterKind::LinkerSoLoad,
            Path::new("/nonexistent"),
        );
        let adapters = runtime
            .initial_observations()
            .into_iter()
            .map(|observation| observation.adapter)
            .collect::<BTreeSet<_>>();
        assert!(adapters.contains("linker_so_load"));
        assert!(adapters.contains("art_dex_load"));
        assert!(adapters.contains("art_dex_memory"));
        assert!(adapters.contains("jni_registration"));
        assert!(adapters.contains("binder_userspace"));
    }

    #[test]
    fn preview_prefers_utf8_for_http() {
        let (preview, encoding) = preview_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n");
        assert_eq!(encoding, "utf8_lossy");
        assert!(preview.contains("example.com"));
    }

    #[test]
    fn classifies_tls_application_data_records() {
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        record.extend_from_slice(&[0u8; 16]);
        assert_eq!(classify_buffer(&record), "tls_record");
        assert_eq!(classify_buffer(b"GET /login HTTP/1.1\r\n"), "text");
    }
}
