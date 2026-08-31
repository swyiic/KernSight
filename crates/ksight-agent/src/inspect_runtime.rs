//! Inspect adapter orchestration. Default-off, auditable, exported-symbol only.

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
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

use crate::elf::{inspect_elf, matching_symbols, symbol_match};

const LINKER_NAMES: [&str; 3] = ["__loader_dlopen", "do_dlopen", "android_dlopen_ext"];
const LINKER_PATHS: [&str; 4] = [
    "/apex/com.android.runtime/bin/linker64",
    "/system/bin/linker64",
    "/apex/com.android.runtime/bin/linker",
    "/system/bin/linker",
];
const TLS_NAMES: [&str; 2] = ["SSL_write", "SSL_write_ex"];
const TLS_READ_NAMES: [&str; 2] = ["SSL_read", "SSL_read_ex"];
const TLS_PATHS: [&str; 6] = [
    "/apex/com.android.conscrypt/lib64/libssl.so",
    "/system/lib64/libssl.so",
    "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
    "/apex/com.android.conscrypt/lib/libssl.so",
    "/system/lib/libssl.so",
    "/apex/com.android.tethering/lib/stable_cronet_libssl.so",
];
/// Exported `DexFileLoader` / `ArtDexFileLoader` Open* prefixes from on-device dynsym.
/// Prefix match is required because Itanium suffixes vary by ART build; offsets are not guessed.
const ART_DEX_NAMES: [&str; 7] = [
    "_ZNK3art16ArtDexFileLoader4OpenE",
    "_ZN3art16ArtDexFileLoader4OpenE",
    "_ZNK3art13DexFileLoader4OpenE",
    "_ZN3art13DexFileLoader4OpenE",
    "_ZN3art13DexFileLoader10OpenCommonE",
    "_ZNK3art13DexFileLoader16OpenFromZipEntryE",
    "_ZN3art13DexFileLoader7OpenOneE",
];
/// Memory DEX Open: exported `Open(uint8_t const*, size_t, ...)` / `OpenCommon(uint8_t const*, size_t, ...)`.
/// There is no `OpenMemory` symbol; only these dynsym prefixes are used.
const ART_DEX_MEMORY_NAMES: [&str; 3] = [
    "_ZNK3art16ArtDexFileLoader4OpenEPKhm",
    "_ZNK3art13DexFileLoader4OpenEPKhm",
    "_ZN3art13DexFileLoader10OpenCommonEPKhm",
];
const ART_DEX_PATHS: [&str; 2] = [
    "/apex/com.android.art/lib64/libdexfile.so",
    "/apex/com.android.art/lib/libdexfile.so",
];
const ART_OPEN_ATTACH_CAP: usize = 12;
const CODE_PATH_MARKERS: [&str; 8] = [
    ".apk", ".dex", ".jar", ".vdex", ".zip", ".oat", ".art", "memfd:",
];
const BINDER_NAMES: [&str; 1] = ["_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j"];
/// Exported `Parcel::writeInterfaceToken(char16_t const*, size_t)`.
const BINDER_TOKEN_NAMES: [&str; 1] = ["_ZN7android6Parcel19writeInterfaceTokenEPKDsm"];
/// Exported `Parcel::writeString16(char16_t const*, size_t)`. The `String16 const&` overload is not attached.
const BINDER_STRING_NAMES: [&str; 1] = ["_ZN7android6Parcel13writeString16EPKDsm"];
/// Exported `Parcel::writeString8(char const*, size_t)`.
const BINDER_STRING8_NAMES: [&str; 1] = ["_ZN7android6Parcel12writeString8EPKcm"];
const BINDER_INT32_NAMES: [&str; 1] = ["_ZN7android6Parcel10writeInt32Ei"];
const BINDER_INT64_NAMES: [&str; 1] = ["_ZN7android6Parcel10writeInt64El"];
const BINDER_UINT32_NAMES: [&str; 1] = ["_ZN7android6Parcel11writeUint32Ej"];
const BINDER_UINT64_NAMES: [&str; 1] = ["_ZN7android6Parcel11writeUint64Em"];
const BINDER_BOOL_NAMES: [&str; 1] = ["_ZN7android6Parcel9writeBoolEb"];
const BINDER_CSTRING_NAMES: [&str; 1] = ["_ZN7android6Parcel12writeCStringEPKc"];
const BINDER_BYTES_NAMES: [&str; 1] = ["_ZN7android6Parcel14writeByteArrayEmPKh"];
const BINDER_FD_NAMES: [&str; 1] = ["_ZN7android6Parcel19writeFileDescriptorEib"];
const BINDER_DUP_FD_NAMES: [&str; 1] = ["_ZN7android6Parcel22writeDupFileDescriptorEi"];
const BINDER_STRONG_NAMES: [&str; 1] =
    ["_ZN7android6Parcel17writeStrongBinderERKNS_2spINS_7IBinderEEE"];
const BINDER_BYTE_NAMES: [&str; 1] = ["_ZN7android6Parcel9writeByteEa"];
const BINDER_CHAR_NAMES: [&str; 1] = ["_ZN7android6Parcel9writeCharEDs"];
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_BINDERS_PER_TID: usize = 4;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_INTS_PER_TID: usize = 8;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_INT64S_PER_TID: usize = 8;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_BOOLS_PER_TID: usize = 8;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_FDS_PER_TID: usize = 4;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_BLOBS_PER_TID: usize = 4;
const BINDER_PATHS: [&str; 2] = ["/system/lib64/libbinder.so", "/system/lib/libbinder.so"];
const BINDER_INTERFACE_UNITS_CAP: usize = 192;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_STRINGS_PER_TID: usize = 8;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_PENDING_TIDS: usize = 4096;
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
    /// ART DEX load via exported `DexFileLoader`/`ArtDexFileLoader` Open*.
    ArtDexLoad,
    /// ART in-memory DEX via exported `Open`/`OpenCommon(uint8_t const*, size_t, ...)`.
    ArtDexMemory,
    /// JNI native registration. No exported JNI table boundary on this build.
    JniRegistration,
    /// Userspace Binder `IPCThreadState::transact`.
    BinderUserspace,
    /// Userspace Binder `Parcel::writeInterfaceToken` (UTF-16 descriptor).
    BinderInterfaceToken,
    /// Userspace Binder `Parcel::writeString16(char16_t const*, size_t)` (UTF-16 arguments).
    BinderParcelString,
    /// Userspace Binder `Parcel::writeString8(char const*, size_t)` (UTF-8 arguments).
    BinderParcelUtf8,
    /// Userspace Binder `Parcel::writeInt32(int)`.
    BinderParcelInt32,
    /// Userspace Binder `Parcel::writeInt64(long)`.
    BinderParcelInt64,
    /// Userspace Binder `Parcel::writeUint32(unsigned)`.
    BinderParcelUint32,
    /// Userspace Binder `Parcel::writeUint64(unsigned long)`.
    BinderParcelUint64,
    /// Userspace Binder `Parcel::writeBool(bool)`.
    BinderParcelBool,
    /// Userspace Binder `Parcel::writeCString(char const*)`.
    BinderParcelCString,
    /// Userspace Binder `Parcel::writeByteArray(size_t, uint8_t const*)`.
    BinderParcelBytes,
    /// Userspace Binder `Parcel::writeFileDescriptor(int, bool)`.
    BinderParcelFd,
    /// Userspace Binder `Parcel::writeDupFileDescriptor(int)`.
    BinderParcelDupFd,
    /// Userspace Binder `Parcel::writeStrongBinder(sp<IBinder> const&)`. Reads the 8-byte `sp` at x1.
    BinderParcelBinder,
    /// Userspace Binder `Parcel::writeByte(signed char)`.
    BinderParcelByte,
    /// Userspace Binder `Parcel::writeChar(char16_t)`.
    BinderParcelChar,
    /// BoringSSL/Conscrypt `SSL_write` plaintext (outbound).
    TlsSslWrite,
    /// BoringSSL/Conscrypt `SSL_read` plaintext (inbound; entry+return pairing).
    TlsSslRead,
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
            Self::BinderInterfaceToken => "binder_interface_token",
            Self::BinderParcelString => "binder_parcel_string",
            Self::BinderParcelUtf8 => "binder_parcel_utf8",
            Self::BinderParcelInt32 => "binder_parcel_int32",
            Self::BinderParcelInt64 => "binder_parcel_int64",
            Self::BinderParcelUint32 => "binder_parcel_uint32",
            Self::BinderParcelUint64 => "binder_parcel_uint64",
            Self::BinderParcelBool => "binder_parcel_bool",
            Self::BinderParcelCString => "binder_parcel_cstring",
            Self::BinderParcelBytes => "binder_parcel_bytes",
            Self::BinderParcelFd => "binder_parcel_fd",
            Self::BinderParcelDupFd => "binder_parcel_dup_fd",
            Self::BinderParcelBinder => "binder_parcel_binder",
            Self::BinderParcelByte => "binder_parcel_byte",
            Self::BinderParcelChar => "binder_parcel_char",
            Self::TlsSslWrite => "tls_ssl_write",
            Self::TlsSslRead => "tls_ssl_read",
        }
    }

    fn libraries(self) -> &'static [&'static str] {
        if self.is_binder() {
            return &BINDER_PATHS;
        }
        match self {
            Self::LinkerSoLoad => &LINKER_PATHS,
            Self::ArtDexLoad | Self::ArtDexMemory => &ART_DEX_PATHS,
            Self::TlsSslWrite | Self::TlsSslRead => &TLS_PATHS,
            _ => &[],
        }
    }

    fn symbols(self) -> &'static [&'static str] {
        match self {
            Self::LinkerSoLoad => &LINKER_NAMES,
            Self::ArtDexLoad => &ART_DEX_NAMES,
            Self::ArtDexMemory => &ART_DEX_MEMORY_NAMES,
            Self::JniRegistration => &[],
            Self::BinderUserspace => &BINDER_NAMES,
            Self::BinderInterfaceToken => &BINDER_TOKEN_NAMES,
            Self::BinderParcelString => &BINDER_STRING_NAMES,
            Self::BinderParcelUtf8 => &BINDER_STRING8_NAMES,
            Self::BinderParcelInt32 => &BINDER_INT32_NAMES,
            Self::BinderParcelInt64 => &BINDER_INT64_NAMES,
            Self::BinderParcelUint32 => &BINDER_UINT32_NAMES,
            Self::BinderParcelUint64 => &BINDER_UINT64_NAMES,
            Self::BinderParcelBool => &BINDER_BOOL_NAMES,
            Self::BinderParcelCString => &BINDER_CSTRING_NAMES,
            Self::BinderParcelBytes => &BINDER_BYTES_NAMES,
            Self::BinderParcelFd => &BINDER_FD_NAMES,
            Self::BinderParcelDupFd => &BINDER_DUP_FD_NAMES,
            Self::BinderParcelBinder => &BINDER_STRONG_NAMES,
            Self::BinderParcelByte => &BINDER_BYTE_NAMES,
            Self::BinderParcelChar => &BINDER_CHAR_NAMES,
            Self::TlsSslWrite => &TLS_NAMES,
            Self::TlsSslRead => &TLS_READ_NAMES,
        }
    }

    fn map_needles(self) -> &'static [&'static str] {
        if self.is_binder() {
            return &["libbinder.so"];
        }
        match self {
            Self::TlsSslWrite | Self::TlsSslRead => &["libssl.so", "libcronet.so"],
            Self::ArtDexLoad | Self::ArtDexMemory => &["libdexfile.so"],
            Self::LinkerSoLoad => &["linker64", "linker"],
            _ => &[],
        }
    }

    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    const fn is_tls(self) -> bool {
        matches!(self, Self::TlsSslWrite | Self::TlsSslRead)
    }

    const fn is_binder(self) -> bool {
        matches!(
            self,
            Self::BinderUserspace
                | Self::BinderInterfaceToken
                | Self::BinderParcelString
                | Self::BinderParcelUtf8
                | Self::BinderParcelInt32
                | Self::BinderParcelInt64
                | Self::BinderParcelUint32
                | Self::BinderParcelUint64
                | Self::BinderParcelBool
                | Self::BinderParcelCString
                | Self::BinderParcelBytes
                | Self::BinderParcelFd
                | Self::BinderParcelDupFd
                | Self::BinderParcelBinder
                | Self::BinderParcelByte
                | Self::BinderParcelChar
        )
    }

    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    fn hit_once(self) -> bool {
        matches!(self, Self::LinkerSoLoad)
    }

    fn default_max_hits(self) -> u32 {
        match self {
            Self::ArtDexLoad | Self::ArtDexMemory => 64,
            Self::LinkerSoLoad | Self::JniRegistration => 1,
            _ => 1024,
        }
    }

    /// Adapters recorded as audited stubs when another adapter is selected.
    pub const fn audited_stubs(self) -> &'static [Self] {
        match self {
            Self::TlsSslWrite | Self::TlsSslRead | Self::LinkerSoLoad => &[
                Self::ArtDexLoad,
                Self::ArtDexMemory,
                Self::JniRegistration,
                Self::BinderUserspace,
            ],
            _ => &[],
        }
    }

    /// Extra exported-symbol adapters attached with this selection.
    fn companions(self) -> &'static [Self] {
        match self {
            Self::TlsSslWrite => &[Self::TlsSslRead],
            Self::BinderUserspace => &[
                Self::BinderInterfaceToken,
                Self::BinderParcelString,
                Self::BinderParcelUtf8,
                Self::BinderParcelCString,
                Self::BinderParcelInt32,
                Self::BinderParcelInt64,
                Self::BinderParcelUint32,
                Self::BinderParcelUint64,
                Self::BinderParcelBool,
                Self::BinderParcelBytes,
                Self::BinderParcelFd,
                Self::BinderParcelDupFd,
                Self::BinderParcelBinder,
                Self::BinderParcelByte,
                Self::BinderParcelChar,
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
            "binder_interface_token" => Ok(Self::BinderInterfaceToken),
            "binder_parcel_string" => Ok(Self::BinderParcelString),
            "binder_parcel_utf8" => Ok(Self::BinderParcelUtf8),
            "binder_parcel_int32" => Ok(Self::BinderParcelInt32),
            "binder_parcel_int64" => Ok(Self::BinderParcelInt64),
            "binder_parcel_uint32" => Ok(Self::BinderParcelUint32),
            "binder_parcel_uint64" => Ok(Self::BinderParcelUint64),
            "binder_parcel_bool" => Ok(Self::BinderParcelBool),
            "binder_parcel_cstring" => Ok(Self::BinderParcelCString),
            "binder_parcel_bytes" => Ok(Self::BinderParcelBytes),
            "binder_parcel_fd" => Ok(Self::BinderParcelFd),
            "binder_parcel_dup_fd" => Ok(Self::BinderParcelDupFd),
            "binder_parcel_binder" => Ok(Self::BinderParcelBinder),
            "binder_parcel_byte" => Ok(Self::BinderParcelByte),
            "binder_parcel_char" => Ok(Self::BinderParcelChar),
            "tls_ssl_write" => Ok(Self::TlsSslWrite),
            "tls_ssl_read" => Ok(Self::TlsSslRead),
            other => Err(format!(
                "unknown inspect adapter {other}; expected linker_so_load, art_dex_load, art_dex_memory, jni_registration, binder_userspace, binder_interface_token, binder_parcel_string, binder_parcel_utf8, binder_parcel_int32, binder_parcel_int64, binder_parcel_uint32, binder_parcel_uint64, binder_parcel_bool, binder_parcel_cstring, binder_parcel_bytes, binder_parcel_fd, binder_parcel_dup_fd, binder_parcel_binder, binder_parcel_byte, binder_parcel_char, tls_ssl_write, or tls_ssl_read"
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
    /// Matched exported symbol, when resolved from dynsym.
    pub symbol: Option<String>,
    /// Pointer width of the target ELF: 4 for ELF32, 8 for ELF64.
    pub pointer_width: u8,
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

    /// Attach every exported Open* that matches this ART adapter's prefixes.
    fn evaluate_art_exports(
        policy: InspectPolicy,
        adapter: InspectAdapterKind,
        uprobe_object: PathBuf,
    ) -> Vec<Self> {
        let libraries = resolve_libraries(&policy, adapter);
        if libraries.is_empty() {
            return Self::evaluate(policy, adapter, uprobe_object);
        }
        let mut plans = Vec::new();
        for library in libraries {
            match evaluate_art_open_exports(&policy, adapter, &uprobe_object, &library) {
                Some(mut found) => plans.append(&mut found),
                None => plans.push(evaluate_one(
                    policy.clone(),
                    adapter,
                    uprobe_object.clone(),
                    Some(library),
                )),
            }
        }
        if plans.is_empty() {
            Self::evaluate(policy, adapter, uprobe_object)
        } else {
            plans
        }
    }
}

/// A live Inspect decision or a plaintext fragment.
pub enum InspectOutput {
    /// Adapter attach/refuse/hit audit, attributed to the hitting thread.
    Observation {
        /// Process that executed the probe.
        pid: u32,
        /// Thread that executed the probe.
        tid: u32,
        /// Adapter attach/refuse/hit audit.
        observation: InspectObservation,
    },
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
    selected_adapters: Vec<InspectAdapterKind>,
    started: Instant,
    max_duration: Duration,
    max_hits: u32,
    hits: u32,
    expired: bool,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    sessions: Vec<LiveProbe>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    ssl_read_pending: HashMap<u32, PendingSslRead>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    binder_pending: BinderPending,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    binder_dex_cache: crate::binder_dex::ProcessDexAidlCache,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    scoped_tgids: Vec<u32>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct BinderPending {
    tokens: HashMap<u32, String>,
    strings: HashMap<u32, Vec<String>>,
    ints: HashMap<u32, Vec<i32>>,
    int64s: HashMap<u32, Vec<i64>>,
    bools: HashMap<u32, Vec<bool>>,
    fds: HashMap<u32, Vec<i32>>,
    blobs: HashMap<u32, Vec<String>>,
    binders: HashMap<u32, Vec<String>>,
}

struct PendingSslRead {
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    pid: u32,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    buf: u64,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    requested: i32,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
struct LiveProbe {
    plan: InspectPlan,
    session: ksight_hwbp::UprobeSession,
    retprobe: bool,
}

impl InspectRuntime {
    /// Evaluate one selected adapter and any registered audited stubs.
    pub fn prepare(
        policy: &InspectPolicy,
        adapter: InspectAdapterKind,
        uprobe_object: &Path,
    ) -> Self {
        Self::prepare_all(policy, &[adapter], uprobe_object)
    }

    /// Evaluate every selected adapter (for example TLS plus Binder) in one session.
    pub fn prepare_all(
        policy: &InspectPolicy,
        adapters: &[InspectAdapterKind],
        uprobe_object: &Path,
    ) -> Self {
        let selected_adapters: Vec<InspectAdapterKind> = if adapters.is_empty() {
            vec![InspectAdapterKind::LinkerSoLoad]
        } else {
            adapters.to_vec()
        };
        let mut policy = policy.clone();
        if policy.max_hits == 0 {
            policy.max_hits = selected_adapters
                .iter()
                .map(|adapter| adapter.default_max_hits())
                .max()
                .unwrap_or(1024);
        }
        if policy.whole_device {
            let names = selected_adapters
                .iter()
                .map(|adapter| adapter.as_str())
                .collect::<Vec<_>>()
                .join("+");
            policy.detectability_notice = format!(
                "{}; whole-device {names} inspect is detectable by every process mapping the target ELF",
                policy.detectability_notice
            );
        }
        let max_duration = if policy.max_duration_secs == 0 {
            Duration::from_secs(u64::MAX / 4)
        } else {
            Duration::from_secs(u64::from(policy.max_duration_secs))
        };
        let max_hits = policy.max_hits.max(1);
        let uprobe_object = uprobe_object.to_path_buf();
        let mut plans = Vec::new();
        for adapter in &selected_adapters {
            if matches!(
                adapter,
                InspectAdapterKind::ArtDexLoad | InspectAdapterKind::ArtDexMemory
            ) {
                plans.extend(InspectPlan::evaluate_art_exports(
                    policy.clone(),
                    *adapter,
                    uprobe_object.clone(),
                ));
            } else {
                plans.extend(InspectPlan::evaluate(
                    policy.clone(),
                    *adapter,
                    uprobe_object.clone(),
                ));
            }
            for companion in adapter.companions() {
                plans.extend(InspectPlan::evaluate(
                    policy.clone(),
                    *companion,
                    uprobe_object.clone(),
                ));
            }
            for stub in adapter.audited_stubs() {
                if selected_adapters.contains(stub) {
                    continue;
                }
                plans.extend(InspectPlan::evaluate(
                    policy.clone(),
                    *stub,
                    uprobe_object.clone(),
                ));
            }
        }
        prune_redundant_elf32_tls(&mut plans);
        Self {
            plans,
            selected_adapters,
            started: Instant::now(),
            max_duration,
            max_hits,
            hits: 0,
            expired: false,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            sessions: Vec::new(),
            ssl_read_pending: HashMap::new(),
            binder_pending: BinderPending::default(),
            binder_dex_cache: crate::binder_dex::ProcessDexAidlCache::default(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            scoped_tgids: Vec::new(),
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
        library: elf_path.clone().unwrap_or_default(),
        build_id: policy.build_id.clone(),
        offset: policy.offset,
        detectability_notice: policy.detectability_notice.clone(),
        ..InspectObservation::default()
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
            let symbol = matched
                .as_ref()
                .map(|(name, _)| name.clone())
                .filter(|name| !name.is_empty());
            if matched.is_none() {
                observation.detail = format!(
                    "{} symbol/offset not found in {}; adapter not attached",
                    adapter.as_str(),
                    elf_path
                );
                if ksight_core::classify_tls_library_path(&elf_path)
                    == Some(ksight_core::TlsLibraryKind::Cronet)
                {
                    observation.detail.push_str(
                        "; Cronet/QUIC plaintext is not captured without exported SSL_write (no invented offsets)",
                    );
                }
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
            let mut built = plan(
                policy,
                adapter,
                uprobe_object,
                Some(elf_path),
                observation.offset,
                elf.build_id,
                observation,
            );
            built.symbol = symbol;
            built.pointer_width = (elf.bits / 8).max(4);
            if matched.is_some() {
                let _ = write!(built.observation.detail, " elf{}", elf.bits);
            }
            built
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

fn evaluate_art_open_exports(
    policy: &InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: &Path,
    elf_path: &str,
) -> Option<Vec<InspectPlan>> {
    let elf = inspect_elf(elf_path).ok()?;
    if let Some(required) = policy.build_id.as_deref() {
        match elf.build_id.as_deref() {
            Some(actual) if actual == required => {}
            _ => return None,
        }
    }
    let matched = matching_symbols(&elf, adapter.symbols());
    if matched.is_empty() {
        return None;
    }
    Some(
        matched
            .into_iter()
            .take(ART_OPEN_ATTACH_CAP)
            .map(|(name, offset)| {
                let mut observation = InspectObservation {
                    adapter: adapter.as_str().to_owned(),
                    library: elf_path.to_owned(),
                    build_id: elf.build_id.clone(),
                    offset: Some(offset),
                    detectability_notice: policy.detectability_notice.clone(),
                    ..InspectObservation::default()
                };
                if Path::new(uprobe_object).is_file() {
                    observation.detail = format!(
                        "ready to attach {} uprobe symbol={name} offset={offset:#x}",
                        adapter.as_str()
                    );
                } else {
                    observation.detail =
                        format!("uprobe object missing: {}", uprobe_object.display());
                }
                InspectPlan {
                    policy: policy.clone(),
                    adapter,
                    uprobe_object: uprobe_object.to_path_buf(),
                    elf_path: Some(elf_path.to_owned()),
                    offset: Some(offset),
                    build_id: elf.build_id.clone(),
                    symbol: Some(name.to_owned()),
                    pointer_width: (elf.bits / 8).max(4),
                    observation,
                }
            })
            .collect(),
    )
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
        symbol: None,
        pointer_width: 8,
        observation,
    }
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn adapter_is_live(selected: &[InspectAdapterKind], adapter: InspectAdapterKind) -> bool {
    selected
        .iter()
        .any(|item| *item == adapter || item.companions().contains(&adapter))
}

fn prune_redundant_elf32_tls(plans: &mut [InspectPlan]) {
    let has_elf64 = plans
        .iter()
        .any(|plan| plan.adapter.is_tls() && plan.pointer_width >= 8 && plan.offset.is_some());
    if !has_elf64 {
        return;
    }
    for plan in plans {
        if plan.adapter.is_tls() && plan.pointer_width == 4 {
            plan.offset = None;
            if !plan.observation.detail.contains("skipped ELF32 TLS") {
                plan.observation.detail.push_str(
                    "; skipped ELF32 TLS on this arm64 GKI because an ELF64 libssl/Cronet with SSL_write is available",
                );
            }
        }
    }
}

fn resolve_libraries(policy: &InspectPolicy, adapter: InspectAdapterKind) -> Vec<String> {
    if let Some(path) = policy.elf_path.clone() {
        return vec![path];
    }
    let needles = adapter.map_needles();
    let mut found = BTreeSet::new();
    for path in adapter.libraries() {
        if Path::new(path).is_file() {
            found.insert((*path).to_owned());
        }
    }
    let mapped = if let Some(pids) = active_tgid_filter(policy) {
        discover_mapped_libraries_in(&pids, needles)
    } else {
        discover_mapped_libraries(needles)
    };
    found.extend(mapped);
    found.into_iter().take(8).collect()
}

fn mapping_path_matches(path: &str, needle: &str) -> bool {
    if needle.contains('/') {
        return path.contains(needle);
    }
    let file = path.rsplit('/').next().unwrap_or(path);
    if needle == "libcronet.so" {
        return file.contains("cronet");
    }
    if needle == "libssl.so" {
        return file == "libssl.so" || file.ends_with("_libssl.so");
    }
    file == needle
}

fn discover_mapped_libraries(needles: &[&str]) -> Vec<String> {
    if needles.is_empty() {
        return Vec::new();
    }
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let pids: Vec<u32> = proc
        .flatten()
        .take(2048)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
        .collect();
    discover_mapped_libraries_in(&pids, needles)
}

fn discover_mapped_libraries_in(pids: &[u32], needles: &[&str]) -> Vec<String> {
    if needles.is_empty() {
        return Vec::new();
    }
    let mut found = BTreeSet::new();
    for pid in pids.iter().copied().take(128) {
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
            if needles
                .iter()
                .any(|needle| mapping_path_matches(path, needle))
            {
                found.insert(path.to_owned());
            }
            if found.len() >= 8 {
                return found.into_iter().collect();
            }
        }
    }
    found.into_iter().collect()
}

/// TGIDs that should reach the uprobe ring. `None` means no kernel filter.
fn active_tgid_filter(policy: &InspectPolicy) -> Option<Vec<u32>> {
    if policy.whole_device {
        return None;
    }
    let mut pids = Vec::new();
    if let Some(pid) = policy.pid.filter(|pid| *pid > 0) {
        pids.push(pid);
    }
    if let Some(package) = policy.package.as_deref().filter(|name| !name.is_empty()) {
        for pid in crate::dexdump::pids_for_package(package) {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    } else if pids.is_empty() {
        if let Some(uid) = policy.uid.filter(|uid| *uid > 0) {
            pids = pids_for_uid(uid);
        }
    }
    (!pids.is_empty()).then_some(pids)
}

fn pids_for_uid(uid: u32) -> Vec<u32> {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in proc.flatten().take(2048) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let Some(line) = status.lines().find(|line| line.starts_with("Uid:")) else {
            continue;
        };
        let Some(value) = line.split_whitespace().nth(1) else {
            continue;
        };
        if value.parse::<u32>().ok() == Some(uid) {
            pids.push(pid);
        }
    }
    pids
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn join_tgids(tgids: &[u32]) -> String {
    tgids
        .iter()
        .take(8)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn refresh_tgid_filter(runtime: &mut InspectRuntime) {
    let Some(policy) = runtime.plans.first().map(|plan| &plan.policy) else {
        return;
    };
    let Some(next) = active_tgid_filter(policy) else {
        return;
    };
    if next == runtime.scoped_tgids {
        return;
    }
    runtime.scoped_tgids.clone_from(&next);
    for probe in &mut runtime.sessions {
        if let Err(error) = probe.session.apply_tgid_filter(Some(&next)) {
            eprintln!(
                "inspect tgid filter update failed adapter={}: {error:#}",
                probe.plan.adapter.as_str()
            );
        }
    }
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
fn start_uprobe_session(
    object: &Path,
    program: &str,
    elf: &Path,
    offset: u64,
    hit_once: bool,
    pointer_width: u8,
    tgids: Option<&[u32]>,
) -> anyhow::Result<ksight_hwbp::UprobeSession> {
    match ksight_hwbp::UprobeSession::start_program(object, program, elf, offset, None, hit_once) {
        Ok(session) => Ok(session),
        Err(error) if pointer_width == 4 && uprobe_attach_unsupported(&error) => {
            let mut last = error;
            for tgid in tgids.unwrap_or(&[]) {
                let pid = i32::try_from(*tgid).unwrap_or(0);
                if pid <= 0 {
                    continue;
                }
                match ksight_hwbp::UprobeSession::start_program(
                    object,
                    program,
                    elf,
                    offset,
                    Some(pid),
                    hit_once,
                ) {
                    Ok(session) => return Ok(session),
                    Err(retry) => last = retry,
                }
            }
            Err(last)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn uprobe_attach_unsupported(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("Not supported") || text.contains("os error 95") || text.contains("os error 22")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn attach_all(runtime: &mut InspectRuntime) -> Vec<InspectObservation> {
    let mut out = Vec::new();
    let selected = runtime.selected_adapters.clone();
    let plans = runtime
        .plans
        .iter()
        .filter(|plan| plan.should_attach() && adapter_is_live(&selected, plan.adapter))
        .cloned()
        .collect::<Vec<_>>();
    let tgids = runtime
        .plans
        .first()
        .and_then(|plan| active_tgid_filter(&plan.policy));
    if let Some(tgids) = tgids.as_ref() {
        runtime.scoped_tgids.clone_from(tgids);
    }
    for plan in plans {
        // Kernel uprobe `pid` is a thread id. Attach globally and drop other TGIDs
        // in BPF before perf_output so busy Binder apps are not drowned.
        let Some(elf) = plan.elf_path.as_ref().map(PathBuf::from) else {
            continue;
        };
        let Some(offset) = plan.offset else {
            continue;
        };
        let hit_once = plan.adapter.hit_once() && !plan.policy.whole_device;
        let programs: &[&str] = if plan.adapter == InspectAdapterKind::TlsSslRead {
            &["ksight_uprobe_regs", "ksight_uretprobe_regs"]
        } else {
            &["ksight_uprobe_regs"]
        };
        for program in programs {
            let retprobe = *program == "ksight_uretprobe_regs";
            match start_uprobe_session(
                &plan.uprobe_object,
                program,
                &elf,
                offset,
                hit_once,
                plan.pointer_width,
                tgids.as_deref(),
            ) {
                Ok(mut session) => {
                    let filter_status = if let Some(tgids) = tgids.as_deref() {
                        match session.apply_tgid_filter(Some(tgids)) {
                            Ok(()) => String::new(),
                            Err(error) => format!(" tgid_filter_error={error:#}"),
                        }
                    } else {
                        String::new()
                    };
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
                    let tgid_note = if runtime.scoped_tgids.is_empty() {
                        " tgid_filter=pending".to_owned()
                    } else {
                        format!(" tgid_filter={}", join_tgids(&runtime.scoped_tgids))
                    };
                    let kind = if retprobe { "uretprobe" } else { "uprobe" };
                    let symbol = plan.symbol.as_deref().unwrap_or("-");
                    observation.detail = format!(
                        "attached {} {kind} filter={scope}{tgid_note}{filter_status} offset={offset:#x} symbol={symbol} hit_once={hit_once} max_hits={}",
                        plan.adapter.as_str(),
                        runtime.max_hits
                    );
                    runtime.sessions.push(LiveProbe {
                        plan: plan.clone(),
                        session,
                        retprobe,
                    });
                    out.push(observation);
                }
                Err(error) => {
                    let mut observation = plan.observation.clone();
                    observation.attached = false;
                    observation.detail = format!("attach failed ({program}): {error:#}");
                    if plan.pointer_width == 4 {
                        observation.detail.push_str(if plan.adapter.is_tls() {
                            "; ELF32 uprobe was tried globally and per-TGID. This arm64 GKI cannot decode AArch32/Thumb instructions (ENOTSUP), so 32-bit Conscrypt/Cronet SSL_write cannot be probed. TLS plaintext is userspace crypto: there is no kernel SSL_write equivalent to binder_transaction"
                        } else {
                            "; ELF32 uprobe was tried globally and per-TGID (this kernel rejects AArch32 uprobes). Kernel binder_transaction parcel prefix covers 32-bit and 64-bit clients"
                        });
                    }
                    out.push(observation);
                }
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
    refresh_tgid_filter(runtime);
    let mut out = Vec::new();
    let max_payload = usize::try_from(
        runtime
            .plans
            .first()
            .map_or(256, |plan| plan.policy.max_payload_bytes.max(1)),
    )
    .unwrap_or(256)
    .min(MAX_PAYLOAD_BYTES);
    let mut batch = Vec::new();
    for probe in &mut runtime.sessions {
        let Ok(hits) = probe.session.poll_hits() else {
            continue;
        };
        for hit in hits {
            batch.push((probe.plan.clone(), probe.retprobe, hit));
        }
    }
    batch.sort_by_key(|(_, _, hit)| hit.time_ns);
    for (plan, retprobe, hit) in batch {
        if runtime.hits >= runtime.max_hits {
            break;
        }
        if let Some(output) = decode_hit(
            &plan,
            &hit,
            max_payload,
            retprobe,
            &mut runtime.ssl_read_pending,
            &mut runtime.binder_pending,
            &mut runtime.binder_dex_cache,
        ) {
            runtime.hits = runtime.hits.saturating_add(1);
            out.push(output);
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
    retprobe: bool,
    ssl_read_pending: &mut HashMap<u32, PendingSslRead>,
    binder: &mut BinderPending,
    binder_dex_cache: &mut crate::binder_dex::ProcessDexAidlCache,
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
        InspectAdapterKind::TlsSslWrite => decode_tls_plaintext(
            plan,
            pid,
            hit.tid,
            hit.regs[1],
            i32::try_from(hit.regs[2] as i64).unwrap_or(0),
            max_payload,
            "send",
        ),
        InspectAdapterKind::TlsSslRead => {
            if retprobe {
                let pending = ssl_read_pending.remove(&hit.tid)?;
                let retval = i64::from(hit.regs[0] as i32);
                if retval <= 0 {
                    return None;
                }
                let captured = i32::try_from(retval).unwrap_or(0).min(pending.requested);
                decode_tls_plaintext(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    captured,
                    max_payload,
                    "recv",
                )
            } else {
                let requested = i32::try_from(hit.regs[2] as i64).unwrap_or(0);
                if requested > 0 && ssl_read_pending.len() < 4096 {
                    ssl_read_pending.insert(
                        hit.tid,
                        PendingSslRead {
                            pid,
                            buf: hit.regs[1],
                            requested,
                        },
                    );
                }
                None
            }
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
            Some(inspect_observation(pid, hit.tid, observation))
        }
        InspectAdapterKind::ArtDexLoad | InspectAdapterKind::ArtDexMemory => {
            decode_art_open(plan, pid, hit)
        }
        InspectAdapterKind::BinderUserspace => {
            let handle = hit.regs[1] as u32;
            let code = hit.regs[2] as u32;
            let (interface, strings) =
                pair_binder_transact(hit.tid, &mut binder.tokens, &mut binder.strings);
            let ints = binder.ints.remove(&hit.tid).unwrap_or_default();
            let int64s = binder.int64s.remove(&hit.tid).unwrap_or_default();
            let bools = binder.bools.remove(&hit.tid).unwrap_or_default();
            let fds = binder.fds.remove(&hit.tid).unwrap_or_default();
            let blobs = binder.blobs.remove(&hit.tid).unwrap_or_default();
            let binders = binder.binders.remove(&hit.tid).unwrap_or_default();
            let (method, method_source) =
                resolve_binder_method(binder_dex_cache, pid, interface.as_deref(), code);
            let mut observation = plan.observation.clone();
            observation.attached = true;
            observation.hit = true;
            observation.binder_handle = Some(handle);
            observation.binder_code = Some(code);
            observation.binder_interface.clone_from(&interface);
            observation.binder_method.clone_from(&method);
            observation.binder_method_source = method_source;
            observation.path_hint = interface.clone().or_else(|| strings.first().cloned());
            let token = interface.as_deref().unwrap_or("-");
            let method_label = method.as_deref().unwrap_or("-");
            observation.detail = format!(
                "binder transact hit pid={pid} handle={handle} code={code:#x} interface={token} method={method_label} strings={} ints={} int64s={} bools={} fds={} blobs={} binders={} (exported Parcel writers on the same TID; object fields not read)",
                strings.len(),
                ints.len(),
                int64s.len(),
                bools.len(),
                fds.len(),
                blobs.len(),
                binders.len()
            );
            observation.binder_strings = (!strings.is_empty()).then_some(strings);
            observation.binder_ints = (!ints.is_empty()).then_some(ints);
            observation.binder_int64s = (!int64s.is_empty()).then_some(int64s);
            observation.binder_bools = (!bools.is_empty()).then_some(bools);
            observation.binder_fds = (!fds.is_empty()).then_some(fds);
            observation.binder_blobs = (!blobs.is_empty()).then_some(blobs);
            observation.binder_binders = (!binders.is_empty()).then_some(binders);
            Some(inspect_observation(pid, hit.tid, observation))
        }
        InspectAdapterKind::BinderInterfaceToken => {
            let token = utf16_from_hit(pid, hit)?;
            if !looks_like_binder_interface(&token) {
                return None;
            }
            if binder.tokens.len() < BINDER_PENDING_TIDS {
                binder.tokens.insert(hit.tid, token);
            }
            None
        }
        InspectAdapterKind::BinderParcelString => {
            let value = utf16_from_hit(pid, hit)?;
            if !looks_like_binder_string(&value) {
                return None;
            }
            push_binder_string(&mut binder.strings, hit.tid, value);
            None
        }
        InspectAdapterKind::BinderParcelUtf8 | InspectAdapterKind::BinderParcelCString => {
            let value = if plan.adapter == InspectAdapterKind::BinderParcelCString {
                cstring_from_hit(pid, hit)?
            } else {
                utf8_from_hit(pid, hit)?
            };
            if !looks_like_binder_string(&value) {
                return None;
            }
            push_binder_string(&mut binder.strings, hit.tid, value);
            None
        }
        InspectAdapterKind::BinderParcelInt32 => {
            let value = hit.regs[1] as i32;
            push_bounded(&mut binder.ints, hit.tid, value, BINDER_INTS_PER_TID);
            None
        }
        InspectAdapterKind::BinderParcelInt64 => {
            push_bounded(
                &mut binder.int64s,
                hit.tid,
                hit.regs[1] as i64,
                BINDER_INT64S_PER_TID,
            );
            None
        }
        InspectAdapterKind::BinderParcelUint32 => {
            push_bounded(
                &mut binder.int64s,
                hit.tid,
                i64::from(hit.regs[1] as u32),
                BINDER_INT64S_PER_TID,
            );
            None
        }
        InspectAdapterKind::BinderParcelUint64 => {
            push_bounded(
                &mut binder.int64s,
                hit.tid,
                hit.regs[1] as i64,
                BINDER_INT64S_PER_TID,
            );
            None
        }
        InspectAdapterKind::BinderParcelBool => {
            push_bounded(
                &mut binder.bools,
                hit.tid,
                hit.regs[1] & 1 != 0,
                BINDER_BOOLS_PER_TID,
            );
            None
        }
        InspectAdapterKind::BinderParcelBytes => {
            if let Some(preview) = byte_array_from_hit(hit) {
                push_bounded(&mut binder.blobs, hit.tid, preview, BINDER_BLOBS_PER_TID);
            }
            None
        }
        InspectAdapterKind::BinderParcelFd | InspectAdapterKind::BinderParcelDupFd => {
            let fd = hit.regs[1] as i32;
            if fd >= 0 {
                push_bounded(&mut binder.fds, hit.tid, fd, BINDER_FDS_PER_TID);
            }
            None
        }
        InspectAdapterKind::BinderParcelBinder => {
            if let Some(preview) = strong_binder_from_hit(pid, hit, plan.pointer_width) {
                push_bounded(
                    &mut binder.binders,
                    hit.tid,
                    preview,
                    BINDER_BINDERS_PER_TID,
                );
            }
            None
        }
        InspectAdapterKind::BinderParcelByte => {
            push_bounded(
                &mut binder.ints,
                hit.tid,
                i32::from(hit.regs[1] as i8),
                BINDER_INTS_PER_TID,
            );
            None
        }
        InspectAdapterKind::BinderParcelChar => {
            push_bounded(
                &mut binder.ints,
                hit.tid,
                i32::from(hit.regs[1] as u16),
                BINDER_INTS_PER_TID,
            );
            None
        }
        InspectAdapterKind::JniRegistration => None,
    }
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn inspect_observation(pid: u32, tid: u32, observation: InspectObservation) -> InspectOutput {
    InspectOutput::Observation {
        pid,
        tid,
        observation,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_art_open(
    plan: &InspectPlan,
    pid: u32,
    hit: &ksight_hwbp::RegisterContext,
) -> Option<InspectOutput> {
    let symbol = plan.symbol.as_deref().unwrap_or("");
    let hint = art_open_path_hint(pid, &hit.regs, symbol);
    let mut observation = plan.observation.clone();
    observation.attached = true;
    observation.hit = true;
    observation.path_hint = hint.path.clone();
    let path = hint.path.as_deref().unwrap_or("unreadable");
    observation.detail = format!(
        "ART DEX Open hit pid={pid} symbol={symbol} layout={} path={path} x1={:#x} x2={:#x} x3={:#x}",
        hint.layout,
        hit.regs[1],
        hit.regs[2],
        hit.regs[3]
    );
    Some(inspect_observation(pid, hit.tid, observation))
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtOpenHint {
    layout: &'static str,
    path: Option<String>,
}

/// Argument layout taken from the Itanium encoding in the exported name.
/// No `ClassLoader` / `std::string` / `MemMap` field offsets are used.
#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtOpenLayout {
    Filename { reg: usize },
    Memory { base: usize, size: usize },
    Probe,
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn art_open_layout(symbol: &str) -> ArtOpenLayout {
    if symbol.contains("16OpenFromZipEntryE") {
        ArtOpenLayout::Filename { reg: 2 }
    } else if symbol.contains("10OpenCommonEPKhm") {
        ArtOpenLayout::Memory { base: 0, size: 1 }
    } else if symbol.contains("4OpenEPKhm") {
        ArtOpenLayout::Memory { base: 1, size: 2 }
    } else if symbol.contains("4OpenEPKc") {
        ArtOpenLayout::Filename { reg: 1 }
    } else if symbol.contains("10OpenCommonENSt") {
        ArtOpenLayout::Memory { base: 2, size: 3 }
    } else {
        ArtOpenLayout::Probe
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn art_open_path_hint(pid: u32, regs: &[u64; 31], symbol: &str) -> ArtOpenHint {
    match art_open_layout(symbol) {
        ArtOpenLayout::Filename { reg } => {
            if let Some(path) = path_cstring(pid, regs.get(reg).copied().unwrap_or(0)) {
                return ArtOpenHint {
                    layout: "file",
                    path: Some(path),
                };
            }
        }
        ArtOpenLayout::Memory { base, size } => {
            if let Some(hint) = memory_open_hint(
                pid,
                regs.get(base).copied().unwrap_or(0),
                regs.get(size).copied().unwrap_or(0),
            ) {
                return hint;
            }
        }
        ArtOpenLayout::Probe => {}
    }
    for index in [1_usize, 2, 3, 0] {
        if let Some(path) = path_cstring(pid, regs[index]) {
            return ArtOpenHint {
                layout: "file",
                path: Some(path),
            };
        }
    }
    for (base, size) in [(1_usize, 2), (0, 1), (2, 3)] {
        if let Some(hint) = memory_open_hint(pid, regs[base], regs[size]) {
            return hint;
        }
    }
    ArtOpenHint {
        layout: "unknown",
        path: None,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn path_cstring(pid: u32, address: u64) -> Option<String> {
    let value = read_remote_cstring(pid, address, REMOTE_PATH_BYTES)?;
    looks_like_code_path(&value).then_some(value)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn memory_open_hint(pid: u32, base: u64, size: u64) -> Option<ArtOpenHint> {
    if !plausible_user_ptr(base) || !plausible_dex_size(size) {
        return None;
    }
    let header = read_remote_bytes(pid, base, 8).unwrap_or_default();
    let magic = if ksight_core::is_dex_magic(&header) {
        "dex"
    } else {
        "unknown"
    };
    Some(ArtOpenHint {
        layout: if magic == "dex" {
            "memory"
        } else {
            "memory_unverified"
        },
        path: Some(format!("memory:{base:#x}+{size}")),
    })
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn looks_like_code_path(value: &str) -> bool {
    if !(3..=255).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("classes") && (lower.contains(".dex") || lower.contains(".cdex")) {
        return true;
    }
    if CODE_PATH_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return lower.starts_with('/') || lower.starts_with("memfd:") || !lower.contains('/');
    }
    lower.starts_with("/data/")
        || lower.starts_with("/system/")
        || lower.starts_with("/system_ext/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/vendor/")
        || lower.starts_with("/product/")
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn plausible_user_ptr(value: u64) -> bool {
    (0x1000..=0x0000_7fff_ffff_ffff).contains(&value)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn plausible_dex_size(value: u64) -> bool {
    (0x70..=64 * 1024 * 1024).contains(&value)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_tls_plaintext(
    plan: &InspectPlan,
    pid: u32,
    tid: u32,
    buf: u64,
    requested: i32,
    max_payload: usize,
    direction: &str,
) -> Option<InspectOutput> {
    if requested <= 0 {
        return None;
    }
    let requested_bytes = u64::try_from(requested).unwrap_or(0);
    let want = usize::try_from(requested_bytes)
        .unwrap_or(0)
        .min(max_payload);
    let bytes = read_remote_bytes(pid, buf, want).unwrap_or_default();
    let truncated = requested_bytes > u64::try_from(bytes.len()).unwrap_or(0);
    let content_class = classify_buffer(&bytes);
    let (preview, preview_encoding) = if content_class == "tls_record" {
        (tls_record_preview(&bytes), "tls_record".to_owned())
    } else {
        preview_bytes(&bytes)
    };
    Some(InspectOutput::Plaintext {
        pid,
        tid,
        fragment: InspectPlaintext {
            adapter: plan.adapter.as_str().to_owned(),
            direction: direction.to_owned(),
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

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn read_remote_utf16(pid: u32, address: u64, units: u64) -> Option<String> {
    let count = usize::try_from(units).ok()?.min(BINDER_INTERFACE_UNITS_CAP);
    if count == 0 {
        return None;
    }
    let address = address & 0x00ff_ffff_ffff_ffff;
    let bytes = read_remote_bytes(pid, address, count.saturating_mul(2))?;
    decode_utf16le(&bytes, count)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn utf16_from_hit(pid: u32, hit: &ksight_hwbp::RegisterContext) -> Option<String> {
    let units = usize::try_from(hit.regs[2] & 0xffff_ffff)
        .ok()?
        .min(BINDER_INTERFACE_UNITS_CAP);
    if units == 0 {
        return None;
    }
    if hit.aux.iter().any(|byte| *byte != 0) {
        if let Some(value) = decode_utf16le(&hit.aux, units) {
            return Some(value);
        }
    }
    read_remote_utf16(pid, hit.regs[1], hit.regs[2])
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn cstring_from_hit(pid: u32, hit: &ksight_hwbp::RegisterContext) -> Option<String> {
    let n = usize::try_from(hit.aux_bytes)
        .unwrap_or(0)
        .min(hit.aux.len())
        .min(BINDER_INTERFACE_UNITS_CAP);
    if n > 0 && hit.aux[0] != 0 {
        let end = hit.aux[..n].iter().position(|byte| *byte == 0).unwrap_or(n);
        let value = String::from_utf8_lossy(&hit.aux[..end]).into_owned();
        if looks_like_binder_string(&value) {
            return Some(value);
        }
    }
    let address = hit.regs[1] & 0x00ff_ffff_ffff_ffff;
    let value = read_remote_cstring(pid, address, BINDER_INTERFACE_UNITS_CAP)?;
    looks_like_binder_string(&value).then_some(value)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn utf8_from_hit(pid: u32, hit: &ksight_hwbp::RegisterContext) -> Option<String> {
    let count = usize::try_from(hit.regs[2] & 0xffff_ffff)
        .ok()?
        .min(BINDER_INTERFACE_UNITS_CAP);
    if count == 0 {
        return None;
    }
    let n = count.min(hit.aux.len());
    if n > 0 && hit.aux[0] != 0 {
        let end = hit.aux[..n].iter().position(|byte| *byte == 0).unwrap_or(n);
        let value = String::from_utf8_lossy(&hit.aux[..end]).into_owned();
        if looks_like_binder_string(&value) {
            return Some(value);
        }
    }
    let address = hit.regs[1] & 0x00ff_ffff_ffff_ffff;
    let bytes = read_remote_bytes(pid, address, count)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).into_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn decode_utf16le(bytes: &[u8], units: usize) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let count = (bytes.len() / 2).min(units);
    let mut units16 = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(2).take(count) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units16.push(unit);
    }
    let value = String::from_utf16(&units16).ok()?;
    (!value.is_empty()).then_some(value)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn looks_like_binder_interface(value: &str) -> bool {
    (3..=192).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '$' | '/'))
        && value.contains('.')
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn looks_like_binder_string(value: &str) -> bool {
    let count = value.chars().count();
    if !(1..=BINDER_INTERFACE_UNITS_CAP).contains(&count) {
        return false;
    }
    value.chars().all(|ch| !ch.is_control())
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn push_binder_string(pending: &mut HashMap<u32, Vec<String>>, tid: u32, value: String) {
    push_bounded(pending, tid, value, BINDER_STRINGS_PER_TID);
}

fn push_bounded<T>(pending: &mut HashMap<u32, Vec<T>>, tid: u32, value: T, cap: usize) {
    if pending.len() >= BINDER_PENDING_TIDS && !pending.contains_key(&tid) {
        return;
    }
    let entry = pending.entry(tid).or_default();
    if entry.len() >= cap {
        entry.remove(0);
    }
    entry.push(value);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn strong_binder_from_hit(
    pid: u32,
    hit: &ksight_hwbp::RegisterContext,
    pointer_width: u8,
) -> Option<String> {
    let address = hit.regs[1] & 0x00ff_ffff_ffff_ffff;
    if !plausible_user_ptr(address) {
        return None;
    }
    let width = if pointer_width == 4 { 4 } else { 8 };
    let bytes = if hit.aux_bytes as usize >= width && hit.aux.len() >= width {
        hit.aux[..width].to_vec()
    } else {
        read_remote_bytes(pid, address, width)?
    };
    let ptr = if width == 4 {
        u64::from(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
    } else {
        u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)
    };
    Some(format!("{ptr:#x}"))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn byte_array_from_hit(hit: &ksight_hwbp::RegisterContext) -> Option<String> {
    let len = usize::try_from(hit.regs[1] & 0xffff_ffff).ok()?;
    if len == 0 {
        return None;
    }
    let n = len.min(32).min(hit.aux.len());
    let mut hex = String::with_capacity(n.saturating_mul(2));
    for byte in hit.aux.iter().take(n) {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
    }
    Some(format!("len={len} hex={hex}"))
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn pair_binder_transact(
    tid: u32,
    tokens: &mut HashMap<u32, String>,
    strings: &mut HashMap<u32, Vec<String>>,
) -> (Option<String>, Vec<String>) {
    let mut collected = strings.remove(&tid).unwrap_or_default();
    let mut interface = tokens.remove(&tid);
    if interface.is_none() {
        if let Some(index) = collected
            .iter()
            .position(|value| looks_like_binder_interface(value))
        {
            interface = Some(collected.remove(index));
        }
    }
    if let Some(token) = interface.as_deref() {
        collected.retain(|value| value != token);
    }
    (interface, collected)
}

/// `IBinder` well-known codes from `binder/IBinder.h`, plus AOSP AIDL declaration order.
/// App-specific AIDL is never guessed: unknown `(interface, code)` stays unnamed.
#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn resolve_binder_method(
    cache: &mut crate::binder_dex::ProcessDexAidlCache,
    pid: u32,
    interface: Option<&str>,
    code: u32,
) -> (Option<String>, Option<String>) {
    if let Some(name) = binder_method_name(interface, code) {
        return (Some(name.to_owned()), Some("aosp_stub".to_owned()));
    }
    let Some(interface) = interface else {
        return (None, None);
    };
    match cache.lookup(pid, interface, code) {
        Some(name) => (Some(name.to_owned()), Some("process_dex".to_owned())),
        None => (None, None),
    }
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn binder_method_name(interface: Option<&str>, code: u32) -> Option<&'static str> {
    if let Some(name) = ibinder_well_known(code) {
        return Some(name);
    }
    crate::binder_aidl::aidl_method(interface?, code)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn ibinder_well_known(code: u32) -> Option<&'static str> {
    match code {
        0x5f4e_5446 => Some("INTERFACE_TRANSACTION"),
        0x5f50_4e47 => Some("PING_TRANSACTION"),
        0x5f44_4d50 => Some("DUMP_TRANSACTION"),
        0x5f43_4d44 => Some("SHELL_COMMAND_TRANSACTION"),
        0x5f53_5052 => Some("SYSPROPS_TRANSACTION"),
        0x5f45_5854 => Some("EXTENSION_TRANSACTION"),
        0x5f42_5044 => Some("DEBUG_PID_TRANSACTION"),
        0x00ff_fffe => Some("getInterfaceHash"),
        0x00ff_ffff => Some("getInterfaceVersion"),
        _ => None,
    }
}

/// Record exported ART `DexFileLoader::Open` hits for dump-package `ClassLoader` provenance.
///
/// This is file/memory DEX open order from an exported symbol, not a Java
/// `ClassLoader` instance. Missing uprobe objects are a no-op.
pub fn record_art_dex_opens(
    package: &str,
    dest_dir: &Path,
    uprobe_object: &Path,
    duration: Duration,
) -> usize {
    record_art_dex_opens_with_ready(package, dest_dir, uprobe_object, duration, None)
}

/// Same as [`record_art_dex_opens`], signalling `ready` after uprobes attach
/// so dump-package can launch the app without missing the first Open.
pub fn record_art_dex_opens_with_ready(
    package: &str,
    dest_dir: &Path,
    uprobe_object: &Path,
    duration: Duration,
    ready: Option<std::sync::mpsc::Sender<()>>,
) -> usize {
    if package.is_empty() || !uprobe_object.is_file() {
        return 0;
    }
    let _ = std::fs::create_dir_all(dest_dir);
    let policy = InspectPolicy {
        enabled: true,
        package: Some(package.to_owned()),
        max_hits: 16_384,
        max_duration_secs: u32::try_from(duration.as_secs()).unwrap_or(8).max(1),
        // Attach globally; dump-package filters hits by /proc cmdline because
        // Inspect identity does not populate `packages`.
        whole_device: true,
        ..InspectPolicy::default()
    };
    let mut art_rt =
        InspectRuntime::prepare(&policy, InspectAdapterKind::ArtDexLoad, uprobe_object);
    let mut attached: Vec<String> = art_rt
        .attach()
        .into_iter()
        .map(|observation| observation.detail)
        .collect();
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
    let deadline = Instant::now() + duration;
    let mut hits = Vec::new();
    let mut dropped = Vec::new();
    let mut raw_hits = 0_u32;
    while Instant::now() < deadline && hits.len() < 256 {
        for output in art_rt.poll() {
            let InspectOutput::Observation {
                pid: hit_pid,
                observation,
                ..
            } = output
            else {
                continue;
            };
            if !observation.hit {
                continue;
            }
            raw_hits = raw_hits.saturating_add(1);
            let pid = if hit_pid > 0 {
                hit_pid
            } else {
                pid_from_detail(&observation.detail)
            };
            let cmdline = proc_cmdline(pid);
            let mut path = observation.path_hint.clone().unwrap_or_default();
            if path.is_empty() {
                if let Some(fd_path) = fd_code_path_for_pid(pid, package) {
                    path = fd_path;
                }
            }
            if !art_open_belongs_to_package(package, &cmdline, &path) {
                if dropped.len() < 24 {
                    dropped.push(serde_json::json!({
                        "pid": pid,
                        "cmdline": cmdline,
                        "symbol": symbol_from_detail(&observation.detail).unwrap_or_default(),
                        "path": path,
                    }));
                }
                continue;
            }
            let opened_bytes = parse_open_size(&path);
            let role = if path.starts_with("memory:") {
                "in_memory"
            } else {
                crate::dexdump::code_loader_role(&path).unwrap_or("unknown")
            };
            hits.push(serde_json::json!({
                "pid": pid,
                "order": hits.len().saturating_add(1),
                "role": role,
                "origin": "art_open",
                "adapter": observation.adapter,
                "symbol": symbol_from_detail(&observation.detail).unwrap_or_default(),
                "path": path,
                "cmdline": cmdline,
                "opened_bytes": opened_bytes,
                "detail": observation.detail,
            }));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(art_rt);
    if attached.is_empty() {
        attached.push("no attach observations".to_owned());
    }
    let payload = serde_json::json!({
        "package": package,
        "note": "ART DexFileLoader/ArtDexFileLoader exported Open* hits; not a Java ClassLoader instance",
        "attached": attached,
        "raw_hits": raw_hits,
        "dropped_samples": dropped,
        "entries": hits,
    });
    let _ = std::fs::write(dest_dir.join("dex-open-order.json"), payload.to_string());
    hits.len()
}

fn art_open_belongs_to_package(package: &str, cmdline: &str, path: &str) -> bool {
    if package.is_empty() {
        return false;
    }
    cmdline == package
        || cmdline.starts_with(&format!("{package}:"))
        || (!path.is_empty() && path.contains(package))
}

fn proc_cmdline(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
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

/// Best-effort path when the Open* export does not pass a C string (location lives
/// in the loader object). Uses `/proc/<pid>/fd` only — no ART field offsets.
fn fd_code_path_for_pid(pid: u32, package: &str) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut ranked = Vec::new();
    for entry in entries.flatten().take(512) {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let path = target.to_string_lossy().into_owned();
        let Some(role) = crate::dexdump::code_loader_role(&path) else {
            continue;
        };
        if role == "boot" {
            continue;
        }
        let rank = if path.contains(package) {
            0_u8
        } else if path.contains("/data/app/") {
            1
        } else if path.contains("code_cache") || path.contains("secondary-dex") {
            2
        } else if role == "in_memory" {
            3
        } else {
            4
        };
        ranked.push((rank, path));
    }
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    ranked.into_iter().map(|(_, path)| path).next()
}

fn pid_from_detail(detail: &str) -> u32 {
    detail
        .split("pid=")
        .nth(1)
        .and_then(|rest| {
            rest.split(|byte: char| !byte.is_ascii_digit())
                .next()
                .and_then(|digits| digits.parse().ok())
        })
        .unwrap_or(0)
}

fn symbol_from_detail(detail: &str) -> Option<String> {
    detail.split("symbol=").nth(1).and_then(|rest| {
        let value = rest.split_whitespace().next().unwrap_or("");
        (!value.is_empty() && value != "-").then(|| value.to_owned())
    })
}

fn parse_open_size(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("memory:")?;
    rest.split_once('+')?.1.parse().ok()
}

#[cfg(test)]
mod tests {
    use ksight_model::ProcessKey;

    use super::*;

    #[test]
    fn pid_and_memory_size_parse_from_art_open_fields() {
        assert_eq!(pid_from_detail("ART DEX Open hit pid=24056 path=/x"), 24056);
        assert_eq!(parse_open_size("memory:0x1000+4096"), Some(4096));
        assert_eq!(parse_open_size("/data/app/x/base.apk"), None);
        assert_eq!(
            symbol_from_detail(
                "ART DEX Open hit pid=1 symbol=_ZN3art13DexFileLoader10OpenCommonEPKhm layout=memory path=memory:0x1+2"
            )
            .as_deref(),
            Some("_ZN3art13DexFileLoader10OpenCommonEPKhm")
        );
    }

    #[test]
    fn art_open_layout_follows_exported_itanium_encoding() {
        assert_eq!(
            art_open_layout("_ZNK3art16ArtDexFileLoader4OpenEPKcRKNSt3__1"),
            ArtOpenLayout::Filename { reg: 1 }
        );
        assert_eq!(
            art_open_layout("_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNS"),
            ArtOpenLayout::Memory { base: 0, size: 1 }
        );
        assert_eq!(
            art_open_layout("_ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__1"),
            ArtOpenLayout::Memory { base: 1, size: 2 }
        );
        assert_eq!(
            art_open_layout("_ZNK3art13DexFileLoader16OpenFromZipEntryERKNS_10ZipArchiveEPKc"),
            ArtOpenLayout::Filename { reg: 2 }
        );
        assert_eq!(
            art_open_layout("_ZN3art13DexFileLoader4OpenEbbbPNS_22DexFileLoaderErrorCodeE"),
            ArtOpenLayout::Probe
        );
    }

    #[test]
    fn code_path_hints_accept_apk_and_zip_entries() {
        assert!(looks_like_code_path("/data/app/x/base.apk"));
        assert!(looks_like_code_path("classes.dex"));
        assert!(looks_like_code_path(
            "/apex/com.android.art/javalib/core-oj.jar"
        ));
        assert!(!looks_like_code_path(""));
        assert!(!looks_like_code_path("ok"));
        assert!(!looks_like_code_path("not a path"));
    }

    #[test]
    fn art_open_package_filter_does_not_keep_other_apks() {
        assert!(art_open_belongs_to_package(
            "com.icbc",
            "com.icbc",
            "memory:0x1+2"
        ));
        assert!(art_open_belongs_to_package("com.icbc", "com.icbc:push", ""));
        assert!(art_open_belongs_to_package(
            "com.icbc",
            "zygote",
            "/data/app/~~x==/com.icbc-y==/base.apk"
        ));
        assert!(!art_open_belongs_to_package(
            "com.icbc",
            "zygote",
            "/data/app/~~x==/com.google.android.trichromelibrary/TrichromeLibrary.apk"
        ));
        assert!(!art_open_belongs_to_package(
            "com.icbc",
            "com.qihoo.magic",
            "/data/app/~~x==/com.eg.android.AlipayGphone-y==/base.apk"
        ));
    }

    #[test]
    fn art_dex_prefixes_cover_loader_and_common() {
        let names = InspectAdapterKind::ArtDexLoad.symbols();
        assert!(names.iter().any(|name| name.contains("DexFileLoader4Open")));
        assert!(names.iter().any(|name| name.contains("OpenCommon")));
        assert!(names.iter().any(|name| name.contains("OpenFromZipEntry")));
        assert!(InspectAdapterKind::ArtDexMemory
            .symbols()
            .iter()
            .all(|name| name.contains("EPKhm")));
        assert!(plausible_dex_size(0x70));
        assert!(!plausible_dex_size(1));
        assert!(plausible_user_ptr(0x1000));
        assert!(!plausible_user_ptr(0));
    }

    #[test]
    fn mapping_path_matches_libbinder_basename() {
        assert!(mapping_path_matches(
            "/system/lib/libbinder.so",
            "libbinder.so"
        ));
        assert!(mapping_path_matches(
            "/system/lib64/libbinder.so",
            "libbinder.so"
        ));
        assert!(!mapping_path_matches(
            "/system/lib64/libbinder_ndk.so",
            "libbinder.so"
        ));
        assert!(mapping_path_matches("/system/bin/linker", "linker"));
        assert!(!mapping_path_matches("/system/bin/linker64", "linker"));
        assert!(mapping_path_matches(
            "/data/app/foo/lib/arm64/libcronet.119.0.6045.so",
            "libcronet.so"
        ));
        assert!(mapping_path_matches(
            "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
            "libssl.so"
        ));
        assert!(mapping_path_matches(
            "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
            "libcronet.so"
        ));
        let libs = InspectAdapterKind::BinderUserspace.libraries();
        assert!(libs
            .iter()
            .any(|path| path.ends_with("/lib64/libbinder.so")));
        assert!(libs.iter().any(|path| path.ends_with("/lib/libbinder.so")));
    }

    #[test]
    fn scoped_inspect_filters_tgid_in_kernel() {
        let whole = InspectPolicy {
            enabled: true,
            whole_device: true,
            package: Some("com.example".to_owned()),
            ..InspectPolicy::default()
        };
        assert_eq!(active_tgid_filter(&whole), None);
        let one = InspectPolicy {
            enabled: true,
            pid: Some(42),
            ..InspectPolicy::default()
        };
        assert_eq!(active_tgid_filter(&one), Some(vec![42]));
        assert_eq!(join_tgids(&[42, 43]), "42,43");
    }

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
    fn binder_userspace_also_plans_write_interface_token() {
        let policy = InspectPolicy {
            enabled: true,
            package: Some("com.example.app".to_owned()),
            ..InspectPolicy::default()
        };
        let runtime = InspectRuntime::prepare(
            &policy,
            InspectAdapterKind::BinderUserspace,
            Path::new("/nonexistent"),
        );
        let adapters: Vec<_> = runtime
            .initial_observations()
            .into_iter()
            .map(|observation| observation.adapter)
            .collect();
        assert!(adapters.iter().any(|adapter| adapter == "binder_userspace"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_interface_token"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_string"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_utf8"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_int64"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_bool"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_cstring"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_dup_fd"));
        assert!("binder_interface_token"
            .parse::<InspectAdapterKind>()
            .is_ok());
        assert!("binder_parcel_string".parse::<InspectAdapterKind>().is_ok());
        assert!("binder_parcel_int64".parse::<InspectAdapterKind>().is_ok());
        assert!(InspectAdapterKind::BinderInterfaceToken.symbols()[0]
            .contains("writeInterfaceTokenEPKDsm"));
        assert!(InspectAdapterKind::BinderParcelString.symbols()[0].contains("writeString16EPKDsm"));
        assert!(InspectAdapterKind::BinderParcelUtf8.symbols()[0].contains("writeString8EPKcm"));
        assert!(InspectAdapterKind::BinderParcelInt64.symbols()[0].contains("writeInt64El"));
        assert!(InspectAdapterKind::BinderParcelBool.symbols()[0].contains("writeBoolEb"));
        assert!(InspectAdapterKind::BinderParcelCString.symbols()[0].contains("writeCStringEPKc"));
        assert!(
            InspectAdapterKind::BinderParcelDupFd.symbols()[0].contains("writeDupFileDescriptorEi")
        );
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_binder"));
        assert!(adapters
            .iter()
            .any(|adapter| adapter == "binder_parcel_byte"));
        assert!("binder_parcel_binder".parse::<InspectAdapterKind>().is_ok());
        assert!(InspectAdapterKind::BinderParcelBinder.symbols()[0].contains("writeStrongBinder"));
        assert!(InspectAdapterKind::BinderParcelByte.symbols()[0].contains("writeByteEa"));
        assert!(InspectAdapterKind::BinderParcelChar.symbols()[0].contains("writeCharEDs"));
    }

    #[test]
    fn utf16_interface_token_rejects_noise() {
        let mut bytes = Vec::new();
        for unit in "android.os.IServiceManager".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            decode_utf16le(&bytes, 64).as_deref(),
            Some("android.os.IServiceManager")
        );
        assert!(looks_like_binder_interface("android.os.IServiceManager"));
        assert!(!looks_like_binder_interface("ok"));
        assert!(!looks_like_binder_interface("not a token"));
        assert!(looks_like_binder_string("activity"));
        assert!(looks_like_binder_string("/data/user/0/com.example/files/x"));
        assert!(!looks_like_binder_string("has\u{0007}bell"));
    }

    #[test]
    fn binder_transact_pairs_token_and_string16_by_tid() {
        let mut tokens = HashMap::from([(7_u32, "android.os.IServiceManager".to_owned())]);
        let mut strings = HashMap::new();
        push_binder_string(&mut strings, 7, "android.os.IServiceManager".to_owned());
        push_binder_string(&mut strings, 7, "activity".to_owned());
        let (interface, collected) = pair_binder_transact(7, &mut tokens, &mut strings);
        assert_eq!(interface.as_deref(), Some("android.os.IServiceManager"));
        assert_eq!(collected, vec!["activity".to_owned()]);
        assert!(!tokens.contains_key(&7));
        assert!(!strings.contains_key(&7));
    }

    #[test]
    fn binder_method_names_are_aosp_table_only() {
        assert_eq!(
            binder_method_name(Some("android.os.IServiceManager"), 1),
            Some("getService")
        );
        assert_eq!(
            binder_method_name(Some("android.os.IServiceManager"), 6),
            Some("listServices")
        );
        assert_eq!(
            binder_method_name(Some("android.content.pm.IPackageManager"), 3),
            Some("getPackageInfo")
        );
        assert_eq!(
            binder_method_name(Some("android.gui.IDisplayEventConnection"), 3),
            Some("requestNextVsync")
        );
        assert_eq!(
            binder_method_name(Some("android.app.IUiModeManager"), 1),
            Some("addCallback")
        );
        assert_eq!(
            binder_method_name(Some("android.app.IUiModeManager"), 5),
            Some("getCurrentModeType")
        );
        assert_eq!(
            binder_method_name(Some("android.os.IServiceManager"), 0x5f50_4e47),
            Some("PING_TRANSACTION")
        );
        assert_eq!(
            binder_method_name(Some("com.example.IBankSession"), 1),
            None
        );
        assert_eq!(binder_method_name(None, 1), None);
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
    fn inspect_tls_and_binder_plan_together() {
        let policy = InspectPolicy {
            enabled: true,
            package: Some("com.example.app".to_owned()),
            ..InspectPolicy::default()
        };
        let runtime = InspectRuntime::prepare_all(
            &policy,
            &[
                InspectAdapterKind::TlsSslWrite,
                InspectAdapterKind::BinderUserspace,
            ],
            Path::new("/nonexistent"),
        );
        let adapters = runtime
            .initial_observations()
            .into_iter()
            .map(|observation| observation.adapter)
            .collect::<BTreeSet<_>>();
        assert!(adapters.contains("tls_ssl_write"));
        assert!(adapters.contains("tls_ssl_read"));
        assert!(adapters.contains("binder_userspace"));
        assert!(adapters.contains("binder_interface_token"));
        assert!(adapter_is_live(
            &[
                InspectAdapterKind::TlsSslWrite,
                InspectAdapterKind::BinderUserspace,
            ],
            InspectAdapterKind::TlsSslRead
        ));
        assert!(adapter_is_live(
            &[
                InspectAdapterKind::TlsSslWrite,
                InspectAdapterKind::BinderUserspace,
            ],
            InspectAdapterKind::BinderParcelString
        ));
    }

    #[test]
    fn skips_elf32_tls_when_elf64_symbol_exists() {
        let policy = InspectPolicy {
            enabled: true,
            package: Some("com.example.app".to_owned()),
            ..InspectPolicy::default()
        };
        let mut elf32 = InspectPlan::evaluate(
            policy.clone(),
            InspectAdapterKind::TlsSslWrite,
            PathBuf::from("/nonexistent"),
        )
        .remove(0);
        elf32.pointer_width = 4;
        elf32.offset = Some(0x10);
        let mut elf64 = elf32.clone();
        elf64.pointer_width = 8;
        elf64.offset = Some(0x20);
        let mut plans = vec![elf32, elf64];
        prune_redundant_elf32_tls(&mut plans);
        assert!(plans[0].offset.is_none());
        assert_eq!(plans[1].offset, Some(0x20));
        assert!(plans[0].observation.detail.contains("skipped ELF32 TLS"));
    }

    #[test]
    fn inspect_tls_also_plans_ssl_read() {
        let policy = InspectPolicy {
            enabled: true,
            package: Some("com.example.app".to_owned()),
            ..InspectPolicy::default()
        };
        let runtime = InspectRuntime::prepare(
            &policy,
            InspectAdapterKind::TlsSslWrite,
            Path::new("/nonexistent"),
        );
        let adapters: Vec<_> = runtime
            .initial_observations()
            .into_iter()
            .map(|observation| observation.adapter)
            .collect();
        assert!(adapters.iter().any(|adapter| adapter == "tls_ssl_write"));
        assert!(adapters.iter().any(|adapter| adapter == "tls_ssl_read"));
        assert!(InspectAdapterKind::TlsSslWrite
            .libraries()
            .iter()
            .any(|path| path.contains("stable_cronet_libssl.so")));
        assert!(InspectAdapterKind::TlsSslWrite
            .symbols()
            .contains(&"SSL_write"));
        assert!(InspectAdapterKind::TlsSslWrite
            .symbols()
            .contains(&"SSL_write_ex"));
        assert!(InspectAdapterKind::TlsSslRead
            .symbols()
            .contains(&"SSL_read_ex"));
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
