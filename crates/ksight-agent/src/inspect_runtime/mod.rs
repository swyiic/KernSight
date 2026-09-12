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

use crate::elf::{inspect_elf, matching_symbols, matching_symbols_exact, symbol_match};

static FRAGMENT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

const LINKER_NAMES: [&str; 3] = ["__loader_dlopen", "do_dlopen", "android_dlopen_ext"];
const LINKER_PATHS: [&str; 4] = [
    "/apex/com.android.runtime/bin/linker64",
    "/system/bin/linker64",
    "/apex/com.android.runtime/bin/linker",
    "/system/bin/linker",
];
const TLS_NAMES: [&str; 8] = [
    "SSL_write",
    "SSL_write_ex",
    "SSL_write_ex2",
    "SSL_write_early_data",
    "mbedtls_ssl_write",
    "wolfSSL_write",
    // Alibaba slightssl (libtnet): plain write only — *_ex needs ProbeSpec.abi.
    "sslWrite",
    "SLIGHT_SSL_write",
];
const TLS_READ_NAMES: [&str; 10] = [
    "SSL_read",
    "SSL_read_ex",
    "SSL_read_ex2",
    "SSL_peek",
    "SSL_peek_ex",
    "SSL_read_early_data",
    "mbedtls_ssl_read",
    "wolfSSL_read",
    // Alibaba slightssl (libtnet): plain read only — *_ex needs ProbeSpec.abi.
    "sslRead",
    "SLIGHT_SSL_read",
];
const TLS_PATHS: [&str; 9] = [
    "/apex/com.android.conscrypt/lib64/libssl.so",
    "/system/lib64/libssl.so",
    "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
    "/apex/com.android.conscrypt/lib/libssl.so",
    "/system/lib/libssl.so",
    "/apex/com.android.tethering/lib/stable_cronet_libssl.so",
    // Dynsym-proven Pixel6a siblings of conscrypt/system libssl (2026-09-10 overnight pull).
    "/apex/com.android.resolv/lib64/libssl.so",
    "/apex/com.android.virt/lib64/libssl.so",
    "/apex/com.android.configinfrastructure/lib64/libssl.so",
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
const ART_JNI_PATHS: [&str; 2] = [
    "/apex/com.android.art/lib64/libart.so",
    "/apex/com.android.art/lib/libart.so",
];
const ART_OPEN_ATTACH_CAP: usize = 12;
const TLS_LIBRARY_CANDIDATE_CAP: usize = 48;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const TLS_EXPORTER_CAP: usize = 24;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const TLS_BURST_RESCAN_INTERVAL: Duration = Duration::from_secs(3);
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const TLS_STEADY_RESCAN_INTERVAL: Duration = Duration::from_secs(15);
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const TLS_BURST_RESCANS: u32 = 8;
/// DexHelper/Bangcle-style packers suicide if `libart` JNI uprobes exist during
/// the first few seconds of process start. Attach after this age instead.
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const PACKER_ATTACH_GRACE: Duration = Duration::from_secs(6);
const JNI_ENV_ATTACH_CAP: usize = 64;
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
/// JNI `GetStringChars` / `GetStringCritical` unit cap. Must exceed the Binder
/// token cap: a 192-unit clamp truncated HSBC `"url":"ht` JSON.
const JNI_UTF16_UNITS_CAP: usize = 2048;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_STRINGS_PER_TID: usize = 8;
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
const BINDER_PENDING_TIDS: usize = 4096;
#[cfg(any(target_os = "android", target_os = "linux"))]
const REMOTE_PATH_BYTES: usize = 256;
#[cfg(any(target_os = "android", target_os = "linux"))]
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

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
    /// JNI `RegisterNatives` via `JNINativeInterface` (jni.h slot from exported `GetFunctionTable`).
    JniRegistration,
    /// Operator alias: `JNIEnv` UTF-8 / `byte[]` plaintext plus `RegisterNatives`.
    JniPlaintext,
    /// `JNINativeInterface::NewStringUTF` (native UTF-8 → Java `String`).
    JniNewStringUtf,
    /// `JNINativeInterface::GetStringUTFChars` (Java `String` → native UTF-8).
    JniGetStringUtfChars,
    /// `JNINativeInterface::GetStringUTFLength`. Pairs length to `GetStringUTFChars` by jobject.
    JniGetStringUtfLength,
    /// `JNINativeInterface::GetStringUTFRegion` (explicit `len` into caller buffer).
    JniGetStringUtfRegion,
    /// `JNINativeInterface::GetArrayLength`. Pairs length to `GetByteArrayElements` by jobject.
    JniGetArrayLength,
    /// `JNINativeInterface::GetByteArrayElements` (Java `byte[]` → native, length from `GetArrayLength`).
    JniGetByteArrayElements,
    /// `JNINativeInterface::GetByteArrayRegion` (Java `byte[]` → caller buffer).
    JniGetByteArrayRegion,
    /// `JNINativeInterface::SetByteArrayRegion` (native buffer → Java `byte[]`).
    JniSetByteArrayRegion,
    /// `JNINativeInterface::NewString` (native UTF-16 → Java `String`).
    JniNewString,
    /// `JNINativeInterface::GetStringLength`. Pairs UTF-16 length by jobject.
    JniGetStringLength,
    /// `JNINativeInterface::GetStringChars` (Java `String` → UTF-16).
    JniGetStringChars,
    /// `JNINativeInterface::GetStringRegion` (UTF-16 into caller buffer).
    JniGetStringRegion,
    /// `JNINativeInterface::GetStringCritical` (Java `String` → UTF-16).
    JniGetStringCritical,
    /// `JNINativeInterface::GetCharArrayElements` (Java `char[]` → UTF-16).
    JniGetCharArrayElements,
    /// `JNINativeInterface::GetCharArrayRegion`.
    JniGetCharArrayRegion,
    /// `JNINativeInterface::SetCharArrayRegion`.
    JniSetCharArrayRegion,
    /// `JNINativeInterface::GetPrimitiveArrayCritical`.
    JniGetPrimitiveArrayCritical,
    /// `JNINativeInterface::GetDirectBufferAddress`.
    JniGetDirectBufferAddress,
    /// `JNINativeInterface::GetDirectBufferCapacity`. Pairs with `GetDirectBufferAddress`.
    JniGetDirectBufferCapacity,
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
            Self::JniPlaintext => "jni_plaintext",
            Self::JniNewStringUtf => "jni_new_string_utf",
            Self::JniGetStringUtfChars => "jni_get_string_utf_chars",
            Self::JniGetStringUtfLength => "jni_get_string_utf_length",
            Self::JniGetStringUtfRegion => "jni_get_string_utf_region",
            Self::JniGetArrayLength => "jni_get_array_length",
            Self::JniGetByteArrayElements => "jni_get_byte_array_elements",
            Self::JniGetByteArrayRegion => "jni_get_byte_array_region",
            Self::JniSetByteArrayRegion => "jni_set_byte_array_region",
            Self::JniNewString => "jni_new_string",
            Self::JniGetStringLength => "jni_get_string_length",
            Self::JniGetStringChars => "jni_get_string_chars",
            Self::JniGetStringRegion => "jni_get_string_region",
            Self::JniGetStringCritical => "jni_get_string_critical",
            Self::JniGetCharArrayElements => "jni_get_char_array_elements",
            Self::JniGetCharArrayRegion => "jni_get_char_array_region",
            Self::JniSetCharArrayRegion => "jni_set_char_array_region",
            Self::JniGetPrimitiveArrayCritical => "jni_get_primitive_array_critical",
            Self::JniGetDirectBufferAddress => "jni_get_direct_buffer_address",
            Self::JniGetDirectBufferCapacity => "jni_get_direct_buffer_capacity",
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
            adapter if adapter.is_jni() => &ART_JNI_PATHS,
            _ => &[],
        }
    }

    fn symbols(self) -> &'static [&'static str] {
        match self {
            Self::LinkerSoLoad => &LINKER_NAMES,
            Self::ArtDexLoad => &ART_DEX_NAMES,
            Self::ArtDexMemory => &ART_DEX_MEMORY_NAMES,
            Self::JniRegistration
            | Self::JniPlaintext
            | Self::JniNewStringUtf
            | Self::JniGetStringUtfChars
            | Self::JniGetStringUtfLength
            | Self::JniGetStringUtfRegion
            | Self::JniGetArrayLength
            | Self::JniGetByteArrayElements
            | Self::JniGetByteArrayRegion
            | Self::JniSetByteArrayRegion
            | Self::JniNewString
            | Self::JniGetStringLength
            | Self::JniGetStringChars
            | Self::JniGetStringRegion
            | Self::JniGetStringCritical
            | Self::JniGetCharArrayElements
            | Self::JniGetCharArrayRegion
            | Self::JniSetCharArrayRegion
            | Self::JniGetPrimitiveArrayCritical
            | Self::JniGetDirectBufferAddress
            | Self::JniGetDirectBufferCapacity => &[],
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
            Self::TlsSslWrite | Self::TlsSslRead => &[
                "libssl.so",
                "libopenssl.so",
                "libcurl.so",
                "libcronet.so",
                "libflutter.so",
                "mbedtls",
                "wolfssl",
                "gmssl",
                "tassl",
                "hssl",
                "libtnet",
                // Vendor boringssl (video SDK); basename may be
                // libttboringssl.so — must be discoverable on lazy rescan after dlopen.
                "ttboringssl",
                "boringssl",
                // 合作社/wework: business TLS historically on libwework* SSL_* after
                // cold start, not the first-mapped Conscrypt copy.
                "wework",
                "libww",
            ],
            Self::ArtDexLoad | Self::ArtDexMemory => &["libdexfile.so"],
            Self::LinkerSoLoad => &["linker64", "linker"],
            adapter if adapter.is_jni() => &["libart.so"],
            _ => &[],
        }
    }

    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    const fn is_tls(self) -> bool {
        matches!(self, Self::TlsSslWrite | Self::TlsSslRead)
    }

    pub(crate) const fn is_jni(self) -> bool {
        matches!(
            self,
            Self::JniRegistration
                | Self::JniPlaintext
                | Self::JniNewStringUtf
                | Self::JniGetStringUtfChars
                | Self::JniGetStringUtfLength
                | Self::JniGetStringUtfRegion
                | Self::JniGetArrayLength
                | Self::JniGetByteArrayElements
                | Self::JniGetByteArrayRegion
                | Self::JniSetByteArrayRegion
                | Self::JniNewString
                | Self::JniGetStringLength
                | Self::JniGetStringChars
                | Self::JniGetStringRegion
                | Self::JniGetStringCritical
                | Self::JniGetCharArrayElements
                | Self::JniGetCharArrayRegion
                | Self::JniSetCharArrayRegion
                | Self::JniGetPrimitiveArrayCritical
                | Self::JniGetDirectBufferAddress
                | Self::JniGetDirectBufferCapacity
        )
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
            Self::LinkerSoLoad => 1,
            Self::JniRegistration => 256,
            adapter if adapter.is_jni() => 1024,
            _ => 1024,
        }
    }

    /// Adapters recorded as audited stubs when another adapter is selected.
    pub const fn audited_stubs(self) -> &'static [Self] {
        match self {
            Self::TlsSslWrite | Self::TlsSslRead => {
                &[Self::ArtDexLoad, Self::ArtDexMemory, Self::BinderUserspace]
            }
            Self::LinkerSoLoad => &[
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
            "jni_plaintext" => Ok(Self::JniPlaintext),
            "jni_new_string_utf" => Ok(Self::JniNewStringUtf),
            "jni_get_string_utf_chars" => Ok(Self::JniGetStringUtfChars),
            "jni_get_string_utf_length" => Ok(Self::JniGetStringUtfLength),
            "jni_get_string_utf_region" => Ok(Self::JniGetStringUtfRegion),
            "jni_get_array_length" => Ok(Self::JniGetArrayLength),
            "jni_get_byte_array_elements" => Ok(Self::JniGetByteArrayElements),
            "jni_get_byte_array_region" => Ok(Self::JniGetByteArrayRegion),
            "jni_set_byte_array_region" => Ok(Self::JniSetByteArrayRegion),
            "jni_new_string" => Ok(Self::JniNewString),
            "jni_get_string_length" => Ok(Self::JniGetStringLength),
            "jni_get_string_chars" => Ok(Self::JniGetStringChars),
            "jni_get_string_region" => Ok(Self::JniGetStringRegion),
            "jni_get_string_critical" => Ok(Self::JniGetStringCritical),
            "jni_get_char_array_elements" => Ok(Self::JniGetCharArrayElements),
            "jni_get_char_array_region" => Ok(Self::JniGetCharArrayRegion),
            "jni_set_char_array_region" => Ok(Self::JniSetCharArrayRegion),
            "jni_get_primitive_array_critical" => Ok(Self::JniGetPrimitiveArrayCritical),
            "jni_get_direct_buffer_address" => Ok(Self::JniGetDirectBufferAddress),
            "jni_get_direct_buffer_capacity" => Ok(Self::JniGetDirectBufferCapacity),
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
                "unknown inspect adapter {other}; expected linker_so_load, art_dex_load, art_dex_memory, jni_registration, jni_plaintext, jni_new_string_utf, jni_get_string_utf_chars, jni_get_string_utf_length, jni_get_string_utf_region, jni_get_array_length, jni_get_byte_array_elements, jni_get_byte_array_region, jni_set_byte_array_region, jni_new_string, jni_get_string_length, jni_get_string_chars, jni_get_string_region, jni_get_string_critical, jni_get_char_array_elements, jni_get_char_array_region, jni_set_char_array_region, jni_get_primitive_array_critical, jni_get_direct_buffer_address, jni_get_direct_buffer_capacity, binder_userspace, binder_interface_token, binder_parcel_string, binder_parcel_utf8, binder_parcel_int32, binder_parcel_int64, binder_parcel_uint32, binder_parcel_uint64, binder_parcel_bool, binder_parcel_cstring, binder_parcel_bytes, binder_parcel_fd, binder_parcel_dup_fd, binder_parcel_binder, binder_parcel_byte, binder_parcel_char, tls_ssl_write, or tls_ssl_read"
            )),
        }
    }
}

/// Optional ProbeSpec / plaintext_probe layout overrides applied on top of
/// [`ksight_core::TlsAbiKind::layout`]. Absent fields keep the ABI defaults.
#[derive(Debug, Clone, Default)]
pub struct ProbeLayoutHint {
    /// When set, overrides ABI default entry/return capture phase.
    pub capture_phase: Option<ksight_core::CapturePhase>,
    /// ARM64 arg register for the plaintext pointer (overrides ABI).
    pub buffer_arg: Option<u8>,
    /// ARM64 arg register for the requested length (overrides ABI).
    pub requested_length_arg: Option<u8>,
    /// Where the actual copied length is read (overrides ABI).
    pub actual_length_source: Option<ksight_core::ActualLengthSource>,
    /// ARM64 arg register for a stable connection/session pointer.
    pub connection_arg: Option<u8>,
    /// Per-hit read ceiling; clamped against the session policy max.
    pub max_bytes: Option<u32>,
    /// Optional architecture label from the rule (`arm64`, …).
    pub architecture: Option<String>,
    /// Optional sample digest pin from plaintext_probe (validated soft).
    pub sample_sha256: Option<String>,
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
    /// Explicit TLS ABI. Never inferred from an `_ex` suffix at the call site.
    pub abi: Option<ksight_core::TlsAbiKind>,
    /// ProbeSpec / plaintext_probe field overrides (buffer_arg, capture_phase, …).
    pub layout_hint: ProbeLayoutHint,
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
        self.adapter != InspectAdapterKind::JniPlaintext
            && self.policy.may_attach()
            && self.offset.is_some()
            && self.elf_path.is_some()
            && Path::new(&self.uprobe_object).is_file()
    }

    /// Attach every exact exported TLS write/read name on each mapped library.
    fn evaluate_tls_exports(
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
            match evaluate_tls_symbol_exports(&policy, adapter, &uprobe_object, &library) {
                Some(mut found) => {
                    found.extend(evaluate_plaintext_probe_plans(
                        &policy,
                        adapter,
                        &uprobe_object,
                        &library,
                    ));
                    plans.append(&mut found);
                }
                None => {
                    let mut found =
                        evaluate_plaintext_probe_plans(&policy, adapter, &uprobe_object, &library);
                    if found.is_empty() {
                        plans.push(evaluate_one(
                            policy.clone(),
                            adapter,
                            uprobe_object.clone(),
                            Some(library),
                        ));
                    } else {
                        plans.append(&mut found);
                    }
                }
            }
        }
        if plans.is_empty() {
            Self::evaluate(policy, adapter, uprobe_object)
        } else {
            plans
        }
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

    /// Attach `JNIEnv` functions resolved from exported `GetFunctionTable` + `jni.h` slots.
    fn evaluate_jni_exports(
        policy: InspectPolicy,
        adapter: InspectAdapterKind,
        uprobe_object: PathBuf,
    ) -> Vec<Self> {
        let libraries = resolve_libraries(&policy, adapter);
        if libraries.is_empty() {
            return Self::evaluate(policy, adapter, uprobe_object);
        }
        let wanted = jni_wanted_slots(adapter);
        let mut plans = Vec::new();
        for library in libraries {
            if let Some(mut found) =
                evaluate_jni_env_exports(&policy, adapter, &uprobe_object, &library, wanted)
            {
                plans.append(&mut found);
            }
        }
        if plans.iter().any(|plan| plan.offset.is_some()) {
            plans
        } else {
            Self::evaluate(policy, adapter, uprobe_object)
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
        /// Stable connection/object pointer when the boundary exposes one.
        connection_id: Option<u64>,
        /// Copied fragment.
        fragment: InspectPlaintext,
        /// Original copied bytes for Burp (preview may be lossy).
        raw: Vec<u8>,
    },
}

/// Convert a decoded external/vendor boundary hit into the same durable event
/// used by built-in TLS/JNI adapters.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn external_plaintext(capture: crate::infosec_probe::BoundaryCapture) -> InspectOutput {
    let captured_bytes = u32::try_from(capture.bytes.len()).unwrap_or(u32::MAX);
    let truncated = capture.requested > u64::from(captured_bytes);
    let mut content_class = classify_buffer(&capture.bytes).to_owned();
    // Cheap reassembly tagging from BoundaryFunction hints (no invented offsets).
    if capture.is_header == Some(true) && !content_class.contains("header") {
        content_class = format!("{content_class}+header");
    }
    if capture.is_body == Some(true) && !content_class.contains("body") {
        content_class = format!("{content_class}+body");
    }
    let (preview, preview_encoding) = preview_bytes(&capture.bytes);
    InspectOutput::Plaintext {
        pid: capture.pid,
        tid: capture.tid,
        connection_id: capture.connection_id.or(capture.stream_id),
        fragment: InspectPlaintext {
            adapter: capture.adapter,
            direction: capture.direction.to_owned(),
            library: capture.library,
            build_id: None,
            offset: Some(capture.offset),
            requested_bytes: capture.requested,
            captured_bytes,
            truncated,
            sha256: hex_sha256(&capture.bytes),
            preview,
            preview_encoding,
            content_class,

            ..Default::default()
        },
        raw: capture.bytes,
    }
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
    /// Raw uprobe records drained from perf buffers, before decode.
    raw_drained: u64,
    /// Records the kernel reported lost to ring-buffer overflow.
    perf_lost: u64,
    /// Hits `decode_hit` turned into outputs.
    decoded_hits: u64,
    /// TlsSslRead funnel (entry stash / uret attempt / plaintext ok / uret miss).
    ssl_read_entry: u64,
    ssl_read_ret: u64,
    ssl_read_ok: u64,
    ssl_read_fail: u64,
    /// uretprobe with signed retval < 0 (typically SSL_ERROR_WANT_READ/WRITE).
    ssl_read_want: u64,
    /// uretprobe with signed retval > 0 (success byte-count / *_ex success).
    ssl_read_ret_gt0: u64,
    /// ret>0 but decode_hit returned None (filter/pending/zero/length miss).
    ssl_read_drop_gt0: u64,
    /// Split by mapped library path (babassl libopenssl vs conscrypt/other).
    ssl_read_want_openssl: u64,
    ssl_read_want_conscrypt: u64,
    ssl_read_ok_openssl: u64,
    ssl_read_ok_conscrypt: u64,
    ssl_read_ret_gt0_openssl: u64,
    ssl_read_ret_gt0_conscrypt: u64,
    /// Last lazy-TLS-exporter rescan time.
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    last_tls_rescan: Option<Instant>,
    /// Completed TLS exporter rescans.
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    tls_rescans: u32,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    hits_by_adapter: HashMap<String, u32>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    per_adapter_budget: bool,
    expired: bool,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    sessions: Vec<LiveProbe>,
    /// Last attach attempt per concrete adapter/library/program. Permanent ABI
    /// failures are throttled while transient failures can still recover.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    attach_attempts: HashMap<String, Instant>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    tls_pending: PendingCallStacks,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    jni_region_pending: HashMap<u32, PendingSslRead>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    jni_pair: JniPairPending,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    binder_pending: BinderPending,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    binder_dex_cache: crate::binder_dex::ProcessDexAidlCache,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    scoped_tgids: Vec<u32>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    delay_notice_emitted: bool,
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

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct PendingJniLen {
    obj: u64,
    len: i32,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct JniPairPending {
    array_len_obj: HashMap<u32, u64>,
    array_len: HashMap<u32, PendingJniLen>,
    string_len_obj: HashMap<u32, u64>,
    string_len: HashMap<u32, PendingJniLen>,
    u16_len_obj: HashMap<u32, u64>,
    u16_len: HashMap<u32, PendingJniLen>,
    elements_obj: HashMap<u32, u64>,
    char_elements_obj: HashMap<u32, u64>,
    utfchars_obj: HashMap<u32, u64>,
    u16chars_obj: HashMap<u32, u64>,
    utf_region: HashMap<u32, PendingSslRead>,
    u16_region: HashMap<u32, PendingSslRead>,
    direct_obj: HashMap<u32, u64>,
    direct_cap_obj: HashMap<u32, u64>,
    direct_cap: HashMap<u32, PendingJniLen>,
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn take_paired_len(pending: &mut HashMap<u32, PendingJniLen>, tid: u32, obj: u64) -> Option<i32> {
    pending
        .remove(&tid)
        .and_then(|pair| (pair.obj == obj && pair.len > 0).then_some(pair.len))
}

#[derive(Debug)]
struct PendingSslRead {
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    pid: u32,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    buf: u64,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    requested: i32,
    /// Out-parameter (`size_t *written` / `*readbytes`) for `_ex` / `_ex2`.
    /// Plain `SSL_read` / `SSL_write` use the function return value in x0.
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    written_ptr: Option<u64>,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    connection_id: Option<u64>,
}

/// Unified send/recv pending key: process + tid + library + offset + ABI.
/// Nesting is the stack depth for that key, not a separate map.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ProbeCallKey {
    pid: u32,
    tid: u32,
    lib_token: u64,
    offset: u64,
    abi: u8,
}

/// Entry frames older than this are stale (timeout). Never decoded as success.
const PENDING_STALE: Duration = Duration::from_secs(8);

#[derive(Debug, Default)]
struct PendingCallStacks {
    stacks: HashMap<ProbeCallKey, Vec<(Instant, PendingSslRead)>>,
    frames: usize,
    /// Frames dropped as incomplete (timeout / thread-exit / depth / session).
    incomplete: usize,
}

impl PendingCallStacks {
    fn mark_incomplete(&mut self, n: usize) {
        self.incomplete = self.incomplete.saturating_add(n);
        self.frames = self.frames.saturating_sub(n);
    }

    fn push(&mut self, key: ProbeCallKey, frame: PendingSslRead) {
        if self.frames >= 4096 {
            // Depth / session overflow: drop without synthesizing a successful send.
            self.incomplete = self.incomplete.saturating_add(1);
            return;
        }
        let stack = self.stacks.entry(key).or_default();
        if stack.len() >= 8 {
            // Overflow oldest frame as incomplete — do not decode as success.
            stack.remove(0);
            self.incomplete = self.incomplete.saturating_add(1);
            self.frames = self.frames.saturating_sub(1);
        }
        stack.push((Instant::now(), frame));
        self.frames = self.frames.saturating_add(1);
    }

    fn pop(&mut self, key: ProbeCallKey) -> Option<PendingSslRead> {
        let stack = self.stacks.get_mut(&key)?;
        let frame = stack.pop().map(|(_, frame)| frame);
        if frame.is_some() {
            self.frames = self.frames.saturating_sub(1);
        }
        if stack.is_empty() {
            self.stacks.remove(&key);
        }
        frame
    }

    /// Timeout / idle: drop aged frames as incomplete, never as success.
    fn drop_stale(&mut self, max_age: Duration) -> usize {
        let now = Instant::now();
        let mut dropped: usize = 0;
        self.stacks.retain(|_, stack| {
            let before = stack.len();
            stack.retain(|(seen, _)| now.saturating_duration_since(*seen) <= max_age);
            let lost = before.saturating_sub(stack.len());
            dropped = dropped.saturating_add(lost);
            !stack.is_empty()
        });
        self.mark_incomplete(dropped);
        dropped
    }

    /// Thread-exit: drop every pending frame for this pid/tid as incomplete.
    fn drop_tid(&mut self, pid: u32, tid: u32) -> usize {
        let mut dropped: usize = 0;
        self.stacks.retain(|key, stack| {
            if key.pid == pid && key.tid == tid {
                dropped = dropped.saturating_add(stack.len());
                return false;
            }
            true
        });
        self.mark_incomplete(dropped);
        dropped
    }

    /// Session-end: remaining frames are incomplete, not successful sends.
    fn drop_all_incomplete(&mut self) -> usize {
        let n = self.frames;
        self.incomplete = self.incomplete.saturating_add(n);
        self.stacks.clear();
        self.frames = 0;
        n
    }

    #[cfg(test)]
    fn age_all(&mut self, age: Duration) {
        let seen = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        for stack in self.stacks.values_mut() {
            for (stamp, _) in stack.iter_mut() {
                *stamp = seen;
            }
        }
    }
}

fn lib_token(plan: &InspectPlan) -> u64 {
    let raw = plan
        .build_id
        .as_deref()
        .or(plan.elf_path.as_deref())
        .unwrap_or("");
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn probe_call_key(plan: &InspectPlan, pid: u32, tid: u32) -> ProbeCallKey {
    ProbeCallKey {
        pid,
        tid,
        lib_token: lib_token(plan),
        offset: plan.offset.unwrap_or(0),
        abi: tls_abi_for_plan(plan) as u8,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn pending_from_entry(
    plan: &InspectPlan,
    hit: &ksight_hwbp::RegisterContext,
    pid: u32,
) -> Option<PendingSslRead> {
    let layout = effective_layout(plan);
    let buf = *hit.regs.get(usize::from(layout.buffer_arg))?;
    if !plausible_user_ptr(buf) {
        return None;
    }
    let requested = i32::try_from(
        *hit.regs
            .get(usize::from(layout.requested_len_arg))
            .unwrap_or(&0) as i64,
    )
    .unwrap_or(0);
    let written_ptr = layout.out_len_arg.and_then(|reg| {
        hit.regs
            .get(usize::from(reg))
            .copied()
            .filter(|ptr| *ptr >= 0x1000)
    });
    Some(PendingSslRead {
        pid,
        buf,
        requested: requested.max(0),
        written_ptr,
        connection_id: hit.regs.get(usize::from(layout.connection_arg)).copied(),
    })
}

fn tls_abi_for_plan(plan: &InspectPlan) -> ksight_core::TlsAbiKind {
    if let Some(abi) = plan.abi {
        return abi;
    }
    if let Some(name) = plan.symbol.as_deref() {
        let abi = ksight_core::TlsAbiKind::from_exported_symbol(name);
        // Do not collapse non-standard names to a fake attachable ABI here;
        // callers that need attach already required ProbeSpec.abi.
        return abi;
    }
    match plan.adapter {
        InspectAdapterKind::TlsSslRead => ksight_core::TlsAbiKind::OpensslRead,
        _ => ksight_core::TlsAbiKind::OpensslWrite,
    }
}

/// ABI layout with ProbeSpec / plaintext_probe field overrides applied.
fn effective_layout(plan: &InspectPlan) -> ksight_core::TlsAbiLayout {
    let mut layout = tls_abi_for_plan(plan).layout();
    let hint = &plan.layout_hint;
    if let Some(phase) = hint.capture_phase {
        layout.capture_phase = phase;
    }
    if let Some(arg) = hint.buffer_arg {
        layout.buffer_arg = arg;
    }
    if let Some(arg) = hint.requested_length_arg {
        layout.requested_len_arg = arg;
    }
    if let Some(source) = hint.actual_length_source {
        layout.actual_len_source = source;
        layout.out_len_arg = match source {
            ksight_core::ActualLengthSource::OutPtr => layout.out_len_arg.or(Some(3)),
            _ => None,
        };
    }
    if let Some(arg) = hint.connection_arg {
        layout.connection_arg = arg;
    }
    layout
}

fn plan_needs_uretprobe(plan: &InspectPlan) -> bool {
    matches!(
        effective_layout(plan).capture_phase,
        ksight_core::CapturePhase::Return | ksight_core::CapturePhase::EntryAndReturn
    )
}

fn plan_max_payload(plan: &InspectPlan, policy_max: usize) -> usize {
    let clamped = plan
        .layout_hint
        .max_bytes
        .map(|n| usize::try_from(n).unwrap_or(policy_max))
        .map(|n| n.clamp(1, policy_max))
        .unwrap_or(policy_max);
    clamped.max(1)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
struct LiveProbe {
    plan: InspectPlan,
    session: ksight_hwbp::UprobeSession,
    retprobe: bool,
    /// Entry+uretprobe share one BPF object (`entry_ptr` visible on return).
    /// Classify each hit with `hit.snapshot_at_return` instead of `retprobe`.
    paired_entry_return: bool,
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
    #[allow(clippy::too_many_lines)]
    pub fn prepare_all(
        policy: &InspectPolicy,
        adapters: &[InspectAdapterKind],
        uprobe_object: &Path,
    ) -> Self {
        let mut selected_adapters: Vec<InspectAdapterKind> = if adapters.is_empty() {
            vec![InspectAdapterKind::LinkerSoLoad]
        } else {
            adapters.to_vec()
        };
        // Lazy TLS rescan only walks `selected_adapters`. Companions such as
        // TlsSslRead used to be plan-only (evaluated once at prepare), so a
        // BABASSL `libopenssl.so` that maps after attach discovered SSL_write
        // but never SSL_read. Promote TLS companions into the selected set.
        let mut companion_tail = Vec::new();
        for adapter in &selected_adapters {
            for companion in adapter.companions() {
                if companion.is_tls()
                    && !selected_adapters.contains(companion)
                    && !companion_tail.contains(companion)
                {
                    companion_tail.push(*companion);
                }
            }
        }
        selected_adapters.extend(companion_tail);
        let mut policy = policy.clone();
        let per_adapter_budget = policy.max_hits == 0;
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
            } else if adapter.is_jni() {
                plans.extend(InspectPlan::evaluate_jni_exports(
                    policy.clone(),
                    *adapter,
                    uprobe_object.clone(),
                ));
            } else if adapter.is_tls() {
                plans.extend(InspectPlan::evaluate_tls_exports(
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
                // Already first-class in selected_adapters (TLS companions) or
                // explicitly selected — evaluated by the outer loop.
                if selected_adapters.contains(companion) {
                    continue;
                }
                if companion.is_tls() {
                    plans.extend(InspectPlan::evaluate_tls_exports(
                        policy.clone(),
                        *companion,
                        uprobe_object.clone(),
                    ));
                } else {
                    plans.extend(InspectPlan::evaluate(
                        policy.clone(),
                        *companion,
                        uprobe_object.clone(),
                    ));
                }
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
        prune_redundant_elf32_jni(&mut plans);
        Self {
            plans,
            selected_adapters,
            started: Instant::now(),
            max_duration,
            max_hits,
            hits: 0,
            raw_drained: 0,
            perf_lost: 0,
            decoded_hits: 0,
            ssl_read_entry: 0,
            ssl_read_ret: 0,
            ssl_read_ok: 0,
            ssl_read_fail: 0,
            ssl_read_want: 0,
            ssl_read_ret_gt0: 0,
            ssl_read_drop_gt0: 0,
            ssl_read_want_openssl: 0,
            ssl_read_want_conscrypt: 0,
            ssl_read_ok_openssl: 0,
            ssl_read_ok_conscrypt: 0,
            ssl_read_ret_gt0_openssl: 0,
            ssl_read_ret_gt0_conscrypt: 0,
            last_tls_rescan: None,
            tls_rescans: 0,
            hits_by_adapter: HashMap::new(),
            per_adapter_budget,
            expired: false,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            sessions: Vec::new(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            attach_attempts: HashMap::new(),
            tls_pending: PendingCallStacks::default(),
            jni_region_pending: HashMap::new(),
            jni_pair: JniPairPending::default(),
            binder_pending: BinderPending::default(),
            binder_dex_cache: crate::binder_dex::ProcessDexAidlCache::default(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            scoped_tgids: Vec::new(),
            delay_notice_emitted: false,
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

    /// Attach TLS exporters that mapped after the first attach pass.
    ///
    /// Vendor stacks are dlopened lazily (ttboringssl appears only when the
    /// SDK initializes), so the once-at-start sweep misses them. Re-evaluate
    /// the TLS plans on a throttle and attach unseen (library, offset) pairs.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn rescan_tls_exports_maybe(&mut self) -> Vec<InspectObservation> {
        if !self
            .selected_adapters
            .iter()
            .any(|adapter| adapter.is_tls())
        {
            return Vec::new();
        }
        let interval = if self.tls_rescans < TLS_BURST_RESCANS {
            TLS_BURST_RESCAN_INTERVAL
        } else {
            TLS_STEADY_RESCAN_INTERVAL
        };
        if self
            .last_tls_rescan
            .is_some_and(|at| at.elapsed() < interval)
        {
            return Vec::new();
        }
        self.last_tls_rescan = Some(Instant::now());
        self.tls_rescans = self.tls_rescans.saturating_add(1);
        let Some(first) = self.plans.first() else {
            return Vec::new();
        };
        let policy = first.policy.clone();
        let uprobe_object = first.uprobe_object.clone();
        let known: std::collections::BTreeSet<(String, String, Option<u64>, String)> = self
            .plans
            .iter()
            .map(|plan| {
                (
                    plan.adapter.as_str().to_owned(),
                    plan.elf_path.clone().unwrap_or_default(),
                    plan.offset,
                    plan.symbol.clone().unwrap_or_default(),
                )
            })
            .collect();
        let mut fresh = Vec::new();
        let mut observations = Vec::new();
        // Walk selected TLS adapters plus any TLS companions still hanging off
        // a selected parent (belt-and-suspenders if expansion was skipped).
        let mut rescan_adapters = Vec::new();
        for adapter in &self.selected_adapters {
            if adapter.is_tls() && !rescan_adapters.contains(adapter) {
                rescan_adapters.push(*adapter);
            }
            for companion in adapter.companions() {
                if companion.is_tls() && !rescan_adapters.contains(companion) {
                    rescan_adapters.push(*companion);
                }
            }
        }
        for adapter in &rescan_adapters {
            for plan in
                InspectPlan::evaluate_tls_exports(policy.clone(), *adapter, uprobe_object.clone())
            {
                let key = (
                    plan.adapter.as_str().to_owned(),
                    plan.elf_path.clone().unwrap_or_default(),
                    plan.offset,
                    plan.symbol.clone().unwrap_or_default(),
                );
                if known.contains(&key)
                    || fresh.iter().any(|item: &InspectPlan| {
                        (
                            item.adapter.as_str().to_owned(),
                            item.elf_path.clone().unwrap_or_default(),
                            item.offset,
                            item.symbol.clone().unwrap_or_default(),
                        ) == key
                    })
                {
                    continue;
                }
                fresh.push(plan);
            }
        }
        if fresh.is_empty() {
            return Vec::new();
        }
        prune_redundant_elf32_tls(&mut fresh);
        for plan in &fresh {
            let mut observation = plan.observation.clone();
            observation.detail = format!(
                "lazy-mapped TLS candidate discovered on rescan {}: {}",
                self.tls_rescans, plan.observation.detail
            );
            observations.push(observation);
        }
        self.plans.extend(fresh);
        observations.extend(attach_all(self));
        observations
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    #[allow(dead_code, unused_variables, clippy::unused_self)]
    fn rescan_tls_exports_maybe(&mut self) -> Vec<InspectObservation> {
        Vec::new()
    }

    /// Attach after a package-scoped process has survived packer init.
    ///
    /// Some packer helpers SIGSEGV at ~2s if `libart` JNI uprobes are already
    /// patched on cold start. Wait until a matching TGID is at least
    /// [`PACKER_ATTACH_GRACE`] old, then attach. Already-running apps attach
    /// immediately. Whole-device inspect is unchanged.
    pub fn attach_when_safe(&mut self) -> Vec<InspectObservation> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if self.expired {
                return Vec::new();
            }
            let mut observations = self.rescan_tls_exports_maybe();
            if !self.sessions.is_empty() {
                // Successful probes are skipped by identity; failed probes are
                // retried on their throttle so one live Conscrypt probe does
                // not permanently suppress a later vendor-stack recovery.
                observations.extend(attach_all(self));
                return observations;
            }
            // Audited stub plans (classification-only) do not patch ART; the
            // grace is only required when an ART-patching probe is selected.
            let art_patching_selected = self.selected_adapters.iter().any(|adapter| {
                matches!(
                    adapter,
                    InspectAdapterKind::JniPlaintext
                        | InspectAdapterKind::JniNewString
                        | InspectAdapterKind::JniGetStringUtfChars
                        | InspectAdapterKind::JniGetStringUtfLength
                        | InspectAdapterKind::JniGetStringUtfRegion
                        | InspectAdapterKind::JniGetArrayLength
                        | InspectAdapterKind::JniGetByteArrayElements
                        | InspectAdapterKind::JniGetByteArrayRegion
                        | InspectAdapterKind::JniSetByteArrayRegion
                        | InspectAdapterKind::JniRegistration
                )
            });
            if art_patching_selected && !inspect_target_survived_packer(&self.plans) {
                // The packer grace protects ART-patching probes (JNI) from
                // packed-process init crashes. TLS uprobes live on libssl and
                // never touch ART, so they attach immediately — the launch
                // burst is exactly the traffic a mirror session must not miss.
                if !self.delay_notice_emitted {
                    self.delay_notice_emitted = true;
                    eprintln!(
                        "inspect waiting for package process to stay up >= {}s (packer init)",
                        PACKER_ATTACH_GRACE.as_secs()
                    );
                }
                return Vec::new();
            }
            observations.extend(attach_all(self));
            observations
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            Vec::new()
        }
    }

    /// Poll authorized hits.
    pub fn poll(&mut self) -> Vec<InspectOutput> {
        if self.expired {
            return Vec::new();
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        refresh_package_tgids(self);
        poll_all(self)
    }

    /// Layered counters for loss analysis: (raw drained, decoded, perf lost).
    pub fn drain_totals(&self) -> (u64, u64, u64) {
        (self.raw_drained, self.decoded_hits, self.perf_lost)
    }

    /// TlsSslRead funnel: (entry, uret, plaintext_ok, uret_fail, want_read_or_neg).
    pub fn ssl_read_funnel(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.ssl_read_entry,
            self.ssl_read_ret,
            self.ssl_read_ok,
            self.ssl_read_fail,
            self.ssl_read_want,
        )
    }

    /// Extended ssl_read split: (ret_gt0, drop_gt0, want_openssl, want_conscrypt,
    /// ok_openssl, ok_conscrypt, gt0_openssl, gt0_conscrypt).
    pub fn ssl_read_funnel_ex(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            self.ssl_read_ret_gt0,
            self.ssl_read_drop_gt0,
            self.ssl_read_want_openssl,
            self.ssl_read_want_conscrypt,
            self.ssl_read_ok_openssl,
            self.ssl_read_ok_conscrypt,
            self.ssl_read_ret_gt0_openssl,
            self.ssl_read_ret_gt0_conscrypt,
        )
    }

    /// Revoke unused probes after the authorized window or hit budget.
    pub fn expire_if_needed(&mut self) -> Option<InspectObservation> {
        let over_time = self.started.elapsed() >= self.max_duration;
        let over_hits = inspect_budget_exhausted(self);
        if self.expired || (!over_time && !over_hits) {
            return None;
        }
        self.expired = true;
        self.tls_pending.drop_all_incomplete();
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
    if adapter.is_jni() {
        "JNIEnv plaintext/RegisterNatives are not dynsym names; resolve JNINativeInterface from exported art::JNIEnvExt::GetFunctionTable using jni.h slots (no ART object offsets). Table was not found in this ELF."
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
                    let found = if adapter.is_tls() {
                        crate::elf::symbol_match_exact(&elf, adapter.symbols())
                    } else {
                        symbol_match(&elf, adapter.symbols())
                    };
                    found.map(|(name, offset)| (name.to_owned(), offset))
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

fn tls_exact_names(adapter: InspectAdapterKind) -> Vec<String> {
    let mut names: Vec<String> = adapter
        .symbols()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    for name in ksight_core::tls_symbol_names() {
        if !ksight_core::is_tls_application_data_export(&name) {
            continue;
        }
        let abi = ksight_core::TlsAbiKind::from_exported_symbol(&name);
        if !abi.is_auto_attachable() {
            continue;
        }
        let keep = match adapter {
            InspectAdapterKind::TlsSslWrite => abi.direction() == ksight_core::TlsDirection::Send,
            InspectAdapterKind::TlsSslRead => abi.direction() == ksight_core::TlsDirection::Recv,
            _ => false,
        };
        if keep && !names.iter().any(|existing| existing == &name) {
            names.push(name);
        }
    }
    names
}

fn evaluate_plaintext_probe_plans(
    policy: &InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: &Path,
    elf_path: &str,
) -> Vec<InspectPlan> {
    let size = std::fs::metadata(elf_path).ok().map(|meta| meta.len());
    let elf = inspect_elf(elf_path).ok();
    let build_id = elf.as_ref().and_then(|item| item.build_id.clone());
    let mut plans = Vec::new();
    for (stack_id, probe) in ksight_core::enabled_plaintext_probes() {
        let Some(offset) = probe.file_offset else {
            continue;
        };
        if let Some(wanted) = probe.build_id.as_deref() {
            if build_id.as_deref() != Some(wanted) {
                continue;
            }
        }
        if let Some(wanted) = probe.size {
            if size != Some(wanted) {
                continue;
            }
        }
        if let Some(arch) = probe.architecture.as_deref() {
            let arch = arch.to_ascii_lowercase();
            let bits = elf.as_ref().map(|item| item.bits).unwrap_or(64);
            let arch_ok = match arch.as_str() {
                "arm64" | "aarch64" | "arm64-v8a" => bits == 64,
                "arm" | "armeabi" | "armeabi-v7a" | "arm32" => bits == 32,
                _ => true,
            };
            if !arch_ok {
                continue;
            }
        }
        let want_adapter = match probe.direction {
            ksight_core::TlsDirection::Send => InspectAdapterKind::TlsSslWrite,
            ksight_core::TlsDirection::Recv => InspectAdapterKind::TlsSslRead,
        };
        if want_adapter != adapter {
            continue;
        }
        if ksight_core::stack_for_path(elf_path, size, build_id.as_deref())
            .is_none_or(|stack| stack.id != stack_id)
            && probe.build_id.is_none()
        {
            continue;
        }
        let mut observation = InspectObservation {
            adapter: adapter.as_str().to_owned(),
            library: elf_path.to_owned(),
            build_id: build_id.clone(),
            offset: Some(offset),
            detectability_notice: policy.detectability_notice.clone(),
            ..InspectObservation::default()
        };
        observation.detail = format!(
            "ready to attach {} plaintext_probe stack={stack_id} offset={offset:#x} abi={} phase={:?} buffer_arg={:?} max_bytes={:?}",
            adapter.as_str(),
            probe.abi.as_str(),
            probe.capture_phase,
            probe.buffer_arg,
            probe.max_bytes
        );
        if let Some(sample) = probe.sample_sha256.as_deref() {
            let _ = write!(observation.detail, " sample_sha256={sample}");
        }
        plans.push(InspectPlan {
            policy: policy.clone(),
            adapter,
            uprobe_object: uprobe_object.to_path_buf(),
            elf_path: Some(elf_path.to_owned()),
            offset: Some(offset),
            build_id: build_id.clone(),
            symbol: Some(format!("plaintext_probe:{stack_id}")),
            abi: Some(probe.abi),
            layout_hint: ProbeLayoutHint {
                capture_phase: probe.capture_phase,
                buffer_arg: probe.buffer_arg,
                requested_length_arg: probe.requested_length_arg,
                actual_length_source: probe
                    .actual_length_source
                    .as_deref()
                    .and_then(ksight_core::ActualLengthSource::parse_label),
                connection_arg: None,
                max_bytes: probe.max_bytes,
                architecture: probe.architecture.clone(),
                sample_sha256: probe.sample_sha256.clone(),
            },
            pointer_width: elf.as_ref().map_or(8, |item| (item.bits / 8).max(4)),
            observation,
        });
    }
    plans
}

fn evaluate_tls_symbol_exports(
    policy: &InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: &Path,
    elf_path: &str,
) -> Option<Vec<InspectPlan>> {
    let size = std::fs::metadata(elf_path).ok().map(|meta| meta.len());
    if !ksight_core::ssl_write_attach_allowed(elf_path, size, None) {
        // Size/build-id gap pins (stripped libssl, Flutter generic, XQUIC)
        // must not fall through to evaluate_one / invented offsets.
        return Some(Vec::new());
    }
    let elf = inspect_elf(elf_path).ok()?;
    if !ksight_core::ssl_write_attach_allowed(elf_path, size, elf.build_id.as_deref()) {
        return Some(Vec::new());
    }
    if let Some(required) = policy.build_id.as_deref() {
        match elf.build_id.as_deref() {
            Some(actual) if actual == required => {}
            _ => return None,
        }
    }

    let mut plans = Vec::new();
    let mut seen_offsets = std::collections::BTreeSet::new();

    // Prefer matched ProbeSpec plans (explicit abi / buffer_arg / file_offset).
    for (stack_id, probe) in
        ksight_core::probe_specs_for_path(elf_path, size, elf.build_id.as_deref())
    {
        if let Some(plan) = inspect_plan_from_probe_spec(
            policy,
            adapter,
            uprobe_object,
            elf_path,
            &elf,
            &stack_id,
            &probe,
        ) {
            if let Some(offset) = plan.offset {
                seen_offsets.insert(offset);
            }
            plans.push(plan);
        }
    }

    let names = tls_exact_names(adapter);
    let matched = matching_symbols_exact(&elf, &names);
    for (name, offset) in matched.into_iter().take(8) {
        if seen_offsets.contains(&offset) {
            continue;
        }
        let abi = ksight_core::TlsAbiKind::from_exported_symbol(name);
        if !abi.is_auto_attachable() {
            // Non-standard name without ProbeSpec.abi: candidate only.
            continue;
        }
        let want = match adapter {
            InspectAdapterKind::TlsSslWrite => ksight_core::TlsDirection::Send,
            InspectAdapterKind::TlsSslRead => ksight_core::TlsDirection::Recv,
            _ => continue,
        };
        if abi.direction() != want {
            continue;
        }
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
        seen_offsets.insert(offset);
        plans.push(InspectPlan {
            policy: policy.clone(),
            adapter,
            uprobe_object: uprobe_object.to_path_buf(),
            elf_path: Some(elf_path.to_owned()),
            offset: Some(offset),
            build_id: elf.build_id.clone(),
            symbol: Some(name.to_owned()),
            abi: Some(abi),
            layout_hint: ProbeLayoutHint::default(),
            pointer_width: (elf.bits / 8).max(4),
            observation,
        });
    }

    if plans.is_empty() {
        None
    } else {
        Some(plans)
    }
}

fn inspect_plan_from_probe_spec(
    policy: &InspectPolicy,
    adapter: InspectAdapterKind,
    uprobe_object: &Path,
    elf_path: &str,
    elf: &crate::elf::ElfIdentity,
    stack_id: &str,
    probe: &ksight_core::ProbeSpec,
) -> Option<InspectPlan> {
    let abi = probe
        .abi
        .unwrap_or_else(|| ksight_core::TlsAbiKind::from_exported_symbol(&probe.symbol));
    // Non-standard names require an explicit ProbeSpec.abi before attach.
    if probe.abi.is_none() && !abi.is_auto_attachable() {
        return None;
    }
    let direction = probe.direction.unwrap_or_else(|| abi.direction());
    let want_adapter = match direction {
        ksight_core::TlsDirection::Send => InspectAdapterKind::TlsSslWrite,
        ksight_core::TlsDirection::Recv => InspectAdapterKind::TlsSslRead,
    };
    if want_adapter != adapter {
        return None;
    }
    if let Some(arch) = probe.architecture.as_deref() {
        let arch = arch.to_ascii_lowercase();
        let arch_ok = match arch.as_str() {
            "arm64" | "aarch64" | "arm64-v8a" => elf.bits == 64,
            "arm" | "armeabi" | "armeabi-v7a" | "arm32" => elf.bits == 32,
            _ => true,
        };
        if !arch_ok {
            return None;
        }
    }
    let offset = if let Some(file_offset) = probe.file_offset {
        file_offset
    } else if !probe.symbol.is_empty() {
        matching_symbols_exact(elf, &[probe.symbol.as_str()])
            .into_iter()
            .next()
            .map(|(_, offset)| offset)?
    } else {
        return None;
    };
    let mut observation = InspectObservation {
        adapter: adapter.as_str().to_owned(),
        library: elf_path.to_owned(),
        build_id: elf.build_id.clone(),
        offset: Some(offset),
        detectability_notice: policy.detectability_notice.clone(),
        ..InspectObservation::default()
    };
    observation.detail = format!(
        "ready to attach {} ProbeSpec stack={stack_id} symbol={} offset={offset:#x} abi={} buffer_arg={:?}",
        adapter.as_str(),
        probe.symbol,
        abi.as_str(),
        probe.buffer_arg
    );
    if !Path::new(uprobe_object).is_file() {
        let _ = write!(
            observation.detail,
            "; uprobe object missing: {}",
            uprobe_object.display()
        );
    }
    Some(InspectPlan {
        policy: policy.clone(),
        adapter,
        uprobe_object: uprobe_object.to_path_buf(),
        elf_path: Some(elf_path.to_owned()),
        offset: Some(offset),
        build_id: elf.build_id.clone(),
        symbol: Some(if probe.symbol.is_empty() {
            format!("probe_spec:{stack_id}")
        } else {
            probe.symbol.clone()
        }),
        abi: Some(abi),
        layout_hint: ProbeLayoutHint {
            capture_phase: probe.capture_phase,
            buffer_arg: probe.buffer_arg,
            requested_length_arg: probe.requested_length_arg,
            actual_length_source: probe
                .actual_length_source
                .as_deref()
                .and_then(ksight_core::ActualLengthSource::parse_label),
            connection_arg: probe.connection_arg,
            max_bytes: None,
            architecture: probe.architecture.clone(),
            sample_sha256: None,
        },
        pointer_width: (elf.bits / 8).max(4),
        observation,
    })
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
                    abi: None,
                    layout_hint: ProbeLayoutHint::default(),
                    pointer_width: (elf.bits / 8).max(4),
                    observation,
                }
            })
            .collect(),
    )
}

fn jni_wanted_slots(adapter: InspectAdapterKind) -> &'static [(&'static str, usize)] {
    match adapter {
        InspectAdapterKind::JniPlaintext => &crate::jni_env::JNI_PLAINTEXT_SLOTS,
        InspectAdapterKind::JniNewStringUtf => {
            &[("NewStringUTF", crate::jni_env::SLOT_NEW_STRING_UTF)]
        }
        InspectAdapterKind::JniGetStringUtfChars => &[(
            "GetStringUTFChars",
            crate::jni_env::SLOT_GET_STRING_UTF_CHARS,
        )],
        InspectAdapterKind::JniGetStringUtfLength => &[(
            "GetStringUTFLength",
            crate::jni_env::SLOT_GET_STRING_UTF_LENGTH,
        )],
        InspectAdapterKind::JniGetStringUtfRegion => &[(
            "GetStringUTFRegion",
            crate::jni_env::SLOT_GET_STRING_UTF_REGION,
        )],
        InspectAdapterKind::JniGetArrayLength => {
            &[("GetArrayLength", crate::jni_env::SLOT_GET_ARRAY_LENGTH)]
        }
        InspectAdapterKind::JniGetByteArrayElements => &[(
            "GetByteArrayElements",
            crate::jni_env::SLOT_GET_BYTE_ARRAY_ELEMENTS,
        )],
        InspectAdapterKind::JniGetByteArrayRegion => &[(
            "GetByteArrayRegion",
            crate::jni_env::SLOT_GET_BYTE_ARRAY_REGION,
        )],
        InspectAdapterKind::JniSetByteArrayRegion => &[(
            "SetByteArrayRegion",
            crate::jni_env::SLOT_SET_BYTE_ARRAY_REGION,
        )],
        InspectAdapterKind::JniRegistration => {
            &[("RegisterNatives", crate::jni_env::SLOT_REGISTER_NATIVES)]
        }
        InspectAdapterKind::JniNewString => &[("NewString", crate::jni_env::SLOT_NEW_STRING)],
        InspectAdapterKind::JniGetStringLength => {
            &[("GetStringLength", crate::jni_env::SLOT_GET_STRING_LENGTH)]
        }
        InspectAdapterKind::JniGetStringChars => {
            &[("GetStringChars", crate::jni_env::SLOT_GET_STRING_CHARS)]
        }
        InspectAdapterKind::JniGetStringRegion => {
            &[("GetStringRegion", crate::jni_env::SLOT_GET_STRING_REGION)]
        }
        InspectAdapterKind::JniGetStringCritical => &[(
            "GetStringCritical",
            crate::jni_env::SLOT_GET_STRING_CRITICAL,
        )],
        InspectAdapterKind::JniGetCharArrayElements => &[(
            "GetCharArrayElements",
            crate::jni_env::SLOT_GET_CHAR_ARRAY_ELEMENTS,
        )],
        InspectAdapterKind::JniGetCharArrayRegion => &[(
            "GetCharArrayRegion",
            crate::jni_env::SLOT_GET_CHAR_ARRAY_REGION,
        )],
        InspectAdapterKind::JniSetCharArrayRegion => &[(
            "SetCharArrayRegion",
            crate::jni_env::SLOT_SET_CHAR_ARRAY_REGION,
        )],
        InspectAdapterKind::JniGetPrimitiveArrayCritical => &[(
            "GetPrimitiveArrayCritical",
            crate::jni_env::SLOT_GET_PRIMITIVE_ARRAY_CRITICAL,
        )],
        InspectAdapterKind::JniGetDirectBufferAddress => &[(
            "GetDirectBufferAddress",
            crate::jni_env::SLOT_GET_DIRECT_BUFFER_ADDRESS,
        )],
        InspectAdapterKind::JniGetDirectBufferCapacity => &[(
            "GetDirectBufferCapacity",
            crate::jni_env::SLOT_GET_DIRECT_BUFFER_CAPACITY,
        )],
        _ => &[],
    }
}

fn jni_adapter_for_slot(name: &str) -> InspectAdapterKind {
    match name {
        "NewStringUTF" => InspectAdapterKind::JniNewStringUtf,
        "GetStringUTFChars" => InspectAdapterKind::JniGetStringUtfChars,
        "GetStringUTFLength" => InspectAdapterKind::JniGetStringUtfLength,
        "GetStringUTFRegion" => InspectAdapterKind::JniGetStringUtfRegion,
        "GetArrayLength" => InspectAdapterKind::JniGetArrayLength,
        "GetByteArrayElements" => InspectAdapterKind::JniGetByteArrayElements,
        "GetByteArrayRegion" => InspectAdapterKind::JniGetByteArrayRegion,
        "SetByteArrayRegion" => InspectAdapterKind::JniSetByteArrayRegion,
        "RegisterNatives" => InspectAdapterKind::JniRegistration,
        "NewString" => InspectAdapterKind::JniNewString,
        "GetStringLength" => InspectAdapterKind::JniGetStringLength,
        "GetStringChars" => InspectAdapterKind::JniGetStringChars,
        "GetStringRegion" => InspectAdapterKind::JniGetStringRegion,
        "GetStringCritical" => InspectAdapterKind::JniGetStringCritical,
        "GetCharArrayElements" => InspectAdapterKind::JniGetCharArrayElements,
        "GetCharArrayRegion" => InspectAdapterKind::JniGetCharArrayRegion,
        "SetCharArrayRegion" => InspectAdapterKind::JniSetCharArrayRegion,
        "GetPrimitiveArrayCritical" => InspectAdapterKind::JniGetPrimitiveArrayCritical,
        "GetDirectBufferAddress" => InspectAdapterKind::JniGetDirectBufferAddress,
        "GetDirectBufferCapacity" => InspectAdapterKind::JniGetDirectBufferCapacity,
        _ => InspectAdapterKind::JniPlaintext,
    }
}

fn evaluate_jni_env_exports(
    policy: &InspectPolicy,
    _selected: InspectAdapterKind,
    uprobe_object: &Path,
    elf_path: &str,
    wanted: &[(&str, usize)],
) -> Option<Vec<InspectPlan>> {
    if wanted.is_empty() {
        return None;
    }
    let elf = crate::elf::inspect_elf(elf_path).ok()?;
    if let Some(required) = policy.build_id.as_deref() {
        match elf.build_id.as_deref() {
            Some(actual) if actual == required => {}
            _ => return None,
        }
    }
    let matched = crate::jni_env::resolve_jni_env_functions(elf_path, wanted).ok()?;
    if matched.is_empty() {
        return None;
    }
    Some(
        matched
            .into_iter()
            .take(JNI_ENV_ATTACH_CAP)
            .map(|function| {
                let adapter = jni_adapter_for_slot(function.name);
                let offset = function.offset;
                let mut observation = InspectObservation {
                    adapter: adapter.as_str().to_owned(),
                    library: elf_path.to_owned(),
                    build_id: elf.build_id.clone(),
                    offset: Some(offset),
                    detectability_notice: policy.detectability_notice.clone(),
                    ..InspectObservation::default()
                };
                observation.detail = format!(
                    "ready to attach {} uprobe JNINativeInterface::{} offset={offset:#x} (GetFunctionTable + jni.h slot)",
                    adapter.as_str(),
                    function.name
                );
                if !Path::new(uprobe_object).is_file() {
                    let _ = write!(
                        observation.detail,
                        "; uprobe object missing: {}",
                        uprobe_object.display()
                    );
                }
                InspectPlan {
                    policy: policy.clone(),
                    adapter,
                    uprobe_object: uprobe_object.to_path_buf(),
                    elf_path: Some(elf_path.to_owned()),
                    offset: Some(offset),
                    build_id: elf.build_id.clone(),
                    symbol: Some(function.name.to_owned()),
                    abi: None,
                    layout_hint: ProbeLayoutHint::default(),
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
        abi: None,
        layout_hint: ProbeLayoutHint::default(),
        pointer_width: 8,
        observation,
    }
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn adapter_is_live(selected: &[InspectAdapterKind], adapter: InspectAdapterKind) -> bool {
    selected.iter().any(|item| {
        *item == adapter
            || item.companions().contains(&adapter)
            || (*item == InspectAdapterKind::JniPlaintext
                && adapter.is_jni()
                && adapter != InspectAdapterKind::JniPlaintext)
    })
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn adapter_probe_programs_for_plan(plan: &InspectPlan) -> &'static [&'static str] {
    // Plain SSL_write must stay entry-only on Pixel GKI — dual uretprobe
    // correlated with raw_uprobe=0 (2026-09-10). Only *_ex needs return length.
    if plan.adapter == InspectAdapterKind::TlsSslWrite {
        return if plan_needs_uretprobe(plan) {
            &["ksight_uprobe_regs", "ksight_uretprobe_regs"]
        } else {
            &["ksight_uprobe_regs"]
        };
    }
    adapter_probe_programs(plan.adapter)
}

fn adapter_probe_programs(adapter: InspectAdapterKind) -> &'static [&'static str] {
    match adapter {
        // Keep plain SSL_write on entry-only uprobe (hit-proven before lunch quiet).
        // SSL_write_ex *written via uretprobe can return once entry hits are healthy.
        InspectAdapterKind::TlsSslRead
        | InspectAdapterKind::JniGetByteArrayRegion
        | InspectAdapterKind::JniGetStringUtfRegion
        | InspectAdapterKind::JniGetArrayLength
        | InspectAdapterKind::JniGetStringUtfLength
        | InspectAdapterKind::JniGetByteArrayElements
        | InspectAdapterKind::JniGetStringUtfChars
        | InspectAdapterKind::JniGetStringLength
        | InspectAdapterKind::JniGetStringChars
        | InspectAdapterKind::JniGetStringRegion
        | InspectAdapterKind::JniGetStringCritical
        | InspectAdapterKind::JniGetCharArrayElements
        | InspectAdapterKind::JniGetCharArrayRegion
        | InspectAdapterKind::JniGetPrimitiveArrayCritical
        | InspectAdapterKind::JniGetDirectBufferAddress
        | InspectAdapterKind::JniGetDirectBufferCapacity => {
            &["ksight_uprobe_regs", "ksight_uretprobe_regs"]
        }
        _ => &["ksight_uprobe_regs"],
    }
}

fn prune_redundant_elf32_jni(plans: &mut [InspectPlan]) {
    let has_elf64 = plans
        .iter()
        .any(|plan| plan.adapter.is_jni() && plan.pointer_width >= 8 && plan.offset.is_some());
    if !has_elf64 {
        return;
    }
    for plan in plans {
        if plan.adapter.is_jni() && plan.pointer_width == 4 {
            plan.offset = None;
            if !plan.observation.detail.contains("skipped ELF32 JNI") {
                plan.observation.detail.push_str(
                    "; skipped ELF32 libart on this arm64 GKI because an ELF64 JNINativeInterface table is available",
                );
            }
        }
    }
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
    // Name needles miss vendor forks that export the standard symbols under
    // arbitrary basenames (ttboringssl, slightssl builds, game SDKs). Sweep
    // every mapped ELF of the target once and keep real exporters.
    if adapter.is_tls() {
        if let Some(pids) = active_tgid_filter(policy) {
            for path in discover_mapped_libraries_by_tls_symbol(&pids, adapter) {
                found.insert(path);
            }
        }
    }
    let mut libs: Vec<String> = found.into_iter().collect();
    libs.sort_by(|left, right| {
        tls_attach_rank(left)
            .cmp(&tls_attach_rank(right))
            .then_with(|| left.cmp(right))
    });
    libs.truncate(TLS_LIBRARY_CANDIDATE_CAP);
    libs
}

fn tls_attach_rank(path: &str) -> u8 {
    let file = path.rsplit('/').next().unwrap_or(path);
    if file.contains("hssl") || file.contains("ttboringssl") {
        0
    } else if path.contains("/data/app/") {
        1
    } else if file.contains("cronet") {
        3
    } else {
        2
    }
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
        return file == "libssl.so" || file.ends_with("_libssl.so") || file == "libboringssl.so";
    }
    if needle == "libopenssl.so" {
        // BABASSL ships as libopenssl.so — not covered by libssl.so alias.
        return file == "libopenssl.so";
    }
    if needle == "libcurl.so" {
        return file == "libcurl.so";
    }
    if needle == "libflutter.so" {
        return file == "libflutter.so" || file.starts_with("libflutter.");
    }
    if needle == "mbedtls" {
        return file.contains("mbedtls") || file.contains("mbedcrypto");
    }
    if needle == "wolfssl" {
        return file.contains("wolfssl");
    }
    if needle == "gmssl" {
        return file.contains("gmssl") || file.contains("smcrypto");
    }
    if needle == "tassl" {
        return file.contains("tassl");
    }
    if needle == "hssl" {
        return file.contains("hssl");
    }
    if needle == "ttboringssl" {
        return file.contains("ttboringssl");
    }
    if needle == "boringssl" {
        // Match libttboringssl.so / libboringssl.so; avoid bare "ssl" false positives.
        return file.contains("boringssl");
    }
    if needle == "libtnet" {
        // Alibaba TNET / slightssl (e.g. libtnet-4.0.0.so). Symbol attach still
        // requires live dynsym exports — basename match alone does not invent offsets.
        return file.contains("libtnet");
    }
    if needle == "wework" {
        return file.contains("wework");
    }
    if needle == "libww" {
        return file.contains("libww");
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

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn discover_mapped_libraries_by_tls_symbol(
    _pids: &[u32],
    _adapter: InspectAdapterKind,
) -> Vec<String> {
    Vec::new()
}

/// Sweep every file-backed mapping of the target processes and keep ELFs that
/// export the adapter's exact TLS symbols, whatever their basename is.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn rank_inspect_pids(pids: &[u32]) -> Vec<u32> {
    let mut scored: Vec<(u32, u32)> = pids
        .iter()
        .copied()
        .map(|pid| {
            let mut score = 0_u32;
            let fd = format!("/proc/{pid}/fd");
            if let Ok(dir) = std::fs::read_dir(&fd) {
                for entry in dir.flatten().take(64) {
                    if let Ok(link) = std::fs::read_link(entry.path()) {
                        let target = link.to_string_lossy();
                        if target.starts_with("socket:") {
                            score = score.saturating_add(30);
                            break;
                        }
                    }
                }
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                if maps.contains("/data/app/") {
                    score = score.saturating_add(40);
                }
                if maps.lines().any(|line| {
                    line.contains(".so")
                        && ksight_core::stack_for_path(
                            line.split_whitespace().last().unwrap_or(""),
                            None,
                            None,
                        )
                        .is_some_and(|stack| stack.coverage.plaintext_copy)
                }) {
                    score = score.saturating_add(50);
                }
            }
            (score, pid)
        })
        .collect();
    scored.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    scored.into_iter().map(|(_, pid)| pid).collect()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[allow(clippy::too_many_lines)]
fn discover_mapped_libraries_by_tls_symbol(
    pids: &[u32],
    adapter: InspectAdapterKind,
) -> Vec<String> {
    let names = tls_exact_names(adapter);
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut exporters: Vec<String> = Vec::new();
    let ranked = rank_inspect_pids(pids);
    let pid_cap = 16;
    let skipped_pids = ranked.len().saturating_sub(pid_cap);
    let mut skipped_maps = 0_u32;
    for pid in ranked.iter().copied().take(pid_cap) {
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().last() else {
                continue;
            };
            if !path.starts_with('/') || path.contains(" (deleted)") {
                continue;
            }
            if !seen.insert(path.to_owned()) {
                continue;
            }
            if !crate::elf::plausible_elf_file(path) {
                continue;
            }
            if seen.len() > 256 {
                skipped_maps = skipped_maps.saturating_add(1);
                eprintln!(
                    "tls scan skip maps cap=256 scanned={} exporters={} skipped_pids={} skipped_maps={}",
                    seen.len(),
                    exporters.len(),
                    skipped_pids,
                    skipped_maps
                );
                return exporters;
            }
            if exporters.len() >= TLS_EXPORTER_CAP {
                eprintln!(
                    "tls scan skip exporters cap={} scanned_maps={} skipped_pids={}",
                    TLS_EXPORTER_CAP,
                    seen.len(),
                    skipped_pids
                );
                return exporters;
            }
            // Hardened/obfuscated ELFs carry hostile section tables; parsing
            // must never take the whole agent down.
            let scanned = std::panic::catch_unwind(|| {
                crate::elf::inspect_elf(path)
                    .ok()
                    .filter(|elf| !matching_symbols_exact(elf, &names).is_empty())
            });
            if let Ok(Some(elf)) = scanned {
                exporters.push(path.to_owned());
                drop(elf);
            }
        }
    }
    exporters
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
            if found.len() >= 24 {
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
    let Some(mut next) = active_tgid_filter(policy) else {
        return;
    };
    // Keep TGIDs already in this capture; short-lived children vanish from
    // /proc between scans (CCB 11468 dropped while SSL_read still buffered).
    for pid in &runtime.scoped_tgids {
        if !next.contains(pid) {
            next.push(*pid);
        }
    }
    next.sort_unstable();
    next.dedup();
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

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn adapter_hit_cap(runtime: &InspectRuntime, adapter: InspectAdapterKind) -> u32 {
    if runtime.per_adapter_budget {
        adapter.default_max_hits()
    } else {
        runtime.max_hits
    }
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn adapter_hits(runtime: &InspectRuntime, adapter: InspectAdapterKind) -> u32 {
    runtime
        .hits_by_adapter
        .get(adapter.as_str())
        .copied()
        .unwrap_or(0)
}

fn inspect_budget_exhausted(runtime: &InspectRuntime) -> bool {
    if !runtime.per_adapter_budget {
        return runtime.hits >= runtime.max_hits;
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        if runtime.sessions.is_empty() {
            return false;
        }
        runtime.sessions.iter().all(|probe| {
            adapter_hits(runtime, probe.plan.adapter) >= probe.plan.adapter.default_max_hits()
        })
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        runtime.hits >= runtime.max_hits
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn inspect_target_survived_packer(plans: &[InspectPlan]) -> bool {
    let Some(policy) = plans.first().map(|plan| &plan.policy) else {
        return true;
    };
    if policy.whole_device {
        return true;
    }
    if let Some(pid) = policy.pid.filter(|pid| *pid > 0) {
        return process_age(pid).is_some_and(|age| age >= PACKER_ATTACH_GRACE);
    }
    let Some(package) = policy.package.as_deref().filter(|name| !name.is_empty()) else {
        return false;
    };
    crate::dexdump::pids_for_package(package)
        .into_iter()
        .filter(|pid| process_cmdline_is_main(*pid, package))
        .any(|pid| process_age(pid).is_some_and(|age| age >= PACKER_ATTACH_GRACE))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn process_cmdline_is_main(pid: u32, package: &str) -> bool {
    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let cmd = bytes.split(|byte| *byte == 0).next().unwrap_or(&[]);
    std::str::from_utf8(cmd).ok() == Some(package)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn process_age(pid: u32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start_ticks = parse_stat_start_ticks(&stat)?;
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let uptime_secs: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    let start_secs = start_ticks as f64 / 100.0;
    let age = uptime_secs - start_secs;
    if age.is_finite() && age >= 0.0 {
        Some(Duration::from_secs_f64(age.min(86_400.0 * 30.0)))
    } else {
        None
    }
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn parse_stat_start_ticks(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn refresh_package_tgids(runtime: &mut InspectRuntime) {
    let Some(package) = runtime
        .plans
        .first()
        .and_then(|plan| plan.policy.package.clone())
        .filter(|name| !name.is_empty())
    else {
        return;
    };
    let mut pids = crate::dexdump::pids_for_package(&package);
    for pid in &runtime.scoped_tgids {
        if !pids.contains(pid) {
            pids.push(*pid);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if pids == runtime.scoped_tgids {
        return;
    }
    eprintln!(
        "inspect tgid_filter refresh {} -> {}",
        join_tgids(&runtime.scoped_tgids),
        join_tgids(&pids)
    );
    runtime.scoped_tgids.clone_from(&pids);
    for live in &mut runtime.sessions {
        if let Err(error) = live.session.apply_tgid_filter(Some(&pids)) {
            eprintln!("inspect tgid_filter update failed: {error:#}");
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

/// Entry + uretprobe from one BPF load so `entry_ptr` survives until return
/// (`SSL_read` aux snapshot). Separate loads left uretprobe blind on Alipay BABASSL.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn start_uprobe_entry_return_session(
    object: &Path,
    elf: &Path,
    offset: u64,
    hit_once: bool,
    pointer_width: u8,
    tgids: Option<&[u32]>,
) -> anyhow::Result<ksight_hwbp::UprobeSession> {
    match ksight_hwbp::UprobeSession::start_entry_return(object, elf, offset, None, hit_once) {
        Ok(session) => Ok(session),
        Err(error) if pointer_width == 4 && uprobe_attach_unsupported(&error) => {
            let mut last = error;
            for tgid in tgids.unwrap_or(&[]) {
                let pid = i32::try_from(*tgid).unwrap_or(0);
                if pid <= 0 {
                    continue;
                }
                match ksight_hwbp::UprobeSession::start_entry_return(
                    object,
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
        let programs: &[&str] = adapter_probe_programs_for_plan(&plan);
        let wants_pair =
            programs.contains(&"ksight_uprobe_regs") && programs.contains(&"ksight_uretprobe_regs");
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
        let symbol = plan.symbol.as_deref().unwrap_or("-");
        let elf32_note = if plan.pointer_width == 4 {
            if plan.adapter.is_tls() {
                "; ELF32 uprobe was tried globally and per-TGID. This arm64 GKI cannot decode AArch32/Thumb instructions (ENOTSUP), so 32-bit Conscrypt/Cronet SSL_write cannot be probed. TLS plaintext is userspace crypto: there is no kernel SSL_write equivalent to binder_transaction"
            } else {
                "; ELF32 uprobe was tried globally and per-TGID (this kernel rejects AArch32 uprobes). Kernel binder_transaction parcel prefix covers 32-bit and 64-bit clients"
            }
        } else {
            ""
        };

        if wants_pair {
            let already_live = runtime.sessions.iter().any(|live| {
                live.paired_entry_return
                    && live.plan.adapter == plan.adapter
                    && live.plan.elf_path == plan.elf_path
                    && live.plan.offset == plan.offset
                    && live.plan.symbol == plan.symbol
            });
            if already_live {
                continue;
            }
            let attempt_key = format!(
                "{}|{}|{}|{}|entry+return",
                plan.adapter.as_str(),
                plan.elf_path.as_deref().unwrap_or_default(),
                plan.offset.unwrap_or_default(),
                plan.symbol.as_deref().unwrap_or_default()
            );
            let now = Instant::now();
            if runtime
                .attach_attempts
                .get(&attempt_key)
                .is_some_and(|attempted| attempted.elapsed() < Duration::from_secs(15))
            {
                continue;
            }
            runtime.attach_attempts.insert(attempt_key, now);
            match start_uprobe_entry_return_session(
                &plan.uprobe_object,
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
                    for kind in ["uprobe", "uretprobe"] {
                        let mut observation = plan.observation.clone();
                        observation.attached = true;
                        observation.detail = format!(
                            "attached {} {kind} filter={scope}{tgid_note}{filter_status} offset={offset:#x} symbol={symbol} hit_once={hit_once} max_hits={} paired_entry_return=true",
                            plan.adapter.as_str(),
                            runtime.max_hits
                        );
                        eprintln!("{}", observation.detail);
                        out.push(observation);
                    }
                    runtime.sessions.push(LiveProbe {
                        plan: plan.clone(),
                        session,
                        retprobe: false,
                        paired_entry_return: true,
                    });
                }
                Err(error) => {
                    for program in programs {
                        let mut observation = plan.observation.clone();
                        observation.attached = false;
                        observation.detail =
                            format!("attach failed ({program}): {error:#}{elf32_note}");
                        out.push(observation);
                    }
                }
            }
            continue;
        }

        for program in programs {
            let retprobe = *program == "ksight_uretprobe_regs";
            let already_live = runtime.sessions.iter().any(|live| {
                !live.paired_entry_return
                    && live.retprobe == retprobe
                    && live.plan.adapter == plan.adapter
                    && live.plan.elf_path == plan.elf_path
                    && live.plan.offset == plan.offset
                    && live.plan.symbol == plan.symbol
            });
            if already_live {
                continue;
            }
            let attempt_key = format!(
                "{}|{}|{}|{}|{program}",
                plan.adapter.as_str(),
                plan.elf_path.as_deref().unwrap_or_default(),
                plan.offset.unwrap_or_default(),
                plan.symbol.as_deref().unwrap_or_default()
            );
            let now = Instant::now();
            if runtime
                .attach_attempts
                .get(&attempt_key)
                .is_some_and(|attempted| attempted.elapsed() < Duration::from_secs(15))
            {
                continue;
            }
            runtime.attach_attempts.insert(attempt_key, now);
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
                    let kind = if retprobe { "uretprobe" } else { "uprobe" };
                    observation.detail = format!(
                        "attached {} {kind} filter={scope}{tgid_note}{filter_status} offset={offset:#x} symbol={symbol} hit_once={hit_once} max_hits={}",
                        plan.adapter.as_str(),
                        runtime.max_hits
                    );
                    eprintln!("{}", observation.detail);
                    runtime.sessions.push(LiveProbe {
                        plan: plan.clone(),
                        session,
                        retprobe,
                        paired_entry_return: false,
                    });
                    out.push(observation);
                }
                Err(error) => {
                    let mut observation = plan.observation.clone();
                    observation.attached = false;
                    observation.detail =
                        format!("attach failed ({program}): {error:#}{elf32_note}");
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
    let _ = runtime.tls_pending.drop_stale(PENDING_STALE);
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
        let before_drained = probe.session.drained_total;
        let before_lost = probe.session.lost_total;
        let Ok(hits) = probe.session.poll_hits() else {
            continue;
        };
        runtime.raw_drained += probe.session.drained_total.saturating_sub(before_drained);
        runtime.perf_lost += probe.session.lost_total.saturating_sub(before_lost);
        for hit in hits {
            let retprobe = if probe.paired_entry_return {
                hit.snapshot_at_return
            } else {
                probe.retprobe
            };
            batch.push((probe.plan.clone(), retprobe, hit));
        }
    }
    batch.sort_by_key(|(_, _, hit)| hit.time_ns);
    for (plan, retprobe, hit) in batch {
        if adapter_hits(runtime, plan.adapter) >= adapter_hit_cap(runtime, plan.adapter) {
            continue;
        }
        if !runtime.per_adapter_budget && runtime.hits >= runtime.max_hits {
            break;
        }
        let ssl_lib = if plan.adapter == InspectAdapterKind::TlsSslRead {
            ssl_read_lib_kind(plan.elf_path.as_deref())
        } else {
            SslReadLibKind::Other
        };
        let mut ssl_ret_gt0 = false;
        if plan.adapter == InspectAdapterKind::TlsSslRead {
            if retprobe {
                runtime.ssl_read_ret = runtime.ssl_read_ret.saturating_add(1);
                let signed = hit.regs[0] as i32;
                // Bifrost/OpenSSL non-blocking: SSL_read returns -1 → WANT_READ/WRITE.
                if signed < 0 {
                    runtime.ssl_read_want = runtime.ssl_read_want.saturating_add(1);
                    match ssl_lib {
                        SslReadLibKind::Openssl => {
                            runtime.ssl_read_want_openssl =
                                runtime.ssl_read_want_openssl.saturating_add(1);
                        }
                        SslReadLibKind::Conscrypt => {
                            runtime.ssl_read_want_conscrypt =
                                runtime.ssl_read_want_conscrypt.saturating_add(1);
                        }
                        SslReadLibKind::Other => {}
                    }
                } else if signed > 0 {
                    ssl_ret_gt0 = true;
                    runtime.ssl_read_ret_gt0 = runtime.ssl_read_ret_gt0.saturating_add(1);
                    match ssl_lib {
                        SslReadLibKind::Openssl => {
                            runtime.ssl_read_ret_gt0_openssl =
                                runtime.ssl_read_ret_gt0_openssl.saturating_add(1);
                        }
                        SslReadLibKind::Conscrypt => {
                            runtime.ssl_read_ret_gt0_conscrypt =
                                runtime.ssl_read_ret_gt0_conscrypt.saturating_add(1);
                        }
                        SslReadLibKind::Other => {}
                    }
                }
            } else {
                runtime.ssl_read_entry = runtime.ssl_read_entry.saturating_add(1);
            }
        }
        if let Some(output) = decode_hit(
            &plan,
            &hit,
            plan_max_payload(&plan, max_payload),
            retprobe,
            &mut runtime.tls_pending,
            &mut runtime.jni_region_pending,
            &mut runtime.jni_pair,
            &mut runtime.binder_pending,
            &mut runtime.binder_dex_cache,
        ) {
            *runtime
                .hits_by_adapter
                .entry(plan.adapter.as_str().to_owned())
                .or_default() += 1;
            runtime.hits = runtime.hits.saturating_add(1);
            runtime.decoded_hits = runtime.decoded_hits.saturating_add(1);
            if plan.adapter == InspectAdapterKind::TlsSslRead && retprobe {
                runtime.ssl_read_ok = runtime.ssl_read_ok.saturating_add(1);
                match ssl_lib {
                    SslReadLibKind::Openssl => {
                        runtime.ssl_read_ok_openssl = runtime.ssl_read_ok_openssl.saturating_add(1);
                    }
                    SslReadLibKind::Conscrypt => {
                        runtime.ssl_read_ok_conscrypt =
                            runtime.ssl_read_ok_conscrypt.saturating_add(1);
                    }
                    SslReadLibKind::Other => {}
                }
            }
            out.push(output);
        } else if plan.adapter == InspectAdapterKind::TlsSslRead && retprobe {
            runtime.ssl_read_fail = runtime.ssl_read_fail.saturating_add(1);
            if ssl_ret_gt0 {
                runtime.ssl_read_drop_gt0 = runtime.ssl_read_drop_gt0.saturating_add(1);
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
    retprobe: bool,
    tls_pending: &mut PendingCallStacks,
    jni_region_pending: &mut HashMap<u32, PendingSslRead>,
    jni_pair: &mut JniPairPending,
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
        InspectAdapterKind::TlsSslWrite => {
            let layout = effective_layout(plan);
            let key = probe_call_key(plan, pid, hit.tid);
            let direction = layout.direction.fragment_label(layout.consumes);
            if retprobe {
                let pending = tls_pending.pop(key)?;
                let captured = match ssl_read_captured(&pending, hit) {
                    Some(n) => n,
                    None => return None,
                };
                decode_tls_plaintext(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    captured,
                    max_payload,
                    direction,
                    &[],
                    false,
                    pending.connection_id,
                )
            } else if plan_needs_uretprobe(plan) {
                // Nested calls: entry pushes only. Never pop a prior frame as
                // "stale success" here — that breaks re-entrant SSL_write and
                // makes incomplete frames look like complete sends. Stale
                // flush belongs to timeout / thread exit / depth overflow /
                // session end (PendingCallStacks::push drops overflow frames
                // without decoding them as success).
                if let Some(frame) = pending_from_entry(plan, hit, pid) {
                    tls_pending.push(key, frame);
                }
                None
            } else {
                let buf = *hit.regs.get(usize::from(layout.buffer_arg)).unwrap_or(&0);
                let requested = i32::try_from(
                    *hit.regs
                        .get(usize::from(layout.requested_len_arg))
                        .unwrap_or(&0) as i64,
                )
                .unwrap_or(0);
                decode_tls_plaintext(
                    plan,
                    pid,
                    hit.tid,
                    buf,
                    requested,
                    max_payload,
                    direction,
                    tls_write_snapshot(hit),
                    true,
                    hit.regs.get(usize::from(layout.connection_arg)).copied(),
                )
            }
        }
        InspectAdapterKind::TlsSslRead => {
            let layout = effective_layout(plan);
            let key = probe_call_key(plan, pid, hit.tid);
            let direction = layout.direction.fragment_label(layout.consumes);
            if retprobe {
                let return_snapshot: &[u8] = if hit.snapshot_at_return {
                    let n = usize::try_from(hit.aux_bytes)
                        .unwrap_or(0)
                        .min(hit.aux.len());
                    &hit.aux[..n]
                } else {
                    &[]
                };
                let snap_usable = return_snapshot.iter().any(|b| *b != 0);
                let signed = hit.regs[0] as i32;
                if let Some(pending) = tls_pending.pop(key) {
                    let captured = match ssl_read_captured(&pending, hit) {
                        Some(n) => n,
                        None if snap_usable => {
                            let snap_len = i32::try_from(return_snapshot.len()).unwrap_or(0);
                            let floor = pending.requested.max(snap_len).max(1);
                            snap_len.max(1).min(floor)
                        }
                        None => return None,
                    };
                    decode_tls_plaintext(
                        plan,
                        pending.pid,
                        hit.tid,
                        pending.buf,
                        captured,
                        max_payload,
                        direction,
                        if snap_usable { return_snapshot } else { &[] },
                        snap_usable,
                        pending.connection_id,
                    )
                } else if signed > 0 && snap_usable {
                    let captured = i32::try_from(return_snapshot.len()).unwrap_or(0).max(1);
                    decode_tls_plaintext(
                        plan,
                        pid,
                        hit.tid,
                        0,
                        captured,
                        max_payload,
                        direction,
                        return_snapshot,
                        true,
                        None,
                    )
                } else {
                    None
                }
            } else {
                if let Some(frame) = pending_from_entry(plan, hit, pid) {
                    tls_pending.push(key, frame);
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
        InspectAdapterKind::JniNewStringUtf => {
            let buf = hit.regs.get(1).copied().unwrap_or(0);
            decode_jni_cstring(plan, pid, hit.tid, buf, max_payload, "native_to_java")
        }
        InspectAdapterKind::JniGetStringUtfLength => {
            if retprobe {
                let obj = jni_pair.string_len_obj.remove(&hit.tid)?;
                let len = i32::try_from(hit.regs.first().copied().unwrap_or(0) as i64).unwrap_or(0);
                if obj != 0 && len > 0 && jni_pair.string_len.len() < 4096 {
                    jni_pair
                        .string_len
                        .insert(hit.tid, PendingJniLen { obj, len });
                }
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.string_len_obj.insert(hit.tid, obj);
            }
            None
        }
        InspectAdapterKind::JniGetStringUtfChars => {
            if retprobe {
                let obj = jni_pair.utfchars_obj.remove(&hit.tid).unwrap_or(0);
                let cap = take_paired_len(&mut jni_pair.string_len, hit.tid, obj)
                    .and_then(|len| usize::try_from(len).ok())
                    .unwrap_or(max_payload)
                    .min(max_payload);
                let buf = hit.regs.first().copied().unwrap_or(0);
                decode_jni_cstring(plan, pid, hit.tid, buf, cap, "java_to_native")
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.utfchars_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniGetStringUtfRegion => {
            if retprobe {
                let pending = jni_pair.utf_region.remove(&hit.tid)?;
                decode_tls_plaintext(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    pending.requested,
                    max_payload,
                    "java_to_native",
                    &[],
                    false,
                    None,
                )
            } else {
                let requested =
                    i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
                let buf = hit.regs.get(4).copied().unwrap_or(0);
                if requested > 0 && buf != 0 && jni_pair.utf_region.len() < 4096 {
                    jni_pair.utf_region.insert(
                        hit.tid,
                        PendingSslRead {
                            pid,
                            buf,
                            requested,
                            written_ptr: None,
                            connection_id: None,
                        },
                    );
                }
                None
            }
        }
        InspectAdapterKind::JniGetArrayLength => {
            if retprobe {
                let obj = jni_pair.array_len_obj.remove(&hit.tid)?;
                let len = i32::try_from(hit.regs.first().copied().unwrap_or(0) as i64).unwrap_or(0);
                if obj != 0 && len > 0 && jni_pair.array_len.len() < 4096 {
                    jni_pair
                        .array_len
                        .insert(hit.tid, PendingJniLen { obj, len });
                }
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.array_len_obj.insert(hit.tid, obj);
            }
            None
        }
        InspectAdapterKind::JniSetByteArrayRegion => {
            let len = i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
            let buf = hit.regs.get(4).copied().unwrap_or(0);
            decode_tls_plaintext(
                plan,
                pid,
                hit.tid,
                buf,
                len,
                max_payload,
                "native_to_java",
                &[],
                false,
                None,
            )
        }
        InspectAdapterKind::JniGetByteArrayElements => {
            if retprobe {
                let obj = jni_pair.elements_obj.remove(&hit.tid)?;
                let len = take_paired_len(&mut jni_pair.array_len, hit.tid, obj)?;
                let buf = hit.regs.first().copied().unwrap_or(0);
                decode_jni_bytes_with_len(
                    plan,
                    pid,
                    hit.tid,
                    buf,
                    len,
                    max_payload,
                    "java_to_native",
                )
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.elements_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniGetByteArrayRegion => {
            if retprobe {
                let pending = jni_region_pending.remove(&hit.tid)?;
                decode_tls_plaintext(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    pending.requested,
                    max_payload,
                    "java_to_native",
                    &[],
                    false,
                    None,
                )
            } else {
                let requested =
                    i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
                let buf = hit.regs.get(4).copied().unwrap_or(0);
                if requested > 0 && buf != 0 && jni_region_pending.len() < 4096 {
                    jni_region_pending.insert(
                        hit.tid,
                        PendingSslRead {
                            pid,
                            buf,
                            requested,
                            written_ptr: None,
                            connection_id: None,
                        },
                    );
                }
                None
            }
        }
        InspectAdapterKind::JniNewString => {
            let units = i32::try_from(hit.regs.get(2).copied().unwrap_or(0) as i64).unwrap_or(0);
            decode_jni_utf16_units(
                plan,
                pid,
                hit.tid,
                hit.regs.get(1).copied().unwrap_or(0),
                units,
                max_payload,
                "native_to_java",
            )
        }
        InspectAdapterKind::JniGetStringLength => {
            if retprobe {
                let obj = jni_pair.u16_len_obj.remove(&hit.tid)?;
                let len = i32::try_from(hit.regs.first().copied().unwrap_or(0) as i64).unwrap_or(0);
                if obj != 0 && len > 0 && jni_pair.u16_len.len() < 4096 {
                    jni_pair.u16_len.insert(hit.tid, PendingJniLen { obj, len });
                }
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.u16_len_obj.insert(hit.tid, obj);
            }
            None
        }
        InspectAdapterKind::JniGetStringChars | InspectAdapterKind::JniGetStringCritical => {
            if retprobe {
                let obj = jni_pair.u16chars_obj.remove(&hit.tid).unwrap_or(0);
                let cap = take_paired_len(&mut jni_pair.u16_len, hit.tid, obj)
                    .unwrap_or(i32::try_from(max_payload).unwrap_or(i32::MAX));
                decode_jni_utf16_units(
                    plan,
                    pid,
                    hit.tid,
                    hit.regs.first().copied().unwrap_or(0),
                    cap,
                    max_payload,
                    "java_to_native",
                )
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.u16chars_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniGetStringRegion => {
            if retprobe {
                let pending = jni_pair.u16_region.remove(&hit.tid)?;
                decode_jni_utf16_units(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    pending.requested,
                    max_payload,
                    "java_to_native",
                )
            } else {
                let requested =
                    i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
                let buf = hit.regs.get(4).copied().unwrap_or(0);
                if requested > 0 && buf != 0 && jni_pair.u16_region.len() < 4096 {
                    jni_pair.u16_region.insert(
                        hit.tid,
                        PendingSslRead {
                            pid,
                            buf,
                            requested,
                            written_ptr: None,
                            connection_id: None,
                        },
                    );
                }
                None
            }
        }
        InspectAdapterKind::JniGetCharArrayElements => {
            if retprobe {
                let obj = jni_pair.char_elements_obj.remove(&hit.tid)?;
                let len = take_paired_len(&mut jni_pair.array_len, hit.tid, obj)?;
                decode_jni_utf16_units(
                    plan,
                    pid,
                    hit.tid,
                    hit.regs.first().copied().unwrap_or(0),
                    len,
                    max_payload,
                    "java_to_native",
                )
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.char_elements_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniGetCharArrayRegion | InspectAdapterKind::JniSetCharArrayRegion => {
            if plan.adapter == InspectAdapterKind::JniSetCharArrayRegion {
                let units =
                    i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
                return decode_jni_utf16_units(
                    plan,
                    pid,
                    hit.tid,
                    hit.regs.get(4).copied().unwrap_or(0),
                    units,
                    max_payload,
                    "native_to_java",
                );
            }
            if retprobe {
                let pending = jni_pair.u16_region.remove(&hit.tid)?;
                decode_jni_utf16_units(
                    plan,
                    pending.pid,
                    hit.tid,
                    pending.buf,
                    pending.requested,
                    max_payload,
                    "java_to_native",
                )
            } else {
                let requested =
                    i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
                let buf = hit.regs.get(4).copied().unwrap_or(0);
                if requested > 0 && buf != 0 && jni_pair.u16_region.len() < 4096 {
                    jni_pair.u16_region.insert(
                        hit.tid,
                        PendingSslRead {
                            pid,
                            buf,
                            requested,
                            written_ptr: None,
                            connection_id: None,
                        },
                    );
                }
                None
            }
        }
        InspectAdapterKind::JniGetPrimitiveArrayCritical => {
            if retprobe {
                let obj = jni_pair.elements_obj.remove(&hit.tid)?;
                let len = take_paired_len(&mut jni_pair.array_len, hit.tid, obj)?;
                decode_jni_bytes_with_len(
                    plan,
                    pid,
                    hit.tid,
                    hit.regs.first().copied().unwrap_or(0),
                    len,
                    max_payload,
                    "java_to_native",
                )
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.elements_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniGetDirectBufferCapacity => {
            if retprobe {
                let obj = jni_pair.direct_cap_obj.remove(&hit.tid)?;
                let len = i32::try_from(hit.regs.first().copied().unwrap_or(0) as i64).unwrap_or(0);
                if obj != 0 && len > 0 && jni_pair.direct_cap.len() < 4096 {
                    jni_pair
                        .direct_cap
                        .insert(hit.tid, PendingJniLen { obj, len });
                }
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.direct_cap_obj.insert(hit.tid, obj);
            }
            None
        }
        InspectAdapterKind::JniGetDirectBufferAddress => {
            if retprobe {
                let obj = jni_pair.direct_obj.remove(&hit.tid).unwrap_or(0);
                let len = take_paired_len(&mut jni_pair.direct_cap, hit.tid, obj)
                    .unwrap_or(i32::try_from(max_payload).unwrap_or(i32::MAX));
                decode_jni_bytes_with_len(
                    plan,
                    pid,
                    hit.tid,
                    hit.regs.first().copied().unwrap_or(0),
                    len,
                    max_payload,
                    "java_to_native",
                )
            } else if let Some(obj) = hit.regs.get(1).copied().filter(|obj| *obj != 0) {
                jni_pair.direct_obj.insert(hit.tid, obj);
                None
            } else {
                None
            }
        }
        InspectAdapterKind::JniRegistration => decode_jni_register_natives(plan, pid, hit),
        InspectAdapterKind::JniPlaintext => None,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_jni_bytes_with_len(
    plan: &InspectPlan,
    pid: u32,
    tid: u32,
    buf: u64,
    len: i32,
    max_payload: usize,
    direction: &str,
) -> Option<InspectOutput> {
    if len <= 0 {
        return None;
    }
    let want = usize::try_from(u64::try_from(len).unwrap_or(0))
        .unwrap_or(0)
        .min(max_payload);
    let raw = read_remote_bytes(pid, buf, want)?;
    let clipped = clip_jni_elements(trim_trailing_zeros(&raw));
    if !keep_jni_elements(clipped) {
        return None;
    }
    let bytes = clipped.to_vec();
    let truncated = u64::try_from(len).unwrap_or(0) > u64::try_from(raw.len()).unwrap_or(0);
    let content_class = classify_buffer(&bytes);
    let (preview, preview_encoding) = preview_bytes(&bytes);
    Some(InspectOutput::Plaintext {
        pid,
        tid,
        connection_id: None,
        fragment: InspectPlaintext {
            adapter: plan.adapter.as_str().to_owned(),
            direction: direction.to_owned(),
            library: plan.elf_path.clone().unwrap_or_default(),
            build_id: plan.build_id.clone(),
            offset: plan.offset,
            requested_bytes: u64::try_from(len).unwrap_or(0),
            captured_bytes: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            truncated,
            sha256: hex_sha256(&bytes),
            preview,
            preview_encoding,
            content_class: content_class.to_owned(),

            ..Default::default()
        },
        raw: bytes,
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_jni_cstring(
    plan: &InspectPlan,
    pid: u32,
    tid: u32,
    buf: u64,
    max_payload: usize,
    direction: &str,
) -> Option<InspectOutput> {
    let bytes = read_remote_cstring_bytes(pid, buf, max_payload)?;
    if !keep_jni_plaintext(&bytes) {
        return None;
    }
    let requested = u64::try_from(bytes.len().saturating_add(1)).unwrap_or(0);
    let truncated = bytes.len() >= max_payload;
    let content_class = classify_buffer(&bytes);
    let (preview, preview_encoding) = preview_bytes(&bytes);
    Some(InspectOutput::Plaintext {
        pid,
        tid,
        connection_id: None,
        fragment: InspectPlaintext {
            adapter: plan.adapter.as_str().to_owned(),
            direction: direction.to_owned(),
            library: plan.elf_path.clone().unwrap_or_default(),
            build_id: plan.build_id.clone(),
            offset: plan.offset,
            requested_bytes: requested,
            captured_bytes: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            truncated,
            sha256: hex_sha256(&bytes),
            preview,
            preview_encoding,
            content_class: content_class.to_owned(),

            ..Default::default()
        },
        raw: bytes,
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_jni_utf16_units(
    plan: &InspectPlan,
    pid: u32,
    tid: u32,
    buf: u64,
    units: i32,
    max_payload: usize,
    direction: &str,
) -> Option<InspectOutput> {
    if units <= 0 || buf == 0 {
        return None;
    }
    let count = usize::try_from(units)
        .ok()?
        .min(max_payload / 2)
        .min(JNI_UTF16_UNITS_CAP);
    let text = read_remote_utf16(pid, buf, u64::try_from(count).ok()?)?;
    if !keep_jni_plaintext(text.as_bytes()) {
        return None;
    }
    let truncated = usize::try_from(units).unwrap_or(0) > count;
    let content_class = classify_buffer(text.as_bytes());
    let (preview, preview_encoding) = preview_bytes(text.as_bytes());
    let raw = text.as_bytes().to_vec();
    Some(InspectOutput::Plaintext {
        pid,
        tid,
        connection_id: None,
        fragment: InspectPlaintext {
            adapter: plan.adapter.as_str().to_owned(),
            direction: direction.to_owned(),
            library: plan.elf_path.clone().unwrap_or_default(),
            build_id: plan.build_id.clone(),
            offset: plan.offset,
            requested_bytes: u64::try_from(units.saturating_mul(2)).unwrap_or(0),
            captured_bytes: u32::try_from(text.len()).unwrap_or(u32::MAX),
            truncated,
            sha256: hex_sha256(text.as_bytes()),
            preview,
            preview_encoding,
            content_class: content_class.to_owned(),

            ..Default::default()
        },
        raw,
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_remote_cstring_bytes(pid: u32, address: u64, max_bytes: usize) -> Option<Vec<u8>> {
    let mut buffer = read_remote_bytes(pid, address, max_bytes)?;
    if let Some(end) = buffer.iter().position(|byte| *byte == 0) {
        buffer.truncate(end);
    }
    (!buffer.is_empty()).then_some(buffer)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn decode_jni_register_natives(
    plan: &InspectPlan,
    pid: u32,
    hit: &ksight_hwbp::RegisterContext,
) -> Option<InspectOutput> {
    let methods = hit.regs.get(2).copied().unwrap_or(0);
    let count = i32::try_from(hit.regs.get(3).copied().unwrap_or(0) as i64).unwrap_or(0);
    if methods == 0 || count <= 0 {
        return None;
    }
    let n = usize::try_from(count).unwrap_or(0).min(32);
    let width = usize::from(plan.pointer_width.max(4));
    let stride = width.saturating_mul(3);
    let raw = read_remote_bytes(pid, methods, stride.saturating_mul(n))?;
    let mut names = Vec::new();
    for chunk in raw.chunks(stride).take(n) {
        if chunk.len() < width.saturating_mul(2) {
            break;
        }
        let name_ptr = read_ptr_le(&chunk[..width]);
        let sig_ptr = read_ptr_le(&chunk[width..width.saturating_mul(2)]);
        let fn_ptr = if chunk.len() >= stride {
            read_ptr_le(&chunk[width.saturating_mul(2)..stride])
        } else {
            0
        };
        let name = read_remote_cstring(pid, name_ptr, 128).unwrap_or_default();
        let sig = read_remote_cstring(pid, sig_ptr, 128).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        names.push(format!("{name}{sig} @{fn_ptr:#x}"));
    }
    if names.is_empty() {
        return None;
    }
    let mut observation = plan.observation.clone();
    observation.attached = true;
    observation.hit = true;
    observation.path_hint = names.first().cloned();
    observation.detail = format!(
        "RegisterNatives hit pid={pid} n={count} methods={} (JNINativeMethod name/signature/fnPtr from jni.h; jclass fields not read)",
        names.join("; ")
    );
    observation.binder_strings = Some(names);
    Some(inspect_observation(pid, hit.tid, observation))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_ptr_le(bytes: &[u8]) -> u64 {
    match bytes.len() {
        8 => u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
        4 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
        _ => 0,
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
    snapshot: &[u8],
    snapshot_exact: bool,
    connection_id: Option<u64>,
) -> Option<InspectOutput> {
    if !tls_decode_should_attempt(requested, snapshot) {
        return None;
    }
    let requested_bytes = u64::try_from(requested.max(0)).unwrap_or(0);
    let want = usize::try_from(requested_bytes)
        .unwrap_or(0)
        .min(max_payload);
    // All-zero aux is a failed probe_read / unfilled buffer, not plaintext.
    // Alipay BABASSL SSL_write hits were decoded then dropped as inert zeros.
    let snapshot_usable = snapshot.iter().any(|byte| *byte != 0);
    // A BPF-time snapshot is the truth for the bytes it covers: the caller's
    // buffer may already be reused by the time this userspace decode runs.
    // Remote reads only extend past the snapshot cap, never replace it.
    let mut bytes = if snapshot_exact && snapshot_usable {
        let mut exact = snapshot.to_vec();
        let have = exact.len();
        if requested_bytes as usize > have && have < want {
            let tail_want = want - have;
            if let Some(tail) = read_remote_bytes(pid, buf.saturating_add(have as u64), tail_want) {
                exact.extend_from_slice(&tail);
            }
        }
        exact
    } else {
        let remote = if want == 0 {
            Vec::new()
        } else {
            read_remote_bytes(pid, buf, want).unwrap_or_default()
        };
        prefer_probe_snapshot(&remote, snapshot)
    };
    let truncated = requested_bytes > u64::try_from(bytes.len()).unwrap_or(0);
    let captured_bytes = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let digest = hex_sha256(&bytes);
    if let Some(plain) = ksight_core::inflate_inspect_buffer(&bytes) {
        bytes = plain;
    }
    if plan.adapter.is_jni() {
        let clipped = clip_jni_elements(trim_trailing_zeros(&bytes));
        if !keep_jni_elements(clipped) {
            return None;
        }
        bytes = clipped.to_vec();
    } else if bytes.is_empty() {
        return None;
    }
    // All-zero SSL_read copies are WANT_READ/unfilled-buffer noise (Alipay BABASSL);
    // Burp already drops them via is_inert_tls_fragment — skip emit earlier.
    if plan.adapter == InspectAdapterKind::TlsSslRead && bytes.iter().all(|b| *b == 0) {
        return None;
    }
    // Optional ProbeSpec/plaintext sample pin: validate when present; do not
    // invent offsets or reject simply because the field is unset.
    if let Some(expected) = plan.layout_hint.sample_sha256.as_deref() {
        let expect = expected.trim().to_ascii_lowercase();
        if !expect.is_empty() && expect != digest {
            // Keep soft: still emit, but mark truncated/detail via content_class tag.
            // Operators compare sample_sha256 offline; mismatch must not crash attach.
        }
    }
    let content_class = classify_buffer(&bytes);
    let (preview, preview_encoding) = if content_class == "tls_record" {
        (tls_record_preview(&bytes), "tls_record".to_owned())
    } else {
        preview_bytes(&bytes)
    };
    Some(InspectOutput::Plaintext {
        pid,
        tid,
        connection_id: connection_id.filter(|value| *value >= 0x1000),
        fragment: InspectPlaintext {
            adapter: plan.adapter.as_str().to_owned(),
            direction: direction.to_owned(),
            library: plan.elf_path.clone().unwrap_or_default(),
            build_id: plan.build_id.clone(),
            offset: plan.offset,
            requested_bytes,
            captured_bytes,
            truncated,
            sha256: digest,
            preview,
            preview_encoding,
            content_class: content_class.to_owned(),
            sequence: FRAGMENT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            symbol: plan.symbol.clone(),
            consumes: effective_layout(plan).consumes,

            ..Default::default()
        },
        raw: bytes,
    })
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn snapshot_looks_like_http(bytes: &[u8]) -> bool {
    http1_prefix(bytes) || ksight_core::looks_like_http2(bytes)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn prefer_probe_snapshot(remote: &[u8], snapshot: &[u8]) -> Vec<u8> {
    // process_vm_readv after SSL_read often returns a cleared buffer (Alipay
    // conscrypt drop_gt0). Treat all-zero as a missed copy, not plaintext.
    let remote = if remote.iter().all(|byte| *byte == 0) {
        &[][..]
    } else {
        remote
    };
    let snapshot = if snapshot.iter().all(|byte| *byte == 0) {
        &[][..]
    } else {
        snapshot
    };
    if snapshot_looks_like_http(snapshot)
        && (remote.is_empty()
            || classify_buffer(remote) == "tls_record"
            || !snapshot_looks_like_http(remote))
    {
        return snapshot.to_vec();
    }
    // Non-empty aux snapshot wins over empty/TLS-ciphertext remote so decode is
    // not dropped solely because process_vm_readv raced after SSL_* returned.
    if !snapshot.is_empty() && (remote.is_empty() || classify_buffer(remote) == "tls_record") {
        return snapshot.to_vec();
    }
    if !remote.is_empty() {
        return remote.to_vec();
    }
    snapshot.to_vec()
}

/// True when userspace should attempt a TLS plaintext decode instead of an
/// early return (empty requested + empty snapshot).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslReadLibKind {
    Openssl,
    Conscrypt,
    Other,
}

/// Key SSL_read pending by tid + attach offset so conscrypt / BABASSL /
/// SSL_read_ex on the same thread cannot steal each other's entry stash.
#[allow(dead_code)]
fn ssl_read_pending_key(tid: u32, offset: u64) -> u64 {
    (offset << 32) ^ u64::from(tid)
}

fn ssl_read_lib_kind(elf_path: Option<&str>) -> SslReadLibKind {
    let path = elf_path.unwrap_or("").to_ascii_lowercase();
    if path.contains("libopenssl") || path.contains("libcurl") {
        // CCB libcurl.so embeds OpenSSL; LOCAL .symtab SSL_read is the same ABI.
        SslReadLibKind::Openssl
    } else if path.contains("conscrypt") {
        SslReadLibKind::Conscrypt
    } else {
        SslReadLibKind::Other
    }
}

fn tls_decode_should_attempt(requested: i32, snapshot: &[u8]) -> bool {
    requested > 0 || !snapshot.is_empty()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn tls_write_snapshot(hit: &ksight_hwbp::RegisterContext) -> &[u8] {
    let n = usize::try_from(hit.aux_bytes)
        .unwrap_or(0)
        .min(hit.aux.len());
    &hit.aux[..n]
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn ssl_read_captured(pending: &PendingSslRead, hit: &ksight_hwbp::RegisterContext) -> Option<i32> {
    let requested = pending.requested.max(0);
    if let Some(ptr) = pending.written_ptr.filter(|ptr| *ptr >= 0x1000) {
        // SSL_*_ex: x0==0 means failure. Do NOT `?` away the whole decode when
        // *written is briefly unreadable — Alipay BABASSL then loses SSL_read
        // entirely (reconstructed_responses=0 while requests still flow).
        if hit.regs[0] == 0 {
            return None;
        }
        if let Some(raw) = read_remote_bytes(pending.pid, ptr, 8) {
            if let Some(arr) = raw.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) {
                let n = i32::try_from(u64::from_le_bytes(arr)).unwrap_or(0);
                if n > 0 {
                    return Some(n.min(requested));
                }
                // *written == 0 is a real empty read — do not invent `requested`
                // bytes (Alipay BABASSL SSL_read_ex then all-zero-dropped).
                return None;
            }
        }
        // Fallbacks only when *written is unreadable but the call succeeded:
        // - retval > 1 ⇒ byte-count ABI (some forks);
        // - retval == 1 ⇒ OpenSSL-style success → use requested as ceiling;
        //   aux near-miss / all-zero reject still gate emit.
        let retval = i64::from(hit.regs[0] as i32);
        if retval > 1 {
            return Some(i32::try_from(retval).unwrap_or(0).min(requested));
        }
        if retval == 1 && requested > 0 {
            return Some(requested);
        }
        return None;
    }
    let retval = i64::from(hit.regs[0] as i32);
    if retval <= 0 {
        return None;
    }
    Some(i32::try_from(retval).unwrap_or(0).min(requested))
}

#[allow(dead_code)]
fn jni_bytes_worth_keeping(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().any(|byte| *byte != 0)
}

/// `GetByteArrayElements` does not return a length. Stop at 8 NULs so we do not
/// copy the following heap (pointers / allocator padding) as if it were the array.
#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn clip_jni_elements(bytes: &[u8]) -> &[u8] {
    const RUN: usize = 8;
    if bytes.len() < RUN {
        return bytes;
    }
    match bytes
        .windows(RUN)
        .position(|window| window.iter().all(|byte| *byte == 0))
    {
        Some(index) => &bytes[..index],
        None => bytes,
    }
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
    match bytes.iter().rposition(|byte| *byte != 0) {
        Some(end) => &bytes[..=end],
        None => &[],
    }
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn keep_jni_elements(bytes: &[u8]) -> bool {
    keep_jni_plaintext(bytes)
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// JNI UTF-8 / `byte[]` is kept only when it names an HTTP/JSON interface.
/// Webpack, hex, `ComponentInfo`, and APK paths are not interfaces.
#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn keep_jni_plaintext(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let mut zeros = 0_usize;
    for byte in bytes {
        zeros += usize::from(*byte == 0);
    }
    if zeros.saturating_mul(2) >= bytes.len() {
        return false;
    }
    if bytes.starts_with(b"HTTP/")
        || bytes.starts_with(b"GET ")
        || bytes.starts_with(b"POST ")
        || bytes.starts_with(b"PK")
        || ksight_core::looks_like_gzip(bytes)
    {
        return true;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if printable.saturating_mul(4) < bytes.len().saturating_mul(3) {
        return false;
    }
    if bytes_contains(bytes, b"https://") || bytes_contains(bytes, b"http://") {
        return true;
    }
    if bytes_contains(bytes, b"ComponentInfo{")
        || bytes_contains(bytes, b"];a(")
        || bytes_contains(bytes, b"function(")
    {
        return false;
    }
    bytes_contains(bytes, b"\"url\"")
        || bytes_contains(bytes, b"\"host\"")
        || bytes_contains(bytes, b"\"path\"")
        || bytes_contains(bytes, b"/api/")
        || bytes_contains(bytes, b"/v1/")
        || bytes_contains(bytes, b"/v2/")
        || bytes_contains(bytes, b"/v3/")
}

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn classify_buffer(bytes: &[u8]) -> &'static str {
    if http1_prefix(bytes) {
        return "text";
    }
    // TLS record header must beat loose HTTP/2 mid-buffer sync: short
    // application-data records (0x17 0x03 0x03 …) can look like a HEADERS
    // frame at offset 3 and would otherwise misclassify as "binary".
    if bytes.len() >= 3 {
        let record = bytes[0];
        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        if matches!(record, 0x14..=0x17) && matches!(version, 0x0301..=0x0304) {
            return "tls_record";
        }
    }
    if ksight_core::looks_like_http2(bytes) {
        return "binary";
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

#[cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
fn http1_prefix(bytes: &[u8]) -> bool {
    const STARTS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"CONNECT ",
        b"HTTP/1.0",
        b"HTTP/1.1",
    ];
    STARTS.iter().any(|needle| bytes.starts_with(needle))
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
    let count = usize::try_from(units).ok()?.min(JNI_UTF16_UNITS_CAP);
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
#[path = "tests.rs"]
mod tests;
