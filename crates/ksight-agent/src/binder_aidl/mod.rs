#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::unreadable_literal, clippy::too_many_lines)]
//! Pixel 6a Android 14 Binder `Stub.TRANSACTION_*` names from on-device framework JARs.
//! App and GMS AIDL are not included. Unknown `(interface, code)` stays unnamed.

/// Look up an AOSP AIDL method for `FIRST_CALL_TRANSACTION + n` codes.
pub fn aidl_method(interface: &str, code: u32) -> Option<&'static str> {
    if let Some(name) = ndk_meta_method(code) {
        return Some(name);
    }
    let names = extra_hal(interface).or_else(|| table(interface))?;
    let index = usize::try_from(code.checked_sub(1)?).ok()?;
    names.get(index).copied().filter(|name| !name.is_empty())
}

/// NDK AIDL `IBinder::LAST_CALL_TRANSACTION` / `- 1`. Same codes on every
/// HAL interface; not a per-app table.
fn ndk_meta_method(code: u32) -> Option<&'static str> {
    match code {
        0x00ff_fffe => Some("getInterfaceHash"),
        0x00ff_ffff => Some("getInterfaceVersion"),
        _ => None,
    }
}

/// NDK/HAL AIDL not present as Java `$Stub.TRANSACTION_*` on this image.
///
/// Tables come from Pixel 6a binaries: NDK `kTransactionNames` pointer
/// arrays, or `Bn*::onTransact` switch + Parcel shape. Methods are not
/// guessed from a mismatched AOSP tag.
fn extra_hal(interface: &str) -> Option<&'static [&'static str]> {
    match interface {
        "android.graphicsenv.IGpuService" => Some(&[
            "setGpuStats",
            "setTargetStats",
            "setUpdatableDriverPath",
            "getUpdatableDriverPath",
            "toggleAngleAsSystemDriver",
            "setTargetStatsArray",
            "addVulkanEngineName",
            "getAngleFeatureOverrides",
        ]),
        "android.hardware.drm.IDrmFactory" => Some(&[
            "createDrmPlugin",
            "createCryptoPlugin",
            "getSupportedCryptoSchemes",
        ]),
        "android.hardware.graphics.allocator.IAllocator" => Some(&[
            "allocate",
            "allocate2",
            "isSupported",
            "getIMapperLibrarySuffix",
        ]),
        "android.hardware.media.c2.IComponent" => Some(&[
            "configureVideoTunnel",
            "createBlockPool",
            "destroyBlockPool",
            "drain",
            "flush",
            "getInterface",
            "queue",
            "release",
            "reset",
            "setDecoderOutputAllocator",
            "start",
            "stop",
        ]),
        // Pixel 6a `BnMediaCodecList::onTransact`: code 1 is not a user
        // method (falls through); 2–6 match Parcel shape + vtable.
        "android.media.IMediaCodecList" => Some(&[
            "",
            "countCodecs",
            "getCodecInfo",
            "getGlobalSettings",
            "findCodecByType",
            "findCodecByName",
        ]),
        // Pixel 6a `mediametricsservice-aidl-cpp.so`: only `submitBuffer`.
        "android.media.IMediaMetricsService" => Some(&["submitBuffer"]),
        _ => None,
    }
}

fn table(interface: &str) -> Option<&'static [&'static str]> {
    let i = TABLES.binary_search_by_key(&interface, |entry| entry.0).ok()?;
    Some(TABLES[i].1)
}

mod tables;
pub(crate) use tables::TABLES;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
