//! Repair dumped DEX containers without merging unrelated files.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Result of stripping trailing packer payload from a DEX file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexRepair {
    /// Bytes that form a self-consistent DEX (`file_size` matches the buffer).
    pub bytes: Vec<u8>,
    /// Bytes discarded after the logical DEX (`data_off + data_size`).
    pub truncated_extra: u64,
}

/// One concatenated DEX image found inside a larger blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexSlice {
    /// Byte offset of this image in the input buffer.
    pub offset: u64,
    /// Self-contained DEX bytes (`file_size` long).
    pub bytes: Vec<u8>,
}

/// Bounded semantic index read from one standard DEX header and its ID tables.
///
/// The collector keeps independent DEX containers. This summary lets clients
/// search and compare the logical multidex set without rewriting evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexSemanticSummary {
    /// Three-digit DEX version, such as `035` or `039`.
    pub version: String,
    /// File size declared by the DEX header.
    pub declared_file_size: u64,
    /// Number of string IDs declared in the header.
    pub string_ids: u32,
    /// Number of type IDs declared in the header.
    pub type_ids: u32,
    /// Number of field IDs declared in the header.
    pub field_ids: u32,
    /// Number of method IDs declared in the header.
    pub method_ids: u32,
    /// Number of class definitions declared in the header.
    pub class_defs: u32,
    /// Bounded class-descriptor index for package-wide lookup and conflicts.
    pub class_descriptors: Vec<String>,
    /// True when more descriptors existed than were published.
    pub class_descriptors_truncated: bool,
    /// Bounded `class->method` names, without claiming call relationships.
    pub method_names: Vec<String>,
    /// True when more method names existed than were published.
    pub method_names_truncated: bool,
}

const DEX_SEMANTIC_SAMPLE_LIMIT: usize = 1024;

/// Parse a bounded semantic index from a standard little-endian DEX image.
///
/// This validates all offsets before reading them and returns `None` for CDEX,
/// VDEX, incomplete snapshots, or malformed tables. It does not infer load
/// order, `ClassLoader` ownership, or method call relationships.
#[must_use]
pub fn parse_dex_semantics(bytes: &[u8]) -> Option<DexSemanticSummary> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") || bytes.get(7) != Some(&0) {
        return None;
    }
    if read_dex_u32(bytes, 40)? != 0x1234_5678 {
        return None;
    }
    let declared_file_size = read_dex_u32(bytes, 32)?;
    if declared_file_size < 0x70 || usize::try_from(declared_file_size).ok()? > bytes.len() {
        return None;
    }
    let string_ids = read_dex_u32(bytes, 56)?;
    let string_ids_off = read_dex_u32(bytes, 60)?;
    let type_ids = read_dex_u32(bytes, 64)?;
    let type_ids_off = read_dex_u32(bytes, 68)?;
    let field_ids = read_dex_u32(bytes, 80)?;
    let method_ids = read_dex_u32(bytes, 88)?;
    let method_ids_off = read_dex_u32(bytes, 92)?;
    let class_defs = read_dex_u32(bytes, 96)?;
    let class_defs_off = read_dex_u32(bytes, 100)?;
    validate_dex_table(bytes, string_ids_off, string_ids, 4)?;
    validate_dex_table(bytes, type_ids_off, type_ids, 4)?;
    validate_dex_table(bytes, method_ids_off, method_ids, 8)?;
    validate_dex_table(bytes, class_defs_off, class_defs, 32)?;

    let string_at = |index: u32| -> Option<String> {
        if index >= string_ids {
            return None;
        }
        let entry = usize::try_from(string_ids_off)
            .ok()?
            .checked_add(usize::try_from(index).ok()?.checked_mul(4)?)?;
        let data_off = read_dex_u32(bytes, entry)?;
        read_dex_string(bytes, usize::try_from(data_off).ok()?)
    };
    let descriptor_at = |type_index: u32| -> Option<String> {
        if type_index >= type_ids {
            return None;
        }
        let entry = usize::try_from(type_ids_off)
            .ok()?
            .checked_add(usize::try_from(type_index).ok()?.checked_mul(4)?)?;
        string_at(read_dex_u32(bytes, entry)?)
    };

    let mut class_descriptors = Vec::new();
    for index in 0..class_defs {
        if class_descriptors.len() >= DEX_SEMANTIC_SAMPLE_LIMIT {
            break;
        }
        let entry = usize::try_from(class_defs_off)
            .ok()?
            .checked_add(usize::try_from(index).ok()?.checked_mul(32)?)?;
        if let Some(descriptor) = descriptor_at(read_dex_u32(bytes, entry)?) {
            class_descriptors.push(descriptor);
        }
    }
    class_descriptors.sort();
    class_descriptors.dedup();

    let mut method_names = Vec::new();
    for index in 0..method_ids {
        if method_names.len() >= DEX_SEMANTIC_SAMPLE_LIMIT {
            break;
        }
        let entry = usize::try_from(method_ids_off)
            .ok()?
            .checked_add(usize::try_from(index).ok()?.checked_mul(8)?)?;
        let class_idx = u32::from(read_dex_u16(bytes, entry)?);
        let name_idx = read_dex_u32(bytes, entry.checked_add(4)?)?;
        if let (Some(class), Some(name)) = (descriptor_at(class_idx), string_at(name_idx)) {
            method_names.push(format!("{class}->{name}"));
        }
    }
    method_names.sort();
    method_names.dedup();

    Some(DexSemanticSummary {
        version: String::from_utf8_lossy(&bytes[4..7]).into_owned(),
        declared_file_size: u64::from(declared_file_size),
        string_ids,
        type_ids,
        field_ids,
        method_ids,
        class_defs,
        class_descriptors,
        class_descriptors_truncated: usize::try_from(class_defs).unwrap_or(usize::MAX)
            > DEX_SEMANTIC_SAMPLE_LIMIT,
        method_names,
        method_names_truncated: usize::try_from(method_ids).unwrap_or(usize::MAX)
            > DEX_SEMANTIC_SAMPLE_LIMIT,
    })
}

fn read_dex_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_dex_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn validate_dex_table(bytes: &[u8], offset: u32, count: u32, width: usize) -> Option<()> {
    if count == 0 {
        return Some(());
    }
    let start = usize::try_from(offset).ok()?;
    let length = usize::try_from(count).ok()?.checked_mul(width)?;
    (start >= 0x70 && start.checked_add(length)? <= bytes.len()).then_some(())
}

fn read_dex_string(bytes: &[u8], offset: usize) -> Option<String> {
    let mut cursor = offset;
    for _ in 0..5 {
        let byte = *bytes.get(cursor)?;
        cursor = cursor.checked_add(1)?;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let tail = bytes.get(cursor..)?;
    let length = tail.iter().position(|byte| *byte == 0)?;
    (length <= 16 * 1024).then(|| String::from_utf8_lossy(&tail[..length]).into_owned())
}

/// SecNeo/DexHelper `dexdata0` container parsed out of an appended payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecNeoDexData {
    /// Number of named blobs in the header.
    pub count: u32,
    /// Vendor blob name, usually `dexdata0`.
    pub name: String,
    /// Encrypted or VM-wrapped body after the ASCII name.
    pub body: Vec<u8>,
}

/// A native library or DEX taken from APK `assets/` (or other non-`lib/` zip paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkPackedFile {
    /// Zip entry path, for example `assets/ijm_lib/arm64-v8a/libexec.so`.
    pub zip_name: String,
    /// Sanitized filename written under the extract directory.
    pub output_name: String,
    /// Uncompressed size.
    pub bytes: u64,
}

/// One `classes*.dex` taken from an APK, plus an optional repaired stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexExtract {
    /// Zip entry name, for example `classes.dex`.
    pub name: String,
    /// Uncompressed size of the zip entry.
    pub original_bytes: u64,
    /// Bytes kept after stripping an appended packer blob.
    pub kept_bytes: u64,
    /// Bytes written to `{name}.payload` when the entry is a stub plus ciphertext.
    pub payload_bytes: u64,
}

/// True when `bytes` starts with a DEX or compact-DEX magic.
#[must_use]
pub fn is_dex_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"dex\n") || bytes.starts_with(b"dey\n") || bytes.starts_with(b"cdex")
}

/// True when `bytes` starts with VDEX magic (`vdex` + three ASCII version digits).
#[must_use]
pub fn is_vdex_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes.starts_with(b"vdex")
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
}

/// Truncate appended ciphertext and rewrite `file_size`. Does not merge DEX files.
///
/// Packers often leave a valid ~few-MB DEX and glue tens of MB of encrypted
/// payload onto the same zip/file entry. Tools then see a 100MB "classes.dex"
/// that is not a single container. Each input file is repaired independently.
#[must_use]
pub fn repair_dex(input: &[u8]) -> Option<DexRepair> {
    if input.len() < 0x70 || !(input.starts_with(b"dex\n") || input.starts_with(b"dey\n")) {
        return None;
    }
    let endian = u32::from_le_bytes(input[40..44].try_into().ok()?);
    if endian != 0x1234_5678 {
        return None;
    }
    let declared = u32::from_le_bytes(input[32..36].try_into().ok()?) as usize;
    let map_off = u32::from_le_bytes(input[52..56].try_into().ok()?) as usize;
    let data_size = u32::from_le_bytes(input[104..108].try_into().ok()?) as usize;
    let data_off = u32::from_le_bytes(input[108..112].try_into().ok()?) as usize;
    let logical = data_off
        .saturating_add(data_size)
        .max(map_off.saturating_add(4))
        .max(0x70);
    if logical > input.len() {
        let mut bytes = input.to_vec();
        let size = u32::try_from(bytes.len()).ok()?;
        bytes[32..36].copy_from_slice(&size.to_le_bytes());
        return Some(DexRepair {
            truncated_extra: 0,
            bytes,
        });
    }
    let extra_beyond_logical = declared
        .saturating_sub(logical)
        .max(input.len().saturating_sub(logical));
    let keep = if extra_beyond_logical > 4096 && declared > logical {
        logical.min(input.len())
    } else {
        declared.min(input.len()).max(logical.min(input.len()))
    };
    let mut bytes = input[..keep].to_vec();
    let size = u32::try_from(bytes.len()).ok()?;
    bytes[32..36].copy_from_slice(&size.to_le_bytes());
    Some(DexRepair {
        truncated_extra: u64::try_from(input.len().saturating_sub(keep)).unwrap_or(0),
        bytes,
    })
}

/// Repair every `*.dex` in `dir` into `dir/repaired/`, keeping original names.
///
/// # Errors
///
/// Returns filesystem errors; invalid DEX files are skipped.
pub fn repair_dex_dir(dir: &std::path::Path) -> std::io::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let repaired_dir = dir.join("repaired");
    std::fs::create_dir_all(&repaired_dir)?;
    let mut count = 0_usize;
    let entries: Vec<_> = std::fs::read_dir(dir)?.flatten().collect();
    for entry in entries {
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
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Some(repaired) = repair_dex(&bytes) else {
            continue;
        };
        std::fs::write(repaired_dir.join(name), repaired.bytes)?;
        count += 1;
    }
    Ok(count)
}

/// Extract every `*.dex` from an APK, repair stubs, and keep leftover packer payload.
///
/// Writes `dest/<filename>`, `dest/repaired/<filename>` when repair succeeds, and
/// `dest/<filename>.payload` when more than 4 KiB was appended after the logical DEX.
///
/// # Errors
///
/// Returns filesystem or zip errors. Individual entries that are not DEX images are skipped.
pub fn extract_apk_dex(apk: &Path, dest: &Path) -> std::io::Result<Vec<DexExtract>> {
    let file = std::fs::File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::create_dir_all(dest)?;
    let repaired_dir = dest.join("repaired");
    std::fs::create_dir_all(&repaired_dir)?;
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if !entry.is_file() {
            continue;
        }
        let entry_name = entry.name().to_owned();
        if !Path::new(&entry_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"))
        {
            continue;
        }
        let uncompressed = entry.size();
        if uncompressed == 0 || uncompressed > 256 * 1024 * 1024 {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        drop(entry);
        if !is_dex_magic(&bytes) {
            continue;
        }
        let output_name = unique_dex_name(dest, &entry_name);
        std::fs::write(dest.join(&output_name), &bytes)?;
        let mut kept_bytes = u64::try_from(bytes.len()).unwrap_or(0);
        let mut payload_bytes = 0_u64;
        if let Some(repaired) = repair_dex(&bytes) {
            kept_bytes = u64::try_from(repaired.bytes.len()).unwrap_or(0);
            if repaired.truncated_extra > 4096 {
                let payload = &bytes[repaired.bytes.len()..];
                payload_bytes = u64::try_from(payload.len()).unwrap_or(0);
                let mut payload_file =
                    std::fs::File::create(dest.join(format!("{output_name}.payload")))?;
                payload_file.write_all(payload)?;
            }
            std::fs::write(repaired_dir.join(&output_name), repaired.bytes)?;
        }
        let slices = split_concatenated_dex(&bytes);
        if slices.len() > 1 {
            let split_dir = dest.join(format!("{output_name}-split"));
            std::fs::create_dir_all(&split_dir)?;
            for (index, slice) in slices.iter().enumerate() {
                let part = format!("part{index:02}.dex");
                std::fs::write(split_dir.join(&part), &slice.bytes)?;
                if let Some(repaired) = repair_dex(&slice.bytes) {
                    std::fs::write(
                        repaired_dir.join(format!("{output_name}-part{index:02}.dex")),
                        repaired.bytes,
                    )?;
                }
            }
        }
        if let Some(dexdata) = parse_secneo_dexdata(
            bytes
                .get(usize::try_from(kept_bytes).unwrap_or(0)..)
                .unwrap_or(&[]),
        ) {
            std::fs::write(dest.join(format!("{output_name}.dexdata0")), &dexdata.body)?;
        }
        extracted.push(DexExtract {
            name: output_name,
            original_bytes: uncompressed,
            kept_bytes,
            payload_bytes,
        });
    }
    let readable = dest.parent().map_or_else(
        || dest.join("readable-dex"),
        |parent| parent.join("readable-dex"),
    );
    let _ = publish_apk_dex_splits(dest, &readable);
    Ok(extracted)
}

/// Copy packer/native files that the installer does not unpack into `/data/app/.../lib`.
///
/// Ijiami and similar wrappers keep `libexec.so` / `libexecmain.so` under `assets/ijm_lib/`.
/// Those never appear in the install `lib/` tree, so a dump that only copies `lib/` misses them.
///
/// # Errors
///
/// Returns filesystem or zip errors. Oversized or non-file entries are skipped.
pub fn extract_apk_packed_native(apk: &Path, dest: &Path) -> std::io::Result<Vec<ApkPackedFile>> {
    let file = std::fs::File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::create_dir_all(dest)?;
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if !entry.is_file() {
            continue;
        }
        let entry_name = entry.name().to_owned();
        if !keep_packed_zip_entry(&entry_name) {
            continue;
        }
        let uncompressed = entry.size();
        if uncompressed == 0 || uncompressed > 48 * 1024 * 1024 {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        drop(entry);
        let output_name = packed_output_name(&entry_name);
        let target = dest.join(&output_name);
        if target.exists() {
            continue;
        }
        std::fs::write(&target, &bytes)?;
        extracted.push(ApkPackedFile {
            zip_name: entry_name,
            output_name,
            bytes: u64::try_from(bytes.len()).unwrap_or(0),
        });
    }
    Ok(extracted)
}

/// Copy `lib/<abi>/*.so` from an APK, including Play Feature/split APKs.
///
/// App Bundles often ship native code only in `split_config.arm64_v8a.apk`, so the
/// install `lib/` tree is empty. This does not replace assets packer SO extraction.
///
/// # Errors
///
/// Returns filesystem or zip errors. Existing files are left unchanged.
pub fn extract_apk_native_libs(apk: &Path, dest: &Path) -> std::io::Result<Vec<ApkPackedFile>> {
    let file = std::fs::File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if !entry.is_file() {
            continue;
        }
        let entry_name = entry.name().replace('\\', "/");
        let lower = entry_name.to_ascii_lowercase();
        if !lower.starts_with("lib/")
            || !Path::new(&lower)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            continue;
        }
        let uncompressed = entry.size();
        if uncompressed == 0 || uncompressed > 128 * 1024 * 1024 {
            continue;
        }
        let Some(relative) = apk_lib_install_relative(&entry_name) else {
            continue;
        };
        let target = dest.join(&relative);
        if target.exists() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        drop(entry);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, &bytes)?;
        extracted.push(ApkPackedFile {
            zip_name: entry_name,
            output_name: relative,
            bytes: u64::try_from(bytes.len()).unwrap_or(0),
        });
    }
    Ok(extracted)
}

/// Map zip `lib/<abi>/...` onto the installer ISA directory (`arm64-v8a` → `arm64`).
fn apk_lib_install_relative(entry_name: &str) -> Option<String> {
    let normalized = entry_name.replace('\\', "/");
    let rest = normalized.strip_prefix("lib/")?;
    let (abi, tail) = rest.split_once('/')?;
    if tail.is_empty() {
        return None;
    }
    let isa = match abi {
        "arm64-v8a" => "arm64",
        "armeabi-v7a" | "armeabi" => "arm",
        other => other,
    };
    let relative = format!("{isa}/{tail}");
    if Path::new(&relative).components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return None;
    }
    Some(relative)
}

fn keep_packed_zip_entry(zip_name: &str) -> bool {
    let lower = zip_name.to_ascii_lowercase().replace('\\', "/");
    if lower.starts_with("lib/") {
        return false;
    }
    let file_name = Path::new(&lower)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let ext = Path::new(file_name).extension();
    let ext_so = ext.is_some_and(|value| value.eq_ignore_ascii_case("so"));
    let ext_dex = ext.is_some_and(|value| value.eq_ignore_ascii_case("dex"));
    let packer = [
        "libexec",
        "execmain",
        "ijm",
        "dexhelper",
        "dexjni",
        "secneo",
        "apkwrapper",
        "apkprotect",
        "jiagu",
        "legu",
        "qihoo",
        "qvm",
        "naga",
        "bangcle",
        "baiduprotect",
        "shella",
        "sgmain",
        "loaddex",
    ]
    .iter()
    .any(|needle| file_name.contains(needle) || lower.contains(needle));
    (lower.starts_with("assets/") && (ext_so || ext_dex || packer)) || packer && ext_so
}

fn packed_output_name(zip_name: &str) -> String {
    zip_name.replace(['/', '\\'], "_")
}

/// Find every self-consistent `dex\n` image in `input`, including files glued after a stub.
#[must_use]
pub fn split_concatenated_dex(input: &[u8]) -> Vec<DexSlice> {
    let mut slices = Vec::new();
    let mut index = 0_usize;
    while index.saturating_add(0x70) <= input.len() {
        match next_dex_image(input, index) {
            Some((at, len)) => {
                slices.push(DexSlice {
                    offset: u64::try_from(at).unwrap_or(0),
                    bytes: input[at..at.saturating_add(len)].to_vec(),
                });
                index = at.saturating_add(len);
            }
            None => break,
        }
    }
    slices
}

fn next_dex_image(input: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut search = from;
    while search.saturating_add(0x70) <= input.len() {
        let rel = find_dex_magic(&input[search..])?;
        let at = search.saturating_add(rel);
        if at.saturating_add(0x70) > input.len() {
            return None;
        }
        if let Some(len) = valid_dex_len(&input[at..]) {
            return Some((at, len));
        }
        search = at.saturating_add(4);
    }
    None
}

fn find_dex_magic(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"dex\n")
}

fn valid_dex_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") {
        return None;
    }
    let endian = u32::from_le_bytes(bytes[40..44].try_into().ok()?);
    if endian != 0x1234_5678 {
        return None;
    }
    let declared = u32::from_le_bytes(bytes[32..36].try_into().ok()?) as usize;
    if declared < 0x70 || declared > bytes.len() || declared > 64 * 1024 * 1024 {
        return None;
    }
    Some(declared)
}

/// Parse a vendor `DexHelper` `dexdata0` blob (count + size + name + body).
#[must_use]
pub fn parse_secneo_dexdata(input: &[u8]) -> Option<SecNeoDexData> {
    if input.len() < 16 {
        return None;
    }
    let count = u32::from_le_bytes(input[0..4].try_into().ok()?);
    let _size = u32::from_le_bytes(input[4..8].try_into().ok()?) as usize;
    let name_len = u32::from_le_bytes(input[8..12].try_into().ok()?) as usize;
    if count == 0 || count > 8 || name_len == 0 || name_len > 64 {
        return None;
    }
    let name_at: usize = 12;
    let name_end = name_at.saturating_add(name_len);
    if name_end > input.len() {
        return None;
    }
    let name = std::str::from_utf8(&input[name_at..name_end]).ok()?;
    if !name.starts_with("dexdata") {
        return None;
    }
    let body = input[name_end..].to_vec();
    if body.len() < 16 {
        return None;
    }
    Some(SecNeoDexData {
        count,
        name: name.to_owned(),
        body,
    })
}

/// Decrypt a `dexdata0` body with the 16-byte SM4 key recovered from helper BSS.
///
/// The loader skips the first 4 bytes of the named blob, then SM4-ECB-decrypts 16-byte blocks.
#[must_use]
pub fn decrypt_secneo_dexdata(container: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    let parsed = parse_secneo_dexdata(container)?;
    if parsed.body.len() < 20 {
        return None;
    }
    Some(crate::sm4::decrypt_ecb(key, &parsed.body[4..]))
}

/// Try SM4-ECB with each key, skipping 4, 0, or 8 body bytes, until a DEX magic appears.
#[must_use]
pub fn try_decrypt_secneo(container: &[u8], keys: &[[u8; 16]]) -> Option<Vec<u8>> {
    let parsed = parse_secneo_dexdata(container)?;
    for key in keys {
        if let Some(rest) = secneo_rest_for_key(&parsed.body, key) {
            return Some(trim_to_dex(crate::sm4::decrypt_ecb(key, rest)));
        }
    }
    None
}

/// First 16–32 ciphertext bytes after each candidate skip, from a header prefix.
///
/// `prefix` only needs the `dexdata0` header plus one or two SM4 blocks (~64 bytes).
#[must_use]
pub fn secneo_cipher_probes(prefix: &[u8]) -> Vec<Vec<u8>> {
    let Some(parsed) = parse_secneo_dexdata(prefix) else {
        return Vec::new();
    };
    let mut probes = Vec::new();
    for skip in [4_usize, 0_usize, 8_usize, 12_usize, 16_usize] {
        if parsed.body.len() < skip.saturating_add(16) {
            continue;
        }
        let end = parsed.body.len().min(skip.saturating_add(32));
        let take = (end.saturating_sub(skip) / 16) * 16;
        if take >= 16 {
            probes.push(parsed.body[skip..skip.saturating_add(take)].to_vec());
        }
    }
    probes
}

/// True when `key` decrypts any probe to a DEX magic (at offset 0/4/8/…).
#[must_use]
pub fn key_unlocks_secneo(key: &[u8; 16], probes: &[Vec<u8>]) -> bool {
    for probe in probes {
        if probe.len() < 16 {
            continue;
        }
        let mut block = [0_u8; 16];
        block.copy_from_slice(&probe[..16]);
        let first = crate::sm4::decrypt_block(key, &block);
        if is_dex_magic(&first) {
            return true;
        }
        if probe.len() >= 32 && dex_magic_in(&crate::sm4::decrypt_ecb(key, &probe[..32])) {
            return true;
        }
    }
    false
}

/// Scan `haystack` for a 16-byte SM4 key that decrypts `container` to DEX magic.
///
/// Walks 8-byte aligned windows. Used when the `DexHelper` GOT pointer has already
/// been overwritten and the key only still exists as bytes on the heap.
#[must_use]
pub fn find_secneo_key(container: &[u8], haystack: &[u8]) -> Option<[u8; 16]> {
    let probes = secneo_cipher_probes(container);
    if probes.is_empty() {
        return None;
    }
    scan_sm4_haystack(haystack, &probes, 8, 64_000)
}

/// Fast path: one ciphertext block, one SM4 decrypt per candidate.
#[must_use]
pub fn scan_sm4_one_block(
    haystack: &[u8],
    cipher: &[u8; 16],
    stride: usize,
    max_probes: usize,
) -> Option<[u8; 16]> {
    if stride == 0 {
        return None;
    }
    let mut offset = 0_usize;
    let mut attempts = 0_usize;
    while offset.saturating_add(16) <= haystack.len() && attempts < max_probes {
        let mut key = [0_u8; 16];
        key.copy_from_slice(&haystack[offset..offset.saturating_add(16)]);
        offset = offset.saturating_add(stride);
        if !plausible_sm4_key(&key) {
            continue;
        }
        attempts = attempts.saturating_add(1);
        if is_dex_magic(&crate::sm4::decrypt_block(&key, cipher)) {
            return Some(key);
        }
    }
    None
}

/// Slide a 16-byte window through `haystack` and test each candidate against SM4 probes.
#[must_use]
pub fn scan_sm4_haystack(
    haystack: &[u8],
    probes: &[Vec<u8>],
    stride: usize,
    max_probes: usize,
) -> Option<[u8; 16]> {
    if probes.is_empty() || stride == 0 {
        return None;
    }
    let mut offset = 0_usize;
    let mut attempts = 0_usize;
    while offset.saturating_add(16) <= haystack.len() && attempts < max_probes {
        let mut key = [0_u8; 16];
        key.copy_from_slice(&haystack[offset..offset.saturating_add(16)]);
        offset = offset.saturating_add(stride);
        if !plausible_sm4_key(&key) {
            continue;
        }
        attempts = attempts.saturating_add(1);
        if key_unlocks_secneo(&key, probes) {
            return Some(key);
        }
    }
    None
}

fn secneo_rest_for_key<'a>(body: &'a [u8], key: &[u8; 16]) -> Option<&'a [u8]> {
    for skip in [4_usize, 0_usize, 8_usize, 12_usize, 16_usize] {
        if body.len() < skip.saturating_add(16) {
            continue;
        }
        let rest = &body[skip..];
        let probe_len = rest.len().min(48) / 16 * 16;
        if probe_len < 16 {
            continue;
        }
        let probe = crate::sm4::decrypt_ecb(key, &rest[..probe_len]);
        if dex_magic_in(&probe) {
            return Some(rest);
        }
    }
    None
}

fn dex_magic_in(bytes: &[u8]) -> bool {
    [0_usize, 4, 8, 12, 16, 20, 24]
        .into_iter()
        .any(|at| bytes.len() >= at.saturating_add(4) && is_dex_magic(&bytes[at..]))
}

fn trim_to_dex(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(at) = [0_usize, 4, 8, 12, 16, 20, 24]
        .into_iter()
        .find(|at| bytes.len() >= at.saturating_add(4) && is_dex_magic(&bytes[*at..]))
    {
        bytes.drain(..at);
    }
    bytes
}

fn plausible_sm4_key(key: &[u8; 16]) -> bool {
    if key.iter().all(|byte| *byte == 0) || key.iter().all(|byte| *byte == 0xff) {
        return false;
    }
    let mut seen = [false; 256];
    let mut unique = 0_usize;
    for byte in key {
        let index = usize::from(*byte);
        if !seen[index] {
            seen[index] = true;
            unique = unique.saturating_add(1);
        }
    }
    if unique < 5 {
        return false;
    }
    let first = u64::from_le_bytes(key[0..8].try_into().unwrap_or([0; 8]));
    let second = u64::from_le_bytes(key[8..16].try_into().unwrap_or([0; 8]));
    !(looks_like_user_ptr(first) && looks_like_user_ptr(second))
}

fn looks_like_user_ptr(value: u64) -> bool {
    (0x6_0000_0000..=0x00ff_ffff_ffff).contains(&value)
}

/// Write jadxable DEX images to `dest/apk-dex/split/` and `dest/readable-dex/`.
///
/// Concatenated APK DEX is split into one file per `dex` image. A pull of
/// `/data/local/tmp/ksight/packages/<pkg>/` then contains readable DEX even when
/// `repaired/` only kept the stub.
///
/// # Errors
///
/// Returns filesystem errors. Invalid DEX files are skipped.
pub fn publish_readable_dex(dest: &Path) -> std::io::Result<usize> {
    let apk_dex = dest.join("apk-dex");
    let readable = dest.join("readable-dex");
    let mut count = publish_apk_dex_splits(&apk_dex, &readable)?;
    count = count.saturating_add(publish_runtime_dex(&dest.join("runtime"), &readable)?);
    Ok(count)
}

fn publish_apk_dex_splits(apk_dex: &Path, readable: &Path) -> std::io::Result<usize> {
    if !apk_dex.is_dir() {
        return Ok(0);
    }
    let split_dir = apk_dex.join("split");
    std::fs::create_dir_all(&split_dir)?;
    std::fs::create_dir_all(readable)?;
    let mut count = 0_usize;
    let entries: Vec<_> = std::fs::read_dir(apk_dex)?.flatten().collect();
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.to_ascii_lowercase().ends_with(".dex") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        count = count.saturating_add(write_split_parts(name, &bytes, &split_dir, readable)?);
    }
    Ok(count)
}

fn publish_runtime_dex(runtime: &Path, readable: &Path) -> std::io::Result<usize> {
    if !runtime.is_dir() {
        return Ok(0);
    }
    std::fs::create_dir_all(readable)?;
    let mut count = 0_usize;
    for folder in [runtime.to_path_buf(), runtime.join("repaired")] {
        if !folder.is_dir() {
            continue;
        }
        let prefix = if folder.ends_with("repaired") {
            "runtime-repaired"
        } else {
            "runtime"
        };
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !name.to_ascii_lowercase().ends_with(".dex") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if !is_dex_magic(&bytes) {
                continue;
            }
            if bytes.len() < 1024 {
                continue;
            }
            let out_name = format!("{prefix}-{name}");
            let slices = split_concatenated_dex(&bytes);
            if slices.len() > 1 {
                count =
                    count.saturating_add(write_split_parts(&out_name, &bytes, readable, readable)?);
                continue;
            }
            std::fs::write(readable.join(&out_name), bytes)?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn write_split_parts(
    name: &str,
    bytes: &[u8],
    split_dir: &Path,
    readable: &Path,
) -> std::io::Result<usize> {
    std::fs::create_dir_all(split_dir)?;
    std::fs::create_dir_all(readable)?;
    let stem = name
        .strip_suffix(".dex")
        .or_else(|| name.strip_suffix(".DEX"))
        .unwrap_or(name);
    let slices = split_concatenated_dex(bytes);
    if slices.len() > 1 {
        for (index, slice) in slices.iter().enumerate() {
            let part_name = format!("{stem}_part{index:02}_{}.dex", slice.offset);
            std::fs::write(split_dir.join(&part_name), &slice.bytes)?;
            if split_dir != readable {
                std::fs::write(readable.join(&part_name), &slice.bytes)?;
            }
        }
        return Ok(slices.len());
    }
    if let Some(slice) = slices.first() {
        let out_name = format!("{stem}.dex");
        std::fs::write(split_dir.join(&out_name), &slice.bytes)?;
        if split_dir != readable {
            std::fs::write(readable.join(&out_name), &slice.bytes)?;
        }
        return Ok(1);
    }
    if is_dex_magic(bytes) {
        let body = repair_dex(bytes).map_or_else(|| bytes.to_vec(), |repaired| repaired.bytes);
        let out_name = format!("{stem}.dex");
        std::fs::write(split_dir.join(&out_name), &body)?;
        if split_dir != readable {
            std::fs::write(readable.join(&out_name), &body)?;
        }
        return Ok(1);
    }
    Ok(0)
}

fn unique_dex_name(dest: &Path, zip_name: &str) -> String {
    let file_name = Path::new(zip_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("classes.dex");
    if !dest.join(file_name).exists() {
        return file_name.to_owned();
    }
    zip_name.replace(['/', '\\'], "_")
}

/// Repair DEX files under `dir` and every `*.apk` beside or beneath it.
///
/// # Errors
///
/// Returns filesystem errors; invalid DEX/APK files are skipped.
pub fn repair_package_dir(dir: &Path) -> std::io::Result<usize> {
    let mut count = repair_dex_dir(dir)?;
    let mut apks = Vec::<PathBuf>::new();
    collect_apks(dir, &mut apks, 0)?;
    for apk in apks {
        let stem = apk
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("apk");
        let dest = apk.parent().unwrap_or(dir).join(format!("{stem}-dex"));
        count = count.saturating_add(extract_apk_dex(&apk, &dest)?.len());
    }
    Ok(count)
}

fn collect_apks(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) -> std::io::Result<()> {
    if depth > 6 || !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_apks(&path, out, depth.saturating_add(1))?;
            continue;
        }
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("apk"))
        {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with(file_size: u32, map_off: u32, data_size: u32, data_off: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x70];
        bytes[..8].copy_from_slice(b"dex\n035\0");
        bytes[32..36].copy_from_slice(&file_size.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x70_u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&map_off.to_le_bytes());
        bytes[104..108].copy_from_slice(&data_size.to_le_bytes());
        bytes[108..112].copy_from_slice(&data_off.to_le_bytes());
        bytes
    }

    #[test]
    fn strips_appended_payload_and_rewrites_file_size() {
        let logical: usize = 0x70 + 4096;
        let mut input = header_with(100_000, u32::try_from(logical - 4).unwrap(), 4096, 0x70);
        input.resize(logical, 0x11);
        input.extend(vec![0xAA; 50_000]);
        let repaired = repair_dex(&input).expect("dex");
        assert_eq!(repaired.bytes.len(), logical);
        assert_eq!(repaired.truncated_extra, 50_000);
        let size = u32::from_le_bytes(repaired.bytes[32..36].try_into().unwrap());
        assert_eq!(size as usize, logical);
    }

    #[test]
    fn leaves_self_consistent_dex_alone() {
        let mut input = header_with(0x70, 0x70, 0, 0x70);
        input.resize(0x70, 0);
        let repaired = repair_dex(&input).expect("dex");
        assert_eq!(repaired.truncated_extra, 0);
        assert_eq!(repaired.bytes.len(), 0x70);
    }

    #[test]
    fn indexes_standard_dex_without_merging_it() {
        let bytes = header_with(0x70, 0x70, 0, 0x70);
        let summary = parse_dex_semantics(&bytes).expect("semantic header");
        assert_eq!(summary.version, "035");
        assert_eq!(summary.declared_file_size, 0x70);
        assert_eq!(summary.class_defs, 0);
        assert!(summary.class_descriptors.is_empty());
        assert!(parse_dex_semantics(b"cdex001\0").is_none());
    }

    #[test]
    fn accepts_compact_dex_and_vdex_magic() {
        assert!(is_dex_magic(b"cdex001\0"));
        assert!(is_vdex_magic(b"vdex027\0"));
        assert!(!is_vdex_magic(b"vdex\0\0\0\0"));
        assert!(!is_vdex_magic(b"dex\n035\0"));
    }

    #[test]
    fn extracts_and_repairs_apk_dex_entries() {
        let dir = std::env::temp_dir().join(format!("ksight-apk-dex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp");
        let logical: usize = 0x70 + 4096;
        let mut dex = header_with(100_000, u32::try_from(logical - 4).unwrap(), 4096, 0x70);
        dex.resize(logical, 0x11);
        dex.extend(vec![0xAA; 8_192]);
        let apk = dir.join("app.apk");
        {
            let file = std::fs::File::create(&apk).expect("apk");
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("classes.dex", options).expect("entry");
            zip.write_all(&dex).expect("write dex");
            zip.finish().expect("finish");
        }
        let extracted = extract_apk_dex(&apk, &dir.join("out")).expect("extract");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].kept_bytes, u64::try_from(logical).unwrap());
        assert_eq!(extracted[0].payload_bytes, 8_192);
        assert!(dir.join("out/repaired/classes.dex").is_file());
        assert!(dir.join("out/classes.dex.payload").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extracts_ijiami_libexec_from_assets_not_install_lib() {
        let dir = std::env::temp_dir().join(format!("ksight-apk-assets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp");
        let apk = dir.join("app.apk");
        let mut elf = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        elf.resize(64, 0x11);
        {
            let file = std::fs::File::create(&apk).expect("apk");
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("assets/ijm_lib/arm64-v8a/libexec.so", options)
                .expect("exec");
            zip.write_all(&elf).expect("write exec");
            zip.start_file("assets/ijm_lib/arm64-v8a/libexecmain.so", options)
                .expect("main");
            zip.write_all(&elf).expect("write main");
            zip.start_file("lib/arm64-v8a/libfoo.so", options)
                .expect("lib");
            zip.write_all(&elf).expect("write lib");
            zip.finish().expect("finish");
        }
        let extracted =
            extract_apk_packed_native(&apk, &dir.join("assets")).expect("extract assets");
        assert_eq!(extracted.len(), 2);
        assert!(dir
            .join("assets/assets_ijm_lib_arm64-v8a_libexec.so")
            .is_file());
        assert!(dir
            .join("assets/assets_ijm_lib_arm64-v8a_libexecmain.so")
            .is_file());
        assert!(!dir.join("assets/lib_arm64-v8a_libfoo.so").exists());
        let libs = extract_apk_native_libs(&apk, &dir.join("lib")).expect("extract lib");
        assert_eq!(libs.len(), 1);
        assert!(dir.join("lib/arm64/libfoo.so").is_file());
        assert!(!dir.join("lib/arm64-v8a/libfoo.so").exists());
        let again = extract_apk_native_libs(&apk, &dir.join("lib")).expect("skip existing");
        assert!(again.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn splits_concatenated_self_consistent_dex_images() {
        let mut first = header_with(0x70, 0x70, 0, 0x70);
        first.resize(0x70, 0);
        let mut second = header_with(0x70, 0x70, 0, 0x70);
        second.resize(0x70, 1);
        let mut glued = first;
        glued.extend_from_slice(&second);
        let slices = split_concatenated_dex(&glued);
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].offset, 0);
        assert_eq!(slices[1].offset, 0x70);
        assert_eq!(slices[0].bytes.len(), 0x70);
    }

    #[test]
    fn parses_secneo_dexdata0_header() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&1_u32.to_le_bytes());
        blob.extend_from_slice(&32_u32.to_le_bytes());
        blob.extend_from_slice(&8_u32.to_le_bytes());
        blob.extend_from_slice(b"dexdata0");
        blob.extend_from_slice(&[0xAA; 32]);
        let parsed = parse_secneo_dexdata(&blob).expect("dexdata");
        assert_eq!(parsed.name, "dexdata0");
        assert_eq!(parsed.body.len(), 32);
        assert!(parse_secneo_dexdata(b"not a container").is_none());
    }

    #[test]
    fn decrypts_secneo_dexdata_with_sm4_key() {
        let mut dex = header_with(0x70, 0x70, 0, 0x70);
        dex.resize(0x80, 0x11);
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut body = vec![0_u8, 0, 0, 0];
        body.extend(crate::sm4::encrypt_ecb(&key, &dex));
        let mut blob = Vec::new();
        blob.extend_from_slice(&1_u32.to_le_bytes());
        blob.extend_from_slice(&u32::try_from(8 + body.len()).unwrap().to_le_bytes());
        blob.extend_from_slice(&8_u32.to_le_bytes());
        blob.extend_from_slice(b"dexdata0");
        blob.extend_from_slice(&body);
        let plain = try_decrypt_secneo(&blob, &[key]).expect("decrypt");
        assert!(is_dex_magic(&plain));
        assert_eq!(&plain[..8], &dex[..8]);
    }

    #[test]
    fn publishes_concatenated_dex_into_split_dir() {
        let dir = std::env::temp_dir().join(format!("ksight-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let apk_dex = dir.join("apk-dex");
        std::fs::create_dir_all(&apk_dex).expect("temp");
        let mut first = header_with(0x70, 0x70, 0, 0x70);
        first.resize(0x70, 0);
        let mut second = header_with(0x80, 0x70, 0, 0x70);
        second.resize(0x80, 1);
        let mut glued = first;
        glued.extend_from_slice(&second);
        std::fs::write(apk_dex.join("classes.dex"), &glued).expect("write");
        let count = publish_readable_dex(&dir).expect("publish");
        assert_eq!(count, 2);
        assert!(apk_dex.join("split/classes_part00_0.dex").is_file());
        assert!(apk_dex.join("split/classes_part01_112.dex").is_file());
        assert!(dir.join("readable-dex/classes_part00_0.dex").is_file());
        assert!(dir.join("readable-dex/classes_part01_112.dex").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finds_secneo_key_hidden_in_heap_haystack() {
        let mut dex = header_with(0x70, 0x70, 0, 0x70);
        dex.resize(0x80, 0x11);
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut body = vec![0_u8, 0, 0, 0];
        body.extend(crate::sm4::encrypt_ecb(&key, &dex));
        let mut blob = Vec::new();
        blob.extend_from_slice(&1_u32.to_le_bytes());
        blob.extend_from_slice(&u32::try_from(8 + body.len()).unwrap().to_le_bytes());
        blob.extend_from_slice(&8_u32.to_le_bytes());
        blob.extend_from_slice(b"dexdata0");
        blob.extend_from_slice(&body);
        let mut haystack = vec![0x11_u8; 96];
        haystack[40..56].copy_from_slice(&key);
        let found = find_secneo_key(&blob, &haystack).expect("key");
        assert_eq!(found, key);
        assert!(find_secneo_key(&blob, &[0x22; 64]).is_none());
        let probes = secneo_cipher_probes(&blob);
        assert!(!probes.is_empty());
        assert!(key_unlocks_secneo(&key, &probes));
        assert_eq!(scan_sm4_haystack(&haystack, &probes, 8, 64_000), Some(key));
    }
}
