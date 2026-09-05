//! Resolve `JNIEnv` plaintext functions from an exported `GetFunctionTable`.
//!
//! `GetStringUTFChars` / `NewStringUTF` / `GetByteArray*` are not dynsym names
//! on Android 16 libart. They live in `JNINativeInterface` (public `jni.h` ABI).
//! `art::JNIEnvExt::GetFunctionTable(bool)` is exported; its AArch64 ADRP+ADD
//! immediates name the tables in this same ELF. Slots are `jni.h` indices, not
//! ART object-field offsets.

use std::{collections::BTreeSet, fs, path::Path};

use crate::elf::{inspect_elf, matching_symbols};

/// Exported `art::JNIEnvExt::GetFunctionTable(bool)`.
pub const GET_FUNCTION_TABLE: &str = "_ZN3art9JNIEnvExt16GetFunctionTableEb";

/// `jni.h` `JNINativeInterface` slot indices (JNI 1.6, slots 0..=232).
///
/// Complete official table, screened once:
///
/// ```text
/// 0..=3 reserved
/// 4 GetVersion — refuse (no buffer)
/// 5..=12 DefineClass/FindClass/FromReflected*/GetSuperclass/IsAssignableFrom/ToReflected* — refuse (class/reflection)
/// 13..=18 Throw*/Exception*/FatalError — refuse
/// 19..=26 local/global refs, frames — refuse
/// 27..=33 AllocObject/NewObject*/GetObjectClass/IsInstanceOf/GetMethodID — refuse (Java construction)
/// 34..=93 Call*Method / CallNonvirtual* — refuse (Java execution; would need ART frames)
/// 94..=112 GetFieldID / Get*Field / Set*Field — refuse (object field offsets)
/// 113..=162 GetStaticMethodID / CallStatic* / GetStaticFieldID / Get/SetStatic*Field — refuse
/// 163..=166 NewString / GetStringLength / GetStringChars / ReleaseStringChars — attach/pair (UTF-16; Release not attached)
/// 167..=170 NewStringUTF / GetStringUTFLength / GetStringUTFChars / ReleaseStringUTFChars — attach/pair (Release not attached)
/// 171 GetArrayLength — pair
/// 172..=174 NewObjectArray / Get/SetObjectArrayElement — refuse (jobject, would need String fields)
/// 175..=182 New*Array — refuse (returns jobject)
/// 183 GetBooleanArrayElements — refuse (not text)
/// 184 GetByteArrayElements — attach
/// 185 GetCharArrayElements — attach (UTF-16 char[])
/// 186..=190 GetShort/Int/Long/Float/DoubleArrayElements — refuse (numeric arrays)
/// 191..=198 Release*ArrayElements — refuse (copy happens at Get)
/// 199 GetBooleanArrayRegion — refuse
/// 200 GetByteArrayRegion — attach
/// 201 GetCharArrayRegion — attach
/// 202..=206 GetShort/Int/Long/Float/DoubleArrayRegion — refuse
/// 207 SetBooleanArrayRegion — refuse
/// 208 SetByteArrayRegion — attach
/// 209 SetCharArrayRegion — attach
/// 210..=214 SetShort/Int/Long/Float/DoubleArrayRegion — refuse
/// 215 RegisterNatives — attach (name/signature/fnPtr)
/// 216 UnregisterNatives — refuse
/// 217..=219 MonitorEnter/Exit / GetJavaVM — refuse
/// 220 GetStringRegion — attach (UTF-16)
/// 221 GetStringUTFRegion — attach
/// 222 GetPrimitiveArrayCritical — attach (same pairing as Elements; keep filter drops non-text)
/// 223 ReleasePrimitiveArrayCritical — refuse
/// 224 GetStringCritical — attach (UTF-16)
/// 225 ReleaseStringCritical — refuse
/// 226..=228 New/DeleteWeakGlobalRef / ExceptionCheck — refuse
/// 229 NewDirectByteBuffer — refuse (construction)
/// 230 GetDirectBufferAddress — attach
/// 231 GetDirectBufferCapacity — pair
/// 232 GetObjectRefType — refuse
/// ```
pub const SLOT_GET_VERSION: usize = 4;
/// `NewString(jchar const*, jsize)`.
pub const SLOT_NEW_STRING: usize = 163;
/// `GetStringLength`.
pub const SLOT_GET_STRING_LENGTH: usize = 164;
/// `GetStringChars`.
pub const SLOT_GET_STRING_CHARS: usize = 165;
/// `NewStringUTF` slot.
pub const SLOT_NEW_STRING_UTF: usize = 167;
/// `GetStringUTFLength` slot. Pairs with `GetStringUTFChars` by jobject, not ART String fields.
pub const SLOT_GET_STRING_UTF_LENGTH: usize = 168;
/// `GetStringUTFChars` slot.
pub const SLOT_GET_STRING_UTF_CHARS: usize = 169;
/// `GetArrayLength` slot. Pairs with `GetByteArrayElements` by jobject, not ART array fields.
pub const SLOT_GET_ARRAY_LENGTH: usize = 171;
/// `GetByteArrayElements` slot.
pub const SLOT_GET_BYTE_ARRAY_ELEMENTS: usize = 184;
/// `GetCharArrayElements` slot.
pub const SLOT_GET_CHAR_ARRAY_ELEMENTS: usize = 185;
/// `GetByteArrayRegion` slot.
pub const SLOT_GET_BYTE_ARRAY_REGION: usize = 200;
/// `GetCharArrayRegion` slot.
pub const SLOT_GET_CHAR_ARRAY_REGION: usize = 201;
/// `SetByteArrayRegion` slot.
pub const SLOT_SET_BYTE_ARRAY_REGION: usize = 208;
/// `SetCharArrayRegion` slot.
pub const SLOT_SET_CHAR_ARRAY_REGION: usize = 209;
/// `RegisterNatives` slot.
pub const SLOT_REGISTER_NATIVES: usize = 215;
/// `GetStringRegion` slot.
pub const SLOT_GET_STRING_REGION: usize = 220;
/// `GetStringUTFRegion` slot (`start`/`len`/`buf` in AAPCS x2/x3/x4).
pub const SLOT_GET_STRING_UTF_REGION: usize = 221;
/// `GetPrimitiveArrayCritical` slot.
pub const SLOT_GET_PRIMITIVE_ARRAY_CRITICAL: usize = 222;
/// `GetStringCritical` slot.
pub const SLOT_GET_STRING_CRITICAL: usize = 224;
/// `GetDirectBufferAddress` slot.
pub const SLOT_GET_DIRECT_BUFFER_ADDRESS: usize = 230;
/// `GetDirectBufferCapacity` slot.
pub const SLOT_GET_DIRECT_BUFFER_CAPACITY: usize = 231;

const GET_FUNCTION_TABLE_BYTES: usize = 128;
const JNI_TABLE_MIN_SLOTS: usize = SLOT_GET_STRING_UTF_REGION + 1;

/// One `JNIEnv` C function resolved to a file offset in libart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JniEnvFunction {
    /// `jni.h` function name, for example `GetStringUTFChars`.
    pub name: &'static str,
    /// ELF file offset for uprobe attach.
    pub offset: u64,
}

/// Slots copied for `--inspect-adapter jni_plaintext`.
pub const JNI_PLAINTEXT_SLOTS: [(&str, usize); 20] = [
    ("NewString", SLOT_NEW_STRING),
    ("GetStringLength", SLOT_GET_STRING_LENGTH),
    ("GetStringChars", SLOT_GET_STRING_CHARS),
    ("NewStringUTF", SLOT_NEW_STRING_UTF),
    ("GetStringUTFLength", SLOT_GET_STRING_UTF_LENGTH),
    ("GetStringUTFChars", SLOT_GET_STRING_UTF_CHARS),
    ("GetArrayLength", SLOT_GET_ARRAY_LENGTH),
    ("GetByteArrayElements", SLOT_GET_BYTE_ARRAY_ELEMENTS),
    ("GetCharArrayElements", SLOT_GET_CHAR_ARRAY_ELEMENTS),
    ("GetByteArrayRegion", SLOT_GET_BYTE_ARRAY_REGION),
    ("GetCharArrayRegion", SLOT_GET_CHAR_ARRAY_REGION),
    ("SetByteArrayRegion", SLOT_SET_BYTE_ARRAY_REGION),
    ("SetCharArrayRegion", SLOT_SET_CHAR_ARRAY_REGION),
    ("RegisterNatives", SLOT_REGISTER_NATIVES),
    ("GetStringRegion", SLOT_GET_STRING_REGION),
    ("GetStringUTFRegion", SLOT_GET_STRING_UTF_REGION),
    (
        "GetPrimitiveArrayCritical",
        SLOT_GET_PRIMITIVE_ARRAY_CRITICAL,
    ),
    ("GetStringCritical", SLOT_GET_STRING_CRITICAL),
    ("GetDirectBufferAddress", SLOT_GET_DIRECT_BUFFER_ADDRESS),
    ("GetDirectBufferCapacity", SLOT_GET_DIRECT_BUFFER_CAPACITY),
];

fn intern_jni_name(name: &str) -> Option<&'static str> {
    JNI_PLAINTEXT_SLOTS
        .iter()
        .find(|(item, _)| *item == name)
        .map(|(item, _)| *item)
}

/// Resolve `wanted` `JNIEnv` functions from `libart.so`.
///
/// Prefers a dynsym name when present. Otherwise walks tables named by the
/// exported `GetFunctionTable` body. Unique by `(name, offset)`.
///
/// # Errors
///
/// Returns an error when the path is not ELF64, `GetFunctionTable` is missing,
/// or no `JNINativeInterface` table could be validated.
pub fn resolve_jni_env_functions(
    path: impl AsRef<Path>,
    wanted: &[(&str, usize)],
) -> Result<Vec<JniEnvFunction>, String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let elf = inspect_elf(path)?;
    if elf.bits != 64 {
        return Err(
            "JNIEnv table resolve requires ELF64 libart (AArch32 uprobes are ENOTSUP)".to_owned(),
        );
    }
    let loads = parse_loads64(&bytes)?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, _) in wanted {
        let Some(static_name) = intern_jni_name(name) else {
            continue;
        };
        for (symbol, offset) in matching_symbols(&elf, &[static_name]) {
            if symbol == static_name && seen.insert((static_name, offset)) {
                out.push(JniEnvFunction {
                    name: static_name,
                    offset,
                });
            }
        }
    }
    let Some((_, table_fn_off)) = matching_symbols(&elf, &[GET_FUNCTION_TABLE])
        .into_iter()
        .next()
    else {
        if out.is_empty() {
            return Err(format!(
                "{GET_FUNCTION_TABLE} is not exported; JNIEnv plaintext functions are not dynsym names"
            ));
        }
        return Ok(out);
    };
    let Some(pc) = file_to_virt(&loads, table_fn_off) else {
        return Err("GetFunctionTable file offset is not in a PT_LOAD".to_owned());
    };
    let start = usize::try_from(table_fn_off).map_err(|_| "GetFunctionTable offset")?;
    let end = (start + GET_FUNCTION_TABLE_BYTES).min(bytes.len());
    let body = bytes.get(start..end).ok_or("truncated GetFunctionTable")?;
    let mut tables = Vec::new();
    for virt in aarch64_adrp_add_targets(body, pc) {
        if looks_like_jni_table(&bytes, &loads, virt) {
            tables.push(virt);
        }
    }
    if tables.is_empty() && out.is_empty() {
        return Err(
            "exported GetFunctionTable did not name a JNINativeInterface table (reserved[4]==0 and jni.h slots in .text)"
                .to_owned(),
        );
    }
    for table in tables {
        for (name, slot) in wanted {
            let Some(func_va) = read_table_slot(&bytes, &loads, table, *slot) else {
                continue;
            };
            let Some(offset) = virt_to_file(&loads, func_va) else {
                continue;
            };
            if !is_executable(&loads, func_va) {
                continue;
            }
            let Some(static_name) = intern_jni_name(name) else {
                continue;
            };
            if seen.insert((static_name, offset)) {
                out.push(JniEnvFunction {
                    name: static_name,
                    offset,
                });
            }
        }
    }
    if out.is_empty() {
        return Err("JNINativeInterface slots were empty or not executable".to_owned());
    }
    Ok(out)
}

struct Load {
    file_offset: u64,
    virt_addr: u64,
    file_size: u64,
    executable: bool,
}

fn parse_loads64(bytes: &[u8]) -> Result<Vec<Load>, String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("not ELF64LE".to_owned());
    }
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().map_err(|_| "phoff")?);
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().map_err(|_| "phentsize")?);
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().map_err(|_| "phnum")?);
    let mut loads = Vec::new();
    for index in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff")?
            + usize::from(index) * usize::from(phentsize);
        if offset + 56 > bytes.len() {
            break;
        }
        let p_type = u32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| "type")?);
        if p_type != 1 {
            continue;
        }
        let flags = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| "flags")?,
        );
        let file_offset = u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| "off")?,
        );
        let virt_addr = u64::from_le_bytes(
            bytes[offset + 16..offset + 24]
                .try_into()
                .map_err(|_| "va")?,
        );
        let file_size = u64::from_le_bytes(
            bytes[offset + 32..offset + 40]
                .try_into()
                .map_err(|_| "fs")?,
        );
        loads.push(Load {
            file_offset,
            virt_addr,
            file_size,
            executable: flags & 1 != 0,
        });
    }
    Ok(loads)
}

fn virt_to_file(loads: &[Load], virt: u64) -> Option<u64> {
    loads.iter().find_map(|segment| {
        (virt >= segment.virt_addr && virt < segment.virt_addr.saturating_add(segment.file_size))
            .then_some(segment.file_offset.saturating_add(virt - segment.virt_addr))
    })
}

fn file_to_virt(loads: &[Load], file_offset: u64) -> Option<u64> {
    loads.iter().find_map(|segment| {
        (file_offset >= segment.file_offset
            && file_offset < segment.file_offset.saturating_add(segment.file_size))
        .then_some(
            segment
                .virt_addr
                .saturating_add(file_offset - segment.file_offset),
        )
    })
}

fn is_executable(loads: &[Load], virt: u64) -> bool {
    loads.iter().any(|segment| {
        segment.executable
            && virt >= segment.virt_addr
            && virt < segment.virt_addr.saturating_add(segment.file_size)
    })
}

fn read_u64_at(bytes: &[u8], offset: u64) -> Option<u64> {
    let start = usize::try_from(offset).ok()?;
    let slice = bytes.get(start..start + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn read_table_slot(bytes: &[u8], loads: &[Load], table: u64, slot: usize) -> Option<u64> {
    let file = virt_to_file(loads, table)?;
    let ptr_off = file.checked_add(u64::try_from(slot.checked_mul(8)?).ok()?)?;
    let ptr = read_u64_at(bytes, ptr_off)?;
    (ptr != 0).then_some(ptr)
}

fn looks_like_jni_table(bytes: &[u8], loads: &[Load], table: u64) -> bool {
    let Some(file) = virt_to_file(loads, table) else {
        return false;
    };
    let need = u64::try_from(JNI_TABLE_MIN_SLOTS.saturating_mul(8)).unwrap_or(0);
    if file.saturating_add(need) > u64::try_from(bytes.len()).unwrap_or(0) {
        return false;
    }
    for reserved in 0..4_u64 {
        if read_u64_at(bytes, file + reserved * 8) != Some(0) {
            return false;
        }
    }
    let Some(get_version) = read_u64_at(
        bytes,
        file + u64::try_from(SLOT_GET_VERSION * 8).unwrap_or(0),
    ) else {
        return false;
    };
    if !is_executable(loads, get_version) {
        return false;
    }
    let Some(new_utf) = read_u64_at(
        bytes,
        file + u64::try_from(SLOT_NEW_STRING_UTF * 8).unwrap_or(0),
    ) else {
        return false;
    };
    is_executable(loads, new_utf)
}

/// Collect `ADRP Xd, page; ADD Xd, Xn, #imm` absolute targets from a leaf.
pub fn aarch64_adrp_add_targets(func: &[u8], pc: u64) -> Vec<u64> {
    let mut pages = [None; 32];
    let mut targets = Vec::new();
    for (index, chunk) in func.chunks_exact(4).enumerate() {
        let insn = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let here = pc.saturating_add(u64::try_from(index.saturating_mul(4)).unwrap_or(0));
        if let Some((rd, page)) = decode_adrp(insn, here) {
            pages[rd] = Some(page);
            continue;
        }
        if let Some((rd, rn, imm)) = decode_add_imm64(insn) {
            if let Some(page) = pages[rn] {
                let value = page.saturating_add(imm);
                if !targets.contains(&value) {
                    targets.push(value);
                }
                pages[rd] = Some(value);
            }
        }
    }
    targets
}

fn decode_adrp(insn: u32, pc: u64) -> Option<(usize, u64)> {
    if insn & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as usize;
    let immlo = (insn >> 29) & 0x3;
    let immhi = (insn >> 5) & 0x7ffff;
    let imm21 = (i64::from(immhi << 2 | immlo) << 43) >> 43;
    let page = (pc & !0xfff).wrapping_add_signed(imm21 << 12);
    Some((rd, page))
}

fn decode_add_imm64(insn: u32) -> Option<(usize, usize, u64)> {
    if insn & 0xff80_0000 != 0x9100_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let imm12 = u64::from((insn >> 10) & 0xfff);
    let imm = if (insn >> 22) & 1 == 1 {
        imm12 << 12
    } else {
        imm12
    };
    Some((rd, rn, imm))
}

#[cfg(test)]
mod tests {
    use super::{
        aarch64_adrp_add_targets, resolve_jni_env_functions, SLOT_GET_ARRAY_LENGTH,
        SLOT_GET_BYTE_ARRAY_ELEMENTS, SLOT_GET_BYTE_ARRAY_REGION, SLOT_GET_CHAR_ARRAY_ELEMENTS,
        SLOT_GET_CHAR_ARRAY_REGION, SLOT_GET_DIRECT_BUFFER_ADDRESS,
        SLOT_GET_DIRECT_BUFFER_CAPACITY, SLOT_GET_PRIMITIVE_ARRAY_CRITICAL, SLOT_GET_STRING_CHARS,
        SLOT_GET_STRING_CRITICAL, SLOT_GET_STRING_LENGTH, SLOT_GET_STRING_REGION,
        SLOT_GET_STRING_UTF_CHARS, SLOT_GET_STRING_UTF_LENGTH, SLOT_GET_STRING_UTF_REGION,
        SLOT_NEW_STRING, SLOT_NEW_STRING_UTF, SLOT_REGISTER_NATIVES, SLOT_SET_BYTE_ARRAY_REGION,
        SLOT_SET_CHAR_ARRAY_REGION,
    };
    use std::path::Path;

    #[test]
    fn jni_h_slots_match_openjdk_jni_native_interface() {
        assert_eq!(SLOT_NEW_STRING, 163);
        assert_eq!(SLOT_GET_STRING_LENGTH, 164);
        assert_eq!(SLOT_GET_STRING_CHARS, 165);
        assert_eq!(SLOT_NEW_STRING_UTF, 167);
        assert_eq!(SLOT_GET_STRING_UTF_LENGTH, 168);
        assert_eq!(SLOT_GET_STRING_UTF_CHARS, 169);
        assert_eq!(SLOT_GET_ARRAY_LENGTH, 171);
        assert_eq!(SLOT_GET_BYTE_ARRAY_ELEMENTS, 184);
        assert_eq!(SLOT_GET_CHAR_ARRAY_ELEMENTS, 185);
        assert_eq!(SLOT_GET_BYTE_ARRAY_REGION, 200);
        assert_eq!(SLOT_GET_CHAR_ARRAY_REGION, 201);
        assert_eq!(SLOT_SET_BYTE_ARRAY_REGION, 208);
        assert_eq!(SLOT_SET_CHAR_ARRAY_REGION, 209);
        assert_eq!(SLOT_REGISTER_NATIVES, 215);
        assert_eq!(SLOT_GET_STRING_REGION, 220);
        assert_eq!(SLOT_GET_STRING_UTF_REGION, 221);
        assert_eq!(SLOT_GET_PRIMITIVE_ARRAY_CRITICAL, 222);
        assert_eq!(SLOT_GET_STRING_CRITICAL, 224);
        assert_eq!(SLOT_GET_DIRECT_BUFFER_ADDRESS, 230);
        assert_eq!(SLOT_GET_DIRECT_BUFFER_CAPACITY, 231);
        assert_eq!(super::JNI_PLAINTEXT_SLOTS.len(), 20);
    }

    #[test]
    fn decodes_get_function_table_adrp_add_tables() {
        // Pixel 6a Android 16 libart `GetFunctionTable` at VA 0x7efe58.
        let body: [u8; 76] = [
            0xe9, 0x20, 0x00, 0xd0, 0x6a, 0x11, 0x00, 0xd0, 0x4a, 0x81, 0x20, 0x91, 0x29, 0xa1,
            0x46, 0xf9, 0xe8, 0x03, 0x00, 0x2a, 0x3f, 0x01, 0x00, 0xf1, 0x20, 0x11, 0x8a, 0x9a,
            0x68, 0x01, 0x00, 0x37, 0x49, 0x01, 0x00, 0xb5, 0xe8, 0x20, 0x00, 0xd0, 0x69, 0x11,
            0x00, 0xf0, 0x29, 0xe1, 0x1d, 0x91, 0x08, 0x7d, 0x47, 0xf9, 0x08, 0xc5, 0x44, 0xb9,
            0x1f, 0x01, 0x00, 0x71, 0x68, 0x11, 0x00, 0xf0, 0x08, 0xc1, 0x00, 0x91, 0x00, 0x01,
            0x89, 0x9a, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let targets = aarch64_adrp_add_targets(&body, 0x007e_fe58);
        assert!(targets.contains(&0x00a1_d820), "{targets:#x?}");
        assert!(targets.contains(&0x00a1_e030), "{targets:#x?}");
        assert!(targets.contains(&0x00a1_e778), "{targets:#x?}");
    }

    #[test]
    fn resolves_jni_slots_from_pulled_libart_when_present() {
        let path = Path::new("/tmp/libart.so");
        if !path.is_file() {
            return;
        }
        let found = resolve_jni_env_functions(
            path,
            &[
                ("NewStringUTF", SLOT_NEW_STRING_UTF),
                ("GetStringUTFChars", SLOT_GET_STRING_UTF_CHARS),
                ("GetArrayLength", SLOT_GET_ARRAY_LENGTH),
                ("GetStringUTFRegion", SLOT_GET_STRING_UTF_REGION),
            ],
        )
        .expect("GetFunctionTable tables");
        assert!(
            found
                .iter()
                .any(|item| item.name == "GetStringUTFChars" && item.offset != 0),
            "{found:?}"
        );
        assert!(found.iter().any(|item| item.name == "NewStringUTF"));
        let utf_offsets = found
            .iter()
            .filter(|item| item.name == "GetStringUTFChars")
            .count();
        assert!(utf_offsets >= 1);
    }
}
