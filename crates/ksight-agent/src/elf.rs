//! Minimal ELF64 parser for GNU build-id and dynamic symbol file offsets.

use std::{collections::BTreeSet, fs, path::Path};

/// Parsed ELF identity used by Inspect adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfIdentity {
    /// Absolute path.
    pub path: String,
    /// Lowercase GNU build-id hex, if present.
    pub build_id: Option<String>,
    /// Dynamic symbol file offsets keyed by name.
    pub symbols: Vec<(String, u64)>,
    /// ELF class: 32 or 64.
    pub bits: u8,
}

/// Read build-id and selected dynamic symbols from an ELF32/ELF64 little-endian shared object.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not ELF little-endian.
pub fn inspect_elf(path: impl AsRef<Path>) -> Result<ElfIdentity, String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() < 52 || &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF file".to_owned());
    }
    if bytes[5] != 1 {
        return Err("only little-endian ELF is supported".to_owned());
    }
    match bytes[4] {
        1 => inspect_elf32(path, &bytes),
        2 => inspect_elf64(path, &bytes),
        _ => Err("unsupported ELF class".to_owned()),
    }
}

fn inspect_elf64(path: &Path, bytes: &[u8]) -> Result<ElfIdentity, String> {
    if bytes.len() < 64 {
        return Err("truncated ELF64".to_owned());
    }
    let phoff = read_u64(bytes, 32)?;
    let shoff = read_u64(bytes, 40)?;
    let phentsize = read_u16(bytes, 54)?;
    let phnum = read_u16(bytes, 56)?;
    let shentsize = read_u16(bytes, 58)?;
    let shnum = read_u16(bytes, 60)?;
    let mut loads = Vec::new();
    for index in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff")?
            + usize::from(index) * usize::from(phentsize);
        if offset + 56 > bytes.len() {
            break;
        }
        if read_u32(bytes, offset)? != 1 {
            continue;
        }
        loads.push(LoadSegment {
            file_offset: read_u64(bytes, offset + 8)?,
            virt_addr: read_u64(bytes, offset + 16)?,
            file_size: read_u64(bytes, offset + 32)?,
        });
    }
    let mut build_id = None;
    let mut dynsym = None;
    let mut dynstr = None;
    for index in 0..shnum {
        let offset = usize::try_from(shoff).map_err(|_| "shoff")?
            + usize::from(index) * usize::from(shentsize);
        if offset + 64 > bytes.len() {
            break;
        }
        let kind = read_u32(bytes, offset + 4)?;
        let section_offset = read_u64(bytes, offset + 24)?;
        let section_size = read_u64(bytes, offset + 32)?;
        if kind == 7 {
            if let Some(id) = parse_gnu_build_id(bytes, section_offset, section_size) {
                build_id = Some(id);
            }
        }
        if kind == 11 {
            dynsym = Some((section_offset, section_size));
        }
        if kind == 3 && dynstr.is_none() {
            dynstr = Some((section_offset, section_size));
        }
    }
    let mut symbols = Vec::new();
    if let (Some((sym_off, sym_size)), Some((str_off, str_size))) = (dynsym, dynstr) {
        let start = usize::try_from(sym_off).unwrap_or(0);
        let len = usize::try_from(sym_size).unwrap_or(0);
        let str_start = usize::try_from(str_off).unwrap_or(0);
        let str_len = usize::try_from(str_size).unwrap_or(0);
        if start + len <= bytes.len() && str_start + str_len <= bytes.len() {
            let strings = &bytes[str_start..str_start + str_len];
            for entry in bytes[start..start + len].chunks(24) {
                if entry.len() < 24 {
                    break;
                }
                let mut name_raw = [0_u8; 4];
                name_raw.copy_from_slice(&entry[0..4]);
                let mut value_raw = [0_u8; 8];
                value_raw.copy_from_slice(&entry[8..16]);
                let name_off = u32::from_le_bytes(name_raw) as usize;
                let value = u64::from_le_bytes(value_raw);
                if name_off >= strings.len() || value == 0 {
                    continue;
                }
                let end = strings[name_off..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map_or(strings.len(), |relative| name_off + relative);
                let name = String::from_utf8_lossy(&strings[name_off..end]).into_owned();
                if name.is_empty() {
                    continue;
                }
                if let Some(file_offset) = virt_to_file(&loads, value) {
                    symbols.push((name, file_offset));
                }
            }
        }
    }
    Ok(ElfIdentity {
        path: path.display().to_string(),
        build_id,
        symbols,
        bits: 64,
    })
}

fn inspect_elf32(path: &Path, bytes: &[u8]) -> Result<ElfIdentity, String> {
    let phoff = u64::from(read_u32(bytes, 28)?);
    let shoff = u64::from(read_u32(bytes, 32)?);
    let phentsize = read_u16(bytes, 42)?;
    let phnum = read_u16(bytes, 44)?;
    let shentsize = read_u16(bytes, 46)?;
    let shnum = read_u16(bytes, 48)?;
    let mut loads = Vec::new();
    for index in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff")?
            + usize::from(index) * usize::from(phentsize);
        if offset + 32 > bytes.len() {
            break;
        }
        if read_u32(bytes, offset)? != 1 {
            continue;
        }
        loads.push(LoadSegment {
            file_offset: u64::from(read_u32(bytes, offset + 4)?),
            virt_addr: u64::from(read_u32(bytes, offset + 8)?),
            file_size: u64::from(read_u32(bytes, offset + 16)?),
        });
    }
    let mut build_id = None;
    let mut dynsym = None;
    let mut dynstr = None;
    for index in 0..shnum {
        let offset = usize::try_from(shoff).map_err(|_| "shoff")?
            + usize::from(index) * usize::from(shentsize);
        if offset + 40 > bytes.len() {
            break;
        }
        let kind = read_u32(bytes, offset + 4)?;
        let section_offset = u64::from(read_u32(bytes, offset + 16)?);
        let section_size = u64::from(read_u32(bytes, offset + 20)?);
        if kind == 7 {
            if let Some(id) = parse_gnu_build_id(bytes, section_offset, section_size) {
                build_id = Some(id);
            }
        }
        if kind == 11 {
            dynsym = Some((section_offset, section_size));
        }
        if kind == 3 && dynstr.is_none() {
            dynstr = Some((section_offset, section_size));
        }
    }
    let mut symbols = Vec::new();
    if let (Some((sym_off, sym_size)), Some((str_off, str_size))) = (dynsym, dynstr) {
        let start = usize::try_from(sym_off).unwrap_or(0);
        let len = usize::try_from(sym_size).unwrap_or(0);
        let str_start = usize::try_from(str_off).unwrap_or(0);
        let str_len = usize::try_from(str_size).unwrap_or(0);
        if start + len <= bytes.len() && str_start + str_len <= bytes.len() {
            let strings = &bytes[str_start..str_start + str_len];
            for entry in bytes[start..start + len].chunks(16) {
                if entry.len() < 16 {
                    break;
                }
                let Ok(name_raw) = <[u8; 4]>::try_from(&entry[0..4]) else {
                    continue;
                };
                let Ok(value_raw) = <[u8; 4]>::try_from(&entry[4..8]) else {
                    continue;
                };
                let name_off = u32::from_le_bytes(name_raw) as usize;
                // ARM Thumb symbols set bit 0; uprobe offsets must be even.
                let value = u64::from(u32::from_le_bytes(value_raw)) & !1;
                if name_off >= strings.len() || value == 0 {
                    continue;
                }
                let end = strings[name_off..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map_or(strings.len(), |relative| name_off + relative);
                let name = String::from_utf8_lossy(&strings[name_off..end]).into_owned();
                if name.is_empty() {
                    continue;
                }
                if let Some(file_offset) = virt_to_file(&loads, value) {
                    symbols.push((name, file_offset));
                }
            }
        }
    }
    Ok(ElfIdentity {
        path: path.display().to_string(),
        build_id,
        symbols,
        bits: 32,
    })
}

/// Locate a preferred exported symbol file offset.
pub fn symbol_offset(elf: &ElfIdentity, names: &[&str]) -> Option<u64> {
    symbol_match(elf, names).map(|(_, offset)| offset)
}

/// Locate an exported symbol by exact name or prefix.
pub fn symbol_match<'a>(elf: &'a ElfIdentity, names: &[&str]) -> Option<(&'a str, u64)> {
    matching_symbols(elf, names).into_iter().next()
}

/// Every exported symbol whose name equals or starts with one of `names`.
/// Unique by file offset, dynsym order.
pub fn matching_symbols<'a>(elf: &'a ElfIdentity, names: &[&str]) -> Vec<(&'a str, u64)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, offset) in &elf.symbols {
        let matched = names
            .iter()
            .any(|wanted| name == wanted || name.starts_with(wanted));
        if !matched || !seen.insert(*offset) {
            continue;
        }
        out.push((name.as_str(), *offset));
    }
    out
}

struct LoadSegment {
    file_offset: u64,
    virt_addr: u64,
    file_size: u64,
}

fn virt_to_file(loads: &[LoadSegment], virt: u64) -> Option<u64> {
    loads.iter().find_map(|segment| {
        (virt >= segment.virt_addr && virt < segment.virt_addr.saturating_add(segment.file_size))
            .then_some(segment.file_offset.saturating_add(virt - segment.virt_addr))
    })
}

fn parse_gnu_build_id(bytes: &[u8], offset: u64, size: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    let note = bytes.get(start..start + len)?;
    if note.len() < 16 {
        return None;
    }
    let namesz = u32::from_le_bytes(note[0..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(note[4..8].try_into().ok()?) as usize;
    let kind = u32::from_le_bytes(note[8..12].try_into().ok()?);
    let name_end = 12usize.checked_add(namesz)?;
    let name = note.get(12..name_end)?;
    if kind != 3 || !name.starts_with(b"GNU") {
        return None;
    }
    let desc_off = (name_end + 3) & !3;
    let desc = note.get(desc_off..desc_off.checked_add(descsz)?)?;
    let mut id = String::with_capacity(desc.len().saturating_mul(2));
    for byte in desc {
        let _ = std::fmt::Write::write_fmt(&mut id, format_args!("{byte:02x}"));
    }
    Some(id)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("truncated")?
            .try_into()
            .map_err(|_| "truncated")?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated")?
            .try_into()
            .map_err(|_| "truncated")?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("truncated")?
            .try_into()
            .map_err(|_| "truncated")?,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{inspect_elf, matching_symbols, parse_gnu_build_id, ElfIdentity};

    #[test]
    fn inspects_elf32_libbinder_transact() {
        let path = Path::new("/tmp/ksight-hal/libbinder32.so");
        if !path.is_file() {
            return;
        }
        let elf = inspect_elf(path).expect("elf32");
        assert!(
            elf.symbols
                .iter()
                .any(|(name, _)| name.contains("IPCThreadState8transact")),
            "32-bit libbinder must export transact"
        );
        let transact = elf
            .symbols
            .iter()
            .find(|(name, _)| name.contains("IPCThreadState8transact"))
            .expect("transact");
        assert_eq!(elf.bits, 32);
        assert_eq!(transact.1, 0x2f020);
        assert_eq!(transact.1 & 1, 0, "uprobe offset must be even");
        assert!(elf
            .symbols
            .iter()
            .any(|(name, _)| name.contains("writeStrongBinderERKNS_2sp")));
    }

    #[test]
    fn matching_symbols_returns_every_prefix_hit() {
        let elf = ElfIdentity {
            path: "/libdexfile.so".to_owned(),
            build_id: None,
            bits: 64,
            symbols: vec![
                ("_ZN3art13DexFileLoader4OpenEbbb".to_owned(), 0x1fe68),
                (
                    "_ZN3art13DexFileLoader10OpenCommonEPKhm".to_owned(),
                    0x21398,
                ),
                ("_ZNK3art16ArtDexFileLoader4OpenEPKc".to_owned(), 0x14624),
                ("_ZN3art9Ignored4OpenE".to_owned(), 0x1),
            ],
        };
        let hits = matching_symbols(
            &elf,
            &[
                "_ZN3art13DexFileLoader4OpenE",
                "_ZN3art13DexFileLoader10OpenCommonE",
                "_ZNK3art16ArtDexFileLoader4OpenE",
            ],
        );
        assert_eq!(hits.len(), 3);
        assert!(hits.iter().any(|(name, _)| name.contains("OpenCommon")));
        assert!(matching_symbols(&elf, &["_ZN3art13DexFileLoader4OpenE"])
            .iter()
            .all(|(name, _)| name.starts_with("_ZN3art13DexFileLoader4OpenE")));
    }

    #[test]
    fn parses_gnu_build_id_note() {
        let mut note = vec![4, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0xab, 0xcd]);
        assert_eq!(
            parse_gnu_build_id(&note, 0, note.len() as u64).as_deref(),
            Some("abcd")
        );
    }
}
