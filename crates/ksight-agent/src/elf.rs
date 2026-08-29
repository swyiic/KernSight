//! Minimal ELF64 parser for GNU build-id and dynamic symbol file offsets.

use std::{fs, path::Path};

/// Parsed ELF identity used by Inspect adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfIdentity {
    /// Absolute path.
    pub path: String,
    /// Lowercase GNU build-id hex, if present.
    pub build_id: Option<String>,
    /// Dynamic symbol file offsets keyed by name.
    pub symbols: Vec<(String, u64)>,
}

/// Read build-id and selected dynamic symbols from an ELF64 little-endian shared object.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not ELF64LE.
pub fn inspect_elf(path: impl AsRef<Path>) -> Result<ElfIdentity, String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF file".to_owned());
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return Err("only ELF64 little-endian is supported".to_owned());
    }
    let phoff = read_u64(&bytes, 32)?;
    let shoff = read_u64(&bytes, 40)?;
    let phentsize = read_u16(&bytes, 54)?;
    let phnum = read_u16(&bytes, 56)?;
    let shentsize = read_u16(&bytes, 58)?;
    let shnum = read_u16(&bytes, 60)?;
    let mut loads = Vec::new();
    for index in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff")?
            + usize::from(index) * usize::from(phentsize);
        if offset + 56 > bytes.len() {
            break;
        }
        if read_u32(&bytes, offset)? != 1 {
            continue;
        }
        loads.push(LoadSegment {
            file_offset: read_u64(&bytes, offset + 8)?,
            virt_addr: read_u64(&bytes, offset + 16)?,
            file_size: read_u64(&bytes, offset + 32)?,
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
        let kind = read_u32(&bytes, offset + 4)?;
        let section_offset = read_u64(&bytes, offset + 24)?;
        let section_size = read_u64(&bytes, offset + 32)?;
        if kind == 7 {
            if let Some(id) = parse_gnu_build_id(&bytes, section_offset, section_size) {
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
    })
}

/// Locate a preferred exported symbol file offset.
pub fn symbol_offset(elf: &ElfIdentity, names: &[&str]) -> Option<u64> {
    symbol_match(elf, names).map(|(_, offset)| offset)
}

/// Locate an exported symbol by exact name or prefix.
pub fn symbol_match<'a>(elf: &'a ElfIdentity, names: &[&str]) -> Option<(&'a str, u64)> {
    for wanted in names {
        if let Some((name, offset)) = elf.symbols.iter().find(|(name, _)| name == wanted) {
            return Some((name.as_str(), *offset));
        }
    }
    for wanted in names {
        if let Some((name, offset)) = elf
            .symbols
            .iter()
            .find(|(name, _)| name.starts_with(wanted))
        {
            return Some((name.as_str(), *offset));
        }
    }
    None
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
    use super::parse_gnu_build_id;

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
