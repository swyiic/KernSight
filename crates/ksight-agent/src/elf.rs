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
    let mut sections = Vec::new();
    for index in 0..shnum {
        let offset = usize::try_from(shoff).map_err(|_| "shoff")?
            + usize::from(index) * usize::from(shentsize);
        if offset + 64 > bytes.len() {
            break;
        }
        let kind = read_u32(bytes, offset + 4)?;
        let section_offset = read_u64(bytes, offset + 24)?;
        let section_size = read_u64(bytes, offset + 32)?;
        let link = read_u32(bytes, offset + 40)?;
        if kind == 7 {
            if let Some(id) = parse_gnu_build_id(bytes, section_offset, section_size) {
                build_id = Some(id);
            }
        }
        sections.push((kind, section_offset, section_size, link));
    }
    let mut symbols = parse_dynsym_via_sections(bytes, &loads, &sections, true);
    if symbols.is_empty() {
        symbols = parse_dynsym_via_pt_dynamic(bytes, &loads, phoff, phentsize, phnum, true);
    }
    merge_tls_symtab(&mut symbols, bytes, &loads, &sections, true);
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
    let mut sections = Vec::new();
    for index in 0..shnum {
        let offset = usize::try_from(shoff).map_err(|_| "shoff")?
            + usize::from(index) * usize::from(shentsize);
        if offset + 40 > bytes.len() {
            break;
        }
        let kind = read_u32(bytes, offset + 4)?;
        let section_offset = u64::from(read_u32(bytes, offset + 16)?);
        let section_size = u64::from(read_u32(bytes, offset + 20)?);
        let link = read_u32(bytes, offset + 24)?;
        if kind == 7 {
            if let Some(id) = parse_gnu_build_id(bytes, section_offset, section_size) {
                build_id = Some(id);
            }
        }
        sections.push((kind, section_offset, section_size, link));
    }
    let mut symbols = parse_dynsym_via_sections(bytes, &loads, &sections, false);
    if symbols.is_empty() {
        symbols = parse_dynsym_via_pt_dynamic(bytes, &loads, phoff, phentsize, phnum, false);
    }
    merge_tls_symtab(&mut symbols, bytes, &loads, &sections, false);
    Ok(ElfIdentity {
        path: path.display().to_string(),
        build_id,
        symbols,
        bits: 32,
    })
}

/// Locate a preferred exported symbol file offset.
#[must_use]
pub fn symbol_offset(elf: &ElfIdentity, names: &[&str]) -> Option<u64> {
    symbol_match(elf, names).map(|(_, offset)| offset)
}

/// Locate an exported symbol by exact name or prefix.
#[must_use]
pub fn symbol_match<'a>(elf: &'a ElfIdentity, names: &[&str]) -> Option<(&'a str, u64)> {
    matching_symbols(elf, names).into_iter().next()
}

/// First exact dynsym name in `names` order. Avoids `sslRead` matching `sslReadEx`.
#[must_use]
pub fn symbol_match_exact<'a>(elf: &'a ElfIdentity, names: &[&str]) -> Option<(&'a str, u64)> {
    matching_symbols_exact(elf, names).into_iter().next()
}

/// GNU versioned dynsym name without `@LIB` / `@@OPENSSL_*` suffix.
#[must_use]
pub fn dynsym_export_name(name: &str) -> &str {
    let no_default = name.split("@@").next().unwrap_or(name);
    no_default.split('@').next().unwrap_or(no_default)
}

/// Every exact dynsym name in `names` order. Unique by file offset.
/// Versioned exports (`SSL_write@@OPENSSL_3`) match the unversioned name.
pub fn matching_symbols_exact<'a, S: AsRef<str>>(
    elf: &'a ElfIdentity,
    names: &[S],
) -> Vec<(&'a str, u64)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for wanted in names {
        let wanted = wanted.as_ref();
        if let Some((name, offset)) = elf
            .symbols
            .iter()
            .find(|(name, _)| name == wanted || dynsym_export_name(name) == wanted)
        {
            if seen.insert(*offset) {
                out.push((name.as_str(), *offset));
            }
        }
    }
    out
}

/// Every exported symbol whose name equals or starts with one of `names`.
/// Unique by file offset, dynsym order.
#[must_use]
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

fn parse_dynsym_via_sections(
    bytes: &[u8],
    loads: &[LoadSegment],
    sections: &[(u32, u64, u64, u32)],
    elf64: bool,
) -> Vec<(String, u64)> {
    let mut dynsym = None;
    let mut dynstr = None;
    for &(kind, offset, size, link) in sections {
        if kind != 11 {
            continue;
        }
        dynsym = Some((offset, size));
        if let Some(&(str_kind, str_off, str_size, _)) = sections.get(link as usize) {
            if str_kind == 3 {
                dynstr = Some((str_off, str_size));
            }
        }
        break;
    }
    if dynstr.is_none() {
        dynstr = sections
            .iter()
            .find(|(kind, _, _, _)| *kind == 3)
            .map(|(_, offset, size, _)| (*offset, *size));
    }
    match (dynsym, dynstr) {
        (Some((sym_off, sym_size)), Some((str_off, str_size))) => {
            parse_dynsym_entries(bytes, loads, sym_off, sym_size, str_off, str_size, elf64)
        }
        _ => Vec::new(),
    }
}

fn parse_dynsym_via_pt_dynamic(
    bytes: &[u8],
    loads: &[LoadSegment],
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    elf64: bool,
) -> Vec<(String, u64)> {
    let phoff = usize::try_from(phoff).unwrap_or(0);
    let entsize = usize::from(phentsize);
    let mut dyn_off = None;
    let mut dyn_filesz = 0_u64;
    for index in 0..phnum {
        let offset = phoff.saturating_add(usize::from(index).saturating_mul(entsize));
        let (kind, file_off, filesz) = if elf64 {
            if offset.saturating_add(56) > bytes.len() {
                break;
            }
            (
                read_u32(bytes, offset).unwrap_or(0),
                read_u64(bytes, offset + 8).unwrap_or(0),
                read_u64(bytes, offset + 32).unwrap_or(0),
            )
        } else {
            if offset.saturating_add(32) > bytes.len() {
                break;
            }
            (
                read_u32(bytes, offset).unwrap_or(0),
                u64::from(read_u32(bytes, offset + 4).unwrap_or(0)),
                u64::from(read_u32(bytes, offset + 16).unwrap_or(0)),
            )
        };
        if kind == 2 {
            dyn_off = Some(file_off);
            dyn_filesz = filesz;
            break;
        }
    }
    let Some(dyn_off) = dyn_off else {
        return Vec::new();
    };
    let start = usize::try_from(dyn_off).unwrap_or(0);
    let len = usize::try_from(dyn_filesz).unwrap_or(0);
    let end = start.saturating_add(len).min(bytes.len());
    if start >= end {
        return Vec::new();
    }
    let dyn_entsize = if elf64 { 16 } else { 8 };
    let mut symtab_va = None;
    let mut strtab_va = None;
    let mut strsz = None;
    let mut syment = if elf64 { 24_u64 } else { 16 };
    let mut hash_va = None;
    for entry in bytes[start..end].chunks(dyn_entsize) {
        if entry.len() < dyn_entsize {
            break;
        }
        let (tag, val) = if elf64 {
            let tag = i64::from_le_bytes(entry[0..8].try_into().unwrap_or([0; 8]));
            let val = u64::from_le_bytes(entry[8..16].try_into().unwrap_or([0; 8]));
            (tag, val)
        } else {
            let tag = i64::from(i32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4])));
            let val = u64::from(u32::from_le_bytes(entry[4..8].try_into().unwrap_or([0; 4])));
            (tag, val)
        };
        match tag {
            0 => break,
            4 => hash_va = Some(val),
            5 => strtab_va = Some(val),
            6 => symtab_va = Some(val),
            10 => strsz = Some(val),
            11 => syment = val,
            _ => {}
        }
    }
    let (Some(sym_va), Some(str_va), Some(str_size)) = (symtab_va, strtab_va, strsz) else {
        return Vec::new();
    };
    let Some(sym_off) = virt_to_file(loads, sym_va) else {
        return Vec::new();
    };
    let Some(str_off) = virt_to_file(loads, str_va) else {
        return Vec::new();
    };
    let nsyms = hash_va
        .and_then(|va| virt_to_file(loads, va))
        .and_then(|off| {
            let idx = usize::try_from(off.saturating_add(4)).ok()?;
            bytes.get(idx..idx + 4).and_then(|raw| {
                let raw: [u8; 4] = raw.try_into().ok()?;
                Some(u32::from_le_bytes(raw))
            })
        })
        .unwrap_or(0);
    if nsyms == 0 || syment == 0 {
        return Vec::new();
    }
    let sym_size = u64::from(nsyms).saturating_mul(syment);
    parse_dynsym_entries(bytes, loads, sym_off, sym_size, str_off, str_size, elf64)
}

fn parse_dynsym_entries(
    bytes: &[u8],
    loads: &[LoadSegment],
    sym_off: u64,
    sym_size: u64,
    str_off: u64,
    str_size: u64,
    elf64: bool,
) -> Vec<(String, u64)> {
    let start = usize::try_from(sym_off).unwrap_or(0);
    let len = usize::try_from(sym_size).unwrap_or(0);
    let str_start = usize::try_from(str_off).unwrap_or(0);
    let str_len = usize::try_from(str_size).unwrap_or(0);
    let Some(sym_end) = start.checked_add(len).filter(|end| *end <= bytes.len()) else {
        return Vec::new();
    };
    let Some(str_end) = str_start
        .checked_add(str_len)
        .filter(|end| *end <= bytes.len())
    else {
        return Vec::new();
    };
    let strings = &bytes[str_start..str_end];
    let chunk = if elf64 { 24 } else { 16 };
    let mut symbols = Vec::new();
    for entry in bytes[start..sym_end].chunks(chunk) {
        if entry.len() < chunk {
            break;
        }
        let (name_off, value, info, shndx) = if elf64 {
            let name_off = u32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4])) as usize;
            let info = entry[4];
            let shndx = u16::from_le_bytes(entry[6..8].try_into().unwrap_or([0; 2]));
            let value = u64::from_le_bytes(entry[8..16].try_into().unwrap_or([0; 8]));
            (name_off, value, info, shndx)
        } else {
            let name_off = u32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4])) as usize;
            let value =
                u64::from(u32::from_le_bytes(entry[4..8].try_into().unwrap_or([0; 4]))) & !1;
            let info = entry[12];
            let shndx = u16::from_le_bytes(entry[14..16].try_into().unwrap_or([0; 2]));
            (name_off, value, info, shndx)
        };
        if !is_defined_func(info, shndx, value) || name_off >= strings.len() {
            continue;
        }
        let end = strings[name_off..]
            .iter()
            .position(|byte| *byte == 0)
            .map_or(strings.len(), |relative| name_off + relative);
        let raw = String::from_utf8_lossy(&strings[name_off..end]);
        let name = dynsym_export_name(&raw).to_owned();
        if name.is_empty() {
            continue;
        }
        if let Some(file_offset) = virt_to_file(loads, value) {
            symbols.push((name, file_offset));
        }
    }
    symbols
}

fn is_defined_func(info: u8, shndx: u16, value: u64) -> bool {
    if value == 0 || shndx == 0 || shndx >= 0xff00 {
        return false;
    }
    // STT_FUNC only. STT_GNU_IFUNC (10) is a resolver; attaching there is an invented target.
    info & 0x0f == 2
}

/// LOCAL `.symtab` `SSL_write/SSL_read` (static OpenSSL in libcurl). Not an invented RVA:
/// the file offset comes from this ELF's own symbol table.
fn merge_tls_symtab(
    symbols: &mut Vec<(String, u64)>,
    bytes: &[u8],
    loads: &[LoadSegment],
    sections: &[(u32, u64, u64, u32)],
    elf64: bool,
) {
    let extra = parse_sym_section(bytes, loads, sections, 2, elf64);
    let mut seen: BTreeSet<u64> = symbols.iter().map(|(_, offset)| *offset).collect();
    for (name, offset) in extra {
        if !is_tls_copy_symbol(&name) || !seen.insert(offset) {
            continue;
        }
        symbols.push((name, offset));
    }
}

fn parse_sym_section(
    bytes: &[u8],
    loads: &[LoadSegment],
    sections: &[(u32, u64, u64, u32)],
    wanted_kind: u32,
    elf64: bool,
) -> Vec<(String, u64)> {
    let mut dynsym = None;
    let mut dynstr = None;
    for &(kind, offset, size, link) in sections {
        if kind != wanted_kind {
            continue;
        }
        dynsym = Some((offset, size));
        if let Some(&(str_kind, str_off, str_size, _)) = sections.get(link as usize) {
            if str_kind == 3 {
                dynstr = Some((str_off, str_size));
            }
        }
        break;
    }
    match (dynsym, dynstr) {
        (Some((sym_off, sym_size)), Some((str_off, str_size))) => {
            parse_dynsym_entries(bytes, loads, sym_off, sym_size, str_off, str_size, elf64)
        }
        _ => Vec::new(),
    }
}

fn is_tls_copy_symbol(name: &str) -> bool {
    matches!(
        dynsym_export_name(name),
        "SSL_write"
            | "SSL_write_ex"
            | "SSL_write_ex2"
            | "SSL_write_early_data"
            | "SSL_read"
            | "SSL_read_ex"
            | "SSL_read_ex2"
            | "SSL_read_early_data"
            | "SSL_peek"
            | "SSL_peek_ex"
            | "mbedtls_ssl_write"
            | "mbedtls_ssl_read"
            | "wolfSSL_write"
            | "wolfSSL_read"
            | "sslWrite"
            | "sslWriteEx"
            | "sslRead"
            | "sslReadEx"
            | "SLIGHT_SSL_write"
            | "SLIGHT_SSL_write_ex"
            | "SLIGHT_SSL_read"
            | "SLIGHT_SSL_read_ex"
    )
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

/// Cheap pre-filter before reading a mapped file as an ELF: size cap plus
/// extension and magic checks. Target processes map huge non-ELF blobs
/// (`base.apk`, webview APKs, OAT/ART images) that must not be read whole.
#[must_use]
pub fn plausible_elf_file(path: &str) -> bool {
    const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
    const SKIP_SUFFIXES: [&str; 6] = [".apk", ".jar", ".oat", ".art", ".odex", ".vdex"];
    if SKIP_SUFFIXES.iter().any(|suffix| path.ends_with(suffix)) {
        return false;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() == 0 || meta.len() > MAX_SCAN_BYTES {
        return false;
    }
    std::fs::File::open(path).is_ok_and(|mut file| {
        let mut magic = [0_u8; 4];
        std::io::Read::read_exact(&mut file, &mut magic).is_ok()
            && magic == [0x7f, b'E', b'L', b'F']
    })
}
