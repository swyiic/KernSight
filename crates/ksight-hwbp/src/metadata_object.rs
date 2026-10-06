#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Pure offline parser for the real `iter/task` ELF. Aya 0.2 lacks iterator
//! section syntax: rename ONLY same-length section/string-table names in a
//! private parsing copy. The original ELF/program bytes stay untouched. The
//! raw loader explicitly uses `TRACING/TRACE_ITER`, never `RawTracePoint` attachment.
use anyhow::{bail, Context, Result};
use aya_obj::{
    btf::{Btf, BtfFeatures, BtfKind},
    maps::Map,
    Object,
};
use object::{read::elf::FileHeader as _, Endianness, Object as _, ObjectSection as _};

pub(crate) struct MetadataObject {
    pub object: Object,
    pub program_key: (usize, u64),
    pub attach_btf_id: u32,
    #[cfg(test)]
    pub changed_instructions: usize,
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
pub(crate) fn parse(bytes: &[u8], target_bytes: &[u8]) -> Result<MetadataObject> {
    if bytes.len() > 256 * 1024 || target_bytes.len() > 8 * 1024 * 1024 {
        bail!("metadata object/BTF bounds");
    }
    let target = Btf::parse(target_bytes, Endianness::Little)?;
    let attach_btf_id = target.id_by_type_name_kind("bpf_iter_task", BtfKind::Func)?;
    let elf = object::File::parse(bytes)?;
    let section = elf
        .section_by_name("iter/task")
        .context("actual iter/task section required")?;
    let original_program = section.data()?;
    let mut parsing = bytes.to_vec();
    let layout = object::read::elf::ElfFile64::<Endianness>::parse(bytes)?;
    if layout.endian() != Endianness::Little || elf.architecture() != object::Architecture::Bpf {
        bail!("only ELF64 little-endian BPF metadata objects are supported");
    }
    let strings = layout.elf_header().shstrndx(layout.endian(), bytes)?;
    let names = elf.section_by_index(object::SectionIndex(strings as usize))?;
    let btf = elf.section_by_name(".BTF").context("local BTF missing")?;
    for sec in [names, btf] {
        let name = sec.name()?;
        let (offset, len) = sec.file_range().context("section range")?;
        let begin = usize::try_from(offset).context("section offset overflows host size")?;
        let end = usize::try_from(offset.checked_add(len).context("section range overflow")?)
            .context("section end overflows host size")?;
        let data = parsing
            .get_mut(begin..end)
            .context("section outside object")?;
        let mut replacements = 0;
        // Both strings are nine bytes. BTF.ext names use unchanged offsets.
        for i in 0..data.len().saturating_sub(9) {
            // ELF permits suffix-merged names (iter/task may be the suffix
            // of .reliter/task). Section lookup above proves the actual name.
            if &data[i..i + 10] == b"iter/task\0" {
                data[i..i + 9].copy_from_slice(b"raw_tp/it");
                replacements += 1;
            }
        }
        if replacements != 1 {
            bail!("ambiguous iterator name in {name}");
        }
    }
    let parsed_elf = object::File::parse(parsing.as_slice())?;
    if parsed_elf
        .section_by_name("raw_tp/it")
        .context("parsing alias")?
        .data()?
        != original_program
    {
        bail!("parser adapter altered program instructions");
    }
    let mut object = Object::parse(&parsing)?;
    if object.programs.len() != 1 || object.maps.len() != 1 {
        bail!("metadata-only object requires ONE program/map");
    }
    let p = object
        .programs
        .get("ksight_task_metadata")
        .context("metadata program name")?;
    let program_key = p.function_key();
    let map = object
        .maps
        .get("metadata_task_v1")
        .context("metadata map name")?;
    if (
        map.map_type(),
        map.key_size(),
        map.value_size(),
        map.max_entries(),
        map.map_flags(),
    ) != (29, 4, 16, 0, 1)
    {
        bail!("metadata task grant ABI mismatch");
    }
    if !matches!(map, Map::Btf(_)) {
        bail!("metadata BTF map required");
    }
    #[cfg(test)]
    let before: Vec<_> = object
        .functions
        .values()
        .flat_map(|f| {
            f.instructions
                .iter()
                .map(|i| (i.code, i.dst_reg(), i.src_reg(), i.off, i.imm))
        })
        .collect();
    object.relocate_btf(&target)?;
    #[cfg(test)]
    let after: Vec<_> = object
        .functions
        .values()
        .flat_map(|f| {
            f.instructions
                .iter()
                .map(|i| (i.code, i.dst_reg(), i.src_reg(), i.off, i.imm))
        })
        .collect();
    #[cfg(test)]
    let changed_instructions = before
        .iter()
        .zip(after.iter())
        .filter(|(a, b)| a != b)
        .count();
    object.fixup_and_sanitize_btf(&BtfFeatures::new(true, true, true, true, true, true, true))?;
    for f in object.functions.values() {
        for i in &f.instructions {
            if i.code == 0x85 && i.src_reg() == 0 && ![113, 127, 156].contains(&i.imm) {
                bail!("metadata object contains forbidden helper {}", i.imm);
            }
        }
    }
    Ok(MetadataObject {
        object,
        program_key,
        attach_btf_id,
        #[cfg(test)]
        changed_instructions,
    })
}

