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

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> (Vec<u8>, Vec<u8>) {
        (
            std::fs::read(std::env::var_os("KSIGHT_METADATA_OBJECT").expect("object path"))
                .unwrap(),
            std::fs::read(std::env::var_os("KSIGHT_METADATA_TARGET_BTF").expect("BTF path"))
                .unwrap(),
        )
    }
    #[test]
    #[ignore = "requires explicit offline compiled object and previously exported target BTF; no kernel calls"]
    #[allow(
        clippy::default_trait_access,
        reason = "Aya uses a private hashbrown set type inferred by its relocation API."
    )]
    fn actual_target_btf_relocates_real_iterator_bits_cred_and_granted_task() {
        let (bytes, target) = inputs();
        let mut p = parse(&bytes, &target).unwrap();
        assert!(p.attach_btf_id > 0);
        assert!(p.changed_instructions > 0);
        let map = p.object.maps.get("metadata_task_v1").unwrap().clone();
        p.object
            .relocate_maps(
                std::iter::once(("metadata_task_v1", 0x4000, &map)),
                &Default::default(),
            )
            .unwrap();
        p.object.relocate_calls(&Default::default()).unwrap();
        let f = &p.object.functions[&p.program_key];
        assert!(f.instructions.len() < 4096);
        assert_eq!(f.func_info.func_info.len(), 1);
        let mut helpers = std::collections::BTreeSet::new();
        for i in &f.instructions {
            if i.code == 0x85 {
                assert_eq!(i.src_reg(), 0);
                assert!([113, 127, 156].contains(&i.imm));
                helpers.insert(i.imm);
            }
        }
        assert_eq!(helpers, std::collections::BTreeSet::from([113, 127, 156]));
        println!("actual target metadata CO-RE: attach_id={} changed={} instructions={} helper_ids={helpers:?} maps=1 kernel_calls=0",p.attach_btf_id,p.changed_instructions,f.instructions.len());
    }
    #[test]
    #[ignore = "requires explicit offline compiled object and target BTF; tests actual parser refusals"]
    fn actual_parser_refuses_missing_field_function_map_and_user_read_helper() {
        let (bytes, target) = inputs();
        assert!(
            parse(&bytes, &target).is_ok(),
            "negative tests require accepted baseline"
        );
        let mut bad = target.clone();
        replace_string(&mut bad, b"in_execve\0", b"in_excvXX\0");
        assert!(parse(&bytes, &bad).is_err());
        let mut bad = target.clone();
        replace_string(&mut bad, b"bpf_iter_task\0", b"bpf_iter_tasX\0");
        assert!(parse(&bytes, &bad).is_err());
        let mut bad = bytes.clone();
        replace_string(&mut bad, b"metadata_task_v1\0", b"metadata_task_vX\0");
        assert!(parse(&bad, &target).is_err());
        let elf = object::File::parse(bytes.as_slice()).unwrap();
        let (off, len) = elf
            .section_by_name("iter/task")
            .unwrap()
            .file_range()
            .unwrap();
        let mut bad = bytes.clone();
        let mut changed = false;
        for at in (usize::try_from(off).unwrap()..usize::try_from(off + len).unwrap()).step_by(8) {
            if bad[at] == 0x85
                && bad[at + 1] >> 4 == 0
                && i32::from_le_bytes(bad[at + 4..at + 8].try_into().unwrap()) == 113
            {
                bad[at + 4..at + 8].copy_from_slice(&112i32.to_le_bytes());
                changed = true;
                break;
            }
        }
        assert!(changed);
        assert!(parse(&bad, &target).is_err());
        assert!(parse(&bytes[..32], &target).is_err());
        assert!(parse(&bytes, &target[..32]).is_err());
        println!("actual parser: 6 negative inputs rejected; no fallback or kernel calls");
    }
    #[test]
    #[ignore = "requires explicitly compiled sampler objects and immutable previous objects; no kernel calls"]
    fn rebuilt_sampler_programs_map_abi_and_core_match_frozen_verifier_source() {
        let current =
            std::path::PathBuf::from(std::env::var_os("KSIGHT_METADATA_SAMPLE_DIR").unwrap());
        let previous =
            std::path::PathBuf::from(std::env::var_os("KSIGHT_METADATA_PREVIOUS_DIR").unwrap());
        let (_, target) = inputs();
        let target = Btf::parse(&target, Endianness::Little).unwrap();
        for name in [
            "process_lifecycle",
            "file_open",
            "network_connect",
            "memory_regions",
            "binder_transaction",
            "sched_wakeup",
            "uprobe_regs",
            "uprobe_instances",
        ] {
            let a = std::fs::read(previous.join(format!("{name}.bpf.o"))).unwrap();
            let b = std::fs::read(current.join(format!("{name}.bpf.o"))).unwrap();
            let mut old = Object::parse(&a).unwrap();
            let mut new = Object::parse(&b).unwrap();
            let ae = object::File::parse(a.as_slice()).unwrap();
            let be = object::File::parse(b.as_slice()).unwrap();
            assert_eq!(old.programs.len(), new.programs.len());
            for prog in old.programs.values() {
                let sec = ae
                    .section_by_index(object::SectionIndex(prog.section_index))
                    .unwrap();
                assert_eq!(
                    sec.data().unwrap(),
                    be.section_by_name(sec.name().unwrap())
                        .unwrap()
                        .data()
                        .unwrap(),
                    "program {name}"
                );
            }
            assert_eq!(old.maps.len(), new.maps.len());
            for (key, m) in &old.maps {
                let n = new.maps.get(key).unwrap();
                assert_eq!(
                    (
                        m.map_type(),
                        m.key_size(),
                        m.value_size(),
                        m.max_entries(),
                        m.map_flags()
                    ),
                    (
                        n.map_type(),
                        n.key_size(),
                        n.value_size(),
                        n.max_entries(),
                        n.map_flags()
                    ),
                    "map {name}/{key}"
                );
            }
            old.relocate_btf(&target).unwrap();
            new.relocate_btf(&target).unwrap();
            let collect = |o: &Object| {
                o.functions
                    .iter()
                    .map(|(key, f)| {
                        (
                            *key,
                            f.instructions
                                .iter()
                                .map(|i| (i.code, i.dst_reg(), i.src_reg(), i.off, i.imm))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            assert_eq!(collect(&old), collect(&new), "relocated program {name}");
            println!("{name}: full_program_sections=equal maps=equal actual_target_CORE=equal whole_ELF_equal={}",a==b);
        }
    }
    fn replace_string(bytes: &mut [u8], old: &[u8], new: &[u8]) {
        assert_eq!(old.len(), new.len());
        let mut n = 0;
        for at in 0..=bytes.len() - old.len() {
            if &bytes[at..at + old.len()] == old {
                bytes[at..at + old.len()].copy_from_slice(new);
                n += 1;
            }
        }
        assert!(n > 0);
    }
}
