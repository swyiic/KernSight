//! Pure `MAP_CREATE` construction shared by the physical issuer and host tests.
//! Kernel object names are informational; the ELF relocation key stays unchanged.
use aya_obj::generated::bpf_attr__bindgen_ty_1;

pub(crate) fn task_map(btf_fd: u32, key_type: u32, value_type: u32) -> bpf_attr__bindgen_ty_1 {
    // SAFETY: zeroed published UAPI attributes, without pointers or syscall execution.
    let mut arg: bpf_attr__bindgen_ty_1 = unsafe { std::mem::zeroed() };
    arg.map_type = 29;
    arg.key_size = 4;
    arg.value_size = 16;
    arg.max_entries = 0;
    arg.map_flags = 1; // BPF_F_NO_PREALLOC, required by TASK_STORAGE.
    arg.btf_fd = btf_fd;
    arg.btf_key_type_id = key_type;
    arg.btf_value_type_id = value_type;
    // BPF_OBJ_NAME_LEN includes the terminator. The 16-byte ELF symbol must not
    // fill all 16 bytes of this syscall field (kernel rejects it with EINVAL).
    for (dst, src) in arg.map_name.iter_mut().take(15).zip(b"metadata_task_v1") {
        *dst = std::ffi::c_char::from_ne_bytes([*src]);
    }
    arg
}

pub(crate) fn map_diagnostic(arg: &bpf_attr__bindgen_ty_1) -> String {
    let name: String = arg
        .map_name
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| char::from(b.to_ne_bytes()[0]))
        .collect();
    format!("command=0 attr_size={} type={} key_size={} value_size={} max_entries={} flags={} btf_fd={} btf_key_type_id={} btf_value_type_id={} map_name={} name_nul_terminated={}", std::mem::size_of::<aya_obj::generated::bpf_attr>(), arg.map_type, arg.key_size, arg.value_size, arg.max_entries, arg.map_flags, arg.btf_fd, arg.btf_key_type_id, arg.btf_value_type_id, name, arg.map_name.contains(&0))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Published bpf_obj_name_cpy rejects a full array lacking NUL.
    fn kernel_name_result(name: &[std::ffi::c_char; 16]) -> Result<(), i32> {
        if name.iter().any(|b| {
            *b != 0
                && !(b.to_ne_bytes()[0]).is_ascii_alphanumeric()
                && !b"_.".contains(&(b.to_ne_bytes()[0]))
        }) || !name.contains(&0)
        {
            Err(22)
        } else {
            Ok(())
        }
    }
    #[test]
    fn production_task_map_preserves_abi_and_terminates_exact_sixteen_byte_symbol() {
        let a = task_map(7, 2, 39);
        assert_eq!(
            (
                a.map_type,
                a.key_size,
                a.value_size,
                a.max_entries,
                a.map_flags
            ),
            (29, 4, 16, 0, 1)
        );
        assert_eq!(
            (a.btf_fd, a.btf_key_type_id, a.btf_value_type_id),
            (7, 2, 39)
        );
        assert_eq!(a.map_name[15], 0);
        assert_eq!(kernel_name_result(&a.map_name), Ok(()));
        let old = b"metadata_task_v1".map(|b| std::ffi::c_char::from_ne_bytes([b]));
        assert_eq!(kernel_name_result(&old), Err(22));
        assert_eq!(a.map_name[..15], old[..15]);
        // The informational syscall name cannot replace the ELF relocation key.
        assert_eq!(b"metadata_task_v1".len(), 16);
    }
    #[test]
    fn production_diagnostic_retains_type_flags_and_btf_dependency_ids() {
        let d = map_diagnostic(&task_map(9, 11, 17));
        for s in [
            "command=0",
            "type=29",
            "key_size=4",
            "value_size=16",
            "max_entries=0",
            "flags=1",
            "btf_fd=9",
            "btf_key_type_id=11",
            "btf_value_type_id=17",
            "name_nul_terminated=true",
        ] {
            assert!(d.contains(s), "{d}");
        }
    }
}
