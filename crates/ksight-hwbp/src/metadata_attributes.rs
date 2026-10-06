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

