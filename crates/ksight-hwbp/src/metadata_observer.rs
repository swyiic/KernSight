//! Explicit, one-use metadata-only candidate loader. Never selected by capture.
//! No feature probes, fallback programs, pins, user probes or payload reads.
use crate::{
    metadata_io::{self, Driver},
    metadata_object,
    metadata_scope::{PolicyWitness, QualificationPolicy, QualifiedInstance, Token},
};
use anyhow::{bail, Context, Result};
use aya_obj::generated::bpf_attr;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::Path,
};

const BTF_LIMIT: usize = 8 * 1024 * 1024;
const OBJECT_LIMIT: usize = 256 * 1024;
const LOG_LIMIT_U32: u32 = 64 * 1024;
const LOG_LIMIT: usize = LOG_LIMIT_U32 as usize;

fn raw_u32(fd: i32) -> Result<u32> {
    u32::try_from(fd).context("negative bpf descriptor")
}
fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut b)?;
    if b.len() > limit {
        bail!("metadata input exceeds bound");
    }
    Ok(b)
}
fn check_hash(bytes: &[u8], expected: [u8; 32]) -> Result<()> {
    if Sha256::digest(bytes).as_slice() != expected {
        bail!("metadata object/kernel BTF identity drift");
    }
    Ok(())
}
fn call(command: u32, attr: &bpf_attr) -> std::io::Result<i64> {
    // SAFETY: zero-initialized UAPI union; every pointer supplied by callers
    // refers to initialized data held alive throughout this synchronous call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attr,
            std::mem::size_of::<bpf_attr>(),
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
fn new_fd(command: u32, attr: &bpf_attr) -> Result<OwnedFd> {
    let raw = call(command, attr)?;
    let raw = i32::try_from(raw).context("BPF descriptor range")?;
    // SAFETY: these commands return a new descriptor on success; sole owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn log_text(log: &[u8]) -> String {
    let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
    String::from_utf8_lossy(&log[..end]).into_owned()
}
/// Loads only an explicitly hash-pinned metadata iterator. Construction issues
/// real BPF syscalls and therefore needs separate authorization on a device.
/// Qualification consumes this observer; success transfers the mark/map lease,
/// while BTF/program handles close. All resources close on error.
pub struct MetadataObserver {
    btf: OwnedFd,
    map: OwnedFd,
    program: OwnedFd,
    nonce: u64,
}
impl MetadataObserver {
    /// Does not attach until `qualify`. No automatic call from CLI or strict mode.
    ///
    /// # Errors
    ///
    /// Returns when the object or kernel BTF misses its pinned hash, or a BPF
    /// load, relocation, or nonce read fails. No program is attached.
    pub fn load(
        object_path: &Path,
        object_sha256: [u8; 32],
        kernel_btf_sha256: [u8; 32],
    ) -> Result<Self> {
        let bytes = bounded(object_path, OBJECT_LIMIT)?;
        let target = bounded(Path::new("/sys/kernel/btf/vmlinux"), BTF_LIMIT)?;
        check_hash(&bytes, object_sha256)?;
        check_hash(&target, kernel_btf_sha256)?;
        let mut parsed = metadata_object::parse(&bytes, &target)?;
        let btf_bytes = parsed
            .object
            .btf
            .as_ref()
            .context("metadata local BTF")?
            .to_bytes();
        let mut log = vec![0u8; LOG_LIMIT];
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.__bindgen_anon_7.btf = btf_bytes.as_ptr() as u64;
        attr.__bindgen_anon_7.btf_size =
            u32::try_from(btf_bytes.len()).context("metadata BTF length")?;
        attr.__bindgen_anon_7.btf_log_buf = log.as_mut_ptr() as u64;
        attr.__bindgen_anon_7.btf_log_size = LOG_LIMIT_U32;
        attr.__bindgen_anon_7.btf_log_level = 1;
        let btf = new_fd(18, &attr).with_context(|| {
            format!(
                "metadata BTF_LOAD command=18 btf_size={} log_level=1: {}",
                btf_bytes.len(),
                log_text(&log)
            )
        })?;
        let map_spec = parsed
            .object
            .maps
            .get("metadata_task_v1")
            .context("metadata map")?
            .clone();
        let aya_obj::maps::Map::Btf(m) = &map_spec else {
            bail!("BTF task map required");
        };
        attr = unsafe { std::mem::zeroed() };
        attr.__bindgen_anon_1 = crate::metadata_attributes::task_map(
            raw_u32(btf.as_raw_fd())?,
            m.def.btf_key_type_id,
            m.def.btf_value_type_id,
        );
        let map_arguments =
            crate::metadata_attributes::map_diagnostic(unsafe { &attr.__bindgen_anon_1 });
        let map = new_fd(0, &attr).with_context(|| format!(
            "metadata TASK_STORAGE create: BTF_LOAD=accepted local_btf_bytes={} target_btf_sha256={:x} {}",
            btf_bytes.len(), Sha256::digest(&target), map_arguments
        ))?;
        parsed.object.relocate_maps(
            std::iter::once(("metadata_task_v1", map.as_raw_fd(), &map_spec)),
            &HashSet::default(),
        )?;
        parsed.object.relocate_calls(&HashSet::default())?;
        let f = parsed
            .object
            .functions
            .get(&parsed.program_key)
            .context("metadata relocated function")?;
        if f.instructions.len() > 4096 || f.func_info.func_info.len() != 1 {
            bail!("metadata function bounds");
        }
        attr = unsafe { std::mem::zeroed() };
        log.fill(0);
        attr.__bindgen_anon_3.prog_type = 26;
        attr.__bindgen_anon_3.expected_attach_type = 28;
        attr.__bindgen_anon_3.attach_btf_id = parsed.attach_btf_id;
        attr.__bindgen_anon_3.insn_cnt =
            u32::try_from(f.instructions.len()).context("metadata instruction count")?;
        attr.__bindgen_anon_3.insns = f.instructions.as_ptr() as u64;
        attr.__bindgen_anon_3.license = c"GPL".as_ptr() as u64;
        attr.__bindgen_anon_3.prog_btf_fd = raw_u32(btf.as_raw_fd())?;
        attr.__bindgen_anon_3.func_info_rec_size = 8;
        attr.__bindgen_anon_3.func_info_cnt = 1;
        attr.__bindgen_anon_3.func_info = f.func_info.func_info.as_ptr() as u64;
        attr.__bindgen_anon_3.log_level = 4; // errors/stats; bounded log without instruction trace
        attr.__bindgen_anon_3.log_size = LOG_LIMIT_U32;
        attr.__bindgen_anon_3.log_buf = log.as_mut_ptr() as u64;
        let mut prog_name = [0; 16];
        for (d, s) in prog_name.iter_mut().zip(b"ksmeta_v1") {
            *d = libc::c_char::try_from(*s).context("metadata program name")?;
        }
        attr.__bindgen_anon_3.prog_name = prog_name;
        let program = new_fd(5, &attr)
            .with_context(|| format!("metadata TRACE_ITER load: BTF_LOAD=accepted TASK_STORAGE=accepted {} command=5 prog_type=26 expected_attach_type=28 attach_btf_id={} instructions={}: {}", map_arguments, parsed.attach_btf_id, f.instructions.len(), log_text(&log)))?;
        let mut nonce = 0u64;
        // SAFETY: eight writable bytes, nonblocking entropy; no retry/fallback.
        let n = unsafe { libc::getrandom((&raw mut nonce).cast(), 8, libc::GRND_NONBLOCK) };
        if n != 8 || nonce == 0 {
            bail!("metadata nonce unavailable");
        }
        Ok(Self {
            btf,
            map,
            program,
            nonce,
        })
    }
    /// Package enrollment is caller policy, not an attestation generated by this
    /// observer. Two kernel snapshots bracket the same-handle policy reader.
    ///
    /// # Errors
    ///
    /// Returns when qualification refuses the pidfd or policy witness. The
    /// observer closes its BTF and program handles on both success and failure.
    pub fn qualify(
        mut self,
        policy: &QualificationPolicy,
        pidfd: OwnedFd,
        witness: impl FnMut(
            BorrowedFd<'_>,
            crate::instance_scope::InstanceIdentity,
        ) -> Result<PolicyWitness>,
    ) -> Result<QualifiedInstance> {
        let nonce = self.nonce;
        let qualified = metadata_io::issue(&mut self, nonce, policy, pidfd, witness)?;
        let Self {
            map, btf, program, ..
        } = self;
        drop(program);
        drop(btf);
        // Keep the map and immutable round-two grant until all sampler/runtime
        // handles close. On any issue error self drops every resource instead.
        Ok(qualified.attach_lease(map, Token { nonce, round: 2 }))
    }
}
impl Driver for MetadataObserver {
    type Handle = OwnedFd;
    fn grant(&mut self, pidfd: BorrowedFd<'_>, token: Token, existing: bool) -> Result<()> {
        let key = pidfd.as_raw_fd();
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.__bindgen_anon_2.map_fd = raw_u32(self.map.as_raw_fd())?;
        attr.__bindgen_anon_2.key = (&raw const key) as u64;
        attr.__bindgen_anon_2.__bindgen_anon_1.value = (&raw const token) as u64;
        attr.__bindgen_anon_2.flags = if existing { 2 } else { 1 }; // EXIST / NOEXIST
        call(2, &attr).context("metadata exact-task grant update")?;
        Ok(())
    }
    fn remove(&mut self, pidfd: BorrowedFd<'_>) -> Result<()> {
        let key = pidfd.as_raw_fd();
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.__bindgen_anon_2.map_fd = raw_u32(self.map.as_raw_fd())?;
        attr.__bindgen_anon_2.key = (&raw const key) as u64;
        match call(3, &attr) {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e).context("metadata grant cleanup"),
        }
    }
    fn link(&mut self, info: [u32; 3]) -> Result<OwnedFd> {
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.link_create.__bindgen_anon_1.prog_fd = raw_u32(self.program.as_raw_fd())?;
        attr.link_create.attach_type = 28;
        attr.link_create.__bindgen_anon_3.__bindgen_anon_1.iter_info = info.as_ptr() as u64;
        attr.link_create
            .__bindgen_anon_3
            .__bindgen_anon_1
            .iter_info_len = 12;
        new_fd(28, &attr).context("metadata pidfd-scoped iterator link")
    }
    fn iterator(&mut self, link: BorrowedFd<'_>) -> Result<OwnedFd> {
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.iter_create.link_fd = raw_u32(link.as_raw_fd())?;
        new_fd(33, &attr).context("metadata iterator file")
    }
    fn read(&mut self, iterator: OwnedFd) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::from(iterator).take(49).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn alive(&mut self, pidfd: BorrowedFd<'_>) -> Result<bool> {
        crate::task_storage::alive(pidfd)
    }
}
