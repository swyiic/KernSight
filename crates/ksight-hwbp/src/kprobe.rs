//! System-wide kprobe attach on every online CPU.
//!
//! Aya 0.13 `KProbe::attach` opens `perf_event` only on CPU 0. Binder
//! transactions run on other CPUs, so parcel copy would miss them.

use std::{
    ffi::CString,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
};

use anyhow::{Context, Result};

use crate::cpu_list::online_cpu_ids;

/// Held per-CPU kprobe perf events. Dropping detaches.
#[derive(Debug)]
pub struct KprobeSession {
    _events: Vec<OwnedFd>,
}

impl KprobeSession {
    /// How many CPUs the probe is armed on.
    #[must_use]
    pub fn cpu_count(&self) -> usize {
        self._events.len()
    }
}

/// Attach a loaded `BPF_PROG_TYPE_KPROBE` to `symbol` on every online CPU.
///
/// # Errors
///
/// Returns when the kprobe PMU is missing or every CPU attach fails.
pub fn attach_kprobe_all_cpus(prog_fd: i32, symbol: &str) -> Result<KprobeSession> {
    let ty: u32 = std::fs::read_to_string("/sys/bus/event_source/devices/kprobe/type")
        .context("read kprobe PMU type")?
        .trim()
        .parse()
        .context("parse kprobe PMU type")?;
    let name = CString::new(symbol).context("kprobe symbol")?;
    let mut attached = Vec::new();
    let mut last_error = None;
    for cpu in online_cpu_ids() {
        let cpu = i32::try_from(cpu).unwrap_or(0);
        match open_kprobe_on_cpu(ty, name.as_ptr(), prog_fd, cpu) {
            Ok(fd) => attached.push(fd),
            Err(error) => last_error = Some(error),
        }
    }
    if attached.is_empty() {
        return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("kprobe attached on no CPUs")));
    }
    Ok(KprobeSession { _events: attached })
}

fn open_kprobe_on_cpu(
    pmu_type: u32,
    symbol: *const libc::c_char,
    prog_fd: i32,
    cpu: i32,
) -> Result<OwnedFd> {
    #[repr(C)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        bits: u64,
        wakeup_events: u32,
        bp_type: u32,
        config1: u64,
        config2: u64,
        _rest: [u64; 8],
    }
    let attr = PerfEventAttr {
        type_: pmu_type,
        size: u32::try_from(std::mem::size_of::<PerfEventAttr>()).unwrap_or(128),
        config: 0,
        sample_period: 0,
        sample_type: 0,
        read_format: 0,
        bits: 0,
        wakeup_events: 0,
        bp_type: 0,
        config1: symbol as u64,
        config2: 0,
        _rest: [0; 8],
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            std::ptr::addr_of!(attr),
            -1_i32,
            cpu,
            -1_i32,
            8, // PERF_FLAG_FD_CLOEXEC
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("perf_event_open kprobe cpu={cpu}"));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).context("perf fd")?) };
    // PERF_EVENT_IOC_SET_BPF = _IOW('$', 8, __u32); ENABLE = _IO('$', 0)
    // Linux libc exposes ioctl's request as `c_ulong`; keeping these as that
    // type also avoids host-dependent inference when CI checks Linux targets.
    const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
    const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
    let set = unsafe { libc::ioctl(owned.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, prog_fd) };
    if set < 0 {
        return Err(std::io::Error::last_os_error()).context("PERF_EVENT_IOC_SET_BPF");
    }
    let enable = unsafe { libc::ioctl(owned.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0) };
    if enable < 0 {
        return Err(std::io::Error::last_os_error()).context("PERF_EVENT_IOC_ENABLE");
    }
    Ok(owned)
}
