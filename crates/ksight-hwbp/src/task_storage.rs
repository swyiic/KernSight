//! Published Linux UAPI only: `TASK_STORAGE` keys are pidfds, not TGIDs.
use super::instance_scope::AllowValue;
use anyhow::{bail, Context, Result};
use aya::maps::{Map, MapData, MapType};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

// Linux v6.1.124 include/uapi/linux/bpf.h, MAP_*_ELEM union prefix.
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}
const _: () = assert!(std::mem::size_of::<ElemAttr>() == 32);

pub(crate) fn checked_map(map: &Map) -> Result<&MapData> {
    let Map::Unsupported(data) = map else {
        bail!("task-storage map missing or wrong kind");
    };
    let info = data.info()?;
    if info.map_type()? != MapType::TaskStorage
        || info.key_size() != 4
        || info.value_size() != 24
        || info.max_entries() != 0
        || info.map_flags() != 1
    {
        bail!("task-storage ABI/flags mismatch; cloning grants is forbidden");
    }
    Ok(data)
}
fn element(
    map: &MapData,
    pidfd: BorrowedFd<'_>,
    command: u32,
    value: Option<&AllowValue>,
) -> std::io::Result<()> {
    let key = pidfd.as_raw_fd();
    let map_fd = u32::try_from(map.fd().as_fd().as_raw_fd()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "task-storage map descriptor",
        )
    })?;
    let attr = ElemAttr {
        map_fd,
        padding: 0,
        key: (&raw const key) as u64,
        value: value.map_or(0, |item| std::ptr::from_ref(item) as u64),
        flags: u64::from(value.is_some()),
    }; // BPF_NOEXIST when a value is inserted.
       // SAFETY: kernel synchronously copies this initialized UAPI prefix and the
       // live key/value; both borrowed map/pidfd handles remain owned by callers.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            &attr,
            std::mem::size_of::<ElemAttr>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
pub(crate) fn insert(map: &MapData, pidfd: BorrowedFd<'_>, value: AllowValue) -> Result<()> {
    element(map, pidfd, 2, Some(&value)).context("bind exact task via owned pidfd")
}
pub(crate) fn remove(map: &MapData, pidfd: BorrowedFd<'_>) -> Result<()> {
    match element(map, pidfd, 3, None) {
        Ok(()) => Ok(()),
        // Exited tasks/absent grant are already denied. Other errors revoke.
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(e) => Err(e).context("remove exact task grant"),
    }
}
pub(crate) fn alive(pidfd: BorrowedFd<'_>) -> Result<bool> {
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: a single initialized pollfd, zero timeout, no handle mutation.
    let rc = unsafe { libc::poll(&raw mut p, 1, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("pidfd poll");
    }
    if p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        bail!("pidfd invalid");
    }
    Ok(p.revents == 0)
}
