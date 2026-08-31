//! ARM64 uprobe 寄存器采集。
//!
//! 挂载 uprobe 到目标进程函数入口，命中时读取用户态 `pt_regs` 现场。
//! 相比硬件断点（`perf_event` 采样被 Android GKI 内核 EPERM 拒绝），
//! uprobe 的 ctx 直接就是用户态寄存器，无需 perf 采样权限。
//!
//! 模块划分：
//! - [`registers`]：寄存器上下文类型与解码（纯逻辑，跨平台）
//! - [`uprobe`]：uprobe 加载 + 命中即撤（仅 Linux/Android）

mod cpu_list;
pub mod registers;

pub use registers::RegisterContext;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod kprobe;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod uprobe;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use kprobe::{attach_kprobe_all_cpus, KprobeSession};
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use uprobe::UprobeSession;

/// Inclusive `close_range(2)` for the on-device FD probe. Safe wrapper around
/// the syscall so the agent crate can keep `forbid(unsafe_code)`.
///
/// # Errors
///
/// Returns when the kernel rejects the range or the syscall is unavailable.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn close_range(first: i32, last: i32, flags: u32) -> std::io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            libc::c_uint::try_from(first).unwrap_or(0),
            libc::c_uint::try_from(last).unwrap_or(u32::MAX),
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
