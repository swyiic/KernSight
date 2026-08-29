//! ARM64 uprobe 寄存器采集。
//!
//! 挂载 uprobe 到目标进程函数入口，命中时读取用户态 `pt_regs` 现场。
//! 相比硬件断点（`perf_event` 采样被 Android GKI 内核 EPERM 拒绝），
//! uprobe 的 ctx 直接就是用户态寄存器，无需 perf 采样权限。
//!
//! 模块划分：
//! - [`registers`]：寄存器上下文类型与解码（纯逻辑，跨平台）
//! - [`uprobe`]：uprobe 加载 + 命中即撤（仅 Linux/Android）

pub mod registers;

pub use registers::RegisterContext;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod uprobe;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use uprobe::UprobeSession;
