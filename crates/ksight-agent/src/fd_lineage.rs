//! 跨进程文件描述符血缘追踪（关联分析层）。
//!
//! 追踪一个文件描述符的来源（文件路径或 socket 对端）在以下生命周期中的传播：
//!   open/connect/accept → dup 复制 → Binder 跨进程传输 → close 消亡。
//! 关联结果以 `transferred_fd_origin` 附加到 Binder FD 接收事件上，
//! 回答「这个通过 Binder 传来的 fd，源头是哪个文件/对端」。

use std::collections::HashMap;

use ksight_model::{
    BinderTransactionStage, EventPayload, FileDescriptorOperation, ProcessLifecycleKind,
    SocketAccept, SocketConnect,
};

/// 单个描述符的来源上限，超过后停止追踪新的来源（有界，避免无界增长）。
const MAX_ORIGINS: usize = 65_536;
/// Binder FD transfers retained while waiting for the receive-side event.
const MAX_PENDING_BINDER_FDS: usize = 16_384;

/// 追踪描述符来源并解析 Binder 跨进程传输的血缘。
#[derive(Debug, Default)]
pub struct FdLineageTracker {
    /// `(tgid, fd)` → 来源描述。
    fd_origins: HashMap<(u32, i32), String>,
    /// `(transaction_id, object_offset)` → 发送侧来源（等待接收侧配对）。
    pending_binder_fds: HashMap<(i32, u64), PendingBinderFd>,
}

#[derive(Debug, Clone)]
struct PendingBinderFd {
    origin: String,
    source_pid: u32,
    source_fd: i32,
}

impl FdLineageTracker {
    /// 关联一个事件，更新状态并回填可解析的血缘字段。
    pub fn correlate(&mut self, event: &mut ksight_model::Event) {
        let pid = event.header.process.tgid;
        match &mut event.payload {
            EventPayload::FileOpen(open) => {
                if let Some(fd) = open.file_descriptor {
                    let origin = open
                        .resolved_path
                        .as_deref()
                        .unwrap_or(&open.path)
                        .to_owned();
                    self.insert_origin(pid, fd, origin);
                }
            }
            EventPayload::FileDescriptorChange(change) => match change.operation {
                FileDescriptorOperation::Duplicate => {
                    if let Some(resulting_fd) = change.resulting_file_descriptor {
                        if let Some(origin) =
                            self.fd_origins.get(&(pid, change.file_descriptor)).cloned()
                        {
                            self.insert_origin(pid, resulting_fd, origin);
                        }
                    }
                }
                FileDescriptorOperation::Close => {
                    self.fd_origins.remove(&(pid, change.file_descriptor));
                }
                FileDescriptorOperation::CloseRange => {
                    self.close_range(pid, change);
                }
                FileDescriptorOperation::RightsSend => {}
                FileDescriptorOperation::RightsReceive => {
                    if let Some(fd) = change.requested_file_descriptor {
                        self.insert_origin(pid, fd, "unix:scm_rights".to_owned());
                    }
                }
            },
            EventPayload::ProcessLifecycle(lifecycle) => match lifecycle.kind {
                ProcessLifecycleKind::Fork => {
                    if let Some(parent) = lifecycle.parent_pid {
                        self.inherit_from(parent, pid);
                    }
                }
                ProcessLifecycleKind::Exec => self.reseed_from_proc(pid),
                ProcessLifecycleKind::Exit => {
                    if event.header.process.tid == event.header.process.tgid {
                        self.drop_process(pid);
                    }
                }
            },
            EventPayload::SocketConnect(connect) => {
                if connect.result == 0 || connect.result == -115 {
                    self.insert_origin(pid, connect.file_descriptor, socket_peer(connect));
                }
            }
            EventPayload::SocketAccept(accept) => {
                if let Some(fd) = accept.accepted_file_descriptor {
                    self.insert_origin(pid, fd, socket_peer_accept(accept));
                }
            }
            EventPayload::SessionFdBaseline(baseline) => {
                for entry in &baseline.fds {
                    self.insert_origin(baseline.process_id, entry.fd, entry.target.clone());
                }
            }
            EventPayload::BinderTransaction(transaction) => {
                self.correlate_binder(pid, transaction);
            }
            _ => {}
        }
    }

    fn correlate_binder(&mut self, pid: u32, transaction: &mut ksight_model::BinderTransaction) {
        let (Some(fd), Some(offset)) = (transaction.file_descriptor, transaction.object_offset)
        else {
            return;
        };
        match transaction.stage {
            BinderTransactionStage::FdSent => {
                let origin = self
                    .fd_origins
                    .get(&(pid, fd))
                    .cloned()
                    .or_else(|| read_fd_target(pid, fd));
                if let Some(origin) = origin {
                    if self.pending_binder_fds.len() < MAX_PENDING_BINDER_FDS {
                        self.pending_binder_fds.insert(
                            (transaction.transaction_id, offset),
                            PendingBinderFd {
                                origin,
                                source_pid: pid,
                                source_fd: fd,
                            },
                        );
                    }
                }
            }
            BinderTransactionStage::FdReceived => {
                if let Some(pending) = self
                    .pending_binder_fds
                    .remove(&(transaction.transaction_id, offset))
                {
                    transaction.transferred_fd_origin = Some(pending.origin.clone());
                    transaction.transferred_fd_source_pid = Some(pending.source_pid);
                    transaction.transferred_fd_source_fd = Some(pending.source_fd);
                    self.insert_origin(pid, fd, pending.origin);
                }
            }
            _ => {}
        }
    }

    fn insert_origin(&mut self, pid: u32, fd: i32, origin: String) {
        if origin.is_empty() || self.fd_origins.len() >= MAX_ORIGINS {
            return;
        }
        self.fd_origins.insert((pid, fd), origin);
    }

    fn inherit_from(&mut self, parent: u32, child: u32) {
        if parent == child {
            return;
        }
        let inherited = self
            .fd_origins
            .iter()
            .filter(|&(&(pid, _), _)| pid == parent)
            .map(|(&(_, fd), origin)| (fd, origin.clone()))
            .collect::<Vec<_>>();
        for (fd, origin) in inherited {
            self.insert_origin(child, fd, origin);
        }
    }

    fn close_range(&mut self, pid: u32, change: &ksight_model::FileDescriptorChange) {
        const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
        if change.flags & CLOSE_RANGE_CLOEXEC != 0 {
            return;
        }
        let first = u32::try_from(change.file_descriptor).unwrap_or(0);
        let last = change.last_file_descriptor.unwrap_or(first);
        self.fd_origins.retain(|&(owner, fd), _| {
            if owner != pid {
                return true;
            }
            let Ok(descriptor) = u32::try_from(fd) else {
                return true;
            };
            descriptor < first || descriptor > last
        });
    }

    fn drop_process(&mut self, pid: u32) {
        self.fd_origins.retain(|&(owner, _), _| owner != pid);
    }

    fn reseed_from_proc(&mut self, pid: u32) {
        self.drop_process(pid);
        let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            return;
        };
        for (index, entry) in entries.flatten().enumerate() {
            if index >= 256 {
                break;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(fd) = name.parse::<i32>() else {
                continue;
            };
            if let Some(origin) = read_fd_target(pid, fd) {
                self.insert_origin(pid, fd, origin);
            }
        }
    }
}

/// 对 scope 外进程的 fd 做用户态补读，提升跨进程血缘命中率。
fn read_fd_target(pid: u32, fd: i32) -> Option<String> {
    let target = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let value = target.to_string_lossy().into_owned();
    (!value.is_empty()).then_some(value)
}

fn socket_peer(connect: &SocketConnect) -> String {
    connect.peer_address.as_ref().map_or_else(
        || format!("socket family {}", connect.address_family),
        |address| match connect.peer_port {
            Some(port) => format!("{address}:{port}"),
            None => address.clone(),
        },
    )
}

fn socket_peer_accept(accept: &SocketAccept) -> String {
    accept.peer_address.as_ref().map_or_else(
        || format!("socket family {}", accept.address_family),
        |address| match accept.peer_port {
            Some(port) => format!("{address}:{port}"),
            None => address.clone(),
        },
    )
}
