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

#[cfg(test)]
mod tests {
    use ksight_model::{
        BinderTransaction, BinderTransactionDirection, BinderTransactionStage, Event,
        FileDescriptorChange, FileDescriptorOperation, FileOpen, MemoryOperation,
        MemoryRegionChange, ProcessLifecycle, ProcessLifecycleKind,
    };

    use super::*;

    #[test]
    fn open_then_duplicate_inherits_origin() {
        let mut tracker = FdLineageTracker::default();
        let mut open = file_open(100, 3, "/data/data/app/db.sqlite");
        tracker.correlate(&mut open);

        let mut dup = fd_dup(100, 3, 7);
        tracker.correlate(&mut dup);

        let mut transfer = binder_fd(100, 42, 7, 0x10, BinderTransactionStage::FdSent);
        tracker.correlate(&mut transfer);

        let mut received = binder_fd(200, 42, 9, 0x10, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received);

        let EventPayload::BinderTransaction(tx) = &received.payload else {
            panic!("expected binder transaction");
        };
        assert_eq!(
            tx.transferred_fd_origin.as_deref(),
            Some("/data/data/app/db.sqlite")
        );
    }

    #[test]
    fn unpaired_received_fd_has_no_origin() {
        let mut tracker = FdLineageTracker::default();
        let mut received = binder_fd(200, 42, 9, 0x10, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received);

        let EventPayload::BinderTransaction(tx) = &received.payload else {
            panic!("expected binder transaction");
        };
        assert!(tx.transferred_fd_origin.is_none());
    }

    #[test]
    fn close_removes_origin() {
        let mut tracker = FdLineageTracker::default();
        let mut open = file_open(100, 3, "/tmp/x");
        tracker.correlate(&mut open);

        let mut close = fd_close(100, 3);
        tracker.correlate(&mut close);

        let mut transfer = binder_fd(100, 42, 3, 0x10, BinderTransactionStage::FdSent);
        tracker.correlate(&mut transfer);
        let mut received = binder_fd(200, 42, 9, 0x10, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received);

        let EventPayload::BinderTransaction(tx) = &received.payload else {
            panic!("expected binder transaction");
        };
        assert!(tx.transferred_fd_origin.is_none());
    }

    #[test]
    fn baseline_seeds_binder_fd_origin() {
        let mut tracker = FdLineageTracker::default();
        let mut baseline = Event {
            header: header(100),
            payload: EventPayload::SessionFdBaseline(ksight_model::SessionFdBaseline {
                process_id: 100,
                fds: vec![ksight_model::BaselineFd {
                    fd: 7,
                    kind: ksight_model::BaselineFdKind::File,
                    target: "/data/app/base.apk".to_owned(),
                }],
                chunk_index: 0,
                chunk_count: 1,
            }),
        };
        tracker.correlate(&mut baseline);
        let mut sent = binder_fd(100, 42, 7, 0x10, BinderTransactionStage::FdSent);
        tracker.correlate(&mut sent);
        let mut received = binder_fd(200, 42, 9, 0x10, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received);

        let EventPayload::BinderTransaction(transaction) = received.payload else {
            panic!("expected Binder transaction");
        };
        assert_eq!(
            transaction.transferred_fd_origin.as_deref(),
            Some("/data/app/base.apk")
        );
        assert_eq!(transaction.transferred_fd_source_pid, Some(100));
        assert_eq!(transaction.transferred_fd_source_fd, Some(7));
    }

    #[test]
    fn fork_inherits_observed_descriptors() {
        let mut tracker = FdLineageTracker::default();
        let mut open = file_open(100, 3, "/tmp/inherited");
        tracker.correlate(&mut open);
        let mut fork = Event {
            header: header(200),
            payload: EventPayload::ProcessLifecycle(ProcessLifecycle {
                kind: ProcessLifecycleKind::Fork,
                parent_pid: Some(100),
                filename: None,
                exit_code: None,
                zygote_source: None,
            }),
        };
        tracker.correlate(&mut fork);
        let mut sent = binder_fd(200, 7, 3, 0x20, BinderTransactionStage::FdSent);
        tracker.correlate(&mut sent);
        let mut received = binder_fd(300, 7, 8, 0x20, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received);
        let EventPayload::BinderTransaction(transaction) = received.payload else {
            panic!("expected Binder transaction");
        };
        assert_eq!(
            transaction.transferred_fd_origin.as_deref(),
            Some("/tmp/inherited")
        );
    }

    #[test]
    fn close_range_drops_inclusive_descriptors() {
        let mut tracker = FdLineageTracker::default();
        tracker.correlate(&mut file_open(100, 3, "/tmp/a"));
        tracker.correlate(&mut file_open(100, 4, "/tmp/b"));
        tracker.correlate(&mut file_open(100, 8, "/tmp/c"));
        let mut range = Event {
            header: header(100),
            payload: EventPayload::FileDescriptorChange(FileDescriptorChange {
                operation: FileDescriptorOperation::CloseRange,
                file_descriptor: 3,
                requested_file_descriptor: Some(4),
                resulting_file_descriptor: None,
                result: 0,
                command: 436,
                flags: 0,
                last_file_descriptor: Some(4),
            }),
        };
        tracker.correlate(&mut range);
        let mut sent_closed = binder_fd(100, 1, 3, 0x10, BinderTransactionStage::FdSent);
        tracker.correlate(&mut sent_closed);
        let mut received_closed = binder_fd(200, 1, 9, 0x10, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received_closed);
        let EventPayload::BinderTransaction(closed) = received_closed.payload else {
            panic!("expected Binder transaction");
        };
        assert!(closed.transferred_fd_origin.is_none());

        let mut sent_kept = binder_fd(100, 2, 8, 0x18, BinderTransactionStage::FdSent);
        tracker.correlate(&mut sent_kept);
        let mut received_kept = binder_fd(200, 2, 10, 0x18, BinderTransactionStage::FdReceived);
        tracker.correlate(&mut received_kept);
        let EventPayload::BinderTransaction(kept) = received_kept.payload else {
            panic!("expected Binder transaction");
        };
        assert_eq!(kept.transferred_fd_origin.as_deref(), Some("/tmp/c"));
    }

    fn file_open(pid: u32, fd: i32, path: &str) -> Event {
        Event {
            header: header(pid),
            payload: EventPayload::FileOpen(FileOpen {
                directory_fd: -100,
                file_descriptor: Some(fd),
                result: fd,
                flags: 0,
                mode: 0,
                path: path.to_owned(),
                resolved_path: Some(path.to_owned()),
                content_sha256: None,
                content_bytes: None,
            }),
        }
    }

    fn fd_dup(pid: u32, old_fd: i32, new_fd: i32) -> Event {
        Event {
            header: header(pid),
            payload: EventPayload::FileDescriptorChange(FileDescriptorChange {
                operation: FileDescriptorOperation::Duplicate,
                file_descriptor: old_fd,
                requested_file_descriptor: Some(new_fd),
                resulting_file_descriptor: Some(new_fd),
                result: new_fd,
                command: 0,
                flags: 0,
                last_file_descriptor: None,
            }),
        }
    }

    fn fd_close(pid: u32, fd: i32) -> Event {
        Event {
            header: header(pid),
            payload: EventPayload::FileDescriptorChange(FileDescriptorChange {
                operation: FileDescriptorOperation::Close,
                file_descriptor: fd,
                requested_file_descriptor: None,
                resulting_file_descriptor: None,
                result: 0,
                command: 0,
                flags: 0,
                last_file_descriptor: None,
            }),
        }
    }

    fn binder_fd(
        pid: u32,
        transaction_id: i32,
        fd: i32,
        object_offset: u64,
        stage: BinderTransactionStage,
    ) -> Event {
        Event {
            header: header(pid),
            payload: EventPayload::BinderTransaction(BinderTransaction {
                stage,
                transaction_id,
                target_node: None,
                target_process_id: None,
                target_thread_id: None,
                target_kind: None,
                reply: false,
                direction: BinderTransactionDirection::Request,
                reply_to_request_id: None,
                reply_latency_ns: None,
                code: 0,
                code_kind: None,
                flags: 0,
                decoded_flags: Vec::new(),
                data_size: None,
                offsets_size: None,
                extra_buffers_size: None,
                file_descriptor: Some(fd),
                object_offset: Some(object_offset),
                transferred_fd_origin: None,
                transferred_fd_source_pid: None,
                transferred_fd_source_fd: None,
                interface_token: None,
                binder_method: None,
                binder_method_source: None,
                parcel_prefix_hex: None,
            }),
        }
    }

    fn header(pid: u32) -> ksight_model::EventHeader {
        use ksight_model::{
            CaptureMode, Confidence, DataQuality, ProcessIdentity, ProcessKey, SensorKind,
        };
        use uuid::Uuid;

        ksight_model::EventHeader {
            schema: ksight_model::CURRENT_SCHEMA,
            session_id: Uuid::nil(),
            source_sequence: 1,
            monotonic_ns: 1,
            cpu: Some(0),
            process: ProcessIdentity {
                key: ProcessKey {
                    boot_id: Uuid::nil(),
                    pid,
                    start_time_ns: 0,
                },
                tid: pid,
                tgid: pid,
                uid: 0,
                gid: 0,
                comm: "test".to_owned(),
                command_line: None,
                selinux_context: None,
                packages: Vec::new(),
            },
            sensor: SensorKind::Binder,
            mode: CaptureMode::Observe,
            quality: DataQuality {
                confidence: Confidence::Partial,
                truncated: false,
                lost_before: 0,
                sample_one_in: 1,
                source: "test".to_owned(),
            },
        }
    }

    #[allow(dead_code)]
    fn memory(pid: u32) -> Event {
        Event {
            header: header(pid),
            payload: EventPayload::MemoryRegionChange(MemoryRegionChange {
                operation: MemoryOperation::Map,
                address: 0,
                length: 0,
                result: 0,
                protection: 0,
                mapping_flags: None,
                file_descriptor: None,
                backing_path: None,
                offset: None,
            }),
        }
    }
}
