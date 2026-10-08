//! uprobe 寄存器采集：挂载 uprobe 到目标 ELF 的指定文件偏移处，
//! 命中时读取用户态 `pt_regs` 现场。
//!
//! 痕迹最小化要点：
//! - 可选 `pid` 过滤；明文全机模式才允许 `pid = None`
//! - `bpf_link`：Aya 走 `perf_event` + `bpf_link`，不经过 `tracefs` 枚举
//! - 命中即撤仍可用于 linker 单次探针；流量采集必须保持挂载并排空 perf buffer
//! - 不 pin：进程退出即卸载，无 bpffs 残留
//!
//! Entry + uretprobe for `SSL_read` MUST share one loaded BPF object so the
//! `entry_ptr` map written on entry is visible when the return probe snapshots
//! the filled buffer. Separate `load_file` sessions left return probes blind.

use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    maps::{perf::PerfEventArray, Array, HashMap, MapData},
    programs::{uprobe::UProbeLinkId, UProbe},
    Btf, Ebpf, EbpfLoader,
};

use super::instance_scope::{
    self, AllowValue, BoundInstance, InstanceIdentity, InstanceMaps, ScopeKey, ScopeState,
};
use super::registers::RegisterContext;
// C map types are repr(C), entirely integer fields with no padding/uninitialized bytes.
unsafe impl aya::Pod for ScopeKey {}
unsafe impl aya::Pod for AllowValue {}
struct BpfInstanceMaps<'a>(&'a mut Ebpf);
impl InstanceMaps for BpfInstanceMaps<'_> {
    fn unbind(&mut self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        crate::task_storage::remove(
            crate::task_storage::checked_map(
                self.0
                    .map("scope_task_v1")
                    .context("task-storage map missing")?,
            )?,
            pidfd,
        )
    }
    fn bind(&mut self, target: &BoundInstance, value: AllowValue) -> Result<()> {
        let map = crate::task_storage::checked_map(
            self.0
                .map("scope_task_v1")
                .context("task-storage map missing")?,
        )?;
        let lease = target
            .metadata_lease
            .as_ref()
            .context("physical metadata lease required before task bind")?;
        let check = || lease.check(target.pidfd.as_fd());
        crate::metadata_lease::guarded_bind(check, || {
            crate::task_storage::insert(map, target.pidfd.as_fd(), value)
        })
    }
    fn gate(&mut self, mode: u32) -> Result<()> {
        BpfFilterMaps(self.0).gate(mode)
    }
    fn epoch(&mut self, epoch: u32) -> Result<()> {
        let mut map: Array<&mut MapData, u32> = Array::try_from(
            self.0
                .map_mut("scope_epoch_v1")
                .context("instance epoch map missing")?,
        )?;
        map.set(0, epoch, 0).context("write instance epoch")
    }
    fn remove(&mut self, key: ScopeKey) -> Result<()> {
        let mut map: HashMap<&mut MapData, ScopeKey, AllowValue> = HashMap::try_from(
            self.0
                .map_mut("scope_allow_v1")
                .context("instance allow map missing")?,
        )?;
        map.remove(&key).context("remove prior instance row")
    }
    fn insert(&mut self, key: ScopeKey, value: AllowValue) -> Result<()> {
        let mut map: HashMap<&mut MapData, ScopeKey, AllowValue> = HashMap::try_from(
            self.0
                .map_mut("scope_allow_v1")
                .context("instance allow map missing")?,
        )?;
        map.insert(key, value, 1)
            .context("insert immutable instance row") // BPF_NOEXIST
    }
}
use super::tgid_filter::{self, FilterMaps};
use crate::perf_drain::{drain_reads, PerfDrainReport, PerfRead};

struct BpfFilterMaps<'a>(&'a mut Ebpf);

impl FilterMaps for BpfFilterMaps<'_> {
    fn gate(&mut self, mode: u32) -> Result<()> {
        let map = self
            .0
            .map_mut("tgid_filter_v2")
            .context("tgid_filter_v2 missing; legacy object refused before attach")?;
        let mut filter: Array<&mut MapData, u32> =
            Array::try_from(map).context("打开 tgid_filter_v2")?;
        filter.set(0, mode, 0).context("写入 tgid_filter_v2")
    }

    fn remove(&mut self, tgid: u32) -> Result<()> {
        let map = self
            .0
            .map_mut("tgid_allow")
            .context("tgid_allow map 缺失")?;
        let mut allow: HashMap<&mut MapData, u32, u32> =
            HashMap::try_from(map).context("打开 tgid_allow")?;
        allow.remove(&tgid).context("移除旧 tgid_allow")
    }

    fn insert(&mut self, tgid: u32) -> Result<()> {
        let map = self
            .0
            .map_mut("tgid_allow")
            .context("tgid_allow map 缺失")?;
        let mut allow: HashMap<&mut MapData, u32, u32> =
            HashMap::try_from(map).context("打开 tgid_allow")?;
        allow.insert(tgid, 1, 0).context("写入 tgid_allow")
    }
}

/// 一次 uprobe 采集会话。
pub struct UprobeSession {
    bpf: Ebpf,
    /// (program name, link) pairs — one for entry-only, two for entry+return.
    links: Vec<(String, UProbeLinkId)>,
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<MapData>>,
    // Reused across read batches, CPUs and polls; no 8x8KiB allocation per read.
    read_slots: [bytes::BytesMut; 8],
    hit_once: bool,
    finished: bool,
    tgid_keys: Vec<u32>,
    instance_scope: Option<ScopeState>,
    /// True when this session owns both entry and uretprobe on the same object.
    pub paired_entry_return: bool,
    /// Total valid records drained from the perf buffers.
    pub drained_total: u64,
    pub decode_counters: crate::registers::DecodeCounters,
    /// Total records the kernel reports as lost (ring overflow).
    pub lost_total: u64,
}

/// Arguments that used to trail `start_configured`. Grouped so the attach
/// entry points stay within Clippy's argument limit. This does not add a
/// capture mode.
#[derive(Debug, Clone, Copy)]
pub struct UprobeAttach<'a> {
    pub offset: u64,
    pub pid: Option<i32>,
    pub hit_once: bool,
    pub tgids: Option<&'a [u32]>,
    pub snapshot: Option<[u64; 6]>,
}

fn instance_context_value_size() -> Result<u32> {
    u32::try_from(crate::registers::INSTANCE_CONTEXT_SIZE)
        .context("instance context size exceeds u32")
}

fn reject_wrong_instance_maps(bpf: &Ebpf) -> Result<()> {
    for (name, map) in bpf.maps() {
        if matches!(map, aya::maps::Map::Unsupported(_)) && name != "scope_task_v1" {
            anyhow::bail!("unexpected unsupported map {name}; instance attach refused");
        }
    }
    let Some(aya::maps::Map::PerCpuArray(map)) = bpf.map("hwbp_ctx") else {
        anyhow::bail!("instance context map missing; legacy object refused before attach");
    };
    if map.info()?.value_size() != instance_context_value_size()? {
        anyhow::bail!("instance context ABI mismatch; legacy object refused before attach");
    }
    crate::task_storage::checked_map(
        bpf.map("scope_task_v1")
            .context("exact pidfd task-storage map missing; raw-only object refused")?,
    )?;
    let _: Array<&MapData, u32> = Array::try_from(
        bpf.map("scope_epoch_v1")
            .context("instance epoch map missing")?,
    )?;
    let _: HashMap<&MapData, ScopeKey, AllowValue> = HashMap::try_from(
        bpf.map("scope_allow_v1")
            .context("instance allow map missing")?,
    )?;
    Ok(())
}

impl UprobeSession {
    /// 挂载 uprobe 到目标 ELF 的指定文件偏移处。
    ///
    /// `pid` 为 `None` 时对所有映射该 inode 的进程生效。`hit_once` 为真时第一次命中后 detach。
    ///
    /// # Errors
    ///
    /// 当 BPF 对象、程序或 perf event map 无法加载，uprobe 无法挂载，或没有任何 CPU
    /// perf buffer 可用时返回错误。
    pub fn start(
        object: &Path,
        target: &Path,
        offset: u64,
        pid: Option<i32>,
        hit_once: bool,
    ) -> Result<Self> {
        Self::start_program(object, "ksight_uprobe_regs", target, offset, pid, hit_once)
    }

    /// Attach a named uprobe/uretprobe program from the same object.
    ///
    /// # Errors
    ///
    /// Returns when the named program cannot be loaded or attached.
    pub fn start_program(
        object: &Path,
        program: &str,
        target: &Path,
        offset: u64,
        pid: Option<i32>,
        hit_once: bool,
    ) -> Result<Self> {
        Self::start_programs(object, &[program], target, offset, pid, hit_once, None)
    }

    /// Configure the allowlist before any link exists; failure attaches nothing.
    /// An empty scope denies all events.
    ///
    /// # Errors
    /// Returns when filter configuration, program load or attachment fails.
    pub fn start_program_scoped(
        object: &Path,
        program: &str,
        target: &Path,
        offset: u64,
        tgids: &[u32],
        hit_once: bool,
    ) -> Result<Self> {
        Self::start_programs(
            object,
            &[program],
            target,
            offset,
            None,
            hit_once,
            Some(tgids),
        )
    }

    /// Attach entry + uretprobe from **one** BPF load so `entry_ptr` is shared.
    ///
    /// Required for `SSL_read` / JNI region return snapshots. Callers should
    /// classify hits with `RegisterContext::snapshot_at_return` (BPF sets
    /// `aux_pad=1` on every uretprobe event).
    ///
    /// # Errors
    ///
    /// Returns when either program cannot be loaded or attached.
    pub fn start_entry_return(
        object: &Path,
        target: &Path,
        offset: u64,
        pid: Option<i32>,
        hit_once: bool,
    ) -> Result<Self> {
        Self::start_programs(
            object,
            &["ksight_uprobe_regs", "ksight_uretprobe_regs"],
            target,
            offset,
            pid,
            hit_once,
            None,
        )
    }

    /// Load and configure a TLS ABI and TGID scope before attaching any link.
    /// mode: 1 byte return, 2 output pointer, 3 attempted bytes only.
    ///
    /// # Errors
    ///
    /// Returns when the object cannot be loaded, a requested program is missing,
    /// or the uprobe cannot be attached. A snapshot request is refused.
    pub fn start_configured(
        object: &Path,
        programs: &[&str],
        target: &Path,
        attach: UprobeAttach<'_>,
    ) -> Result<Self> {
        Self::start_programs_configured(object, programs, target, attach, None)
    }

    fn start_programs(
        object: &Path,
        programs: &[&str],
        target: &Path,
        offset: u64,
        pid: Option<i32>,
        hit_once: bool,
        tgids: Option<&[u32]>,
    ) -> Result<Self> {
        Self::start_programs_configured(
            object,
            programs,
            target,
            UprobeAttach {
                offset,
                pid,
                hit_once,
                tgids,
                snapshot: None,
            },
            None,
        )
    }

    /// Low-level candidate backend. Requires trusted exact metadata and local
    /// target BTF; does not bootstrap authorization or enable strict mirror.
    /// Verify actual target BTF, task-storage ABI and every uprobe program without attaching or granting a task.
    ///
    /// # Errors
    ///
    /// Returns when kernel BTF, the object, the task-storage map, the context
    /// ABI, or an uprobe program cannot be loaded. Nothing is attached.
    pub fn verify_instance_backend(object: &Path) -> Result<()> {
        let btf = Btf::from_sys_fs().context("qualified backend requires real kernel BTF")?;
        let bytes = std::fs::read(object)?;
        let mut bpf = EbpfLoader::new()
            .btf(Some(&btf))
            .allow_unsupported_maps()
            .load(&bytes)?;
        crate::task_storage::checked_map(
            bpf.map("scope_task_v1")
                .context("qualified task-storage map absent")?,
        )?;
        let Some(aya::maps::Map::PerCpuArray(map)) = bpf.map("hwbp_ctx") else {
            anyhow::bail!("qualified context map absent");
        };
        if map.info()?.value_size() != instance_context_value_size()? {
            anyhow::bail!("qualified context ABI mismatch");
        }
        let mut loaded = 0usize;
        for (_, program) in bpf.programs_mut() {
            if let aya::programs::Program::UProbe(p) = program {
                p.load()?;
                loaded += 1;
            }
        }
        if loaded == 0 {
            anyhow::bail!("qualified uprobe programs absent");
        }
        Ok(()) // Local handles drop; no attach, pins, target grants or payload reads.
    }
    /// Missing BTF, old objects, relocation, verifier or map errors attach nothing.
    ///
    /// # Errors
    ///
    /// Always returns. A raw identity list is not an owned pidfd binding.
    pub fn start_instance_scoped(
        object: &Path,
        programs: &[&str],
        target: &Path,
        offset: u64,
        identities: &[InstanceIdentity],
        hit_once: bool,
        snapshot: Option<[u64; 6]>,
    ) -> Result<Self> {
        let _ = (
            object, programs, target, offset, identities, hit_once, snapshot,
        );
        anyhow::bail!("raw identity alone is insufficient; exact owned pidfd binding required")
    }

    /// Candidate backend with mandatory pidfd/task-storage binding. Caller must
    /// supply sealed metadata leases retained from qualification against each
    /// owned group-leader pidfd and package policy. This does not enable strict mirror by itself.
    ///
    /// # Errors
    ///
    /// Returns when a lease is missing, the object is refused, or attach fails.
    /// A snapshot request is refused before any link is created.
    pub fn start_bound_instances(
        object: &Path,
        programs: &[&str],
        target: &Path,
        offset: u64,
        instances: &[BoundInstance],
        hit_once: bool,
        snapshot: Option<[u64; 6]>,
    ) -> Result<Self> {
        Self::start_programs_configured(
            object,
            programs,
            target,
            UprobeAttach {
                offset,
                pid: None,
                hit_once,
                tgids: None,
                snapshot,
            },
            Some(instances),
        )
    }

    fn start_programs_configured(
        object: &Path,
        programs: &[&str],
        target: &Path,
        attach: UprobeAttach<'_>,
        instances: Option<&[BoundInstance]>,
    ) -> Result<Self> {
        // Warm attaches can burst across TLS stacks; keep 4 MiB per CPU at 4 KiB/page.
        const PERF_RING_PAGES: usize = 1024;
        let UprobeAttach {
            offset,
            pid,
            hit_once,
            tgids,
            snapshot,
        } = attach;

        if let Some(targets) = instances {
            instance_scope::require_metadata_leases(targets)?;
        }
        let mut bpf = if instances.is_some() {
            // Aya's default .ok() BTF fallback is unsuitable for mandatory CO-RE.
            let btf = Btf::from_sys_fs()
                .context("instance gate requires target /sys/kernel/btf/vmlinux")?;
            let bytes = std::fs::read(object).context("read instance BPF object")?;
            EbpfLoader::new()
                .btf(Some(&btf))
                .allow_unsupported_maps() // Aya represents validated TASK_STORAGE as Unsupported.
                .load(&bytes)
                .context("load instance CO-RE object")?
        } else {
            Ebpf::load_file(object).context("加载 uprobe BPF 对象")?
        };
        if instances.is_some() {
            reject_wrong_instance_maps(&bpf)?;
        } else if bpf.map("scope_epoch_v1").is_some()
            || bpf.map("scope_allow_v1").is_some()
            || bpf.map("scope_task_v1").is_some()
        {
            anyhow::bail!("instance object requires exact instance API; numeric downgrade refused");
        }
        if snapshot.is_some() {
            anyhow::bail!("TLS snapshot configuration is outside the memory candidate");
        }

        let tgid_keys = if tgids.is_some() {
            tgid_filter::configure(&mut BpfFilterMaps(&mut bpf), &[], tgids)
                .context("拒绝挂载：TGID 过滤配置失败")?
        } else {
            Vec::new()
        };
        let instance_scope = instances
            .map(|identities| {
                instance_scope::configure(
                    &mut BpfInstanceMaps(&mut bpf),
                    &ScopeState::default(),
                    identities,
                )
            })
            .transpose()?;
        let mut links = Vec::with_capacity(programs.len());
        for program in programs {
            let link_id = {
                let probe: &mut UProbe = bpf
                    .program_mut(program)
                    .with_context(|| format!("{program} 程序缺失"))?
                    .try_into()
                    .context("不是 uprobe 程序")?;
                probe.load().context("加载 uprobe 程序")?;
                probe
                    .attach(None, offset, target, pid)
                    .context("挂载 uprobe")?
            };
            links.push(((*program).to_owned(), link_id));
        }

        let mut events = PerfEventArray::try_from(
            bpf.take_map("hwbp_events")
                .context("hwbp_events map 缺失")?,
        )
        .context("打开 hwbp_events perf array")?;
        // Alipay warm attach can burst SSL_read/write across BabaSSL+Cronet+Conscrypt;
        // 128 pages/CPU overflowed (perf_lost≈1.6k / 90s). Lean JNI slots + 1024 pages ≈ 4MiB/CPU @4KiB.
        let mut buffers = Vec::new();
        for cpu in crate::cpu_list::online_cpu_ids() {
            if let Ok(buffer) = events.open(cpu, Some(PERF_RING_PAGES)) {
                buffers.push(buffer);
            }
        }
        if buffers.is_empty() {
            anyhow::bail!("failed to open uprobe perf buffers");
        }

        let paired_entry_return =
            programs.contains(&"ksight_uprobe_regs") && programs.contains(&"ksight_uretprobe_regs");

        Ok(Self {
            bpf,
            links,
            buffers,
            read_slots: std::array::from_fn(|_| bytes::BytesMut::with_capacity(8192)),
            hit_once,
            finished: false,
            tgid_keys,
            instance_scope,
            paired_entry_return,
            drained_total: 0,
            decode_counters: crate::registers::DecodeCounters::default(),
            lost_total: 0,
        })
    }

    /// Restrict emission to these thread-group IDs.
    ///
    /// `None` records every mapping process. An empty slice still enables the
    /// filter and denies all events. Never use `None` for an unknown scope.
    ///
    /// # Errors
    ///
    /// Returns when the filter maps are missing or cannot be updated, detaching
    /// the session so a partial update cannot leave an active probe behind.
    pub fn apply_tgid_filter(&mut self, tgids: Option<&[u32]>) -> Result<()> {
        if self.finished {
            anyhow::bail!("cannot update a detached uprobe session");
        }
        if self.instance_scope.is_some() {
            self.detach();
            anyhow::bail!("numeric filter cannot downgrade instance session; detached");
        }
        match tgid_filter::configure(&mut BpfFilterMaps(&mut self.bpf), &self.tgid_keys, tgids) {
            Ok(keys) => {
                self.tgid_keys = keys;
                Ok(())
            }
            Err(error) => {
                self.detach();
                Err(error.context("TGID filter failed; session detached"))
            }
        }
    }

    /// Advance an exact scope transaction. Every error detaches and discards
    /// the object; retries need a fresh object, never a rolled-back generation.
    ///
    /// # Errors
    ///
    /// Always returns after detaching. Raw identities are not owned pidfds.
    pub fn apply_instance_scope(&mut self, identities: &[InstanceIdentity]) -> Result<()> {
        let _ = identities;
        self.detach();
        anyhow::bail!("raw-only scope update refused; detached; owned pidfds required")
    }

    /// Replace the bound instances on an already attached session.
    ///
    /// # Errors
    ///
    /// Returns when the session is detached, a lease is missing, or the
    /// transaction fails. A failed transaction detaches the session.
    pub fn apply_bound_instances(&mut self, instances: &[BoundInstance]) -> Result<()> {
        if self.finished {
            anyhow::bail!("cannot update detached instance session");
        }
        if let Err(error) = instance_scope::require_metadata_leases(instances) {
            self.detach();
            return Err(error);
        }
        let Some(previous) = self.instance_scope.as_ref() else {
            self.detach();
            anyhow::bail!("numeric object has no instance capability; detached");
        };
        match instance_scope::configure(&mut BpfInstanceMaps(&mut self.bpf), previous, instances) {
            Ok(next) => {
                self.instance_scope = Some(next);
                Ok(())
            }
            Err(error) => {
                self.detach();
                Err(error.context("instance transaction failed; detached"))
            }
        }
    }

    /// 非阻塞排空当前可读命中。
    ///
    /// # Errors
    ///
    /// 保留底层采集接口的错误通道；当前无法读取的 perf buffer 会结束该次排空。
    pub fn poll_hits(&mut self) -> Result<Vec<RegisterContext>> {
        let report = self.poll_hits_report();
        if let Some(error) = report.error {
            anyhow::bail!("{error}");
        }
        Ok(report.records)
    }

    /// Preserve earlier records, individual loss-notification times and a later
    /// read error. Inspect must revoke transport proof before routing records.
    pub fn poll_hits_report(&mut self) -> PerfDrainReport<RegisterContext, String> {
        let started = std::time::Instant::now();
        let mut result = PerfDrainReport::default();
        if self.finished {
            return result;
        }
        if let Err(error) = self.check_instance_handles() {
            self.detach();
            result.error = Some(format!("instance handle invalidated: {error:#}"));
            return result;
        }
        let instance_scope = self.instance_scope.as_ref();
        let counters = &mut self.decode_counters;
        for buffer in &mut self.buffers {
            let slots = &mut self.read_slots;
            let report = drain_reads(
                || {
                    let read = match buffer.read_events(slots) {
                        Ok(read) => read,
                        Err(error) => {
                            return Err((
                                format!("perf_buffer_read_error: {error}"),
                                monotonic_ns(),
                            ))
                        }
                    };
                    // Capture the notification instant BEFORE record decoding.
                    let observed = monotonic_ns();
                    let records = slots
                        .iter()
                        .take(read.read)
                        .filter_map(|slot| {
                            let hit = counters.admit_perf_sample(
                                slot,
                                instance_scope.map(|s| (s.epoch, s.identities.as_slice())),
                            )?;
                            if let Some(scope) = instance_scope {
                                scope.accepts(hit.instance.as_ref()?).then_some(hit)
                            } else {
                                Some(hit)
                            }
                        })
                        .collect();
                    Ok(PerfRead {
                        samples: read.read as u64,
                        records,
                        lost_samples: read.lost as u64,
                        notification_monotonic_ns: observed,
                    })
                },
                |hit: &RegisterContext| hit.time_ns,
            );
            self.drained_total = self.drained_total.saturating_add(report.raw_samples);
            self.lost_total = self.lost_total.saturating_add(report.lost_samples);
            result.raw_samples = result.raw_samples.saturating_add(report.raw_samples);
            result.lost_samples = result.lost_samples.saturating_add(report.lost_samples);
            result.read_calls = result.read_calls.saturating_add(report.read_calls);
            result.lost_only_reads = result
                .lost_only_reads
                .saturating_add(report.lost_only_reads);
            result.records.extend(report.records);
            result.notifications.extend(report.notifications);
            if report.error.is_some() {
                result.error = report.error;
                result.error_notification_monotonic_ns = report.error_notification_monotonic_ns;
                break;
            }
            if self.hit_once && !result.records.is_empty() {
                break;
            }
        }
        if let Err(error) = self.check_instance_handles() {
            result.records.clear();
            result.error = Some(format!(
                "instance handle invalidated after drain: {error:#}"
            ));
            self.detach();
        }
        if self.hit_once && !result.records.is_empty() {
            self.detach();
        }
        result.elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        result
    }

    fn check_instance_handles(&self) -> Result<()> {
        if let Some(scope) = &self.instance_scope {
            for target in &scope.bindings {
                if !crate::task_storage::alive(target.pidfd.as_fd())? {
                    anyhow::bail!("authorized task exited; discard drained generation");
                }
            }
        }
        Ok(())
    }

    /// Current committed generation; returned records must not outlive it.
    pub fn instance_epoch(&self) -> Option<u32> {
        self.instance_scope.as_ref().map(|s| s.epoch)
    }
    /// 非阻塞轮询一次命中。
    ///
    /// # Errors
    ///
    /// 当命中批次无法读取时返回错误。
    pub fn poll_hit(&mut self) -> Result<Option<RegisterContext>> {
        Ok(self.poll_hits()?.into_iter().next())
    }

    /// 是否已结束（命中即撤完成或已 detach）。
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// 解除 uprobe。
    fn detach(&mut self) {
        self.finished = true;
        if self.instance_scope.is_some() {
            let _ = BpfFilterMaps(&mut self.bpf).gate(2);
        }
        self.instance_scope = None;
        let links = std::mem::take(&mut self.links);
        for (program, link_id) in links {
            let Some(prog) = self.bpf.program_mut(&program) else {
                continue;
            };
            let Ok(probe): Result<&mut UProbe, _> = prog.try_into() else {
                continue;
            };
            let _ = probe.detach(link_id);
        }
    }
}

impl Drop for UprobeSession {
    fn drop(&mut self) {
        self.detach();
    }
}

fn monotonic_ns() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time) } != 0 {
        return None;
    }
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_nsec).ok()?)
}
