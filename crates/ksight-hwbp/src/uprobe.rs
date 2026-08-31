//! uprobe 寄存器采集：挂载 uprobe 到目标 ELF 的指定文件偏移处，
//! 命中时读取用户态 `pt_regs` 现场。
//!
//! 痕迹最小化要点：
//! - 可选 `pid` 过滤；明文全机模式才允许 `pid = None`
//! - `bpf_link`：Aya 走 `perf_event` + `bpf_link`，不经过 `tracefs` 枚举
//! - 命中即撤仍可用于 linker 单次探针；流量采集必须保持挂载并排空 perf buffer
//! - 不 pin：进程退出即卸载，无 bpffs 残留

use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    maps::{perf::PerfEventArray, Array, HashMap, MapData},
    programs::{uprobe::UProbeLinkId, UProbe},
    Ebpf,
};

use super::registers::RegisterContext;

/// 一次 uprobe 采集会话。
pub struct UprobeSession {
    bpf: Ebpf,
    program: String,
    link_id: Option<UProbeLinkId>,
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<MapData>>,
    hit_once: bool,
    finished: bool,
    tgid_keys: Vec<u32>,
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
        let mut bpf = Ebpf::load_file(object).context("加载 uprobe BPF 对象")?;

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

        let mut events = PerfEventArray::try_from(
            bpf.take_map("hwbp_events")
                .context("hwbp_events map 缺失")?,
        )
        .context("打开 hwbp_events perf array")?;
        let mut buffers = Vec::new();
        for cpu in crate::cpu_list::online_cpu_ids() {
            if let Ok(buffer) = events.open(cpu, Some(128)) {
                buffers.push(buffer);
            }
        }
        if buffers.is_empty() {
            anyhow::bail!("failed to open uprobe perf buffers");
        }

        Ok(Self {
            bpf,
            program: program.to_owned(),
            link_id: Some(link_id),
            buffers,
            hit_once,
            finished: false,
            tgid_keys: Vec::new(),
        })
    }

    /// Restrict emission to these thread-group IDs.
    ///
    /// `None` records every mapping process. An empty slice still enables the
    /// filter, so callers should pass `None` until at least one TGID is known.
    ///
    /// # Errors
    ///
    /// Returns when the filter maps are missing or cannot be updated.
    pub fn apply_tgid_filter(&mut self, tgids: Option<&[u32]>) -> Result<()> {
        if let Some(tgids) = tgids {
            let map = self
                .bpf
                .map_mut("tgid_allow")
                .context("tgid_allow map 缺失")?;
            let mut allow: HashMap<&mut MapData, u32, u32> =
                HashMap::try_from(map).context("打开 tgid_allow")?;
            for old in self.tgid_keys.drain(..) {
                let _ = allow.remove(&old);
            }
            for tgid in tgids.iter().copied().filter(|tgid| *tgid > 0).take(128) {
                allow.insert(tgid, 1, 0).context("写入 tgid_allow")?;
                self.tgid_keys.push(tgid);
            }
        }
        let enabled = u32::from(tgids.is_some_and(|tgids| !tgids.is_empty()));
        let map = self
            .bpf
            .map_mut("tgid_filter")
            .context("tgid_filter map 缺失")?;
        let mut filter: Array<&mut MapData, u32> =
            Array::try_from(map).context("打开 tgid_filter")?;
        filter.set(0, enabled, 0).context("写入 tgid_filter")?;
        Ok(())
    }

    /// 非阻塞排空当前可读命中。
    ///
    /// # Errors
    ///
    /// 保留底层采集接口的错误通道；当前无法读取的 perf buffer 会结束该次排空。
    pub fn poll_hits(&mut self) -> Result<Vec<RegisterContext>> {
        if self.finished {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();
        for buffer in &mut self.buffers {
            for raw in drain(buffer) {
                if let Some(hit) = RegisterContext::decode(&raw) {
                    hits.push(hit);
                }
                if self.hit_once {
                    self.detach();
                    return Ok(hits);
                }
            }
        }
        Ok(hits)
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
        let Some(link_id) = self.link_id.take() else {
            return;
        };
        let Some(program) = self.bpf.program_mut(&self.program) else {
            return;
        };
        let Ok(probe): Result<&mut UProbe, _> = program.try_into() else {
            return;
        };
        let _ = probe.detach(link_id);
    }
}

impl Drop for UprobeSession {
    fn drop(&mut self) {
        self.detach();
    }
}

fn drain(buffer: &mut aya::maps::perf::PerfEventArrayBuffer<MapData>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut slots = [
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
            bytes::BytesMut::with_capacity(1024),
        ];
        let Ok(read) = buffer.read_events(&mut slots) else {
            break;
        };
        if read.read == 0 {
            break;
        }
        for slot in slots.into_iter().take(read.read) {
            if !slot.is_empty() {
                out.push(slot.to_vec());
            }
        }
        if read.lost > 0 {
            break;
        }
    }
    out
}
