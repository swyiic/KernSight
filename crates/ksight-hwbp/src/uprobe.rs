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
    maps::{perf::PerfEventArray, MapData},
    programs::{uprobe::UProbeLinkId, UProbe},
    Ebpf,
};

use super::registers::RegisterContext;

/// 一次 uprobe 采集会话。
pub struct UprobeSession {
    bpf: Ebpf,
    link_id: Option<UProbeLinkId>,
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<MapData>>,
    hit_once: bool,
    finished: bool,
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
        let mut bpf = Ebpf::load_file(object).context("加载 uprobe BPF 对象")?;

        let link_id = {
            let probe: &mut UProbe = bpf
                .program_mut("ksight_uprobe_regs")
                .context("ksight_uprobe_regs 程序缺失")?
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
        for cpu in 0..online_cpus() {
            if let Ok(buffer) = events.open(cpu, Some(64)) {
                buffers.push(buffer);
            }
        }
        if buffers.is_empty() {
            anyhow::bail!("failed to open uprobe perf buffers");
        }

        Ok(Self {
            bpf,
            link_id: Some(link_id),
            buffers,
            hit_once,
            finished: false,
        })
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
        let Some(program) = self.bpf.program_mut("ksight_uprobe_regs") else {
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

fn online_cpus() -> u32 {
    std::thread::available_parallelism()
        .map_or(8, |value| u32::try_from(value.get()).unwrap_or(8))
        .max(1)
}

fn drain(buffer: &mut aya::maps::perf::PerfEventArrayBuffer<MapData>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut slots = [
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
            bytes::BytesMut::with_capacity(512),
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
