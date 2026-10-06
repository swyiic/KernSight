//! uprobe 命中时的用户态寄存器上下文。

/// ABI 尺寸：与 `bpf/include/ksight_hwbp.h` 的 `ksight_hwbp_context` 对齐。
pub const HWBP_CONTEXT_SIZE: usize = 4408;
const AUX_LEN: usize = 4096;
pub const INSTANCE_CONTEXT_SIZE: usize = 4448;
use crate::instance_scope::{InstanceIdentity, InstanceStamp, INSTANCE_ABI_V1};

/// ARM64 用户态寄存器现场（x0-x30、SP、PC、PSTATE）。
#[derive(Debug, Clone, Copy)]
pub struct RegisterContext {
    /// 命中的线程组 ID。
    pub pid: u32,
    /// 命中的线程 ID。
    pub tid: u32,
    /// 通用寄存器 x0-x30。
    pub regs: [u64; 31],
    /// 栈指针。
    pub sp: u64,
    /// 程序计数器（命中地址）。
    pub pc: u64,
    /// 处理器状态寄存器。
    pub pstate: u64,
    /// Kernel monotonic ns at the probe, for cross-probe ordering.
    pub time_ns: u64,
    /// Bytes valid in `aux`, from x2 units capped at 192 UTF-16 units.
    pub aux_bytes: u32,
    /// True when aux was snapshotted at probe return (`SSL_read` output buffer).
    pub snapshot_at_return: bool,
    /// True only after a successful kernel copy; zero bytes remain valid data.
    pub snapshot_valid: bool,
    /// ABI-resolved length captured at return, including a valid empty result.
    pub actual_len: Option<u64>,
    /// Kernel entry timestamp pairing this record with its invocation.
    pub call_id: u64,
    /// Exact kernel identity and map generation, present only on the separate instance ABI.
    pub instance: Option<InstanceStamp>,
    /// x1 user-buffer snapshot at hit time. Empty when x1 is not a pointer.
    pub aux: [u8; AUX_LEN],
}

impl Default for RegisterContext {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            time_ns: 0,
            aux_bytes: 0,
            snapshot_at_return: false,
            snapshot_valid: false,
            actual_len: None,
            call_id: 0,
            instance: None,
            aux: [0; AUX_LEN],
        }
    }
}

impl RegisterContext {
    /// 从事件字节流解码寄存器现场。
    ///
    /// Layout: `pid`/`tid`, `regs[31]`, `sp`/`pc`/`pstate`, `time_ns`, `aux_bytes`, pad, `aux[4096]`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HWBP_CONTEXT_SIZE {
            return None;
        }
        let mut ctx = RegisterContext {
            pid: read_u32(bytes, 0),
            tid: read_u32(bytes, 4),
            ..RegisterContext::default()
        };
        for (index, slot) in ctx.regs.iter_mut().enumerate() {
            *slot = read_u64(bytes, 8 + index * 8);
        }
        ctx.sp = read_u64(bytes, 8 + 31 * 8);
        ctx.pc = read_u64(bytes, 8 + 32 * 8);
        ctx.pstate = read_u64(bytes, 8 + 33 * 8);
        ctx.time_ns = read_u64(bytes, 8 + 34 * 8);
        ctx.aux_bytes = read_u32(bytes, 8 + 35 * 8);
        let flags = read_u32(bytes, 8 + 35 * 8 + 4);
        ctx.snapshot_at_return = flags & 1 != 0;
        ctx.snapshot_valid = flags & 2 != 0;
        ctx.actual_len = (flags & 4 != 0).then(|| read_u64(bytes, 4392));
        ctx.call_id = read_u64(bytes, 4400);
        if ctx.aux_bytes > 4096_u32 {
            return None;
        }
        let aux_off = 8 + 35 * 8 + 8;
        ctx.aux
            .copy_from_slice(bytes.get(aux_off..aux_off + AUX_LEN)?);
        Some(ctx)
    }

    /// Strict instance records require their complete ABI; legacy prefixes,
    /// malformed identities and trailing bytes cannot acquire instance proof.
    pub fn decode_instance(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != INSTANCE_CONTEXT_SIZE || read_u32(bytes, 4420) != INSTANCE_ABI_V1 {
            return None;
        }
        let identity = InstanceIdentity {
            tgid: read_u32(bytes, 4408),
            uid: read_u32(bytes, 4412),
            birth_ns: read_u64(bytes, 4424),
            exec_id: read_u64(bytes, 4432),
        };
        let epoch = read_u32(bytes, 4416);
        let thread_birth_ns = read_u64(bytes, 4440);
        if identity.tgid == 0
            || identity.birth_ns == 0
            || epoch == 0
            || thread_birth_ns == 0
            || identity.tgid != read_u32(bytes, 0)
        {
            return None;
        }
        let mut ctx = Self::decode(bytes)?;
        ctx.instance = Some(InstanceStamp {
            identity,
            epoch,
            thread_birth_ns,
        });
        Some(ctx)
    }

    /// 命中的线程组 ID（pid）。
    pub fn pid(bytes: &[u8]) -> u32 {
        read_u32(bytes, 0)
    }

    /// 命中的线程 ID（tid）。
    pub fn tid(bytes: &[u8]) -> u32 {
        read_u32(bytes, 4)
    }

    /// 返回地址（x30，即 LR），用于定位调用者。
    pub fn link_register(&self) -> u64 {
        self.regs[30]
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed offset"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed offset"))
}
