//! uprobe 命中时的用户态寄存器上下文。

/// ABI 尺寸：与 `bpf/include/ksight_hwbp.h` 的 `ksight_hwbp_context` 对齐。
pub const HWBP_CONTEXT_SIZE: usize = 680;
const AUX_LEN: usize = 384;

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
            aux: [0; AUX_LEN],
        }
    }
}

impl RegisterContext {
    /// 从事件字节流解码寄存器现场。
    ///
    /// Layout: `pid`/`tid`, `regs[31]`, `sp`/`pc`/`pstate`, `time_ns`, `aux_bytes`, pad, `aux[384]`.
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
        let aux_off = 8 + 35 * 8 + 8;
        ctx.aux
            .copy_from_slice(bytes.get(aux_off..aux_off + AUX_LEN)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_round_trips_register_layout() {
        let mut bytes = vec![0u8; HWBP_CONTEXT_SIZE];
        bytes[0..4].copy_from_slice(&42u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&43u32.to_le_bytes());
        let x2_offset = 8 + 2 * 8;
        bytes[x2_offset..x2_offset + 8].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        let pc_offset = 8 + 32 * 8;
        bytes[pc_offset..pc_offset + 8].copy_from_slice(&0x1234_5678_9abcu64.to_le_bytes());

        let ctx = RegisterContext::decode(&bytes).expect("decode");
        assert_eq!(ctx.pid, 42);
        assert_eq!(ctx.tid, 43);
        assert_eq!(ctx.regs[2], 0xdead_beef);
        assert_eq!(ctx.pc, 0x1234_5678_9abc);
        assert_eq!(RegisterContext::pid(&bytes), 42);
        assert_eq!(RegisterContext::tid(&bytes), 43);
        assert_eq!(HWBP_CONTEXT_SIZE, 680);
    }

    #[test]
    fn short_buffer_is_rejected() {
        assert!(RegisterContext::decode(&[0u8; 16]).is_none());
    }
}
