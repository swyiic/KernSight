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

/// Bounded mutually exclusive reasons at the raw perf-record admission boundary.
/// No rejected register payload is retained and no admission rule is relaxed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DecodeCounters {
    pub perf_min_size: u64,
    pub perf_max_size: u64,
    pub perf_padding_removed: u64,
    pub bad_size: u64,
    pub bad_abi: u64,
    pub malformed: u64,
    pub scope_epoch: u64,
    pub scope_identity: u64,
    pub accepted: u64,
}
impl DecodeCounters {
    /// Aya returns `PERF_SAMPLE_RAW`'s aligned size, including transport padding.
    /// Only this perf ingress removes the exact four-byte framing tail. The
    /// identity decoder still requires an exact 4448-byte payload.
    pub fn admit_perf_sample(
        &mut self,
        bytes: &[u8],
        scope: Option<(u32, &[InstanceIdentity])>,
    ) -> Option<RegisterContext> {
        let size = bytes.len() as u64;
        if self.perf_min_size == 0 || size < self.perf_min_size {
            self.perf_min_size = size;
        }
        self.perf_max_size = self.perf_max_size.max(size);
        if scope.is_some() {
            // perf_prepare_sample: round_up(payload_size + sizeof(u32), 8) - sizeof(u32).
            // Padding is transport storage, not ABI data and need not be zero.
            const FRAMED_SIZE: usize = (INSTANCE_CONTEXT_SIZE + 4).next_multiple_of(8) - 4;
            if bytes.len() != FRAMED_SIZE {
                self.bad_size = self.bad_size.saturating_add(1);
                return None;
            }
            self.perf_padding_removed = self.perf_padding_removed.saturating_add(1);
            self.admit(&bytes[..INSTANCE_CONTEXT_SIZE], scope)
        } else {
            self.admit(bytes, scope)
        }
    }

    pub fn admit(
        &mut self,
        bytes: &[u8],
        scope: Option<(u32, &[InstanceIdentity])>,
    ) -> Option<RegisterContext> {
        let reason;
        if let Some((epoch, identities)) = scope {
            if bytes.len() != INSTANCE_CONTEXT_SIZE {
                reason = &mut self.bad_size;
            } else if read_u32(bytes, 4420) != INSTANCE_ABI_V1 {
                reason = &mut self.bad_abi;
            } else if let Some(hit) = RegisterContext::decode_instance(bytes) {
                let stamp = hit.instance?;
                if epoch == 0 || stamp.epoch != epoch {
                    reason = &mut self.scope_epoch;
                } else if !identities.contains(&stamp.identity) {
                    reason = &mut self.scope_identity;
                } else {
                    self.accepted = self.accepted.saturating_add(1);
                    return Some(hit);
                }
            } else {
                reason = &mut self.malformed;
            }
        } else if let Some(hit) = RegisterContext::decode(bytes) {
            self.accepted = self.accepted.saturating_add(1);
            return Some(hit);
        } else {
            reason = &mut self.malformed;
        }
        *reason = reason.saturating_add(1);
        None
    }
}
#[cfg(test)]
mod admission_tests {
    use super::*;
    fn record() -> Vec<u8> {
        let mut b = vec![0; INSTANCE_CONTEXT_SIZE];
        for (offset, value) in [
            (0, 7u32),
            (4408, 7),
            (4412, 10285),
            (4416, 3),
            (4420, INSTANCE_ABI_V1),
        ] {
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(4424, 9u64), (4432, 4), (4440, 10)] {
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        b
    }
    #[test]
    fn perf_alignment_is_removed_only_at_transport_ingress() {
        let ids = [InstanceIdentity {
            tgid: 7,
            uid: 10285,
            birth_ns: 9,
            exec_id: 4,
        }];
        let b = record();
        let mut c = DecodeCounters::default();
        let mut framed = b.clone();
        framed.extend_from_slice(&[0xa5; 4]);
        assert!(RegisterContext::decode_instance(&framed).is_none());
        assert!(c.admit_perf_sample(&framed, Some((3, &ids))).is_some());
        for size in [4408, 4448, 4449, 4451, 4453, 4460] {
            let mut bad = framed.clone();
            bad.resize(size, 0);
            assert!(c.admit_perf_sample(&bad, Some((3, &ids))).is_none());
        }
        let mut bad = framed.clone();
        bad[4420..4424].fill(0);
        assert!(c.admit_perf_sample(&bad, Some((3, &ids))).is_none());
        assert!(c.admit_perf_sample(&framed, Some((4, &ids))).is_none());
        assert!(c.admit_perf_sample(&framed, Some((3, &[]))).is_none());
        assert_eq!(
            (
                c.accepted,
                c.bad_size,
                c.bad_abi,
                c.scope_epoch,
                c.scope_identity
            ),
            (1, 6, 1, 1, 1)
        );
        assert_eq!(c.perf_padding_removed, 4);
    }
    #[test]
    fn strict_record_funnel_classifies_without_granting_invalid_payloads() {
        let identity = InstanceIdentity {
            tgid: 7,
            uid: 10285,
            birth_ns: 9,
            exec_id: 4,
        };
        let ids = [identity];
        let mut c = DecodeCounters::default();
        let b = record();
        assert!(c.admit(&b, Some((3, &ids))).is_some());
        for size in [4408, 4447, 4449] {
            let mut bad = b.clone();
            bad.resize(size, 0);
            assert!(c.admit(&bad, Some((3, &ids))).is_none());
        }
        let mut bad = b.clone();
        bad[4420..4424].fill(0);
        assert!(c.admit(&bad, Some((3, &ids))).is_none());
        for offset in [0, 4408, 4424, 4440] {
            let mut bad = b.clone();
            bad[offset..offset + 4].fill(0);
            assert!(c.admit(&bad, Some((3, &ids))).is_none());
        }
        let mut bad = b.clone();
        bad[288..292].copy_from_slice(&4097u32.to_le_bytes());
        assert!(c.admit(&bad, Some((3, &ids))).is_none());
        assert!(c.admit(&b, Some((4, &ids))).is_none());
        for identity in [
            InstanceIdentity { uid: 1, ..identity },
            InstanceIdentity {
                birth_ns: 11,
                ..identity
            },
            InstanceIdentity {
                exec_id: 5,
                ..identity
            },
            InstanceIdentity {
                tgid: 8,
                ..identity
            },
        ] {
            assert!(c.admit(&b, Some((3, &[identity]))).is_none());
        }
        assert_eq!(
            (
                c.accepted,
                c.bad_size,
                c.bad_abi,
                c.malformed,
                c.scope_epoch,
                c.scope_identity
            ),
            (1, 3, 1, 5, 1, 4)
        );
    }
}
