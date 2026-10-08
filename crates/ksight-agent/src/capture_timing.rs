//! Bounded payload-free phase clock; diagnostic only, never renews a lease.
use serde::Serialize;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Fixed phase vocabulary, independent of target data.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Backend, baseline and sensor preparation.
    Prepare,
    /// Observation loop and its work between probes.
    Observe,
    /// ELF candidate preparation.
    InspectPrepare,
    /// Synchronous perf poll.
    Poll,
    /// Probe detachment including kernel close work.
    Detach,
    /// Batch compression and durable flush.
    Flush,
    /// Durable manifest publication.
    Manifest,
    /// Final spool seal.
    Seal,
    /// Capture returned including its owned destructors.
    Returned,
}

/// One monotonic-domain diagnostic snapshot, containing no payload or paths.
#[derive(Clone, Serialize)]
pub struct Snapshot {
    schema: &'static str,
    active_phase: Phase,
    entered_ms: u64,
    elapsed_ms: u64,
    exclusive_ms: [u64; 9],
}
impl Snapshot {
    fn new() -> Self {
        Self {
            schema: "kernsight.capture-clock/v1",
            active_phase: Phase::Prepare,
            entered_ms: 0,
            elapsed_ms: 0,
            exclusive_ms: [0; 9],
        }
    }
    fn transition(&mut self, phase: Phase, now: u64) -> Phase {
        let previous = self.active_phase;
        self.exclusive_ms[previous as usize] = self.exclusive_ms[previous as usize]
            .saturating_add(now.saturating_sub(self.entered_ms));
        self.active_phase = phase;
        self.entered_ms = now;
        self.elapsed_ms = now;
        previous
    }
}
fn clock() -> &'static (Instant, Mutex<Snapshot>) {
    static CLOCK: OnceLock<(Instant, Mutex<Snapshot>)> = OnceLock::new();
    CLOCK.get_or_init(|| (Instant::now(), Mutex::new(Snapshot::new())))
}
fn elapsed() -> u64 {
    u64::try_from(clock().0.elapsed().as_millis()).unwrap_or(u64::MAX)
}
/// Change the current diagnostic phase; does not alter deadline state.
pub fn set(phase: Phase) -> Phase {
    clock()
        .1
        .lock()
        .map_or(Phase::Prepare, |mut s| s.transition(phase, elapsed()))
}
/// Snapshot both completed costs and the still-running phase.
pub fn snapshot() -> Snapshot {
    let mut s = clock()
        .1
        .lock()
        .map_or_else(|_| Snapshot::new(), |s| s.clone());
    s.elapsed_ms = elapsed();
    s
}
/// Restore the enclosing phase after synchronous work returns.
pub struct Span(Phase);
/// Mark synchronous work while it is still executing, including a stalled call.
pub fn enter(phase: Phase) -> Span {
    Span(set(phase))
}
impl Drop for Span {
    fn drop(&mut self) {
        set(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slow_flush_and_exit_remain_distinguishable_without_renewing_clock() {
        let mut s = Snapshot::new();
        s.transition(Phase::Observe, 4_000);
        s.transition(Phase::Seal, 94_000);
        s.transition(Phase::Flush, 95_000);
        // Deadline at 105s snapshots active work, not a fabricated successful seal.
        assert_eq!(s.active_phase, Phase::Flush);
        assert_eq!(s.entered_ms, 95_000);
        s.transition(Phase::Detach, 108_000);
        s.transition(Phase::Returned, 116_184);
        assert_eq!(s.exclusive_ms[Phase::Flush as usize], 13_000);
        assert_eq!(s.exclusive_ms[Phase::Detach as usize], 8_184);
        assert_eq!(s.elapsed_ms, 116_184);
        assert_eq!(s.exclusive_ms.iter().sum::<u64>(), 116_184);
    }
}
