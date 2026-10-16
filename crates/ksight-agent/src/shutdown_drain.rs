//! Ordered, bounded capture shutdown shared by live capture and offline fixtures.
mod frozen;
pub use frozen::{FrozenQueues, ReadFailure, ReadProgress, ReadStep, SourceDrain};

/// Carve a shutdown reserve from an existing deadline without extending it.
pub fn before_reserve(
    deadline: std::time::Instant,
    reserve: std::time::Duration,
    now: std::time::Instant,
) -> std::time::Instant {
    deadline
        .checked_sub(reserve)
        .unwrap_or(now)
        .max(now)
        .min(deadline)
}

/// Keep short inspect windows within their existing phase lease; long inspect
/// captures need the larger drain reserve. An unbounded capture is long-lived.
pub fn reserve(inspect: bool, duration_seconds: u64) -> std::time::Duration {
    std::time::Duration::from_secs(
        if inspect && (duration_seconds == 0 || duration_seconds > 30) {
            15
        } else {
            5
        },
    )
}

/// Spend the capture's original shutdown allowance, keeping five seconds for
/// publication. An unleased capture preserves the existing five-second drain
/// fallback; an expired lease never receives another read window.
pub fn capture_drain_deadline(
    invocation_end: Option<std::time::Instant>,
    now: std::time::Instant,
) -> std::time::Instant {
    invocation_end.map_or_else(
        || now + std::time::Duration::from_secs(5),
        |end| before_reserve(end, std::time::Duration::from_secs(5), now),
    )
}

/// Evidence of producer closure and the final queue observation.
#[derive(Debug, PartialEq, Eq)]
pub struct DrainEnd {
    /// Every owned producer confirmed stopped before any final queue read.
    pub producers_stopped: bool,
    /// Empty was actually observed after stopping; exhaustion is not empty.
    pub empty: bool,
    /// Number of bounded rounds performed.
    pub rounds: u64,
    /// Wall time spent stopping producers before the first permitted read.
    pub stop_elapsed_ms: u64,
    /// Wall time spent in final reads, including an empty observation.
    pub drain_elapsed_ms: u64,
}
impl DrainEnd {
    /// Queue completion only; callers retain kernel loss and scope failures separately.
    pub fn complete(&self) -> bool {
        self.producers_stopped && self.empty
    }
}
/// Stop all producers, drain already queued records under the original allowance.
/// The read callback returns true only when all queues were observed empty.
/// # Errors
/// Returns a reader/output failure; earlier accepted records remain owned by the caller.
pub fn stop_and_drain<C, E>(
    context: &mut C,
    stop: impl FnOnce(&mut C) -> bool,
    mut read_round: impl FnMut(&mut C) -> Result<bool, E>,
    allowed: impl Fn() -> bool,
) -> Result<DrainEnd, E> {
    let stopping_started = std::time::Instant::now();
    let producers_stopped = stop(context);
    let draining_started = std::time::Instant::now();
    let mut end = DrainEnd {
        producers_stopped,
        empty: false,
        rounds: 0,
        stop_elapsed_ms: u64::try_from(
            draining_started
                .duration_since(stopping_started)
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
        drain_elapsed_ms: 0,
    };
    while allowed() {
        end.rounds += 1;
        if read_round(context)? {
            end.empty = true;
            break;
        }
    }
    end.drain_elapsed_ms =
        u64::try_from(draining_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(end)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[test]
    fn shutdown_reserve_never_renews_or_spends_an_expired_lease() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        assert_eq!(
            before_reserve(now + Duration::from_secs(105), Duration::from_secs(15), now),
            now + Duration::from_secs(90)
        );
        assert_eq!(
            before_reserve(now + Duration::from_secs(2), Duration::from_secs(15), now),
            now
        );
        let expired = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            before_reserve(expired, Duration::from_secs(15), now),
            expired
        );
    }
    #[test]
    fn linker_window_fits_original_lease_and_expired_lease_stays_expired() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        // The real Linker phase allowed 25s; 734ms was spent before observation.
        let lease = now + Duration::from_millis(24266);
        let observation_end = before_reserve(lease, reserve(true, 15), now);
        assert!(observation_end >= now + Duration::from_secs(15));
        assert!(observation_end < lease);
        assert_eq!(reserve(true, 90), Duration::from_secs(15));
        let expired = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(before_reserve(expired, reserve(true, 15), now), expired);
    }
    struct Queue {
        live: bool,
        queued: VecDeque<u32>,
        retained: Vec<u32>,
        loss: u64,
    }
    #[test]
    fn stop_preserves_inflight_record_then_drains_before_seal() {
        let mut q = Queue {
            live: true,
            queued: VecDeque::from([1, 2]),
            retained: vec![],
            loss: 3,
        };
        let end = stop_and_drain(
            &mut q,
            |q| {
                q.queued.push_back(3);
                q.live = false;
                true
            },
            |q| {
                assert!(!q.live);
                if let Some(v) = q.queued.pop_front() {
                    q.retained.push(v);
                    Ok::<_, ()>(false)
                } else {
                    Ok(true)
                }
            },
            || true,
        )
        .unwrap();
        assert!(end.complete());
        assert_eq!(q.retained, [1, 2, 3]);
        assert_eq!(q.loss, 3); // Drained never means lossless.
    }
    #[test]
    fn original_l1_allowance_survives_slow_stop_before_draining() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};
        let started = Instant::now();
        let lease_end = started + Duration::from_secs(105);
        let stopping_started = started + Duration::from_secs(90);
        let now = Cell::new(stopping_started);
        let drain_end = capture_drain_deadline(Some(lease_end), stopping_started);
        assert_eq!(drain_end, started + Duration::from_secs(100));
        let mut q = Queue {
            live: true,
            queued: VecDeque::from([1, 2]),
            retained: vec![],
            loss: 213_066,
        };
        let end = stop_and_drain(
            &mut q,
            |q| {
                // Serial producer closure takes six seconds on this fixture.
                now.set(stopping_started + Duration::from_secs(6));
                q.queued.push_back(3);
                q.live = false;
                true
            },
            |q| {
                assert!(!q.live);
                let empty = if let Some(record) = q.queued.pop_front() {
                    q.retained.push(record);
                    false
                } else {
                    true
                };
                now.set(now.get() + Duration::from_millis(500));
                Ok::<_, ()>(empty)
            },
            || now.get() < drain_end,
        )
        .unwrap();
        assert!(end.complete());
        assert_eq!(end.rounds, 4);
        assert_eq!(q.retained, [1, 2, 3]);
        assert_eq!(q.loss, 213_066); // Queue emptiness cannot restore kernel loss.
        assert!(now.get() < lease_end);
        // The former second cut ended at 95s, before producer closure at 96s.
        let old_end = (stopping_started + Duration::from_secs(10))
            .min(lease_end)
            .checked_sub(Duration::from_secs(5))
            .unwrap();
        assert!(stopping_started + Duration::from_secs(6) >= old_end);
    }
    #[test]
    fn late_stop_never_forces_a_read_past_the_original_drain_deadline() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};
        let started = Instant::now();
        let stopping_started = started + Duration::from_secs(99);
        let lease_end = started + Duration::from_secs(105);
        let now = Cell::new(stopping_started);
        let drain_end = capture_drain_deadline(Some(lease_end), stopping_started);
        let mut q = Queue {
            live: true,
            queued: VecDeque::from([1]),
            retained: vec![],
            loss: 7,
        };
        let end = stop_and_drain(
            &mut q,
            |q| {
                q.live = false;
                now.set(stopping_started + Duration::from_secs(2));
                true
            },
            |_| panic!("no payload read after the original allowance expires"),
            || now.get() < drain_end,
        );
        let end: DrainEnd = end.unwrap_or_else(|error: ()| panic!("{error:?}"));
        assert!(end.producers_stopped);
        assert!(!end.complete());
        assert_eq!(end.rounds, 0);
        assert_eq!(q.retained, [] as [u32; 0]);
        assert_eq!(q.queued, [1]);
        assert_eq!(q.loss, 7);
    }
    #[test]
    fn drain_deadline_keeps_short_and_expired_leases_and_legacy_fallback() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let expired = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(capture_drain_deadline(Some(expired), now), expired);
        assert_eq!(
            capture_drain_deadline(Some(now + Duration::from_secs(2)), now),
            now
        );
        assert_eq!(
            capture_drain_deadline(None, now),
            now + Duration::from_secs(5)
        );
        // The UI's 15/90/15 are observations, not an extra drain allocation.
        assert_eq!(reserve(false, 15), Duration::from_secs(5));
        assert_eq!(reserve(true, 90), Duration::from_secs(15));
        assert_eq!(reserve(true, 15), Duration::from_secs(5));
    }
    #[test]
    fn allowance_exhaustion_keeps_tail_and_cannot_claim_empty() {
        let mut q = Queue {
            live: true,
            queued: VecDeque::from([1, 2]),
            retained: vec![],
            loss: 7,
        };
        let calls = std::cell::Cell::new(0);
        let end = stop_and_drain(
            &mut q,
            |q| {
                q.live = false;
                true
            },
            |q| {
                q.retained.push(q.queued.pop_front().unwrap());
                Ok::<_, ()>(false)
            },
            || {
                let n = calls.get();
                calls.set(n + 1);
                n < 1
            },
        )
        .unwrap();
        assert!(!end.complete());
        assert_eq!(q.retained, [1]);
        assert_eq!(q.queued, [2]);
        assert_eq!(q.loss, 7);
    }
    #[test]
    fn failed_stop_and_read_error_never_fabricate_completion() {
        let mut retained = vec![];
        let end = stop_and_drain(&mut retained, |_| false, |_| Ok::<_, ()>(true), || true).unwrap();
        assert!(!end.complete());
        let result = stop_and_drain(
            &mut retained,
            |_| true,
            |r| {
                r.push(9);
                Err::<bool, _>("read failure")
            },
            || true,
        );
        assert_eq!(result, Err("read failure"));
        assert_eq!(retained, [9]);
    }
}
