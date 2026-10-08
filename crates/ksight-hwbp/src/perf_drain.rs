//! Portable perf-read accounting shared by the live uprobe reader and tests.
//! Counts are kernel samples, including metadata and payload segments, not HTTP
//! requests. Lost records have no recoverable event timestamp.

/// One successful buffer read. Empty records can still contain a loss notice.
pub struct PerfRead<T> {
    /// Number of raw samples returned, including malformed/undecodable records.
    pub samples: u64,
    /// Valid decoded records, in the buffer's original order.
    pub records: Vec<T>,
    /// Kernel-reported sample loss, never inferred from decoded counts.
    pub lost_samples: u64,
    /// Instant at which the read result was observed, not lost-record time.
    pub notification_monotonic_ns: Option<u64>,
}

/// Original read-result loss notification with available returned-record bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfLossNotification {
    /// Number of kernel samples reported lost by this read result.
    pub lost_samples: u64,
    /// Read-result observation time; absent if the monotonic clock failed.
    pub notification_monotonic_ns: Option<u64>,
    /// Earliest timestamp among valid samples returned by this same read.
    pub first_returned_kernel_ns: Option<u64>,
    /// Latest timestamp among valid samples returned by this same read.
    pub last_returned_kernel_ns: Option<u64>,
}

/// Complete or partial poll. Successful earlier reads survive a later error.
pub struct PerfDrainReport<T, E> {
    /// All valid records already consumed from the ring, in read order.
    pub records: Vec<T>,
    /// Raw kernel samples consumed, independent of decoder success.
    pub raw_samples: u64,
    /// Kernel-reported lost samples, including lost-only reads.
    pub lost_samples: u64,
    /// Every original loss notice, without timestamp reconstruction.
    pub notifications: Vec<PerfLossNotification>,
    /// Failed read; callers must invalidate proofs before processing records.
    pub error: Option<E>,
    /// Original failed-read observation time.
    pub error_notification_monotonic_ns: Option<u64>,
    /// Number of read calls, including the final empty read or error.
    pub read_calls: u64,
    /// Number of read results containing loss and zero samples.
    pub lost_only_reads: u64,
    /// Measured wall time in this drain, not CPU time or kernel-record age.
    pub elapsed_us: u64,
    /// Poll yielded with unread ring data; not a loss or a failed read.
    pub budget_yielded: bool,
}

impl<T, E> Default for PerfDrainReport<T, E> {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            raw_samples: 0,
            lost_samples: 0,
            notifications: Vec::new(),
            error: None,
            error_notification_monotonic_ns: None,
            read_calls: 0,
            lost_only_reads: 0,
            elapsed_us: 0,
            budget_yielded: false,
        }
    }
}

/// Drain a bounded slice until empty, an error or the poll allowance expires.
/// Unread data stays in the kernel ring for the next poll. The caller owns reusable
/// read slots. No successful read or loss counter is discarded on error.
pub fn drain_reads<T, E>(
    mut read: impl FnMut() -> Result<PerfRead<T>, (E, Option<u64>)>,
    timestamp: impl Fn(&T) -> u64,
) -> PerfDrainReport<T, E> {
    let start = std::time::Instant::now();
    let mut report = PerfDrainReport::default();
    loop {
        // A continuously replenished (including lost-only) ring need never empty.
        // Return to the capture loop so its original observation/lease can be checked.
        if report.read_calls >= 8 || (report.read_calls > 0 && start.elapsed().as_millis() >= 2) {
            report.budget_yielded = true;
            break;
        }
        report.read_calls += 1;
        let batch = match read() {
            Ok(batch) => batch,
            Err((error, when)) => {
                report.error = Some(error);
                report.error_notification_monotonic_ns = when;
                break;
            }
        };
        report.raw_samples = report.raw_samples.saturating_add(batch.samples);
        report.lost_samples = report.lost_samples.saturating_add(batch.lost_samples);
        if batch.lost_samples != 0 {
            report.lost_only_reads += u64::from(batch.samples == 0);
            report.notifications.push(PerfLossNotification {
                lost_samples: batch.lost_samples,
                notification_monotonic_ns: batch.notification_monotonic_ns,
                first_returned_kernel_ns: batch.records.iter().map(&timestamp).min(),
                last_returned_kernel_ns: batch.records.iter().map(&timestamp).max(),
            });
        }
        report.records.extend(batch.records);
        // A lost-only read advanced the ring tail; keep reading rather than
        // silently losing its notification or fabricating a sample.
        if batch.samples == 0 && batch.lost_samples == 0 {
            break;
        }
    }
    report.elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuous_producer_yields_without_discarding_consumed_records() {
        let mut sequence = 0;
        let mut read = || {
            sequence += 1;
            Ok::<_, ((), Option<u64>)>(PerfRead {
                samples: 1,
                records: vec![sequence],
                lost_samples: 0,
                notification_monotonic_ns: Some(sequence),
            })
        };
        let first = drain_reads(&mut read, |v| *v);
        assert!(first.budget_yielded);
        // Returning successfully is not proof of an empty ring at observation end.
        assert!(first.error.is_none() && first.budget_yielded);
        assert!((1..=8).contains(&first.read_calls));
        assert_eq!(first.records.len() as u64, first.raw_samples);
        assert_eq!(first.error, None);
        let next = drain_reads(&mut read, |v| *v);
        assert_eq!(next.records[0], first.records.last().unwrap() + 1);
    }

    #[test]
    fn continuous_lost_only_notifications_cannot_starve_deadline_checks() {
        let r = drain_reads(
            || {
                Ok::<_, ((), Option<u64>)>(PerfRead::<u64> {
                    samples: 0,
                    records: vec![],
                    lost_samples: 3,
                    notification_monotonic_ns: Some(7),
                })
            },
            |v| *v,
        );
        assert!(r.budget_yielded);
        assert_eq!(r.lost_only_reads, r.read_calls);
        assert_eq!(r.lost_samples, r.read_calls * 3);
        assert_eq!(r.notifications.len() as u64, r.read_calls);
    }

    #[test]
    fn slow_read_yields_before_another_read_and_preserves_its_result() {
        let r = drain_reads(
            || {
                std::thread::sleep(std::time::Duration::from_millis(3));
                Ok::<_, ((), Option<u64>)>(PerfRead {
                    samples: 1,
                    records: vec![9],
                    lost_samples: 2,
                    notification_monotonic_ns: Some(5),
                })
            },
            |v| *v,
        );
        assert!(r.budget_yielded);
        assert_eq!(r.read_calls, 1);
        assert_eq!(r.records, vec![9]);
        assert_eq!(r.lost_samples, 2);
    }
}

/// Status of a completed bounded read slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollDrainState {
    /// Empty was observed, without claiming later arrivals are impossible.
    Empty,
    /// The allowance ended before empty could be established.
    Yielded,
}
/// Payload-free progress callback from the synchronous reader.
#[derive(Clone, Copy)]
pub enum PollPhase {
    /// Physical scope validation.
    Scope,
    /// Aya ring read.
    Read,
    /// Raw record decoding.
    Decode,
    /// Owned probe detachment.
    Detach,
    /// Return to the enclosing poll.
    Poll,
}
static OBSERVER: std::sync::OnceLock<fn(PollPhase)> = std::sync::OnceLock::new();
/// Install diagnostic observation once; this grants no scope and alters no deadline.
pub fn observe_phases(observer: fn(PollPhase)) {
    let _ = OBSERVER.set(observer);
}
pub(crate) fn phase(phase: PollPhase) {
    if let Some(observer) = OBSERVER.get() {
        observer(phase);
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod inner_reader_tests {
    #[test]
    fn production_guard_rejects_non_progressing_and_oversized_ring_records() {
        for (size, available, ring) in [
            (0, 64, 4096),
            (7, 64, 4096),
            (128, 64, 4096),
            (8192, 8192, 4096),
        ] {
            assert!(aya::maps::perf::validate_record_size(size, available, ring).is_err());
        }
        for size in [8, 16, 32, 64] {
            aya::maps::perf::validate_record_size(size, 64, 4096).unwrap();
        }
    }
}
