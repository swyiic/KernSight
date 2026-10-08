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
    /// CPU buffer reporting the loss; generic fixtures leave it unspecified.
    pub cpu_id: Option<u32>,
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
    read: impl FnMut() -> Result<PerfRead<T>, (E, Option<u64>)>,
    timestamp: impl Fn(&T) -> u64,
) -> PerfDrainReport<T, E> {
    drain_reads_bounded(read, timestamp, 8)
}

/// Once producers are confirmed stopped, larger bounded read batches reduce
/// repeated per-buffer overhead without enlarging kernel rings or time slices.
pub fn drain_stopped_reads<T, E>(
    read: impl FnMut() -> Result<PerfRead<T>, (E, Option<u64>)>,
    timestamp: impl Fn(&T) -> u64,
) -> PerfDrainReport<T, E> {
    drain_reads_bounded(read, timestamp, 32)
}
fn drain_reads_bounded<T, E>(
    mut read: impl FnMut() -> Result<PerfRead<T>, (E, Option<u64>)>,
    timestamp: impl Fn(&T) -> u64,
    max_calls: u64,
) -> PerfDrainReport<T, E> {
    let start = std::time::Instant::now();
    let mut report = PerfDrainReport::default();
    loop {
        // A continuously replenished (including lost-only) ring need never empty.
        // Return to the capture loop so its original observation/lease can be checked.
        if report.read_calls >= max_calls
            || (report.read_calls > 0 && start.elapsed().as_millis() >= 2)
        {
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
                cpu_id: None,
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

/// Visit every CPU once, rotating the starting point without enlarging a ring.
pub fn fair_indices(count: usize, first: usize) -> impl Iterator<Item = usize> {
    (0..count).map(move |offset| (first + offset) % count)
}
#[cfg(test)]
mod fairness_tests {
    #[test]
    fn continuous_first_cpu_cannot_starve_other_cpus_or_reorder_its_tail() {
        let mut seen = vec![vec![]; 3];
        for round in 0..6 {
            for cpu in super::fair_indices(3, round % 3) {
                seen[cpu].push(round);
            }
        }
        assert_eq!(seen, vec![vec![0, 1, 2, 3, 4, 5]; 3]);
        assert_eq!(super::fair_indices(0, 0).count(), 0);
        assert_eq!(super::fair_indices(3, 2).collect::<Vec<_>>(), [2, 0, 1]);
    }
}

#[cfg(test)]
mod stopped_batch_tests {
    use super::*;
    #[test]
    fn stopped_batch_is_finite_retains_loss_and_can_observe_empty() {
        let mut count = 0;
        let report = drain_stopped_reads(
            || {
                count += 1;
                Ok::<_, ((), Option<u64>)>(PerfRead {
                    samples: u64::from(count <= 20),
                    records: if count <= 20 { vec![count] } else { vec![] },
                    lost_samples: if count == 2 { 7 } else { 0 },
                    notification_monotonic_ns: None,
                })
            },
            |x| *x,
        );
        assert!(!report.budget_yielded);
        assert_eq!(report.raw_samples, 20);
        assert_eq!(report.lost_samples, 7);
        assert_eq!(report.read_calls, 21);
        let forever = drain_stopped_reads(
            || {
                Ok::<_, ((), Option<u64>)>(PerfRead {
                    samples: 1,
                    records: vec![1],
                    lost_samples: 0,
                    notification_monotonic_ns: None,
                })
            },
            |x| *x,
        );
        assert!(forever.budget_yielded);
        assert!(forever.read_calls <= 32);
    }
}

/// Close a one-shot producer without discarding unread queue decoding authority.
/// A closure failure retains already-read records and remains a reader error.
pub fn stop_after_one_shot<T, E>(
    hit_once: bool,
    report: &mut PerfDrainReport<T, E>,
    stop: impl FnOnce() -> Result<(), E>,
) {
    if hit_once && !report.records.is_empty() && report.error.is_none() {
        if let Err(error) = stop() {
            report.error = Some(error);
        }
    }
}
#[cfg(test)]
mod one_shot_shutdown_tests {
    use super::*;
    #[test]
    fn stops_once_without_discarding_records_or_loss_and_preserves_errors() {
        let mut report: PerfDrainReport<u64, &str> = PerfDrainReport {
            records: vec![1],
            raw_samples: 1,
            lost_samples: 7,
            budget_yielded: true,
            ..Default::default()
        };
        let mut closed = false;
        stop_after_one_shot(true, &mut report, || {
            closed = true;
            Ok(())
        });
        assert!(closed);
        assert_eq!(report.records, vec![1]);
        assert_eq!(report.lost_samples, 7);
        assert!(report.budget_yielded);
        stop_after_one_shot(true, &mut report, || Err("detach denied"));
        assert_eq!(report.error, Some("detach denied"));
        assert_eq!(report.records, vec![1]);
        let mut empty: PerfDrainReport<u64, &str> = Default::default();
        stop_after_one_shot(true, &mut empty, || {
            panic!("empty queue cannot trigger a hit")
        });
    }
}

#[cfg(test)]
mod one_shot_tail_integration {
    use super::*;
    use std::collections::VecDeque;
    #[test]
    fn hit_closes_producer_tail_still_decodes_and_real_empty_is_observed() {
        let mut queue = VecDeque::from([11_u64, 12, 13]);
        let epoch = 7;
        let mut first: PerfDrainReport<u64, &str> = PerfDrainReport {
            records: vec![10],
            raw_samples: 1,
            budget_yielded: true,
            ..Default::default()
        };
        let mut producer_live = true;
        stop_after_one_shot(true, &mut first, || {
            producer_live = false;
            Ok(())
        });
        assert!(!producer_live);
        let mut valid_scope = true;
        let tail = drain_stopped_reads(
            || {
                assert!(valid_scope);
                assert_eq!(epoch, 7);
                Ok::<_, (&str, Option<u64>)>(match queue.pop_front() {
                    Some(v) => PerfRead {
                        samples: 1,
                        records: vec![v],
                        lost_samples: 0,
                        notification_monotonic_ns: None,
                    },
                    None => PerfRead {
                        samples: 0,
                        records: vec![],
                        lost_samples: 0,
                        notification_monotonic_ns: None,
                    },
                })
            },
            |v| *v,
        );
        assert_eq!(tail.records, vec![11, 12, 13]);
        assert!(!tail.budget_yielded);
        assert_eq!(tail.read_calls, 4);
        valid_scope = false;
        assert!(!valid_scope); // Final authority revocation follows queue observation.
    }
    #[test]
    fn canceled_shutdown_stops_production_but_identity_error_never_claims_empty() {
        let mut first: PerfDrainReport<u64, &str> = PerfDrainReport {
            records: vec![10],
            ..Default::default()
        };
        let mut live = true;
        stop_after_one_shot(true, &mut first, || {
            live = false;
            Ok(())
        });
        assert!(!live);
        let invalid = drain_stopped_reads(
            || Err::<PerfRead<u64>, _>(("original identity invalidated", Some(9))),
            |v| *v,
        );
        assert_eq!(invalid.error, Some("original identity invalidated"));
        assert!(invalid.records.is_empty());
        assert_eq!(first.records, vec![10]);
    }
}
