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
        }
    }
}

/// Drain until genuinely empty or an explicit error. The caller owns reusable
/// read slots. No successful read or loss counter is discarded on error.
pub fn drain_reads<T, E>(
    mut read: impl FnMut() -> Result<PerfRead<T>, (E, Option<u64>)>,
    timestamp: impl Fn(&T) -> u64,
) -> PerfDrainReport<T, E> {
    let start = std::time::Instant::now();
    let mut report = PerfDrainReport::default();
    loop {
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
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn read(
        samples: &[u64],
        lost: u64,
        when: u64,
    ) -> Result<PerfRead<u64>, (&'static str, Option<u64>)> {
        Ok(PerfRead {
            samples: samples.len() as u64,
            records: samples.to_vec(),
            lost_samples: lost,
            notification_monotonic_ns: Some(when),
        })
    }
    #[test]
    fn perf_lost_only_read_is_recorded_before_empty_and_has_no_fake_kernel_time() {
        let mut reads = [read(&[], 7, 100), read(&[], 0, 110)].into_iter();
        let r = drain_reads(|| reads.next().unwrap(), |t| *t);
        assert_eq!(r.raw_samples, 0);
        assert_eq!(r.lost_samples, 7);
        assert_eq!(r.lost_only_reads, 1);
        assert_eq!(r.read_calls, 2);
        assert_eq!(
            r.notifications[0],
            PerfLossNotification {
                lost_samples: 7,
                notification_monotonic_ns: Some(100),
                first_returned_kernel_ns: None,
                last_returned_kernel_ns: None
            }
        );
        assert!(r.records.is_empty() && r.error.is_none());
    }
    #[test]
    fn perf_mixed_samples_and_loss_preserve_units_order_and_original_notice_times() {
        let mut reads = [
            read(&[10, 12], 3, 100),
            read(&[], 4, 150),
            read(&[18], 0, 160),
            read(&[], 0, 170),
        ]
        .into_iter();
        let r = drain_reads(|| reads.next().unwrap(), |t| *t);
        assert_eq!(r.records, [10, 12, 18]);
        assert_eq!(r.raw_samples, 3);
        assert_eq!(r.lost_samples, 7);
        assert_eq!(r.notifications.len(), 2);
        assert_eq!(r.notifications[0].notification_monotonic_ns, Some(100));
        assert_eq!(r.notifications[0].first_returned_kernel_ns, Some(10));
        assert_eq!(r.notifications[0].last_returned_kernel_ns, Some(12));
        assert_eq!(r.notifications[1].notification_monotonic_ns, Some(150));
        assert_eq!(r.notifications[1].first_returned_kernel_ns, None);
    }
    #[test]
    fn perf_error_keeps_already_consumed_records_loss_and_retry_does_not_duplicate() {
        let mut reads = [read(&[10], 2, 100), Err(("read_failure", Some(130)))].into_iter();
        let r = drain_reads(|| reads.next().unwrap(), |t| *t);
        assert_eq!(r.records, [10]);
        assert_eq!(r.raw_samples, 1);
        assert_eq!(r.lost_samples, 2);
        assert_eq!(r.error, Some("read_failure"));
        assert_eq!(r.error_notification_monotonic_ns, Some(130));
        let mut retry = [read(&[20], 0, 200), read(&[], 0, 210)].into_iter();
        let next = drain_reads(|| retry.next().unwrap(), |t| *t);
        assert_eq!(next.records, [20]);
        assert_eq!(next.lost_samples, 0);
        assert_eq!(r.raw_samples + next.raw_samples, 2);
    }
    #[test]
    fn perf_invalid_sample_is_counted_raw_without_creating_a_decoded_record() {
        let mut reads = [
            Ok::<_, (&'static str, Option<u64>)>(PerfRead {
                samples: 1,
                records: vec![],
                lost_samples: 2,
                notification_monotonic_ns: None,
            }),
            read(&[], 0, 110),
        ]
        .into_iter();
        let r = drain_reads(|| reads.next().unwrap(), |t| *t);
        assert_eq!(r.raw_samples, 1);
        assert_eq!(r.records.len(), 0);
        assert_eq!(r.lost_only_reads, 0);
        assert_eq!(r.notifications[0].notification_monotonic_ns, None);
    }
}
