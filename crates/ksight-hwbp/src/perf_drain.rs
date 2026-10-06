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
