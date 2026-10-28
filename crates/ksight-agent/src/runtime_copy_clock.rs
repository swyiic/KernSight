//! Device-owned effective copy time. Setup never spends an explicit operator
//! duration, and an outer invocation limit may refuse it but never shorten it.
use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};

pub(crate) struct RuntimeCopyClock {
    outer_copy_deadline: Instant,
    requested: Option<Duration>,
    started: Option<Instant>,
    deadline: Option<Instant>,
}

impl RuntimeCopyClock {
    pub(crate) fn new(outer_copy_deadline: Instant, requested_ms: Option<u64>) -> Result<Self> {
        if requested_ms.is_some_and(|ms| !(1..=3_600_000).contains(&ms)) {
            bail!("runtime-copy-ms must be between 1 and 3600000");
        }
        Ok(Self {
            outer_copy_deadline,
            requested: requested_ms.map(Duration::from_millis),
            started: None,
            deadline: None,
        })
    }

    /// Called after qualification, anchored handles and candidate metadata are ready.
    pub(crate) fn ready(&mut self, now: Instant) -> Result<Instant> {
        if let Some(deadline) = self.deadline {
            return Ok(deadline);
        }
        let deadline = if let Some(requested) = self.requested {
            let end = now
                .checked_add(requested)
                .context("runtime copy deadline overflow")?;
            if end > self.outer_copy_deadline {
                bail!("runtime_copy_time_contract_unavailable: preparation left less than the requested copy duration; not started, duration not shortened");
            }
            end
        } else {
            self.outer_copy_deadline
        };
        if now >= deadline {
            bail!("runtime copy window expired before readiness");
        }
        self.started = Some(now);
        self.deadline = Some(deadline);
        Ok(deadline)
    }

    pub(crate) fn requested_ms(&self) -> Option<u64> {
        self.requested.map(|duration| {
            u64::try_from(duration.as_millis()).expect("validated one-hour maximum")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_does_not_spend_requested_time_and_next_source_cannot_renew_it() {
        let start = Instant::now();
        let mut clock =
            RuntimeCopyClock::new(start + Duration::from_secs(240), Some(180_000)).unwrap();
        let ready = start + Duration::from_secs(20);
        let end = clock.ready(ready).unwrap();
        assert_eq!(end - ready, Duration::from_secs(180));
        assert_eq!(clock.ready(ready + Duration::from_secs(150)).unwrap(), end);
        assert_eq!(clock.requested_ms(), Some(180_000));
    }
    #[test]
    fn insufficient_outer_budget_refuses_instead_of_clipping_user_duration() {
        let start = Instant::now();
        let mut clock =
            RuntimeCopyClock::new(start + Duration::from_secs(180), Some(180_000)).unwrap();
        assert!(clock
            .ready(start + Duration::from_millis(1))
            .unwrap_err()
            .to_string()
            .contains("duration not shortened"));
        assert!(clock.started.is_none());
        assert!(clock.deadline.is_none());
        for ms in [0, 3_600_001, u64::MAX] {
            assert!(RuntimeCopyClock::new(start, Some(ms)).is_err());
        }
    }
    #[test]
    fn legacy_clock_retains_original_absolute_boundary() {
        let start = Instant::now();
        let mut clock = RuntimeCopyClock::new(start + Duration::from_secs(30), None).unwrap();
        assert_eq!(
            clock.ready(start + Duration::from_secs(10)).unwrap(),
            start + Duration::from_secs(30)
        );
    }
}
