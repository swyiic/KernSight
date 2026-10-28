//! Device ready time owns the requested observation interval. Outer protection
//! may reject an impossible request, never silently steal time from it.
use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};

pub(super) fn end(
    ready: Instant,
    seconds: u64,
    outer_end: Option<Instant>,
    closeout: Duration,
) -> Result<Option<Instant>> {
    let available_end = outer_end.map(|end| end.checked_sub(closeout).unwrap_or(ready));
    if seconds == 0 {
        if available_end.is_some_and(|end| end <= ready) {
            bail!("observation_time_contract_unavailable: no observation allowance remains after preparation and closeout; not started");
        }
        return Ok(available_end);
    }
    let requested_end = ready
        .checked_add(Duration::from_secs(seconds))
        .context("observation duration overflow")?;
    if available_end.is_some_and(|end| requested_end > end) {
        bail!("observation_time_contract_unavailable: preparation left less than the requested ready-to-stop duration plus closeout; not started, duration not shortened");
    }
    Ok(Some(requested_end))
}

/// Start the next phase with its complete requested interval. Late detection of
/// the preceding boundary and transition work cannot consume the next phase.
/// The effective origin changes; the original outer limit does not.
pub(super) fn next_stage(
    ready: Instant,
    completed_seconds: u64,
    total_seconds: u64,
    outer_end: Option<Instant>,
    closeout: Duration,
) -> Result<(Instant, Option<Instant>)> {
    if completed_seconds >= total_seconds {
        bail!("no remaining observation stage");
    }
    let origin = ready
        .checked_sub(Duration::from_secs(completed_seconds))
        .context("stage observation origin overflow")?;
    Ok((origin, end(origin, total_seconds, outer_end, closeout)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ready_time_has_full_user_interval_with_separate_closeout() {
        let start = Instant::now();
        let ready = start + Duration::from_secs(20);
        assert_eq!(
            end(
                ready,
                30,
                Some(start + Duration::from_secs(75)),
                Duration::from_secs(15)
            )
            .unwrap(),
            Some(ready + Duration::from_secs(30))
        );
        assert_eq!(
            end(ready, 30, None, Duration::from_secs(15)).unwrap(),
            Some(ready + Duration::from_secs(30))
        );
    }
    #[test]
    fn short_outer_contract_refuses_instead_of_shortening_requested_window() {
        let ready = Instant::now();
        assert!(end(
            ready,
            30,
            Some(ready + Duration::from_secs(40)),
            Duration::from_secs(15)
        )
        .is_err());
    }
    #[test]
    fn stage_setup_moves_only_effective_observation_not_original_outer_limit() {
        let start = Instant::now();
        let outer = start + Duration::from_secs(100);
        let setup = Duration::from_secs(10);
        assert_eq!(
            end(start + setup, 60, Some(outer), Duration::from_secs(15)).unwrap(),
            Some(start + Duration::from_secs(70))
        );
        assert!(end(
            start + Duration::from_secs(30),
            60,
            Some(outer),
            Duration::from_secs(15)
        )
        .is_err());
        assert_eq!(
            end(start, 0, Some(outer), Duration::from_secs(15)).unwrap(),
            Some(outer.checked_sub(Duration::from_secs(15)).unwrap())
        );
    }

    #[test]
    fn stage_ready_excludes_prior_overrun_and_setup_from_next_requested_window() {
        let start = Instant::now();
        // First 10-second phase is detected 2.1 seconds late; transition takes
        // another 3 seconds. The second phase still receives its full 10s.
        let ready = start + Duration::from_millis(15_100);
        let outer = start + Duration::from_secs(40);
        let (origin, end) = next_stage(ready, 10, 20, Some(outer), Duration::from_secs(5)).unwrap();
        assert_eq!(ready.duration_since(origin), Duration::from_secs(10));
        assert_eq!(end, Some(ready + Duration::from_secs(10)));

        // A later ready time is refused, rather than extending the same lease.
        assert!(next_stage(
            start + Duration::from_secs(26),
            10,
            20,
            Some(outer),
            Duration::from_secs(5)
        )
        .is_err());
    }

    #[test]
    fn all_remaining_stages_share_original_outer_limit_and_zero_total_is_invalid() {
        let start = Instant::now();
        let outer = start + Duration::from_secs(75);
        let ready = start + Duration::from_secs(30);
        let (origin, end) =
            next_stage(ready, 10, 30, Some(outer), Duration::from_secs(15)).unwrap();
        assert_eq!(ready.duration_since(origin), Duration::from_secs(10));
        assert_eq!(end, Some(ready + Duration::from_secs(20)));
        let later_ready = start + Duration::from_secs(52);
        assert!(next_stage(later_ready, 20, 30, Some(outer), Duration::from_secs(15)).is_err());
        assert!(next_stage(ready, 0, 0, None, Duration::ZERO).is_err());
        assert!(next_stage(ready, 30, 30, None, Duration::ZERO).is_err());
    }

    #[test]
    fn zero_requested_duration_rejects_expired_outer_but_retains_unbounded_mode() {
        let ready = Instant::now();
        assert!(end(ready, 0, Some(ready), Duration::ZERO).is_err());
        assert!(end(
            ready,
            0,
            Some(ready + Duration::from_secs(5)),
            Duration::from_secs(5)
        )
        .is_err());
        assert!(end(
            ready,
            0,
            Some(ready + Duration::from_secs(4)),
            Duration::from_secs(5)
        )
        .is_err());
        assert_eq!(end(ready, 0, None, Duration::from_secs(5)).unwrap(), None);
        assert_eq!(
            end(
                ready,
                0,
                Some(ready + Duration::from_secs(6)),
                Duration::from_secs(5)
            )
            .unwrap(),
            Some(ready + Duration::from_secs(1))
        );
    }
}
