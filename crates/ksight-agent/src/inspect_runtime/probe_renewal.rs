//! A completed one-shot probe stays completed; renewal cannot rearm it.
use anyhow::Result;

pub(super) fn renew_active<T>(
    probes: &mut [T],
    completed_once: impl Fn(&T) -> bool,
    mut renew: impl FnMut(&mut T) -> Result<()>,
) -> Result<()> {
    for probe in probes {
        if !completed_once(probe) {
            renew(probe)?;
        }
    }
    Ok(())
}

// Scope transactions are synchronous. A completed one-shot poll may detach,
// but its successful returned batch still belongs to the pre-poll epoch.
// A poll error returns no epoch/batch to the consumer.
pub(super) fn poll_with_epoch<T, R>(
    probe: &mut T,
    epoch: impl FnOnce(&T) -> Option<u32>,
    poll: impl FnOnce(&mut T) -> Result<R>,
) -> Result<(Option<u32>, R)> {
    let committed = epoch(probe);
    let batch = poll(probe)?;
    Ok((committed, batch))
}

#[cfg(test)]
mod tests {
    use super::{poll_with_epoch, renew_active};

    struct Probe {
        finished: bool,
        renewals: usize,
        fail: bool,
    }
    impl Probe {
        fn renew(&mut self) -> anyhow::Result<()> {
            self.renewals += 1;
            anyhow::ensure!(!self.finished, "cannot update detached instance session");
            anyhow::ensure!(!self.fail, "active instance transaction failed");
            Ok(())
        }
    }

    #[test]
    fn completed_one_shot_stays_detached_while_active_probe_renews() {
        let mut probes = [
            Probe {
                finished: true,
                renewals: 0,
                fail: false,
            },
            Probe {
                finished: false,
                renewals: 0,
                fail: false,
            },
        ];
        for _ in 0..2 {
            renew_active(&mut probes, |probe| probe.finished, Probe::renew).expect("renewal");
        }
        assert!(probes[0].finished);
        assert_eq!(probes[0].renewals, 0);
        assert_eq!(probes[1].renewals, 2);
    }

    #[test]
    fn active_failure_is_not_swallowed_or_retried() {
        let mut probes = [
            Probe {
                finished: false,
                renewals: 0,
                fail: true,
            },
            Probe {
                finished: false,
                renewals: 0,
                fail: false,
            },
        ];
        let error = renew_active(&mut probes, |probe| probe.finished, Probe::renew)
            .expect_err("active failure");
        assert!(error
            .to_string()
            .contains("active instance transaction failed"));
        assert_eq!(probes[0].renewals, 1);
        assert_eq!(probes[1].renewals, 0);
    }

    #[test]
    fn empty_and_fully_completed_sets_require_no_new_admission() {
        let mut empty: [Probe; 0] = [];
        renew_active(
            &mut empty,
            |probe| probe.finished,
            |_| panic!("empty renew"),
        )
        .expect("empty");
        let mut probes = [Probe {
            finished: true,
            renewals: 0,
            fail: true,
        }];
        renew_active(
            &mut probes,
            |probe| probe.finished,
            |_| panic!("completed renew"),
        )
        .expect("completed");
    }

    #[test]
    fn successful_one_shot_retains_its_batch_epoch_after_detach() {
        let mut live_epoch = Some(7);
        let (epoch, records) = poll_with_epoch(
            &mut live_epoch,
            |scope| *scope,
            |scope| {
                *scope = None; // UprobeSession detaches after collecting the final batch.
                Ok(vec![7_u32])
            },
        )
        .expect("successful one-shot batch");
        assert!(live_epoch.is_none());
        assert_eq!(epoch, Some(7));
        assert_eq!(records, [7]);
    }

    #[test]
    fn poll_failure_never_exposes_a_saved_epoch_or_partial_batch() {
        let mut live_epoch = Some(7);
        let result = poll_with_epoch::<_, Vec<u32>>(
            &mut live_epoch,
            |scope| *scope,
            |scope| {
                *scope = None;
                anyhow::bail!("authorized task exited; discard drained generation");
            },
        );
        let error = result.expect_err("failed poll must not return retained epoch");
        assert!(error.to_string().contains("authorized task exited"));
        assert!(live_epoch.is_none());
    }

    #[test]
    fn detached_continuous_probe_is_not_treated_as_completed_one_shot() {
        let mut probes = [Probe {
            finished: true,
            renewals: 0,
            fail: false,
        }];
        let error = renew_active(&mut probes, |_| false, Probe::renew)
            .expect_err("continuous probe cannot silently stay detached");
        assert!(error
            .to_string()
            .contains("cannot update detached instance session"));
        assert_eq!(probes[0].renewals, 1);
    }
}
