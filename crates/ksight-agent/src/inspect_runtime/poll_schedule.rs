//! Advisory scheduling only: no capability, quota, ring discard or new deadline.
#![cfg_attr(
    not(any(test, target_os = "linux", target_os = "android")),
    allow(dead_code)
)]

pub(super) fn order(ready: &[bool], first: usize) -> Vec<usize> {
    let len = ready.len();
    if len == 0 {
        return Vec::new();
    }
    let first = first % len;
    let circular = || (0..len).map(|step| (first + step) % len);
    circular()
        .filter(|&i| ready[i])
        .chain(circular().filter(|&i| !ready[i]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ready_first_fair_and_idle_still_checked_without_reordering_owned_sessions() {
        assert_eq!(order(&[], 100), Vec::<usize>::new());
        assert_eq!(order(&[false, true, false, true], 2), vec![3, 1, 2, 0]);
        assert_eq!(order(&[false, false, false], 5), vec![2, 0, 1]);
        let ready = [true; 24];
        let mut cursor = 0;
        let mut visited = [0; 24];
        for _ in 0..24 {
            for i in order(&ready, cursor).into_iter().take(10) {
                visited[i] += 1;
                cursor = (i + 1) % ready.len();
            }
        }
        assert_eq!(visited, [10; 24]);
    }
    #[test]
    fn selected_pair_records_loss_and_later_read_failure_survive_scheduling() {
        use ksight_hwbp::perf_drain::{drain_reads, PerfRead};
        let mut consumed = Vec::new();
        let mut lost = 0;
        let mut failure = None;
        for index in order(&[true, true], 1) {
            let mut calls = 0;
            let report = drain_reads(
                || {
                    calls += 1;
                    if index == 0 && calls == 2 {
                        return Err(("fixture read failure", Some(12)));
                    }
                    Ok(PerfRead {
                        samples: if calls == 1 { 2 } else { 0 },
                        records: if calls == 1 {
                            vec![(index, 1), (index, 2)]
                        } else {
                            vec![]
                        },
                        lost_samples: if calls == 1 { 7 } else { 0 },
                        notification_monotonic_ns: Some(11),
                    })
                },
                |r| r.1,
            );
            consumed.extend(report.records);
            lost += report.lost_samples;
            if report.error.is_some() {
                failure = report.error;
            }
        }
        assert_eq!(consumed, vec![(1, 1), (1, 2), (0, 1), (0, 2)]);
        assert_eq!(lost, 14);
        assert_eq!(failure, Some("fixture read failure"));
    }

    fn replay(fair: bool, sparse: bool) -> (u64, usize, u64, u64) {
        // Deterministic isolated reader costs; NOT measured phone timings.
        // Each busy paired session takes its existing maximum 2ms read slice.
        // Idle-session validation/read overhead is explicitly modeled as200us.
        let ready = (0..48).map(|i| !sparse || i >= 24).collect::<Vec<_>>();
        let mut visits = [0u64; 48];
        let mut cursor = 0;
        let mut idle = 0;
        let mut time = 0;
        for _ in 0..96 {
            let indices = if fair {
                order(&ready, cursor)
            } else {
                (0..ready.len()).collect()
            };
            let mut elapsed = 0;
            for i in indices {
                if elapsed >= 20_000 {
                    break;
                }
                if ready[i] {
                    visits[i] += 1;
                    elapsed += 2_000;
                } else {
                    idle += 1;
                    elapsed += 200;
                }
                cursor = (i + 1) % ready.len();
            }
            time += elapsed;
        }
        let serviced = visits
            .iter()
            .enumerate()
            .filter(|&(i, n)| ready[i] && *n > 0)
            .count();
        (visits.iter().sum(), serviced, idle, time)
    }
    #[test]
    fn bounded_fixed_prefix_starvation_reproduces_and_fair_ready_set_removes_it() {
        let old = replay(false, false);
        let new = replay(true, false);
        assert_eq!(old.1, 10);
        assert_eq!(new.1, 48);
        assert_eq!(old.0, new.0);
        assert_eq!(old.3, new.3);
        let old_sparse = replay(false, true);
        let new_sparse = replay(true, true);
        assert!(new_sparse.0 > old_sparse.0);
        assert_eq!(new_sparse.1, 24);
        assert!(new_sparse.2 < old_sparse.2);
        println!("ISOLATED_POLL_REPLAY all_busy old={old:?} new={new:?}; sparse old={old_sparse:?} new={new_sparse:?}; tuple=(busy_slices,unique_busy_sessions,idle_visits,modeled_us); device_throughput_not_measured=true");
    }
}
