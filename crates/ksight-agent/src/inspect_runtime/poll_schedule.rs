//! Advisory scheduling only: no capability, quota, ring discard or new deadline.
#![cfg_attr(
    not(any(test, target_os = "linux", target_os = "android")),
    allow(dead_code)
)]

fn order(ready: &[bool], first: usize) -> Vec<usize> {
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

/// Shared by the live poll and deterministic fixtures, including the owned slice rotation.
pub(super) struct Round {
    indices: Vec<usize>,
    probes_read: usize,
    unread_probes: bool,
}

impl Round {
    pub(super) fn new(ready: &[bool], first: usize) -> Self {
        Self {
            indices: order(ready, first),
            probes_read: 0,
            unread_probes: false,
        }
    }

    /// Update the cursor before polling, so an early scope failure preserves progress.
    pub(super) fn next(&mut self, elapsed_ms: u128, cursor: &mut usize) -> Option<usize> {
        let index = *self.indices.get(self.probes_read)?;
        if self.probes_read != 0 && elapsed_ms >= 20 {
            self.unread_probes = true;
            return None;
        }
        self.probes_read += 1;
        *cursor = (index + 1) % self.indices.len();
        Some(index)
    }

    pub(super) fn finish<T>(self, sessions: &mut [T], cursor: &mut usize) -> bool {
        debug_assert_eq!(sessions.len(), self.indices.len());
        if !sessions.is_empty() {
            let len = sessions.len();
            let rotate = self.probes_read % len;
            sessions.rotate_left(rotate);
            // The cursor indexes this slice, so move it into the rotated coordinates.
            *cursor = (*cursor % len + len - rotate) % len;
        }
        self.unread_probes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksight_hwbp::perf_drain::{drain_reads, fair_indices, PerfRead};

    fn run_round(
        sessions: &mut [usize],
        cursor: &mut usize,
        ready_id: impl Fn(usize) -> bool,
        cost_ms: impl Fn(usize) -> u128,
        mut visit: impl FnMut(usize),
    ) -> bool {
        let ready = sessions.iter().map(|&id| ready_id(id)).collect::<Vec<_>>();
        let mut round = Round::new(&ready, *cursor);
        let mut elapsed = 0;
        while let Some(index) = round.next(elapsed, cursor) {
            let id = sessions[index];
            visit(id);
            elapsed += cost_ms(id);
        }
        round.finish(sessions, cursor)
    }

    #[test]
    fn live_round_cursor_and_owned_rotation_do_not_starve_persistent_ready_probes() {
        let mut sessions = (0..20).collect::<Vec<_>>();
        let mut cursor = 0;
        let mut visits = [0; 20];
        for _ in 0..20 {
            assert!(run_round(
                &mut sessions,
                &mut cursor,
                |_| true,
                |_| 2,
                |id| {
                    visits[id] += 1;
                }
            ));
        }
        println!("LIVE_POLL_SCHEDULE visits={visits:?}; modeled_probe_ms=2; shared_budget_ms=20; device_throughput_not_measured=true");
        assert_eq!(visits, [10; 20]);
    }

    #[test]
    fn sparse_ready_set_uses_the_same_cursor_and_rotation_path() {
        let mut sessions = (0..24).collect::<Vec<_>>();
        let mut cursor = 0;
        let mut visits = [0; 24];
        for _ in 0..12 {
            assert!(run_round(
                &mut sessions,
                &mut cursor,
                |id| id % 2 == 1,
                |_| 2,
                |id| {
                    visits[id] += 1;
                }
            ));
        }
        for (id, count) in visits.into_iter().enumerate() {
            assert_eq!(count, if id % 2 == 1 { 10 } else { 0 });
        }
    }

    #[test]
    fn advisory_idle_probes_are_still_visited_when_the_budget_allows() {
        assert_eq!(order(&[], 100), Vec::<usize>::new());
        assert_eq!(order(&[false, true, false, true], 2), vec![3, 1, 2, 0]);
        let mut sessions = vec![0, 1, 2, 3];
        let mut cursor = 2;
        let mut visited = Vec::new();
        assert!(!run_round(
            &mut sessions,
            &mut cursor,
            |id| id % 2 == 1,
            |_| 1,
            |id| {
                visited.push(id);
            }
        ));
        assert_eq!(visited, vec![3, 1, 2, 0]);
    }

    #[test]
    fn budget_break_preserves_the_next_owned_probe_and_checks_one_probe_first() {
        let mut sessions = vec![10, 11, 12];
        let mut cursor = 0;
        let mut first = Round::new(&[true; 3], cursor);
        assert_eq!(first.next(20, &mut cursor), Some(0));
        assert_eq!(first.next(20, &mut cursor), None);
        assert!(first.finish(&mut sessions, &mut cursor));
        let mut second = Round::new(&[true; 3], cursor);
        let index = second.next(0, &mut cursor).unwrap();
        assert_eq!(sessions[index], 11);
    }

    #[test]
    fn probe_growth_removal_and_empty_sets_keep_indices_in_the_current_slice() {
        let mut empty = Vec::<usize>::new();
        let mut cursor = usize::MAX;
        assert!(!run_round(
            &mut empty,
            &mut cursor,
            |_| true,
            |_| 2,
            |_| panic!("empty poll")
        ));
        let mut sessions = vec![0, 1, 2, 3];
        let mut visited = Vec::new();
        run_round(
            &mut sessions,
            &mut cursor,
            |_| true,
            |_| 20,
            |id| visited.push(id),
        );
        sessions.extend(4..9);
        sessions.retain(|id| *id != 0 && *id != 2);
        let retained = sessions.clone();
        visited.clear();
        for _ in 0..sessions.len() {
            run_round(
                &mut sessions,
                &mut cursor,
                |_| true,
                |_| 20,
                |id| visited.push(id),
            );
        }
        let mut seen = visited;
        seen.sort_unstable();
        let mut expected = retained;
        expected.sort_unstable();
        assert_eq!(seen, expected);
        sessions.clear();
        assert!(!run_round(
            &mut sessions,
            &mut cursor,
            |_| false,
            |_| 0,
            |_| panic!("cleared poll")
        ));
    }

    #[test]
    fn multiple_cpu_sources_and_paired_records_keep_loss_and_later_read_errors() {
        // A pair remains one scheduling unit. Readiness on any CPU selects it;
        // the original fair CPU iterator and drain accounting remain unchanged.
        let mut sessions = vec![0, 1];
        let ready_cpu = [[false, false, true], [false, true, false]];
        let ready = ready_cpu
            .iter()
            .map(|cpus| cpus.iter().any(|v| *v))
            .collect::<Vec<_>>();
        let mut cursor = 1;
        let mut round = Round::new(&ready, cursor);
        let mut consumed = Vec::new();
        let mut lost = 0;
        let mut failure = None;
        while let Some(index) = round.next(0, &mut cursor) {
            let id = sessions[index];
            for cpu in fair_indices(3, id) {
                if !ready_cpu[id][cpu] {
                    continue;
                }
                let mut calls = 0;
                let report = drain_reads(
                    || {
                        calls += 1;
                        if id == 0 && calls == 2 {
                            return Err(("fixture read failure", Some(12)));
                        }
                        Ok(PerfRead {
                            samples: if calls == 1 { 2 } else { 0 },
                            records: if calls == 1 {
                                vec![(id, cpu, 1), (id, cpu, 2)]
                            } else {
                                vec![]
                            },
                            lost_samples: if calls == 1 { 7 } else { 0 },
                            notification_monotonic_ns: Some(11),
                        })
                    },
                    |r| r.2,
                );
                consumed.extend(report.records);
                lost += report.lost_samples;
                if report.error.is_some() {
                    failure = report.error;
                }
            }
        }
        assert!(!round.finish(&mut sessions, &mut cursor));
        assert_eq!(consumed, vec![(1, 1, 1), (1, 1, 2), (0, 2, 1), (0, 2, 2)]);
        assert_eq!(lost, 14);
        assert_eq!(failure, Some("fixture read failure"));
    }

    #[test]
    fn early_scope_return_does_not_require_a_completed_round_to_advance_cursor() {
        let mut cursor = 0;
        let mut round = Round::new(&[true; 3], cursor);
        assert_eq!(round.next(0, &mut cursor), Some(0));
        // The live scope/read failure path returns before finish/rotation.
        assert_eq!(cursor, 1);
        let mut resumed = Round::new(&[true; 3], cursor);
        assert_eq!(resumed.next(0, &mut cursor), Some(1));
    }
}
