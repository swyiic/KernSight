//! Shared production state transitions and transaction failure injection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcStartRead {
    Running(u64),
    Gone,
    Unreadable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessEpoch {
    First(u64),
    Same(u64),
    Reused { previous: u64, current: u64 },
    Exited { previous: u64 },
    Unverified,
}
pub(super) fn observe_process_start(
    cached: Option<u64>,
    read: ProcStartRead,
) -> (Option<u64>, ProcessEpoch) {
    let cached = cached.filter(|n| *n != 0);
    match (cached, read) {
        (None, ProcStartRead::Running(start)) if start != 0 => {
            (Some(start), ProcessEpoch::First(start))
        }
        (Some(previous), ProcStartRead::Running(start)) if start != 0 && previous == start => {
            (Some(start), ProcessEpoch::Same(start))
        }
        (Some(previous), ProcStartRead::Running(start)) if start != 0 => (
            Some(start),
            ProcessEpoch::Reused {
                previous,
                current: start,
            },
        ),
        (Some(previous), ProcStartRead::Gone) => (None, ProcessEpoch::Exited { previous }),
        _ => (None, ProcessEpoch::Unverified),
    }
}

/// Cache commits only after every live hook has updated. Any failure drops all
/// owned hooks, leaving a known-empty hook/cache state for a fresh retry.
pub(super) fn update_allowlist<T, E>(
    current: &mut Vec<u32>,
    hooks: &mut Vec<T>,
    next: &[u32],
    mut apply: impl FnMut(&mut T, &[u32]) -> Result<(), E>,
) -> Result<(), E> {
    for hook in hooks.iter_mut() {
        if let Err(error) = apply(hook, next) {
            hooks.clear();
            current.clear();
            return Err(error);
        }
    }
    *current = next.to_vec();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Hook {
        closed: Arc<AtomicUsize>,
        fail: bool,
    }
    impl Drop for Hook {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn unreadable_zero_and_exit_never_retain_an_old_instance() {
        for read in [
            ProcStartRead::Unreadable,
            ProcStartRead::Running(0),
            ProcStartRead::Gone,
        ] {
            assert_eq!(observe_process_start(Some(100), read).0, None);
        }
        let (cached, epoch) = observe_process_start(Some(100), ProcStartRead::Unreadable);
        assert_eq!(epoch, ProcessEpoch::Unverified);
        assert_eq!(
            observe_process_start(cached, ProcStartRead::Running(100)),
            (Some(100), ProcessEpoch::First(100))
        );
        assert!(matches!(
            observe_process_start(Some(100), ProcStartRead::Running(200)).1,
            ProcessEpoch::Reused { .. }
        ));
    }
    #[test]
    fn partial_hook_failure_drops_every_owned_hook_and_never_commits_next_cache() {
        for failed in 0..3 {
            let closed = Arc::new(AtomicUsize::new(0));
            let mut hooks = (0..3)
                .map(|i| Hook {
                    closed: closed.clone(),
                    fail: i == failed,
                })
                .collect();
            let mut cache = vec![7];
            assert!(
                update_allowlist(&mut cache, &mut hooks, &[9], |h, _| if h.fail {
                    Err("map failure")
                } else {
                    Ok(())
                })
                .is_err()
            );
            assert!(cache.is_empty() && hooks.is_empty());
            assert_eq!(closed.load(Ordering::SeqCst), 3);
            // A fresh retry is not skipped as though the failed update committed.
            hooks.push(Hook {
                closed: closed.clone(),
                fail: false,
            });
            update_allowlist(&mut cache, &mut hooks, &[9], |_, _| Ok::<_, ()>(())).unwrap();
            assert_eq!(cache, [9]);
        }
    }
    #[test]
    fn no_target_commits_only_empty_allowlist() {
        let mut hooks = vec![()];
        let mut cache = vec![7];
        let mut writes = Vec::new();
        update_allowlist(&mut cache, &mut hooks, &[], |(), keys| {
            writes.push(keys.to_vec());
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(writes, [Vec::<u32>::new()]);
        assert!(cache.is_empty());
    }
}
