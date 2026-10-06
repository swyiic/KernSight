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

