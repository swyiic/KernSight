//! Scheduling of records already consumed from a perf report. A work cutoff
//! leaves ownership in the queue; it does not discard or mint record authority.
#![cfg_attr(
    not(any(test, target_os = "android", target_os = "linux")),
    allow(dead_code)
)]
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub(super) fn slice_end(now: Instant, outer: Option<Instant>) -> Instant {
    let end = now + Duration::from_millis(20);
    outer.map_or(end, |outer| end.min(outer))
}

pub(super) fn take_before<T>(
    queue: &mut VecDeque<T>,
    now: Instant,
    deadline: Instant,
) -> Option<T> {
    (now < deadline).then(|| queue.pop_front()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Consumed {
        time_ns: u64,
        original_epoch: Option<u32>,
        identity: (u32, u64),
        bytes: Vec<u8>,
    }

    #[test]
    fn consumed_prefix_and_return_remain_owned_across_deadline_then_post_stop_drain() {
        let start = Instant::now();
        let outer = start + Duration::from_millis(7);
        let end = slice_end(start, Some(outer));
        assert_eq!(end, outer);
        let mut queue = VecDeque::from([
            Consumed {
                time_ns: 1,
                original_epoch: Some(11),
                identity: (42, 1001),
                bytes: vec![1, 2],
            },
            Consumed {
                time_ns: 2,
                original_epoch: Some(11),
                identity: (42, 1001),
                bytes: vec![3, 4],
            },
        ]);
        let first = take_before(&mut queue, start, end).unwrap();
        assert_eq!(first.time_ns, 1);
        assert!(take_before(&mut queue, end, end).is_none());
        assert_eq!(queue.len(), 1);
        // A later probe epoch cannot re-authorize the consumed return record.
        let new_probe_epoch = 12;
        let drain_start = outer + Duration::from_millis(5);
        let last = take_before(&mut queue, drain_start, slice_end(drain_start, None)).unwrap();
        assert_eq!(last.original_epoch, Some(11));
        assert_ne!(last.original_epoch, Some(new_probe_epoch));
        assert_eq!(last.identity, (42, 1001));
        assert_eq!(last.bytes, [3, 4]);
        assert!(queue.is_empty());
    }

    #[test]
    fn original_outer_boundary_never_renews_but_unleased_passes_get_only_twenty_ms() {
        let now = Instant::now();
        assert_eq!(slice_end(now, None), now + Duration::from_millis(20));
        let outer = now + Duration::from_millis(5);
        assert_eq!(slice_end(now, Some(outer)), outer);
        assert_eq!(slice_end(outer, Some(outer)), outer);
        let mut queue = VecDeque::from([1, 2, 3]);
        assert!(take_before(&mut queue, outer, outer).is_none());
        assert_eq!(queue, VecDeque::from([1, 2, 3]));
    }
}
