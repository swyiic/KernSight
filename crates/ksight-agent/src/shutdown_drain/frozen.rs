//! Final reads from stopped queues, with the existing per-source record bound.
use serde::Serialize;

/// A source's actual final read result; none/yield is not an empty proof.
pub enum ReadProgress {
    /// Consumed records; another bounded read may run this round.
    More(u64),
    /// Observed exact queue emptiness after these consumed records.
    Empty(u64),
    /// No available record while the exact queue position remains nonempty.
    Busy,
    /// A bounded poll yielded with possible remaining records.
    Yielded(u64),
}

/// One bounded source action and its payload-free costs.
pub struct ReadStep {
    /// Actual source progress, independent of decoded/output event counts.
    pub progress: ReadProgress,
    /// Wall time in the collector/poll, including its owned decoding.
    pub read_elapsed_us: u64,
    /// Wall time publishing the returned records.
    pub emit_elapsed_us: u64,
}

/// A failed action's actual consumed records and costs, retained before returning the error.
pub struct ReadFailure<E> {
    /// Observed progress only; an error can never establish an empty proof.
    pub step: ReadStep,
    /// Original reader or publication failure.
    pub error: E,
}

/// One source's retained final-read facts.
#[derive(Debug, Default, Serialize)]
pub struct SourceDrain {
    /// Number of source actions, including empty/busy observations.
    pub read_calls: u64,
    /// Actual returned raw records, not committed application events.
    pub raw_records: u64,
    /// Rounds that visited this source.
    pub rounds_read: u64,
    /// Rounds reaching the existing 32-action bound without an empty proof.
    pub round_limit_hits: u64,
    /// `next == None` while exact producer/consumer positions differ.
    pub none_nonempty: u64,
    /// Bounded inspect polls that yielded without an empty proof.
    pub slice_yields: u64,
    /// Most recent actual source observation was empty.
    pub empty_observed: bool,
    /// Empty was observed after all owned producers confirmed stopped.
    pub frozen_empty: bool,
    /// First round that actually observed this queue empty.
    pub first_empty_round: Option<u64>,
    /// Later rounds that skipped this proved-empty stopped queue.
    pub skipped_frozen_rounds: u64,
    /// Reader/output errors; successful earlier reads stay retained.
    pub read_errors: u64,
    /// Collector/poll wall time.
    pub read_elapsed_us: u64,
    /// Publication wall time.
    pub emit_elapsed_us: u64,
    #[serde(skip)]
    blocked_this_round: bool,
    #[serde(skip)]
    calls_this_round: u64,
}

/// Track proofs only; this never creates or renews an allowance.
pub struct FrozenQueues {
    producers_stopped: bool,
    round: u64,
    cursor: usize,
    sources: Vec<SourceDrain>,
}

impl FrozenQueues {
    /// Create one tracker for the capture's fixed, already-owned sources.
    pub fn new(source_count: usize) -> Self {
        Self {
            producers_stopped: false,
            round: 0,
            cursor: 0,
            sources: (0..source_count).map(|_| SourceDrain::default()).collect(),
        }
    }

    /// Confirm closure before freezing; an earlier empty observation is not reused.
    pub fn confirm_producers_stopped(&mut self, stopped: bool) {
        self.producers_stopped = stopped;
    }

    /// Retained payload-free source counters.
    pub fn sources(&self) -> &[SourceDrain] {
        &self.sources
    }

    /// Read one record per source in turn, retaining the old 32-action bound.
    /// Checks the same external allowance before every action. Busy/yielded
    /// sources remain eligible in the next round; proved-empty stopped sources
    /// never repeat expensive metadata/poll work.
    /// # Errors
    /// Returns a source/output failure without discarding earlier progress.
    pub fn read_round<C, E>(
        &mut self,
        context: &mut C,
        mut read: impl FnMut(&mut C, usize) -> Result<ReadStep, ReadFailure<E>>,
        allowed: impl Fn() -> bool,
    ) -> Result<bool, E> {
        const MAX_ACTIONS: u64 = 32;
        self.round = self.round.saturating_add(1);
        for source in &mut self.sources {
            source.blocked_this_round = false;
            source.calls_this_round = 0;
            if source.frozen_empty {
                source.skipped_frozen_rounds = source.skipped_frozen_rounds.saturating_add(1);
            }
        }
        let len = self.sources.len();
        let order: Vec<_> = (0..len).map(|step| (self.cursor + step) % len).collect();
        for _ in 0..MAX_ACTIONS {
            let mut visited = false;
            for &index in &order {
                let source = &mut self.sources[index];
                if source.frozen_empty || source.blocked_this_round {
                    continue;
                }
                if !allowed() {
                    return Ok(false);
                }
                visited = true;
                self.cursor = (index + 1) % len;
                if source.calls_this_round == 0 {
                    source.rounds_read = source.rounds_read.saturating_add(1);
                }
                source.calls_this_round += 1;
                source.read_calls = source.read_calls.saturating_add(1);
                let step = match read(context, index) {
                    Ok(step) => step,
                    Err(failure) => {
                        source.read_elapsed_us = source
                            .read_elapsed_us
                            .saturating_add(failure.step.read_elapsed_us);
                        source.emit_elapsed_us = source
                            .emit_elapsed_us
                            .saturating_add(failure.step.emit_elapsed_us);
                        let records = match failure.step.progress {
                            ReadProgress::More(records)
                            | ReadProgress::Empty(records)
                            | ReadProgress::Yielded(records) => records,
                            ReadProgress::Busy => 0,
                        };
                        source.raw_records = source.raw_records.saturating_add(records);
                        source.read_errors = source.read_errors.saturating_add(1);
                        source.empty_observed = false;
                        source.frozen_empty = false;
                        return Err(failure.error);
                    }
                };
                source.read_elapsed_us =
                    source.read_elapsed_us.saturating_add(step.read_elapsed_us);
                source.emit_elapsed_us =
                    source.emit_elapsed_us.saturating_add(step.emit_elapsed_us);
                let records = match step.progress {
                    ReadProgress::More(records) => {
                        source.empty_observed = false;
                        records
                    }
                    ReadProgress::Empty(records) => {
                        source.empty_observed = true;
                        source.first_empty_round.get_or_insert(self.round);
                        source.frozen_empty = self.producers_stopped;
                        source.blocked_this_round = true;
                        records
                    }
                    ReadProgress::Busy => {
                        source.empty_observed = false;
                        source.none_nonempty = source.none_nonempty.saturating_add(1);
                        source.blocked_this_round = true;
                        0
                    }
                    ReadProgress::Yielded(records) => {
                        source.empty_observed = false;
                        source.slice_yields = source.slice_yields.saturating_add(1);
                        source.blocked_this_round = true;
                        records
                    }
                };
                source.raw_records = source.raw_records.saturating_add(records);
                if source.calls_this_round == MAX_ACTIONS && !source.empty_observed {
                    source.round_limit_hits = source.round_limit_hits.saturating_add(1);
                }
            }
            if !visited {
                break;
            }
        }
        Ok(self.sources.iter().all(|source| source.empty_observed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;

    fn step(progress: ReadProgress) -> ReadStep {
        ReadStep {
            progress,
            read_elapsed_us: 0,
            emit_elapsed_us: 0,
        }
    }

    #[test]
    fn stopped_empty_source_is_polled_once_while_slow_tail_finishes_on_original_allowance() {
        let now = Cell::new(0_u64);
        let deadline = 250;
        let mut tail = (0..150).collect::<VecDeque<_>>();
        let mut ledger = FrozenQueues::new(2);
        ledger.confirm_producers_stopped(true);
        let mut retained = vec![];
        let mut empty_polls = 0;
        let mut rounds = 0;
        while now.get() < deadline {
            rounds += 1;
            if ledger
                .read_round(
                    &mut (),
                    |(), index| {
                        if index == 0 {
                            empty_polls += 1;
                            now.set(now.get() + 40); // Expensive empty scope/poll.
                            Ok::<_, ReadFailure<()>>(step(ReadProgress::Empty(0)))
                        } else {
                            now.set(now.get() + 1); // Slow consumer publication.
                            if let Some(value) = tail.pop_front() {
                                retained.push(value);
                                Ok(step(ReadProgress::More(1)))
                            } else {
                                Ok(step(ReadProgress::Empty(0)))
                            }
                        }
                    },
                    || now.get() < deadline,
                )
                .unwrap()
            {
                break;
            }
        }
        assert_eq!(retained, (0..150).collect::<Vec<_>>());
        assert!(tail.is_empty());
        assert_eq!(empty_polls, 1);
        assert_eq!(rounds, 5);
        assert!(now.get() < deadline);
        assert!(ledger.sources().iter().all(|s| s.frozen_empty));
        assert_eq!(ledger.sources()[0].skipped_frozen_rounds, 4);
        // Re-polling the frozen source every round would cost 5*40+151 >250.
        assert!(5 * 40 + 151 > deadline);
    }

    #[test]
    fn busy_queue_is_not_frozen_and_cannot_starve_later_ready_queue() {
        let now = Cell::new(0_u64);
        let mut retained = vec![];
        let mut ready = VecDeque::from([10, 11]);
        let mut ledger = FrozenQueues::new(2);
        ledger.confirm_producers_stopped(true);
        let empty = ledger
            .read_round(
                &mut (),
                |(), index| {
                    now.set(now.get() + 1);
                    if index == 0 {
                        Ok::<_, ReadFailure<()>>(step(ReadProgress::Busy))
                    } else if let Some(value) = ready.pop_front() {
                        retained.push(value);
                        Ok(step(ReadProgress::More(1)))
                    } else {
                        Ok(step(ReadProgress::Empty(0)))
                    }
                },
                || now.get() < 10,
            )
            .unwrap();
        assert!(!empty);
        assert_eq!(retained, [10, 11]);
        assert_eq!(ledger.sources()[0].none_nonempty, 1);
        assert!(!ledger.sources()[0].frozen_empty);
        assert!(ledger.sources()[1].frozen_empty);
        assert!(ledger
            .read_round(
                &mut (),
                |(), index| {
                    assert_eq!(index, 0); // Previously proved-empty queue is skipped.
                    Ok::<_, ReadFailure<()>>(step(ReadProgress::Empty(0)))
                },
                || now.get() < 10
            )
            .unwrap());
    }

    #[test]
    fn slow_first_source_does_not_take_32_records_before_later_source() {
        let now = Cell::new(0_u64);
        let mut visited = vec![];
        let mut ledger = FrozenQueues::new(2);
        ledger.confirm_producers_stopped(true);
        assert!(!ledger
            .read_round(
                &mut (),
                |(), index| {
                    visited.push(index);
                    now.set(now.get() + 2);
                    Ok::<_, ReadFailure<()>>(step(ReadProgress::More(1)))
                },
                || now.get() < 4
            )
            .unwrap());
        assert_eq!(visited, [0, 1]);
        assert_eq!(now.get(), 4);
        assert!(!ledger
            .read_round(
                &mut (),
                |(), _| panic!("no renewed allowance"),
                || now.get() < 4
            )
            .unwrap_or_else(|error: ()| panic!("{error:?}")));
    }

    #[test]
    fn unconfirmed_stop_never_freezes_an_empty_then_refilled_queue() {
        let mut ledger = FrozenQueues::new(1);
        ledger.confirm_producers_stopped(false);
        assert!(ledger
            .read_round(
                &mut (),
                |(), _| Ok::<_, ReadFailure<()>>(step(ReadProgress::Empty(0))),
                || true
            )
            .unwrap());
        assert!(!ledger.sources()[0].frozen_empty);
        let mut calls = 0;
        assert!(ledger
            .read_round(
                &mut (),
                |(), _| {
                    calls += 1;
                    Ok::<_, ReadFailure<()>>(step(if calls == 1 {
                        ReadProgress::More(1)
                    } else {
                        ReadProgress::Empty(0)
                    }))
                },
                || true
            )
            .unwrap());
        assert_eq!(ledger.sources()[0].raw_records, 1);
        assert_eq!(ledger.sources()[0].read_calls, 3);
        assert!(!ledger.sources()[0].frozen_empty);
    }

    #[test]
    fn bounded_source_yields_and_read_errors_retain_earlier_records_and_loss() {
        let mut ledger = FrozenQueues::new(1);
        ledger.confirm_producers_stopped(true);
        assert!(!ledger
            .read_round(
                &mut (),
                |(), _| Ok::<_, ReadFailure<()>>(step(ReadProgress::More(1))),
                || true
            )
            .unwrap());
        assert_eq!(ledger.sources()[0].raw_records, 32);
        assert_eq!(ledger.sources()[0].round_limit_hits, 1);
        let loss = 188_896;
        let mut calls = 0;
        let result = ledger.read_round(
            &mut (),
            |(), _| {
                calls += 1;
                if calls == 1 {
                    Ok(step(ReadProgress::More(1)))
                } else {
                    Err(ReadFailure {
                        step: step(ReadProgress::More(0)),
                        error: "reader failure",
                    })
                }
            },
            || true,
        );
        assert_eq!(result, Err("reader failure"));
        assert_eq!(ledger.sources()[0].raw_records, 33);
        assert_eq!(ledger.sources()[0].read_errors, 1);
        assert!(!ledger.sources()[0].frozen_empty);
        assert_eq!(loss, 188_896);
    }
    #[test]
    fn publication_error_retains_this_actions_consumed_batch_and_costs_without_freezing() {
        let mut ledger = FrozenQueues::new(1);
        ledger.confirm_producers_stopped(true);
        let mut raw = VecDeque::from([1, 2, 3]);
        let mut committed_prefix = vec![0];
        let result = ledger.read_round(
            &mut (),
            |(), _| {
                let consumed = raw.len() as u64;
                // First output from this read publishes before a later output fails.
                committed_prefix.push(raw.pop_front().expect("first output"));
                raw.clear();
                Err(ReadFailure {
                    step: ReadStep {
                        progress: ReadProgress::More(consumed),
                        read_elapsed_us: 17,
                        emit_elapsed_us: 23,
                    },
                    error: "publication failure",
                })
            },
            || true,
        );
        assert_eq!(result, Err("publication failure"));
        assert!(raw.is_empty()); // The payload read already happened, even though publication failed.
        assert_eq!(committed_prefix, [0, 1]); // Previously published prefix stays owned by the consumer.
        let s = &ledger.sources()[0];
        assert_eq!(s.raw_records, 3);
        assert_eq!(s.read_calls, 1);
        assert_eq!(s.read_elapsed_us, 17);
        assert_eq!(s.emit_elapsed_us, 23);
        assert_eq!(s.read_errors, 1);
        assert!(!s.empty_observed);
        assert!(!s.frozen_empty);
    }
}
