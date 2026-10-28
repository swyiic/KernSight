//! Cooperative deadline for optional synchronous discovery work.
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
thread_local! { static END: Cell<Option<Instant>> = const { Cell::new(None) }; }

pub(crate) struct WorkWindow {
    previous: Option<Instant>,
    pub(crate) end: Instant,
}
impl WorkWindow {
    pub(crate) fn enter(parent: Option<Instant>, slice: Duration) -> Self {
        let mut end = Instant::now() + slice;
        if let Some(parent) = parent {
            end = end.min(parent);
        }
        let previous = END.with(Cell::get);
        if let Some(previous) = previous {
            end = end.min(previous);
        }
        END.with(|slot| slot.set(Some(end)));
        Self { previous, end }
    }
}
impl Drop for WorkWindow {
    fn drop(&mut self) {
        END.with(|slot| slot.set(self.previous));
    }
}
pub(crate) fn expired() -> bool {
    END.with(|slot| slot.get().is_some_and(|end| Instant::now() >= end))
}
pub(crate) fn check() -> std::io::Result<()> {
    if expired() {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "discovery work window expired; result deferred",
        ))
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_work_cannot_extend_original_deadline_and_restores_scope() {
        assert!(!expired());
        {
            let outer = WorkWindow::enter(Some(Instant::now()), Duration::from_secs(10));
            let inner = WorkWindow::enter(None, Duration::from_secs(20));
            assert!(inner.end <= outer.end);
            assert_eq!(check().unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        }
        assert!(!expired());
    }
}
