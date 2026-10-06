//! Explicit, bounded Inspect phases. L0 sensors and the spool keep running.
use crate::inspect_runtime::InspectAdapterKind;

/// One validated foreground phase and its bounded planned window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectStage {
    /// Phase name: `l0`, `l1`, or `linker`.
    pub name: String,
    /// Planned window in seconds, in the inclusive range 1 to 300.
    pub seconds: u64,
}
impl InspectStage {
    /// Inspect capabilities selected for this validated phase.
    ///
    /// # Panics
    /// Panics if the phase name did not come from [`parse_stages`].
    pub fn adapters(&self) -> Vec<InspectAdapterKind> {
        match self.name.as_str() {
            "l0" => Vec::new(),
            "l1" => vec![
                InspectAdapterKind::TlsSslWrite,
                InspectAdapterKind::JniPlaintext,
                InspectAdapterKind::BinderUserspace,
            ],
            "linker" => vec![InspectAdapterKind::LinkerSoLoad],
            _ => unreachable!("validated stage"),
        }
    }
}

/// Parse one to three unique phases with at least one Inspect phase.
///
/// # Errors
/// Returns an error for malformed, duplicate, unknown, or unbounded phases.
pub fn parse_stages(text: &str) -> Result<Vec<InspectStage>, String> {
    let mut stages = Vec::new();
    for item in text.split(',') {
        let (name, seconds) = item
            .split_once(':')
            .ok_or("stages must use l0:SECONDS,l1:SECONDS,linker:SECONDS")?;
        if !matches!(name, "l0" | "l1" | "linker") {
            return Err(format!("unsupported stage {name}"));
        }
        if stages.iter().any(|s: &InspectStage| s.name == name) {
            return Err(format!("duplicate stage {name}"));
        }
        let seconds: u64 = seconds.parse().map_err(|_| "invalid stage duration")?;
        if !(1..=300).contains(&seconds) {
            return Err("each stage must be 1..300 seconds".into());
        }
        stages.push(InspectStage {
            name: name.into(),
            seconds,
        });
    }
    if stages.is_empty() || stages.len() > 3 || stages.iter().all(|s| s.name == "l0") {
        return Err(
            "stages must select at least one Inspect capability, at most three unique phases"
                .into(),
        );
    }
    Ok(stages)
}

/// Absolute planned windows never silently skip an overdue phase or extend time.
#[derive(Debug)]
pub struct StageCursor {
    /// Index of the active phase in the validated plan.
    pub index: usize,
    /// Whether the final planned window has completed.
    pub finished: bool,
    ends: Vec<u64>,
}
impl StageCursor {
    /// Create a cursor from a plan returned by [`parse_stages`].
    pub fn new(stages: &[InspectStage]) -> Self {
        let mut total = 0;
        Self {
            index: 0,
            finished: false,
            ends: stages
                .iter()
                .map(|s| {
                    total += s.seconds;
                    total
                })
                .collect(),
        }
    }
    /// Whether the active phase reached its absolute end time.
    ///
    /// # Panics
    /// Panics if the cursor was created from an empty, unvalidated plan.
    pub fn due(&self, elapsed: u64) -> bool {
        !self.finished && elapsed >= self.ends[self.index]
    }
    /// Close the due phase and select its successor without skipping a window.
    ///
    /// # Errors
    /// Returns an error before the active deadline or after the successor deadline.
    pub fn advance(&mut self, elapsed: u64) -> Result<bool, String> {
        if !self.due(elapsed) {
            return Err("stage not finished".into());
        }
        if self.index + 1 == self.ends.len() {
            self.finished = true;
            return Ok(false);
        }
        if elapsed >= self.ends[self.index + 1] {
            return Err("next stage window already elapsed; refusing to skip or restart it".into());
        }
        self.index += 1;
        Ok(true)
    }
}

/// Kernel process birth identity; no inference from a matching PID alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetInstance {
    /// Positive process identifier read from the selected target.
    pub pid: u32,
    /// Nonzero kernel birth ticks from `/proc/<pid>/stat`.
    pub start_ticks: u64,
}
/// Read PID and kernel birth identity from a live process stat record.
/// Returns `None` for a mismatched PID, malformed record, or dead process.
pub fn instance_from_stat(pid: u32, stat: &str) -> Option<TargetInstance> {
    if stat.split_once('(')?.0.trim().parse::<u32>().ok()? != pid {
        return None;
    }
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    if matches!(*fields.first()?, "Z" | "X" | "x") {
        return None;
    }
    let start_ticks = fields.get(19)?.parse().ok()?;
    (start_ticks > 0).then_some(TargetInstance { pid, start_ticks })
}

/// Require the currently observed process to match the pinned instance.
///
/// # Errors
/// Returns an error on exit, PID reuse, or unverified current identity.
pub fn confirm_instance(
    expected: TargetInstance,
    current: Option<TargetInstance>,
) -> Result<(), String> {
    if current == Some(expected) {
        Ok(())
    } else {
        Err(
            "staged target instance exited, changed, or cannot be verified; no automatic restart"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_capabilities_remain_sequential() {
        let s = parse_stages("l0:15,l1:90,linker:15").unwrap();
        assert!(s[0].adapters().is_empty());
        assert_eq!(
            s[1].adapters(),
            vec![
                InspectAdapterKind::TlsSslWrite,
                InspectAdapterKind::JniPlaintext,
                InspectAdapterKind::BinderUserspace
            ]
        );
        assert_eq!(s[2].adapters(), vec![InspectAdapterKind::LinkerSoLoad]);
    }
    #[test]
    fn invalid_or_ambiguous_plan_is_refused() {
        for s in [
            "",
            "l0:1",
            "l1:0",
            "l1:301",
            "l1:-1",
            "l1:1,l1:2",
            "l1:1.5",
            "other:5",
            "l1:1;cmd",
        ] {
            assert!(parse_stages(s).is_err(), "{s}");
        }
    }
    #[test]
    fn transitions_are_bounded_and_no_phase_is_skipped() {
        let s = parse_stages("l0:2,l1:3,linker:4").unwrap();
        let mut c = StageCursor::new(&s);
        assert!(!c.due(1));
        assert!(c.advance(1).is_err());
        assert!(c.advance(2).unwrap());
        assert_eq!(c.index, 1);
        assert!(c.advance(5).unwrap());
        assert_eq!(c.index, 2);
        assert!(!c.advance(9).unwrap());
        assert!(c.finished);
        let mut c = StageCursor::new(&s);
        assert!(c.advance(5).is_err());
        assert_eq!(c.index, 0);
    }
    #[test]
    fn pid_reuse_exit_and_missing_birth_are_not_same_instance() {
        let a = TargetInstance {
            pid: 42,
            start_ticks: 7,
        };
        assert!(confirm_instance(a, Some(a)).is_ok());
        for b in [
            None,
            Some(TargetInstance {
                pid: 42,
                start_ticks: 8,
            }),
            Some(TargetInstance {
                pid: 43,
                start_ticks: 7,
            }),
        ] {
            assert!(confirm_instance(a, b).is_err());
        }
    }
    #[test]
    fn kernel_stat_birth_uses_actual_field_and_rejects_zombie_or_wrong_pid() {
        let mut tail = vec!["0"; 20];
        tail[0] = "S";
        tail[19] = "123456";
        let stat = format!("42 (comm has ) parentheses) {}", tail.join(" "));
        assert_eq!(
            instance_from_stat(42, &stat),
            Some(TargetInstance {
                pid: 42,
                start_ticks: 123_456
            })
        );
        assert!(instance_from_stat(43, &stat).is_none());
        for state in ["Z", "X", "x"] {
            tail[0] = state;
            assert!(instance_from_stat(42, &format!("42 (name) {}", tail.join(" "))).is_none());
        }
        assert!(instance_from_stat(42, "42 (short) S 1").is_none());
        tail[0] = "S";
        tail[19] = "0";
        assert!(instance_from_stat(42, &format!("42 (name) {}", tail.join(" "))).is_none());
    }
}
