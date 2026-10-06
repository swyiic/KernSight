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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
#[must_use]
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

