use serde::{Deserialize, Serialize};

/// Honest statement of agent and sensor integrity coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Whether the report was produced on Android.
    pub android: bool,
    /// Verified Boot state, when readable.
    pub verified_boot_state: Option<String>,
    /// Whether expected sensor attachments were verified.
    pub sensor_links_verified: bool,
    /// Known record loss at report time.
    pub dropped_records: u64,
    /// Limitations that prevent a stronger trust claim.
    pub limitations: Vec<String>,
}
