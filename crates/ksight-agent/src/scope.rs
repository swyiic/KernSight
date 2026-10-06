//! Userspace capture-scope validation for semantics unavailable to eBPF.

use ksight_model::ProcessIdentity;

/// Optional process constraints applied after identity enrichment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureScope {
    /// Required thread-group ID.
    pub target_tgid: Option<u32>,
    /// Required effective Linux UID.
    pub target_uid: Option<u32>,
    /// Required Android package identity.
    pub target_package: Option<String>,
}

impl CaptureScope {
    /// Return whether the enriched identity belongs in this capture.
    #[must_use]
    pub fn matches(&self, identity: &ProcessIdentity) -> bool {
        if self
            .target_tgid
            .is_some_and(|target| identity.tgid != target)
            || self.target_uid.is_some_and(|target| identity.uid != target)
        {
            return false;
        }

        let Some(package) = self.target_package.as_deref() else {
            return true;
        };
        identity.packages.iter().any(|candidate| {
            candidate.package_name == package && candidate.confidence_percent >= 90
        }) || identity
            .command_line
            .as_deref()
            .is_some_and(|command| process_name_matches(command, package))
    }
}

fn process_name_matches(command: &str, package: &str) -> bool {
    command == package
        || command
            .strip_prefix(package)
            .is_some_and(|suffix| suffix.starts_with(':'))
}

