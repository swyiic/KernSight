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

#[cfg(test)]
mod tests {
    use ksight_model::{PackageCandidate, ProcessKey};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn package_scope_rejects_ambiguous_shared_uid() {
        let scope = CaptureScope {
            target_uid: Some(10_123),
            target_package: Some("com.example.alpha".to_owned()),
            ..CaptureScope::default()
        };
        let mut identity = identity();
        identity.packages.push(PackageCandidate {
            package_name: "com.example.alpha".to_owned(),
            source: "packages.list:uid".to_owned(),
            confidence_percent: 65,
        });
        assert!(!scope.matches(&identity));

        identity.command_line = Some("com.example.alpha:worker".to_owned());
        assert!(scope.matches(&identity));
    }

    #[test]
    fn pid_and_uid_scope_are_intersected() {
        let scope = CaptureScope {
            target_tgid: Some(42),
            target_uid: Some(10_123),
            target_package: None,
        };
        let mut identity = identity();
        assert!(scope.matches(&identity));
        identity.tgid = 43;
        assert!(!scope.matches(&identity));
    }

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            key: ProcessKey {
                boot_id: Uuid::nil(),
                pid: 42,
                start_time_ns: 1,
            },
            tid: 42,
            tgid: 42,
            uid: 10_123,
            gid: 10_123,
            comm: "example".to_owned(),
            command_line: None,
            selinux_context: None,
            packages: Vec::new(),
        }
    }
}
