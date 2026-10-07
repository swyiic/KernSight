//! Revalidate only the already enrolled physical source. Errors never authorize
//! another PID and never imply task exit without independent exit evidence.
use crate::qualified_code::SourceIdentity;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize, thiserror::Error)]
#[error(
    "qualified capture {kind}: pid={pid} birth_ns={birth} exec_id={exec}; target exit unconfirmed; no numeric replacement: {cause}",
    pid = .expected.pid, birth = .expected.birth_ns, exec = .expected.exec_id
)]
pub(crate) struct Failure {
    kind: &'static str,
    expected: SourceIdentity,
    observed: Option<SourceIdentity>,
    cause: String,
    errno: Option<i32>,
    target_exit_confirmed: Option<bool>,
}

impl Failure {
    fn from_error(kind: &'static str, expected: &SourceIdentity, error: &anyhow::Error) -> Self {
        Self {
            kind,
            expected: expected.clone(),
            observed: None,
            cause: format!("{error:#}"),
            errno: error.chain().find_map(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    .or_else(|| {
                        cause
                            .downcast_ref::<rustix::io::Errno>()
                            .map(|errno| errno.raw_os_error())
                    })
            }),
            // A qualification failure is not a retained-pidfd exit observation.
            target_exit_confirmed: None,
        }
    }
}

/// Keep the decision boundary shared by production and host counterexamples.
/// Neither a failed observation nor a changed identity may reach `install`.
pub(crate) fn refresh<T>(
    expected: &SourceIdentity,
    qualify: impl FnOnce() -> Result<(SourceIdentity, T)>,
    install: impl FnOnce(T) -> Result<()>,
) -> std::result::Result<(), Box<Failure>> {
    let (observed, target) = qualify().map_err(|error| {
        Box::new(Failure::from_error(
            "requalification_failed",
            expected,
            &error,
        ))
    })?;
    if observed != *expected {
        return Err(Box::new(Failure {
            kind: "identity_changed",
            expected: expected.clone(),
            cause: format!(
                "physical identity changed; expected={}; observed={}",
                serde_json::json!(expected),
                serde_json::json!(observed),
            ),
            observed: Some(observed),
            errno: None,
            target_exit_confirmed: None,
        }));
    }
    install(target).map_err(|error| {
        let mut failure = Failure::from_error("sampler_refresh_failed", expected, &error);
        failure.observed = Some(observed);
        Box::new(failure)
    })
}

#[cfg(test)]
mod tests {
    use super::refresh;
    use crate::qualified_code::SourceIdentity;
    use anyhow::Context as _;
    use std::cell::Cell;

    fn source() -> SourceIdentity {
        SourceIdentity {
            package: "com.example.app".into(),
            pid: 5249,
            uid: 10_123,
            birth_ns: 526_537_675_433_199,
            exec_id: 4,
            boot_id: "test-boot".into(),
        }
    }

    #[test]
    fn qualification_failure_preserves_context_errno_and_never_installs() {
        let installs = Cell::new(0);
        let error = refresh::<()>(
            &source(),
            || Err(std::io::Error::from_raw_os_error(13)).context("metadata iterator denied"),
            |()| {
                installs.set(installs.get() + 1);
                Ok(())
            },
        )
        .expect_err("failed observation must fail closed");
        assert_eq!(installs.get(), 0);
        assert_eq!(error.kind, "requalification_failed");
        assert_eq!(error.errno, Some(13));
        assert!(error.cause.contains("metadata iterator denied"));
        assert!(error.cause.contains("Permission denied"));
        assert!(!error.to_string().contains("task exited"));
        let note = serde_json::to_value(&error).expect("diagnostic");
        assert!(note["target_exit_confirmed"].is_null());
        assert!(note["observed"].is_null());
    }

    #[test]
    fn rustix_pidfd_errno_is_preserved_without_an_exit_claim() {
        let error = refresh::<()>(
            &source(),
            || Err(rustix::io::Errno::PERM).context("open qualification pidfd"),
            |()| panic!("install"),
        )
        .expect_err("pidfd failure");
        assert_eq!(error.errno, Some(1));
        assert!(error.cause.contains("open qualification pidfd"));
        assert!(error.target_exit_confirmed.is_none());
    }

    #[test]
    fn empty_timeout_and_policy_errors_do_not_become_exit_claims() {
        for cause in [
            "live metadata observation empty",
            "qualification deadline exceeded",
            "not-supported: shared/ambiguous/missing package UID enrollment",
            "task exited during qualification",
        ] {
            let error = refresh::<()>(
                &source(),
                || anyhow::bail!("{cause}"),
                |()| panic!("install"),
            )
            .expect_err("observation error");
            assert_eq!(error.cause, cause);
            assert!(error.target_exit_confirmed.is_none());
            assert!(error.observed.is_none());
            assert!(error.to_string().contains("target exit unconfirmed"));
        }
    }

    #[test]
    fn every_identity_component_blocks_install_and_records_both_sources() {
        let expected = source();
        let mut variants = Vec::new();
        let mut changed = expected.clone();
        changed.package.push_str(".other");
        variants.push(changed);
        let mut changed = expected.clone();
        changed.pid += 1;
        variants.push(changed);
        let mut changed = expected.clone();
        changed.uid += 1;
        variants.push(changed);
        let mut changed = expected.clone();
        changed.birth_ns += 1;
        variants.push(changed);
        let mut changed = expected.clone();
        changed.exec_id += 1;
        variants.push(changed);
        let mut changed = expected.clone();
        changed.boot_id.push_str("-other");
        variants.push(changed);
        for changed in variants {
            let error = refresh(
                &expected,
                || Ok((changed.clone(), ())),
                |()| panic!("replacement installed"),
            )
            .expect_err("changed physical source");
            assert_eq!(error.kind, "identity_changed");
            assert_eq!(error.expected, expected);
            assert_eq!(error.observed, Some(changed));
            assert!(error.target_exit_confirmed.is_none());
            assert!(error.to_string().contains("no numeric replacement"));
        }
    }

    #[test]
    fn unchanged_source_is_the_only_install_path_and_runs_once() {
        let qualifies = Cell::new(0);
        let installs = Cell::new(0);
        refresh(
            &source(),
            || {
                qualifies.set(qualifies.get() + 1);
                Ok((source(), 17))
            },
            |target| {
                assert_eq!(target, 17);
                installs.set(installs.get() + 1);
                Ok(())
            },
        )
        .expect("same physical source");
        assert_eq!(qualifies.get(), 1);
        assert_eq!(installs.get(), 1);
    }

    #[test]
    fn sampler_failure_is_distinct_and_never_retries_installation() {
        let installs = Cell::new(0);
        let error = refresh(
            &source(),
            || Ok((source(), ())),
            |()| {
                installs.set(installs.get() + 1);
                anyhow::bail!("metadata lease expired before sampler binding")
            },
        )
        .expect_err("sampler admission");
        assert_eq!(installs.get(), 1);
        assert_eq!(error.kind, "sampler_refresh_failed");
        assert_eq!(error.observed, Some(source()));
        assert!(error.cause.contains("lease expired"));
        assert!(error.target_exit_confirmed.is_none());
    }
}
