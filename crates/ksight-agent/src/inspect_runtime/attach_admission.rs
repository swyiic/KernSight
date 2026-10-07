//! Scheduling guard only: it cannot qualify a task or weaken the sampler gate.
//! Enforce ART grace at the common per-plan dispatch, including TLS rescans.
use super::{InspectAdapterKind, PACKER_ATTACH_GRACE};
use ksight_hwbp::instance_scope::BoundInstance;
use std::time::Duration;

pub(super) fn allowed(
    adapter: InspectAdapterKind,
    whole_device: bool,
    qualified: Option<&[BoundInstance]>,
    legacy_ready: impl FnOnce() -> bool,
    mut age: impl FnMut(u32) -> Option<Duration>,
) -> bool {
    if !adapter.is_jni() || whole_device {
        return true;
    }
    match qualified {
        Some(targets) => {
            // An older unselected same-package task must not vouch for a young
            // qualified source. Empty/missing observations never waive grace.
            !targets.is_empty()
                && targets.iter().all(|target| {
                    age(target.identity.tgid).is_some_and(|value| value >= PACKER_ATTACH_GRACE)
                })
        }
        None => legacy_ready(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksight_hwbp::instance_scope::InstanceIdentity;
    use std::{cell::RefCell, fs::File};

    fn target(pid: u32) -> BoundInstance {
        // Scheduling-only fixture, not a physical qualification or payload grant.
        BoundInstance::trusted_candidate(
            InstanceIdentity {
                tgid: pid,
                uid: 10_001,
                birth_ns: 123,
                exec_id: 4,
            },
            File::open("/dev/null").expect("owned fixture").into(),
        )
    }

    #[test]
    fn tls_binder_and_linker_do_not_wait_for_jni_grace() {
        let targets = [target(7)];
        for adapter in [
            InspectAdapterKind::TlsSslRead,
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::BinderUserspace,
            InspectAdapterKind::LinkerSoLoad,
        ] {
            assert!(allowed(
                adapter,
                false,
                Some(&targets),
                || panic!("legacy policy"),
                |_| panic!("age read")
            ));
        }
    }

    #[test]
    fn every_jni_variant_waits_even_after_tls_attaches_or_rescans() {
        let targets = [target(7)];
        let jni = [
            InspectAdapterKind::JniRegistration,
            InspectAdapterKind::JniPlaintext,
            InspectAdapterKind::JniNewStringUtf,
            InspectAdapterKind::JniGetStringUtfChars,
            InspectAdapterKind::JniGetStringUtfLength,
            InspectAdapterKind::JniGetStringUtfRegion,
            InspectAdapterKind::JniGetArrayLength,
            InspectAdapterKind::JniGetByteArrayElements,
            InspectAdapterKind::JniGetByteArrayRegion,
            InspectAdapterKind::JniSetByteArrayRegion,
            InspectAdapterKind::JniNewString,
            InspectAdapterKind::JniGetStringLength,
            InspectAdapterKind::JniGetStringChars,
            InspectAdapterKind::JniGetStringRegion,
            InspectAdapterKind::JniGetStringCritical,
            InspectAdapterKind::JniGetCharArrayElements,
            InspectAdapterKind::JniGetCharArrayRegion,
            InspectAdapterKind::JniSetCharArrayRegion,
            InspectAdapterKind::JniGetPrimitiveArrayCritical,
            InspectAdapterKind::JniGetDirectBufferAddress,
            InspectAdapterKind::JniGetDirectBufferCapacity,
        ];
        for adapter in jni {
            assert!(adapter.is_jni());
            // Successful TLS scheduling never changes the result of the next plan.
            assert!(allowed(
                InspectAdapterKind::TlsSslRead,
                false,
                Some(&targets),
                || false,
                |_| None
            ));
            assert!(
                !allowed(
                    adapter,
                    false,
                    Some(&targets),
                    || true,
                    |_| Some(Duration::from_millis(3500))
                ),
                "{adapter:?}"
            );
        }
    }

    #[test]
    fn exact_boundary_is_six_seconds_and_missing_age_fails_closed() {
        let targets = [target(7)];
        for (age, expected) in [
            (None, false),
            (Some(Duration::ZERO), false),
            (Some(Duration::from_millis(5999)), false),
            (Some(Duration::from_secs(6)), true),
        ] {
            assert_eq!(
                allowed(
                    InspectAdapterKind::JniRegistration,
                    false,
                    Some(&targets),
                    || panic!("fallback"),
                    |_| age
                ),
                expected
            );
        }
    }

    #[test]
    fn only_qualified_sources_can_satisfy_grace_and_all_must_be_old_enough() {
        let targets = [target(7), target(8)];
        let seen = RefCell::new(Vec::new());
        let permitted = allowed(
            InspectAdapterKind::JniNewStringUtf,
            false,
            Some(&targets),
            || panic!("old unselected package task cannot vouch"),
            |pid| {
                seen.borrow_mut().push(pid);
                Some(Duration::from_secs(if pid == 7 { 60 } else { 3 }))
            },
        );
        assert!(!permitted);
        assert_eq!(*seen.borrow(), [7, 8]);
        assert!(allowed(
            InspectAdapterKind::JniNewStringUtf,
            false,
            Some(&targets),
            || false,
            |_| Some(Duration::from_secs(6))
        ));
    }

    #[test]
    fn empty_qualified_scope_never_falls_back_to_numeric_policy() {
        assert!(!allowed(
            InspectAdapterKind::JniRegistration,
            false,
            Some(&[]),
            || panic!("numeric fallback"),
            |_| panic!("no selected PID")
        ));
    }

    #[test]
    fn whole_device_and_legacy_policy_semantics_are_explicit() {
        assert!(allowed(
            InspectAdapterKind::JniRegistration,
            true,
            None,
            || panic!("legacy"),
            |_| None
        ));
        for ready in [false, true] {
            assert_eq!(
                allowed(
                    InspectAdapterKind::JniRegistration,
                    false,
                    None,
                    || ready,
                    |_| panic!("qualified age")
                ),
                ready
            );
        }
    }
}
