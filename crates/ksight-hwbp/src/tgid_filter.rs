//! Filter policy shared by the loader and host-side failure-injection tests.
use anyhow::{bail, Result};

pub(crate) trait FilterMaps {
    fn gate(&mut self, mode: u32) -> Result<()>;
    fn remove(&mut self, tgid: u32) -> Result<()>;
    fn insert(&mut self, tgid: u32) -> Result<()>;
}

/// Call before attaching a new probe. Existing probes must detach on error.
pub(crate) fn configure(
    maps: &mut impl FilterMaps,
    previous: &[u32],
    tgids: Option<&[u32]>,
) -> Result<Vec<u32>> {
    let Some(tgids) = tgids else {
        maps.gate(0)?;
        return Ok(previous.to_vec());
    };
    let mut keys = tgids.to_vec();
    keys.sort_unstable();
    keys.dedup();
    if keys.contains(&0) || keys.len() > 128 {
        bail!("TGID scope requires nonzero IDs and at most 128 distinct entries");
    }
    // Gate 2 denies every sample while deleting/inserting map keys.
    // Commit gate 1 only after the complete allowlist is installed.
    // Some([]) means deny all, never unrestricted capture.
    maps.gate(2)?;
    for &old in previous {
        maps.remove(old)?;
    }
    for &key in &keys {
        maps.insert(key)?;
    }
    maps.gate(1)?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        fail_at: Option<usize>,
    }
    impl Fake {
        fn record(&mut self, call: String) -> Result<()> {
            self.calls.push(call);
            if self.fail_at == Some(self.calls.len()) {
                bail!("injected map failure");
            }
            Ok(())
        }
    }
    impl FilterMaps for Fake {
        fn gate(&mut self, value: u32) -> Result<()> {
            self.record(format!("gate:{value}"))
        }
        fn remove(&mut self, key: u32) -> Result<()> {
            self.record(format!("remove:{key}"))
        }
        fn insert(&mut self, key: u32) -> Result<()> {
            self.record(format!("insert:{key}"))
        }
    }
    #[test]
    fn empty_scope_denies_all_and_clears_old_keys() {
        let mut maps = Fake::default();
        assert!(configure(&mut maps, &[7], Some(&[])).unwrap().is_empty());
        assert_eq!(maps.calls, ["gate:2", "remove:7", "gate:1"]);
    }
    #[test]
    fn gate_is_enabled_before_allowlist_and_keys_are_deduplicated() {
        let mut maps = Fake::default();
        assert_eq!(configure(&mut maps, &[], Some(&[9, 7, 9])).unwrap(), [7, 9]);
        assert_eq!(maps.calls, ["gate:2", "insert:7", "insert:9", "gate:1"]);
    }
    #[test]
    fn every_map_error_propagates_without_disabling_filter() {
        for fail_at in 1..=4 {
            let mut maps = Fake {
                fail_at: Some(fail_at),
                ..Fake::default()
            };
            assert!(configure(&mut maps, &[7], Some(&[9])).is_err());
            assert_eq!(maps.calls.len(), fail_at);
            assert!(!maps.calls.iter().any(|c| c == "gate:0"));
        }
    }
    #[test]
    fn invalid_scope_is_not_silently_truncated() {
        for keys in [vec![0], (1..=129).collect()] {
            let mut maps = Fake::default();
            assert!(configure(&mut maps, &[], Some(&keys)).is_err());
            assert!(maps.calls.is_empty());
        }
    }
    #[test]
    fn only_none_explicitly_disables_filter() {
        let mut maps = Fake::default();
        assert_eq!(configure(&mut maps, &[7], None).unwrap(), [7]);
        assert_eq!(maps.calls, ["gate:0"]);
    }
    struct KernelMaps {
        mode: u32,
        keys: std::collections::BTreeSet<u32>,
        step: usize,
        fail_at: Option<usize>,
    }
    impl KernelMaps {
        fn before_write(&mut self) -> Result<()> {
            self.step += 1;
            if self.fail_at == Some(self.step) {
                bail!("injected partial map failure");
            }
            Ok(())
        }
        fn admits(&self, pid: u32) -> bool {
            self.mode == 0 || (self.mode == 1 && self.keys.contains(&pid))
        }
    }
    impl FilterMaps for KernelMaps {
        fn gate(&mut self, mode: u32) -> Result<()> {
            self.before_write()?;
            self.mode = mode;
            Ok(())
        }
        fn remove(&mut self, pid: u32) -> Result<()> {
            assert!(!self.admits(7) && !self.admits(9));
            self.before_write()?;
            self.keys.remove(&pid);
            Ok(())
        }
        fn insert(&mut self, pid: u32) -> Result<()> {
            assert!(!self.admits(7) && !self.admits(9));
            self.before_write()?;
            self.keys.insert(pid);
            Ok(())
        }
    }
    #[test]
    fn every_partial_map_write_keeps_deny_gate_until_complete_commit() {
        for fail_at in 2..=4 {
            let mut maps = KernelMaps {
                mode: 1,
                keys: [7].into(),
                step: 0,
                fail_at: Some(fail_at),
            };
            assert!(configure(&mut maps, &[7], Some(&[9])).is_err());
            assert_eq!(maps.mode, 2);
            assert!(!maps.admits(7) && !maps.admits(9));
            // Production loader detaches on error. For an explicit retry here,
            // clear every actual residual key rather than claiming commit.
            let residual: Vec<_> = maps.keys.iter().copied().collect();
            maps.fail_at = None;
            assert_eq!(configure(&mut maps, &residual, Some(&[9])).unwrap(), [9]);
            assert!(!maps.admits(7) && maps.admits(9));
        }
    }
    #[test]
    fn failed_initial_gate_requires_owner_revoke_and_does_not_claim_denial() {
        let mut maps = KernelMaps {
            mode: 1,
            keys: [7].into(),
            step: 0,
            fail_at: Some(1),
        };
        assert!(configure(&mut maps, &[7], Some(&[9])).is_err());
        // A failed gate write cannot change the kernel. The caller must drop
        // owned links; configure cannot promise instantaneous quiescence.
        assert!(maps.admits(7));
        assert!(!maps.admits(9));
    }
}
