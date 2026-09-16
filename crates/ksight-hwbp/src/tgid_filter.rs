//! Filter policy shared by the loader and host-side failure-injection tests.
use anyhow::{bail, Result};

pub(crate) trait FilterMaps {
    fn enable(&mut self, enabled: bool) -> Result<()>;
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
        maps.enable(false)?;
        return Ok(previous.to_vec());
    };
    let mut keys = tgids.to_vec();
    keys.sort_unstable();
    keys.dedup();
    if keys.contains(&0) || keys.len() > 128 {
        bail!("TGID scope requires nonzero IDs and at most 128 distinct entries");
    }
    // Some([]) means deny all, never unrestricted capture.
    maps.enable(true)?;
    for &old in previous {
        maps.remove(old)?;
    }
    for &key in &keys {
        maps.insert(key)?;
    }
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
        fn enable(&mut self, value: bool) -> Result<()> {
            self.record(format!("enable:{value}"))
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
        assert_eq!(maps.calls, ["enable:true", "remove:7"]);
    }
    #[test]
    fn gate_is_enabled_before_allowlist_and_keys_are_deduplicated() {
        let mut maps = Fake::default();
        assert_eq!(configure(&mut maps, &[], Some(&[9, 7, 9])).unwrap(), [7, 9]);
        assert_eq!(maps.calls, ["enable:true", "insert:7", "insert:9"]);
    }
    #[test]
    fn every_map_error_propagates_without_disabling_filter() {
        for fail_at in 1..=3 {
            let mut maps = Fake {
                fail_at: Some(fail_at),
                ..Fake::default()
            };
            assert!(configure(&mut maps, &[7], Some(&[9])).is_err());
            assert_eq!(maps.calls.len(), fail_at);
            assert!(!maps.calls.iter().any(|c| c == "enable:false"));
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
        assert_eq!(maps.calls, ["enable:false"]);
    }
}
