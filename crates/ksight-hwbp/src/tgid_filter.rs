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
