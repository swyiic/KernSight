//! Best-effort virtual-memory semantic enrichment.

use std::io::Read as _;

use ksight_model::MemoryRegionChange;

const MAX_PROC_MAPS_BYTES: usize = 8 * 1024 * 1024;

/// Resolve a file-backed mapping descriptor through procfs while the process is alive.
pub fn resolve_backing_path(process_id: u32, change: &mut MemoryRegionChange) {
    if let Some(file_descriptor) = change.file_descriptor {
        let link = format!("/proc/{process_id}/fd/{file_descriptor}");
        change.backing_path = std::fs::read_link(link)
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
    }
    if change.backing_path.is_none() {
        let address = u64::try_from(change.result)
            .ok()
            .filter(|_| change.result >= 0)
            .unwrap_or(change.address);
        change.backing_path = read_maps(process_id).and_then(|maps| mapped_path(&maps, address));
    }
}

fn read_maps(process_id: u32) -> Option<String> {
    let file = std::fs::File::open(format!("/proc/{process_id}/maps")).ok()?;
    let limit = u64::try_from(MAX_PROC_MAPS_BYTES).ok()?.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    if bytes.len() > MAX_PROC_MAPS_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn mapped_path(maps: &str, address: u64) -> Option<String> {
    maps.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        if !(start..end).contains(&address) {
            return None;
        }
        let path = fields.nth(4)?;
        Some(path.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_path_from_covering_maps_range() {
        let maps = "70000000-70001000 r--p 00000000 00:00 0 [anon]\n\
                    71000000-71002000 r-xp 00001000 08:01 42 /system/lib64/libdemo.so\n";
        assert_eq!(
            mapped_path(maps, 0x7100_0100).as_deref(),
            Some("/system/lib64/libdemo.so")
        );
        assert_eq!(mapped_path(maps, 0x7200_0000), None);
    }
}
