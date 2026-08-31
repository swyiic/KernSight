//! Online CPU id lists for per-CPU perf buffers.

/// Parse a Linux `cpu/online` list (`0-7`, `0-3,6-7`, `0,2,4`).
pub(crate) fn parse_cpu_list(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.trim().parse::<u32>() else {
                continue;
            };
            let Ok(end) = end.trim().parse::<u32>() else {
                continue;
            };
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            for cpu in start..=end.min(start.saturating_add(127)) {
                out.push(cpu);
                if out.len() >= 128 {
                    break;
                }
            }
        } else if let Ok(cpu) = part.parse::<u32>() {
            out.push(cpu);
        }
        if out.len() >= 128 {
            break;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// CPU ids that must have a perf buffer, otherwise uprobe hits on those
/// CPUs never surface.
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
pub(crate) fn online_cpu_ids() -> Vec<u32> {
    if let Ok(text) = std::fs::read_to_string("/sys/devices/system/cpu/online") {
        let ids = parse_cpu_list(&text);
        if !ids.is_empty() {
            return ids;
        }
    }
    let n = std::thread::available_parallelism()
        .map_or(8, |value| u32::try_from(value.get()).unwrap_or(8))
        .clamp(1, 128);
    (0..n).collect()
}

#[cfg(test)]
mod tests {
    use super::parse_cpu_list;

    #[test]
    fn parses_contiguous_and_sparse_cpu_lists() {
        assert_eq!(parse_cpu_list("0-7\n"), (0..=7).collect::<Vec<_>>());
        assert_eq!(parse_cpu_list("0-3,6-7"), vec![0, 1, 2, 3, 6, 7]);
        assert_eq!(parse_cpu_list("0,2,4"), vec![0, 2, 4]);
        assert!(parse_cpu_list("").is_empty());
    }
}
