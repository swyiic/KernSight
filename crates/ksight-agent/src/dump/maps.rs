//! Proc maps enrichment for package dumps.

use std::path::Path;

#[derive(Debug, Clone)]
pub(super) struct MapRange {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

impl MapRange {
    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn readable(&self) -> bool {
        self.perms.contains('r')
    }

    fn executable(&self) -> bool {
        self.perms.contains('x')
    }
}

pub(super) fn load_maps_file(dest: &Path) -> std::collections::BTreeMap<u32, Vec<MapRange>> {
    let runtime = dest.join("runtime");
    let Ok(entries) = std::fs::read_dir(&runtime) else {
        return std::collections::BTreeMap::new();
    };
    let mut maps = std::collections::BTreeMap::<u32, Vec<MapRange>>::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(pid_s) = name
            .strip_prefix("maps-")
            .and_then(|rest| rest.strip_suffix(".txt"))
        else {
            continue;
        };
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        maps.insert(pid, parse_maps_ranges(&text));
    }
    maps
}

pub(super) fn maps_as_observed(
    dest: &Path,
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<ksight_core::ObservedMapping> {
    let mut mappings = Vec::new();
    for (pid, ranges) in load_maps_file(dest) {
        for range in ranges {
            if range.end <= range.start || !mapping_needed(pid, &range, artifacts) {
                continue;
            }
            mappings.push(ksight_core::ObservedMapping {
                process_id: pid,
                start: range.start,
                end: range.end,
                backing_path: nonempty_path(&range.path),
                source: ksight_core::MappingSource::ProcMaps,
                mapping_generation: 0,
            });
        }
    }
    ksight_core::rank_observed_mappings(&mut mappings);
    mappings.truncate(512);
    mappings
}

pub(super) fn mapping_needed(
    pid: u32,
    range: &MapRange,
    artifacts: &[ksight_core::DumpArtifact],
) -> bool {
    artifacts.iter().any(|artifact| {
        if artifact.pid != Some(pid) {
            return false;
        }
        if let (Some(start), Some(end)) = (artifact.vma_start, artifact.vma_end) {
            if ksight_core::ranges_overlap(start, end, range.start, range.end) {
                return true;
            }
        } else if let Some(start) = artifact.vma_start {
            if range.contains(start) {
                return true;
            }
        }
        so_file_name(artifact).is_some_and(|name| so_map_matches(range, &name))
    })
}

pub(super) fn enrich_artifacts_from_maps(dest: &Path, artifacts: &mut [ksight_core::DumpArtifact]) {
    let maps = load_maps_file(dest);
    for artifact in artifacts.iter_mut() {
        if artifact.map_path.as_deref().is_some_and(str::is_empty) {
            artifact.map_path = None;
        }
        let Some(pid) = artifact.pid else {
            continue;
        };
        let Some(ranges) = maps.get(&pid) else {
            continue;
        };
        if artifact.vma_start.is_none() {
            if let Some(name) = so_file_name(artifact) {
                if let Some(range) = so_map(ranges, &name) {
                    artifact.vma_start = Some(range.start);
                    artifact.vma_end = Some(range.end);
                    if artifact.map_path.is_none() {
                        artifact.map_path = nonempty_path(&range.path);
                    }
                }
            }
        }
        let Some(start) = artifact.vma_start else {
            continue;
        };
        let prefer_anon = artifact.source == "heap-blob";
        let Some(range) = covering_map(ranges, start, prefer_anon) else {
            continue;
        };
        if artifact.vma_end.is_none() && range.readable() {
            artifact.vma_end = Some(range.end);
        }
        if artifact.map_path.is_none() {
            artifact.map_path = nonempty_path(&range.path);
        }
    }
}

pub(super) fn covering_map(
    ranges: &[MapRange],
    start: u64,
    prefer_anon: bool,
) -> Option<&MapRange> {
    ranges
        .iter()
        .filter(|range| range.contains(start))
        .max_by_key(|range| {
            (
                range.readable(),
                prefer_anon && map_is_anon(&range.path),
                !range.path.starts_with('/'),
                u64::MAX - range.end.saturating_sub(range.start),
            )
        })
}

pub(super) fn map_is_anon(path: &str) -> bool {
    path.is_empty() || path.starts_with('[') || path.starts_with("anon:")
}

pub(super) fn so_map<'a>(ranges: &'a [MapRange], so_name: &str) -> Option<&'a MapRange> {
    ranges
        .iter()
        .filter(|range| so_map_matches(range, so_name))
        .max_by_key(|range| {
            (
                range.executable(),
                range.readable(),
                range.end.saturating_sub(range.start),
            )
        })
}

pub(super) fn so_map_matches(range: &MapRange, so_name: &str) -> bool {
    Path::new(&range.path)
        .file_name()
        .and_then(|name| name.to_str())
        == Some(so_name)
}

pub(super) fn so_file_name(artifact: &ksight_core::DumpArtifact) -> Option<String> {
    if artifact.source != "runtime-so" {
        return None;
    }
    let name = Path::new(&artifact.relative_path)
        .file_name()
        .and_then(|name| name.to_str())?;
    if let Some(pid) = artifact.pid {
        let prefix = format!("{pid}-");
        if let Some(stripped) = name.strip_prefix(&prefix) {
            return Some(stripped.to_owned());
        }
    }
    Some(name.to_owned())
}

pub(super) fn nonempty_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

pub(super) fn parse_maps_ranges(text: &str) -> Vec<MapRange> {
    let mut ranges = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end_s, 16) else {
            continue;
        };
        let Some(perms) = fields.next() else {
            continue;
        };
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let path = fields.collect::<Vec<_>>().join(" ");
        ranges.push(MapRange {
            start,
            end,
            perms: perms.to_owned(),
            path,
        });
    }
    ranges
}
