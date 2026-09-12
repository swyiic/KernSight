//! ART open → dump-artifact joins.

use super::CodeLoaderEntry;

pub(super) fn join_art_opens(
    loaders: &mut [CodeLoaderEntry],
    artifacts: &[ksight_core::DumpArtifact],
) {
    for loader in loaders
        .iter_mut()
        .filter(|loader| loader.origin == "art_open")
    {
        let Some(artifact) = match_art_open_artifact(loader, artifacts) else {
            continue;
        };
        loader.joined_relative_path = Some(artifact.relative_path.clone());
        loader.joined_sha256.clone_from(&artifact.sha256);
    }
}

pub(super) fn art_open_joins(
    loaders: &[CodeLoaderEntry],
    artifacts: &[ksight_core::DumpArtifact],
) -> Vec<(u32, String, String)> {
    let mut joins = Vec::new();
    for loader in loaders.iter().filter(|loader| loader.origin == "art_open") {
        for artifact in artifacts
            .iter()
            .filter(|artifact| art_open_matches(loader, artifact))
        {
            joins.push((
                loader.pid,
                loader.path.clone(),
                artifact_graph_key(artifact),
            ));
        }
    }
    joins
}

pub(super) fn artifact_graph_key(artifact: &ksight_core::DumpArtifact) -> String {
    artifact.sha256.as_ref().map_or_else(
        || format!("artifact:{}", artifact.relative_path),
        |sha256| format!("artifact:sha256:{sha256}"),
    )
}

pub(super) fn match_art_open_artifact<'a>(
    loader: &CodeLoaderEntry,
    artifacts: &'a [ksight_core::DumpArtifact],
) -> Option<&'a ksight_core::DumpArtifact> {
    artifacts
        .iter()
        .filter(|artifact| art_open_matches(loader, artifact))
        .max_by_key(|artifact| artifact.bytes)
}

pub(super) fn art_open_matches(
    loader: &CodeLoaderEntry,
    artifact: &ksight_core::DumpArtifact,
) -> bool {
    if artifact.kind != "dex" {
        return false;
    }
    if let Some((base, size)) = parse_memory_open(&loader.path) {
        if let (Some(start), Some(end)) = (artifact.vma_start, artifact.vma_end) {
            if base >= start && base < end {
                return true;
            }
        }
        let opened = loader.opened_bytes.unwrap_or(size);
        return artifact.bytes.abs_diff(opened) <= 4096;
    }
    let open = loader.path.trim();
    if open.is_empty() {
        return false;
    }
    if artifact.map_path.as_deref() == Some(open) {
        return true;
    }
    if artifact
        .map_path
        .as_deref()
        .is_some_and(|path| path.ends_with(open) || open.ends_with(path))
    {
        return true;
    }
    let open_name = std::path::Path::new(open)
        .file_name()
        .and_then(|name| name.to_str());
    let artifact_name = std::path::Path::new(&artifact.relative_path)
        .file_name()
        .and_then(|name| name.to_str());
    if open_name.is_some() && open_name == artifact_name {
        return true;
    }
    let open_ext = std::path::Path::new(open).extension();
    if open_ext
        .is_some_and(|ext| ext.eq_ignore_ascii_case("apk") || ext.eq_ignore_ascii_case("jar"))
        && artifact.source == "apk-dex"
    {
        let lower = open.to_ascii_lowercase();
        return lower.contains("/data/app")
            || lower.contains("/priv-app/")
            || lower.contains("split_config")
            || open_name == Some("base.apk");
    }
    false
}

pub(super) fn parse_memory_open(path: &str) -> Option<(u64, u64)> {
    let rest = path.strip_prefix("memory:")?;
    let (base, size) = rest.split_once('+')?;
    let base = u64::from_str_radix(base.trim_start_matches("0x"), 16).ok()?;
    let size = size.parse().ok()?;
    Some((base, size))
}
