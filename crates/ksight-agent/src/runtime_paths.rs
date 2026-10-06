//! Explicit process-local runtime root. Legacy CLI retains its original paths.
use anyhow::{bail, Result};
use std::{
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};
/// DEFAULT ROOT retained by this evidence operation.
pub const DEFAULT_ROOT: &str = "/data/local/tmp/ksight";
static ROOT: OnceLock<PathBuf> = OnceLock::new();
/// Root retained by this evidence operation.
pub fn root() -> PathBuf {
    ROOT.get().cloned().unwrap_or_else(|| DEFAULT_ROOT.into())
}
/// Isolated retained by this evidence operation.
pub fn isolated() -> bool {
    ROOT.get().is_some()
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Validate shape retained by this evidence operation.
pub fn validate_shape(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("runtime path is not UTF8"))?;
    if !path.is_absolute()
        || text.ends_with('/')
        || text.contains("//")
        || text
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"/._-".contains(&b))
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || text.split('/').any(|s| s == "." || s == "..")
    {
        bail!("invalid runtime path");
    }
    Ok(())
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// No symlinks retained by this evidence operation.
pub fn no_symlinks(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        match std::fs::symlink_metadata(&prefix) {
            Ok(m) if m.file_type().is_symlink() => {
                bail!("runtime path symlink refused: {}", prefix.display())
            }
            Ok(m) if prefix != path && !m.is_dir() => bail!("runtime ancestor is not directory"),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Configure retained by this evidence operation.
pub fn configure(path: &Path) -> Result<()> {
    validate_shape(path)?;
    if !path.starts_with("/data/local/tmp")
        || path == Path::new("/data/local/tmp")
        || path.starts_with(DEFAULT_ROOT)
    {
        bail!("isolated root must be a distinct directory under /data/local/tmp");
    }
    no_symlinks(path)?;
    let executable = std::env::current_exe()?;
    if !executable.starts_with(path) {
        bail!("isolated executable must reside inside runtime root");
    }
    no_symlinks(&executable)?;
    ROOT.set(path.into())
        .map_err(|_| anyhow::anyhow!("runtime root already configured"))
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Route at retained by this evidence operation.
pub fn route_at(path: &Path, root: &Path) -> Result<PathBuf> {
    validate_shape(path)?;
    let mapped = path
        .strip_prefix(DEFAULT_ROOT)
        .map_or_else(|_| path.to_owned(), |relative| root.join(relative));
    if !mapped.starts_with(root) {
        bail!("isolated path escapes runtime root");
    }
    no_symlinks(&mapped)?;
    Ok(mapped)
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Route retained by this evidence operation.
pub fn route(path: &Path) -> Result<PathBuf> {
    if isolated() {
        route_at(path, &root())
    } else {
        Ok(path.into())
    }
}
/// Captures retained by this evidence operation.
#[must_use]
pub fn captures() -> PathBuf {
    root().join("captures")
}
