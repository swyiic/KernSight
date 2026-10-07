//! Build-time source provenance, independent from protocol/semantic version fields.

/// Human-readable semantic version with Git build metadata (or explicit unknown).
pub const VERSION: &str = env!("KERNSIGHT_BUILD_VERSION");
/// Provenance origin: `git`, an explicit release `override`, or `unknown`.
pub const SOURCE: &str = env!("KERNSIGHT_BUILD_IDENTITY_SOURCE");

/// Full Git commit, absent when the build had no verified source identity.
pub fn git_commit() -> Option<&'static str> {
    let value = env!("KERNSIGHT_GIT_COMMIT");
    (!value.is_empty()).then_some(value)
}

/// Whether relevant source inputs differed from HEAD; absent if not established.
pub fn git_dirty() -> Option<bool> {
    match env!("KERNSIGHT_GIT_DIRTY") {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}
