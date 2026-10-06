//! Fail-closed validation of existing offset pins; never discovers new pins.

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct KeylogEntry {
    #[serde(default)]
    pub build_id: String,
    pub offset: u64,
    #[serde(default)]
    pub lib_name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub client_random_offset: Option<u64>,
    #[serde(default)]
    pub note: String,
}

impl KeylogEntry {
    pub fn has_identity(&self) -> bool {
        !self.build_id.is_empty()
            && self.build_id.len() % 2 == 0
            && self.build_id.bytes().all(|b| b.is_ascii_hexdigit())
    }

    pub fn matches(&self, basename: &str, size: u64, build_id: Option<&str>) -> bool {
        self.has_identity()
            && build_id.is_some_and(|id| id.eq_ignore_ascii_case(&self.build_id))
            && self.lib_name.as_deref().is_none_or(|name| name == basename)
            && self.size.is_none_or(|expected| expected == size)
    }
}

/// Reject every member of a conflicting identity group, not just the last row.
pub(crate) fn reject_unsafe_entries(entries: &mut Vec<KeylogEntry>) -> usize {
    let before = entries.len();
    let mut pins = std::collections::BTreeMap::new();
    let mut conflicts = std::collections::BTreeSet::new();
    for entry in entries.iter().filter(|entry| entry.has_identity()) {
        let id = entry.build_id.to_ascii_lowercase();
        let pin = (entry.offset, entry.client_random_offset);
        if pins.insert(id.clone(), pin).is_some_and(|old| old != pin) {
            conflicts.insert(id);
        }
    }
    entries.retain(|entry| {
        entry.has_identity() && !conflicts.contains(&entry.build_id.to_ascii_lowercase())
    });
    before - entries.len()
}
