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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> KeylogEntry {
        serde_json::from_str(
            r#"{"build_id":"aabb","offset":32,"lib_name":"libfixture.so","size":256}"#,
        )
        .unwrap()
    }

    #[test]
    fn basename_never_overrides_identity() {
        let rule = entry();
        assert!(rule.matches("libfixture.so", 256, Some("AABB")));
        assert!(!rule.matches("libfixture.so", 256, Some("ccdd")));
        assert!(!rule.matches("libfixture.so", 256, None));
        assert!(!rule.matches("other.so", 256, Some("aabb")));
        assert!(!rule.matches("libfixture.so", 257, Some("aabb")));
    }

    #[test]
    fn missing_or_malformed_identity_is_rejected() {
        for id in ["", " ", "abc", "not-hex"] {
            let mut rule = entry();
            rule.build_id = id.into();
            assert!(!rule.matches("libfixture.so", 256, Some(id)));
            let mut entries = vec![rule];
            assert_eq!(reject_unsafe_entries(&mut entries), 1);
        }
    }

    #[test]
    fn conflicting_pins_disable_whole_group_even_with_different_names() {
        let a = entry();
        let mut b = a.clone();
        b.build_id = "AABB".into();
        b.offset += 4;
        b.lib_name = None;
        let mut other = a.clone();
        other.build_id = "ccdd".into();
        let mut entries = vec![a.clone(), b, a, other];
        assert_eq!(reject_unsafe_entries(&mut entries), 3);
        assert_eq!(entries[0].build_id, "ccdd");
    }

    #[test]
    fn conflicting_layout_is_rejected_but_identical_pins_are_allowed() {
        let a = entry();
        let mut entries = vec![a.clone(), a.clone()];
        assert_eq!(reject_unsafe_entries(&mut entries), 0);
        entries[1].client_random_offset = Some(64);
        assert_eq!(reject_unsafe_entries(&mut entries), 2);
    }
}
