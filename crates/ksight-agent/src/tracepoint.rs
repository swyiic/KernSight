//! Runtime tracepoint-format contracts.

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{bail, Context, Result};

/// One tracefs field layout required by a BPF tracepoint context adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedField {
    /// Field name without an array suffix.
    pub name: &'static str,
    /// Byte offset from the tracepoint record start.
    pub offset: u32,
    /// Field storage size in bytes.
    pub size: u32,
}

/// Pixel/Android 6.1 `sched_wakeup` layout consumed by the current BPF object.
pub const SCHED_WAKEUP_FIELDS: &[ExpectedField] = &[
    ExpectedField {
        name: "comm",
        offset: 8,
        size: 16,
    },
    ExpectedField {
        name: "pid",
        offset: 24,
        size: 4,
    },
    ExpectedField {
        name: "prio",
        offset: 28,
        size: 4,
    },
    ExpectedField {
        name: "target_cpu",
        offset: 32,
        size: 4,
    },
];

/// Check a runtime tracefs format without loading or attaching a BPF program.
pub fn format_compatible(category: &str, name: &str, expected: &[ExpectedField]) -> Option<bool> {
    let format = std::fs::read_to_string(format_path(category, name)).ok()?;
    Some(fields_match(&format, expected))
}

/// Reject a BPF adapter when the runtime tracepoint record layout differs.
///
/// # Errors
///
/// Returns an error when tracefs is unreadable or any required field differs.
pub fn validate_format(category: &str, name: &str, expected: &[ExpectedField]) -> Result<()> {
    let path = format_path(category, name);
    let format = std::fs::read_to_string(&path)
        .with_context(|| format!("read tracepoint format {}", path.display()))?;
    if !fields_match(&format, expected) {
        bail!("tracepoint {category}/{name} format is incompatible with this BPF object");
    }
    Ok(())
}

fn format_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from("/sys/kernel/tracing/events")
        .join(category)
        .join(name)
        .join("format")
}

fn fields_match(format: &str, expected: &[ExpectedField]) -> bool {
    let fields = parse_fields(format);
    expected
        .iter()
        .all(|field| fields.get(field.name) == Some(&(field.offset, field.size)))
}

fn parse_fields(format: &str) -> BTreeMap<String, (u32, u32)> {
    let mut fields = BTreeMap::new();
    for line in format.lines() {
        let Some(declaration) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let mut sections = declaration.split(';');
        let Some(field_declaration) = sections.next() else {
            continue;
        };
        let Some(offset) = sections
            .find_map(|value| value.trim().strip_prefix("offset:"))
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(size) = declaration
            .split(';')
            .find_map(|value| value.trim().strip_prefix("size:"))
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(raw_name) = field_declaration.split_whitespace().last() else {
            continue;
        };
        let name = raw_name
            .trim_start_matches('*')
            .split('[')
            .next()
            .unwrap_or(raw_name);
        fields.insert(name.to_owned(), (offset, size));
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT: &str = "name: sched_wakeup\nID: 1\nformat:\n\tfield:char comm[16]; offset:8; size:16; signed:1;\n\tfield:pid_t pid; offset:24; size:4; signed:1;\n\tfield:int prio; offset:28; size:4; signed:1;\n\tfield:int target_cpu; offset:32; size:4; signed:1;\n";

    #[test]
    fn accepts_exact_sched_wakeup_layout() {
        assert!(fields_match(FORMAT, SCHED_WAKEUP_FIELDS));
    }

    #[test]
    fn rejects_shifted_target_cpu() {
        let shifted = FORMAT.replace("offset:32", "offset:36");
        assert!(!fields_match(&shifted, SCHED_WAKEUP_FIELDS));
    }
}
