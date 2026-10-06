//! Android identity adapter boundary.

use std::{collections::BTreeMap, io::Read as _};

pub use ksight_core::IdentityRegistry;
use ksight_model::{PackageCandidate, ProcessIdentity};

const MAX_PACKAGES_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROC_IDENTITY_BYTES: usize = 4096;
const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;

/// Whether a package name is safe to use as an exact Android identity selector.
#[must_use]
pub fn valid_package_name(package_name: &str) -> bool {
    !package_name.is_empty()
        && package_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
}

/// Read-only Android package and procfs identity resolver.
#[derive(Debug, Clone, Default)]
pub struct AndroidIdentityResolver {
    packages_by_uid: BTreeMap<u32, Vec<String>>,
}

impl AndroidIdentityResolver {
    /// Load Android's package-to-UID index.
    ///
    /// # Errors
    ///
    /// Returns an error when `packages.list` is not readable in the current security domain.
    pub fn from_system() -> Result<Self, std::io::Error> {
        let packages = read_bounded_string("/data/system/packages.list", MAX_PACKAGES_LIST_BYTES)?;
        Ok(Self::from_packages_list(&packages))
    }

    /// Add command line, `SELinux` domain, and package candidates to an identity.
    pub fn enrich(&self, identity: &mut ProcessIdentity) {
        let process_root = format!("/proc/{}", identity.key.pid);
        if let Some(tgid) = read_tgid(&format!("{process_root}/status")) {
            identity.tgid = tgid;
        }
        identity.command_line = read_nul_terminated(&format!("{process_root}/cmdline"));
        identity.selinux_context = read_nul_terminated(&format!("{process_root}/attr/current"));
        identity.packages = self.package_candidates(identity.uid, identity.command_line.as_deref());
    }

    /// Resolve an installed package to its Linux UID.
    #[must_use]
    pub fn uid_for_package(&self, package_name: &str) -> Option<u32> {
        self.packages_by_uid.iter().find_map(|(uid, packages)| {
            packages
                .iter()
                .any(|package| package == package_name)
                .then_some(*uid)
        })
    }

    /// Explicit package enrollment refuses shared UIDs instead of guessing by mutable cmdline.
    #[must_use]
    pub fn exclusive_package_uid(&self, package_name: &str) -> Option<u32> {
        self.packages_by_uid
            .iter()
            .find_map(|(uid, names)| (names.len() == 1 && names[0] == package_name).then_some(*uid))
    }
    fn from_packages_list(packages: &str) -> Self {
        let mut packages_by_uid: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for line in packages.lines() {
            let mut fields = line.split_whitespace();
            let Some(package_name) = fields.next() else {
                continue;
            };
            let Some(uid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
                continue;
            };
            packages_by_uid
                .entry(uid)
                .or_default()
                .push(package_name.to_owned());
        }
        for packages in packages_by_uid.values_mut() {
            packages.sort();
            packages.dedup();
        }
        Self { packages_by_uid }
    }

    fn package_candidates(&self, uid: u32, command_line: Option<&str>) -> Vec<PackageCandidate> {
        let Some(packages) = self.packages_by_uid.get(&uid) else {
            return command_line
                .and_then(command_line_package)
                .map(|package_name| {
                    vec![PackageCandidate {
                        package_name,
                        source: "proc_cmdline".to_owned(),
                        confidence_percent: 60,
                    }]
                })
                .unwrap_or_default();
        };

        let exact = command_line.and_then(|command| {
            packages
                .iter()
                .find(|package| process_name_matches(command, package))
        });
        let mut candidates = packages
            .iter()
            .map(|package| PackageCandidate {
                package_name: package.clone(),
                source: if exact == Some(package) {
                    "packages.list+proc_cmdline"
                } else {
                    "packages.list:uid"
                }
                .to_owned(),
                confidence_percent: if exact == Some(package) {
                    100
                } else if packages.len() == 1 {
                    95
                } else {
                    65
                },
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .confidence_percent
                .cmp(&left.confidence_percent)
                .then_with(|| left.package_name.cmp(&right.package_name))
        });
        candidates
    }
}

fn read_nul_terminated(path: &str) -> Option<String> {
    let bytes = read_bounded(path, MAX_PROC_IDENTITY_BYTES).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn read_tgid(path: &str) -> Option<u32> {
    let status = read_bounded_string(path, MAX_PROC_STATUS_BYTES).ok()?;
    let line = status.lines().find(|line| line.starts_with("Tgid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("identity source exceeds {maximum} bytes"),
        ));
    }
    Ok(bytes)
}

fn read_bounded_string(path: &str, maximum: usize) -> Result<String, std::io::Error> {
    String::from_utf8(read_bounded(path, maximum)?).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("identity source is not UTF-8: {error}"),
        )
    })
}

fn process_name_matches(command: &str, package: &str) -> bool {
    command == package
        || command
            .strip_prefix(package)
            .is_some_and(|rest| rest.starts_with(':'))
}

fn command_line_package(command: &str) -> Option<String> {
    let package = command.split(':').next()?;
    let valid = package.contains('.')
        && !package.contains('/')
        && package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'));
    valid.then(|| package.to_owned())
}

