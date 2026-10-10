//! Compile-time provenance shared by the agent and host CLI. No runtime Git calls.

use std::{env, path::Path, process::Command};

// Only inputs that can affect shipped code/assets count as source modifications.
// Ignore documentation, generated build outputs and unrelated untracked files.
const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "Makefile",
    "rust-toolchain.toml",
    ".cargo",
    "crates",
    "bpf",
    "native",
    "android",
    "rules",
    "xtask",
    "scripts",
];

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    // A caller's repository/index/config overrides must never impersonate this tree.
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command
        .args(["--no-optional-locks", "-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn valid_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn fresh_suffix() -> String {
    let mut bytes = [0_u8; 4];
    let generated = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .is_ok();
    if !generated {
        bytes = std::process::id().to_le_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn watch(path: &Path) {
    // A nonexistent rerun-if-changed path would make Cargo rebuild on every call.
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=KERNSIGHT_BUILD_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=KERNSIGHT_BUILD_GIT_DIRTY");
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-changed=build.rs");
    let manifest =
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies the manifest directory");
    let root = Path::new(&manifest)
        .join("../..")
        .canonicalize()
        .expect("workspace root exists");
    // An extracted archive inside an unrelated Git checkout must not inherit its SHA.
    let own_repository = git(&root, &["rev-parse", "--show-toplevel"])
        .and_then(|path| Path::new(&path).canonicalize().ok())
        .is_some_and(|path| path == root);
    for input in INPUTS.iter().copied().chain(std::iter::once(".gitignore")) {
        let path = root.join(input);
        // Every declared input exists in a full checkout. Keep a missing path
        // watched there so delete/build/restore cannot leave a stale identity.
        // Only incomplete checkouts pay repeated checks until it is restored;
        // archives with unknown identity can cache without those missing paths.
        if own_repository || path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    watch(&root.join(".git"));

    // Both directories are necessary for linked worktrees. Watching metadata also
    // covers detached HEAD, packed refs, ref creation/deletion and index-only edits.
    // --no-optional-locks above prevents our own reads from refreshing the index.
    for kind in ["--absolute-git-dir", "--git-common-dir"] {
        if !own_repository {
            break;
        }
        if let Some(directory) = git(&root, &["rev-parse", kind]) {
            watch(&root.join(directory));
        }
    }

    let override_commit = env::var("KERNSIGHT_BUILD_GIT_COMMIT").ok();
    let override_dirty = env::var("KERNSIGHT_BUILD_GIT_DIRTY").ok();
    let (commit, dirty, source) = match (override_commit, override_dirty) {
        (Some(commit), Some(dirty)) => {
            assert!(valid_commit(&commit), "KERNSIGHT_BUILD_GIT_COMMIT must be a full 40- or 64-character hexadecimal Git commit");
            let dirty = match dirty.as_str() {
                "true" => true,
                "false" => false,
                _ => panic!("KERNSIGHT_BUILD_GIT_DIRTY must be true or false"),
            };
            (Some(commit.to_ascii_lowercase()), Some(dirty), "override")
        }
        (None, None) => {
            let commit = own_repository
                .then(|| git(&root, &["rev-parse", "--verify", "HEAD"]))
                .flatten()
                .filter(|commit| valid_commit(commit));
            let dirty = commit.as_ref().and_then(|_| {
                let mut args = vec!["status", "--porcelain=v1", "-z", "--untracked-files=all", "--"];
                args.extend_from_slice(INPUTS);
                args.push(":(exclude,glob)**/*.md");
                args.push(":(exclude,glob)**/*.rst");
                git(&root, &args).map(|status| !status.is_empty())
            });
            let source = if commit.is_some() { "git" } else { "unknown" };
            (commit, dirty, source)
        }
        _ => panic!("set both KERNSIGHT_BUILD_GIT_COMMIT and KERNSIGHT_BUILD_GIT_DIRTY for an archive/release override"),
    };
    let base = env::var("CARGO_PKG_VERSION").expect("Cargo supplies the package version");
    // One suffix, and it changes on every compile. The Git commit stays in
    // KERNSIGHT_GIT_COMMIT and is not repeated here.
    println!("cargo:rerun-if-changed=target/kernsight-build-nonce");
    println!(
        "cargo:rustc-env=KERNSIGHT_BUILD_VERSION={base}_{}",
        fresh_suffix()
    );
    println!(
        "cargo:rustc-env=KERNSIGHT_GIT_COMMIT={}",
        commit.as_deref().unwrap_or("")
    );
    println!(
        "cargo:rustc-env=KERNSIGHT_GIT_DIRTY={}",
        dirty.map_or("unknown", |value| if value { "true" } else { "false" })
    );
    println!("cargo:rustc-env=KERNSIGHT_BUILD_IDENTITY_SOURCE={source}");
}
