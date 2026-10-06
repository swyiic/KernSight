//! Strict sampling capability for the current numeric-TGID backend.

/// Refuse strict mirror before external actions while instance binding is absent.
///
/// # Errors
/// Numeric TGID filtering and userspace starttime polling cannot prove the
/// process instance at kernel sampling time. There is no bypass flag.
pub fn require_strict_mirror_backend() -> Result<(), &'static str> {
    Err("strict mirror unavailable: current backend filters numeric TGIDs without verified process-instance binding at kernel sampling time; refusing before layout, hooks or payload sampling")
}

/// Refuse optional ptrace/inline TLS injection until complete restoration has
/// been proved. No caller flag, environment value or library version bypasses it.
///
/// # Errors
/// Remote-call timeout recovery, original signal delivery and FPSIMD/TLS state
/// restoration remain unproved. Refusal precedes target or filesystem actions.
pub fn require_injection_restore_backend() -> Result<(), &'static str> {
    Err("TLS injection disabled: reliable timeout recovery, signal delivery and FPSIMD/TLS state restoration are unproved; refusing before target, socket, layout or routing actions")
}

/// Code one-click needs sampling and live-copy instance binding, which this backend cannot attest.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn require_code_collection_backend() -> Result<(), &'static str> {
    if !cfg!(any(target_os = "linux", target_os = "android")) || std::env::consts::ARCH != "aarch64"
    {
        return Err("process-instance qualification not-supported on this host; ARM64 Linux/Android required");
    }
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").is_file() {
        return Err("process-instance qualification not-supported: kernel BTF absent");
    }
    Ok(()) // Platform prerequisite only. Agent separately loads/verifies the physical backend.
}
