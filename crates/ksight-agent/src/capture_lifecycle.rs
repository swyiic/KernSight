//! Cooperative, parent/attempt-owned lifecycle. Never signals a target or kills an agent.
use crate::capture_relation::CaptureRelation;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;
const SCHEMA: &str = "kernsight.capture-lifecycle/v1";
const MAX_RECORD: u64 = 16384;

/// Immutable identity and no-pause contract of one collection attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Owner {
    /// Versioned lifecycle record schema.
    pub schema: String,
    /// Exact parent, stage and attempt ancestry.
    pub relation: CaptureRelation,
    /// Fresh immutable ownership token for this attempt.
    pub token: Uuid,
    /// Agent process, never the target App.
    pub pid: u32,
    /// Agent procfs start ticks, unknown on unsupported hosts.
    pub process_start_ticks: Option<u64>,
    /// Kernel boot identity, unknown when unavailable.
    /// Boot identity when observed; absence remains unknown.
    pub boot_id: Option<String>,
    /// Issued upper bound; the active output deadline may shorten it.
    pub max_ms: u64,
    /// This contract forbids target pause; forensic CLI is separate.
    pub target_pause: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Stop {
    token: Uuid,
    cause: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct PrestartStop {
    relation: CaptureRelation,
    cause: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Returned {
    token: Uuid,
    result: String,
    stop_reason: Option<String>,
    cleanup: String,
}
/// Independent durable stop/return facts and current process observation.
#[derive(Debug, Serialize)]
pub struct Status {
    /// Versioned lifecycle record schema.
    pub schema: &'static str,
    /// Exact parent, stage and attempt ancestry.
    pub relation: CaptureRelation,
    /// Fresh immutable ownership token for this attempt.
    pub token: Uuid,
    /// A matching cooperative request exists durably.
    pub stop_request_recorded: bool,
    /// Worker observed this stop reason; independent from exit.
    pub stop_acknowledged: bool,
    /// First worker stop cause, if observed.
    pub stop_reason: Option<String>,
    /// Producer scope returned and committed its terminal record.
    pub collection_returned: bool,
    /// Completed or partial producer status; absent while running.
    pub collection_status: Option<String>,
    /// Exact PID/start/boot owner has exited; null is unknown.
    pub agent_exited_confirmed: Option<bool>,
    /// Scope return fact, never a claim about external launcher cleanup.
    pub cleanup: String,
    /// This contract forbids target pause; forensic CLI is separate.
    pub target_pause: String,
    /// Optional matching launch/attach timing; absent is unknown for legacy data.
    pub startup: Option<serde_json::Value>,
    /// Physical qualified source identities; absent remains unknown.
    pub qualification: Option<serde_json::Value>,
}
fn same(a: &CaptureRelation, b: &CaptureRelation) -> bool {
    a.parent_id == b.parent_id
        && a.stage_id == b.stage_id
        && a.attempt_id == b.attempt_id
        && a.attempt == b.attempt
        && a.stage_key == b.stage_key
}
/// Immutable bounded records. Only this call's scratch is removed; prior evidence is untouched.
fn retain<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() as u64 > MAX_RECORD {
        bail!("lifecycle record exceeds bound");
    }
    let temp = root.join(format!(".lifecycle-{}", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&temp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        match fs::hard_link(&temp, root.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::symlink_metadata(root.join(name))?;
                if existing.file_type().is_symlink() || existing.len() > MAX_RECORD {
                    bail!("lifecycle conflict/symlink/oversized record");
                }
                if fs::read(root.join(name))? == body {
                    Ok(())
                } else {
                    bail!("lifecycle record conflict");
                }
            }
            Err(e) => Err(e.into()),
        }
    })();
    let _ = fs::remove_file(temp);
    result?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}
fn read<T: for<'a> Deserialize<'a>>(root: &Path, name: &str) -> Result<T> {
    let path = root.join(name);
    if fs::symlink_metadata(&path)?.file_type().is_symlink() {
        bail!("lifecycle symlink refused");
    }
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_RECORD {
        bail!("lifecycle record exceeds bound");
    }
    Ok(serde_json::from_slice(&data)?)
}
fn owner(root: &Path, expected: &CaptureRelation) -> Result<Owner> {
    let o: Owner = read(root, "owner.json")?;
    if o.schema != SCHEMA
        || o.token.is_nil()
        || !same(&o.relation, expected)
        || o.target_pause != "forbidden"
    {
        bail!("lifecycle owner/parent/no-pause contract mismatch");
    }
    Ok(o)
}
/// The CLI derives this path from validated UUIDs; no PID or package guesses.
pub fn control_root(base: &Path, r: &CaptureRelation) -> PathBuf {
    base.join(r.parent_id.to_string())
        .join(r.stage_id.to_string())
        .join(r.attempt_id.to_string())
        .join("control")
}
/// Records a cooperative request only; no SIGTERM/SIGKILL/SIGCONT or target-state change.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn request_stop(root: &Path, r: &CaptureRelation, cause: &str) -> Result<Status> {
    if !["parent_cancelled", "parent_deadline_exhausted"].contains(&cause) {
        bail!("invalid lifecycle stop reason");
    }
    if !root.join("owner.json").exists() {
        ensure_control_root(root)?;
        retain(
            root,
            "prestart-stop.json",
            &PrestartStop {
                relation: r.clone(),
                cause: cause.into(),
            },
        )?;
        // No owner/token exists yet: never manufacture an agent acknowledgement or exit.
        bail!("prestart cancellation retained; owner/exit unconfirmed");
    }
    let o = owner(root, r)?;
    if root.join("stop.json").exists() {
        let s: Stop = read(root, "stop.json")?;
        if s.token != o.token {
            bail!("foreign stop token");
        }
    } else {
        retain(
            root,
            "stop.json",
            &Stop {
                token: o.token,
                cause: cause.into(),
            },
        )?;
    }
    inspect(root, r)
}
/// Read-only status: process exit and successful resource unwinding are independent facts.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn inspect(root: &Path, r: &CaptureRelation) -> Result<Status> {
    inspect_with(root, r, owner_alive)
}
fn owner_alive(o: &Owner) -> Option<bool> {
    let boot = crate::retention::boot_id()?;
    let recorded = o.boot_id.as_ref()?;
    if &boot != recorded {
        return Some(false);
    }
    let path = format!("/proc/{}/stat", o.pid);
    match fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
        Ok(_) => Some(crate::retention::process_start_ticks(o.pid)? == o.process_start_ticks?),
    }
}
fn inspect_with(
    root: &Path,
    r: &CaptureRelation,
    probe: impl FnOnce(&Owner) -> Option<bool>,
) -> Result<Status> {
    let o = owner(root, r)?;
    let stop = if root.join("stop.json").exists() {
        Some(read::<Stop>(root, "stop.json")?)
    } else {
        None
    };
    let ack = if root.join("stop-ack.json").exists() {
        Some(read::<Stop>(root, "stop-ack.json")?)
    } else {
        None
    };
    let returned = if root.join("returned.json").exists() {
        Some(read::<Returned>(root, "returned.json")?)
    } else {
        None
    };
    if stop.as_ref().is_some_and(|s| s.token != o.token)
        || ack.as_ref().is_some_and(|s| s.token != o.token)
        || returned.as_ref().is_some_and(|s| s.token != o.token)
    {
        bail!("lifecycle record token mismatch");
    }
    let startup = if root.join("startup.json").exists() {
        let note: serde_json::Value = read(root, "startup.json")?;
        let relation: CaptureRelation = serde_json::from_value(note["relation"].clone())?;
        if note["schema"] != "kernsight.startup/v1"
            || !same(&relation, r)
            || note["token"] != o.token.to_string()
        {
            bail!("foreign startup evidence");
        }
        Some(note)
    } else {
        None
    };
    let qualification = if root.join("qualification.json").exists() {
        let note: serde_json::Value = read(root, "qualification.json")?;
        let relation: CaptureRelation = serde_json::from_value(note["relation"].clone())?;
        if note["schema"] != "kernsight.qualified-source/v1"
            || !same(&relation, r)
            || note["token"] != o.token.to_string()
        {
            bail!("foreign qualification source receipt");
        }
        Some(note)
    } else {
        None
    };
    let exited = probe(&o).map(|alive| !alive);
    Ok(Status {
        schema: SCHEMA,
        relation: o.relation.clone(),
        token: o.token,
        stop_request_recorded: stop.is_some(),
        stop_acknowledged: ack
            .as_ref()
            .is_some_and(|a| stop.as_ref().is_none_or(|s| s.cause == a.cause)),
        stop_reason: returned
            .as_ref()
            .and_then(|v| v.stop_reason.clone())
            .or_else(|| ack.as_ref().map(|s| s.cause.clone())),
        collection_returned: returned.is_some(),
        collection_status: returned.as_ref().map(|v| v.result.clone()),
        agent_exited_confirmed: exited,
        cleanup: returned.map_or("unconfirmed".into(), |v| v.cleanup),
        target_pause: o.target_pause,
        startup,
        qualification,
    })
}
/// Preserve physical source evidence only; the controller cannot mint a qualification by passing raw tuples.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn retain_qualification(
    root: &Path,
    r: &CaptureRelation,
    sources: &[crate::qualified_code::SourceIdentity],
) -> Result<()> {
    let o = owner(root, r)?;
    for source in sources {
        source.validate()?;
    }
    retain(
        root,
        "qualification.json",
        &serde_json::json!({"schema":"kernsight.qualified-source/v1","relation":r,"token":o.token,"sources":sources,"source":"MetadataObserver physical pidfd lease","l0_scope":"legacy numeric UID metadata; not a qualified payload proof"}),
    )
}
/// Scope around a no-pause producer. Finish only after the producer returns and drops resources.
pub struct Lease {
    root: PathBuf,
    owner: Owner,
    deadline: Instant,
    scopes: Vec<PathBuf>,
    done: Arc<AtomicBool>,
    watch: Option<JoinHandle<Option<String>>>,
    launch_cleanup_confirmed: Arc<AtomicBool>,
}
impl Lease {
    /// Acquire an immutable attempt and start cooperative deadline/request observation.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn begin(
        root: &Path,
        relation: &CaptureRelation,
        scopes: Vec<PathBuf>,
        max_ms: u64,
        no_pause: bool,
    ) -> Result<Self> {
        if !no_pause || !(1..=3_600_000).contains(&max_ms) {
            bail!("cooperative lifecycle requires no-pause and a bounded deadline");
        }
        ensure_control_root(root)?;
        // One attempt is immutable. A retry needs a new attempt ID/root.
        if root.join("owner.json").exists() {
            bail!("lifecycle attempt already exists; retry cannot reset deadline");
        }
        let o = Owner {
            schema: SCHEMA.into(),
            relation: relation.clone(),
            token: Uuid::new_v4(),
            pid: std::process::id(),
            process_start_ticks: crate::retention::process_start_ticks(std::process::id()),
            boot_id: crate::retention::boot_id(),
            max_ms,
            target_pause: "forbidden".into(),
        };
        reject_prestart(root, relation)?;
        retain(root, "owner.json", &o)?;
        reject_prestart(root, relation)?;
        let deadline = scopes.iter().fold(
            Instant::now() + Duration::from_millis(max_ms),
            |d, scope| ksight_core::output_budget::deadline(scope, d),
        );
        let done = Arc::new(AtomicBool::new(false));
        let signal = done.clone();
        let path = root.to_owned();
        let token = o.token;
        let monitored = scopes.clone();
        let watch = std::thread::spawn(move || {
            while !signal.load(Ordering::SeqCst) {
                let request = if Instant::now() >= deadline {
                    Some("parent_deadline_exhausted".to_owned())
                } else if path.join("stop.json").exists() {
                    match read::<Stop>(&path, "stop.json") {
                        Ok(s) if s.token == token => Some(s.cause),
                        _ => Some("lifecycle_control_invalid".into()),
                    }
                } else {
                    None
                };
                if let Some(cause) = request {
                    for scope in &monitored {
                        ksight_core::output_budget::interrupt(scope, &cause);
                    }
                    let _ = retain(
                        &path,
                        "stop-ack.json",
                        &Stop {
                            token,
                            cause: cause.clone(),
                        },
                    );
                    return Some(cause);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            None
        });
        Ok(Self {
            root: root.into(),
            owner: o,
            deadline,
            scopes,
            done,
            watch: Some(watch),
            launch_cleanup_confirmed: Arc::new(AtomicBool::new(true)),
        })
    }
    /// Derive a launch permit from this exact attempt's existing clock and token.
    pub fn startup(&self, package: String) -> Startup {
        Startup {
            root: self.root.clone(),
            relation: self.owner.relation.clone(),
            token: self.owner.token,
            deadline: self.deadline,
            package,
            cleanup_confirmed: self.launch_cleanup_confirmed.clone(),
            cancelled: Arc::new(AtomicBool::new(false)),
            clock: Instant::now(),
            timing: Arc::new(Mutex::new(StartupTiming::default())),
        }
    }
    /// Commit only after the producer scope has returned; never claim process exit here.
    ///
    /// # Panics
    /// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn finish(mut self, successful: bool) -> Result<Status> {
        self.done.store(true, Ordering::SeqCst);
        let mut reason = self
            .watch
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("lifecycle watcher panicked"))?;
        if reason.is_none() {
            reason = self
                .scopes
                .iter()
                .find_map(|s| ksight_core::output_budget::stop_reason(s));
        }
        if reason.is_none() {
            if Instant::now() >= self.deadline {
                reason = Some("parent_deadline_exhausted".into());
            } else if self.root.join("stop.json").exists() {
                let s: Stop = read(&self.root, "stop.json")?;
                if s.token != self.owner.token {
                    bail!("foreign stop token");
                }
                reason = Some(s.cause);
            }
        }
        if let Some(cause) = &reason {
            for scope in &self.scopes {
                ksight_core::output_budget::interrupt(scope, cause);
            }
            retain(
                &self.root,
                "stop-ack.json",
                &Stop {
                    token: self.owner.token,
                    cause: cause.clone(),
                },
            )?;
        }
        retain(
            &self.root,
            "returned.json",
            &Returned {
                token: self.owner.token,
                result: if successful && reason.is_none() {
                    "completed"
                } else {
                    "partial"
                }
                .into(),
                stop_reason: reason,
                cleanup: if self.launch_cleanup_confirmed.load(Ordering::SeqCst) {
                    "producer_scope_returned"
                } else {
                    "unconfirmed"
                }
                .into(),
            },
        )?;
        inspect(&self.root, &self.owner.relation)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(w) = self.watch.take() {
            let _ = w.join();
        }
    }
}

fn ensure_control_root(root: &Path) -> Result<()> {
    if root
        .ancestors()
        .take(4)
        .any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
    {
        bail!("lifecycle root symlink refused");
    }
    fs::create_dir_all(root)?;
    Ok(())
}

fn reject_prestart(root: &Path, relation: &CaptureRelation) -> Result<()> {
    if root.join("prestart-stop.json").exists() {
        let stop: PrestartStop = read(root, "prestart-stop.json")?;
        if !same(&stop.relation, relation) {
            bail!("foreign prestart cancellation");
        }
        bail!("attempt cancelled before owner acquisition: {}", stop.cause);
    }
    Ok(())
}
/// Launch after attachment with the same owner and deadline; no detached sleeper or target pause.
#[derive(Clone, Debug)]
pub struct Startup {
    root: PathBuf,
    relation: CaptureRelation,
    token: Uuid,
    deadline: Instant,
    package: String,
    cleanup_confirmed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    clock: Instant,
    timing: Arc<Mutex<StartupTiming>>,
}
impl Startup {
    fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            bail!("owned launcher scope ended");
        }
        reject_prestart(&self.root, &self.relation)?;
        if Instant::now() >= self.deadline {
            bail!("parent_deadline_exhausted before launch");
        }
        let o = owner(&self.root, &self.relation)?;
        if o.token != self.token
            || self.root.join("returned.json").exists()
            || self.root.join("stop.json").exists()
        {
            bail!("inactive/foreign attempt cannot launch");
        }
        Ok(())
    }
    /// Force-stop under the same lease before sensors are prepared; preserve prior instance evidence.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn force_stop(&self) -> Result<()> {
        self.check()?;
        let mut command = std::process::Command::new("am");
        command.args(["force-stop", &self.package]);
        self.force_stop_with(command, Duration::from_secs(2), || {
            package_instances(&self.package)
        })
    }
    fn force_stop_with(
        &self,
        command: std::process::Command,
        wait_for_exit: Duration,
        probe: impl Fn() -> Vec<StartupInstance>,
    ) -> Result<()> {
        self.check()?;
        self.update(|t| {
            t.cold_start_requested = true;
            t.previous_instances = probe();
        });
        let result = self.run_command(command);
        self.update(|t| {
            t.force_stop_status = if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into();
        });
        result?;
        let wait_until = Instant::now() + wait_for_exit;
        loop {
            let left = probe();
            if left.is_empty() {
                self.update(|t| t.previous_instance_exit_observed_ms = Some(self.elapsed_ms()));
                break;
            }
            self.check()?;
            if Instant::now() >= wait_until {
                self.update(|t| {
                    t.force_stop_status = "remaining_after_wait".into();
                    t.previous_instance_exit_observed_ms = None;
                });
                eprintln!(
                    "force-stop wait ended with {} package process(es) still present; they are not merged into the next instance",
                    left.len()
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
    /// Start an owned worker without blocking the capture/event loop.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn start(&self) -> Result<LaunchTask> {
        if !cfg!(any(target_os = "linux", target_os = "android")) {
            bail!("owned Android launcher unsupported on this host");
        }
        // Android monkey is a shell script without a shebang on some builds.
        // Pass its path as an argument, preserving the owned process group.
        let mut command = script_command("/system/bin/sh", "/system/bin/monkey");
        command.args([
            "-p",
            &self.package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]);
        self.start_command(command)
    }
    fn start_command(&self, command: std::process::Command) -> Result<LaunchTask> {
        self.check()?;
        self.update(|t| t.sensors_ready_ms = Some(self.elapsed_ms()));
        let owned = self.clone();
        let worker = std::thread::spawn(move || {
            let result = owned.run_command(command);
            owned.update(|t| {
                t.launcher_finished_ms = Some(owned.elapsed_ms());
                t.launcher_error = result.as_ref().err().map(|e| format!("{e:#}"));
                t.launcher_errno = result.as_ref().err().and_then(|e| {
                    e.chain().find_map(|c| {
                        c.downcast_ref::<std::io::Error>()
                            .and_then(std::io::Error::raw_os_error)
                    })
                });
                t.launcher_status = if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                }
                .into();
            });
            result
        });
        Ok(LaunchTask {
            owner: self.clone(),
            worker: Some(worker),
        })
    }
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn update(&self, change: impl FnOnce(&mut StartupTiming)) {
        if let Ok(mut t) = self.timing.lock() {
            change(&mut t);
        }
    }
    /// Record observed attach time, not assumed startup coverage.
    pub fn record_attach(&self, adapter: &str) {
        let elapsed = self.elapsed_ms();
        self.update(|t| {
            t.first_attach_ms.entry(adapter.into()).or_insert(elapsed);
        });
    }
    /// Observe new process generations separately from launcher success.
    pub fn observe_target(&self) {
        let instances = package_instances(&self.package);
        self.update(|t| {
            if !instances.is_empty() {
                t.observed_instances = instances;
            }
        });
    }
    /// Preserve startup timing and identity facts with this attempt's immutable ancestry.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn retain_timing(&self) -> Result<()> {
        let t = self
            .timing
            .lock()
            .map_err(|_| anyhow::anyhow!("startup timing poisoned"))?;
        retain(
            &self.root,
            "startup.json",
            &serde_json::json!({"schema":"kernsight.startup/v1", "relation":self.relation,"token":self.token,"package":self.package,"timing":*t,"generation_state":generation_state(&t.previous_instances, &t.observed_instances),"coverage":"first attach is observed; earlier startup events may be missing","target_pause":"forbidden"}),
        )
    }
    #[allow(
        clippy::too_many_lines,
        reason = "Keep the admission or lifecycle transaction together for review."
    )]
    #[allow(
        clippy::items_after_statements,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn run_command(&self, mut command: std::process::Command) -> Result<()> {
        self.check()?;
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let program = command.get_program().to_string_lossy().into_owned();
        let mut child = command
            .spawn()
            .with_context(|| format!("owned launcher spawn program={program}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("owned launcher stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("owned launcher stderr unavailable"))?;
        // Drain only launcher diagnostics; EOF is a separate resource fact, never an App exit.
        let out_done = Arc::new(AtomicBool::new(false));
        let err_done = Arc::new(AtomicBool::new(false));
        #[allow(
            clippy::needless_pass_by_value,
            reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
        )]
        fn drain(mut pipe: impl Read, done: Arc<AtomicBool>) {
            let mut block = [0u8; 4096];
            let mut bytes = 0usize;
            loop {
                match pipe.read(&mut block) {
                    Ok(0) => {
                        done.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(n) => {
                        bytes += n;
                        if bytes > 262_144 {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }
        let out_signal = out_done.clone();
        let err_signal = err_done.clone();
        let out_worker = std::thread::spawn(move || drain(stdout, out_signal));
        let err_worker = std::thread::spawn(move || drain(stderr, err_signal));
        self.cleanup_confirmed.store(false, Ordering::SeqCst);
        self.update(|t| {
            if t.sensors_ready_ms.is_some() {
                t.launcher_started_ms = Some(self.elapsed_ms());
            }
        });
        // Keep ownership until reap; never signal a numeric PID after reap.
        let result = loop {
            if let Err(e) = self.check() {
                break Err(e);
            }
            #[cfg(unix)]
            {
                use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
                match waitid(
                    WaitId::Pid(
                        Pid::from_raw(i32::try_from(child.id()).unwrap_or(0))
                            .ok_or_else(|| anyhow::anyhow!("invalid owned launcher PID"))?,
                    ),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(Some(_))
                        if out_done.load(Ordering::SeqCst) && err_done.load(Ordering::SeqCst) =>
                    {
                        break Ok(())
                    }
                    Ok(None | Some(_)) => {}
                    Err(e) => break Err(e.into()),
                }
            }
            #[cfg(not(unix))]
            {
                break Err(anyhow::anyhow!(
                    "owned launcher lifecycle unsupported on this host"
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // A normally exited leader with both owned pipes at EOF needs no post-exit numeric signal.
        // On stop/error, signal only while the owned leader is still unreaped.
        let mut group_confirmed = result.is_ok();
        if result.is_err() {
            #[cfg(unix)]
            {
                group_confirmed = i32::try_from(child.id())
                    .ok()
                    .filter(|pid| *pid > 0)
                    .is_some_and(|pid| {
                        matches!(
                            nix::sys::signal::kill(
                                nix::unistd::Pid::from_raw(-pid),
                                nix::sys::signal::Signal::SIGKILL
                            ),
                            Ok(()) | Err(nix::errno::Errno::ESRCH)
                        )
                    });
            }
            let _ = child.kill();
        }
        let waited = child.wait();
        // Pipe EOF proves owned diagnostic descendants have closed; escaped/re-directed processes are outside this fact.
        for _ in 0..100 {
            if out_worker.is_finished() && err_worker.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !group_confirmed
            || waited.is_err()
            || !out_worker.is_finished()
            || !err_worker.is_finished()
            || !out_done.load(Ordering::SeqCst)
            || !err_done.load(Ordering::SeqCst)
        {
            bail!("owned launcher cleanup unconfirmed; original stop: {result:?}");
        }
        let _ = out_worker.join();
        let _ = err_worker.join();
        self.cleanup_confirmed.store(true, Ordering::SeqCst);
        result?;
        let status = waited?;
        if !status.success() {
            bail!("owned launcher failed: {status}");
        }
        Ok(())
    }
}

/// Process generation observation. Missing identity remains unknown.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StartupInstance {
    /// Observed PID; never a sufficient task identity by itself.
    pub pid: u32,
    /// Start ticks retained by this evidence operation.
    pub start_ticks: Option<u64>,
    /// Boot identity when observed; absence remains unknown.
    pub boot_id: Option<String>,
}
fn generation_state(previous: &[StartupInstance], observed: &[StartupInstance]) -> &'static str {
    if observed.is_empty()
        || observed
            .iter()
            .any(|i| i.start_ticks.is_none() || i.boot_id.is_none())
        || previous
            .iter()
            .any(|i| i.start_ticks.is_none() || i.boot_id.is_none())
    {
        return "unknown";
    }
    if observed.iter().any(|i| previous.contains(i)) {
        return "prior_instance_still_observed";
    }
    "new_instance_observed"
}
fn package_instances(package: &str) -> Vec<StartupInstance> {
    crate::dexdump::pids_for_package(package)
        .into_iter()
        .take(32)
        .map(|pid| StartupInstance {
            pid,
            start_ticks: crate::retention::process_start_ticks(pid),
            boot_id: crate::retention::boot_id(),
        })
        .collect()
}
/// Actual timing is relative to this lease-derived startup clock.
#[derive(Debug, Default, Serialize)]
struct StartupTiming {
    cold_start_requested: bool,
    previous_instances: Vec<StartupInstance>,
    force_stop_status: String,
    previous_instance_exit_observed_ms: Option<u64>,
    sensors_ready_ms: Option<u64>,
    launcher_started_ms: Option<u64>,
    launcher_finished_ms: Option<u64>,
    launcher_status: String,
    #[serde(default)]
    launcher_error: Option<String>,
    #[serde(default)]
    launcher_errno: Option<i32>,
    observed_instances: Vec<StartupInstance>,
    first_attach_ms: std::collections::BTreeMap<String, u64>,
}
/// Own the worker through all producer exits. Drop requests cooperative cleanup and joins.
pub struct LaunchTask {
    owner: Startup,
    worker: Option<JoinHandle<Result<()>>>,
}
impl LaunchTask {
    /// Surface launcher failure while the collection loop continues polling sensors.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            let t = self
                .owner
                .timing
                .lock()
                .map_err(|_| anyhow::anyhow!("startup timing poisoned"))?;
            if t.launcher_status == "failed" {
                bail!(
                    "owned launcher failed; startup coverage partial: {}",
                    t.launcher_error
                        .as_deref()
                        .unwrap_or("legacy diagnostic unknown")
                );
            }
        }
        Ok(())
    }
    /// Reap this attempt's launcher before producer terminal acknowledgement.
    ///
    /// # Panics
    /// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn finish(mut self) -> Result<()> {
        if !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            self.owner.cancelled.store(true, Ordering::SeqCst);
        }
        let result = self
            .worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("owned launcher worker panicked"))?;
        self.owner.retain_timing()?;
        result
    }
}
impl Drop for LaunchTask {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.owner.cancelled.store(true, Ordering::SeqCst);
            let _ = worker.join();
            let _ = self.owner.retain_timing();
        }
    }
}

fn script_command(
    shell: impl AsRef<std::ffi::OsStr>,
    script: impl AsRef<std::ffi::OsStr>,
) -> std::process::Command {
    let mut command = std::process::Command::new(shell);
    command.arg(script);
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    fn relation() -> CaptureRelation {
        CaptureRelation::parse(
            Some(Uuid::new_v4()),
            Some(Uuid::new_v4()),
            Some(Uuid::new_v4()),
            Some(1),
            Some("dump".into()),
        )
        .unwrap()
        .unwrap()
    }
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("lifecycle-{}", Uuid::new_v4()))
    }
    #[cfg(unix)]
    #[test]
    fn production_launcher_spawn_failure_retains_errno_before_start_timestamp() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 2000, true).unwrap();
        let startup = lease.startup("org.example.fixture".into());
        let task = startup
            .start_command(std::process::Command::new(root.join("missing-launcher")))
            .unwrap();
        while !task.worker.as_ref().unwrap().is_finished() {
            std::thread::yield_now();
        }
        assert!(task
            .check()
            .unwrap_err()
            .to_string()
            .contains("owned launcher spawn"));
        assert!(task.finish().is_err());
        let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
        assert_eq!(receipt["timing"]["launcher_errno"], 2);
        assert!(receipt["timing"]["launcher_error"]
            .as_str()
            .unwrap()
            .contains("missing-launcher"));
        assert!(receipt["timing"]["launcher_started_ms"].is_null());
        assert_eq!(receipt["timing"]["launcher_status"], "failed");
    }

    #[cfg(unix)]
    #[test]
    fn production_launcher_runs_script_without_shebang_as_owned_child() {
        use std::os::unix::fs::PermissionsExt;
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 2000, true).unwrap();
        let script = root.join("monkey script");
        std::fs::write(
            &script,
            "# Android-style launcher without shebang\n[ \"$1\" = 'package;literal' ]\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let startup = lease.startup("org.example.fixture".into());
        let mut command = script_command("/bin/sh", &script);
        command.arg("package;literal");
        let task = startup.start_command(command).unwrap();
        while !task.worker.as_ref().unwrap().is_finished() {
            std::thread::yield_now();
        }
        task.finish().unwrap();
        let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
        assert_eq!(receipt["timing"]["launcher_status"], "completed");
        assert!(receipt["timing"]["launcher_errno"].is_null());
        assert!(receipt["timing"]["launcher_started_ms"].is_number());
    }

    #[test]
    fn startup_preowner_cancellation_blocks_late_attempt_without_fabricating_owner() {
        let root = root();
        let r = relation();
        assert!(request_stop(&root, &r, "parent_cancelled").is_err());
        assert!(root.join("prestart-stop.json").exists());
        assert!(!root.join("owner.json").exists());
        assert!(Lease::begin(&root, &r, vec![], 1000, true).is_err());
        assert!(!root.join("owner.json").exists());
    }
    #[test]
    fn startup_cancelled_expired_and_foreign_permits_never_spawn() {
        for mode in ["cancel", "expire", "foreign", "returned"] {
            let root = root();
            let r = relation();
            let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
            let mut permit = lease.startup("org.example.fixture".into());
            let marker = root.join("must-not-launch");
            match mode {
                "cancel" => {
                    request_stop(&root, &r, "parent_cancelled").unwrap();
                }
                "expire" => permit.deadline = Instant::now(),
                "foreign" => permit.token = Uuid::new_v4(),
                _ => {
                    lease.finish(true).unwrap();
                }
            }
            let mut command = std::process::Command::new("sh");
            command
                .arg("-c")
                .arg("echo launched > \"$1\"")
                .arg("fixture")
                .arg(&marker);
            assert!(permit.run_command(command).is_err());
            assert!(!marker.exists());
        }
    }
    #[cfg(unix)]
    #[test]
    fn startup_deadline_reaps_owned_launcher_and_background_descendant() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 300, true).unwrap();
        let permit = lease.startup("org.example.fixture".into());
        let marker = root.join("must-not-leak");
        let ready = root.join("ready");
        let release = root.join("release");
        let mut command = std::process::Command::new("sh");
        command.arg("-c").arg("(echo ready > \"$2\"; while [ ! -f \"$3\" ]; do sleep 0.005; done; echo leaked > \"$1\") & wait").arg("fixture").arg(&marker).arg(&ready).arg(&release);
        let error = permit.run_command(command).unwrap_err();
        assert!(
            error.to_string().contains("parent_deadline_exhausted"),
            "{error}"
        );
        assert!(ready.exists());
        fs::write(&release, b"release").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!marker.exists());
    }
    #[cfg(unix)]
    #[test]
    fn startup_success_observes_pipe_eof_before_reaping_leader() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "exit 0"]);
        lease
            .startup("org.example.fixture".into())
            .run_command(command)
            .unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn corrected_startup_worker_allows_attach_during_launch_and_records_order() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 2000, true).unwrap();
        let startup = lease.startup("org.example.fixture".into());
        let ready = root.join("ready");
        let release = root.join("release");
        let mut command = std::process::Command::new("sh");
        command
            .args([
                "-c",
                "echo ready > \"$1\"; while [ ! -f \"$2\" ]; do sleep 0.005; done",
            ])
            .arg("fixture")
            .arg(&ready)
            .arg(&release);
        let task = startup.start_command(command).unwrap();
        while !ready.exists() {
            startup.check().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        startup.record_attach("tls_ssl_write"); // Same production callback, while launcher still running.
        assert!(!task.worker.as_ref().unwrap().is_finished());
        fs::write(release, b"release").unwrap();
        while !task.worker.as_ref().unwrap().is_finished() {
            startup.check().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        task.finish().unwrap();
        let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
        assert!(
            receipt["timing"]["first_attach_ms"]["tls_ssl_write"]
                .as_u64()
                .unwrap()
                <= receipt["timing"]["launcher_finished_ms"].as_u64().unwrap()
        );
        assert!(receipt["coverage"]
            .as_str()
            .unwrap()
            .contains("may be missing"));
    }
    #[cfg(unix)]
    #[test]
    fn corrected_three_cold_starts_keep_each_attempt_and_instance_evidence() {
        for generation in 1..=3 {
            let root = root();
            let r = relation();
            let lease = Lease::begin(&root, &r, vec![], 2000, true).unwrap();
            let startup = lease.startup("org.example.fixture".into());
            let live = Arc::new(AtomicBool::new(true));
            let view = live.clone();
            let old = StartupInstance {
                pid: 71,
                start_ticks: Some(generation * 100),
                boot_id: Some("same-boot".into()),
            };
            let next = StartupInstance {
                pid: 71,
                start_ticks: Some((generation + 1) * 100),
                boot_id: Some("same-boot".into()),
            };
            let mut stop = std::process::Command::new("sh");
            stop.args(["-c", "exit 0"]);
            let probes = std::sync::atomic::AtomicUsize::new(0);
            startup
                .force_stop_with(stop, Duration::from_secs(2), || {
                    if probes.fetch_add(1, Ordering::SeqCst) == 0 && view.load(Ordering::SeqCst) {
                        vec![old.clone()]
                    } else {
                        live.store(false, Ordering::SeqCst);
                        vec![]
                    }
                })
                .unwrap();
            let mut launch = std::process::Command::new("sh");
            launch.args(["-c", "exit 0"]);
            let task = startup.start_command(launch).unwrap();
            while !task.worker.as_ref().unwrap().is_finished() {
                startup.check().unwrap();
                std::thread::sleep(Duration::from_millis(5));
            }
            startup.update(|t| t.observed_instances = vec![next.clone()]);
            task.finish().unwrap();
            let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
            assert_eq!(receipt["relation"]["attempt_id"], r.attempt_id.to_string());
            assert_eq!(
                receipt["timing"]["previous_instances"][0]["start_ticks"],
                generation * 100
            );
            assert_eq!(
                receipt["timing"]["observed_instances"][0]["start_ticks"],
                (generation + 1) * 100
            );
            assert_eq!(receipt["timing"]["force_stop_status"], "completed");
        }
    }
    #[cfg(unix)]
    #[test]
    fn corrected_force_stop_failure_never_starts_launcher() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
        let startup = lease.startup("org.example.fixture".into());
        let mut stop = std::process::Command::new("sh");
        stop.args(["-c", "exit 7"]);
        assert!(startup
            .force_stop_with(stop, Duration::from_secs(2), Vec::new)
            .is_err());
        startup.retain_timing().unwrap();
        let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
        assert_eq!(receipt["timing"]["force_stop_status"], "failed");
    }
    #[cfg(unix)]
    #[test]
    fn force_stop_wait_does_not_block_on_a_remaining_process() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 2000, true).unwrap();
        let startup = lease.startup("org.example.fixture".into());
        let mut stop = std::process::Command::new("sh");
        stop.args(["-c", "exit 0"]);
        let stuck = StartupInstance {
            pid: 71,
            start_ticks: Some(100),
            boot_id: Some("same-boot".into()),
        };
        startup
            .force_stop_with(stop, Duration::from_millis(30), move || vec![stuck.clone()])
            .unwrap();
        startup.retain_timing().unwrap();
        let receipt: serde_json::Value = read(&root, "startup.json").unwrap();
        assert_eq!(receipt["timing"]["force_stop_status"], "remaining_after_wait");
        assert!(receipt["timing"]["previous_instance_exit_observed_ms"].is_null());
        assert!(receipt["timing"]["launcher_started_ms"].is_null());
    }
    #[test]
    fn corrected_startup_missing_identity_is_unknown_not_new_generation() {
        let instance = StartupInstance {
            pid: 71,
            start_ticks: None,
            boot_id: None,
        };
        assert_eq!(
            generation_state(&[], std::slice::from_ref(&instance)),
            "unknown"
        );
        let known = StartupInstance {
            pid: 71,
            start_ticks: Some(1),
            boot_id: Some("boot".into()),
        };
        assert_eq!(
            generation_state(std::slice::from_ref(&known), std::slice::from_ref(&known)),
            "prior_instance_still_observed"
        );
    }
    #[test]
    fn lifecycle_stop_ack_return_and_exit_are_separate_production_facts() {
        let root = root();
        fs::create_dir(&root).unwrap();
        let output = root.join("output");
        fs::create_dir(&output).unwrap();
        let control = root.join("control");
        let r = relation();
        let budget =
            ksight_core::output_budget::Guard::install(vec![output.clone()], 1024, 1000).unwrap();
        let lease = Lease::begin(&control, &r, vec![output.clone()], 1000, true).unwrap();
        ksight_core::output_budget::write(output.join("original"), b"retained").unwrap();
        let sent = request_stop(&control, &r, "parent_cancelled").unwrap();
        assert!(sent.stop_request_recorded);
        assert!(!sent.collection_returned);
        let start = Instant::now();
        while !ksight_core::output_budget::should_stop(&output) {
            assert!(start.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(2));
        }
        let returned = lease.finish(false).unwrap();
        assert!(returned.stop_acknowledged);
        assert!(returned.collection_returned);
        assert_eq!(returned.collection_status.as_deref(), Some("partial"));
        assert_eq!(returned.stop_reason.as_deref(), Some("parent_cancelled"));
        let still_running = inspect_with(&control, &r, |_| Some(true)).unwrap();
        assert_eq!(still_running.agent_exited_confirmed, Some(false));
        let exited = inspect_with(&control, &r, |_| Some(false)).unwrap();
        assert_eq!(exited.agent_exited_confirmed, Some(true));
        assert_eq!(exited.cleanup, "producer_scope_returned");
        assert_eq!(fs::read(output.join("original")).unwrap(), b"retained");
        assert!(ksight_core::output_budget::write(output.join("late"), b"bad").is_err());
        assert!(!output.join("late").exists());
        assert_eq!(budget.receipt().reason.as_deref(), Some("parent_cancelled"));
        drop(budget);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lifecycle_agent_deadline_does_not_require_a_connected_controller() {
        let root = root();
        fs::create_dir(&root).unwrap();
        let output = root.join("output");
        fs::create_dir(&output).unwrap();
        let control = root.join("control");
        let r = relation();
        let budget =
            ksight_core::output_budget::Guard::install(vec![output.clone()], 1024, 1000).unwrap();
        let lease = Lease::begin(&control, &r, vec![output.clone()], 35, true).unwrap();
        ksight_core::output_budget::write(output.join("prefix"), b"partial").unwrap();
        // No host callbacks/connection are available. The same production watchdog stops admission.
        let start = Instant::now();
        while !ksight_core::output_budget::should_stop(&output) {
            assert!(start.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(2));
        }
        let status = lease.finish(false).unwrap();
        assert!(!status.stop_request_recorded);
        assert!(status.stop_acknowledged);
        assert_eq!(
            status.stop_reason.as_deref(),
            Some("parent_deadline_exhausted")
        );
        assert_eq!(status.collection_status.as_deref(), Some("partial"));
        assert_eq!(fs::read(output.join("prefix")).unwrap(), b"partial");
        drop(budget);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lifecycle_abnormal_agent_exit_never_invents_cleanup_and_retry_is_immutable() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
        drop(lease); // Unwinding/abnormal exit cannot commit returned.json.
        let status = inspect_with(&root, &r, |_| Some(false)).unwrap();
        assert_eq!(status.agent_exited_confirmed, Some(true));
        assert!(!status.collection_returned);
        assert_eq!(status.cleanup, "unconfirmed");
        assert!(Lease::begin(&root, &r, vec![], 1000, true).is_err());
        let old = fs::read(root.join("owner.json")).unwrap();
        assert!(request_stop(&root, &relation(), "parent_cancelled").is_err());
        assert_eq!(fs::read(root.join("owner.json")).unwrap(), old);
        assert!(!root.join("stop.json").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lifecycle_rejects_pause_and_forged_tokens_without_signalling_any_process() {
        let root = root();
        let r = relation();
        assert!(Lease::begin(&root, &r, vec![], 1000, false).is_err());
        assert!(!root.exists());
        let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
        retain(
            &root,
            "stop.json",
            &Stop {
                token: Uuid::new_v4(),
                cause: "parent_cancelled".into(),
            },
        )
        .unwrap();
        assert!(request_stop(&root, &r, "parent_cancelled").is_err());
        assert!(inspect_with(&root, &r, |_| Some(true)).is_err());
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lifecycle_completed_scope_does_not_claim_process_exit_or_other_attempts() {
        let root = root();
        let r = relation();
        let lease = Lease::begin(&root, &r, vec![], 1000, true).unwrap();
        let completed = lease.finish(true).unwrap();
        assert!(completed.collection_returned);
        assert_eq!(completed.collection_status.as_deref(), Some("completed"));
        assert_eq!(
            inspect_with(&root, &r, |_| None)
                .unwrap()
                .agent_exited_confirmed,
            None
        );
        assert!(inspect(&root, &relation()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
