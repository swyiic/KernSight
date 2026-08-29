use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command as ProcessCommand, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use ksight_core::{MergedDumpRef, SessionReport, SessionReportBuilder};
use ksight_protocol::{
    AcknowledgeBatches, Hello, JsonFrameCodec, ListSessions, Message, ReplayBatches,
    CURRENT_PROTOCOL,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::display::print_session_report;

pub(crate) const DEVICE_AGENT: &str = "/data/local/tmp/ksight/ksightd";
pub(crate) const DEVICE_PROCESS_OBJECT: &str = "/data/local/tmp/ksight/process_lifecycle.bpf.o";
pub(crate) const DEVICE_FILE_OBJECT: &str = "/data/local/tmp/ksight/file_open.bpf.o";
pub(crate) const DEVICE_NETWORK_OBJECT: &str = "/data/local/tmp/ksight/network_connect.bpf.o";
pub(crate) const DEVICE_MEMORY_OBJECT: &str = "/data/local/tmp/ksight/memory_regions.bpf.o";
pub(crate) const DEVICE_BINDER_OBJECT: &str = "/data/local/tmp/ksight/binder_transaction.bpf.o";
pub(crate) const DEVICE_SCHED_OBJECT: &str = "/data/local/tmp/ksight/sched_wakeup.bpf.o";
pub(crate) const DEVICE_UPROBE_OBJECT: &str = "/data/local/tmp/ksight/uprobe_regs.bpf.o";
pub(crate) const DEVICE_SPOOL_ROOT: &str = "/data/local/tmp/ksight/spool";
pub(crate) const DEVICE_CONFIG: &str = "/data/local/tmp/ksight/ksightd.json";
pub(crate) const DEVICE_DAEMON_LOG: &str = "/data/local/tmp/ksight/ksightd.log";
pub(crate) const DEVICE_HIDE_SCRIPT: &str = "/data/local/tmp/ksight/ksight-hide-debug.sh";
pub(crate) const DEVICE_LAST_SESSION: &str = "/data/local/tmp/ksight/spool/last_session";
pub(crate) const DEVICE_CAPTURE_LOG: &str = "/data/local/tmp/ksight/capture-live.log";
pub(crate) const DEVICE_PACKAGES_ROOT: &str = "/data/local/tmp/ksight/packages";
/// Shared storage path the ADB Toolbox dump-collect button pulls from.
pub(crate) const DEVICE_DEXDUMP_ROOT: &str = "/storage/emulated/0/Download/dexDump";
pub(crate) const DEVICE_DAEMON_DISABLED: &str = "/data/local/tmp/ksight/ksightd.disabled";
const PRIVATE_PACKAGE_RETENTION_MIB: u64 = 16 * 1024;
const PUBLIC_PACKAGE_RETENTION_MIB: u64 = 8 * 1024;
const PACKAGE_RETENTION_COUNT: usize = 8;

pub(crate) fn daemon_start(serial: Option<&str>) -> Result<()> {
    run_device(serial, &format!("rm -f {DEVICE_DAEMON_DISABLED}"))?;
    run_device(
        serial,
        &format!("{DEVICE_AGENT} run --config {DEVICE_CONFIG} --dry-run"),
    )?;
    run_device(
        serial,
        &format!(
            "nohup {DEVICE_AGENT} run --config {DEVICE_CONFIG} </dev/null >>{DEVICE_DAEMON_LOG} 2>&1 &"
        ),
    )?;
    let status = wait_for_daemon_state(serial, "running", Duration::from_secs(5))?;
    println!("{status}");
    Ok(())
}

pub(crate) fn daemon_status(serial: Option<&str>) -> Result<()> {
    let status = daemon_status_json(serial)?;
    println!("{status}");
    Ok(())
}

pub(crate) fn deploy_agent(serial: Option<&str>) -> Result<()> {
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("locate workspace root")?;
    let adb = match serial {
        Some(serial) => {
            validate_serial(serial)?;
            format!("adb -s {serial}")
        }
        None => "adb".to_owned(),
    };
    eprintln!(
        "building and pushing ksightd with `{adb}` from {}",
        workspace.display()
    );
    let status = ProcessCommand::new("make")
        .current_dir(&workspace)
        .arg("deploy")
        .arg(format!("ADB={adb}"))
        .status()
        .context("run make deploy")?;
    ensure_success(status)?;
    eprintln!("deployed {DEVICE_AGENT}. Subsequent device capture uses this binary.");
    Ok(())
}

pub(crate) fn pull_forensics(serial: Option<&str>, session: Uuid, dest: &Path) -> Result<()> {
    let remote = format!("{DEVICE_SPOOL_ROOT}/forensics/{session}");
    let exists = run_device_output(serial, &format!("test -d {remote} && echo yes || echo no"))?;
    if exists.trim() != "yes" {
        eprintln!("no forensic snapshots for {session} (no DEX/connlog copied this session)");
        return Ok(());
    }
    let _ = run_device(serial, &format!("chmod -R a+r {remote}"));
    std::fs::create_dir_all(dest).context("create forensics destination")?;
    let dest_str = dest.to_string_lossy().into_owned();
    let mut adb = adb_command(serial)?;
    let status = adb
        .args(["pull", &remote, &dest_str])
        .status()
        .context("adb pull forensics")?;
    ensure_success(status)?;
    eprintln!("pulled {remote} -> {}", dest.display());
    let session_dir = dest.join(session.to_string());
    match ksight_core::repair_dex_dir(&session_dir) {
        Ok(0) => {}
        Ok(count) => eprintln!(
            "repaired {count} DEX file(s) under {}/repaired",
            session_dir.display()
        ),
        Err(error) => eprintln!("DEX repair skipped: {error}"),
    }
    Ok(())
}

pub(crate) fn pull_package(
    serial: Option<&str>,
    package: &str,
    dest: &Path,
    launch: bool,
    runtime_only: bool,
) -> Result<()> {
    validate_package(package)?;
    let remote = format!("{DEVICE_PACKAGES_ROOT}/{package}");
    eprintln!("dumping package {package} on device to {remote}");
    let prepare = if runtime_only {
        format!("mkdir -p {remote}")
    } else {
        format!("rm -rf {remote} && mkdir -p {remote}")
    };
    let mut flags = String::new();
    if launch {
        flags.push_str(" --launch");
    }
    if runtime_only {
        flags.push_str(" --runtime-only");
    }
    run_device(
        serial,
        &format!(
            "{prepare} && {DEVICE_AGENT} dump-package --package {package} --dest {remote}{flags}"
        ),
    )?;
    let _ = run_device(serial, &format!("chmod -R a+rX {remote}"));
    publish_dexdump(serial, package, &remote)?;
    enforce_package_retention(serial)?;
    std::fs::create_dir_all(dest).context("create package destination")?;
    let dest_str = dest.to_string_lossy().into_owned();
    let mut adb = adb_command(serial)?;
    let status = adb
        .args(["pull", &remote, &dest_str])
        .status()
        .context("adb pull package")?;
    ensure_success(status)?;
    let package_dir = dest.join(package);
    eprintln!("pulled {remote} -> {}", package_dir.display());
    eprintln!(
        "可读 DEX: {}/readable-dex  和  {}/apk-dex/split",
        package_dir.display(),
        package_dir.display()
    );
    eprintln!(
        "SO: {}/lib  （安装目录）  {}/apk-assets  （APK assets 壳库）  {}/runtime/runtime-so  （已加载）",
        package_dir.display(),
        package_dir.display(),
        package_dir.display()
    );
    eprintln!("说明见 {}/HOWTO.txt", package_dir.display());
    if let Ok(text) = std::fs::read_to_string(package_dir.join("dump-report.json")) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            let n = value
                .get("artifacts")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            eprintln!(
                "{n} 个 DEX/SO 已编入 dump-report.json（进程实例 correlated；VMA overlaps_mmap 也是 correlated，不是 mmap 证明）"
            );
        }
    }
    eprintln!(
        "也可只 adb pull {remote} ；MobileE 填 {DEVICE_DEXDUMP_ROOT} （包在 {DEVICE_DEXDUMP_ROOT}/{package}）"
    );
    match ksight_core::repair_package_dir(&package_dir) {
        Ok(0) => {}
        Ok(count) => eprintln!(
            "extracted/repaired {count} DEX file(s) under {}",
            package_dir.display()
        ),
        Err(error) => eprintln!("DEX extract/repair skipped: {error}"),
    }
    Ok(())
}

fn publish_dexdump(serial: Option<&str>, package: &str, remote: &str) -> Result<()> {
    let public = format!("{DEVICE_DEXDUMP_ROOT}/{package}");
    eprintln!(
        "publishing curated DEX/SO/plaintext/key evidence {remote} -> {public} for MobileE adb pull"
    );
    run_device(
        serial,
        &format!(
            "rm -rf {public} && mkdir -p {public}/runtime && \
             for item in dump-report.json HOWTO.txt apk apk-dex readable-dex lib apk-assets; do \
               if [ -e {remote}/$item ]; then cp -a {remote}/$item {public}/; fi; \
             done && \
             for item in runtime-so plaintext packer-keys repaired; do \
               if [ -e {remote}/runtime/$item ]; then cp -a {remote}/runtime/$item {public}/runtime/; fi; \
             done && chmod -R a+rX {public}"
        ),
    )?;
    Ok(())
}

fn enforce_package_retention(serial: Option<&str>) -> Result<()> {
    for (root, max_mib) in [
        (DEVICE_PACKAGES_ROOT, PRIVATE_PACKAGE_RETENTION_MIB),
        (DEVICE_DEXDUMP_ROOT, PUBLIC_PACKAGE_RETENTION_MIB),
    ] {
        run_device(
            serial,
            &format!(
                "{DEVICE_AGENT} prune-packages --root {root} --max-total-mib {max_mib} --keep {PACKAGE_RETENTION_COUNT}"
            ),
        )?;
    }
    Ok(())
}

pub(crate) fn daemon_stop(serial: Option<&str>) -> Result<()> {
    // Persist the operator's stop intent before signalling the collector so a
    // Magisk/KernelSU supervisor cannot immediately restart it.
    run_device(serial, &format!("touch {DEVICE_DAEMON_DISABLED}"))?;
    let current = daemon_status_json(serial)?;
    let current_value: serde_json::Value = serde_json::from_str(&current)?;
    if current_value
        .get("state")
        .and_then(serde_json::Value::as_str)
        == Some("stopped")
    {
        println!("{current}");
        return Ok(());
    }
    run_device(
        serial,
        &format!("{DEVICE_AGENT} stop --config {DEVICE_CONFIG}"),
    )?;
    let status = wait_for_daemon_state(serial, "stopped", Duration::from_secs(10))?;
    println!("{status}");
    Ok(())
}

fn wait_for_daemon_state(serial: Option<&str>, wanted: &str, timeout: Duration) -> Result<String> {
    let started = Instant::now();
    loop {
        let status = daemon_status_json(serial)?;
        let value: serde_json::Value = serde_json::from_str(&status)?;
        let state_matches = value.get("state").and_then(serde_json::Value::as_str) == Some(wanted);
        let capture_ready = wanted != "running"
            || (value
                .pointer("/health/session_id")
                .and_then(serde_json::Value::as_str)
                .is_some()
                && value
                    .get("health_fresh")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true));
        if state_matches && capture_ready {
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            bail!("daemon did not reach {wanted} state; last status: {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn daemon_status_json(serial: Option<&str>) -> Result<String> {
    run_device_output(
        serial,
        &format!("{DEVICE_AGENT} status --config {DEVICE_CONFIG} --json"),
    )
}

pub(crate) fn protocol_sessions(serial: Option<&str>) -> Result<()> {
    let mut connection = DeviceProtocol::connect(serial)?;
    let request_id = Uuid::new_v4();
    connection.send(&Message::ListSessions(ListSessions { request_id }))?;
    match connection.receive()? {
        Message::SessionInventory(inventory) if inventory.request_id == request_id => {
            println!("{}", serde_json::to_string_pretty(&inventory.sessions)?);
        }
        Message::Ack(ack) if ack.request_id == request_id && !ack.accepted => {
            bail!(
                "device rejected session inventory: {}",
                ack.detail.as_deref().unwrap_or("no detail")
            );
        }
        response => bail!("unexpected session inventory response: {response:?}"),
    }
    connection.close()
}

pub(crate) fn protocol_replay(
    serial: Option<&str>,
    session_id: Uuid,
    after: Option<u64>,
) -> Result<()> {
    let mut connection = DeviceProtocol::connect(serial)?;
    let request_id = Uuid::new_v4();
    connection.send(&Message::ReplayBatches(ReplayBatches {
        request_id,
        session_id,
        after_batch_sequence: after,
    }))?;
    loop {
        match connection.receive()? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
                if !write_json_line(&Message::EventBatch(batch))? {
                    return Ok(());
                }
            }
            Message::ReplayComplete(complete)
                if complete.request_id == request_id && complete.session_id == session_id =>
            {
                break;
            }
            Message::Ack(ack) if ack.request_id == request_id && !ack.accepted => {
                bail!(
                    "device rejected replay: {}",
                    ack.detail.as_deref().unwrap_or("no detail")
                );
            }
            response => bail!("unexpected replay response: {response:?}"),
        }
    }
    connection.close()
}

pub(crate) fn protocol_report(
    serial: Option<&str>,
    session_id: Uuid,
    after: Option<u64>,
    top: usize,
    json: bool,
) -> Result<()> {
    let mut connection = DeviceProtocol::connect(serial)?;
    let request_id = Uuid::new_v4();
    connection.send(&Message::ReplayBatches(ReplayBatches {
        request_id,
        session_id,
        after_batch_sequence: after,
    }))?;
    let mut builder = SessionReportBuilder::default();
    loop {
        match connection.receive()? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
                for event in &batch.events {
                    builder.record(event);
                }
            }
            Message::ReplayComplete(complete)
                if complete.request_id == request_id && complete.session_id == session_id =>
            {
                break;
            }
            Message::Ack(ack) if ack.request_id == request_id && !ack.accepted => {
                bail!(
                    "device rejected report replay: {}",
                    ack.detail.as_deref().unwrap_or("no detail")
                );
            }
            response => bail!("unexpected report replay response: {response:?}"),
        }
    }
    connection.close()?;

    let mut report = builder.finish();
    merge_dump_reports(serial, &mut report);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_session_report(&report, top);
    }
    Ok(())
}

pub(crate) fn protocol_graph(
    serial: Option<&str>,
    session_id: Uuid,
    after: Option<u64>,
    query: &ksight_core::GraphQuery,
    json: bool,
) -> Result<()> {
    let mut connection = DeviceProtocol::connect(serial)?;
    let request_id = Uuid::new_v4();
    connection.send(&Message::ReplayBatches(ReplayBatches {
        request_id,
        session_id,
        after_batch_sequence: after,
    }))?;
    let mut builder = SessionReportBuilder::default();
    loop {
        match connection.receive()? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
                for event in &batch.events {
                    builder.record(event);
                }
            }
            Message::ReplayComplete(complete)
                if complete.request_id == request_id && complete.session_id == session_id =>
            {
                break;
            }
            Message::Ack(ack) if ack.request_id == request_id && !ack.accepted => {
                bail!(
                    "device rejected graph replay: {}",
                    ack.detail.as_deref().unwrap_or("no detail")
                );
            }
            response => bail!("unexpected graph replay response: {response:?}"),
        }
    }
    connection.close()?;
    let mut report = builder.finish();
    merge_dump_reports(serial, &mut report);
    let graph = report.graph.query(query);
    if json {
        println!("{}", serde_json::to_string_pretty(&graph)?);
    } else {
        crate::display::print_graph(&graph);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PackageDumpFile {
    #[serde(default)]
    package: String,
    #[serde(default)]
    dump_id: String,
    #[serde(default)]
    artifacts: Vec<ksight_core::DumpArtifact>,
    #[serde(default)]
    graph: ksight_core::SessionGraph,
}

fn merge_dump_reports(serial: Option<&str>, report: &mut SessionReport) {
    let session_id = report.session_id.unwrap_or(Uuid::nil());
    let mut packages = BTreeSet::new();
    for process in &report.processes {
        if let Some(package) = &process.package {
            packages.insert(package.clone());
        } else if process.label.contains('.') {
            packages.insert(process.label.clone());
        }
    }
    for package in packages {
        let Some(dump) = load_dump_report(serial, &package) else {
            continue;
        };
        let dump_id = if dump.dump_id.is_empty() {
            dump.graph
                .dump_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned())
        } else {
            dump.dump_id.clone()
        };
        let package_name = if dump.package.is_empty() {
            package.clone()
        } else {
            dump.package.clone()
        };
        if !report
            .merged_dumps
            .iter()
            .any(|existing| existing.dump_id == dump_id)
        {
            report.merged_dumps.push(MergedDumpRef {
                package: package_name.clone(),
                dump_id: dump_id.clone(),
            });
        }
        if !report
            .graph
            .dump_ids
            .iter()
            .any(|existing| existing == &dump_id)
        {
            report.graph.dump_ids.push(dump_id.clone());
        }
        let dump_key = format!("dump:{dump_id}");
        if !report
            .graph
            .entities
            .iter()
            .any(|entity| entity.key == dump_key)
        {
            if let Ok(dump_uuid) = Uuid::parse_str(&dump_id) {
                report.graph.entities.push(ksight_core::GraphEntity {
                    kind: ksight_core::GraphEntityKind::EvidenceDump,
                    session_id: dump_uuid,
                    key: dump_key.clone(),
                    label: format!("{package_name} dump"),
                    sensors: Vec::new(),
                    artifact: None,
                });
                report.graph.edges.push(ksight_core::GraphEdge {
                    from: dump_key,
                    to: format!("process:{package_name}"),
                    relation: "records".to_owned(),
                    strength: ksight_core::EdgeStrength::Correlated,
                    sensor: None,
                });
            }
        }
        report.graph.merge_from(&dump.graph);
        report
            .graph
            .correlate_dump_vmas(session_id, &dump.artifacts, &report.observed_mappings);
    }
}

fn load_dump_report(serial: Option<&str>, package: &str) -> Option<PackageDumpFile> {
    if validate_package(package).is_err() {
        return None;
    }
    if let Ok(text) = run_device_output(
        serial,
        &format!("cat {DEVICE_PACKAGES_ROOT}/{package}/dump-report.json"),
    ) {
        if let Ok(dump) = serde_json::from_str::<PackageDumpFile>(&text) {
            return Some(dump);
        }
    }
    let local = Path::new("packages").join(package).join("dump-report.json");
    std::fs::read_to_string(local)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

pub(crate) fn recatalog_package(serial: Option<&str>, package: &str) -> Result<()> {
    validate_package(package)?;
    let remote = format!("{DEVICE_PACKAGES_ROOT}/{package}");
    let output = run_device_tee(
        serial,
        &format!("{DEVICE_AGENT} recatalog-package --dest {remote}"),
    )?;
    if output.trim().is_empty() {
        bail!("recatalog produced no dump-report for {package}");
    }
    Ok(())
}

pub(crate) fn cleanup_package(serial: Option<&str>, package: &str) -> Result<()> {
    validate_package(package)?;
    let private = format!("{DEVICE_PACKAGES_ROOT}/{package}");
    let public = format!("{DEVICE_DEXDUMP_ROOT}/{package}");
    run_device(serial, &format!("rm -rf {private} {public}"))?;
    println!("removed device package evidence: {private} and {public}");
    Ok(())
}

pub(crate) fn protocol_acknowledge(
    serial: Option<&str>,
    session_id: Uuid,
    through: u64,
) -> Result<()> {
    if through == 0 {
        bail!("acknowledgement sequence must be greater than zero");
    }
    let mut connection = DeviceProtocol::connect(serial)?;
    let request_id = Uuid::new_v4();
    connection.send(&Message::AcknowledgeBatches(AcknowledgeBatches {
        request_id,
        session_id,
        through_batch_sequence: through,
    }))?;
    match connection.receive()? {
        Message::Ack(ack) if ack.request_id == request_id && ack.accepted => {
            println!(
                "acknowledged session={session_id} through={through} {}",
                ack.detail.as_deref().unwrap_or_default()
            );
        }
        Message::Ack(ack) if ack.request_id == request_id => {
            bail!(
                "device rejected acknowledgement: {}",
                ack.detail.as_deref().unwrap_or("no detail")
            );
        }
        response => bail!("unexpected acknowledgement response: {response:?}"),
    }
    connection.close()
}

pub(crate) fn run_device(serial: Option<&str>, device_command: &str) -> Result<()> {
    let mut adb = adb_command(serial)?;
    let remote = format!("su -c \"{device_command}\"");
    let status = adb
        .args(["shell", &remote])
        .status()
        .context("start adb; ensure Android platform-tools is installed and on PATH")?;
    ensure_success(status)
}

/// Stream a device command to the terminal and return the captured stdout.
pub(crate) fn run_device_tee(serial: Option<&str>, device_command: &str) -> Result<String> {
    let mut adb = adb_command(serial)?;
    let remote = format!("su -c \"{device_command}\"");
    let mut child = adb
        .args(["shell", &remote])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("start adb; ensure Android platform-tools is installed and on PATH")?;
    let mut stdout = child
        .stdout
        .take()
        .context("ADB stdout pipe is unavailable")?;
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stdout.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        std::io::stdout().write_all(&buffer[..read])?;
        captured.extend_from_slice(&buffer[..read]);
    }
    let status = child.wait()?;
    ensure_success(status)?;
    Ok(String::from_utf8_lossy(&captured).into_owned())
}

pub(crate) fn parse_session_token(text: &str) -> Option<Uuid> {
    text.split_whitespace().find_map(|word| {
        word.strip_prefix("session=")
            .and_then(|value| Uuid::parse_str(value).ok())
    })
}

pub(crate) fn read_last_session(serial: Option<&str>) -> Result<Uuid> {
    if let Ok(raw) = run_device_output(serial, &format!("cat {DEVICE_LAST_SESSION}")) {
        let trimmed = raw.trim();
        if let Ok(session) = Uuid::parse_str(trimmed) {
            return Ok(session);
        }
    }
    if let Ok(log) = run_device_output(serial, &format!("cat {DEVICE_CAPTURE_LOG}")) {
        if let Some(session) = parse_session_token(&log) {
            return Ok(session);
        }
    }
    bail!("could not read last capture session id from {DEVICE_LAST_SESSION}")
}

pub(crate) fn run_hide_debug_capture(
    serial: Option<&str>,
    duration_seconds: u64,
    capture_command: &str,
) -> Result<()> {
    if duration_seconds == 0 {
        bail!("--hide-debug requires --duration-seconds greater than zero so ADB can be restored");
    }
    eprintln!(
        "hide-debug: starting detached capture, then turning off USB debugging and developer options for {duration_seconds}s"
    );
    eprintln!(
        "hide-debug: this does not hide root or an unlocked bootloader; put the target package on Magisk/KernelSU DenyList if you have it"
    );
    let wrapped = format!("{DEVICE_HIDE_SCRIPT} {duration_seconds} {capture_command}");
    let mut adb = adb_command(serial)?;
    let remote = format!("su -c \"{wrapped}\"");
    let _ = adb
        .args(["shell", &remote])
        .status()
        .context("start hide-debug capture")?;
    let timeout = Duration::from_secs(duration_seconds.saturating_add(20));
    eprintln!(
        "hide-debug: waiting for ADB to return (watchdog restores debugging after the capture)"
    );
    wait_for_adb(serial, timeout)?;
    if let Ok(log) = run_device_output(serial, &format!("cat {DEVICE_CAPTURE_LOG}")) {
        print!("{log}");
        if !log.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

fn wait_for_adb(serial: Option<&str>, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        let mut adb = adb_command(serial)?;
        let output = adb.args(["get-state"]).output();
        if let Ok(output) = output {
            if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "device"
            {
                return Ok(());
            }
        }
        if started.elapsed() >= timeout {
            bail!(
                "ADB did not return within {}s; restore USB debugging on the phone if the watchdog failed",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn run_device_output(serial: Option<&str>, device_command: &str) -> Result<String> {
    let mut adb = adb_command(serial)?;
    let remote = format!("su -c \"{device_command}\"");
    let output = adb
        .args(["shell", &remote])
        .output()
        .context("start adb; ensure Android platform-tools is installed and on PATH")?;
    ensure_success(output.status)?;
    String::from_utf8(output.stdout).context("device command returned non-UTF-8 output")
}

fn adb_command(serial: Option<&str>) -> Result<ProcessCommand> {
    let mut adb = ProcessCommand::new("adb");
    if let Some(serial) = serial {
        validate_serial(serial)?;
        adb.args(["-s", serial]);
    }
    Ok(adb)
}

pub(crate) fn validate_package(package: &str) -> Result<()> {
    if package.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        bail!("Android package name contains unsupported characters")
    }
    Ok(())
}

struct DeviceProtocol {
    child: Child,
    reader: Option<ChildStdout>,
    writer: Option<ChildStdin>,
    codec: JsonFrameCodec,
    closed: bool,
}

impl DeviceProtocol {
    fn connect(serial: Option<&str>) -> Result<Self> {
        let mut adb = ProcessCommand::new("adb");
        if let Some(serial) = serial {
            validate_serial(serial)?;
            adb.args(["-s", serial]);
        }
        let remote = format!("su -c \"{DEVICE_AGENT} serve --spool-root {DEVICE_SPOOL_ROOT}\"");
        let mut child = adb
            .args(["shell", &remote])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start framed ADB transport")?;
        let reader = child
            .stdout
            .take()
            .context("ADB stdout pipe is unavailable")?;
        let writer = child
            .stdin
            .take()
            .context("ADB stdin pipe is unavailable")?;
        let mut connection = Self {
            child,
            reader: Some(reader),
            writer: Some(writer),
            codec: JsonFrameCodec::default(),
            closed: false,
        };
        connection.send(&Message::Hello(Hello {
            protocol: CURRENT_PROTOCOL,
            client_name: format!("ksightctl/{}", env!("CARGO_PKG_VERSION")),
            capabilities: Vec::new(),
        }))?;
        match connection.receive()? {
            Message::HelloAck(ack)
                if ack.protocol.major == CURRENT_PROTOCOL.major
                    && ack.protocol.minor <= CURRENT_PROTOCOL.minor => {}
            Message::HelloAck(ack) => bail!(
                "agent negotiated incompatible protocol {}.{}",
                ack.protocol.major,
                ack.protocol.minor
            ),
            response => bail!("unexpected protocol greeting response: {response:?}"),
        }
        Ok(connection)
    }

    fn send(&mut self, message: &Message) -> Result<()> {
        let writer = self.writer.as_mut().context("ADB input pipe is closed")?;
        self.codec.write(writer, message)?;
        writer.flush()?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Message> {
        let reader = self.reader.as_mut().context("ADB output pipe is closed")?;
        self.codec
            .read(reader)?
            .context("device closed the framed protocol unexpectedly")
    }

    fn close(mut self) -> Result<()> {
        self.writer.take();
        self.reader.take();
        let status = self.child.wait()?;
        self.closed = true;
        ensure_success(status)
    }
}

impl Drop for DeviceProtocol {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.writer.take();
        self.reader.take();
        let _ = self.child.wait();
    }
}

fn validate_serial(serial: &str) -> Result<()> {
    if serial.is_empty()
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        bail!("ADB serial contains unsupported characters")
    }
    Ok(())
}

fn ensure_success(status: ExitStatus) -> Result<()> {
    if !status.success() {
        bail!("ADB device command failed with {status}")
    }
    Ok(())
}

fn write_json_line(value: &impl serde::Serialize) -> Result<bool> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    match std::io::stdout().write_all(&bytes) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_banner() {
        let text = "ksightd 0.1.0 session=7440084a-80e0-423d-ac1e-a513287f4d96 files=true";
        assert_eq!(
            parse_session_token(text).unwrap().to_string(),
            "7440084a-80e0-423d-ac1e-a513287f4d96"
        );
    }

    #[test]
    fn adb_serial_validation_rejects_shell_syntax() {
        assert!(validate_serial("42091FDH20089A").is_ok());
        assert!(validate_serial("emulator-5554").is_ok());
        assert!(validate_serial("device;reboot").is_err());
        assert!(validate_serial("").is_err());
    }

    #[test]
    fn package_validation_rejects_shell_syntax() {
        assert!(validate_package("com.google.android.gms").is_ok());
        assert!(validate_package("android").is_ok());
        assert!(validate_package("com.example;reboot").is_err());
        assert!(validate_package("").is_err());
    }
}
