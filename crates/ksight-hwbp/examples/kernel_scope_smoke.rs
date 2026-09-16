//! Device-only integration check. Attaches ONLY to this executable's fixture.
//! No App selection, TLS hooks, offset discovery, or user-memory payloads.
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn main() {
    eprintln!("Run the aarch64 Linux-musl build on the test device.");
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ksight_scope_fixture(a: u64, b: u64, c: u64, d: u64) -> u64 {
    std::hint::black_box(a ^ b ^ c ^ d)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    device::run()
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod device {
    use anyhow::{ensure, Context, Result};
    use ksight_hwbp::{RegisterContext, UprobeSession};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const CALLS: usize = 8;
    fn invoke() {
        let function: extern "C" fn(u64, u64, u64, u64) -> u64 =
            std::hint::black_box(super::ksight_scope_fixture);
        // x1/x2 are null: the generic probe cannot read a user payload.
        std::hint::black_box(function(0x1234, 0, 0, 0));
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn mapped_offset(pc: u64) -> Result<u64> {
        for line in std::fs::read_to_string("/proc/self/maps")?.lines() {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 3 || !columns[1].contains('x') {
                continue;
            }
            let Some((start, end)) = columns[0].split_once('-') else {
                continue;
            };
            let start = u64::from_str_radix(start, 16)?;
            let end = u64::from_str_radix(end, 16)?;
            if (start..end).contains(&pc) {
                return Ok(u64::from_str_radix(columns[2], 16)? + pc - start);
            }
        }
        anyhow::bail!("fixture PC is not in an executable mapping")
    }

    fn exercise(
        session: &mut UprobeSession,
        child: &mut ChildGuard,
        output: &mut BufReader<std::process::ChildStdout>,
    ) -> Result<Vec<RegisterContext>> {
        for _ in 0..CALLS {
            invoke();
        }
        let input = child.0.stdin.as_mut().context("child stdin")?;
        input.write_all(b"call\n")?;
        input.flush()?;
        let mut ack = String::new();
        ensure!(
            output.read_line(&mut ack)? > 0 && ack.trim() == "done",
            "fixture child failed"
        );
        let deadline = Instant::now() + Duration::from_millis(350);
        let mut hits = Vec::new();
        while Instant::now() < deadline {
            hits.extend(session.poll_hits()?);
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(hits)
    }

    fn allowed_cpus() -> Result<Vec<usize>> {
        // SAFETY: cpu_set_t is plain C storage; libc receives its exact size.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) };
        ensure!(
            result == 0,
            "get affinity: {}",
            std::io::Error::last_os_error()
        );
        let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) })
            .collect();
        ensure!(!cpus.is_empty(), "no allowed CPUs");
        Ok(cpus)
    }

    fn pin_fixture(pid: u32, cpu: usize) -> Result<()> {
        ensure!(cpu < libc::CPU_SETSIZE as usize, "CPU out of range");
        // Only called for this fixture and its own child, never an App PID.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_SET(cpu, &mut set);
        }
        let result =
            unsafe { libc::sched_setaffinity(pid.try_into()?, std::mem::size_of_val(&set), &set) };
        ensure!(
            result == 0,
            "pin fixture to CPU {cpu}: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }

    fn soak(
        session: &mut UprobeSession,
        child: &mut ChildGuard,
        output: &mut BufReader<std::process::ChildStdout>,
        seconds: u64,
    ) -> Result<()> {
        let cpus = allowed_cpus()?;
        let pid = std::process::id();
        let mut totals = vec![(0usize, 0usize); cpus.len()];
        let started = Instant::now();
        let mut rounds = 0usize;
        let mut next_report = 30;
        println!("SOAK start seconds={seconds} cpus={cpus:?} continuous_attachment=true");
        while started.elapsed() < Duration::from_secs(seconds) {
            let slot = rounds % cpus.len();
            pin_fixture(pid, cpus[slot])?;
            pin_fixture(child.0.id(), cpus[slot])?;
            let hits = exercise(session, child, output)?;
            let entries = hits.iter().filter(|hit| !hit.snapshot_at_return).count();
            let returns = hits.iter().filter(|hit| hit.snapshot_at_return).count();
            ensure!(
                entries == CALLS && returns == CALLS,
                "soak CPU {} round {rounds}: entry={entries} return={returns}",
                cpus[slot]
            );
            ensure!(
                hits.iter().all(|hit| hit.pid == pid && hit.aux_bytes == 0),
                "soak leaked another process or included a payload"
            );
            ensure!(session.lost_total == 0, "perf reported lost events");
            totals[slot].0 += entries;
            totals[slot].1 += returns;
            rounds += 1;
            if started.elapsed().as_secs() >= next_report {
                println!(
                    "SOAK elapsed={}s rounds={rounds} entry={} return={} lost=0 scope_leaks=0",
                    started.elapsed().as_secs(),
                    rounds * CALLS,
                    rounds * CALLS
                );
                next_report += 30;
            }
        }
        for (cpu, (entries, returns)) in cpus.iter().zip(totals) {
            println!("SOAK cpu={cpu} entry={entries} return={returns}");
        }
        println!(
            "SOAK PASS elapsed={}s rounds={rounds} entry={} return={} lost=0 scope_leaks=0",
            started.elapsed().as_secs(),
            rounds * CALLS,
            rounds * CALLS
        );
        Ok(())
    }

    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.get(1).is_some_and(|arg| arg == "--fixture-child") {
            for line in std::io::stdin().lock().lines() {
                ensure!(line? == "call", "unknown fixture command");
                for _ in 0..CALLS {
                    invoke();
                }
                println!("done");
                std::io::stdout().flush()?;
            }
            return Ok(());
        }
        ensure!(
            args.len() == 3 || args.len() == 4,
            "usage: kernel_scope_smoke BPF_OBJECT FILE_OFFSET_HEX [SOAK_SECONDS]"
        );
        let soak_seconds = args.get(3).map(|value| value.parse::<u64>()).transpose()?;
        ensure!(
            soak_seconds.is_none_or(|seconds| (1..=600).contains(&seconds)),
            "soak duration must be 1..600 seconds"
        );
        let offset = u64::from_str_radix(args[2].trim_start_matches("0x"), 16)?;
        let pc = super::ksight_scope_fixture as *const () as usize as u64;
        let actual_offset = mapped_offset(pc)?;
        ensure!(offset == actual_offset, "supplied ELF offset {offset:#x} != fixture mapping offset {actual_offset:#x}; refusing attach");
        let exe = std::env::current_exe()?;
        let pid = std::process::id();
        let mut child = ChildGuard(
            Command::new(&exe)
                .arg("--fixture-child")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut output = BufReader::new(child.0.stdout.take().context("child stdout")?);
        println!(
            "fixture pid={pid} excluded_child={} pc={pc:#x} file_offset={offset:#x}",
            child.0.id()
        );
        let mut session = UprobeSession::start_program_scoped(
            std::path::Path::new(&args[1]),
            "ksight_uprobe_regs",
            &exe,
            offset,
            &[pid],
            false,
        )?;
        let hits = exercise(&mut session, &mut child, &mut output)?;
        println!(
            "allow_parent hits={} expected={CALLS} lost={}",
            hits.len(),
            session.lost_total
        );
        ensure!(hits.len() == CALLS, "unexpected initial hit count");
        ensure!(
            hits.iter()
                .all(|h| h.pid == pid && h.pc == pc && h.aux_bytes == 0 && h.regs[0] == 0x1234),
            "wrong process, PC, argument or unexpected payload"
        );
        session.apply_tgid_filter(Some(&[]))?;
        let hits = exercise(&mut session, &mut child, &mut output)?;
        println!("empty_scope hits={}", hits.len());
        ensure!(hits.is_empty(), "empty scope leaked events");
        session.apply_tgid_filter(Some(&[pid]))?;
        let hits = exercise(&mut session, &mut child, &mut output)?;
        println!("restored_scope hits={}", hits.len());
        ensure!(
            hits.len() == CALLS && hits.iter().all(|h| h.pid == pid),
            "scope restore/isolation failed"
        );
        ensure!(
            session.apply_tgid_filter(Some(&[0])).is_err(),
            "invalid TGID accepted"
        );
        ensure!(session.finished(), "failed update left session active");
        let hits = exercise(&mut session, &mut child, &mut output)?;
        ensure!(hits.is_empty(), "detached session emitted events");
        println!("invalid_update detached=true");
        drop(session);

        // Both parent and child only call the fixture on explicit instructions,
        // so no fixture calls occur before this filter is installed.
        let mut paired = UprobeSession::start_entry_return(
            std::path::Path::new(&args[1]),
            &exe,
            offset,
            None,
            false,
        )?;
        paired.apply_tgid_filter(Some(&[pid]))?;
        let hits = exercise(&mut paired, &mut child, &mut output)?;
        let entries = hits.iter().filter(|hit| !hit.snapshot_at_return).count();
        let returns = hits.iter().filter(|hit| hit.snapshot_at_return).count();
        println!(
            "paired entry={entries} return={returns} lost={}",
            paired.lost_total
        );
        ensure!(
            entries == CALLS && returns == CALLS,
            "entry/return transport lost events"
        );
        ensure!(
            hits.iter().all(|hit| hit.pid == pid && hit.aux_bytes == 0),
            "paired scope leaked or read a payload"
        );
        if let Some(seconds) = soak_seconds {
            soak(&mut paired, &mut child, &mut output, seconds)?;
        }
        paired.apply_tgid_filter(Some(&[]))?;
        let hits = exercise(&mut paired, &mut child, &mut output)?;
        ensure!(hits.is_empty(), "empty paired scope leaked events");
        println!("paired_empty_scope hits=0; kernel_scope_smoke PASS");
        Ok(())
    }
}
