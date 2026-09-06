//! Late `dlopen` of the TLS hook after packer init. No libart.

use std::fs::File;
use std::io::{ErrorKind, Read as _, Seek as _, SeekFrom};
use std::net::UdpSocket;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const INJECT: &str = "/data/local/tmp/ksight/ksight-inject";
const LIB: &str = "/data/local/tmp/ksight/libksight_tls.so";
const MAGIC: u32 = 0x3154_4c4b;
const UDP_PORT: u16 = 18444;
const PACKER_GRACE: Duration = Duration::from_secs(6);

/// One plaintext SSL_write/SSL_read copy from the injected library.
#[derive(Debug, Clone)]
pub struct InjectedPlaintext {
    /// `send` or `recv`.
    pub direction: &'static str,
    /// Copied buffer.
    pub bytes: Vec<u8>,
}

/// UDP + app-cache listener and one-shot injector.
pub struct TlsInject {
    rx: Receiver<InjectedPlaintext>,
    injected_pid: Option<u32>,
    attempts: u8,
    next_try: Instant,
}

impl TlsInject {
    /// Bind the UDP port the injected library writes to.
    ///
    /// # Errors
    ///
    /// Returns when the socket cannot be bound.
    pub fn start(package: Option<&str>) -> Result<Self, String> {
        let sock = UdpSocket::bind(("127.0.0.1", UDP_PORT)).map_err(|error| error.to_string())?;
        let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
        let (tx, rx) = mpsc::channel();
        let cache = package.map(|name| cache_path(name));
        thread::Builder::new()
            .name("ksight-tls-inject".into())
            .spawn(move || listen_loop(sock, cache, tx))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            rx,
            injected_pid: None,
            attempts: 0,
            next_try: Instant::now(),
        })
    }

    /// `dlopen` the TLS hook into `pid` once, after packer grace.
    pub fn inject(&mut self, pid: u32) {
        if self.injected_pid == Some(pid) || pid == 0 {
            return;
        }
        if Instant::now() < self.next_try {
            return;
        }
        if process_age(pid).is_none_or(|age| age < PACKER_GRACE) {
            return;
        }
        if already_loaded(pid) {
            eprintln!("tls-inject pid={pid} already mapped memfd:jit-cache");
            self.injected_pid = Some(pid);
            return;
        }
        if !Path::new(INJECT).is_file() || !Path::new(LIB).is_file() {
            eprintln!("tls-inject skipped: missing {INJECT} or {LIB}");
            self.attempts = 3;
            return;
        }
        self.attempts = self.attempts.saturating_add(1);
        self.next_try = Instant::now() + Duration::from_secs(3);
        let output = Command::new(INJECT)
            .args([pid.to_string(), LIB.to_owned()])
            .output();
        match output {
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                if out.status.success() {
                    eprintln!("tls-inject ok pid={pid} {err}");
                    self.injected_pid = Some(pid);
                    log_maps_hint(pid);
                } else {
                    eprintln!("tls-inject failed pid={pid} attempt={} {err}", self.attempts);
                    if self.attempts >= 3 {
                        self.injected_pid = Some(pid);
                    }
                }
            }
            Err(error) => eprintln!("tls-inject exec failed: {error}"),
        }
    }

    /// Main package PID (`cmdline` equals the package, not `:push`).
    #[must_use]
    pub fn main_pid(package: &str) -> Option<u32> {
        crate::dexdump::pids_for_package(package)
            .into_iter()
            .find(|pid| {
                let Ok(bytes) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                    return false;
                };
                bytes.split(|byte| *byte == 0).next().unwrap_or(&[]) == package.as_bytes()
            })
    }

    /// Drain copies from the injected library.
    pub fn poll(&mut self) -> Vec<InjectedPlaintext> {
        let mut out = Vec::new();
        while let Ok(item) = self.rx.try_recv() {
            out.push(item);
            if out.len() >= 32 {
                break;
            }
        }
        out
    }
}

fn already_loaded(pid: u32) -> bool {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return false;
    };
    maps.lines().any(|line| {
        if !line.contains("/memfd:jit-cache") || !line.contains("r-xp") {
            return false;
        }
        let Some(range) = line.split_whitespace().next() else {
            return false;
        };
        let mut parts = range.split('-');
        let (Some(start), Some(end)) = (parts.next(), parts.next()) else {
            return false;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            return false;
        };
        end.saturating_sub(start) <= 64 * 1024
    })
}

fn cache_path(package: &str) -> String {
    format!("/data/user/0/{package}/cache/.fl")
}

fn log_maps_hint(pid: u32) {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return;
    };
    let hits: Vec<&str> = maps
        .lines()
        .filter(|line| {
            line.contains("memfd:jit-cache") || line.contains("libpac.so") || line.contains("libksight")
        })
        .collect();
    if hits.is_empty() {
        eprintln!("tls-inject maps: no memfd/libpac mapping yet");
    } else {
        eprintln!("tls-inject maps {}:", hits.len());
        for line in hits.iter().take(6) {
            eprintln!("  {line}");
        }
    }
}

fn process_age(pid: u32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start_ticks = parse_stat_start_ticks(&stat)?;
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let uptime_secs: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    let start_secs = start_ticks as f64 / 100.0;
    let age = uptime_secs - start_secs;
    if age.is_finite() && age >= 0.0 {
        Some(Duration::from_secs_f64(age.min(86_400.0 * 30.0)))
    } else {
        None
    }
}

fn parse_stat_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse().ok())
}

fn listen_loop(sock: UdpSocket, cache: Option<String>, tx: Sender<InjectedPlaintext>) {
    let mut buf = [0_u8; 12 + 2048];
    let mut file_off = 0_u64;
    loop {
        match sock.recv(&mut buf) {
            Ok(n) if n >= 12 => {
                push_packet(&buf[..n], &tx);
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
        if let Some(path) = cache.as_deref() {
            file_off = drain_file(path, file_off, &tx);
        }
    }
}

fn drain_file(path: &str, mut offset: u64, tx: &Sender<InjectedPlaintext>) -> u64 {
    let Ok(mut file) = File::open(path) else {
        return offset;
    };
    let Ok(len) = file.metadata().map(|meta| meta.len()) else {
        return offset;
    };
    if len < offset {
        offset = 0;
    }
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return offset;
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return offset;
    }
    let mut off = 0;
    while off + 12 <= buf.len() {
        if u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4])) != MAGIC {
            off += 1;
            continue;
        }
        let len = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap_or([0; 4])) as usize;
        let end = off + 12 + len;
        if end > buf.len() {
            break;
        }
        push_packet(&buf[off..end], tx);
        off = end;
    }
    offset + off as u64
}

fn push_packet(buf: &[u8], tx: &Sender<InjectedPlaintext>) {
    if buf.len() < 12 {
        return;
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
    if magic != MAGIC {
        return;
    }
    let dir = if buf[4] == 0 { "send" } else { "recv" };
    let len = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4])) as usize;
    let end = 12_usize.saturating_add(len).min(buf.len());
    let bytes = buf[12..end].to_vec();
    if !bytes.is_empty() {
        let _ = tx.send(InjectedPlaintext {
            direction: dir,
            bytes,
        });
    }
}
