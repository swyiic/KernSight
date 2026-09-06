//! Live heap scan for app-layer crypto material during capture.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::time::Instant;

const LOG: &str = "/data/local/tmp/ksight/crypto-watch.log";
const WINDOW: usize = 512;
const CAP: usize = 24;
const MAP_CAP: u64 = 4 * 1024 * 1024;

const NEEDLES: [&[u8]; 16] = [
    b"X-Qen",
    b"X-Sign",
    b"X-Nonce",
    b"X-Token",
    b"getScanItWhiteList",
    b"sysLogin",
    b"\"enc\":",
    b"\"key\":",
    b"AES/CBC",
    b"SM4/",
    b"SM4_decrypt",
    b"appSecret",
    b"encryptSM4",
    b"EncryptionAesUtils",
    b"BHtQRepXEBWle7CJ",
    b"sm4 encrypt keyString",
];

/// Scan one process and append new findings.
pub fn scan_pid(pid: u32, package: &str) -> usize {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return 0;
    };
    let mut seen = load_seen();
    let mut added = 0_usize;
    let started = Instant::now();
    for line in maps.lines() {
        if added >= CAP || started.elapsed().as_millis() > 400 {
            break;
        }
        let Some((start, end, perms, path)) = parse_map(line) else {
            continue;
        };
        if !perms.contains('r') || perms.contains('x') {
            continue;
        }
        if path.starts_with("/system/") || path.starts_with("/apex/") || path.starts_with("/vendor/")
        {
            continue;
        }
        let heap = path.is_empty()
            || path.starts_with('[')
            || path.contains("scudo")
            || path.contains("dalvik");
        if !heap {
            continue;
        }
        let len = end.saturating_sub(start).min(MAP_CAP);
        if len < 4096 {
            continue;
        }
        let Some(bytes) = read_mem(&mut mem, start, len as usize) else {
            continue;
        };
        for needle in NEEDLES {
            let mut from = 0;
            while added < CAP {
                let Some(rel) = bytes[from..].windows(needle.len()).position(|w| w == needle) else {
                    break;
                };
                let at = from + rel;
                let begin = at.saturating_sub(32);
                let end = (at + WINDOW).min(bytes.len());
                let slice = &bytes[begin..end];
                let printable: String = slice
                    .iter()
                    .map(|b| {
                        if (32..127).contains(b) || *b == b'\n' || *b == b'\r' {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let line = format!(
                    "pid={pid} pkg={package} needle={} va={:#x} {}",
                    String::from_utf8_lossy(needle),
                    start + at as u64,
                    printable.replace('\n', " ").chars().take(240).collect::<String>()
                );
                if seen.insert(line.clone()) {
                    append_log(&line);
                    added += 1;
                    eprintln!("crypto-watch {line}");
                }
                from = at + needle.len().max(1);
            }
        }
    }
    added
}

fn parse_map(line: &str) -> Option<(u64, u64, &str, &str)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let perms = parts.next()?;
    let path = line.splitn(6, char::is_whitespace).last().unwrap_or("");
    Some((start, end, perms, path))
}

fn read_mem(mem: &mut File, start: u64, len: usize) -> Option<Vec<u8>> {
    mem.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = vec![0_u8; len];
    let n = mem.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn load_seen() -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(LOG) else {
        return BTreeSet::new();
    };
    text.lines().map(str::to_owned).collect()
}

fn append_log(line: &str) {
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(LOG) else {
        return;
    };
    let _ = writeln!(file, "{line}");
}
