//! Dump in-memory DEX while the target process still holds decrypted pages.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_REGION: u64 = 64 * 1024 * 1024;
const MAX_DECLARED: u64 = 48 * 1024 * 1024;
const MIN_DEX: usize = 0x70;
const ANON_SEARCH_WINDOW: u64 = 64 * 1024;
const PACKER_REGION_CAP: u64 = 12 * 1024 * 1024;

/// Counts of live images copied from one process.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveDump {
    /// DEX/CDEX images taken from `/proc/<pid>/mem`.
    pub memory_images: usize,
    /// VDEX images taken from memory or named mappings.
    pub vdex_images: usize,
    /// Files copied through `/proc/<pid>/fd`.
    pub fd_images: usize,
    /// Packer/gadget/app `.so` files copied from maps.
    pub native_libs: usize,
    /// Packer/VMP `rwx`/`rw` regions copied as raw blobs.
    pub packer_regions: usize,
    /// Bounded HTTP/JSON-looking windows copied from anonymous memory.
    pub plaintext_windows: usize,
    /// Heap/BSS pointers followed from packer mappings (SM4 key candidates).
    pub key_slots: usize,
    /// DEX images harvested from payload-sized anonymous heaps.
    pub blob_dex: usize,
    /// Adjacent same-path maps joined before a DEX copy.
    pub stitched_spans: usize,
    /// True when the target was `SIGSTOP`'d for the copy.
    pub paused: bool,
    /// Wall time of the paused copy window.
    pub snapshot_ms: u64,
}

/// Scan mappings, open FDs, and loaded packer/gadget libraries.
///
/// Writes raw images plus a repaired copy under `repaired/` when the bytes are DEX.
pub fn dump_live_process(pid: u32, dest_dir: &Path, deadline: Instant) -> LiveDump {
    let _ = std::fs::create_dir_all(dest_dir);
    let _ = std::fs::create_dir_all(dest_dir.join("repaired"));
    let maps_path = format!("/proc/{pid}/maps");
    let maps_text = std::fs::read_to_string(&maps_path).unwrap_or_default();
    if !maps_text.is_empty() {
        let _ = std::fs::write(
            dest_dir.join(format!("maps-{pid}.txt")),
            maps_text.as_bytes(),
        );
    }
    let maps = parse_maps(&maps_text);
    write_mapped_code(pid, dest_dir, &maps);
    let pause = StoppedProcess::enter(pid);
    let started = Instant::now();
    let mut dump = LiveDump {
        paused: pause.active,
        ..LiveDump::default()
    };
    let memory = dump_process_dex_from_maps(pid, dest_dir, deadline, &maps);
    dump.memory_images = memory.dex;
    dump.vdex_images = memory.vdex;
    dump.stitched_spans = dump.stitched_spans.saturating_add(memory.stitched);
    dump.fd_images = dump_process_fds(pid, dest_dir, deadline);
    write_open_code(pid, dest_dir);
    dump.native_libs = dump_loaded_sos(pid, dest_dir, deadline);
    let packer = maps_have_packer_so(&maps);
    if packer {
        dump.packer_regions = dump_packer_regions(pid, dest_dir, deadline);
        dump.key_slots = dump_followed_keys(pid, dest_dir, deadline);
    }
    dump.plaintext_windows = dump_plaintext_windows(pid, dest_dir, deadline);
    let harvest = harvest_payload_blobs(pid, dest_dir, &maps, 0);
    dump.blob_dex = harvest.dex;
    dump.stitched_spans = dump.stitched_spans.saturating_add(harvest.stitched);
    dump.snapshot_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    drop(pause);
    write_snapshot_sidecar(pid, dest_dir, &dump);
    dump
}

/// One GOT/heap poll: dump counts plus a key recovered from live memory, if any.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyPoll {
    /// GOT/BSS/heap snapshots written this round.
    pub dumped: usize,
    /// SM4 key that decrypts `dexdata0` to DEX magic, found in live process memory.
    pub recovered_key: Option<[u8; 16]>,
    /// DEX images taken from payload-sized heaps this round.
    pub blob_dex: usize,
}

/// Poll packer GOT/keys and payload-sized heaps as soon as the PID exists.
///
/// Works for `SecNeo` (`DexHelper`/`dexjni`), concatenated APK DEX, and gadget
/// packers: large anonymous heaps are selected by each package's own payload
/// size, not a per-app address range.
pub fn poll_followed_keys(pid: u32, dest_dir: &Path, seq: u32) -> KeyPoll {
    snapshot_dexhelper_keys(pid, dest_dir, seq)
}

/// Scan `/proc/<pid>/maps` and copy mappings that begin with DEX/CDEX/VDEX magic.
///
/// Writes raw `mem-<pid>-<start>.dex` (or `.vdex`) plus a repaired copy under `repaired/`.
#[must_use]
pub fn dump_process_dex(pid: u32, dest_dir: &Path, deadline: Instant) -> MemoryDump {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    dump_process_dex_from_maps(pid, dest_dir, deadline, &parse_maps(&maps))
}

fn dump_process_dex_from_maps(
    pid: u32,
    dest_dir: &Path,
    deadline: Instant,
    maps: &[MapRow],
) -> MemoryDump {
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return MemoryDump::default();
    };
    let _ = std::fs::create_dir_all(dest_dir);
    let repaired_dir = dest_dir.join("repaired");
    let _ = std::fs::create_dir_all(&repaired_dir);
    let mut dumped = MemoryDump::default();
    for (index, row) in maps.iter().enumerate() {
        if Instant::now() >= deadline {
            break;
        }
        if !row.perms.contains('r') {
            continue;
        }
        let len = row.end.saturating_sub(row.start);
        if len < u64::try_from(MIN_DEX).unwrap_or(0x70) {
            continue;
        }
        if !mapping_worth_reading(&row.path, len, &row.perms) {
            continue;
        }
        let search = search_window(&row.path, &row.perms, len);
        let Some((magic_at, magic)) = find_container_magic(&mut mem, row.start, search) else {
            continue;
        };
        let kind = container_kind(&magic);
        let span_end = extend_span(maps, index, false, MAX_REGION);
        if span_end > row.end {
            dumped.stitched = dumped.stitched.saturating_add(1);
        }
        let available = span_end.saturating_sub(magic_at);
        let want = match kind {
            ContainerKind::Dex | ContainerKind::Cdex => {
                let declared = peek_declared_size(&mut mem, magic_at).unwrap_or(available);
                if declared > MAX_DECLARED {
                    continue;
                }
                declared
                    .max(u64::try_from(MIN_DEX).unwrap_or(0x70))
                    .min(available)
                    .min(MAX_REGION)
            }
            ContainerKind::Vdex => available.min(MAX_REGION).min(96 * 1024 * 1024),
        };
        let Some(bytes) = read_region(&mut mem, magic_at, want) else {
            continue;
        };
        if matches!(kind, ContainerKind::Dex | ContainerKind::Cdex) && bytes.len() < 1024 {
            continue;
        }
        let ext = match kind {
            ContainerKind::Vdex => "vdex",
            ContainerKind::Cdex => "cdex",
            ContainerKind::Dex => "dex",
        };
        let name = format!("mem-{pid}-{magic_at:x}.{ext}");
        let raw = dest_dir.join(&name);
        if raw.exists() {
            let existing = raw.metadata().map(|meta| meta.len()).unwrap_or(0);
            if existing >= u64::try_from(bytes.len()).unwrap_or(0) {
                continue;
            }
        }
        if File::create(&raw)
            .and_then(|mut file| file.write_all(&bytes))
            .is_err()
        {
            continue;
        }
        match kind {
            ContainerKind::Vdex => {
                dumped.vdex = dumped.vdex.saturating_add(1);
            }
            ContainerKind::Dex | ContainerKind::Cdex => {
                if let Some(repaired) = ksight_core::repair_dex(&bytes) {
                    let _ = std::fs::write(repaired_dir.join(&name), repaired.bytes);
                }
                dumped.dex = dumped.dex.saturating_add(1);
            }
        }
    }
    dumped
}

/// Memory-image counts from `/proc/<pid>/mem`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryDump {
    /// DEX/CDEX images.
    pub dex: usize,
    /// VDEX images.
    pub vdex: usize,
    /// Copies that read past the original VMA into an adjacent same-path map.
    pub stitched: usize,
}

/// PIDs whose cmdline starts with `package` or `package:`.
#[must_use]
pub fn pids_for_package(package: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let cmd = cmdline.split(|byte| *byte == 0).next().unwrap_or(&[]);
        let cmd = String::from_utf8_lossy(cmd);
        if cmd == package || cmd.starts_with(&format!("{package}:")) {
            pids.push(pid);
        }
    }
    pids
}

const PLAINTEXT_NEEDLES: [&[u8]; 16] = [
    b"https://",
    b"HTTP/1.",
    b"POST /",
    b"GET /",
    b"\"url\"",
    b"\"host\"",
    b"\"path\"",
    b"/api/",
    b":path",
    b":authority",
    b":method",
    b"application/json",
    b"\"password\"",
    b"\"token\"",
    b"Authorization:",
    b"http://",
];
const PLAINTEXT_WINDOW: usize = 4096;
const PLAINTEXT_CAP: usize = 64;
const PLAINTEXT_PER_NEEDLE: usize = 12;

fn dump_plaintext_windows(pid: u32, dest_dir: &Path, deadline: Instant) -> usize {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return 0;
    };
    let out_dir = dest_dir.join("plaintext");
    let _ = std::fs::create_dir_all(&out_dir);
    let mut dumped = 0_usize;
    let mut seen = BTreeSet::new();
    for line in maps.lines() {
        if Instant::now() >= deadline || dumped >= PLAINTEXT_CAP {
            break;
        }
        let Some((start, end, perms, path)) = parse_map_line(line) else {
            continue;
        };
        if !perms.contains('r') || perms.contains('x') {
            continue;
        }
        if path.starts_with("/system/")
            || path.starts_with("/apex/")
            || path.starts_with("/vendor/")
        {
            continue;
        }
        let lower = path.to_ascii_lowercase();
        let packer_heap = lower.contains("scudo:secondary")
            || path.is_empty()
            || (path.starts_with('[') && !lower.contains("dalvik") && !lower.contains("stack"));
        if !packer_heap {
            continue;
        }
        let len = end.saturating_sub(start).min(8 * 1024 * 1024);
        if len < 64 * 1024 {
            continue;
        }
        let Some(bytes) = read_region(&mut mem, start, len) else {
            continue;
        };
        for needle in PLAINTEXT_NEEDLES {
            let mut from = 0_usize;
            let mut needle_hits = 0_usize;
            while dumped < PLAINTEXT_CAP && needle_hits < PLAINTEXT_PER_NEEDLE {
                if Instant::now() >= deadline {
                    return dumped;
                }
                let Some(rel) = find_bytes(&bytes[from..], needle) else {
                    break;
                };
                let at = from.saturating_add(rel);
                let begin = plaintext_window_begin(&bytes, at, needle);
                let stop = (at.saturating_add(PLAINTEXT_WINDOW)).min(bytes.len());
                let Some(slice) = keep_plaintext_window(&bytes[begin..stop]) else {
                    from = at.saturating_add(needle.len().max(1));
                    continue;
                };
                let fingerprint = plaintext_fingerprint(slice);
                if !seen.insert(fingerprint) {
                    from = at.saturating_add(needle.len().max(1));
                    continue;
                }
                let name = format!("mem-{pid}-{start:x}+{at:x}.txt");
                let dest = out_dir.join(&name);
                if !dest.exists() {
                    let _ = std::fs::write(&dest, slice);
                    dumped = dumped.saturating_add(1);
                    needle_hits = needle_hits.saturating_add(1);
                }
                from = at.saturating_add(needle.len().max(1));
            }
        }
    }
    dumped
}

/// HTTP status/request needles start at the token. JSON/token needles keep 64 bytes of context.
/// Response `HTTP/1.1` lookbehind is neighboring heap, not a URL path.
fn plaintext_window_begin(bytes: &[u8], at: usize, needle: &[u8]) -> usize {
    if needle == b"HTTP/1." {
        let mut index = at;
        while index > 0 {
            let previous = bytes[index - 1];
            if previous.is_ascii_graphic() || previous == b' ' || previous == b'\t' {
                index -= 1;
                continue;
            }
            break;
        }
        return index;
    }
    if needle == b"GET /" || needle == b"POST /" || needle == b"https://" || needle == b"http://" {
        return at;
    }
    at.saturating_sub(64)
}

/// Heap windows are a fixed 4096-byte cut around a needle, not a URL extractor.
/// Drop trailing NULs (allocator padding) and skip slices that are mostly binary.
fn keep_plaintext_window(slice: &[u8]) -> Option<&[u8]> {
    let end = slice
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let trimmed = slice.get(..end)?;
    if trimmed.len() < 24 {
        return None;
    }
    let printable = trimmed
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    let has_url = trimmed.windows(8).any(|window| window == b"https://")
        || trimmed.windows(7).any(|window| window == b"http://")
        || trimmed.windows(7).any(|window| window == b":method")
        || trimmed.windows(5).any(|window| window == b":path");
    if pki_plaintext_window(trimmed) {
        return None;
    }
    let enough = if has_url {
        printable.saturating_mul(5) >= trimmed.len().saturating_mul(2)
    } else {
        printable.saturating_mul(4) >= trimmed.len().saturating_mul(3)
    };
    enough.then_some(trimmed)
}

fn pki_plaintext_window(trimmed: &[u8]) -> bool {
    let pki = contains_ignore_ascii(trimmed, b"digicert")
        || contains_ignore_ascii(trimmed, b"/ocsp")
        || contains_ignore_ascii(trimmed, b".crl")
        || contains_ignore_ascii(trimmed, b"cacerts");
    if !pki {
        return false;
    }
    let useful = trimmed.windows(8).any(|window| window == b"https://")
        || trimmed.windows(7).any(|window| window == b":method")
        || trimmed.windows(5).any(|window| window == b":path")
        || trimmed.windows(5).any(|window| window == b"GET /")
        || trimmed.windows(6).any(|window| window == b"POST /");
    !useful
}

fn contains_ignore_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn plaintext_fingerprint(slice: &[u8]) -> (u64, usize) {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in slice.iter().take(96) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    (hash, slice.len())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn dump_packer_regions(pid: u32, dest_dir: &Path, deadline: Instant) -> usize {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return 0;
    };
    let region_dir = dest_dir.join("packer-mem");
    let repaired_dir = dest_dir.join("repaired");
    let _ = std::fs::create_dir_all(&region_dir);
    let _ = std::fs::create_dir_all(&repaired_dir);
    let mut dumped = 0_usize;
    let mut last_packer_end = 0_u64;
    for line in maps.lines() {
        if Instant::now() >= deadline {
            break;
        }
        let Some((start, end, perms, path)) = parse_map_line(line) else {
            continue;
        };
        if !perms.contains('r') {
            continue;
        }
        let len = end.saturating_sub(start);
        if crate::file::is_interesting_native(path) {
            last_packer_end = end;
        }
        if !packer_region_worth_copying(path, perms, len) {
            continue;
        }
        if path.contains("anon:.bss")
            && (last_packer_end == 0 || start > last_packer_end.saturating_add(0x4_0000))
        {
            continue;
        }
        let Some(bytes) = read_region(&mut mem, start, len) else {
            continue;
        };
        let label = packer_region_label(path);
        let raw = region_dir.join(format!("{pid}-{start:x}-{label}.bin"));
        if raw.exists() {
            continue;
        }
        if File::create(&raw)
            .and_then(|mut file| file.write_all(&bytes))
            .is_err()
        {
            continue;
        }
        dumped = dumped.saturating_add(1);
        for offset in dex_offsets(&bytes) {
            let slice = &bytes[offset..];
            let declared = declared_size(slice).unwrap_or(0);
            let want = declared
                .max(u64::try_from(MIN_DEX).unwrap_or(0x70))
                .min(u64::try_from(slice.len()).unwrap_or(0))
                .min(MAX_DECLARED);
            let take = usize::try_from(want).unwrap_or(0);
            if take < MIN_DEX {
                continue;
            }
            let dex = &slice[..take];
            let name = format!("mem-{pid}-{start:x}+{offset:x}.dex");
            let dest = dest_dir.join(&name);
            if dest.exists() {
                continue;
            }
            if std::fs::write(&dest, dex).is_err() {
                continue;
            }
            if let Some(repaired) = ksight_core::repair_dex(dex) {
                let _ = std::fs::write(repaired_dir.join(&name), repaired.bytes);
            }
        }
    }
    dumped
}

const KEY_SLOT_BYTES: u64 = 128;
const KEY_HEAP_CAP: u64 = 512 * 1024;
const MAX_KEY_SLOTS: usize = 32;

fn dump_followed_keys(pid: u32, dest_dir: &Path, deadline: Instant) -> usize {
    let Ok(maps_text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return 0;
    };
    let maps: Vec<(u64, u64, String, String)> = maps_text
        .lines()
        .filter_map(|line| {
            let (start, end, perms, path) = parse_map_line(line)?;
            Some((start, end, perms.to_owned(), path.to_owned()))
        })
        .collect();
    let key_dir = dest_dir.join("packer-keys");
    let _ = std::fs::create_dir_all(&key_dir);
    let mut dumped = 0_usize;
    let mut seen_maps = Vec::<u64>::new();
    let mut candidates = Vec::<u64>::new();

    if maps
        .iter()
        .any(|(_, _, _, path)| crate::file::is_interesting_native(path))
    {
        collect_packer_pointers(&mut mem, &maps, &mut candidates);
    }

    candidates.sort_unstable();
    candidates.dedup();
    for ptr in candidates.into_iter().take(MAX_KEY_SLOTS) {
        if Instant::now() >= deadline {
            break;
        }
        let Some((map_start, map_end, _, _)) =
            maps.iter().find(|(s, e, _, _)| ptr >= *s && ptr < *e)
        else {
            continue;
        };
        let map_len = map_end.saturating_sub(*map_start);
        if map_len > 0
            && map_len <= KEY_HEAP_CAP
            && seen_maps.len() < 4
            && !seen_maps.contains(map_start)
        {
            seen_maps.push(*map_start);
            if let Some(bytes) = read_region(&mut mem, *map_start, map_len) {
                let path = key_dir.join(format!("heap-{pid}-{map_start:x}.bin"));
                let _ = std::fs::write(path, bytes);
            }
        }
        let Some(slot) = read_region(&mut mem, ptr, KEY_SLOT_BYTES) else {
            continue;
        };
        let path = key_dir.join(format!("slot-{pid}-{ptr:x}.bin"));
        if path.exists() {
            continue;
        }
        if std::fs::write(&path, slot).is_ok() {
            dumped = dumped.saturating_add(1);
        }
    }
    dumped
}

fn snapshot_dexhelper_keys(pid: u32, dest_dir: &Path, seq: u32) -> KeyPoll {
    let Ok(maps_text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return KeyPoll::default();
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return KeyPoll::default();
    };
    let maps = parse_maps(&maps_text);
    let key_maps = maps
        .iter()
        .map(|row| (row.start, row.end, row.perms.clone(), row.path.clone()))
        .collect::<Vec<_>>();
    let key_dir = dest_dir.join("packer-keys");
    let _ = std::fs::create_dir_all(&key_dir);
    let probes = load_cipher_probes(dest_dir);
    let mut poll = KeyPoll {
        blob_dex: harvest_payload_blobs(pid, dest_dir, &maps, seq).dex,
        ..KeyPoll::default()
    };
    let mut got_addrs = Vec::<u64>::new();
    if key_maps
        .iter()
        .any(|(_, _, _, path)| crate::file::is_interesting_native(path))
    {
        collect_packer_pointers(&mut mem, &key_maps, &mut got_addrs);
    }
    got_addrs.sort_unstable();
    got_addrs.dedup();
    got_addrs.truncate(MAX_KEY_SLOTS);
    if seq == 0 && !probes.is_empty() {
        if let Some(first) = probes.first() {
            let _ = std::fs::write(key_dir.join("cipher-probe.bin"), first);
        }
    }
    let mut got_live = false;
    for got in &got_addrs {
        let word = got.to_le_bytes();
        let path = key_dir.join(format!("ptr-{pid}-{seq:04}-{got:x}.bin"));
        if std::fs::write(&path, word).is_ok() {
            poll.dumped = poll.dumped.saturating_add(1);
        }
        got_live = got_live || looks_like_heap_ptr(*got);
        poll.dumped = poll.dumped.saturating_add(dump_ptr_chain(
            &mut mem, &key_maps, &key_dir, pid, seq, &word, 0,
        ));
        if got_live {
            if let Some((at, bytes)) = read_heap_around_ptr(&mut mem, &key_maps, &word) {
                if poll.recovered_key.is_none() && !probes.is_empty() {
                    if let Some(probe) = probes.first() {
                        if probe.len() >= 16 {
                            let mut cipher = [0_u8; 16];
                            cipher.copy_from_slice(&probe[..16]);
                            poll.recovered_key = scan_ptr_window(&bytes, at, &word, &cipher);
                        }
                    }
                }
                let path = key_dir.join(format!("poll-heap-{pid}-{seq:04}-{at:x}.bin"));
                if !path.exists() && std::fs::write(&path, bytes).is_ok() {
                    poll.dumped = poll.dumped.saturating_add(1);
                }
            }
        }
    }
    if poll.recovered_key.is_none() && !probes.is_empty() && !got_addrs.is_empty() {
        poll.recovered_key =
            live_scan_key_maps(&mut mem, &key_maps, &probes, &got_addrs, &key_dir, pid, seq);
        poll.dumped = poll.dumped.saturating_add(1);
    }
    if let Some(key) = poll.recovered_key {
        let _ = std::fs::write(key_dir.join("recovered-sm4.bin"), key);
    }
    poll
}

const PAYLOAD_BLOB_MIN: u64 = 4 * 1024 * 1024;
const PAYLOAD_BLOB_MAX: u64 = 160 * 1024 * 1024;
const APP_FILE_BLOB_MIN: u64 = 512 * 1024;
const BLOB_PEEK_MAX: u64 = 16 * 1024 * 1024;
const BLOB_CANDIDATE_CAP: usize = 16;

fn harvest_payload_blobs(pid: u32, dest_dir: &Path, maps: &[MapRow], seq: u32) -> HarvestStats {
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return HarvestStats::default();
    };
    let hints = apk_blob_sizes(dest_dir);
    let spans = harvest_spans(maps, &hints);
    let mut stats = HarvestStats::default();
    for (class, dist, start, len, map_path, stitched) in spans.into_iter().take(BLOB_CANDIDATE_CAP)
    {
        let _ = (class, dist);
        let written = harvest_one_blob(
            &mut mem, dest_dir, pid, start, len, seq, &map_path, stitched,
        );
        stats.dex = stats.dex.saturating_add(written);
        if written > 0 && stitched > 1 {
            stats.stitched = stats.stitched.saturating_add(1);
        }
    }
    stats
}

#[allow(clippy::too_many_arguments)]
fn harvest_one_blob(
    mem: &mut File,
    dest_dir: &Path,
    pid: u32,
    start: u64,
    len: u64,
    seq: u32,
    map_path: &str,
    vma_count: u32,
) -> usize {
    let parent = dest_dir.parent().unwrap_or(dest_dir);
    let marker = dest_dir
        .join("blob-dex")
        .join(format!("{pid}-{start:x}.ok"));
    if marker.exists() {
        return 0;
    }
    let peek_len = len.min(BLOB_PEEK_MAX);
    let Some(peek) = read_region(mem, start, peek_len) else {
        return 0;
    };
    if find_dex_magic_offset(&peek).is_none() {
        return 0;
    }
    let take = len.min(PAYLOAD_BLOB_MAX);
    let Some(bytes) = read_region(mem, start, take) else {
        return 0;
    };
    let slices = ksight_core::split_concatenated_dex(&bytes);
    if slices.is_empty() {
        return 0;
    }
    let split_dir = parent.join("apk-dex").join("split");
    let readable = parent.join("readable-dex");
    let _ = std::fs::create_dir_all(&split_dir);
    let _ = std::fs::create_dir_all(&readable);
    let _ = std::fs::create_dir_all(dest_dir.join("blob-dex"));
    let mut written = 0_usize;
    let mut files = Vec::new();
    for (index, slice) in slices.iter().enumerate() {
        let name = format!("blob-{pid}-{start:x}_part{index:02}_{}.dex", slice.offset);
        let _ = std::fs::write(split_dir.join(&name), &slice.bytes);
        let _ = std::fs::write(readable.join(&name), &slice.bytes);
        files.push(name);
        written = written.saturating_add(1);
    }
    if written > 0 {
        let meta = serde_json::json!({
            "pid": pid,
            "vma_start": start,
            "vma_end": start.saturating_add(len),
            "map_path": (!map_path.is_empty()).then_some(map_path),
            "seq": seq,
            "bytes": bytes.len(),
            "slices": written,
            "files": files,
            "vma_count": vma_count.max(1),
        });
        let json_path = dest_dir
            .join("blob-dex")
            .join(format!("{pid}-{start:x}.json"));
        if let Err(error) = std::fs::write(&json_path, meta.to_string()) {
            eprintln!("blob sidecar {}: {error}", json_path.display());
        }
        let _ = std::fs::write(
            marker,
            format!("seq={seq} bytes={} slices={written}\n", bytes.len()),
        );
        eprintln!("harvested {written} DEX image(s) from pid {pid} heap {start:#x} ({len} bytes)");
    }
    written
}

fn find_dex_magic_offset(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"dex\n")
}

fn apk_blob_sizes(runtime_dir: &Path) -> Vec<u64> {
    let Some(parent) = runtime_dir.parent() else {
        return Vec::new();
    };
    let apk_dex = parent.join("apk-dex");
    let Ok(entries) = std::fs::read_dir(&apk_dex) else {
        return Vec::new();
    };
    let mut sizes = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        let is_dex = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"));
        if !(is_dex || lower.contains("payload") || lower.contains("dexdata")) {
            continue;
        }
        let Ok(meta) = path.metadata() else {
            continue;
        };
        if meta.len() >= 1024 * 1024 {
            sizes.push(meta.len());
        }
    }
    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

fn is_harvestable_blob_map(path: &str, perms: &str, len: u64, hints: &[u64]) -> bool {
    if skip_blob_noise(path) {
        return false;
    }
    if is_payload_blob_map(path, perms, len, hints) {
        return true;
    }
    is_writable_app_file_blob(path, perms, len)
}

fn is_payload_blob_map(path: &str, perms: &str, len: u64, hints: &[u64]) -> bool {
    if !perms.contains('r') || !perms.contains('w') {
        return false;
    }
    if maps_path_for_match(path).starts_with('/') {
        return false;
    }
    if skip_art_heap(path) {
        return false;
    }
    blob_len_matches(len, hints)
}

/// Writable app-private file overlay (`MAP_PRIVATE` `.so`/`.jar`/`memfd`, not vdex).
fn is_writable_app_file_blob(path: &str, perms: &str, len: u64) -> bool {
    perms.contains('r')
        && perms.contains('w')
        && is_app_private_path(path)
        && !is_installer_code_file(path)
        && !skip_art_heap(path)
        && (APP_FILE_BLOB_MIN..=PAYLOAD_BLOB_MAX).contains(&len)
}

fn maps_path_for_match(path: &str) -> &str {
    path.strip_suffix(" (deleted)")
        .or_else(|| path.strip_suffix("(deleted)"))
        .unwrap_or(path)
        .trim()
}

fn is_os_image_path(path: &str) -> bool {
    let lower = maps_path_for_match(path).to_ascii_lowercase();
    lower.starts_with("/system/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/vendor/")
        || lower.starts_with("/dev/")
        || lower.contains("/dalvik-cache/")
}

fn is_installer_code_file(path: &str) -> bool {
    Path::new(maps_path_for_match(path))
        .extension()
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("vdex")
                || ext.eq_ignore_ascii_case("oat")
                || ext.eq_ignore_ascii_case("art")
                || ext.eq_ignore_ascii_case("apk")
                || ext.eq_ignore_ascii_case("odex")
        })
}

fn is_app_private_path(path: &str) -> bool {
    let path = maps_path_for_match(path);
    if path.is_empty() || is_os_image_path(path) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/data/app/")
        || lower.starts_with("/data/app-")
        || lower.starts_with("/data/data/")
        || lower.starts_with("/data/user/")
        || lower.starts_with("/data/user_de/")
        || lower.starts_with("/mnt/expand/")
        || lower.starts_with("/mnt/user/")
        || lower.starts_with("/memfd:")
}

fn path_is_native_so(path: &str) -> bool {
    Path::new(maps_path_for_match(path))
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
}

/// Keep a heap-blob whose `map_path` is anonymous or an app-private overlay.
#[must_use]
pub(crate) fn keep_heap_blob_map_path(path: &str) -> bool {
    let path = maps_path_for_match(path);
    if !path.starts_with('/') {
        return true;
    }
    is_app_private_path(path) && !is_installer_code_file(path)
}

fn skip_blob_noise(path: &str) -> bool {
    let lower = maps_path_for_match(path).to_ascii_lowercase();
    lower.contains("[stack")
        || lower.contains("stack_and_tls")
        || lower.contains("bitmap")
        || lower.contains("card table")
        || lower.contains("compaction buffers")
}

pub(crate) fn blob_map_class(path: &str) -> u8 {
    let lower = maps_path_for_match(path).to_ascii_lowercase();
    if lower.contains("scudo:secondary") {
        0
    } else if (path_is_native_so(path) && is_app_private_path(path))
        || (lower.starts_with("/memfd:") && !lower.contains("jit"))
    {
        1
    } else if path.is_empty()
        || path == "[anon]"
        || lower.contains("anon:.bss")
        || (path.starts_with("[anon]") && !lower.contains("dalvik"))
    {
        2
    } else if is_app_private_path(path) {
        3
    } else if lower.contains("scudo") {
        4
    } else {
        5
    }
}

fn skip_art_heap(path: &str) -> bool {
    let lower = maps_path_for_match(path).to_ascii_lowercase();
    lower.starts_with("/system/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/vendor/")
        || lower.contains("dalvik")
        || lower.contains("jit-cache")
        || lower.starts_with("/memfd:jit")
        || lower.contains("stack_and_tls")
        || lower.contains("primary_reserve")
}

fn blob_len_matches(len: u64, _hints: &[u64]) -> bool {
    (PAYLOAD_BLOB_MIN..=PAYLOAD_BLOB_MAX).contains(&len)
}

fn is_instrumentation_so(path: &str) -> bool {
    let lower = maps_path_for_match(path).to_ascii_lowercase();
    lower.contains("frida")
        || lower.contains("gadget")
        || lower.contains("xposed")
        || lower.contains("substrate")
}

fn packer_got_candidate(path: &str, perms: &str) -> bool {
    perms.contains('x') && crate::file::is_interesting_native(path) && !is_instrumentation_so(path)
}

fn maps_have_packer_so(maps: &[MapRow]) -> bool {
    maps.iter()
        .any(|row| crate::file::is_interesting_native(&row.path))
}

fn should_scan_for_keys(
    path: &str,
    perms: &str,
    start: u64,
    maps: &[(u64, u64, String, String)],
) -> bool {
    if is_instrumentation_so(path) {
        return false;
    }
    if packer_got_candidate(path, perms)
        || (crate::file::is_interesting_native(path) && perms.contains('r'))
    {
        return true;
    }
    if !path.contains("anon:.bss") || !perms.contains('w') {
        return false;
    }
    maps.iter().any(|(map_start, map_end, _, map_path)| {
        crate::file::is_interesting_native(map_path)
            && (start.abs_diff(*map_end) < 0x4_0000 || start.abs_diff(*map_start) < 0x4_0000)
    })
}

fn load_cipher_probes(runtime_dir: &Path) -> Vec<Vec<u8>> {
    let Some(parent) = runtime_dir.parent() else {
        return Vec::new();
    };
    let apk_dex = parent.join("apk-dex");
    let Ok(entries) = std::fs::read_dir(&apk_dex) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !lower.contains("payload") && !lower.contains("dexdata") {
            continue;
        }
        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        let mut prefix = [0_u8; 128];
        let Ok(read) = file.read(&mut prefix) else {
            continue;
        };
        let probes = ksight_core::secneo_cipher_probes(&prefix[..read]);
        if !probes.is_empty() {
            return probes;
        }
    }
    Vec::new()
}

fn live_scan_key_maps(
    mem: &mut File,
    maps: &[(u64, u64, String, String)],
    probes: &[Vec<u8>],
    got_addrs: &[u64],
    key_dir: &Path,
    pid: u32,
    seq: u32,
) -> Option<[u8; 16]> {
    let probe = probes.first()?;
    if probe.len() < 16 {
        return None;
    }
    let mut cipher = [0_u8; 16];
    cipher.copy_from_slice(&probe[..16]);
    let mut targets: Vec<(u8, u64, u64)> = Vec::new();
    for (start, end, perms, path) in maps {
        let len = end.saturating_sub(*start);
        let packer = is_packer_key_map(path, perms, *start, maps);
        if !packer {
            continue;
        }
        let rank = u8::from(!(64 * 1024..=512 * 1024).contains(&len));
        targets.push((rank, *start, len));
    }
    targets.sort_unstable_by_key(|item| (item.0, item.1));
    for (_, start, len) in targets {
        if let Some(key) = scan_got_if_live(mem, maps, got_addrs, &cipher, key_dir, pid, seq) {
            return Some(key);
        }
        let Some(bytes) = read_region(mem, start, len) else {
            continue;
        };
        if seq == 0 && len <= 128 * 1024 {
            let out = key_dir.join(format!("poll-bss-{pid}-{seq:04}-{start:x}.bin"));
            let _ = std::fs::write(out, &bytes);
        }
        if let Some(key) = ksight_core::scan_sm4_one_block(&bytes, &cipher, 16, 20_000) {
            let hit = key_dir.join(format!("poll-hit-{pid}-{seq:04}-{start:x}.bin"));
            let _ = std::fs::write(hit, &bytes);
            return Some(key);
        }
    }
    None
}

fn scan_got_if_live(
    mem: &mut File,
    maps: &[(u64, u64, String, String)],
    got_addrs: &[u64],
    cipher: &[u8; 16],
    key_dir: &Path,
    pid: u32,
    seq: u32,
) -> Option<[u8; 16]> {
    let ptr = *got_addrs.first()?;
    if !looks_like_heap_ptr(ptr) {
        return None;
    }
    let word = ptr.to_le_bytes();
    let (at, bytes) = read_heap_around_ptr(mem, maps, &word)?;
    let key = scan_ptr_window(&bytes, at, &word, cipher)?;
    let hit = key_dir.join(format!("poll-hit-{pid}-{seq:04}-{ptr:x}.bin"));
    let _ = std::fs::write(hit, &bytes);
    Some(key)
}

fn scan_ptr_window(
    bytes: &[u8],
    dump_start: u64,
    word: &[u8],
    cipher: &[u8; 16],
) -> Option<[u8; 16]> {
    let ptr = u64::from_le_bytes(word[0..8].try_into().unwrap_or([0; 8]));
    let off = usize::try_from(ptr.saturating_sub(dump_start)).unwrap_or(0);
    let from = off.saturating_sub(1024);
    let to = off.saturating_add(1024).min(bytes.len());
    if to > from + 16 {
        if let Some(key) = ksight_core::scan_sm4_one_block(&bytes[from..to], cipher, 1, 4096) {
            return Some(key);
        }
    }
    ksight_core::scan_sm4_one_block(bytes, cipher, 8, 40_000)
}

fn read_heap_around_ptr(
    mem: &mut File,
    maps: &[(u64, u64, String, String)],
    word: &[u8],
) -> Option<(u64, Vec<u8>)> {
    if word.len() < 8 {
        return None;
    }
    let ptr = u64::from_le_bytes(word[0..8].try_into().unwrap_or([0; 8]));
    let (start, end, _, _) = maps
        .iter()
        .find(|(map_start, map_end, _, _)| ptr >= *map_start && ptr < *map_end)?;
    let len = end.saturating_sub(*start);
    if len == 0 {
        return None;
    }
    if len <= KEY_HEAP_CAP {
        return read_region(mem, *start, len).map(|bytes| (*start, bytes));
    }
    let half = 128 * 1024;
    let at = ptr.saturating_sub(half).max(*start);
    let want = (*end).saturating_sub(at).min(256 * 1024);
    read_region(mem, at, want).map(|bytes| (at, bytes))
}

fn is_packer_key_map(
    path: &str,
    perms: &str,
    start: u64,
    maps: &[(u64, u64, String, String)],
) -> bool {
    if !perms.contains('w') {
        return false;
    }
    if is_dexhelper_rw(path, perms, start, maps) {
        return true;
    }
    crate::file::is_interesting_native(path)
}

fn is_dexhelper_rw(
    path: &str,
    perms: &str,
    start: u64,
    maps: &[(u64, u64, String, String)],
) -> bool {
    if !perms.contains('w') {
        return false;
    }
    if path.to_ascii_lowercase().contains("dexhelper") {
        return true;
    }
    if !path.contains("anon:.bss") {
        return false;
    }
    maps.iter().any(|(map_start, map_end, _, map_path)| {
        map_path.to_ascii_lowercase().contains("dexhelper")
            && (start.abs_diff(*map_end) < 0x4_0000 || start.abs_diff(*map_start) < 0x4_0000)
    })
}

fn dump_ptr_chain(
    mem: &mut File,
    maps: &[(u64, u64, String, String)],
    key_dir: &Path,
    pid: u32,
    seq: u32,
    word: &[u8],
    depth: u32,
) -> usize {
    if depth > 2 || word.len() < 8 {
        return 0;
    }
    let ptr = u64::from_le_bytes(word[0..8].try_into().unwrap_or([0; 8]));
    if !looks_like_heap_ptr(ptr) {
        return 0;
    }
    let mapped = maps.iter().any(|(start, end, perms, path)| {
        ptr >= *start
            && ptr < *end
            && perms.contains('w')
            && !path.starts_with("/system/")
            && !path.starts_with("/apex/")
    });
    if !mapped {
        return 0;
    }
    let mut dumped = 0_usize;
    let at = ptr.saturating_sub(16);
    if let Some(slot) = read_region(mem, at, KEY_SLOT_BYTES) {
        let path = key_dir.join(format!("slot-{pid}-{seq:04}-d{depth}-{ptr:x}.bin"));
        if std::fs::write(&path, &slot).is_ok() {
            dumped = dumped.saturating_add(1);
        }
        if slot.len() >= 24 {
            dumped = dumped.saturating_add(dump_ptr_chain(
                mem,
                maps,
                key_dir,
                pid,
                seq,
                &slot[16..24],
                depth.saturating_add(1),
            ));
        }
    }
    dumped
}

fn looks_like_heap_ptr(value: u64) -> bool {
    if value < 0x1000 {
        return false;
    }
    if value <= 0xbfff_ffff {
        return true;
    }
    (0x1_0000_0000..=0x0000_7fff_ffff_ffff).contains(&value)
}

fn collect_packer_pointers(
    mem: &mut File,
    maps: &[(u64, u64, String, String)],
    out: &mut Vec<u64>,
) {
    for (start, end, perms, path) in maps {
        if !perms.contains('r') {
            continue;
        }
        if !should_scan_for_keys(path, perms, *start, maps) {
            continue;
        }
        let len = end.saturating_sub(*start);
        if len == 0 || len > PACKER_REGION_CAP {
            continue;
        }
        if let Some(bytes) = read_region(mem, *start, len) {
            collect_pointers(&bytes, maps, out);
        }
    }
}

fn collect_pointers(bytes: &[u8], maps: &[(u64, u64, String, String)], out: &mut Vec<u64>) {
    let mut offset = 0_usize;
    while offset.saturating_add(8) <= bytes.len() {
        let ptr = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
        offset = offset.saturating_add(8);
        if !looks_like_heap_ptr(ptr) {
            continue;
        }
        let mapped = maps.iter().any(|(start, end, perms, path)| {
            ptr >= *start
                && ptr < *end
                && perms.contains('w')
                && !path.starts_with("/system/")
                && !path.starts_with("/apex/")
        });
        if mapped && !out.contains(&ptr) {
            out.push(ptr);
        }
    }
}

fn packer_region_worth_copying(path: &str, perms: &str, len: u64) -> bool {
    if !(0x1000..=PACKER_REGION_CAP).contains(&len) {
        return false;
    }
    if path.starts_with("/system/") || path.starts_with("/apex/") || path.starts_with("/vendor/") {
        return false;
    }
    if crate::file::is_interesting_native(path) {
        return perms.contains('x') || perms.contains('w');
    }
    if path.contains("anon:.bss") {
        return perms.contains('r');
    }
    (path.is_empty() || path.starts_with("[anon") || path.starts_with("anon:"))
        && perms.contains('x')
        && perms.contains('w')
}

fn packer_region_label(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .map_or_else(
            || "anon-rwx".to_owned(),
            |name| name.replace(['/', '\\', ':'], "_"),
        )
}

fn search_window(path: &str, perms: &str, len: u64) -> u64 {
    if crate::file::is_interesting_native(path) || (perms.contains('x') && perms.contains('w')) {
        len.min(PACKER_REGION_CAP)
    } else if path.is_empty() || path.starts_with('[') {
        ANON_SEARCH_WINDOW.min(len)
    } else {
        8
    }
}

fn dex_offsets(buf: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut index = 0_usize;
    while index.saturating_add(4) <= buf.len() {
        if ksight_core::is_dex_magic(&buf[index..]) {
            offsets.push(index);
            if let Some(declared) = declared_size(&buf[index..]) {
                let skip = usize::try_from(declared).unwrap_or(0);
                if skip >= MIN_DEX && index.saturating_add(skip) <= buf.len() {
                    index = index.saturating_add(skip);
                    continue;
                }
            }
        }
        index = index.saturating_add(4);
    }
    offsets
}

fn declared_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 36 {
        return None;
    }
    Some(u64::from(u32::from_le_bytes(
        bytes[32..36].try_into().ok()?,
    )))
}

fn dump_process_fds(pid: u32, dest_dir: &Path, deadline: Instant) -> usize {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return 0;
    };
    let fd_dir = dest_dir.join("fd");
    let repaired_dir = dest_dir.join("repaired");
    let _ = std::fs::create_dir_all(&fd_dir);
    let mut dumped = 0_usize;
    for entry in entries.flatten() {
        if Instant::now() >= deadline {
            break;
        }
        let name = entry.file_name();
        let Some(fd) = name.to_str().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let proc_fd = format!("/proc/{pid}/fd/{fd}");
        let target = std::fs::read_link(&proc_fd)
            .ok()
            .and_then(|path| path.to_str().map(str::to_owned))
            .unwrap_or_default();
        if skip_fd_target(&target) {
            continue;
        }
        let Ok(mut file) = File::open(&proc_fd) else {
            continue;
        };
        let mut magic = [0_u8; 8];
        if file.read_exact(&mut magic).is_err() {
            continue;
        }
        let dex = ksight_core::is_dex_magic(&magic);
        let vdex = ksight_core::is_vdex_magic(&magic);
        let interesting_name = fd_target_interesting(&target);
        if !dex && !vdex && !interesting_name {
            continue;
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            continue;
        }
        let cap = if dex || vdex {
            MAX_DECLARED
        } else {
            12 * 1024 * 1024
        };
        let ext = if vdex {
            "vdex"
        } else if dex {
            "dex"
        } else {
            Path::new(&target)
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("bin")
        };
        let base = Path::new(&target)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("blob")
            .replace(['/', '\\', ':'], "_");
        let out = fd_dir.join(format!("fd-{pid}-{fd}-{base}.{ext}"));
        if out.exists() {
            continue;
        }
        let Ok(copied) = copy_capped(&mut file, &out, cap) else {
            let _ = std::fs::remove_file(&out);
            continue;
        };
        if copied == 0 {
            let _ = std::fs::remove_file(&out);
            continue;
        }
        if dex {
            if let Ok(bytes) = std::fs::read(&out) {
                if let Some(repaired) = ksight_core::repair_dex(&bytes) {
                    let _ = std::fs::write(
                        repaired_dir.join(out.file_name().unwrap_or_default()),
                        repaired.bytes,
                    );
                }
            }
        }
        dumped = dumped.saturating_add(1);
    }
    dumped
}

fn dump_loaded_sos(pid: u32, dest_dir: &Path, deadline: Instant) -> usize {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    let so_dir = dest_dir.join("runtime-so");
    let _ = std::fs::create_dir_all(&so_dir);
    let mut seen = Vec::<String>::new();
    let mut dumped = 0_usize;
    let mut extracted_apk = Vec::<String>::new();
    for line in maps.lines() {
        if Instant::now() >= deadline {
            break;
        }
        let Some((start, end, perms, path)) = parse_map_line(line) else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        if apk_embedded_native(path, perms) {
            if !extracted_apk.iter().any(|existing| existing == path) {
                extracted_apk.push(path.to_owned());
                dumped = dumped.saturating_add(extract_mapped_apk_native(path, &so_dir, pid));
            }
            continue;
        }
        if !Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            continue;
        }
        if !crate::file::is_interesting_native(path) && !path.contains("/data/") {
            continue;
        }
        if path.starts_with("/system/")
            || path.starts_with("/apex/")
            || path.starts_with("/vendor/")
        {
            continue;
        }
        if seen.iter().any(|existing| existing == path) {
            continue;
        }
        seen.push(path.to_owned());
        let name = Path::new(path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("lib.so");
        let dest = so_dir.join(format!("{pid}-{name}"));
        if dest.exists() {
            continue;
        }
        let copied = std::fs::copy(path, &dest).ok().or_else(|| {
            let map_file = format!("/proc/{pid}/map_files/{start:x}-{end:x}");
            std::fs::copy(map_file, &dest).ok()
        });
        if copied.is_some() {
            dumped = dumped.saturating_add(1);
        } else {
            let _ = std::fs::remove_file(&dest);
        }
    }
    dumped
}

fn apk_embedded_native(path: &str, perms: &str) -> bool {
    if !perms.contains('x') || !path.starts_with("/data/app/") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("webview") || lower.contains("trichrome") {
        return false;
    }
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("apk"))
}

fn extract_mapped_apk_native(apk: &str, so_dir: &Path, pid: u32) -> usize {
    let lower = apk.to_ascii_lowercase();
    if !lower.contains("split_config.arm64") && !lower.contains("base.apk") {
        return 0;
    }
    let Ok(extracted) = ksight_core::extract_apk_native_libs(Path::new(apk), so_dir) else {
        return 0;
    };
    let mut renamed = 0_usize;
    for file in extracted {
        let src = so_dir.join(&file.output_name);
        let name = Path::new(&file.output_name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("lib.so");
        let dest = so_dir.join(format!("{pid}-{name}"));
        if dest.exists() {
            let _ = std::fs::remove_file(&src);
            continue;
        }
        if std::fs::rename(&src, &dest).is_ok() || std::fs::copy(&src, &dest).is_ok() {
            renamed = renamed.saturating_add(1);
        }
        let _ = std::fs::remove_file(&src);
    }
    renamed
}

fn copy_capped(input: &mut File, dest: &Path, max_bytes: u64) -> std::io::Result<u64> {
    let mut output = File::create(dest)?;
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            break;
        }
        let take = read.min(usize::try_from(remaining).unwrap_or(read));
        output.write_all(&buffer[..take])?;
        total = total.saturating_add(u64::try_from(take).unwrap_or(0));
        if take < read {
            break;
        }
    }
    Ok(total)
}

fn skip_fd_target(target: &str) -> bool {
    target.starts_with("/dev/")
        || target.starts_with("/sys/")
        || target.starts_with("/proc/")
        || target.starts_with("/apex/")
        || target.starts_with("socket:")
        || target.starts_with("pipe:")
        || target.starts_with("anon_inode:")
}

fn fd_target_interesting(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.contains(".dex")
        || lower.contains(".vdex")
        || lower.contains(".odex")
        || lower.contains(".dve")
        || lower.contains("info.y")
        || crate::file::is_interesting_native(target)
        || lower.contains("(deleted)")
            && (lower.contains("dex") || lower.contains("dalvik") || lower.contains("code_cache"))
}

fn mapping_worth_reading(path: &str, len: u64, perms: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("/system/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/vendor/")
        || lower.starts_with("/dev/")
        || lower.starts_with("/dmabuf")
    {
        return false;
    }
    if Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        || crate::file::is_interesting_native(path)
    {
        return false;
    }
    if matches!(
        path,
        "[heap]" | "[stack]" | "[vdso]" | "[vvar]" | "[vsyscall]" | "[vectors]"
    ) {
        return false;
    }
    if lower.contains("local ref table") || lower.contains("messagequeue") {
        return false;
    }
    if lower.contains(".dex")
        || lower.contains(".vdex")
        || lower.contains(".odex")
        || lower.contains(".art")
        || lower.contains("dalvik")
        || lower.contains("code_cache")
        || lower.contains("dexfile")
        || lower.contains("jit")
    {
        return true;
    }
    let min = u64::try_from(MIN_DEX).unwrap_or(0x70);
    if len < min || len > MAX_DECLARED {
        return false;
    }
    path.is_empty() || path.starts_with("[anon") || path.starts_with("anon:") || perms.contains('x')
}

fn find_container_magic(mem: &mut File, start: u64, window: u64) -> Option<(u64, [u8; 8])> {
    if mem.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let read_len = usize::try_from(window.clamp(8, PACKER_REGION_CAP)).ok()?;
    let mut buf = vec![0_u8; read_len];
    let read = mem.read(&mut buf).ok()?;
    buf.truncate(read);
    if buf.len() < 4 {
        return None;
    }
    for offset in (0..=buf.len().saturating_sub(4)).step_by(4) {
        let Some(kind) = container_kind_at(&buf[offset..]) else {
            continue;
        };
        if offset != 0 && !matches!(kind, ContainerKind::Dex | ContainerKind::Cdex) {
            continue;
        }
        let mut magic = [0_u8; 8];
        let take = buf[offset..].len().min(8);
        magic[..take].copy_from_slice(&buf[offset..offset + take]);
        return Some((start.saturating_add(u64::try_from(offset).ok()?), magic));
    }
    None
}

fn container_kind_at(bytes: &[u8]) -> Option<ContainerKind> {
    if ksight_core::is_dex_magic(bytes) {
        if bytes.starts_with(b"cdex") {
            Some(ContainerKind::Cdex)
        } else {
            Some(ContainerKind::Dex)
        }
    } else if ksight_core::is_vdex_magic(bytes) {
        Some(ContainerKind::Vdex)
    } else {
        None
    }
}

fn container_kind(magic: &[u8]) -> ContainerKind {
    container_kind_at(magic).unwrap_or(ContainerKind::Dex)
}

fn peek_declared_size(mem: &mut File, magic_at: u64) -> Option<u64> {
    if mem
        .seek(SeekFrom::Start(magic_at.saturating_add(32)))
        .is_err()
    {
        return None;
    }
    let mut size = [0_u8; 4];
    mem.read_exact(&mut size).ok()?;
    Some(u64::from(u32::from_le_bytes(size)))
}

pub(crate) fn read_region(mem: &mut File, start: u64, want: u64) -> Option<Vec<u8>> {
    let len = usize::try_from(want).ok()?;
    if len < 4 {
        return None;
    }
    if mem.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut bytes = vec![0_u8; len];
    mem.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerKind {
    Dex,
    Cdex,
    Vdex,
}

#[derive(Debug, Clone, Default)]
struct HarvestStats {
    dex: usize,
    stitched: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MapRow {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) perms: String,
    pub(crate) path: String,
    pub(crate) inode: u64,
}

pub(crate) fn parse_maps(text: &str) -> Vec<MapRow> {
    text.lines()
        .filter_map(|line| {
            let (start, end, perms, path) = parse_map_line(line)?;
            Some(MapRow {
                start,
                end,
                perms: perms.to_owned(),
                path: path.to_owned(),
                inode: parse_map_inode(line).unwrap_or(0),
            })
        })
        .collect()
}

pub(crate) fn extend_span(maps: &[MapRow], index: usize, need_write: bool, max_len: u64) -> u64 {
    let origin = maps[index].start;
    let key = maps_path_for_match(&maps[index].path);
    let mut end = maps[index].end;
    for next in maps.iter().skip(index.saturating_add(1)) {
        if next.start != end {
            break;
        }
        if !next.perms.contains('r') {
            break;
        }
        if need_write && !next.perms.contains('w') {
            break;
        }
        if maps_path_for_match(&next.path) != key {
            break;
        }
        if skip_blob_noise(&next.path) || skip_art_heap(&next.path) {
            break;
        }
        if next.end.saturating_sub(origin) > max_len {
            break;
        }
        end = next.end;
    }
    end
}

pub(crate) fn can_join_harvest(row: &MapRow) -> bool {
    if skip_blob_noise(&row.path) || skip_art_heap(&row.path) {
        return false;
    }
    if !row.perms.contains('r') || !row.perms.contains('w') {
        return false;
    }
    let path = maps_path_for_match(&row.path);
    if path.starts_with('/') {
        return is_app_private_path(path) && !is_installer_code_file(path);
    }
    true
}

fn harvest_spans(maps: &[MapRow], hints: &[u64]) -> Vec<(u8, u64, u64, u64, String, u32)> {
    let mut spans = Vec::new();
    let mut index = 0_usize;
    while index < maps.len() {
        if !can_join_harvest(&maps[index]) {
            index = index.saturating_add(1);
            continue;
        }
        let start = maps[index].start;
        let span_end = extend_span(maps, index, true, PAYLOAD_BLOB_MAX);
        let len = span_end.saturating_sub(start);
        let mut count = 0_u32;
        let mut next = index;
        while next < maps.len() && maps[next].start < span_end && maps[next].end <= span_end {
            count = count.saturating_add(1);
            next = next.saturating_add(1);
        }
        if is_harvestable_blob_map(&maps[index].path, &maps[index].perms, len, hints) {
            let dist = if is_app_private_path(&maps[index].path) {
                0
            } else {
                hints
                    .iter()
                    .map(|hint| len.abs_diff(*hint))
                    .min()
                    .unwrap_or(len)
            };
            spans.push((
                blob_map_class(&maps[index].path),
                dist,
                start,
                len,
                maps[index].path.clone(),
                count.max(1),
            ));
        }
        index = next.max(index.saturating_add(1));
    }
    spans.sort_unstable();
    spans
}

pub(crate) struct StoppedProcess {
    pid: i32,
    pub(crate) active: bool,
}

impl StoppedProcess {
    pub(crate) fn inert() -> Self {
        Self {
            pid: -1,
            active: false,
        }
    }

    pub(crate) fn enter(pid: u32) -> Self {
        let raw = i32::try_from(pid).unwrap_or(-1);
        if raw <= 1 || pid == std::process::id() {
            return Self::inert();
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let active = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(raw),
                nix::sys::signal::Signal::SIGSTOP,
            )
            .is_ok();
            Self { pid: raw, active }
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        Self {
            pid: raw,
            active: false,
        }
    }
}

impl Drop for StoppedProcess {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.pid),
                nix::sys::signal::Signal::SIGCONT,
            );
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = self.pid;
        }
    }
}

fn write_mapped_code(pid: u32, dest_dir: &Path, maps: &[MapRow]) {
    let mut rows = Vec::new();
    let mut loaders = Vec::<serde_json::Value>::new();
    let mut order = 0_u32;
    let mut loader_order = 0_u32;
    for row in maps {
        if is_mapped_code_path(&row.path) {
            order = order.saturating_add(1);
            rows.push(serde_json::json!({
                "pid": pid,
                "order": order,
                "start": row.start,
                "end": row.end,
                "perms": row.perms,
                "path": row.path,
            }));
        }
        if let Some(role) = code_loader_role(&row.path) {
            let path = maps_path_for_match(&row.path);
            if loaders
                .iter()
                .any(|row| row.get("path").and_then(serde_json::Value::as_str) == Some(path))
            {
                continue;
            }
            loader_order = loader_order.saturating_add(1);
            loaders.push(serde_json::json!({
                "pid": pid,
                "order": loader_order,
                "role": role,
                "origin": "maps",
                "path": maps_path_for_match(&row.path),
                "start": row.start,
                "end": row.end,
                "inode": (row.inode != 0).then_some(row.inode),
            }));
        }
    }
    let payload = serde_json::json!({
        "pid": pid,
        "note": "maps order of apk/dex/jar/so, not ClassLoader load order",
        "entries": rows,
    });
    let _ = std::fs::write(
        dest_dir.join(format!("mapped-code-{pid}.json")),
        payload.to_string(),
    );
    let loader_payload = serde_json::json!({
        "pid": pid,
        "note": "path-derived ClassLoader role from maps; not a Java ClassLoader instance",
        "entries": loaders,
    });
    let _ = std::fs::write(
        dest_dir.join(format!("code-loader-{pid}.json")),
        loader_payload.to_string(),
    );
}

fn write_open_code(pid: u32, dest_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return;
    };
    let mut loaders = Vec::new();
    let mut order = 0_u32;
    for entry in entries.flatten() {
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(target) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) else {
            continue;
        };
        let path = target.to_string_lossy();
        let Some(role) = code_loader_role(&path) else {
            continue;
        };
        order = order.saturating_add(1);
        loaders.push(serde_json::json!({
            "pid": pid,
            "order": order,
            "role": role,
            "origin": "fd",
            "path": maps_path_for_match(&path),
            "fd": fd,
        }));
    }
    let payload = serde_json::json!({
        "pid": pid,
        "note": "open apk/dex/jar fds; not a Java ClassLoader instance",
        "entries": loaders,
    });
    let _ = std::fs::write(
        dest_dir.join(format!("open-code-{pid}.json")),
        payload.to_string(),
    );
}

pub(crate) fn code_loader_role(path: &str) -> Option<&'static str> {
    let path = maps_path_for_match(path);
    let lower = path.to_ascii_lowercase();
    if lower.contains("/overlay/") || lower.contains("/auto_generated_rro_") {
        return None;
    }
    let named = Path::new(path).extension().is_some_and(|ext| {
        ext.eq_ignore_ascii_case("dex")
            || ext.eq_ignore_ascii_case("apk")
            || ext.eq_ignore_ascii_case("jar")
            || ext.eq_ignore_ascii_case("zip")
            || ext.eq_ignore_ascii_case("vdex")
    });
    let memfd = lower.starts_with("/memfd:");
    let anon_dex = (lower.contains("[anon") || path.is_empty())
        && (lower.contains("dex") || lower.contains("classes"));
    if !(named || memfd || anon_dex) {
        return None;
    }
    if lower.contains("/framework/")
        || lower.contains("/javalib/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/system/framework")
    {
        return Some("boot");
    }
    if lower.contains("/code_cache/")
        || lower.contains("secondary-dex")
        || lower.contains("/app_dex/")
        || (lower.contains("/oat/") && lower.contains("/data/"))
    {
        return Some("secondary");
    }
    if memfd || anon_dex || !path.starts_with('/') {
        return Some("in_memory");
    }
    if lower.starts_with("/data/app")
        || is_app_private_path(path)
        || lower.contains("/priv-app/")
        || ((lower.starts_with("/system/")
            || lower.starts_with("/system_ext/")
            || lower.starts_with("/product/"))
            && lower.contains("/app/"))
    {
        return Some("install");
    }
    Some("unknown")
}

fn is_mapped_code_path(path: &str) -> bool {
    let path = maps_path_for_match(path);
    if path.is_empty() || is_os_image_path(path) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("/product/overlay/")
        || lower.starts_with("/system_ext/framework/")
        || lower.contains("/auto_generated_rro_")
    {
        return false;
    }
    Path::new(path).extension().is_some_and(|ext| {
        ext.eq_ignore_ascii_case("dex")
            || ext.eq_ignore_ascii_case("apk")
            || ext.eq_ignore_ascii_case("jar")
            || ext.eq_ignore_ascii_case("zip")
            || ext.eq_ignore_ascii_case("so")
    })
}

fn write_snapshot_sidecar(pid: u32, dest_dir: &Path, dump: &LiveDump) {
    let payload = serde_json::json!({
        "pid": pid,
        "paused": dump.paused,
        "torn": !dump.paused,
        "elapsed_ms": dump.snapshot_ms,
        "stitched_spans": dump.stitched_spans,
        "memory_images": dump.memory_images,
        "blob_dex": dump.blob_dex,
        "visibility": "L2 forensic SIGSTOP + /proc/pid/mem copy",
    });
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let _ = std::fs::write(
        dest_dir.join(format!("snapshot-{pid}-{stamp}.json")),
        payload.to_string(),
    );
}

fn parse_map_inode(line: &str) -> Option<u64> {
    let mut fields = line.split_whitespace();
    fields.next()?;
    fields.next()?;
    fields.next()?;
    fields.next()?;
    fields.next()?.parse().ok()
}

fn parse_map_line(line: &str) -> Option<(u64, u64, &str, &str)> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let perms = fields.next()?;
    Some((start, end, perms, maps_pathname(line)))
}

fn maps_pathname(line: &str) -> &str {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        match rest.find(char::is_whitespace) {
            Some(idx) => rest = &rest[idx..],
            None => return "",
        }
    }
    rest.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_and_anonymous_map_lines() {
        let line = "71000000-71002000 r-xp 00001000 08:01 42 /data/user/0/app/code_cache/a.dex";
        let (start, end, perms, path) = parse_map_line(line).expect("line");
        assert_eq!(start, 0x7100_0000);
        assert_eq!(end, 0x7100_2000);
        assert!(perms.contains('r'));
        assert!(path.contains("code_cache"));
        assert!(mapping_worth_reading(path, end - start, perms));
        assert!(!mapping_worth_reading(
            "/system/lib64/libc.so",
            0x10000,
            "r-xp"
        ));
        assert!(mapping_worth_reading("", 0x10000, "r--p"));
        assert!(!mapping_worth_reading("[heap]", 0x10000, "rw-p"));
        assert!(mapping_worth_reading(
            "[anon:dalvik-classes.dex]",
            0x20000,
            "r--p"
        ));
        let unnamed = "6e5de00000-6e60c00000 ---p 00000000 00:00 0 ";
        let (_, _, perms, path) = parse_map_line(unnamed).expect("unnamed");
        assert_eq!(perms, "---p");
        assert!(path.is_empty());
    }

    #[test]
    fn skips_dev_and_socket_fds() {
        assert!(skip_fd_target("/dev/null"));
        assert!(skip_fd_target("socket:[123]"));
        assert!(!skip_fd_target(
            "/data/user/0/app/code_cache/a.dex (deleted)"
        ));
        assert!(fd_target_interesting("/data/app/x/libdexvmp.so"));
    }

    #[test]
    fn apk_embedded_native_is_executable_data_app_apk() {
        assert!(apk_embedded_native(
            "/data/app/~~x==/com.citibank.mobile.hk-y==/split_config.arm64_v8a.apk",
            "r-xp"
        ));
        assert!(apk_embedded_native(
            "/data/app/~~x==/com.citibank.mobile.hk-y==/split_config.arm64_v8a.apk",
            "rwxp"
        ));
        assert!(!apk_embedded_native(
            "/data/app/~~x==/com.citibank.mobile.hk-y==/split_config.arm64_v8a.apk",
            "r--s"
        ));
        assert!(!apk_embedded_native(
            "/data/app/~~x==/com.google.android.webview-y==/base.apk",
            "r-xp"
        ));
        assert!(!apk_embedded_native(
            "/system/framework/framework-res.apk",
            "r-xp"
        ));
    }

    #[test]
    fn copies_packer_rwx_and_finds_embedded_dex() {
        assert!(packer_region_worth_copying(
            "/data/app/x/libDexHelper.so",
            "rwxp",
            0xE_0000
        ));
        assert!(packer_region_worth_copying("", "rwxp", 0x2_0000));
        assert!(!packer_region_worth_copying(
            "/system/lib64/libc.so",
            "r-xp",
            0x2_0000
        ));
        assert_eq!(
            search_window("/data/app/x/libdexvmp.so", "rwxp", 0x10_0000),
            0x10_0000
        );
        let mut dex = vec![0_u8; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&0x70_u32.to_le_bytes());
        assert_eq!(dex_offsets(&dex), vec![0]);
    }

    #[test]
    fn matches_payload_sized_heaps_without_app_specific_addresses() {
        let jiangsu = 124_149_792_u64;
        let guowang = 71_000_000_u64;
        assert!(blob_len_matches(121 * 1024 * 1024, &[jiangsu]));
        assert!(blob_len_matches(70 * 1024 * 1024, &[guowang]));
        assert!(blob_len_matches(20 * 1024 * 1024, &[18 * 1024 * 1024]));
        assert!(!blob_len_matches(512 * 1024 * 1024, &[jiangsu]));
        assert!(!blob_len_matches(256 * 1024, &[jiangsu]));
        assert!(blob_len_matches(12 * 1024 * 1024, &[]));
        assert!(blob_len_matches(12 * 1024 * 1024, &[jiangsu]));
        assert!(!blob_len_matches(1024 * 1024, &[]));
        assert!(skip_art_heap("[anon:dalvik-main space]"));
        assert!(!skip_art_heap("[anon:scudo:secondary]"));
        assert!(is_payload_blob_map(
            "[anon:scudo:secondary]",
            "rw-p",
            121 * 1024 * 1024,
            &[jiangsu]
        ));
        assert!(is_payload_blob_map(
            "[anon:scudo:secondary]",
            "rw-p",
            12 * 1024 * 1024,
            &[jiangsu]
        ));
        assert!(!is_payload_blob_map(
            "[anon:dalvik-main space]",
            "rw-p",
            121 * 1024 * 1024,
            &[jiangsu]
        ));
        assert!(packer_got_candidate("/data/app/x/libDexHelper.so", "r-xp"));
        assert!(packer_got_candidate("/data/app/x/libdexjni.so", "rwxp"));
        assert!(packer_got_candidate("/data/app/x/libjiagu.so", "r-xp"));
        assert!(!packer_got_candidate(
            "/data/app/x/libfrida-gadget.so",
            "r-xp"
        ));
        let overlay = "/data/app/x/lib/arm64/libpayload.so";
        assert!(is_writable_app_file_blob(overlay, "rw-p", 64 * 1024 * 1024));
        assert!(is_harvestable_blob_map(
            overlay,
            "rw-p",
            64 * 1024 * 1024,
            &[]
        ));
        assert!(is_writable_app_file_blob(
            "/data/user_de/0/pkg/code_cache/oat.so (deleted)",
            "rw-p",
            3 * 1024 * 1024
        ));
        assert!(is_writable_app_file_blob(
            "/mnt/expand/0000/user/0/pkg/lib/arm64/libx.so",
            "rw-p",
            8 * 1024 * 1024
        ));
        assert!(is_writable_app_file_blob(
            "/memfd:classes",
            "rw-p",
            6 * 1024 * 1024
        ));
        assert!(!is_payload_blob_map(overlay, "rw-p", 64 * 1024 * 1024, &[]));
        assert!(!is_writable_app_file_blob(
            "/system/lib64/libc.so",
            "rw-p",
            64 * 1024 * 1024
        ));
        assert!(!is_writable_app_file_blob(
            overlay,
            "r-xp",
            64 * 1024 * 1024
        ));
        assert!(!is_writable_app_file_blob(
            "/data/app/x/oat/arm64/base.vdex",
            "rw-p",
            64 * 1024 * 1024
        ));
        assert!(!is_harvestable_blob_map(
            "[stack]",
            "rw-p",
            8 * 1024 * 1024,
            &[]
        ));
        assert!(!keep_heap_blob_map_path("/data/app/x/oat/arm64/base.vdex"));
        assert!(keep_heap_blob_map_path(overlay));
        assert!(keep_heap_blob_map_path("[anon:scudo:secondary]"));
        assert_eq!(blob_map_class("[anon:scudo:secondary]"), 0);
        assert_eq!(blob_map_class(overlay), 1);
        assert!(looks_like_heap_ptr(0x006e_5b25_3000));
        assert!(looks_like_heap_ptr(0x7f00_0000));
        assert!(!looks_like_heap_ptr(0xff));
    }

    #[test]
    fn adjacent_same_path_maps_form_one_span() {
        let maps = vec![
            MapRow {
                start: 0x1000,
                end: 0x2000,
                perms: "rw-p".to_owned(),
                path: "[anon:scudo:secondary]".to_owned(),
                ..MapRow::default()
            },
            MapRow {
                start: 0x2000,
                end: 0x1000 + 5 * 1024 * 1024,
                perms: "rw-p".to_owned(),
                path: "[anon:scudo:secondary]".to_owned(),
                ..MapRow::default()
            },
        ];
        assert_eq!(
            extend_span(&maps, 0, true, PAYLOAD_BLOB_MAX),
            0x1000 + 5 * 1024 * 1024
        );
        let spans = harvest_spans(&maps, &[]);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].3, 5 * 1024 * 1024);
        assert_eq!(spans[0].5, 2);
    }

    #[test]
    fn gap_or_different_path_is_not_stitched() {
        let maps = vec![
            MapRow {
                start: 0x1000,
                end: 0x2000,
                perms: "rw-p".to_owned(),
                path: String::new(),
                ..MapRow::default()
            },
            MapRow {
                start: 0x3000,
                end: 0x4000,
                perms: "rw-p".to_owned(),
                path: String::new(),
                ..MapRow::default()
            },
            MapRow {
                start: 0x4000,
                end: 0x5000,
                perms: "rw-p".to_owned(),
                path: "[anon:libc_malloc]".to_owned(),
                ..MapRow::default()
            },
        ];
        assert_eq!(extend_span(&maps, 0, true, PAYLOAD_BLOB_MAX), 0x2000);
        assert_eq!(extend_span(&maps, 1, true, PAYLOAD_BLOB_MAX), 0x4000);
    }

    #[test]
    fn code_loader_role_from_path_not_java_instance() {
        assert_eq!(
            code_loader_role("/data/app/~~x==/pkg-y==/base.apk"),
            Some("install")
        );
        assert_eq!(
            code_loader_role("/system_ext/priv-app/SettingsGoogle/SettingsGoogle.apk"),
            Some("install")
        );
        assert_eq!(
            code_loader_role("/data/user/0/pkg/code_cache/secondary-dex/base.apk"),
            Some("secondary")
        );
        assert_eq!(
            code_loader_role("/apex/com.android.art/javalib/core-oj.jar"),
            Some("boot")
        );
        assert_eq!(code_loader_role("/memfd:classes.dex"), Some("in_memory"));
        assert_eq!(code_loader_role("/product/overlay/Foo.apk"), None);
        assert_eq!(code_loader_role("/data/app/x/lib/arm64/libfoo.so"), None);
    }

    #[test]
    fn key_scan_skips_bss_without_nearby_packer() {
        let maps = [(
            0x1000_u64,
            0x2000_u64,
            "rw-p".to_owned(),
            "[anon:.bss]".to_owned(),
        )];
        assert!(!should_scan_for_keys("[anon:.bss]", "rw-p", 0x1000, &maps));
        let packer = [
            (
                0x1000_u64,
                0x2000_u64,
                "r-xp".to_owned(),
                "/data/app/x/libDexHelper.so".to_owned(),
            ),
            (
                0x2000_u64,
                0x3000_u64,
                "rw-p".to_owned(),
                "[anon:.bss]".to_owned(),
            ),
        ];
        assert!(should_scan_for_keys("[anon:.bss]", "rw-p", 0x2000, &packer));
        assert!(should_scan_for_keys(
            "/data/app/x/libDexHelper.so",
            "r-xp",
            0x1000,
            &packer
        ));
    }

    #[test]
    fn plaintext_window_starts_at_http_response_not_object_header() {
        let mut bytes = vec![0_u8; 0x40];
        bytes[0x28..0x2c].copy_from_slice(&[0x9d, 0xb8, 0x2f, 0x00]);
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\0Content-Type: image/jpeg\0");
        let at = find_bytes(&bytes, b"HTTP/1.").expect("needle");
        assert_eq!(plaintext_window_begin(&bytes, at, b"HTTP/1."), at);
        let request = b"GET /v6/feed HTTP/1.1\r\nHost: api.example\r\n\r\n";
        let at = find_bytes(request, b"HTTP/1.").expect("request");
        assert_eq!(plaintext_window_begin(request, at, b"HTTP/1."), 0);
        assert_eq!(plaintext_window_begin(request, 0, b"GET /"), 0);
    }

    #[test]
    fn plaintext_window_drops_nul_padding_and_keeps_http_text() {
        let mut padded = b"GET /v1/login HTTP/1.1\r\nHost: api.example\r\n\r\n".to_vec();
        padded.resize(2048, 0);
        let kept = keep_plaintext_window(&padded).expect("http text");
        assert!(kept.starts_with(b"GET /v1/login"));
        assert!(!kept.ends_with(&[0]));
        assert!(kept.len() < 80);
        let zeros = vec![0_u8; 2048];
        assert!(keep_plaintext_window(&zeros).is_none());
        let mut sparse = vec![0_u8; 2048];
        sparse[10..17].copy_from_slice(b"HTTP/1.");
        assert!(keep_plaintext_window(&sparse).is_none());
    }

    #[test]
    fn plaintext_window_keeps_https_and_h2_header_tokens() {
        let https = b"https://api.example/v1/login extra";
        assert_eq!(plaintext_window_begin(https, 0, b"https://"), 0);
        let mut padded = b":method: GET\n:path: /v1/login\n:authority: api.example\n".to_vec();
        padded.resize(2048, 0);
        let kept = keep_plaintext_window(&padded).expect("h2 tokens");
        assert!(kept.windows(5).any(|window| window == b":path"));
        assert!(kept.windows(7).any(|window| window == b":method"));
        let pki =
            b"http://crl.digicert.cn/GeoTrustG2TLSCNRSA4096SHA2562022CA1.crl extra-bytes-here!!";
        assert!(keep_plaintext_window(pki).is_none());
    }
}
