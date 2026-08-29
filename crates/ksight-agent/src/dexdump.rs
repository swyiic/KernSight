//! Dump in-memory DEX while the target process still holds decrypted pages.

use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
    time::Instant,
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
}

/// Scan mappings, open FDs, and loaded packer/gadget libraries.
///
/// Writes raw images plus a repaired copy under `repaired/` when the bytes are DEX.
pub fn dump_live_process(pid: u32, dest_dir: &Path, deadline: Instant) -> LiveDump {
    let _ = std::fs::create_dir_all(dest_dir);
    let _ = std::fs::create_dir_all(dest_dir.join("repaired"));
    let maps_path = format!("/proc/{pid}/maps");
    if let Ok(maps) = std::fs::read_to_string(&maps_path) {
        let _ = std::fs::write(dest_dir.join(format!("maps-{pid}.txt")), maps.as_bytes());
    }
    let mut dump = LiveDump::default();
    let memory = dump_process_dex(pid, dest_dir, deadline);
    dump.memory_images = memory.dex;
    dump.vdex_images = memory.vdex;
    dump.fd_images = dump_process_fds(pid, dest_dir, deadline);
    dump.native_libs = dump_loaded_sos(pid, dest_dir, deadline);
    dump.packer_regions = dump_packer_regions(pid, dest_dir, deadline);
    dump.key_slots = dump_followed_keys(pid, dest_dir, deadline);
    dump.plaintext_windows = dump_plaintext_windows(pid, dest_dir, deadline);
    dump.blob_dex = dump_payload_blobs(pid, dest_dir, 0);
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
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return MemoryDump::default();
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return MemoryDump::default();
    };
    let _ = std::fs::create_dir_all(dest_dir);
    let repaired_dir = dest_dir.join("repaired");
    let _ = std::fs::create_dir_all(&repaired_dir);
    let mut dumped = MemoryDump::default();
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
        if len < u64::try_from(MIN_DEX).unwrap_or(0x70) || len > MAX_REGION {
            continue;
        }
        if !mapping_worth_reading(path, len, perms) {
            continue;
        }
        let search = search_window(path, perms, len);
        let Some((magic_at, magic)) = find_container_magic(&mut mem, start, search) else {
            continue;
        };
        let kind = container_kind(&magic);
        let want = match kind {
            ContainerKind::Dex | ContainerKind::Cdex => {
                let declared = peek_declared_size(&mut mem, magic_at).unwrap_or(len);
                if declared > MAX_DECLARED {
                    continue;
                }
                declared
                    .max(u64::try_from(MIN_DEX).unwrap_or(0x70))
                    .min(len.saturating_sub(magic_at.saturating_sub(start)))
                    .min(MAX_REGION)
            }
            ContainerKind::Vdex => len.min(MAX_REGION).min(96 * 1024 * 1024),
        };
        let Some(bytes) = read_region(&mut mem, magic_at, want) else {
            continue;
        };
        let ext = match kind {
            ContainerKind::Vdex => "vdex",
            ContainerKind::Cdex => "cdex",
            ContainerKind::Dex => "dex",
        };
        let name = format!("mem-{pid}-{magic_at:x}.{ext}");
        let raw = dest_dir.join(&name);
        if raw.exists() {
            continue;
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

const PLAINTEXT_NEEDLES: [&[u8]; 8] = [
    b"HTTP/1.",
    b"POST /",
    b"GET /",
    b"application/json",
    b"\"password\"",
    b"\"token\"",
    b"Authorization:",
    b"https://",
];
const PLAINTEXT_WINDOW: usize = 2048;
const PLAINTEXT_CAP: usize = 32;

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
        if !(path.is_empty() || path.starts_with('[') || path.starts_with("anon:")) {
            continue;
        }
        let len = end.saturating_sub(start).min(8 * 1024 * 1024);
        if len < 4096 {
            continue;
        }
        let Some(bytes) = read_region(&mut mem, start, len) else {
            continue;
        };
        for needle in PLAINTEXT_NEEDLES {
            let mut from = 0_usize;
            while dumped < PLAINTEXT_CAP {
                if Instant::now() >= deadline {
                    return dumped;
                }
                let Some(rel) = find_bytes(&bytes[from..], needle) else {
                    break;
                };
                let at = from.saturating_add(rel);
                let begin = at.saturating_sub(64);
                let stop = (at.saturating_add(PLAINTEXT_WINDOW)).min(bytes.len());
                let slice = &bytes[begin..stop];
                let name = format!("mem-{pid}-{start:x}+{at:x}.txt");
                let dest = out_dir.join(&name);
                if !dest.exists() {
                    let _ = std::fs::write(&dest, slice);
                    dumped = dumped.saturating_add(1);
                }
                from = at.saturating_add(needle.len().max(1));
            }
        }
    }
    dumped
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
const DEXHELPER_GOT_OFFSET: u64 = 0xf3c10;

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

    for (start, end, perms, path) in &maps {
        if packer_got_candidate(path, perms) {
            if let Some(offset) = map_file_offset(&maps_text, *start) {
                if offset == 0 {
                    candidates.push(start.saturating_add(DEXHELPER_GOT_OFFSET));
                }
            }
        }
        if path.contains("anon:.bss")
            || (crate::file::is_interesting_native(path)
                && perms.contains('w')
                && !perms.contains('x'))
        {
            let len = end.saturating_sub(*start);
            if len == 0 || len > PACKER_REGION_CAP {
                continue;
            }
            if let Some(bytes) = read_region(&mut mem, *start, len) {
                collect_pointers(&bytes, &maps, &mut candidates);
            }
        }
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
    let maps: Vec<(u64, u64, String, String)> = maps_text
        .lines()
        .filter_map(|line| {
            let (start, end, perms, path) = parse_map_line(line)?;
            Some((start, end, perms.to_owned(), path.to_owned()))
        })
        .collect();
    let key_dir = dest_dir.join("packer-keys");
    let _ = std::fs::create_dir_all(&key_dir);
    let probes = load_cipher_probes(dest_dir);
    let mut poll = KeyPoll {
        blob_dex: harvest_payload_blobs(pid, dest_dir, &maps, &mut mem, seq),
        ..KeyPoll::default()
    };
    let mut got_addrs = Vec::<u64>::new();
    for (start, _end, perms, path) in &maps {
        if !packer_got_candidate(path, perms) {
            continue;
        }
        let Some(offset) = map_file_offset(&maps_text, *start) else {
            continue;
        };
        if offset == 0 {
            got_addrs.push(start.saturating_add(DEXHELPER_GOT_OFFSET));
        }
    }
    got_addrs.sort_unstable();
    got_addrs.dedup();
    if seq == 0 && !probes.is_empty() {
        if let Some(first) = probes.first() {
            let _ = std::fs::write(key_dir.join("cipher-probe.bin"), first);
        }
    }
    let mut got_live = false;
    for got in &got_addrs {
        let Some(word) = read_region(&mut mem, *got, 16) else {
            continue;
        };
        let path = key_dir.join(format!("got-{pid}-{seq:04}-{got:x}.bin"));
        if std::fs::write(&path, &word).is_ok() {
            poll.dumped = poll.dumped.saturating_add(1);
        }
        if word.len() >= 8 {
            let ptr = u64::from_le_bytes(word[0..8].try_into().unwrap_or([0; 8]));
            got_live = got_live || looks_like_heap_ptr(ptr);
        }
        poll.dumped = poll.dumped.saturating_add(dump_ptr_chain(
            &mut mem, &maps, &key_dir, pid, seq, &word, 0,
        ));
        if got_live {
            if let Some((at, bytes)) = read_heap_around_ptr(&mut mem, &maps, &word) {
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
            live_scan_key_maps(&mut mem, &maps, &probes, &got_addrs, &key_dir, pid, seq);
        poll.dumped = poll.dumped.saturating_add(1);
    }
    if let Some(key) = poll.recovered_key {
        let _ = std::fs::write(key_dir.join("recovered-sm4.bin"), key);
    }
    poll
}

const PAYLOAD_BLOB_MIN: u64 = 4 * 1024 * 1024;
const PAYLOAD_BLOB_MAX: u64 = 160 * 1024 * 1024;

fn dump_payload_blobs(pid: u32, dest_dir: &Path, seq: u32) -> usize {
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
    harvest_payload_blobs(pid, dest_dir, &maps, &mut mem, seq)
}

fn harvest_payload_blobs(
    pid: u32,
    dest_dir: &Path,
    maps: &[(u64, u64, String, String)],
    mem: &mut File,
    seq: u32,
) -> usize {
    let hints = apk_blob_sizes(dest_dir);
    let mut candidates = Vec::<(u64, u64, u64, String)>::new();
    for (start, end, perms, path) in maps {
        let len = end.saturating_sub(*start);
        if !is_payload_blob_map(path, perms, len, &hints) {
            continue;
        }
        let dist = hints
            .iter()
            .map(|hint| len.abs_diff(*hint))
            .min()
            .unwrap_or(len);
        candidates.push((dist, *start, len, path.clone()));
    }
    candidates.sort_unstable();
    let mut harvested = 0_usize;
    for (_, start, len, map_path) in candidates.into_iter().take(12) {
        harvested = harvested.saturating_add(harvest_one_blob(
            mem, dest_dir, pid, start, len, seq, &map_path,
        ));
    }
    harvested
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
) -> usize {
    let parent = dest_dir.parent().unwrap_or(dest_dir);
    let marker = dest_dir
        .join("blob-dex")
        .join(format!("{pid}-{start:x}.ok"));
    if marker.exists() {
        return 0;
    }
    let peek_len = len.min(1024 * 1024);
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

fn is_payload_blob_map(path: &str, perms: &str, len: u64, hints: &[u64]) -> bool {
    if !perms.contains('r') || !perms.contains('w') {
        return false;
    }
    if path.starts_with('/') {
        return false;
    }
    if skip_art_heap(path) {
        return false;
    }
    blob_len_matches(len, hints)
}

fn skip_art_heap(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/system/")
        || lower.starts_with("/apex/")
        || lower.starts_with("/vendor/")
        || lower.contains("dalvik")
        || lower.contains("jit-cache")
        || lower.contains("stack_and_tls")
        || lower.contains("primary_reserve")
}

fn blob_len_matches(len: u64, hints: &[u64]) -> bool {
    if !(PAYLOAD_BLOB_MIN..=PAYLOAD_BLOB_MAX).contains(&len) {
        return false;
    }
    if hints.is_empty() {
        return true;
    }
    hints.iter().any(|hint| {
        if *hint < PAYLOAD_BLOB_MIN {
            return false;
        }
        let lo = (*hint / 2).max(PAYLOAD_BLOB_MIN);
        let hi = hint.saturating_mul(2).clamp(lo, PAYLOAD_BLOB_MAX);
        (lo..=hi).contains(&len)
    })
}

fn packer_got_candidate(path: &str, perms: &str) -> bool {
    if !perms.contains('x') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    crate::file::is_interesting_native(path)
        && (lower.contains("dexhelper")
            || lower.contains("dexjni")
            || lower.contains("secneo")
            || lower.contains("apkwrapper"))
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
    let got = *got_addrs.first()?;
    let word = read_region(mem, got, 16)?;
    if word.len() < 8 {
        return None;
    }
    let ptr = u64::from_le_bytes(word[0..8].try_into().unwrap_or([0; 8]));
    if !looks_like_heap_ptr(ptr) {
        return None;
    }
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
    (0x6_0000_0000..=0x00ff_ffff_ffff).contains(&value)
}

fn map_file_offset(maps: &str, start: u64) -> Option<u64> {
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let (a, _) = range.split_once('-')?;
        let mapped = u64::from_str_radix(a, 16).ok()?;
        if mapped != start {
            continue;
        }
        let _perms = fields.next()?;
        let offset = fields.next()?;
        return u64::from_str_radix(offset, 16).ok();
    }
    None
}

fn collect_pointers(bytes: &[u8], maps: &[(u64, u64, String, String)], out: &mut Vec<u64>) {
    let mut offset = 0_usize;
    while offset.saturating_add(8) <= bytes.len() {
        let ptr = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
        offset = offset.saturating_add(8);
        if !(0x6_0000_0000..=0x00ff_ffff_ffff).contains(&ptr) {
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
    for line in maps.lines() {
        if Instant::now() >= deadline {
            break;
        }
        let Some((start, end, _perms, path)) = parse_map_line(line) else {
            continue;
        };
        if path.is_empty()
            || !Path::new(path)
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

fn read_region(mem: &mut File, start: u64, want: u64) -> Option<Vec<u8>> {
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
        assert!(!blob_len_matches(1024 * 1024, &[]));
        assert!(skip_art_heap("[anon:dalvik-main space]"));
        assert!(!skip_art_heap("[anon:scudo:secondary]"));
        assert!(is_payload_blob_map(
            "[anon:scudo:secondary]",
            "rw-p",
            121 * 1024 * 1024,
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
        assert!(!packer_got_candidate(
            "/data/app/x/libfrida-gadget.so",
            "r-xp"
        ));
    }
}
