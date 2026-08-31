//! Session-scoped AIDL method names from a process's own DEX.
//!
//! App/GMS stubs are never written into the global AOSP table. A scan of
//! `/proc/<pid>/maps` plus bounded DEX bytes looks up `DESCRIPTOR` and
//! `TRANSACTION_*` on the same class.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

const MAX_DEX_IMAGES: usize = 64;
/// One DEX `file_size` from the header. Spans may be larger; they are walked.
const MAX_IMAGE_BYTES: usize = 48 * 1024 * 1024;
const MIN_DEX: u64 = 0x70;
const MAX_SCANS: u8 = 8;
const GAP_SEARCH: u64 = 64 * 1024;
const TOKEN_WINDOW: usize = 1024 * 1024;
const MAX_CLASS_DEFS: u32 = 20_000;

/// `interface token -> (code -> method name)` extracted from one process.
pub type ProcessAidlTables = HashMap<String, BTreeMap<u32, String>>;

/// Cache of per-PID DEX AIDL tables so each process is scanned once.
#[derive(Debug, Default)]
pub struct ProcessDexAidlCache {
    tables: HashMap<u32, ProcessAidlTables>,
    scans: HashMap<u32, u8>,
    token_miss: HashSet<(u32, String)>,
}

impl ProcessDexAidlCache {
    /// Look up a method for `interface`/`code` in this PID's loaded DEX.
    pub fn lookup(&mut self, pid: u32, interface: &str, code: u32) -> Option<&str> {
        if pid == 0 || interface.is_empty() {
            return None;
        }
        if self.cached(pid, interface, code).is_some() {
            return self.cached(pid, interface, code);
        }
        let scans = self.scans.entry(pid).or_insert(0);
        if *scans < MAX_SCANS {
            *scans = scans.saturating_add(1);
            let extra = scan_process_dex(pid);
            merge_tables(self.tables.entry(pid).or_default(), extra);
        }
        if self.cached(pid, interface, code).is_none()
            && !self.token_miss.contains(&(pid, interface.to_owned()))
        {
            let extra = scan_token(pid, interface);
            merge_tables(self.tables.entry(pid).or_default(), extra);
            if self.cached(pid, interface, code).is_none() {
                self.token_miss.insert((pid, interface.to_owned()));
            }
        }
        self.cached(pid, interface, code)
    }

    fn cached(&self, pid: u32, interface: &str, code: u32) -> Option<&str> {
        self.tables
            .get(&pid)?
            .get(interface)?
            .get(&code)
            .map(String::as_str)
    }
}

/// Convert an AIDL field name into a method identifier.
#[must_use]
pub fn txn_method_name(field: &str) -> Option<String> {
    if let Some(rest) = field.strip_prefix("TRANSACTION_") {
        return (!rest.is_empty()).then(|| rest.to_owned());
    }
    let snake = field.strip_suffix("_TRANSACTION")?;
    let mut parts = snake.split('_');
    let first = parts.next()?.to_ascii_lowercase();
    if first.is_empty() {
        return None;
    }
    let mut name = first;
    for part in parts {
        let mut chars = part.chars();
        if let Some(head) = chars.next() {
            name.push(head.to_ascii_uppercase());
            name.extend(chars.map(|ch| ch.to_ascii_lowercase()));
        }
    }
    (!name.is_empty()).then_some(name)
}

/// `foo.bar.IName` → `Lfoo/bar/IName$Stub;`
#[must_use]
pub fn stub_descriptor(interface: &str) -> String {
    format!("L{}$Stub;", interface.replace('.', "/"))
}

/// Parse Binder Stub tables from one DEX image.
#[must_use]
pub fn parse_binder_tables(bytes: &[u8]) -> ProcessAidlTables {
    parse_binder_tables_inner(bytes).unwrap_or_default()
}

fn parse_binder_tables_inner(bytes: &[u8]) -> Option<ProcessAidlTables> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") || bytes.get(7) != Some(&0) {
        return None;
    }
    if u32_le(bytes, 40)? != 0x1234_5678 {
        return None;
    }
    let string_ids = u32_le(bytes, 56)?;
    let string_ids_off = u32_le(bytes, 60)?;
    let type_ids = u32_le(bytes, 64)?;
    let type_ids_off = u32_le(bytes, 68)?;
    let field_ids = u32_le(bytes, 80)?;
    let field_ids_off = u32_le(bytes, 84)?;
    let method_ids = u32_le(bytes, 88)?;
    let method_ids_off = u32_le(bytes, 92)?;
    let class_defs = u32_le(bytes, 96)?.min(MAX_CLASS_DEFS);
    let class_defs_off = u32_le(bytes, 100)?;
    let ids = DexIds {
        string_ids,
        string_ids_off,
        type_ids,
        type_ids_off,
        field_ids,
        field_ids_off,
        method_ids,
        method_ids_off,
        class_defs,
        class_defs_off,
    };
    Some(assemble_aidl_tables(collect_class_rows(bytes, &ids)))
}

#[derive(Clone, Copy)]
struct DexIds {
    string_ids: u32,
    string_ids_off: u32,
    type_ids: u32,
    type_ids_off: u32,
    field_ids: u32,
    field_ids_off: u32,
    method_ids: u32,
    method_ids_off: u32,
    class_defs: u32,
    class_defs_off: u32,
}

fn collect_class_rows(bytes: &[u8], ids: &DexIds) -> Vec<ClassAidl> {
    let mut rows = Vec::<ClassAidl>::new();
    for index in 0..ids.class_defs {
        let Some(entry) = usize::try_from(ids.class_defs_off).ok().and_then(|base| {
            usize::try_from(index)
                .ok()?
                .checked_mul(32)?
                .checked_add(base)
        }) else {
            continue;
        };
        let Some(row) = parse_class_row(bytes, ids, entry) else {
            continue;
        };
        rows.push(row);
    }
    rows
}

fn parse_class_row(bytes: &[u8], ids: &DexIds, entry: usize) -> Option<ClassAidl> {
    let class_idx = u32_le(bytes, entry)?;
    let class_data_off = entry.checked_add(24).and_then(|off| u32_le(bytes, off))?;
    let static_values_off = entry.checked_add(28).and_then(|off| u32_le(bytes, off))?;
    if class_data_off == 0 {
        return None;
    }
    let class_name = type_at(
        bytes,
        ids.string_ids,
        ids.string_ids_off,
        ids.type_ids,
        ids.type_ids_off,
        class_idx,
    )?;
    let (fields, values, virtual_methods) = class_aidl_body(
        bytes,
        class_data_off,
        static_values_off,
        ids.string_ids,
        ids.string_ids_off,
        ids.method_ids,
        ids.method_ids_off,
    )?;
    let mut descriptor: Option<String> = None;
    let mut named_txns = BTreeMap::new();
    let mut int_codes = Vec::new();
    for (field_idx, value) in fields.into_iter().zip(values) {
        let Some((_, field_name)) = field_at(
            bytes,
            ids.string_ids,
            ids.string_ids_off,
            ids.type_ids,
            ids.type_ids_off,
            ids.field_ids,
            ids.field_ids_off,
            field_idx,
        ) else {
            continue;
        };
        match value {
            Encoded::Int(code) => {
                if let Ok(code) = u32::try_from(code) {
                    if code > 0 && code <= 512 {
                        int_codes.push(code);
                        if let Some(method) = txn_method_name(&field_name) {
                            named_txns.entry(code).or_insert(method);
                        }
                    }
                }
            }
            Encoded::String(text) => {
                if looks_like_descriptor(&text)
                    && (field_name == "DESCRIPTOR" || descriptor.is_none())
                {
                    descriptor = Some(text);
                }
            }
            Encoded::Other => {}
        }
    }
    Some(ClassAidl {
        name: class_name,
        descriptor,
        named_txns,
        int_codes,
        virtual_methods,
    })
}

fn assemble_aidl_tables(rows: Vec<ClassAidl>) -> ProcessAidlTables {
    let interface_methods: HashMap<String, Vec<String>> = rows
        .iter()
        .map(|row| {
            (
                row.name.clone(),
                row.virtual_methods
                    .iter()
                    .filter(|name| keep_aidl_method(name))
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    let mut out = ProcessAidlTables::new();
    for row in rows {
        let mut txns = row.named_txns.clone();
        let token = row
            .descriptor
            .clone()
            .or_else(|| token_from_stub_class(&row.name));
        if txns.is_empty() {
            if let Some(token) = token.as_ref() {
                let iface = format!("L{};", token.replace('.', "/"));
                if let Some(methods) = interface_methods.get(&iface) {
                    for (code, method) in row.int_codes.iter().zip(methods) {
                        txns.entry(*code).or_insert_with(|| method.clone());
                    }
                }
            }
        }
        if txns.is_empty() {
            continue;
        }
        if let Some(token) = token {
            out.entry(token).or_default().extend(txns.clone());
        }
        if let Some(token) = token_from_stub_class(&row.name) {
            out.entry(token).or_default().extend(txns);
        }
    }
    out
}

struct ClassAidl {
    name: String,
    descriptor: Option<String>,
    named_txns: BTreeMap<u32, String>,
    int_codes: Vec<u32>,
    virtual_methods: Vec<String>,
}

fn keep_aidl_method(name: &str) -> bool {
    if matches!(
        name,
        "asBinder" | "onTransact" | "getInterfaceDescriptor" | "getDefaultImpl" | "setDefaultImpl"
    ) || name.starts_with('<')
        || name.len() < 3
        || obfuscated_short_id(name)
    {
        return false;
    }
    name.starts_with(|ch: char| ch.is_ascii_lowercase())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn obfuscated_short_id(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 4 {
        return false;
    }
    let letters = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_lowercase())
        .count();
    (1..=2).contains(&letters)
        && bytes
            .get(letters..)
            .is_some_and(|rest| rest.iter().all(u8::is_ascii_digit))
}

fn looks_like_descriptor(value: &str) -> bool {
    (3..=192).contains(&value.len())
        && value.contains('.')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '$'))
}

fn token_from_stub_class(descriptor: &str) -> Option<String> {
    let inner = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    let inner = inner.strip_suffix("$Stub")?;
    Some(inner.replace('/', "."))
}

#[derive(Debug, Clone)]
enum Encoded {
    Int(i32),
    String(String),
    Other,
}

fn class_aidl_body(
    bytes: &[u8],
    class_data_off: u32,
    static_values_off: u32,
    string_ids: u32,
    string_ids_off: u32,
    method_ids: u32,
    method_ids_off: u32,
) -> Option<(Vec<u32>, Vec<Encoded>, Vec<String>)> {
    let mut cursor = usize::try_from(class_data_off).ok()?;
    let static_fields_size = uleb(bytes, &mut cursor)?;
    let instance = uleb(bytes, &mut cursor)?;
    let direct = uleb(bytes, &mut cursor)?;
    let virtual_count = uleb(bytes, &mut cursor)?;
    let mut field_idx = 0_u32;
    let mut fields = Vec::with_capacity(static_fields_size.min(512) as usize);
    for _ in 0..static_fields_size {
        let diff = uleb(bytes, &mut cursor)?;
        let _access = uleb(bytes, &mut cursor)?;
        field_idx = field_idx.checked_add(diff)?;
        fields.push(field_idx);
    }
    for _ in 0..instance {
        let _diff = uleb(bytes, &mut cursor)?;
        let _access = uleb(bytes, &mut cursor)?;
    }
    let mut encoded_idx = 0_u32;
    for _ in 0..direct {
        let diff = uleb(bytes, &mut cursor)?;
        let _access = uleb(bytes, &mut cursor)?;
        let _code = uleb(bytes, &mut cursor)?;
        encoded_idx = encoded_idx.checked_add(diff)?;
    }
    encoded_idx = 0;
    let mut virtual_methods = Vec::with_capacity(virtual_count.min(64) as usize);
    for _ in 0..virtual_count {
        let diff = uleb(bytes, &mut cursor)?;
        let _access = uleb(bytes, &mut cursor)?;
        let _code = uleb(bytes, &mut cursor)?;
        encoded_idx = encoded_idx.checked_add(diff)?;
        if let Some(name) = method_name_at(
            bytes,
            string_ids,
            string_ids_off,
            method_ids,
            method_ids_off,
            encoded_idx,
        ) {
            virtual_methods.push(name);
        }
    }
    if static_values_off == 0 {
        return Some((fields, Vec::new(), virtual_methods));
    }
    let mut value_cursor = usize::try_from(static_values_off).ok()?;
    let count = uleb(bytes, &mut value_cursor)?;
    let mut values = Vec::with_capacity(count.min(512) as usize);
    for _ in 0..count {
        values.push(encoded_value(bytes, &mut value_cursor).unwrap_or(Encoded::Other));
    }
    Some((fields, values, virtual_methods))
}

fn encoded_value(bytes: &[u8], cursor: &mut usize) -> Option<Encoded> {
    let arg_type = *bytes.get(*cursor)?;
    *cursor = cursor.checked_add(1)?;
    let vtype = arg_type & 0x1f;
    let arg = arg_type >> 5;
    let size = usize::from(arg) + 1;
    match vtype {
        0x00 => {
            let value = i8::from_le_bytes([*bytes.get(*cursor)?]);
            *cursor = cursor.checked_add(1)?;
            Some(Encoded::Int(i32::from(value)))
        }
        0x02..=0x04 => {
            let mut raw = [0_u8; 4];
            for (index, slot) in raw.iter_mut().enumerate().take(size.min(4)) {
                *slot = *bytes.get((*cursor).checked_add(index)?)?;
            }
            *cursor = cursor.checked_add(size)?;
            Some(Encoded::Int(i32::from_le_bytes(raw)))
        }
        0x17 => {
            let mut raw = [0_u8; 4];
            for (index, slot) in raw.iter_mut().enumerate().take(size.min(4)) {
                *slot = *bytes.get((*cursor).checked_add(index)?)?;
            }
            *cursor = cursor.checked_add(size)?;
            let index = u32::from_le_bytes(raw);
            let string_ids = u32_le(bytes, 56)?;
            let string_ids_off = u32_le(bytes, 60)?;
            Some(
                string_at(bytes, string_ids, string_ids_off, index)
                    .map_or(Encoded::Other, Encoded::String),
            )
        }
        0x1e => Some(Encoded::Other),
        0x1f => Some(Encoded::Int(i32::from(arg != 0))),
        0x1c => {
            let count = uleb(bytes, cursor)?;
            for _ in 0..count {
                let _ = encoded_value(bytes, cursor);
            }
            Some(Encoded::Other)
        }
        _ => {
            *cursor = cursor.checked_add(size)?;
            Some(Encoded::Other)
        }
    }
}

fn u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn uleb(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let mut result = 0_u32;
    let mut shift = 0_u32;
    for _ in 0..5 {
        let byte = *bytes.get(*cursor)?;
        *cursor = cursor.checked_add(1)?;
        result |= u32::from(byte & 0x7f).checked_shl(shift)?;
        if byte < 0x80 {
            return Some(result);
        }
        shift = shift.checked_add(7)?;
    }
    None
}

fn string_at(bytes: &[u8], string_ids: u32, string_ids_off: u32, index: u32) -> Option<String> {
    if index >= string_ids {
        return None;
    }
    let entry = usize::try_from(string_ids_off)
        .ok()?
        .checked_add(usize::try_from(index).ok()?.checked_mul(4)?)?;
    let data_off = usize::try_from(u32_le(bytes, entry)?).ok()?;
    let mut cursor = data_off;
    let len = uleb(bytes, &mut cursor)? as usize;
    let slice = bytes.get(cursor..cursor.checked_add(len)?)?;
    Some(String::from_utf8_lossy(slice).into_owned())
}

fn type_at(
    bytes: &[u8],
    string_ids: u32,
    string_ids_off: u32,
    type_ids: u32,
    type_ids_off: u32,
    index: u32,
) -> Option<String> {
    if index >= type_ids {
        return None;
    }
    let entry = usize::try_from(type_ids_off)
        .ok()?
        .checked_add(usize::try_from(index).ok()?.checked_mul(4)?)?;
    string_at(bytes, string_ids, string_ids_off, u32_le(bytes, entry)?)
}

#[allow(clippy::too_many_arguments)]
fn method_name_at(
    bytes: &[u8],
    string_ids: u32,
    string_ids_off: u32,
    method_ids: u32,
    method_ids_off: u32,
    index: u32,
) -> Option<String> {
    if index >= method_ids {
        return None;
    }
    let entry = usize::try_from(method_ids_off)
        .ok()?
        .checked_add(usize::try_from(index).ok()?.checked_mul(8)?)?;
    let name_idx = u32_le(bytes, entry.checked_add(4)?)?;
    string_at(bytes, string_ids, string_ids_off, name_idx)
}

#[allow(clippy::too_many_arguments)]
fn field_at(
    bytes: &[u8],
    string_ids: u32,
    string_ids_off: u32,
    type_ids: u32,
    type_ids_off: u32,
    field_ids: u32,
    field_ids_off: u32,
    index: u32,
) -> Option<(String, String)> {
    if index >= field_ids {
        return None;
    }
    let entry = usize::try_from(field_ids_off)
        .ok()?
        .checked_add(usize::try_from(index).ok()?.checked_mul(8)?)?;
    let class_idx = u16::from_le_bytes(bytes.get(entry..entry + 2)?.try_into().ok()?);
    let name_idx = u32_le(bytes, entry.checked_add(4)?)?;
    Some((
        type_at(
            bytes,
            string_ids,
            string_ids_off,
            type_ids,
            type_ids_off,
            u32::from(class_idx),
        )?,
        string_at(bytes, string_ids, string_ids_off, name_idx)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapSpan {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

fn scan_process_dex(pid: u32) -> ProcessAidlTables {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return ProcessAidlTables::new();
    };
    let maps = parse_maps(&text);
    let mut tables = ProcessAidlTables::new();
    let mut images = 0_usize;
    ingest_file_backed_dex(&maps, &mut tables, &mut images);
    ingest_stitched_dex_data(pid, &maps, &mut tables, &mut images);
    ingest_payload_heaps(pid, &maps, &mut tables, &mut images);
    tables
}

fn parse_maps(text: &str) -> Vec<MapSpan> {
    text.lines()
        .filter_map(|line| {
            let (start, end, perms, path) = parse_map_line(line)?;
            Some(MapSpan {
                start,
                end,
                perms: perms.to_owned(),
                path,
            })
        })
        .collect()
}

/// Merge adjacent same-path readable VMAs. ART splits one DEX across r--/rw-
/// `[anon:dalvik-DEX data]` pages; the header only lives in the first piece.
fn stitch_adjacent(maps: &[MapSpan]) -> Vec<MapSpan> {
    let mut out: Vec<MapSpan> = Vec::new();
    for map in maps {
        if !map.perms.contains('r') {
            continue;
        }
        if let Some(last) = out.last_mut() {
            if last.end == map.start && !map.path.is_empty() && last.path == map.path {
                last.end = map.end;
                continue;
            }
        }
        out.push(map.clone());
    }
    out
}

fn ingest_file_backed_dex(maps: &[MapSpan], tables: &mut ProcessAidlTables, images: &mut usize) {
    let mut seen = BTreeSet::<String>::new();
    for map in maps {
        if *images >= MAX_DEX_IMAGES {
            return;
        }
        if skip_system_path(&map.path) || seen.contains(&map.path) {
            continue;
        }
        if has_ext(&map.path, "dex") && Path::new(&map.path).is_file() {
            seen.insert(map.path.clone());
            if let Ok(bytes) = std::fs::read(&map.path) {
                merge_tables(tables, parse_binder_tables(&bytes));
                *images = images.saturating_add(1);
            }
            continue;
        }
        if (has_ext(&map.path, "apk") || has_ext(&map.path, "jar"))
            && Path::new(&map.path).is_file()
        {
            seen.insert(map.path.clone());
            merge_tables(tables, parse_apk_dex(Path::new(&map.path)));
            *images = images.saturating_add(1);
        }
    }
}

fn ingest_stitched_dex_data(
    pid: u32,
    maps: &[MapSpan],
    tables: &mut ProcessAidlTables,
    images: &mut usize,
) {
    for span in stitch_adjacent(maps) {
        if *images >= MAX_DEX_IMAGES {
            return;
        }
        if !dex_span_eligible(&span.path, span.end.saturating_sub(span.start)) {
            continue;
        }
        walk_span_images(
            pid,
            span.start,
            span.end.saturating_sub(span.start),
            tables,
            images,
        );
    }
}

fn scan_token(pid: u32, token: &str) -> ProcessAidlTables {
    if token.is_empty() || token.len() > 192 {
        return ProcessAidlTables::new();
    }
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return ProcessAidlTables::new();
    };
    let needle = token.as_bytes();
    let mut tables = ProcessAidlTables::new();
    let mut images = 0_usize;
    for span in stitch_adjacent(&parse_maps(&text)) {
        if images >= MAX_DEX_IMAGES {
            break;
        }
        let size = span.end.saturating_sub(span.start);
        if !dex_span_eligible(&span.path, size) {
            continue;
        }
        if !span_has_token(pid, span.start, size, needle) {
            continue;
        }
        walk_span_images(pid, span.start, size, &mut tables, &mut images);
    }
    tables
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ingest_payload_heaps(
    pid: u32,
    maps: &[MapSpan],
    tables: &mut ProcessAidlTables,
    images: &mut usize,
) {
    let mut kept = 0_usize;
    for span in stitch_adjacent(maps) {
        if *images >= MAX_DEX_IMAGES || kept >= 16 {
            return;
        }
        if is_dex_data_map(&span.path)
            || skip_system_path(&span.path)
            || skip_art_non_dex(&span.path)
        {
            continue;
        }
        if !is_payload_heap(&span) {
            continue;
        }
        let before = *images;
        walk_span_images(
            pid,
            span.start,
            span.end.saturating_sub(span.start),
            tables,
            images,
        );
        if *images > before {
            kept = kept.saturating_add(1);
        }
    }
}

/// ART may split one logical DEX across many small VMAs. Eligibility is by
/// map name, not a per-app size range.
fn dex_span_eligible(path: &str, size: u64) -> bool {
    is_dex_data_map(path) && size >= MIN_DEX
}

fn walk_span_images(
    pid: u32,
    start: u64,
    size: u64,
    tables: &mut ProcessAidlTables,
    images: &mut usize,
) {
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return;
    };
    let mut off = 0_u64;
    while off.saturating_add(MIN_DEX) <= size && *images < MAX_DEX_IMAGES {
        let Some(at) = find_magic_offset(&mut mem, start, off, size) else {
            return;
        };
        let remaining = size.saturating_sub(at);
        let Some(bytes) = read_dex_image(&mut mem, start.saturating_add(at), remaining) else {
            off = at.saturating_add(4);
            continue;
        };
        let step = u64::try_from(bytes.len()).unwrap_or(MIN_DEX);
        ingest_dex_bytes(tables, images, &bytes);
        off = at.saturating_add(step);
    }
}

fn find_magic_offset(mem: &mut File, base: u64, from: u64, size: u64) -> Option<u64> {
    let dense_end = from.saturating_add(GAP_SEARCH).min(size);
    let mut off = from;
    while off.saturating_add(8) <= dense_end {
        if peek_is_dex(mem, base.saturating_add(off)) {
            return Some(off);
        }
        off = off.saturating_add(4);
    }
    off = dense_end;
    while off.saturating_add(8) <= size {
        if peek_is_dex(mem, base.saturating_add(off)) {
            return Some(off);
        }
        off = off.saturating_add(4096);
    }
    None
}

fn peek_is_dex(mem: &mut File, at: u64) -> bool {
    peek_magic(mem, at).is_some_and(|magic| magic.starts_with(b"dex\n"))
}

fn peek_magic(mem: &mut File, at: u64) -> Option<[u8; 8]> {
    mem.seek(SeekFrom::Start(at)).ok()?;
    let mut magic = [0_u8; 8];
    mem.read_exact(&mut magic).ok()?;
    Some(magic)
}

fn read_dex_image(mem: &mut File, at: u64, remaining: u64) -> Option<Vec<u8>> {
    if !peek_is_dex(mem, at) {
        return None;
    }
    mem.seek(SeekFrom::Start(at.saturating_add(32))).ok()?;
    let mut size_bytes = [0_u8; 4];
    mem.read_exact(&mut size_bytes).ok()?;
    let declared = usize::try_from(u32::from_le_bytes(size_bytes)).ok()?;
    if !(usize::try_from(MIN_DEX).ok()?..=MAX_IMAGE_BYTES).contains(&declared) {
        return None;
    }
    if u64::try_from(declared).ok()? > remaining {
        return None;
    }
    mem.seek(SeekFrom::Start(at.saturating_add(40))).ok()?;
    let mut endian = [0_u8; 4];
    mem.read_exact(&mut endian).ok()?;
    if u32::from_le_bytes(endian) != 0x1234_5678 {
        return None;
    }
    mem.seek(SeekFrom::Start(at)).ok()?;
    let mut bytes = vec![0_u8; declared];
    mem.read_exact(&mut bytes).ok()?;
    bytes.starts_with(b"dex\n").then_some(bytes)
}

fn span_has_token(pid: u32, start: u64, size: u64, needle: &[u8]) -> bool {
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return false;
    };
    let mut off = 0_u64;
    let overlap = u64::try_from(needle.len().saturating_sub(1)).unwrap_or(0);
    while off < size {
        let take = size
            .saturating_sub(off)
            .min(u64::try_from(TOKEN_WINDOW).unwrap_or(size));
        let Some(buf) = read_exact(&mut mem, start.saturating_add(off), take) else {
            off = off.saturating_add(take.max(1));
            continue;
        };
        if find_bytes(&buf, needle).is_some() {
            return true;
        }
        let step = take.saturating_sub(overlap).max(1);
        off = off.saturating_add(step);
    }
    false
}

fn read_exact(mem: &mut File, at: u64, size: u64) -> Option<Vec<u8>> {
    let len = usize::try_from(size).ok()?;
    if len == 0 {
        return None;
    }
    mem.seek(SeekFrom::Start(at)).ok()?;
    let mut bytes = vec![0_u8; len];
    mem.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

fn ingest_dex_bytes(tables: &mut ProcessAidlTables, images: &mut usize, bytes: &[u8]) {
    let slices = ksight_core::split_concatenated_dex(bytes);
    if slices.is_empty() {
        if bytes.starts_with(b"dex\n") {
            merge_tables(tables, parse_binder_tables(bytes));
            *images = images.saturating_add(1);
        }
        return;
    }
    for slice in slices {
        if *images >= MAX_DEX_IMAGES {
            return;
        }
        merge_tables(tables, parse_binder_tables(&slice.bytes));
        *images = images.saturating_add(1);
    }
}

fn is_dex_data_map(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("dalvik-dex data")
        || lower.contains("dalvik-classes")
        || lower.contains("dalvik-dexfile")
}

fn skip_art_non_dex(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("linearalloc")
        || lower.contains("main space")
        || lower.contains("free list")
        || lower.contains("non moving")
        || lower.contains("zygote space")
        || lower.contains("card table")
        || lower.contains("bitmap")
        || lower.contains("live stack")
        || lower.contains("allocation stack")
        || lower.contains("jit")
        || lower.contains("[stack")
        || lower.contains("[heap]")
}

fn is_payload_heap(span: &MapSpan) -> bool {
    if !span.perms.contains('r') || !span.perms.contains('w') {
        return false;
    }
    let size = span.end.saturating_sub(span.start);
    if size < 64 * 1024 {
        return false;
    }
    let path = span.path.as_str();
    path.is_empty()
        || path == "[anon]"
        || path.to_ascii_lowercase().contains("scudo:secondary")
        || (path.starts_with("[anon") && !path.to_ascii_lowercase().contains("dalvik"))
}

fn has_ext(path: &str, ext: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(ext))
}

fn skip_system_path(path: &str) -> bool {
    path.starts_with("/system/")
        || path.starts_with("/apex/")
        || path.starts_with("/vendor/")
        || path.starts_with("/data/dalvik-cache/")
}

fn parse_map_line(line: &str) -> Option<(u64, u64, &str, String)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let _offset = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.collect::<Vec<_>>().join(" ");
    let (start, end) = range.split_once('-')?;
    Some((
        u64::from_str_radix(start, 16).ok()?,
        u64::from_str_radix(end, 16).ok()?,
        perms,
        path,
    ))
}

fn parse_apk_dex(path: &Path) -> ProcessAidlTables {
    let Ok(file) = File::open(path) else {
        return ProcessAidlTables::new();
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return ProcessAidlTables::new();
    };
    let mut tables = ProcessAidlTables::new();
    let mut kept = 0_usize;
    for index in 0..archive.len() {
        if kept >= 8 {
            break;
        }
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_owned();
        if !has_ext(&name, "dex") {
            continue;
        }
        if entry.size() == 0 || entry.size() > MAX_IMAGE_BYTES as u64 {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            continue;
        }
        drop(entry);
        if bytes.starts_with(b"dex\n") {
            merge_tables(&mut tables, parse_binder_tables(&bytes));
            kept = kept.saturating_add(1);
        }
    }
    tables
}

fn merge_tables(into: &mut ProcessAidlTables, extra: ProcessAidlTables) {
    for (iface, methods) in extra {
        into.entry(iface).or_default().extend(methods);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::{
        dex_span_eligible, is_dex_data_map, keep_aidl_method, merge_tables, parse_binder_tables,
        skip_art_non_dex, stitch_adjacent, stub_descriptor, txn_method_name, MapSpan,
        ProcessAidlTables,
    };

    #[test]
    fn field_names_become_method_ids() {
        assert_eq!(
            txn_method_name("TRANSACTION_shareData").as_deref(),
            Some("shareData")
        );
        assert_eq!(
            txn_method_name("QUERY_TRANSACTION").as_deref(),
            Some("query")
        );
        assert_eq!(
            txn_method_name("GET_TYPE_TRANSACTION").as_deref(),
            Some("getType")
        );
        assert_eq!(txn_method_name("DESCRIPTOR"), None);
    }

    #[test]
    fn stub_descriptor_follows_token() {
        assert_eq!(
            stub_descriptor("cn.jiguang.android.IDataShare"),
            "Lcn/jiguang/android/IDataShare$Stub;"
        );
    }

    fn span(start: u64, end: u64, perms: &str, path: &str) -> MapSpan {
        MapSpan {
            start,
            end,
            perms: perms.to_owned(),
            path: path.to_owned(),
        }
    }

    #[test]
    fn stitches_adjacent_dalvik_dex_data_pages() {
        let maps = [
            span(0x1000, 0x2000, "r--p", "[anon:dalvik-DEX data]"),
            span(0x2000, 0x3000, "rw-p", "[anon:dalvik-DEX data]"),
            span(0x3000, 0x8000, "r--p", "[anon:dalvik-DEX data]"),
            span(0x9000, 0xa000, "r--p", "[anon:dalvik-DEX data]"),
            span(0xa000, 0xb000, "rw-p", "[anon:scudo:secondary]"),
        ];
        let stitched = stitch_adjacent(&maps);
        assert_eq!(stitched.len(), 3);
        assert_eq!(stitched[0].start, 0x1000);
        assert_eq!(stitched[0].end, 0x8000);
        assert_eq!(stitched[1].start, 0x9000);
        assert_eq!(stitched[1].end, 0xa000);
        assert_eq!(stitched[2].path, "[anon:scudo:secondary]");
    }

    #[test]
    fn empty_path_maps_are_not_stitched() {
        let maps = [
            span(0x1000, 0x2000, "rw-p", ""),
            span(0x2000, 0x3000, "rw-p", ""),
        ];
        let stitched = stitch_adjacent(&maps);
        assert_eq!(stitched.len(), 2);
    }

    #[test]
    fn dex_data_maps_are_kept_and_art_heaps_skipped() {
        assert!(is_dex_data_map("[anon:dalvik-DEX data]"));
        assert!(is_dex_data_map("[anon:dalvik-classes.dex]"));
        assert!(skip_art_non_dex("[anon:dalvik-main space]"));
        assert!(skip_art_non_dex("[anon:dalvik-LinearAlloc]"));
        assert!(!skip_art_non_dex("[anon:dalvik-DEX data]"));
        assert!(dex_span_eligible(
            "[anon:dalvik-DEX data]",
            18 * 1024 * 1024
        ));
        assert!(dex_span_eligible(
            "[anon:dalvik-DEX data]",
            40 * 1024 * 1024
        ));
        assert!(!dex_span_eligible("[anon:dalvik-DEX data]", 0x10));
        assert!(!dex_span_eligible(
            "[anon:dalvik-main space]",
            40 * 1024 * 1024
        ));
    }

    #[test]
    fn parses_dumped_process_dex_if_present() {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        let dir = format!(
            "{home}/Desktop/KernSight-reports/mobi.w3studio.apps.android.shsmy.phone/readable-dex"
        );
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"))
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") {
                continue;
            }
            let Some(declared) = bytes.get(32..36) else {
                continue;
            };
            let declared = u32::from_le_bytes(declared.try_into().unwrap()) as usize;
            if declared != bytes.len() {
                continue;
            }
            let _ = parse_binder_tables(&bytes);
        }
    }

    #[test]
    fn parses_idatashare_from_stitched_live_span_if_present() {
        let path = "/tmp/shsmy-stitch/6e6761f000.bin";
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let mut found = ProcessAidlTables::new();
        for slice in ksight_core::split_concatenated_dex(&bytes) {
            merge_tables(&mut found, parse_binder_tables(&slice.bytes));
        }
        let methods = found
            .get("cn.jiguang.android.IDataShare")
            .expect("IDataShare Stub TRANSACTION_* in stitched dalvik-DEX data");
        assert_eq!(methods.get(&1).map(String::as_str), Some("getBinderByType"));
        assert_eq!(methods.get(&2).map(String::as_str), Some("onAction"));
        assert_eq!(methods.get(&3).map(String::as_str), Some("execute"));
        assert_eq!(methods.get(&4).map(String::as_str), Some("bind"));
    }

    #[test]
    fn aidl_method_filter_keeps_real_names() {
        assert!(keep_aidl_method("getDataByType"));
        assert!(keep_aidl_method("call"));
        assert!(keep_aidl_method("onResult"));
        assert!(!keep_aidl_method("a"));
        assert!(!keep_aidl_method("asBinder"));
        assert!(!keep_aidl_method("onTransact"));
    }

    #[test]
    fn parses_content_provider_style_tables_from_framework_if_present() {
        let path = "/tmp/ksight-aidl/framework.jar";
        let Ok(file) = std::fs::File::open(path) else {
            return;
        };
        let Ok(mut archive) = zip::ZipArchive::new(file) else {
            return;
        };
        let Ok(mut entry) = archive.by_name("classes.dex") else {
            return;
        };
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            return;
        }
        let tables = parse_binder_tables(&bytes);
        let provider = tables.get("android.content.IContentProvider");
        if let Some(provider) = provider {
            assert_eq!(provider.get(&1).map(String::as_str), Some("query"));
            assert_eq!(provider.get(&21).map(String::as_str), Some("call"));
        }
    }
}
