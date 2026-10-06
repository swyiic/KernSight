use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use ksight_model::{CaptureStopReason, Event};
use ksight_protocol::{
    DurableSessionState, DurableSessionSummary, EventBatch, DEFAULT_MAX_FRAME_BYTES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const BATCH_PREFIX: &str = "batch-";
const BATCH_JSON_SUFFIX: &str = ".json";
const BATCH_LZ4_SUFFIX: &str = ".json.lz4";
const MANIFEST_NAME: &str = "session.json";
/// Maximum event-count bound accepted for one durable protocol batch.
pub const MAX_EVENTS_PER_BATCH: usize = 1024;
/// Bytes reserved so a completion event can still be sealed at capacity.
pub const DEFAULT_COMPLETION_RESERVE_BYTES: u64 = 64 * 1024;

/// Writer and directory options for one durable session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolOptions {
    /// Compress each batch independently with LZ4.
    pub compress: bool,
    /// Bytes withheld from ordinary events so completion can be written.
    pub completion_reserve_bytes: u64,
}

impl Default for SpoolOptions {
    fn default() -> Self {
        Self {
            compress: true,
            completion_reserve_bytes: DEFAULT_COMPLETION_RESERVE_BYTES,
        }
    }
}

/// On-disk session inventory that avoids decoding every batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionManifest {
    /// Capture session.
    pub session_id: Uuid,
    /// Lifecycle state.
    pub state: DurableSessionState,
    /// Sealed stop reason, if any.
    pub stop_reason: Option<CaptureStopReason>,
    /// First complete batch.
    pub first_batch_sequence: Option<u64>,
    /// Last complete batch.
    pub last_batch_sequence: Option<u64>,
    /// Complete batch count.
    pub batch_count: u64,
    /// Event count across complete batches.
    pub event_count: u64,
    /// Encoded complete-batch bytes.
    pub used_bytes: u64,
    /// True when new batches are LZ4-framed.
    pub compressed: bool,
    /// Unix milliseconds when the directory was created.
    pub started_unix_ms: u64,
    /// Bounded writer evidence and failure status (absent on legacy manifests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<SpoolWriterDiagnostics>,
}

/// Durable bounded queue used while the USB client is disconnected.
pub trait Spool {
    /// Spool-specific error.
    type Error;

    /// Persist a complete immutable batch.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence or capacity error.
    fn append(&mut self, batch: &EventBatch) -> Result<(), Self::Error>;

    /// Load all unacknowledged batches in sequence order.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence or decoding error.
    fn pending(&self) -> Result<Vec<EventBatch>, Self::Error>;

    /// Discard batches acknowledged by the client.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence error.
    fn acknowledge_through(&mut self, batch_sequence: u64) -> Result<(), Self::Error>;
}

/// Filesystem-backed spool containing one immutable JSON document per batch.
#[derive(Debug)]
pub struct DirectorySpool {
    directory: PathBuf,
    max_bytes: u64,
    used_bytes: u64,
    last_sequence: Option<u64>,
    options: SpoolOptions,
    event_count: u64,
    started_unix_ms: u64,
}

/// Converts normalized events into ordered durable protocol batches for one capture session.
#[derive(Debug)]
pub struct SessionSpoolWriter {
    spool: DirectorySpool,
    session_id: Uuid,
    next_batch_sequence: u64,
    max_events_per_batch: usize,
    events: Vec<StoredEvent>,
    event_bytes: u64,
    pending_since: Option<Instant>,
    blocked: bool,
    manifest_dirty: bool,
    diagnostics: SpoolWriterDiagnostics,
    persisted_batches: u64,
    started: Instant,
}

/// Inspect every UUID-named session directory beneath a spool root.
///
/// Unknown files and non-UUID directories are ignored. Every recognized session is fully decoded
/// and validated so the inventory cannot hide corrupt or cross-session batches.
///
/// # Errors
///
/// Returns an error when the root cannot be read or a recognized session is invalid.
pub fn inspect_root(root: impl AsRef<Path>) -> Result<Vec<DurableSessionSummary>, SpoolError> {
    let root = root.as_ref();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut sessions = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Ok(session_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        sessions.push(summarize_session(entry.path().as_path(), session_id)?);
    }
    sessions.sort_unstable_by_key(|summary| summary.session_id);
    Ok(sessions)
}

fn summarize_session(
    directory: &Path,
    session_id: Uuid,
) -> Result<DurableSessionSummary, SpoolError> {
    if let Some(manifest) = load_manifest(directory)? {
        if manifest.session_id != session_id {
            return Err(SpoolError::DirectorySessionMismatch {
                directory_session: session_id,
                batch_session: manifest.session_id,
            });
        }
        return Ok(DurableSessionSummary {
            session_id,
            batch_count: manifest.batch_count,
            event_count: manifest.event_count,
            first_batch_sequence: manifest.first_batch_sequence,
            last_batch_sequence: manifest.last_batch_sequence,
            used_bytes: manifest.used_bytes,
            state: manifest.state,
            compressed: manifest.compressed,
            started_unix_ms: Some(manifest.started_unix_ms),
            stop_reason: manifest.stop_reason,
        });
    }
    let inventory = scan_inventory(directory)?;
    Ok(DurableSessionSummary {
        session_id,
        batch_count: inventory.batch_count,
        event_count: 0,
        first_batch_sequence: inventory.first_sequence,
        last_batch_sequence: inventory.last_sequence,
        used_bytes: inventory.used_bytes,
        state: DurableSessionState::Running,
        compressed: inventory.compressed,
        started_unix_ms: None,
        stop_reason: None,
    })
}

/// Visit complete batches in sequence without collecting them.
///
/// # Errors
///
/// Returns an error when a batch cannot be decoded or belongs to another session.
///
/// # Panics
/// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
pub fn visit_batches(
    directory: impl AsRef<Path>,
    session_id: Uuid,
    after_batch_sequence: Option<u64>,
    mut visit: impl FnMut(EventBatch) -> Result<(), SpoolError>,
) -> Result<Option<u64>, SpoolError> {
    let mut last = None;
    for (sequence, path, encoding) in list_batch_files(directory.as_ref())? {
        if after_batch_sequence.is_some_and(|after| sequence <= after) {
            continue;
        }
        if last.is_some_and(|previous| sequence <= previous) {
            return Err(SpoolError::NonMonotonicSequence {
                previous: last.unwrap(),
                observed: sequence,
            });
        }
        let batch = decode_batch_file(&path, encoding)?;
        if batch.batch_sequence != sequence {
            return Err(SpoolError::FilenameSequenceMismatch {
                path,
                filename: sequence,
                payload: batch.batch_sequence,
            });
        }
        if batch.session_id != session_id {
            return Err(SpoolError::DirectorySessionMismatch {
                directory_session: session_id,
                batch_session: batch.session_id,
            });
        }
        last = Some(batch.batch_sequence);
        visit(batch)?;
    }
    Ok(last)
}

/// Load a session manifest when present.
///
/// # Errors
///
/// Returns an error for I/O or JSON failure.
pub fn load_manifest(directory: impl AsRef<Path>) -> Result<Option<SessionManifest>, SpoolError> {
    let path = directory.as_ref().join(MANIFEST_NAME);
    match read_bounded(&path, 4096) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(SpoolError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Atomically replace a session manifest.
///
/// # Errors
///
/// Returns an error when the document cannot be written.
pub fn write_manifest(
    directory: impl AsRef<Path>,
    manifest: &SessionManifest,
) -> Result<(), SpoolError> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    let destination = directory.join(MANIFEST_NAME);
    let temporary = directory.join(format!(".manifest-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if bytes.len() > 4096 {
        return Err(SpoolError::BatchTooLarge {
            observed: bytes.len() as u64,
            maximum: 4096,
        });
    }
    write_replace(&temporary, &destination, &bytes)?;
    Ok(())
}

/// Update only lifecycle fields of an existing or synthesized manifest.
///
/// # Errors
///
/// Returns an error when the directory cannot be written.
pub fn mark_session_state(
    directory: impl AsRef<Path>,
    state: DurableSessionState,
    stop_reason: Option<CaptureStopReason>,
) -> Result<(), SpoolError> {
    let directory = directory.as_ref();
    let mut manifest = load_manifest(directory)?.unwrap_or_else(|| SessionManifest {
        session_id: Uuid::nil(),
        state,
        stop_reason,
        first_batch_sequence: None,
        last_batch_sequence: None,
        batch_count: 0,
        event_count: 0,
        used_bytes: 0,
        compressed: false,
        started_unix_ms: unix_ms(),
        writer: None,
    });
    if let Some(name) = directory.file_name().and_then(|name| name.to_str()) {
        if let Ok(session_id) = Uuid::parse_str(name) {
            manifest.session_id = session_id;
        }
    }
    manifest.state = state;
    manifest.stop_reason = stop_reason;
    write_manifest(directory, &manifest)
}

include!("spool_writer.rs");
include!("spool_append.rs");

impl DirectorySpool {
    /// Open or create a single-session spool directory.
    ///
    /// Existing complete batches are validated before accepting new data. Files not matching the
    /// batch filename format are ignored, allowing an interrupted temporary write to remain visible
    /// for operator recovery rather than being deleted silently.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created or existing batches are invalid.
    pub fn open(directory: impl AsRef<Path>, max_bytes: u64) -> Result<Self, SpoolError> {
        Self::open_with(
            directory,
            max_bytes,
            SpoolOptions {
                compress: false,
                completion_reserve_bytes: 0,
            },
        )
    }

    /// Open a session directory with compression and reserve options.
    ///
    /// Existing complete batches are accounted by filename and size so large sessions do not have
    /// to be decoded at open. Files not matching the batch filename format are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created or existing data exceeds capacity.
    pub fn open_with(
        directory: impl AsRef<Path>,
        max_bytes: u64,
        options: SpoolOptions,
    ) -> Result<Self, SpoolError> {
        if max_bytes == 0 {
            return Err(SpoolError::InvalidCapacity);
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let inventory = scan_inventory(&directory)?;
        let used_bytes = inventory.used_bytes;
        let last_sequence = inventory.last_sequence;
        if used_bytes > max_bytes {
            return Err(SpoolError::ExistingDataExceedsCapacity {
                used: used_bytes,
                maximum: max_bytes,
            });
        }
        let started_unix_ms =
            load_manifest(&directory)?.map_or_else(unix_ms, |manifest| manifest.started_unix_ms);
        let event_count = load_manifest(&directory)?.map_or(0, |manifest| manifest.event_count);
        Ok(Self {
            directory,
            max_bytes,
            used_bytes,
            last_sequence,
            options,
            event_count,
            started_unix_ms,
        })
    }

    /// Open an existing spool directory without creating a missing session.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is absent or its contents are invalid.
    pub fn open_existing(directory: impl AsRef<Path>, max_bytes: u64) -> Result<Self, SpoolError> {
        let directory = directory.as_ref();
        if !directory.is_dir() {
            return Err(SpoolError::MissingSession(directory.to_path_buf()));
        }
        Self::open(directory, max_bytes)
    }

    /// Directory holding persisted batches.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Bytes currently occupied by complete unacknowledged batches.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    fn read_pending(&self) -> Result<Vec<PendingBatch>, SpoolError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if !file_type.is_file() {
                continue;
            }
            if let Some((sequence, encoding)) =
                parse_batch_filename(&entry.file_name().to_string_lossy())
            {
                paths.push((sequence, entry.path(), encoding));
            }
        }
        paths.sort_unstable_by_key(|(sequence, _, _)| *sequence);

        let mut pending = Vec::with_capacity(paths.len());
        let mut previous = None;
        let mut session_id = None;
        for (sequence, path, encoding) in paths {
            if previous.is_some_and(|value| sequence <= value) {
                return Err(SpoolError::NonMonotonicSequence {
                    previous: previous.unwrap_or_default(),
                    observed: sequence,
                });
            }
            let batch = match decode_batch_file(&path, encoding) {
                Ok(batch) => batch,
                Err(SpoolError::Io(error)) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if batch.batch_sequence != sequence {
                return Err(SpoolError::FilenameSequenceMismatch {
                    path,
                    filename: sequence,
                    payload: batch.batch_sequence,
                });
            }
            if let Some(expected) = session_id {
                if batch.session_id != expected {
                    return Err(SpoolError::MixedSessions {
                        expected,
                        observed: batch.session_id,
                    });
                }
            } else {
                session_id = Some(batch.session_id);
            }
            previous = Some(sequence);
            let bytes = fs::metadata(&path).map_or(0, |metadata| metadata.len());
            pending.push(PendingBatch { batch, bytes });
        }
        Ok(pending)
    }
}

impl Spool for DirectorySpool {
    type Error = SpoolError;

    fn append(&mut self, batch: &EventBatch) -> Result<(), Self::Error> {
        let (size, _) = measure_json(batch)?;
        if size > u64::from(DEFAULT_MAX_FRAME_BYTES) {
            return Err(SpoolError::BatchTooLarge {
                observed: size,
                maximum: DEFAULT_MAX_FRAME_BYTES,
            });
        }
        let mut json =
            Vec::with_capacity(usize::try_from(size).map_err(|_| SpoolError::CapacityOverflow)?);
        serde_json::to_writer(&mut json, batch)?;
        let completion = batch
            .events
            .iter()
            .all(|e| matches!(e.payload, ksight_model::EventPayload::SessionCompletion(_)));
        self.append_serialized(
            &json,
            batch.batch_sequence,
            batch.events.len() as u64,
            false,
            completion,
            &mut 0,
        )?;
        Ok(())
    }

    fn pending(&self) -> Result<Vec<EventBatch>, Self::Error> {
        self.read_pending()
            .map(|entries| entries.into_iter().map(|entry| entry.batch).collect())
    }

    fn acknowledge_through(&mut self, batch_sequence: u64) -> Result<(), Self::Error> {
        let mut remaining_event_count = 0_u64;
        for entry in self.read_pending()? {
            if entry.batch.batch_sequence > batch_sequence {
                remaining_event_count = remaining_event_count.saturating_add(
                    u64::try_from(entry.batch.events.len())
                        .map_err(|_| SpoolError::CapacityOverflow)?,
                );
                continue;
            }
            let path = batch_path(&self.directory, entry.batch.batch_sequence);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            self.used_bytes = self.used_bytes.saturating_sub(entry.bytes);
            self.event_count = self
                .event_count
                .saturating_sub(u64::try_from(entry.batch.events.len()).unwrap_or(0));
        }
        self.event_count = remaining_event_count;
        if let Some(name) = self.directory.file_name().and_then(|name| name.to_str()) {
            if let Ok(session_id) = Uuid::parse_str(name) {
                let inventory = scan_inventory(&self.directory)?;
                self.used_bytes = inventory.used_bytes;
                if let Some(mut manifest) = load_manifest(&self.directory)? {
                    // ACK changes the pending inventory, not the collector's lifecycle.
                    manifest.first_batch_sequence = inventory.first_sequence;
                    manifest.last_batch_sequence = inventory.last_sequence;
                    manifest.batch_count = inventory.batch_count;
                    manifest.event_count = self.event_count;
                    manifest.used_bytes = inventory.used_bytes;
                    write_manifest(&self.directory, &manifest)?;
                } else {
                    // Legacy directories have no persisted lifecycle to preserve.
                    self.persist_manifest(session_id, DurableSessionState::Running, None)?;
                }
            }
        }
        Ok(())
    }
}

impl DirectorySpool {
    fn reconcile_external_acknowledgements(&mut self) -> Result<(), SpoolError> {
        let inventory = scan_inventory(&self.directory)?;
        let used_bytes = inventory.used_bytes;
        let last_sequence = inventory.last_sequence;
        self.used_bytes = used_bytes;
        if let Some(sequence) = last_sequence {
            self.last_sequence = Some(
                self.last_sequence
                    .map_or(sequence, |previous| previous.max(sequence)),
            );
        }
        Ok(())
    }

    fn event_capacity_exhausted(&self) -> bool {
        let reserve = self.options.completion_reserve_bytes;
        self.used_bytes >= self.max_bytes.saturating_sub(reserve)
    }

    fn manifest(
        &self,
        session_id: Uuid,
        state: DurableSessionState,
        stop_reason: Option<CaptureStopReason>,
    ) -> Result<SessionManifest, SpoolError> {
        let inventory = scan_inventory(&self.directory)?;
        Ok(SessionManifest {
            session_id,
            state,
            stop_reason,
            first_batch_sequence: inventory.first_sequence,
            last_batch_sequence: inventory.last_sequence,
            batch_count: inventory.batch_count,
            event_count: self.event_count,
            used_bytes: inventory.used_bytes,
            compressed: inventory.compressed || self.options.compress,
            started_unix_ms: self.started_unix_ms,
            writer: None,
        })
    }
    fn persist_manifest(
        &self,
        session_id: Uuid,
        state: DurableSessionState,
        stop_reason: Option<CaptureStopReason>,
    ) -> Result<(), SpoolError> {
        write_manifest(
            &self.directory,
            &self.manifest(session_id, state, stop_reason)?,
        )
    }
}

struct InventoryScan {
    used_bytes: u64,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    batch_count: u64,
    compressed: bool,
}

fn scan_inventory(directory: &Path) -> Result<InventoryScan, SpoolError> {
    let mut scan = InventoryScan {
        used_bytes: 0,
        first_sequence: None,
        last_sequence: None,
        batch_count: 0,
        compressed: false,
    };
    if !directory.exists() {
        return Ok(scan);
    }
    for (sequence, path, encoding) in list_batch_files(directory)? {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        scan.used_bytes = scan
            .used_bytes
            .checked_add(metadata.len())
            .ok_or(SpoolError::CapacityOverflow)?;
        scan.first_sequence = Some(
            scan.first_sequence
                .map_or(sequence, |first| first.min(sequence)),
        );
        scan.last_sequence = Some(
            scan.last_sequence
                .map_or(sequence, |last| last.max(sequence)),
        );
        scan.batch_count = scan.batch_count.saturating_add(1);
        scan.compressed |= encoding == BatchEncoding::Lz4;
    }
    Ok(scan)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchEncoding {
    Json,
    Lz4,
}

fn list_batch_files(directory: &Path) -> Result<Vec<(u64, PathBuf, BatchEncoding)>, SpoolError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !file_type.is_file() {
            continue;
        }
        if let Some((sequence, encoding)) =
            parse_batch_filename(&entry.file_name().to_string_lossy())
        {
            paths.push((sequence, entry.path(), encoding));
        }
    }
    paths.sort_unstable_by_key(|(sequence, _, _)| *sequence);
    Ok(paths)
}

fn decode_batch_json(path: &Path, encoding: BatchEncoding) -> Result<Vec<u8>, SpoolError> {
    let encoded_max =
        DEFAULT_MAX_FRAME_BYTES as usize + (DEFAULT_MAX_FRAME_BYTES as usize / 255) + 32;
    let bytes = read_bounded(path, encoded_max)?;
    let json = match encoding {
        BatchEncoding::Json => {
            if bytes.len() > DEFAULT_MAX_FRAME_BYTES as usize {
                return Err(SpoolError::BatchTooLarge {
                    observed: bytes.len() as u64,
                    maximum: DEFAULT_MAX_FRAME_BYTES,
                });
            }
            bytes
        }
        BatchEncoding::Lz4 => {
            let declared = bytes
                .get(..4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| SpoolError::Decompress {
                    path: path.to_path_buf(),
                    detail: "missing length prefix".into(),
                })?;
            if declared > DEFAULT_MAX_FRAME_BYTES {
                return Err(SpoolError::BatchTooLarge {
                    observed: u64::from(declared),
                    maximum: DEFAULT_MAX_FRAME_BYTES,
                });
            }
            lz4_flex::decompress_size_prepended(&bytes).map_err(|error| SpoolError::Decompress {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?
        }
    };
    Ok(json)
}
fn decode_batch_file(path: &Path, encoding: BatchEncoding) -> Result<EventBatch, SpoolError> {
    let json = decode_batch_json(path, encoding)?;
    let batch: EventBatch =
        serde_json::from_slice(&json).map_err(|source| SpoolError::InvalidBatch {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(batch)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Debug)]
struct PendingBatch {
    batch: EventBatch,
    bytes: u64,
}

/// Persistent spool failure.
#[derive(Debug, Error)]
pub enum SpoolError {
    /// One event cannot fit the unchanged frame/session byte bound.
    #[error("event {source_sequence} uses {serialized_bytes} serialized bytes, above {maximum}")]
    EventTooLarge {
        /// Sequence of the rejected source event.
        source_sequence: u64,
        /// Exact singleton batch bytes after JSON escaping.
        serialized_bytes: u64,
        /// Applicable frame/session bound.
        maximum: u64,
    },
    /// An earlier write failed; pending evidence must be retried before new input.
    #[error("spool writer blocked by retained pending evidence")]
    WriterBlocked,
    /// A requested captured byte range could not be proven.
    #[error("captured evidence recovery failed: {0}")]
    Evidence(&'static str),
    /// The configured bound cannot hold any data.
    #[error("spool capacity must be greater than zero")]
    InvalidCapacity,
    /// A batch must contain at least one event.
    #[error("events per batch must be between 1 and {MAX_EVENTS_PER_BATCH}")]
    InvalidBatchSize,
    /// A batch cannot be replayed through the bounded wire codec.
    #[error("encoded batch uses {observed} bytes, above wire maximum {maximum}")]
    BatchTooLarge {
        /// Encoded batch bytes.
        observed: u64,
        /// Wire frame maximum.
        maximum: u32,
    },
    /// A requested capture session does not exist.
    #[error("spool session directory does not exist: {}", .0.display())]
    MissingSession(PathBuf),
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Batch serialization failed.
    #[error(transparent)]
    Encode(#[from] serde_json::Error),
    /// A persisted document is not a valid event batch.
    #[error("invalid persisted batch {}: {source}", path.display())]
    InvalidBatch {
        /// Invalid batch path.
        path: PathBuf,
        /// JSON decoding failure.
        source: serde_json::Error,
    },
    /// A batch filename and its payload disagree.
    #[error(
        "batch filename sequence {filename} does not match payload sequence {payload} in {}",
        path.display()
    )]
    FilenameSequenceMismatch {
        /// Invalid batch path.
        path: PathBuf,
        /// Sequence encoded in the filename.
        filename: u64,
        /// Sequence encoded in the payload.
        payload: u64,
    },
    /// A single directory contains batches from multiple sessions.
    #[error("spool mixes sessions {expected} and {observed}")]
    MixedSessions {
        /// Session established by the first batch.
        expected: Uuid,
        /// Conflicting session.
        observed: Uuid,
    },
    /// An event belongs to another capture session.
    #[error("event session {observed} does not match spool session {expected}")]
    ForeignEventSession {
        /// Session owned by the writer.
        expected: Uuid,
        /// Session encoded in the event.
        observed: Uuid,
    },
    /// A UUID-named directory contains a batch from another session.
    #[error("spool directory session {directory_session} contains batch session {batch_session}")]
    DirectorySessionMismatch {
        /// Session parsed from the directory name.
        directory_session: Uuid,
        /// Session encoded by the conflicting batch.
        batch_session: Uuid,
    },
    /// Batch ordering moved backward or repeated.
    #[error("batch sequence moved from {previous} to {observed}")]
    NonMonotonicSequence {
        /// Last accepted sequence.
        previous: u64,
        /// Rejected sequence.
        observed: u64,
    },
    /// The configured bound would be exceeded.
    #[error("spool capacity exceeded: used={used} incoming={incoming} maximum={maximum} bytes")]
    CapacityExceeded {
        /// Current complete batch bytes.
        used: u64,
        /// Incoming encoded batch bytes.
        incoming: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// Existing data already exceeds the configured bound.
    #[error("existing spool uses {used} bytes, above configured maximum {maximum}")]
    ExistingDataExceedsCapacity {
        /// Existing complete batch bytes.
        used: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// An encoded size could not be represented safely.
    #[error("spool byte accounting overflow")]
    CapacityOverflow,
    /// An immutable destination already exists.
    #[error("immutable batch destination already exists: {}", .0.display())]
    DestinationExists(PathBuf),
    /// Independent batch decompression failed.
    #[error("failed to decompress batch {}: {detail}", path.display())]
    Decompress {
        /// Compressed batch path.
        path: PathBuf,
        /// Decompressor diagnostic.
        detail: String,
    },
}

fn batch_filename(sequence: u64, suffix: &str) -> String {
    format!("{BATCH_PREFIX}{sequence:020}{suffix}")
}

fn parse_batch_filename(name: &str) -> Option<(u64, BatchEncoding)> {
    let rest = name.strip_prefix(BATCH_PREFIX)?;
    if let Some(sequence) = rest.strip_suffix(BATCH_LZ4_SUFFIX) {
        return Some((sequence.parse().ok()?, BatchEncoding::Lz4));
    }
    let sequence = rest.strip_suffix(BATCH_JSON_SUFFIX)?;
    Some((sequence.parse().ok()?, BatchEncoding::Json))
}

fn batch_path(directory: &Path, sequence: u64) -> PathBuf {
    let lz4 = directory.join(batch_filename(sequence, BATCH_LZ4_SUFFIX));
    if lz4.exists() {
        lz4
    } else {
        directory.join(batch_filename(sequence, BATCH_JSON_SUFFIX))
    }
}

fn write_atomic(temporary: &Path, destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let result = (|| {
        ksight_core::output_budget::charge(temporary, bytes.len() as u64)?;
        fault("batch_open")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)?;
        file.write_all(&bytes[..bytes.len() / 2])?;
        fault("batch_short_write")?;
        file.write_all(&bytes[bytes.len() / 2..])?;
        fault("batch_file_sync")?;
        file.sync_all()?;
        drop(file);
        fault("batch_publish")?;
        fs::hard_link(temporary, destination)?;
        fs::remove_file(temporary)?;
        fault("batch_directory_sync")?;
        sync_parent(destination)
    })();
    if result.is_err() {
        ksight_core::output_budget::record_failure(temporary, "spool_output_failed");
        let _ = fs::remove_file(temporary);
    }
    result
}

fn write_replace(temporary: &Path, destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let result = (|| {
        ksight_core::output_budget::charge(temporary, bytes.len() as u64)?;
        fault("manifest_open")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)?;
        file.write_all(&bytes[..bytes.len() / 2])?;
        fault("manifest_short_write")?;
        file.write_all(&bytes[bytes.len() / 2..])?;
        fault("manifest_file_sync")?;
        file.sync_all()?;
        drop(file);
        fault("manifest_publish")?;
        fs::rename(temporary, destination)?;
        fault("manifest_directory_sync")?;
        sync_parent(destination)
    })();
    if result.is_err() {
        ksight_core::output_budget::record_failure(temporary, "spool_output_failed");
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
#[path = "spool_evidence_tests.rs"]
mod evidence_tests;

#[cfg(test)]
mod tests {
    use ksight_model::{
        CaptureMode, Confidence, DataQuality, Event, EventHeader, EventPayload, ProcessIdentity,
        ProcessKey, ProcessLifecycle, ProcessLifecycleKind, SchemaVersion, SensorKind,
    };

    use super::*;

    #[test]
    fn persists_reopens_and_acknowledges_batches() {
        let directory = test_directory();
        let session = Uuid::new_v4();
        let mut spool = DirectorySpool::open(&directory, 1024 * 1024).unwrap();
        spool.append(&batch(session, 1)).unwrap();
        spool.append(&batch(session, 2)).unwrap();
        let used = spool.used_bytes();
        assert!(used > 0);

        let mut reopened = DirectorySpool::open(&directory, 1024 * 1024).unwrap();
        assert_eq!(
            reopened
                .pending()
                .unwrap()
                .iter()
                .map(|batch| batch.batch_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        reopened.acknowledge_through(1).unwrap();
        assert_eq!(reopened.pending().unwrap(), vec![batch(session, 2)]);
        assert!(reopened.used_bytes() < used);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn acknowledgements_preserve_sealed_lifecycle_and_retention_eligibility() {
        for (state, stop_reason) in [
            (
                DurableSessionState::Completed,
                Some(CaptureStopReason::DurationElapsed),
            ),
            (
                DurableSessionState::Rotated,
                Some(CaptureStopReason::SessionRotated),
            ),
            (DurableSessionState::Interrupted, None),
            (
                DurableSessionState::StorageLimited,
                Some(CaptureStopReason::StorageLimitReached),
            ),
        ] {
            for compress in [false, true] {
                let root = test_directory();
                let session = Uuid::new_v4();
                let mut writer = SessionSpoolWriter::open_with(
                    &root,
                    session,
                    1024 * 1024,
                    1,
                    SpoolOptions {
                        compress,
                        completion_reserve_bytes: 0,
                    },
                )
                .unwrap();
                writer.push(&batch(session, 1).events[0]).unwrap();
                // An ACK handle may be opened before the collector seals the session.
                let mut spool =
                    DirectorySpool::open_existing(writer.directory(), 1024 * 1024).unwrap();
                writer.push(&batch(session, 2).events[0]).unwrap();
                writer.seal(state, stop_reason).unwrap();
                let sealed = load_manifest(writer.directory()).unwrap().unwrap();
                let second_batch_bytes = fs::metadata(batch_path(writer.directory(), 2))
                    .unwrap()
                    .len();
                drop(writer);

                for (through, remaining, next_sequence, used_bytes) in [
                    (1, 1, Some(2), second_batch_bytes),
                    (1, 1, Some(2), second_batch_bytes),
                    (2, 0, None, 0),
                    (2, 0, None, 0),
                ] {
                    spool.acknowledge_through(through).unwrap();
                    assert_eq!(
                        load_manifest(spool.directory()).unwrap().unwrap(),
                        SessionManifest {
                            first_batch_sequence: next_sequence,
                            last_batch_sequence: next_sequence,
                            batch_count: remaining,
                            event_count: remaining,
                            used_bytes,
                            ..sealed.clone()
                        }
                    );
                    assert_eq!(spool.used_bytes(), used_bytes);
                    assert_eq!(
                        spool.pending().unwrap().len(),
                        usize::try_from(remaining).unwrap()
                    );
                }

                let retention = crate::retention::SpoolRetention {
                    root: root.clone(),
                    max_total_bytes: 0,
                    keep_completed: 0,
                };
                assert_eq!(retention.prune().unwrap(), 0);
                assert!(!spool.directory().exists());
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn acknowledgements_keep_running_sessions_out_of_retention() {
        let root = test_directory();
        let session = Uuid::new_v4();
        let mut writer = SessionSpoolWriter::open(&root, session, 1024 * 1024, 1).unwrap();
        writer.push(&batch(session, 1).events[0]).unwrap();
        let running = load_manifest(writer.directory()).unwrap().unwrap();
        let mut spool = DirectorySpool::open_existing(writer.directory(), 1024 * 1024).unwrap();
        spool.acknowledge_through(1).unwrap();
        assert_eq!(
            load_manifest(spool.directory()).unwrap().unwrap(),
            SessionManifest {
                first_batch_sequence: None,
                last_batch_sequence: None,
                batch_count: 0,
                event_count: 0,
                used_bytes: 0,
                ..running
            }
        );
        let retention = crate::retention::SpoolRetention {
            root: root.clone(),
            max_total_bytes: 0,
            keep_completed: 0,
        };
        assert_eq!(retention.prune().unwrap(), 0);
        assert!(spool.directory().is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acknowledging_legacy_sessions_synthesizes_remaining_inventory() {
        let root = test_directory();
        let session = Uuid::new_v4();
        let directory = root.join(session.to_string());
        let mut writer = DirectorySpool::open(&directory, 1024 * 1024).unwrap();
        writer.append(&batch(session, 1)).unwrap();
        writer.append(&batch(session, 2)).unwrap();
        assert!(load_manifest(&directory).unwrap().is_none());

        let mut spool = DirectorySpool::open_existing(&directory, 1024 * 1024).unwrap();
        for (through, remaining, next_sequence) in
            [(1, 1, Some(2)), (1, 1, Some(2)), (2, 0, None), (2, 0, None)]
        {
            spool.acknowledge_through(through).unwrap();
            let manifest = load_manifest(&directory).unwrap().unwrap();
            assert_eq!(manifest.session_id, session);
            assert_eq!(manifest.state, DurableSessionState::Running);
            assert_eq!(manifest.stop_reason, None);
            assert_eq!(manifest.batch_count, remaining);
            assert_eq!(manifest.event_count, remaining);
            assert_eq!(manifest.first_batch_sequence, next_sequence);
            assert_eq!(manifest.last_batch_sequence, next_sequence);
            assert_eq!(manifest.used_bytes, spool.used_bytes());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_unacknowledged_data_at_capacity() {
        let directory = test_directory();
        let session = Uuid::new_v4();
        let encoded = serde_json::to_vec(&batch(session, 1)).unwrap();
        let mut spool = DirectorySpool::open(&directory, encoded.len() as u64).unwrap();
        spool.append(&batch(session, 1)).unwrap();
        assert!(matches!(
            spool.append(&batch(session, 2)),
            Err(SpoolError::CapacityExceeded { .. })
        ));
        assert_eq!(spool.pending().unwrap(), vec![batch(session, 1)]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn opening_missing_session_does_not_create_it() {
        let directory = test_directory();
        assert!(matches!(
            DirectorySpool::open_existing(&directory, 1024),
            Err(SpoolError::MissingSession(_))
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn session_writer_rejects_unbounded_event_counts() {
        let root = test_directory();
        let session = Uuid::new_v4();
        assert!(matches!(
            SessionSpoolWriter::open(&root, session, 1024, 0),
            Err(SpoolError::InvalidBatchSize)
        ));
        assert!(matches!(
            SessionSpoolWriter::open(&root, session, 1024, MAX_EVENTS_PER_BATCH + 1),
            Err(SpoolError::InvalidBatchSize)
        ));
        assert!(!root.exists());
    }

    #[test]
    fn writer_reconciles_capacity_after_external_acknowledgement() {
        let directory = test_directory();
        let session = Uuid::new_v4();
        let first = batch(session, 1);
        let capacity = serde_json::to_vec(&first).unwrap().len() as u64;
        let mut writer = DirectorySpool::open(&directory, capacity).unwrap();
        writer.append(&first).unwrap();

        let mut client = DirectorySpool::open_existing(&directory, capacity).unwrap();
        client.acknowledge_through(1).unwrap();
        writer.append(&batch(session, 2)).unwrap();
        assert_eq!(
            writer
                .pending()
                .unwrap()
                .iter()
                .map(|batch| batch.batch_sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compresses_and_reopens_independent_batches() {
        let directory = test_directory();
        let session = Uuid::new_v4();
        let mut spool = DirectorySpool::open_with(
            &directory,
            1024 * 1024,
            SpoolOptions {
                compress: true,
                completion_reserve_bytes: 0,
            },
        )
        .unwrap();
        spool.append(&batch(session, 1)).unwrap();
        assert!(directory
            .join("batch-00000000000000000001.json.lz4")
            .exists());
        let reopened = DirectorySpool::open_existing(&directory, 1024 * 1024).unwrap();
        assert_eq!(reopened.pending().unwrap(), vec![batch(session, 1)]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn session_writer_flushes_full_and_partial_batches() {
        let root = test_directory();
        let session = Uuid::new_v4();
        let mut writer = SessionSpoolWriter::open(&root, session, 1024 * 1024, 2).unwrap();
        writer.push(&batch(session, 1).events[0]).unwrap();
        assert_eq!(writer.persisted_batches(), 0);
        writer.push(&batch(session, 2).events[0]).unwrap();
        assert_eq!(writer.persisted_batches(), 1);
        writer.push(&batch(session, 3).events[0]).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.persisted_batches(), 2);

        let spool = DirectorySpool::open(writer.directory(), 1024 * 1024).unwrap();
        assert_eq!(
            spool
                .pending()
                .unwrap()
                .iter()
                .map(|batch| batch.events.len())
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        let summaries = inspect_root(&root).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].session_id, session);
        assert_eq!(summaries[0].batch_count, 2);
        assert_eq!(summaries[0].event_count, 3);
        assert_eq!(summaries[0].first_batch_sequence, Some(1));
        assert_eq!(summaries[0].last_batch_sequence, Some(2));
        fs::remove_dir_all(root).unwrap();
    }

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!("ksight-spool-test-{}", Uuid::new_v4()))
    }

    pub(super) fn batch(session_id: Uuid, batch_sequence: u64) -> EventBatch {
        EventBatch {
            session_id,
            batch_sequence,
            events: vec![Event {
                header: EventHeader {
                    schema: SchemaVersion { major: 1, minor: 8 },
                    session_id,
                    source_sequence: batch_sequence,
                    monotonic_ns: batch_sequence,
                    cpu: Some(0),
                    process: ProcessIdentity {
                        key: ProcessKey {
                            boot_id: Uuid::nil(),
                            pid: 1,
                            start_time_ns: 1,
                        },
                        tid: 1,
                        tgid: 1,
                        uid: 0,
                        gid: 0,
                        comm: "init".to_owned(),
                        command_line: None,
                        selinux_context: None,
                        packages: Vec::new(),
                    },
                    sensor: SensorKind::Process,
                    mode: CaptureMode::Observe,
                    quality: DataQuality {
                        confidence: Confidence::Confirmed,
                        truncated: false,
                        lost_before: 0,
                        sample_one_in: 1,
                        source: "test".to_owned(),
                    },
                },
                payload: EventPayload::ProcessLifecycle(ProcessLifecycle {
                    kind: ProcessLifecycleKind::Exec,
                    parent_pid: None,
                    filename: Some("/system/bin/init".to_owned()),
                    exit_code: None,
                    zygote_source: None,
                }),
            }],
        }
    }
}

#[cfg(test)]
mod output_budget_tests {
    use super::*;
    #[test]
    fn production_batch_refuses_next_write_and_keeps_sealed_bytes() {
        let root = std::env::temp_dir().join(format!("spool-budget-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let g = ksight_core::output_budget::Guard::install(vec![root.clone()], 3, 1000).unwrap();
        write_atomic(&root.join("temp"), &root.join("sealed"), b"abc").unwrap();
        assert!(write_atomic(&root.join("next-temp"), &root.join("next"), b"x").is_err());
        assert_eq!(fs::read(root.join("sealed")).unwrap(), b"abc");
        assert!(g.receipt().partial);
        assert!(!root.join("next").exists());
        drop(g);
        fs::remove_dir_all(root).unwrap();
    }
}
