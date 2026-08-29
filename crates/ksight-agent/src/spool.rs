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
    events: Vec<Event>,
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
        let batch = decode_batch_file(&path, encoding)?;
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
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
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
    write_replace(
        &temporary,
        &destination,
        &serde_json::to_vec_pretty(manifest)?,
    )?;
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

impl SessionSpoolWriter {
    /// Create a writer beneath `root/<session-id>`.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero event bound or when the session spool cannot be opened.
    pub fn open(
        root: impl AsRef<Path>,
        session_id: Uuid,
        max_bytes: u64,
        max_events_per_batch: usize,
    ) -> Result<Self, SpoolError> {
        Self::open_with(
            root,
            session_id,
            max_bytes,
            max_events_per_batch,
            SpoolOptions {
                compress: false,
                completion_reserve_bytes: 0,
            },
        )
    }

    /// Create a writer with compression and completion-reserve options.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero event bound or when the session spool cannot be opened.
    pub fn open_with(
        root: impl AsRef<Path>,
        session_id: Uuid,
        max_bytes: u64,
        max_events_per_batch: usize,
        options: SpoolOptions,
    ) -> Result<Self, SpoolError> {
        if max_events_per_batch == 0 || max_events_per_batch > MAX_EVENTS_PER_BATCH {
            return Err(SpoolError::InvalidBatchSize);
        }
        let spool = DirectorySpool::open_with(
            root.as_ref().join(session_id.to_string()),
            max_bytes,
            options,
        )?;
        let next_batch_sequence = spool
            .last_sequence
            .map_or(1, |sequence| sequence.saturating_add(1));
        Ok(Self {
            spool,
            session_id,
            next_batch_sequence,
            max_events_per_batch,
            events: Vec::with_capacity(max_events_per_batch),
            persisted_batches: 0,
            started: Instant::now(),
        })
    }

    /// Buffer one event and persist a complete batch when the configured bound is reached.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign session or persistence failure.
    pub fn push(&mut self, event: &Event) -> Result<(), SpoolError> {
        if event.header.session_id != self.session_id {
            return Err(SpoolError::ForeignEventSession {
                expected: self.session_id,
                observed: event.header.session_id,
            });
        }
        self.events.push(event.clone());
        if self.events.len() >= self.max_events_per_batch {
            self.flush()?;
        }
        Ok(())
    }

    /// Persist the current partial batch, if any.
    ///
    /// # Errors
    ///
    /// Returns a persistence or capacity error without discarding buffered events.
    pub fn flush(&mut self) -> Result<(), SpoolError> {
        if self.events.is_empty() {
            return Ok(());
        }
        let batch = EventBatch {
            session_id: self.session_id,
            batch_sequence: self.next_batch_sequence,
            events: self.events.clone(),
        };
        self.spool.append(&batch)?;
        self.events.clear();
        self.next_batch_sequence = self.next_batch_sequence.saturating_add(1);
        self.persisted_batches = self.persisted_batches.saturating_add(1);
        self.spool
            .persist_manifest(self.session_id, DurableSessionState::Running, None)?;
        Ok(())
    }

    /// Seal the session with a lifecycle state after the final flush.
    ///
    /// # Errors
    ///
    /// Returns a persistence error.
    pub fn seal(
        &mut self,
        state: DurableSessionState,
        stop_reason: Option<CaptureStopReason>,
    ) -> Result<(), SpoolError> {
        self.flush()?;
        self.spool
            .persist_manifest(self.session_id, state, stop_reason)
    }

    /// Whether remaining event capacity or age requires a new session directory.
    pub fn should_rotate(&self, max_age_secs: u64) -> bool {
        let aged = max_age_secs != 0 && self.started.elapsed().as_secs() >= max_age_secs;
        aged || self.spool.event_capacity_exhausted()
    }

    /// Session-specific spool directory.
    pub fn directory(&self) -> &Path {
        self.spool.directory()
    }

    /// Complete batch bytes written or recovered for this session.
    pub fn used_bytes(&self) -> u64 {
        self.spool.used_bytes()
    }

    /// Batches persisted by this writer instance.
    pub fn persisted_batches(&self) -> u64 {
        self.persisted_batches
    }
}

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
            let bytes = fs::metadata(&path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            pending.push(PendingBatch { batch, bytes });
        }
        Ok(pending)
    }
}

impl Spool for DirectorySpool {
    type Error = SpoolError;

    fn append(&mut self, batch: &EventBatch) -> Result<(), Self::Error> {
        self.reconcile_external_acknowledgements()?;
        if self
            .last_sequence
            .is_some_and(|previous| batch.batch_sequence <= previous)
        {
            return Err(SpoolError::NonMonotonicSequence {
                previous: self.last_sequence.unwrap_or_default(),
                observed: batch.batch_sequence,
            });
        }
        let json = serde_json::to_vec(batch)?;
        let json_len = u64::try_from(json.len()).map_err(|_| SpoolError::CapacityOverflow)?;
        if json_len > u64::from(DEFAULT_MAX_FRAME_BYTES) {
            return Err(SpoolError::BatchTooLarge {
                observed: json_len,
                maximum: DEFAULT_MAX_FRAME_BYTES,
            });
        }
        let (encoded, suffix) = if self.options.compress {
            (lz4_flex::compress_prepend_size(&json), BATCH_LZ4_SUFFIX)
        } else {
            (json, BATCH_JSON_SUFFIX)
        };
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| SpoolError::CapacityOverflow)?;
        let next_usage = self
            .used_bytes
            .checked_add(encoded_len)
            .ok_or(SpoolError::CapacityOverflow)?;
        if next_usage > self.max_bytes {
            return Err(SpoolError::CapacityExceeded {
                used: self.used_bytes,
                incoming: encoded_len,
                maximum: self.max_bytes,
            });
        }

        let destination = self
            .directory
            .join(batch_filename(batch.batch_sequence, suffix));
        if destination.exists() {
            return Err(SpoolError::DestinationExists(destination));
        }
        let temporary = self
            .directory
            .join(format!(".pending-{}.tmp", Uuid::new_v4()));
        let result = write_atomic(&temporary, &destination, &encoded);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.used_bytes = next_usage;
        self.last_sequence = Some(batch.batch_sequence);
        self.event_count = self.event_count.saturating_add(
            u64::try_from(batch.events.len()).map_err(|_| SpoolError::CapacityOverflow)?,
        );
        Ok(())
    }

    fn pending(&self) -> Result<Vec<EventBatch>, Self::Error> {
        self.read_pending()
            .map(|entries| entries.into_iter().map(|entry| entry.batch).collect())
    }

    fn acknowledge_through(&mut self, batch_sequence: u64) -> Result<(), Self::Error> {
        for entry in self.read_pending()? {
            if entry.batch.batch_sequence > batch_sequence {
                break;
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
        if let Some(name) = self.directory.file_name().and_then(|name| name.to_str()) {
            if let Ok(session_id) = Uuid::parse_str(name) {
                self.persist_manifest(session_id, DurableSessionState::Running, None)?;
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

    fn persist_manifest(
        &self,
        session_id: Uuid,
        state: DurableSessionState,
        stop_reason: Option<CaptureStopReason>,
    ) -> Result<(), SpoolError> {
        let inventory = scan_inventory(&self.directory)?;
        write_manifest(
            &self.directory,
            &SessionManifest {
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
            },
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

fn decode_batch_file(path: &Path, encoding: BatchEncoding) -> Result<EventBatch, SpoolError> {
    let bytes = fs::read(path)?;
    let json = match encoding {
        BatchEncoding::Json => bytes,
        BatchEncoding::Lz4 => {
            lz4_flex::decompress_size_prepended(&bytes).map_err(|error| SpoolError::Decompress {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?
        }
    };
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
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug)]
struct PendingBatch {
    batch: EventBatch,
    bytes: u64,
}

/// Persistent spool failure.
#[derive(Debug, Error)]
pub enum SpoolError {
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::hard_link(temporary, destination)?;
    let _ = fs::remove_file(temporary);
    Ok(())
}

fn write_replace(temporary: &Path, destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, destination)?;
    Ok(())
}

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

    fn batch(session_id: Uuid, batch_sequence: u64) -> EventBatch {
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
