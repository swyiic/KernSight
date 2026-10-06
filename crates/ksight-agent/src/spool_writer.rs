/// Maximum manifest/diagnostic bytes reserved inside each writer's session budget.
pub const WRITER_METADATA_RESERVE: u64 = 8 * 1024;
/// Maximum age of an uncommitted partial event batch.
pub const WRITER_IDLE_FLUSH: std::time::Duration = std::time::Duration::from_secs(1);

/// A bounded failure index. No captured content or credentials are included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolFailure {
    /// push, flush, or manifest.
    pub stage: String,
    /// Sanitized failure class/detail, at most 256 characters.
    pub reason: String,
    /// Incoming event sequence if this was a push failure.
    pub source_sequence: Option<u64>,
    /// Canonical fragment sequence when the incoming event was captured bytes.
    pub fragment_sequence: Option<u64>,
    /// Captured length, without claiming the whole request was captured.
    pub captured_bytes: Option<u32>,
    /// Valid full captured-byte hash, if supplied by the producer.
    pub captured_sha256: Option<String>,
    /// Incoming serialized event bytes; None for flush-only failures.
    pub serialized_bytes: Option<u64>,
    /// True if the event remains in the bounded pending buffer.
    pub retained_pending: bool,
    /// True if bytes were committed before a metadata error.
    pub committed: bool,
}

/// Byte and event bounds/high watermarks and failure status for a single writer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpoolWriterDiagnostics {
    /// Current buffered JSON bytes including the exact batch envelope.
    pub pending_json_bytes: u64,
    /// Current buffered event count.
    pub pending_events: usize,
    /// Maximum buffered JSON permitted, unchanged wire maximum or smaller session budget.
    pub pending_limit_bytes: u64,
    /// Maximum event count permitted.
    pub pending_limit_events: usize,
    /// Peak buffered JSON bytes.
    pub high_water_pending_bytes: u64,
    /// Peak buffered event count.
    pub high_water_pending_events: usize,
    /// Peak owned serialized buffers, including retry JSON; excludes caller Events,
    /// deserialized validation objects, allocator overhead and process RSS.
    pub high_water_working_bytes: u64,
    /// Largest committed batch's uncompressed JSON size.
    pub max_batch_json_bytes: u64,
    /// Largest committed batch's encoded size.
    pub max_batch_encoded_bytes: u64,
    /// Capacity-triggered partial flushes before admitting another event.
    pub capacity_splits: u64,
    /// Upper bound on the encoded current pending batch; included in admission.
    pub pending_encoded_upper_bound: u64,
    /// Incoming events refused by the disk-capacity admission gate, never accepted.
    pub capacity_admission_rejections: u64,
    /// Exactly one data/metadata retry is permitted during terminal shutdown.
    pub terminal_flush_attempts: u64,
    /// Terminal state metadata writes, at most two (initial + one retry).
    pub terminal_manifest_attempts: u64,
    /// Last terminal manifest failure; stderr must expose failure if no metadata can be saved.
    pub terminal_manifest_error: Option<String>,
    /// Terminal retry failure, at most 256 characters; not a durability receipt.
    pub terminal_flush_error: Option<String>,
    /// Accepted events still in RAM at terminal shutdown, not promised durable.
    pub unpersisted_events_at_exit: u64,
    /// A prior manifest reported queued events not recovered from immutable batches.
    /// Historical uncertainty is preserved across subsequent writer restarts.
    pub unrecovered_previous_pending_events: u64,
    /// Once finalized, this writer refuses new input, even when its tail was saved.
    pub terminal_finalized: bool,
    /// Accepted into bounded RAM, including the uncommitted tail. Only committed
    /// events are durable; abrupt termination can lose a tail before its idle flush.
    pub accepted_events: u64,
    /// Durable events committed by this writer instance.
    pub committed_events: u64,
    /// Rejected push attempts. Rejected content is not buffered.
    pub rejected_events: u64,
    /// Failed data or manifest writes.
    pub write_failures: u64,
    /// Batches split by the byte gate instead of the event gate.
    pub byte_splits: u64,
    /// Exact retries of the last accepted event that were not appended twice.
    pub retry_deduplicated: u64,
    /// Monotonic next sequence survives all batches being acknowledged.
    pub next_batch_sequence: u64,
    /// Digest of the most recently accepted serialized event, never content.
    pub last_event_digest: Option<String>,
    /// Whether that last event has been committed (pending receipts cannot survive restart).
    pub last_event_committed: bool,
    /// The last bounded failure; retained for audit after recovery.
    pub last_failure: Option<SpoolFailure>,
}

#[derive(Debug)]
struct StoredEvent {
    json: Vec<u8>,
    completion: bool,
}

impl SessionSpoolWriter {
    /// Create a writer with bounded pending bytes and an 8 KiB metadata allowance.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
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

    /// Create/recover a writer. Committed batches are validated one at a time.
    ///
    /// # Panics
    /// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
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
        if max_bytes <= WRITER_METADATA_RESERVE + options.completion_reserve_bytes {
            return Err(SpoolError::InvalidCapacity);
        }
        let mut spool = DirectorySpool::open_with(
            root.as_ref().join(session_id.to_string()),
            max_bytes - WRITER_METADATA_RESERVE,
            options,
        )?;
        let old = load_manifest(&spool.directory)?;
        if old.as_ref().is_some_and(|m| m.session_id != session_id) {
            return Err(SpoolError::DirectorySessionMismatch {
                directory_session: session_id,
                batch_session: old.unwrap().session_id,
            });
        }
        let mut recovered_count = 0u64;
        let mut recovered_digest = None;
        visit_batches(&spool.directory, session_id, None, |batch| {
            recovered_count = recovered_count.saturating_add(batch.events.len() as u64);
            if let Some(event) = batch.events.last() {
                recovered_digest = Some(measure_json(event)?.1);
            }
            Ok(())
        })?;
        spool.event_count = recovered_count;
        let old_diag = old.and_then(|m| m.writer);
        let unrecovered_previous_pending_events = old_diag.as_ref().map_or(0, |d| {
            // Immutable publication is whole-batch atomic. A matching last queued
            // digest recovers that entire batch even if its manifest write failed.
            let recovered_tail = recovered_digest.is_some()
                && recovered_digest.as_ref() == d.last_event_digest.as_ref();
            d.unrecovered_previous_pending_events.saturating_add(
                if recovered_tail { 0 } else { d.pending_events as u64 }
            )
        });
        let next_batch_sequence = spool
            .last_sequence
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SpoolError::CapacityOverflow)?
            .max(old_diag.as_ref().map_or(1, |d| d.next_batch_sequence));
        let last_digest = if let Some(digest) = recovered_digest {
            Some(digest)
        } else {
            old_diag
                .as_ref()
                .filter(|d| d.last_event_committed)
                .and_then(|d| d.last_event_digest.clone())
        };
        let pending_limit_bytes = u64::from(DEFAULT_MAX_FRAME_BYTES).min(spool.max_bytes);
        let diagnostics = SpoolWriterDiagnostics {
            pending_limit_bytes,
            pending_limit_events: max_events_per_batch,
            next_batch_sequence,
            last_event_committed: last_digest.is_some(),
            last_event_digest: last_digest,
            unrecovered_previous_pending_events,
            last_failure: old_diag.and_then(|d| d.last_failure),
            ..Default::default()
        };
        Ok(Self {
            spool,
            session_id,
            next_batch_sequence,
            max_events_per_batch,
            events: Vec::with_capacity(max_events_per_batch),
            event_bytes: 0,
            persisted_batches: 0,
            started: Instant::now(),
            pending_since: None,
            blocked: false,
            manifest_dirty: false,
            diagnostics,
        })
    }

    /// Accept a bounded serialized event or return an observable rejection/failure.
    /// An error after acceptance retains its bytes; retrying that exact event is idempotent.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn push(&mut self, event: &Event) -> Result<(), SpoolError> {
        let result = self.push_inner(event);
        if let Err(error) = &result {
            let digest = measure_json(event).ok().map(|(_, d)| d);
            let retained = self.blocked
                && digest.as_ref() == self.diagnostics.last_event_digest.as_ref()
                && !self.diagnostics.last_event_committed;
            let accepted = !self.diagnostics.terminal_finalized
                && digest.is_some() && digest.as_ref() == self.diagnostics.last_event_digest.as_ref();
            if !accepted {
                if matches!(error, SpoolError::CapacityExceeded { .. }) {
                    self.diagnostics.capacity_admission_rejections =
                        self.diagnostics.capacity_admission_rejections.saturating_add(1);
                }
                self.diagnostics.rejected_events =
                    self.diagnostics.rejected_events.saturating_add(1);
            }
            self.record_failure("push", error, Some(event), retained);
        }
        result
    }

    #[allow(clippy::too_many_lines, reason = "Keep the admission or lifecycle transaction together for review.")]
    fn push_inner(&mut self, event: &Event) -> Result<(), SpoolError> {
        if event.header.session_id != self.session_id {
            return Err(SpoolError::ForeignEventSession {
                expected: self.session_id,
                observed: event.header.session_id,
            });
        }
        if self.diagnostics.terminal_finalized {
            return Err(SpoolError::WriterBlocked);
        }
        let (size, digest) = measure_json(event)?;
        let completion = matches!(
            event.payload,
            ksight_model::EventPayload::SessionCompletion(_)
        );
        let limit = if completion {
            u64::from(DEFAULT_MAX_FRAME_BYTES).min(self.spool.max_bytes)
        } else {
            self.diagnostics.pending_limit_bytes.min(
                self.spool
                    .max_bytes
                    .saturating_sub(self.spool.options.completion_reserve_bytes),
            )
        };
        let singleton =
            batch_prefix(self.session_id, self.next_batch_sequence).len() as u64 + 2 + size;
        if singleton > limit {
            return Err(SpoolError::EventTooLarge {
                source_sequence: event.header.source_sequence,
                serialized_bytes: singleton,
                maximum: limit,
            });
        }
        if self.diagnostics.last_event_digest.as_ref() == Some(&digest) {
            if self.blocked {
                self.flush()?;
            }
            self.diagnostics.retry_deduplicated =
                self.diagnostics.retry_deduplicated.saturating_add(1);
            return Ok(());
        }
        if self.blocked {
            return Err(SpoolError::WriterBlocked);
        }
        let prospective = self
            .buffered_json_bytes()
            .checked_add(size)
            .and_then(|v| v.checked_add(u64::from(!self.events.is_empty())))
            .ok_or(SpoolError::CapacityOverflow)?;
        if !self.events.is_empty()
            && (completion || prospective > limit || self.events.len() >= self.max_events_per_batch)
        {
            if prospective > limit {
                self.diagnostics.byte_splits = self.diagnostics.byte_splits.saturating_add(1);
            }
            self.flush()?;
        }
        if batch_prefix(self.session_id, self.next_batch_sequence).len() as u64 + 2 + size > limit {
            return Err(SpoolError::EventTooLarge {
                source_sequence: event.header.source_sequence,
                serialized_bytes: size,
                maximum: limit,
            });
        }
        // Disk admission precedes allocation/acceptance. Every accepted pending
        // batch must fit even for incompressible LZ4 input. Flush the previously
        // admitted prefix first; never make an unflushable new tail accepted.
        let maximum = if completion { self.spool.max_bytes } else {
            self.spool.max_bytes.saturating_sub(self.spool.options.completion_reserve_bytes)
        };
        let prospective = self.projected_json_bytes(size)?;
        let bound = self.encoded_upper_bound(prospective)?;
        if self.spool.used_bytes.saturating_add(bound) > maximum {
            // ACKs may have freed space. Inventory reconciliation is needed only
            // at the disk boundary, not on every event on the fast path.
            self.spool.reconcile_external_acknowledgements()?;
            if !self.events.is_empty() && self.spool.used_bytes.saturating_add(bound) > maximum {
                self.diagnostics.capacity_splits = self.diagnostics.capacity_splits.saturating_add(1);
                self.flush()?;
            }
        }
        let prospective = self.projected_json_bytes(size)?;
        if prospective > limit {
            return Err(SpoolError::EventTooLarge { source_sequence: event.header.source_sequence,
                serialized_bytes: prospective, maximum: limit });
        }
        let mut reservation = self.encoded_upper_bound(prospective)?;
        let mut exact_singleton = None;
        if self.spool.used_bytes.checked_add(reservation).ok_or(SpoolError::CapacityOverflow)? > maximum {
            if self.spool.options.compress {
                // A compressible singleton can fit below the conservative bound.
                // Only at this boundary, measure its actual encoded bytes before
                // acceptance and force an immediate flush; no growing trial batches.
                debug_assert_eq!(self.events.len(), 0);
                let mut event_json = Vec::with_capacity(usize::try_from(size).map_err(|_| SpoolError::CapacityOverflow)?);
                serde_json::to_writer(&mut event_json, event)?;
                let prefix = batch_prefix(self.session_id, self.next_batch_sequence);
                let mut trial = Vec::with_capacity(prefix.len() + event_json.len() + 2);
                trial.extend_from_slice(prefix.as_bytes());
                trial.extend_from_slice(&event_json);
                trial.extend_from_slice(b"]}");
                let encoded = lz4_flex::compress_prepend_size(&trial);
                reservation = encoded.len() as u64;
                self.diagnostics.high_water_working_bytes = self.diagnostics.high_water_working_bytes.max(
                    self.owned_pending_bytes() + event_json.capacity() as u64
                    + trial.capacity() as u64 + encoded.capacity() as u64
                );
                exact_singleton = Some(event_json);
            }
            if self.spool.used_bytes.checked_add(reservation).ok_or(SpoolError::CapacityOverflow)? > maximum {
                return Err(SpoolError::CapacityExceeded {
                    used: self.spool.used_bytes, incoming: reservation, maximum,
                });
            }
        }
        let force_singleton_flush = exact_singleton.is_some();
        // No Event clone or serialized input allocation precedes the wire byte gate.
        let json = if let Some(json) = exact_singleton { json } else {
            let mut json = Vec::with_capacity(usize::try_from(size).map_err(|_| SpoolError::CapacityOverflow)?);
            serde_json::to_writer(&mut json, event)?;
            json
        };
        if json.len() as u64 != size {
            return Err(SpoolError::CapacityOverflow);
        }
        self.event_bytes = self
            .event_bytes
            .checked_add(size)
            .ok_or(SpoolError::CapacityOverflow)?;
        self.events.push(StoredEvent { json, completion });
        self.diagnostics.pending_encoded_upper_bound = reservation;
        self.pending_since.get_or_insert_with(Instant::now);
        self.diagnostics.accepted_events = self.diagnostics.accepted_events.saturating_add(1);
        self.diagnostics.last_event_digest = Some(digest);
        self.diagnostics.last_event_committed = false;
        self.refresh_high_water();
        if force_singleton_flush || completion || self.events.len() >= self.max_events_per_batch {
            self.flush()?;
        }
        Ok(())
    }

    /// Commit pending bytes without cloning Events. Retry never overwrites a different batch.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn flush(&mut self) -> Result<(), SpoolError> {
        let result = self.flush_inner();
        if let Err(error) = &result {
            self.blocked = true;
            self.diagnostics.write_failures = self.diagnostics.write_failures.saturating_add(1);
            self.record_failure(
                if self.events.is_empty() {
                    "manifest"
                } else {
                    "flush"
                },
                error,
                None,
                !self.events.is_empty(),
            );
        } else {
            self.blocked = false;
        }
        result
    }

    fn flush_inner(&mut self) -> Result<(), SpoolError> {
        if self.events.is_empty() {
            if self.manifest_dirty {
                self.persist_state(DurableSessionState::Running, None)?;
                self.manifest_dirty = false;
            }
            return Ok(());
        }
        let future_sequence = self
            .next_batch_sequence
            .checked_add(1)
            .ok_or(SpoolError::CapacityOverflow)?;
        let bytes = self.buffered_json_bytes();
        if bytes > u64::from(DEFAULT_MAX_FRAME_BYTES) {
            return Err(SpoolError::BatchTooLarge {
                observed: bytes,
                maximum: DEFAULT_MAX_FRAME_BYTES,
            });
        }
        let mut json = Vec::with_capacity(usize::try_from(bytes).map_err(|_| SpoolError::CapacityOverflow)?);
        json.extend_from_slice(batch_prefix(self.session_id, self.next_batch_sequence).as_bytes());
        for (i, event) in self.events.iter().enumerate() {
            if i != 0 {
                json.push(b',');
            }
            json.extend_from_slice(&event.json);
        }
        json.extend_from_slice(b"]}");
        assert_eq!(json.len() as u64, bytes);
        let mut encoded_working = 0;
        let append_result = self.spool.append_serialized(
            &json,
            self.next_batch_sequence,
            self.events.len() as u64,
            self.blocked,
            self.events.iter().all(|e| e.completion),
            &mut encoded_working,
        );
        self.diagnostics.high_water_working_bytes = self
            .diagnostics
            .high_water_working_bytes
            .max(self.owned_pending_bytes() + json.capacity() as u64 + encoded_working);
        let encoded_bytes = append_result?;
        self.diagnostics.max_batch_json_bytes = self.diagnostics.max_batch_json_bytes.max(bytes);
        self.diagnostics.max_batch_encoded_bytes =
            self.diagnostics.max_batch_encoded_bytes.max(encoded_bytes);
        self.diagnostics.committed_events = self
            .diagnostics
            .committed_events
            .saturating_add(self.events.len() as u64);
        self.events.clear();
        self.event_bytes = 0;
        self.diagnostics.pending_encoded_upper_bound = 0;
        self.pending_since = None;
        self.next_batch_sequence = future_sequence;
        self.diagnostics.next_batch_sequence = self.next_batch_sequence;
        self.diagnostics.last_event_committed = true;
        self.persisted_batches = self.persisted_batches.saturating_add(1);
        self.manifest_dirty = true;
        self.persist_state(DurableSessionState::Running, None)?;
        self.manifest_dirty = false;
        Ok(())
    }

    /// Poll from the production capture loop, including polls with no new events.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn flush_if_idle(&mut self) -> Result<bool, SpoolError> {
        if self
            .pending_since
            .is_some_and(|t| t.elapsed() >= WRITER_IDLE_FLUSH)
        {
            self.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Seal only after all buffered events have been committed.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn seal(
        &mut self,
        state: DurableSessionState,
        reason: Option<CaptureStopReason>,
    ) -> Result<(), SpoolError> {
        self.flush()?;
        self.persist_state(state, reason)
    }

    /// Stop input and attempt one final flush of the accepted tail. The original
    /// capture error remains an error. false means queued data is still volatile;
    /// a manifest error is returned separately. No capacity is increased.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn finish_interrupted(&mut self) -> Result<bool, SpoolError> {
        if !self.diagnostics.terminal_finalized {
            self.diagnostics.terminal_finalized = true;
            if !self.events.is_empty() || self.manifest_dirty {
                self.diagnostics.terminal_flush_attempts = 1;
                if let Err(error) = self.flush() {
                    self.diagnostics.terminal_flush_error =
                        Some(error.to_string().chars().take(256).collect());
                }
            }
        }
        self.diagnostics.unpersisted_events_at_exit = self.events.len() as u64;
        if self.diagnostics.terminal_manifest_attempts != 0
            && self.diagnostics.terminal_manifest_error.is_none()
        {
            return Ok(self.events.is_empty() && !self.manifest_dirty);
        }
        if self.diagnostics.terminal_manifest_attempts >= 2 {
            return Err(SpoolError::WriterBlocked);
        }
        self.diagnostics.terminal_manifest_attempts += 1;
        self.diagnostics.terminal_manifest_error = None;
        if let Err(error) = self.persist_state(DurableSessionState::Interrupted, None) {
            self.diagnostics.terminal_manifest_error = Some(error.to_string().chars().take(256).collect());
            return Err(error);
        }
        Ok(self.events.is_empty() && !self.manifest_dirty)
    }

    fn projected_json_bytes(&self, incoming: u64) -> Result<u64, SpoolError> {
        let existing = if self.events.is_empty() {
            batch_prefix(self.session_id, self.next_batch_sequence).len() as u64 + 2
        } else { self.buffered_json_bytes() };
        existing.checked_add(incoming)
            .and_then(|v| v.checked_add(u64::from(!self.events.is_empty())))
            .ok_or(SpoolError::CapacityOverflow)
    }
    fn encoded_upper_bound(&self, json_bytes: u64) -> Result<u64, SpoolError> {
        if json_bytes == 0 || !self.spool.options.compress { return Ok(json_bytes); }
        let size = usize::try_from(json_bytes).map_err(|_| SpoolError::CapacityOverflow)?;
        // The pinned compressor's proven bound, plus its LE length prefix.
        (lz4_flex::block::get_maximum_output_size(size) as u64).checked_add(4)
            .ok_or(SpoolError::CapacityOverflow)
    }

    /// Best-effort bounded failure manifest. Returns failure if the disk cannot record even metadata.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn mark_interrupted(&mut self) -> Result<(), SpoolError> {
        self.persist_state(DurableSessionState::Interrupted, None)
    }

    fn persist_state(
        &mut self,
        state: DurableSessionState,
        reason: Option<CaptureStopReason>,
    ) -> Result<(), SpoolError> {
        let mut manifest = self.spool.manifest(self.session_id, state, reason)?;
        manifest.writer = Some(self.diagnostics());
        write_manifest(&self.spool.directory, &manifest)
    }

    fn buffered_json_bytes(&self) -> u64 {
        if self.events.is_empty() {
            return 0;
        }
        batch_prefix(self.session_id, self.next_batch_sequence).len() as u64
            + 2
            + self.event_bytes
            + self.events.len().saturating_sub(1) as u64
    }
    fn owned_pending_bytes(&self) -> u64 {
        self.events.capacity() as u64 * std::mem::size_of::<StoredEvent>() as u64
            + self
                .events
                .iter()
                .map(|e| e.json.capacity() as u64)
                .sum::<u64>()
    }
    fn refresh_high_water(&mut self) {
        self.diagnostics.high_water_pending_bytes = self
            .diagnostics
            .high_water_pending_bytes
            .max(self.buffered_json_bytes());
        self.diagnostics.high_water_pending_events = self
            .diagnostics
            .high_water_pending_events
            .max(self.events.len());
        self.diagnostics.high_water_working_bytes = self
            .diagnostics
            .high_water_working_bytes
            .max(self.owned_pending_bytes());
    }
    fn record_failure(
        &mut self,
        stage: &str,
        error: &SpoolError,
        event: Option<&Event>,
        retained: bool,
    ) {
        let fragment = event.and_then(|e| {
            if let ksight_model::EventPayload::InspectPlaintext(p) = &e.payload {
                Some(p)
            } else {
                None
            }
        });
        self.diagnostics.last_failure = Some(SpoolFailure {
            stage: stage.into(),
            reason: error.to_string().chars().take(256).collect(),
            source_sequence: event.map(|e| e.header.source_sequence),
            fragment_sequence: fragment.map(|f| f.sequence),
            captured_bytes: fragment.map(|f| f.captured_bytes),
            captured_sha256: fragment.and_then(|f| valid_hash(&f.sha256).then(|| f.sha256.clone())),
            serialized_bytes: event.and_then(|e| measure_json(e).ok().map(|(n, _)| n)),
            retained_pending: retained,
            committed: event.is_some()
                && !retained
                && self.diagnostics.last_event_committed
                && event
                    .and_then(|e| measure_json(e).ok().map(|(_, d)| d))
                    .as_ref()
                    == self.diagnostics.last_event_digest.as_ref(),
        });
    }
    /// Snapshot of current state; all strings/counts are bounded.
    #[must_use] 
    pub fn diagnostics(&self) -> SpoolWriterDiagnostics {
        let mut d = self.diagnostics.clone();
        d.pending_json_bytes = self.buffered_json_bytes();
        d.pending_events = self.events.len();

        d
    }
    /// Whether session capacity or age requires rotation.
    #[must_use] 
    pub fn should_rotate(&self, max_age_secs: u64) -> bool {
        (max_age_secs != 0 && self.started.elapsed().as_secs() >= max_age_secs)
            || self.spool.event_capacity_exhausted()
    }
    /// Session directory.
    #[must_use] 
    pub fn directory(&self) -> &Path {
        self.spool.directory()
    }
    /// Complete encoded batch bytes, excluding the fixed metadata allowance.
    #[must_use] 
    pub fn used_bytes(&self) -> u64 {
        self.spool.used_bytes()
    }
    /// Batches committed by this instance.
    #[must_use] 
    pub fn persisted_batches(&self) -> u64 {
        self.persisted_batches
    }
}

fn batch_prefix(session: Uuid, sequence: u64) -> String {
    format!("{{\"session_id\":\"{session}\",\"batch_sequence\":{sequence},\"events\":[")
}
struct JsonMeasure {
    bytes: u64,
    hash: sha2::Sha256,
}
impl io::Write for JsonMeasure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use sha2::Digest;
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("serialized size overflow"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn measure_json(value: &impl Serialize) -> Result<(u64, String), SpoolError> {
    use sha2::Digest;
    let mut m = JsonMeasure {
        bytes: 0,
        hash: sha2::Sha256::new(),
    };
    serde_json::to_writer(&mut m, value)?;
    Ok((m.bytes, format!("{:x}", m.hash.finalize())))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recover only the captured byte range after checking encoding, length and full SHA.
/// Partial captures remain partial; transport/request completeness is not upgraded.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn recover_captured_range(
    fragment: &ksight_model::InspectPlaintext,
    range: std::ops::Range<usize>,
) -> Result<Vec<u8>, SpoolError> {
    use sha2::{Digest, Sha256};
    let n = fragment.captured_bytes as usize;
    if n > 262_144_usize {
        return Err(SpoolError::Evidence("capture_budget"));
    }
    if range.start > range.end || range.end > n {
        return Err(SpoolError::Evidence("range_out_of_capture"));
    }
    let bytes = match fragment.preview_encoding.as_str() {
        "utf8_lossy" | "utf8" => {
            if fragment.preview.len() != n {
                return Err(SpoolError::Evidence("length_mismatch"));
            }
            fragment.preview.as_bytes().to_vec()
        }
        "hex" => {
            if fragment.preview.len() != n.checked_mul(2).ok_or(SpoolError::CapacityOverflow)? {
                return Err(SpoolError::Evidence("length_mismatch"));
            }
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            let mut out = Vec::with_capacity(n);
            for p in fragment.preview.as_bytes().chunks_exact(2) {
                out.push(
                    digit(p[0])
                        .zip(digit(p[1]))
                        .map(|(h, l)| (h << 4) | l)
                        .ok_or(SpoolError::Evidence("invalid_hex"))?,
                );
            }
            out
        }
        _ => return Err(SpoolError::Evidence("unsupported_encoding")),
    };
    if !valid_hash(&fragment.sha256)
        || format!("{:x}", Sha256::digest(&bytes)) != fragment.sha256.to_ascii_lowercase()
    {
        return Err(SpoolError::Evidence("hash_mismatch"));
    }
    Ok(bytes[range].to_vec())
}
