impl DirectorySpool {
    // Public Spool::append remains strict about duplicate sequences. Writer retries
    // may acknowledge an identical immutable destination after publication failed.
    fn append_serialized(
        &mut self,
        json: &[u8],
        sequence: u64,
        event_count: u64,
        retry_identical: bool,
        completion: bool,
        working_bytes: &mut u64,
    ) -> Result<u64, SpoolError> {
        self.reconcile_external_acknowledgements()?;
        if json.len() > DEFAULT_MAX_FRAME_BYTES as usize {
            return Err(SpoolError::BatchTooLarge {
                observed: json.len() as u64,
                maximum: DEFAULT_MAX_FRAME_BYTES,
            });
        }
        let existing = batch_path(&self.directory, sequence);
        if existing.exists() {
            if !retry_identical {
                return Err(SpoolError::NonMonotonicSequence {
                    previous: self.last_sequence.unwrap_or(sequence),
                    observed: sequence,
                });
            }
            let encoding = if existing.extension().and_then(|e| e.to_str()) == Some("lz4") {
                BatchEncoding::Lz4
            } else {
                BatchEncoding::Json
            };
            let original = decode_batch_json(&existing, encoding)?;
            *working_bytes = original.capacity() as u64;
            if original != json {
                return Err(SpoolError::DestinationExists(existing));
            }
            sync_parent(&existing)?;
            // A visible batch may have been published before its directory sync failed.
            // Reconcile the actual inventory once instead of charging/appending it twice.
            self.used_bytes = scan_inventory(&self.directory)?.used_bytes;
            let mut count = 0u64;
            let session_id = Uuid::parse_str(
                self.directory
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default(),
            )
            .map_err(|_| SpoolError::Evidence("invalid_session_directory"))?;
            visit_batches(&self.directory, session_id, None, |b| {
                count = count
                    .checked_add(b.events.len() as u64)
                    .ok_or(SpoolError::CapacityOverflow)?;
                Ok(())
            })?;
            self.event_count = count;
            self.last_sequence = Some(sequence);
            return Ok(fs::metadata(existing)?.len());
        }
        if self
            .last_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(SpoolError::NonMonotonicSequence {
                previous: self.last_sequence.unwrap(),
                observed: sequence,
            });
        }
        let encoded = self
            .options
            .compress
            .then(|| lz4_flex::compress_prepend_size(json));
        *working_bytes = encoded.as_ref().map_or(0, |b| b.capacity() as u64);
        let data = encoded.as_deref().unwrap_or(json);
        let suffix = if self.options.compress {
            BATCH_LZ4_SUFFIX
        } else {
            BATCH_JSON_SUFFIX
        };
        let incoming = data.len() as u64;
        let next = self
            .used_bytes
            .checked_add(incoming)
            .ok_or(SpoolError::CapacityOverflow)?;
        let maximum = if completion {
            self.max_bytes
        } else {
            self.max_bytes
                .saturating_sub(self.options.completion_reserve_bytes)
        };
        if next > maximum {
            return Err(SpoolError::CapacityExceeded {
                used: self.used_bytes,
                incoming,
                maximum,
            });
        }
        let destination = self.directory.join(batch_filename(sequence, suffix));
        let temporary = self
            .directory
            .join(format!(".pending-{}.tmp", Uuid::new_v4()));
        write_atomic(&temporary, &destination, data)?;
        self.used_bytes = next;
        self.last_sequence = Some(sequence);
        self.event_count = self
            .event_count
            .checked_add(event_count)
            .ok_or(SpoolError::CapacityOverflow)?;
        Ok(incoming)
    }
}

#[cfg(test)]
thread_local! {static IO_FAULT:std::cell::RefCell<Option<&'static str>>=const {std::cell::RefCell::new(None)};}
#[allow(clippy::unnecessary_wraps, reason = "Local fixture or owned callback keeps its explicit scope and fallible signature.")]
fn fault(stage: &str) -> io::Result<()> {
    #[cfg(test)]
    if IO_FAULT.with(|f| {
        let mut f = f.borrow_mut();
        if *f == Some(stage) {
            *f = None;
            true
        } else {
            false
        }
    }) {
        return Err(io::Error::other(format!("injected {stage}")));
    }
    let _ = stage;
    Ok(())
}
fn sync_parent(path: &Path) -> io::Result<()> {
    fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("missing parent directory"))?,
    )?
    .sync_all()
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, SpoolError> {
    use std::io::Read;
    let mut data = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > maximum {
        return Err(SpoolError::BatchTooLarge {
            observed: data.len() as u64,
            maximum: u32::try_from(maximum).unwrap_or(u32::MAX),
        });
    }
    Ok(data)
}
