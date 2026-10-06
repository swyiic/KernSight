//! Opaque connection keys observed from an exported getter's return value.
//!
//! The key is whatever `xqc_get_conn_user_data_by_stream` or
//! `xqc_get_conn_alp_user_data_by_stream` returned. Callers pass that value
//! in. This module does not read `xqc_stream_t`.

use std::collections::HashMap;

/// A pointer this small is NULL, an error code, or not a userspace object.
const MIN_POINTER: u64 = 0x1000;

/// How many stream pointers shared one observed return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnUserDataStats {
    /// Stream pointers that observed a usable return value.
    pub streams: u64,
    /// Distinct usable return values.
    pub returns: u64,
    /// Return values seen on two or more stream pointers.
    pub shared: u64,
}

/// Stream pointer → last usable return value.
#[derive(Debug, Default)]
pub struct ConnUserDataBook {
    by_stream: HashMap<u64, u64>,
    by_return: HashMap<u64, u64>,
}

impl ConnUserDataBook {
    /// Record one getter return. Values below [`MIN_POINTER`] are ignored.
    pub fn observe(&mut self, stream: u64, returned: u64) {
        if stream < MIN_POINTER || returned < MIN_POINTER {
            return;
        }
        if let Some(previous) = self.by_stream.insert(stream, returned) {
            if previous == returned {
                return;
            }
            self.forget_return(previous);
        }
        *self.by_return.entry(returned).or_insert(0) += 1;
    }

    /// Return value for `stream` when at least one other stream saw it too.
    #[must_use]
    pub fn shared_key(&self, stream: u64) -> Option<u64> {
        let returned = *self.by_stream.get(&stream)?;
        if self.by_return.get(&returned).copied().unwrap_or(0) >= 2 {
            Some(returned)
        } else {
            None
        }
    }

    /// Counts of observed streams, return values, and shared keys.
    #[must_use]
    pub fn stats(&self) -> ConnUserDataStats {
        ConnUserDataStats {
            streams: u64::try_from(self.by_stream.len()).unwrap_or(u64::MAX),
            returns: u64::try_from(self.by_return.len()).unwrap_or(u64::MAX),
            shared: self
                .by_return
                .values()
                .filter(|count| **count >= 2)
                .count()
                .try_into()
                .unwrap_or(u64::MAX),
        }
    }

    fn forget_return(&mut self, returned: u64) {
        let Some(count) = self.by_return.get_mut(&returned) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.by_return.remove(&returned);
        }
    }
}
