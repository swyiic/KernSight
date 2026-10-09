//! Existing adapter quota closure; no new quota or numeric-source authority.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct Receipt {
    pub schema: &'static str,
    pub adapter: String,
    pub hit_cap: u32,
    pub accepted_hits: u32,
    pub producer_stopped: bool,
    pub stop_error: Option<String>,
    pub coverage_partial: bool,
    pub omitted_future_events: Option<u64>,
    pub queued_records: &'static str,
}

pub(super) fn eligible(adapter: &str, connkey: bool, hits: u32, cap: u32) -> bool {
    !connkey
        && cap != 0
        && hits >= cap
        && (adapter.starts_with("jni_") && !matches!(adapter, "jni_registration" | "jni_plaintext")
            || adapter.starts_with("binder_parcel_"))
}

pub(super) fn close(
    adapter: &str,
    hits: u32,
    cap: u32,
    stop: impl FnOnce() -> Result<(), String>,
) -> Receipt {
    let error = stop().err();
    Receipt {
        schema: "kernsight.probe-quota-stop/v1",
        adapter: adapter.into(),
        hit_cap: cap,
        accepted_hits: hits,
        producer_stopped: error.is_none(),
        stop_error: error,
        coverage_partial: true,
        omitted_future_events: None,
        queued_records: "retain original epoch; drain and count omitted records and perf loss",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_quota_only_excludes_sources_and_connection_pairs() {
        assert!(!eligible("jni_get_byte_array_region", false, 1023, 1024));
        assert!(eligible("jni_get_byte_array_region", false, 1024, 1024));
        assert!(eligible("binder_parcel_int32", false, 1024, 1024));
        for adapter in [
            "tls_ssl_read",
            "tls_ssl_write",
            "linker_so_load",
            "art_dex_load",
            "jni_registration",
            "binder_userspace",
        ] {
            assert!(!eligible(adapter, false, 1024, 1024));
        }
        assert!(!eligible("jni_get_byte_array_region", true, 1024, 1024));
    }
    #[test]
    fn closure_retains_tail_loss_and_unknown_future_omissions() {
        use std::collections::VecDeque;
        struct Producer {
            live: bool,
            queue: VecDeque<u32>,
            retained: Vec<u32>,
            loss: u64,
        }
        let mut q = Producer {
            live: true,
            queue: VecDeque::from([1, 2]),
            retained: vec![],
            loss: 7,
        };
        let r = close("binder_parcel_int32", 1024, 1024, || {
            q.live = false;
            Ok(())
        });
        assert!(r.producer_stopped && r.coverage_partial);
        assert_eq!(r.omitted_future_events, None);
        assert_eq!(q.queue.len(), 2); // Stop leaves original queue owned, not discarded.
        let end = crate::shutdown_drain::stop_and_drain(
            &mut q,
            |q| !q.live,
            |q| {
                assert!(!q.live);
                if let Some(n) = q.queue.pop_front() {
                    q.retained.push(n);
                    Ok::<_, ()>(false)
                } else {
                    Ok(true)
                }
            },
            || true,
        )
        .unwrap();
        assert!(end.complete());
        assert_eq!(q.retained, [1, 2]);
        assert_eq!(q.loss, 7);
        assert!(r.coverage_partial); // Queue closure never upgrades quota coverage.
        let failed = close("binder_parcel_int32", 1024, 1024, || {
            Err("detach unconfirmed".into())
        });
        assert!(!failed.producer_stopped);
        assert_eq!(failed.stop_error.as_deref(), Some("detach unconfirmed"));
    }
}
