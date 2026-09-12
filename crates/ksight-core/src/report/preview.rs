//! Inspect plaintext preview decode, stitch, and ranking.

use super::{extend_unique, MutablePlaintext};

pub(super) const PREVIEW_STITCH_CAP: usize = 16 * 1024;

pub(super) fn decode_inspect_preview(
    fragment: &ksight_model::InspectPlaintext,
) -> (String, String) {
    let raw = if fragment.preview_encoding == "hex" || preview_is_hex(&fragment.preview) {
        crate::decode_hex_bytes(&fragment.preview)
            .unwrap_or_else(|| fragment.preview.as_bytes().to_vec())
    } else {
        fragment.preview.as_bytes().to_vec()
    };
    if let Some(plain) = crate::inflate_inspect_buffer(&raw) {
        let text = String::from_utf8_lossy(&plain).into_owned();
        let class = if looks_mostly_printable(plain.as_slice()) {
            "text".to_owned()
        } else {
            "binary".to_owned()
        };
        return (text, class);
    }
    let class = if fragment.content_class.is_empty() {
        inferred_content_class("", Some(&fragment.preview))
    } else {
        fragment.content_class.clone()
    };
    if class == "tls_record" {
        return (fragment.preview.clone(), class);
    }
    (fragment.preview.clone(), class)
}

pub(super) fn inspect_preview_bytes(fragment: &ksight_model::InspectPlaintext) -> Vec<u8> {
    if fragment.preview_encoding == "hex" || preview_is_hex(&fragment.preview) {
        crate::decode_hex_bytes(&fragment.preview)
            .unwrap_or_else(|| fragment.preview.as_bytes().to_vec())
    } else {
        fragment.preview.as_bytes().to_vec()
    }
}

pub(super) fn absorb_plaintext_preview(
    activity: &mut MutablePlaintext,
    preview: &str,
    class: &str,
) {
    if preview.is_empty() {
        return;
    }
    extend_unique(&mut activity.urls, &preview_url_list(preview), 32);
    let new_score = preview_evidence_score(preview, class);
    activity.preview = Some(match activity.preview.take() {
        None => preview.to_owned(),
        Some(existing) => {
            let old_score = preview_evidence_score(&existing, "");
            let new_urls = new_score.0;
            let old_urls = old_score.0;
            if new_urls > 0
                && old_urls > 0
                && !preview_is_hex(preview)
                && !preview_is_hex(&existing)
                && !preview_is_tls_record_text(preview)
                && !preview_is_tls_record_text(&existing)
            {
                stitch_preview(&existing, preview)
            } else if new_score > old_score {
                preview.to_owned()
            } else {
                existing
            }
        }
    });
}

pub(super) fn preview_url_list(preview: &str) -> Vec<String> {
    crate::parse_http_plain_all(preview, "text")
        .into_iter()
        .filter_map(|parsed| {
            if !matches!(parsed.kind, "url" | "http1_request" | "http2_request") {
                return None;
            }
            let scheme = parsed.scheme.or(Some("https"));
            crate::format_inspect_url(scheme, parsed.host.as_deref()?, &parsed.path)
        })
        .collect()
}

pub(super) fn preview_evidence_score(preview: &str, class: &str) -> (u32, u8, u8, usize) {
    if preview.is_empty() || class == "tls_record" || preview_is_tls_record_text(preview) {
        return (0, 0, 0, 0);
    }
    if preview_is_hex(preview) {
        return (0, 0, 0, 0);
    }
    let urls = u32::try_from(preview_url_list(preview).len()).unwrap_or(u32::MAX);
    let kind = if preview.contains("HTTP/1.")
        || preview.starts_with("GET ")
        || preview.starts_with("POST ")
    {
        3_u8
    } else if preview.contains("\"url\"")
        || preview.contains("https://")
        || preview.contains("http://")
        || preview.contains('{')
    {
        2
    } else {
        u8::from(class == "text" || looks_mostly_printable(preview.as_bytes()))
    };
    (
        urls,
        1,
        kind,
        if urls > 0 {
            preview.len().min(PREVIEW_STITCH_CAP)
        } else {
            0
        },
    )
}

pub(super) fn stitch_preview(existing: &str, next: &str) -> String {
    let mut out = String::with_capacity(
        existing
            .len()
            .saturating_add(next.len())
            .saturating_add(1)
            .min(PREVIEW_STITCH_CAP),
    );
    out.push_str(existing);
    let next_trim = next.trim_start();
    if !existing.ends_with('\n')
        && (next_trim.starts_with("http://")
            || next_trim.starts_with("https://")
            || next_trim.starts_with("HTTP/"))
    {
        out.push('\n');
    }
    out.push_str(next);
    if out.len() > PREVIEW_STITCH_CAP {
        out.truncate(PREVIEW_STITCH_CAP);
    }
    out
}

pub(super) fn preview_is_hex(preview: &str) -> bool {
    let trimmed = preview.trim();
    trimmed.len() >= 8
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn preview_is_tls_record_text(preview: &str) -> bool {
    preview.starts_with("TLS ") || inferred_content_class("", Some(preview)) == "tls_record"
}

pub(super) fn looks_mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    printable.saturating_mul(4) >= bytes.len().saturating_mul(3)
}

pub(super) fn inferred_content_class(class: &str, preview: Option<&str>) -> String {
    if !class.is_empty() {
        return class.to_owned();
    }
    let Some(preview) = preview.map(str::trim) else {
        return String::new();
    };
    if preview.len() < 6 || !preview.is_ascii() {
        return String::new();
    }
    let Ok(record) = u8::from_str_radix(&preview[..2], 16) else {
        return String::new();
    };
    let Ok(version) = u16::from_str_radix(&preview[2..6], 16) else {
        return String::new();
    };
    if matches!(record, 0x14..=0x17) && matches!(version, 0x0301..=0x0304) {
        "tls_record".to_owned()
    } else {
        String::new()
    }
}
