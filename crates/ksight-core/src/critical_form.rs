//! Classify reconstructed HTTP as a critical app form submit (login / SMS / OTP).
//!
//! This is report-side labeling of already-captured plaintext HTTP — not a new
//! capture ABI. Markers are generic field names, not a particular app's RPC.

/// Stable labels for mirror / report surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalFormHit {
    pub kind: &'static str,
    pub method_rpc: Option<String>,
    pub detail: String,
}

/// Scan a reconstructed HTTP request for critical form markers.
#[must_use]
pub fn classify_critical_form(
    http_method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> Option<CriticalFormHit> {
    let path_l = path.to_ascii_lowercase();
    let body_s = String::from_utf8_lossy(body);
    let body_l = body_s.to_ascii_lowercase();

    // Generic form markers
    if http_method.eq_ignore_ascii_case("POST") {
        if body_l.contains("sendsms")
            || body_l.contains("send_sms")
            || body_l.contains("sendcode")
            || body_l.contains("send_code")
            || body_l.contains("验证码")
        {
            return Some(CriticalFormHit {
                kind: "sms",
                method_rpc: None,
                detail: format!("{} {}{}", http_method, host, path),
            });
        }
        if path_l.contains("login") || body_l.contains("\"password\"") || body_l.contains("passwd=")
        {
            return Some(CriticalFormHit {
                kind: "login",
                method_rpc: None,
                detail: format!("{} {}{}", http_method, host, path),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_send_sms_field_is_sms() {
        let hit = classify_critical_form("POST", "api.example.test", "/v1/notify", b"send_sms=1")
            .expect("hit");
        assert_eq!(hit.kind, "sms");
        assert!(hit.method_rpc.is_none());
    }
}
