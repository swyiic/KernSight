//! Explicit TLS/plaintext function ABIs. Never infer `_ex` vs `_ex2` from a
//! suffix: `SSL_write_ex2` ends with `_ex` and that misplaces the length pointer.

use serde::{Deserialize, Serialize};

/// Direction of a plaintext probe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsDirection {
    /// Outbound plaintext.
    #[default]
    Send,
    /// Inbound plaintext.
    Recv,
}

/// When the probe copies bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePhase {
    /// Copy at function entry.
    Entry,
    /// Copy at function return.
    Return,
    /// Copy at entry and again at return.
    EntryAndReturn,
}

/// Where the actual copied length comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualLengthSource {
    /// Function return value in x0 (plain `SSL_write` / `SSL_read`).
    ReturnValue,
    /// `size_t *` out-parameter (OpenSSL `_ex` / `_ex2`).
    OutPtr,
    /// Use the requested-length argument (entry-only write).
    RequestedArg,
}

impl ActualLengthSource {
    /// Parse stack-rule / `ProbeSpec` string forms.
    #[must_use]
    pub fn parse_label(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "return_value" | "return" | "retval" | "x0" => Some(Self::ReturnValue),
            "out_ptr" | "outptr" | "written_ptr" | "readbytes" => Some(Self::OutPtr),
            "requested_arg" | "requested" | "length_arg" => Some(Self::RequestedArg),
            _ => None,
        }
    }
}

/// Named calling convention. Layout is table-driven; names are not guessed
/// from suffixes at the call site.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TlsAbiKind {
    /// Plain `SSL_write`.
    OpensslWrite,
    /// Plain `SSL_read`.
    OpensslRead,
    /// `SSL_write_ex`.
    OpensslExWrite,
    /// `SSL_read_ex`.
    OpensslExRead,
    /// `SSL_write_ex2`.
    OpensslEx2Write,
    /// `SSL_read_ex2`.
    OpensslEx2Read,
    /// Plain `SSL_peek`.
    OpensslPeek,
    /// `SSL_peek_ex`.
    OpensslExPeek,
    /// `SSL_peek_ex2`.
    OpensslEx2Peek,
    /// `SSL_write_early_data`.
    OpensslEarlyWrite,
    /// `SSL_read_early_data`.
    OpensslEarlyRead,
    /// `mbedtls_ssl_write`.
    MbedtlsWrite,
    /// `mbedtls_ssl_read`.
    MbedtlsRead,
    /// `wolfSSL_write`.
    WolfsslWrite,
    /// `wolfSSL_read`.
    WolfsslRead,
    /// Vendor send with the plain `SSL_write` layout.
    VendorWrite,
    /// Vendor recv with the plain `SSL_read` layout.
    VendorRead,
    /// Explicit vendor layout that is not auto-attached.
    #[default]
    VendorCustom,
}

/// Register / return layout for one ABI kind (ARM64 AAPCS64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAbiLayout {
    /// ABI this layout describes.
    pub kind: TlsAbiKind,
    /// Send or recv.
    pub direction: TlsDirection,
    /// False for peek: copies plaintext without consuming the stream.
    pub consumes: bool,
    /// When bytes are copied.
    pub capture_phase: CapturePhase,
    /// Register index of the buffer.
    pub buffer_arg: u8,
    /// Register index of the requested length.
    pub requested_len_arg: u8,
    /// Where the copied length comes from.
    pub actual_len_source: ActualLengthSource,
    /// Register holding `size_t *written` / `*readbytes` when `OutPtr`.
    pub out_len_arg: Option<u8>,
    /// Register index of the connection.
    pub connection_arg: u8,
    /// Register index of flags when the ABI has one.
    pub flags_arg: Option<u8>,
}

/// Strip `@@OPENSSL_3` / `@LIB` version suffixes.
#[must_use]
pub fn dynsym_base_name(name: &str) -> &str {
    let no_default = name.split("@@").next().unwrap_or(name);
    no_default.split('@').next().unwrap_or(no_default)
}

/// True when `name` is an SSL/mbed/wolf application-data copy, not a generic
/// BIO chain or a QUIC encryption-level helper.
///
/// `BIO_read`/`BIO_write` live in libcrypto and copy file/mem/socket bytes.
/// `SSL_quic_read_level`/`SSL_quic_write_level` return `ssl_encryption_level_t`.
/// Neither is a plaintext-probe attach target.
#[must_use]
pub fn is_tls_application_data_export(name: &str) -> bool {
    let base = dynsym_base_name(name);
    if base.starts_with("BIO_") {
        return false;
    }
    if base.starts_with("SSL_quic_") || base.starts_with("tb_SSL_quic_") {
        return false;
    }
    !matches!(
        base,
        "SSL_provide_quic_data"
            | "SSL_set_quic_method"
            | "SSL_CTX_set_quic_method"
            | "SSL_set_quic_use_legacy_codepoint"
            | "SSL_set_quic_transport_params"
            | "SSL_get_peer_quic_transport_params"
            | "SSL_set_quic_early_data_context"
            | "SSL_process_quic_post_handshake"
            | "SSL_is_quic"
            | "tb_SSL_provide_quic_data"
            | "tb_SSL_set_quic_method"
            | "tb_SSL_set_quic_use_legacy_codepoint"
            | "tb_SSL_set_quic_transport_params"
            | "tb_SSL_get_peer_quic_transport_params"
            | "tb_SSL_set_quic_early_data_context"
            | "tb_SSL_process_quic_post_handshake"
    )
}

/// QUIC STREAM send C exports. Attach only when dynsym DEFINES the name.
pub const QUIC_STREAM_SEND_EXPORTS: &[&str] = &[
    "quic_stream_write",
    "quic_stream_send",
    "xqc_stream_send",
    "lsquic_stream_write",
];

/// QUIC STREAM recv C exports.
pub const QUIC_STREAM_RECV_EXPORTS: &[&str] = &[
    "quic_stream_read",
    "quic_stream_recv",
    "xqc_stream_recv",
    "lsquic_stream_read",
];

impl TlsAbiKind {
    /// Classify an exported symbol by exact name. `_ex2` is checked before `_ex`.
    #[must_use]
    /// Exact-name whitelist only. No substring / fuzzy mapping of vendor
    /// names (`sslWriteEx`, `Foo_write_ex`, …) onto OpenSSL `_ex` layouts.
    /// Unknown names stay [`Self::VendorCustom`] and must not auto-attach
    /// without an explicit [`crate::stack_rules::ProbeSpec::abi`].
    pub fn from_exported_symbol(name: &str) -> Self {
        if !is_tls_application_data_export(name) {
            return Self::VendorCustom;
        }
        let base = dynsym_base_name(name);
        match base {
            "SSL_write_ex2" => Self::OpensslEx2Write,
            "SSL_read_ex2" => Self::OpensslEx2Read,
            "SSL_peek_ex2" => Self::OpensslEx2Peek,
            "SSL_write_ex" => Self::OpensslExWrite,
            "SSL_read_ex" => Self::OpensslExRead,
            "SSL_peek_ex" => Self::OpensslExPeek,
            "SSL_write_early_data" => Self::OpensslEarlyWrite,
            "SSL_read_early_data" => Self::OpensslEarlyRead,
            "SSL_peek" => Self::OpensslPeek,
            "SSL_write" => Self::OpensslWrite,
            "SSL_read" => Self::OpensslRead,
            "mbedtls_ssl_write" => Self::MbedtlsWrite,
            "mbedtls_ssl_read" => Self::MbedtlsRead,
            "wolfSSL_write" => Self::WolfsslWrite,
            "wolfSSL_read" => Self::WolfsslRead,
            // Known vendor exact names with the plain SSL_write/read layout.
            // QUIC STREAM C APIs: x0=stream, x1=buf, x2=len (same as SSL_write).
            // Attach only when dynsym DEFINES the name — never by size/RVA.
            "sslWrite"
            | "SLIGHT_SSL_write"
            | "quic_stream_write"
            | "quic_stream_send"
            | "xqc_stream_send"
            | "lsquic_stream_write" => Self::VendorWrite,
            "sslRead" | "SLIGHT_SSL_read" => Self::VendorRead,
            "quic_stream_read" | "quic_stream_recv" | "xqc_stream_recv" | "lsquic_stream_read" => {
                Self::VendorRead
            }
            // Non-standard / vendor-custom: candidate only until ProbeSpec.abi pins it.
            _ => Self::VendorCustom,
        }
    }

    /// True when this ABI may be attached from an exported-name match alone.
    /// [`Self::VendorCustom`] is never auto-attached — it needs ProbeSpec.abi
    /// (and usually buffer/length overrides) before a live uprobe is armed.
    #[must_use]
    pub fn is_auto_attachable(self) -> bool {
        !matches!(self, Self::VendorCustom)
    }

    /// Register layout for this ABI kind on ARM64 AAPCS64.
    #[must_use]
    pub fn layout(self) -> TlsAbiLayout {
        match self {
            Self::OpensslWrite
            | Self::MbedtlsWrite
            | Self::WolfsslWrite
            | Self::VendorWrite
            | Self::OpensslRead
            | Self::MbedtlsRead
            | Self::WolfsslRead
            | Self::VendorRead
            | Self::OpensslPeek
            | Self::VendorCustom => self.plain_ssl_layout(),
            Self::OpensslExWrite
            | Self::OpensslEarlyWrite
            | Self::OpensslExRead
            | Self::OpensslEarlyRead
            | Self::OpensslExPeek
            | Self::OpensslEx2Write
            | Self::OpensslEx2Read
            | Self::OpensslEx2Peek => self.extended_ssl_layout(),
        }
    }

    fn plain_ssl_layout(self) -> TlsAbiLayout {
        match self {
            Self::OpensslWrite | Self::MbedtlsWrite | Self::WolfsslWrite | Self::VendorWrite => {
                TlsAbiLayout {
                    kind: self,
                    direction: TlsDirection::Send,
                    consumes: true,
                    capture_phase: CapturePhase::Entry,
                    buffer_arg: 1,
                    requested_len_arg: 2,
                    actual_len_source: ActualLengthSource::RequestedArg,
                    out_len_arg: None,
                    connection_arg: 0,
                    flags_arg: None,
                }
            }
            Self::OpensslRead | Self::MbedtlsRead | Self::WolfsslRead | Self::VendorRead => {
                TlsAbiLayout {
                    kind: self,
                    direction: TlsDirection::Recv,
                    consumes: true,
                    capture_phase: CapturePhase::EntryAndReturn,
                    buffer_arg: 1,
                    requested_len_arg: 2,
                    actual_len_source: ActualLengthSource::ReturnValue,
                    out_len_arg: None,
                    connection_arg: 0,
                    flags_arg: None,
                }
            }
            Self::OpensslPeek => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Recv,
                consumes: false,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::ReturnValue,
                out_len_arg: None,
                connection_arg: 0,
                flags_arg: None,
            },
            // Placeholder only for explicit VendorCustom + ProbeSpec overrides.
            // Do NOT auto-attach with these x1/x2 defaults — layout is unknown
            // until ProbeSpec.buffer_arg / requested_length_arg pin it.
            Self::VendorCustom => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Send,
                consumes: true,
                capture_phase: CapturePhase::Entry,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::RequestedArg,
                out_len_arg: None,
                connection_arg: 0,
                flags_arg: None,
            },
            Self::OpensslExWrite
            | Self::OpensslEarlyWrite
            | Self::OpensslExRead
            | Self::OpensslEarlyRead
            | Self::OpensslExPeek
            | Self::OpensslEx2Write
            | Self::OpensslEx2Read
            | Self::OpensslEx2Peek => self.extended_ssl_layout(),
        }
    }

    fn extended_ssl_layout(self) -> TlsAbiLayout {
        match self {
            Self::OpensslExWrite | Self::OpensslEarlyWrite => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Send,
                consumes: true,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(3),
                connection_arg: 0,
                flags_arg: None,
            },
            Self::OpensslExRead | Self::OpensslEarlyRead => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Recv,
                consumes: true,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(3),
                connection_arg: 0,
                flags_arg: None,
            },
            Self::OpensslExPeek => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Recv,
                consumes: false,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(3),
                connection_arg: 0,
                flags_arg: None,
            },
            // SSL_write_ex2(s, buf, num, flags, *written): x3=flags, x4=*written
            Self::OpensslEx2Write => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Send,
                consumes: true,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(4),
                connection_arg: 0,
                flags_arg: Some(3),
            },
            Self::OpensslEx2Read => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Recv,
                consumes: true,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(4),
                connection_arg: 0,
                flags_arg: Some(3),
            },
            Self::OpensslEx2Peek => TlsAbiLayout {
                kind: self,
                direction: TlsDirection::Recv,
                consumes: false,
                capture_phase: CapturePhase::EntryAndReturn,
                buffer_arg: 1,
                requested_len_arg: 2,
                actual_len_source: ActualLengthSource::OutPtr,
                out_len_arg: Some(4),
                connection_arg: 0,
                flags_arg: Some(3),
            },
            Self::OpensslWrite
            | Self::MbedtlsWrite
            | Self::WolfsslWrite
            | Self::VendorWrite
            | Self::OpensslRead
            | Self::MbedtlsRead
            | Self::WolfsslRead
            | Self::VendorRead
            | Self::OpensslPeek
            | Self::VendorCustom => self.plain_ssl_layout(),
        }
    }

    /// True when the copy happens on return and needs a uretprobe.
    #[must_use]
    pub fn needs_uretprobe(self) -> bool {
        matches!(
            self.layout().capture_phase,
            CapturePhase::Return | CapturePhase::EntryAndReturn
        )
    }

    /// True when the call consumes stream bytes.
    #[must_use]
    pub fn consumes(self) -> bool {
        self.layout().consumes
    }

    /// Send or recv for this ABI.
    #[must_use]
    pub fn direction(self) -> TlsDirection {
        self.layout().direction
    }

    /// Stable `snake_case` name of this ABI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpensslWrite => "openssl_write",
            Self::OpensslRead => "openssl_read",
            Self::OpensslExWrite => "openssl_ex_write",
            Self::OpensslExRead => "openssl_ex_read",
            Self::OpensslEx2Write => "openssl_ex2_write",
            Self::OpensslEx2Read => "openssl_ex2_read",
            Self::OpensslPeek => "openssl_peek",
            Self::OpensslExPeek => "openssl_ex_peek",
            Self::OpensslEx2Peek => "openssl_ex2_peek",
            Self::OpensslEarlyWrite => "openssl_early_write",
            Self::OpensslEarlyRead => "openssl_early_read",
            Self::MbedtlsWrite => "mbedtls_write",
            Self::MbedtlsRead => "mbedtls_read",
            Self::WolfsslWrite => "wolfssl_write",
            Self::WolfsslRead => "wolfssl_read",
            Self::VendorWrite => "vendor_write",
            Self::VendorRead => "vendor_read",
            Self::VendorCustom => "vendor_custom",
        }
    }
}

impl TlsDirection {
    /// `send` or `recv`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }

    /// Stream-feed label. Peek copies inbound bytes without consuming them.
    #[must_use]
    pub fn fragment_label(self, consumes: bool) -> &'static str {
        match (self, consumes) {
            (Self::Send, _) => "send",
            (Self::Recv, true) => "recv",
            (Self::Recv, false) => "peek",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ex2_is_not_classified_as_ex() {
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_write_ex2"),
            TlsAbiKind::OpensslEx2Write
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_read_ex2"),
            TlsAbiKind::OpensslEx2Read
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_write_ex"),
            TlsAbiKind::OpensslExWrite
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_read_ex"),
            TlsAbiKind::OpensslExRead
        );
        // `ends_with("_ex")` is false for `_ex2`, so the old heuristic treated
        // ex2 as a plain write (entry-only, length in x2) and missed x4=*written.
        assert!(
            !"SSL_write_ex2".ends_with("_ex") && !"SSL_write_ex2".ends_with("Ex"),
            "ex2 must not look like _ex to a suffix check"
        );
        assert_ne!(
            TlsAbiKind::from_exported_symbol("SSL_write_ex2")
                .layout()
                .out_len_arg,
            TlsAbiKind::from_exported_symbol("SSL_write_ex")
                .layout()
                .out_len_arg
        );
        assert_eq!(TlsAbiKind::OpensslEx2Write.layout().out_len_arg, Some(4));
        assert_eq!(TlsAbiKind::OpensslExWrite.layout().out_len_arg, Some(3));
    }

    #[test]
    fn bio_and_quic_level_are_not_application_data_exports() {
        for name in [
            "BIO_write",
            "BIO_read",
            "BIO_write_all",
            "SSL_quic_read_level",
            "SSL_quic_write_level",
            "SSL_provide_quic_data",
            "SSL_set_quic_method",
            "tb_SSL_quic_read_level",
        ] {
            assert!(
                !is_tls_application_data_export(name),
                "{name} must not attach as TLS plaintext"
            );
            assert_eq!(
                TlsAbiKind::from_exported_symbol(name),
                TlsAbiKind::VendorCustom,
                "{name} must not collapse to write/read via substring"
            );
        }
        assert!(is_tls_application_data_export("SSL_write"));
        assert!(is_tls_application_data_export("SSL_peek"));
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_write"),
            TlsAbiKind::OpensslWrite
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_write@@OPENSSL_3.0.0"),
            TlsAbiKind::OpensslWrite
        );
        // Substring trap: quic_write_level contains "write".
        assert_ne!(
            TlsAbiKind::from_exported_symbol("SSL_quic_write_level"),
            TlsAbiKind::VendorWrite
        );
    }

    #[test]
    fn quic_stream_exports_use_plain_write_layout_without_inventing_offsets() {
        for name in QUIC_STREAM_SEND_EXPORTS {
            assert!(is_tls_application_data_export(name));
            let abi = TlsAbiKind::from_exported_symbol(name);
            assert_eq!(abi, TlsAbiKind::VendorWrite);
            assert!(abi.is_auto_attachable());
            assert_eq!(abi.layout().buffer_arg, 1);
            assert_eq!(abi.layout().requested_len_arg, 2);
        }
        for name in QUIC_STREAM_RECV_EXPORTS {
            assert_eq!(
                TlsAbiKind::from_exported_symbol(name),
                TlsAbiKind::VendorRead
            );
        }
        assert_eq!(
            TlsAbiKind::from_exported_symbol("quic_conn_write_pkt"),
            TlsAbiKind::VendorCustom
        );
    }

    #[test]
    fn peek_is_recv_without_consume() {
        let peek = TlsAbiKind::from_exported_symbol("SSL_peek");
        assert_eq!(peek, TlsAbiKind::OpensslPeek);
        assert!(!peek.consumes());
        assert_eq!(peek.direction(), TlsDirection::Recv);
        assert_eq!(peek.direction().fragment_label(peek.consumes()), "peek");
        assert!(peek.needs_uretprobe());
        let read = TlsAbiKind::from_exported_symbol("SSL_read");
        assert!(read.consumes());
        assert_eq!(read.direction().fragment_label(read.consumes()), "recv");
    }

    #[test]
    fn plain_write_is_entry_only() {
        let write = TlsAbiKind::from_exported_symbol("SSL_write");
        assert!(!write.needs_uretprobe());
        assert_eq!(write.layout().capture_phase, CapturePhase::Entry);
    }

    #[test]
    fn vendor_and_mbedtls_names() {
        assert_eq!(
            TlsAbiKind::from_exported_symbol("sslWrite"),
            TlsAbiKind::VendorWrite
        );
        // Non-standard vendor name: never fuzzy-map onto OpensslEx*.
        assert_eq!(
            TlsAbiKind::from_exported_symbol("sslWriteEx"),
            TlsAbiKind::VendorCustom
        );
        assert!(!TlsAbiKind::from_exported_symbol("sslWriteEx").is_auto_attachable());
        assert_eq!(
            TlsAbiKind::from_exported_symbol("Foo_ssl_write_ex"),
            TlsAbiKind::VendorCustom
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("mbedtls_ssl_read"),
            TlsAbiKind::MbedtlsRead
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("wolfSSL_write"),
            TlsAbiKind::WolfsslWrite
        );
        assert_eq!(
            TlsAbiKind::from_exported_symbol("SSL_write_early_data"),
            TlsAbiKind::OpensslEarlyWrite
        );
        assert!(TlsAbiKind::OpensslWrite.is_auto_attachable());
        assert!(!TlsAbiKind::VendorCustom.is_auto_attachable());
    }
}
