use std::sync::OnceLock;

/// Metadata for a single supported encoding.
#[derive(Debug, Clone, Copy)]
pub struct EncodingInfo {
    /// Canonical name (WHATWG-style, uppercase with dashes).
    pub name: &'static str,
    /// Whether this encoding uses multi-byte sequences.
    pub is_multibyte: bool,
    /// The `encoding_rs` decoder for this encoding.
    pub encoding_rs: &'static encoding_rs::Encoding,
}

/// Static registry of supported encodings.
pub static REGISTRY: OnceLock<Vec<EncodingInfo>> = OnceLock::new();

/// Initialize and return the encoding registry.
pub fn registry() -> &'static [EncodingInfo] {
    REGISTRY.get_or_init(|| {
        vec![
            EncodingInfo {
                name: "UTF-8",
                is_multibyte: false,
                encoding_rs: encoding_rs::UTF_8,
            },
            EncodingInfo {
                name: "UTF-16LE",
                is_multibyte: false,
                encoding_rs: encoding_rs::UTF_16LE,
            },
            EncodingInfo {
                name: "UTF-16BE",
                is_multibyte: false,
                encoding_rs: encoding_rs::UTF_16BE,
            },
            EncodingInfo {
                name: "WINDOWS-1252",
                is_multibyte: false,
                encoding_rs: encoding_rs::WINDOWS_1252,
            },
            EncodingInfo {
                name: "GBK",
                is_multibyte: true,
                encoding_rs: encoding_rs::GBK,
            },
            EncodingInfo {
                name: "GB18030",
                is_multibyte: true,
                encoding_rs: encoding_rs::GB18030,
            },
            EncodingInfo {
                name: "BIG5",
                is_multibyte: true,
                encoding_rs: encoding_rs::BIG5,
            },
            EncodingInfo {
                name: "BIG5-HKSCS",
                is_multibyte: true,
                encoding_rs: encoding_rs::BIG5,
            },
            EncodingInfo {
                name: "SHIFT_JIS",
                is_multibyte: true,
                encoding_rs: encoding_rs::SHIFT_JIS,
            },
            EncodingInfo {
                name: "EUC-JP",
                is_multibyte: true,
                encoding_rs: encoding_rs::EUC_JP,
            },
            EncodingInfo {
                name: "EUC-KR",
                is_multibyte: true,
                encoding_rs: encoding_rs::EUC_KR,
            },
        ]
    })
}
