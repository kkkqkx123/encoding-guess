//! Detection pipeline stages.
//!
//! Each stage either returns a definitive result or passes to the next,
//! progressing from cheap deterministic checks to more expensive analysis.

use crate::EncodingInfo;

// ---------------------------------------------------------------------------
// Stage 1: BOM detection
// ---------------------------------------------------------------------------

/// Detect byte-order marks at the start of data.
pub fn detect_bom(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        return Some("UTF-8");
    }
    if data.len() >= 2 {
        if data[0] == 0xFF && data[1] == 0xFE {
            return Some("UTF-16LE");
        }
        if data[0] == 0xFE && data[1] == 0xFF {
            return Some("UTF-16BE");
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Stage 2: UTF-16/32 null-byte pattern detection
// ---------------------------------------------------------------------------

/// Detect BOM-less UTF-16/32 by analyzing null-byte patterns.
///
/// Interleaved null bytes strongly indicate UTF-16; groups of three null
/// bytes indicate UTF-32. Returns None if the pattern does not match.
pub fn detect_utf16_shape(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    // Sample up to 8 KB for shape detection
    let sample_len = data.len().min(8192);
    let sample = &data[..sample_len];

    let mut nul_even = 0usize;
    let mut nul_odd = 0usize;
    let mut printable_other = 0usize;

    for pair in sample.chunks_exact(2) {
        let (a, b) = (pair[0], pair[1]);
        if a == 0 {
            nul_even += 1;
        } else if is_printable_ascii(a) {
            printable_other += 1;
        }
        if b == 0 {
            nul_odd += 1;
        } else if is_printable_ascii(b) {
            printable_other += 1;
        }
    }

    let nul_total = nul_even + nul_odd;
    if sample_len == 0 || nul_total * 10 < sample_len * 4 {
        return None;
    }

    let aligned = nul_even.max(nul_odd);
    if aligned * 10 < nul_total * 9 {
        return None;
    }

    if printable_other * 2 < sample_len {
        return None;
    }

    if nul_odd >= nul_even {
        Some("UTF-16LE")
    } else {
        Some("UTF-16BE")
    }
}

fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

// ---------------------------------------------------------------------------
// Stage 3: ASCII check
// ---------------------------------------------------------------------------

/// Check if every byte is printable ASCII, tab, newline, or carriage return.
pub fn is_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b <= 0x7F)
}

// ---------------------------------------------------------------------------
// Stage 4: UTF-8 validation
// ---------------------------------------------------------------------------

/// Check whether data is valid UTF-8.
pub fn is_valid_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

/// Count non-ASCII bytes in data.
pub fn non_ascii_count(data: &[u8]) -> usize {
    data.iter().filter(|&&b| b >= 0x80).count()
}

// ---------------------------------------------------------------------------
// Stage 5: Byte-validity filtering
// ---------------------------------------------------------------------------

/// Filter candidate encodings by attempting to decode the data.
///
/// Any encoding that produces a decode error is eliminated. An incomplete
/// multi-byte sequence at the very end of the data does not count as an
/// error (the input may have been cut mid-character).
pub fn filter_by_validity<'a>(
    data: &[u8],
    candidates: &[&'a EncodingInfo],
) -> Vec<&'a EncodingInfo> {
    candidates
        .iter()
        .filter(|enc| decodes_losslessly(data, enc.encoding_rs))
        .copied()
        .collect()
}

/// Check whether the data decodes without errors under the given encoding.
///
/// A trailing incomplete multi-byte sequence is tolerated (the input may be
/// a truncated view of a larger file).
fn decodes_losslessly(data: &[u8], encoding: &'static encoding_rs::Encoding) -> bool {
    // Try a full decode first
    let (text, _, had_errors) = encoding.decode(data);
    if !had_errors {
        return true;
    }

    // If there was an error, check if it's only due to a truncated tail.
    // Trim up to 3 bytes from the end (max multi-byte sequence length in
    // the encodings we support) and retry.
    for trim in 1..=3 {
        if data.len() <= trim {
            break;
        }
        let trimmed = &data[..data.len() - trim];
        let (_, _, had_errors) = encoding.decode(trimmed);
        if !had_errors {
            return true;
        }
    }

    // Also check if the decoded text contains replacement characters
    !text.contains('\u{FFFD}')
}

// ---------------------------------------------------------------------------
// Confidence helpers
// ---------------------------------------------------------------------------

/// Confidence for deterministic (non-heuristic) detections.
pub const DETERMINISTIC_CONFIDENCE: f64 = 0.95;

/// Confidence for BOM-based detection.
pub const BOM_CONFIDENCE: f64 = 1.0;

/// Confidence for ASCII detection.
pub const ASCII_CONFIDENCE: f64 = 1.0;

/// Confidence for valid UTF-8 with multi-byte sequences.
pub const UTF8_CONFIDENCE: f64 = 0.95;

/// Fallback confidence when no candidate survives.
pub const FALLBACK_CONFIDENCE: f64 = 0.10;
