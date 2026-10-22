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

/// Confidence for a charset declared in markup (`<meta>` / `<?xml>` / `@charset`).
///
/// Lower than BOM/shape detection: a declaration can be wrong, but it is a
/// strong signal for non-UTF-8 text (e.g. a GBK/Big5 HTML page).
pub const MARKUP_CONFIDENCE: f64 = 0.9;

// ---------------------------------------------------------------------------
// Stage: UTF-32 shape detection (BOM-less, detect-only)
// ---------------------------------------------------------------------------

/// Detect BOM-less UTF-32 by analyzing 4-byte null lanes.
///
/// UTF-32 stores one code unit per 4 bytes. For BMP text (the common case in
/// source/markup files) exactly one of the four byte lanes carries the data
/// while the other three are NUL. We require a single printable-ASCII data
/// lane and three NUL-dominated lanes; this avoids false positives on CJK
/// (which fills two lanes) and on random binary. Returns `UTF-32LE` when the
/// data lane is lane 0, `UTF-32BE` when it is lane 3.
///
/// NOTE: `encoding_rs` does not implement UTF-32 decoding, so this is a
/// detect-only answer (no decoder is available); callers that need to transcode
/// must handle it separately.
pub fn detect_utf32_shape(data: &[u8]) -> Option<&'static str> {
    if data.len() < 8 || data.len() % 4 != 0 {
        return None;
    }
    let sample_len = data.len().min(8192);
    let sample = &data[..sample_len];
    let mut lanes_nul = [0usize; 4];
    let mut lanes_print = [0usize; 4];
    let mut chunks = 0usize;
    for q in sample.chunks_exact(4) {
        chunks += 1;
        for i in 0..4 {
            if q[i] == 0 {
                lanes_nul[i] += 1;
            } else if is_printable_ascii(q[i]) {
                lanes_print[i] += 1;
            }
        }
    }
    if chunks == 0 {
        return None;
    }
    // Exactly one data lane: < 50% NUL yet mostly printable ASCII.
    let mut data_lane = None;
    for i in 0..4 {
        if lanes_nul[i] * 2 < chunks && lanes_print[i] * 10 >= chunks * 7 {
            if data_lane.is_some() {
                return None; // more than one data lane -> not UTF-32
            }
            data_lane = Some(i);
        }
    }
    let data_lane = data_lane?;
    // The other three lanes must be >= 90% NUL.
    for (i, lane_nul) in lanes_nul.iter().enumerate() {
        if i == data_lane {
            continue;
        }
        if lane_nul * 10 < chunks * 9 {
            return None;
        }
    }
    match data_lane {
        0 => Some("UTF-32LE"),
        3 => Some("UTF-32BE"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Stage: escape-sequence encodings (ISO-2022 / HZ / UTF-7, detect-only)
// ---------------------------------------------------------------------------

/// Detect escape-sequence based encodings from control/shift markers.
///
/// These encodings are detected *by declaration* only — `encoding_rs` has no
/// decoder for them, so the returned names are detect-only answers.
pub fn detect_escape_encoding(data: &[u8]) -> Option<&'static str> {
    let has_esc = data.contains(&0x1B);
    let has_tilde = data.contains(&b'~');
    let has_plus = data.contains(&b'+');
    if !has_esc && !has_tilde && !has_plus {
        return None;
    }

    // ISO-2022-JP: ESC $ B / ESC $ @ (JIS X 0208) or ESC ( B / ESC ( J (JIS X 0201)
    if has_esc {
        let iso = data.windows(3).any(|w| {
            w[0] == 0x1B
                && ((w[1] == b'$' && (w[2] == b'B' || w[2] == b'@'))
                    || (w[1] == b'(' && (w[2] == b'B' || w[2] == b'J' || w[2] == b'I')))
        });
        if iso {
            return Some("ISO-2022-JP");
        }
    }

    // HZ-GB-2312: ~{ ... ~} with even-length GB2312 byte pairs (0x21-0x7E)
    if has_tilde {
        if let (Some(open), Some(close)) = (find_sub(data, b"~{"), find_sub(data, b"~}")) {
            if open < close {
                let region = &data[open + 2..close];
                if region.len() >= 2
                    && region.len() % 2 == 0
                    && region.iter().all(|&b| (0x21..=0x7E).contains(&b))
                {
                    return Some("HZ-GB-2312");
                }
            }
        }
    }

    // UTF-7: 7-bit; whole input is ASCII and contains a +<base64>{-,non-b64} run
    // with at least one uppercase base64 char (guard against accidental "+foo").
    if has_plus && data.iter().all(|&b| b <= 0x7F) && has_utf7_sequence(data) {
        return Some("UTF-7");
    }

    None
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Scan for a plausible UTF-7 shifted sequence: `+` followed by >=3 base64
/// chars (with at least one uppercase) and terminated by `-`, a non-base64
/// byte, or end of input. The `+-` literal-plus case is skipped.
fn has_utf7_sequence(data: &[u8]) -> bool {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let is_b64 = |b: u8| B64.contains(&b);
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'+' {
            i += 1;
            continue;
        }
        // skip literal-plus / consecutive '+' (C++-style noise)
        let mut j = i + 1;
        while j < data.len() && data[j] == b'+' {
            j += 1;
        }
        if j >= data.len() {
            break;
        }
        if data[j] == b'-' {
            i = j + 1;
            continue;
        }
        let start = j;
        let mut count = 0usize;
        let mut has_upper = false;
        while j < data.len() && is_b64(data[j]) {
            if data[j].is_ascii_uppercase() {
                has_upper = true;
            }
            count += 1;
            j += 1;
        }
        if count >= 3 && has_upper && (j >= data.len() || data[j] == b'-' || !is_b64(data[j])) {
            return true;
        }
        i = j.max(start);
    }
    false
}

// ---------------------------------------------------------------------------
// Stage: markup charset declaration (HTML / XML / CSS, detect-only)
// ---------------------------------------------------------------------------

/// Detect a character-set declared in markup and map it to a known encoding.
///
/// Only triggers on inputs that look like markup (start with `<` or contain a
/// doctype/processing-instruction/comment/html tag), so ordinary code/text is
/// never misrouted here. The returned name is a detect-only declaration.
pub fn detect_markup_charset(data: &[u8]) -> Option<&'static str> {
    let looks_like_markup = data.first().is_some_and(|&b| b == b'<')
        || contains_sub(data, b"<?xml")
        || contains_sub(data, b"<!DOCTYPE")
        || contains_sub(data, b"<!--")
        || contains_sub(data, b"<html");
    if !looks_like_markup {
        return None;
    }
    let head = &data[..data.len().min(2048)];
    let pats: &[&[u8]] = &[b"charset=", b"encoding=", b"@charset"];
    for pat in pats {
        if let Some(pos) = find_sub(head, pat) {
            // Pass the slice *after* the matched keyword so parsing starts at '='.
            if let Some(enc) = parse_charset_value(&head[pos + pat.len()..]) {
                return Some(enc);
            }
        }
    }
    None
}

/// Search for `needle` anywhere in `haystack`.
fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
    find_sub(haystack, needle).is_some()
}

/// Parse the value following a `charset=`/`encoding=`/`@charset` token and map
/// common labels to this crate's canonical encoding names.
fn parse_charset_value(rest: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    // skip the '=' (and optional spaces) after the keyword
    if rest.first() == Some(&b'=') {
        i += 1;
    }
    while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
        i += 1;
    }
    let quoted = rest.get(i) == Some(&b'"') || rest.get(i) == Some(&b'\'');
    if quoted {
        i += 1;
    }
    let start = i;
    while i < rest.len() {
        let b = rest[i];
        if quoted {
            if b == b'"' || b == b'\'' {
                break;
            }
        } else if b == b' ' || b == b'\t' || b == b'>' || b == b';' || b == b'\n' || b == b'\r' {
            break;
        }
        i += 1;
    }
    if i == start {
        return None;
    }
    let raw = &rest[start..i];
    // Build a lowercased ASCII label. Charset tokens are ASCII, so a plain
    // byte-wise lowercase is sufficient and avoids char-conversion pitfalls.
    let mut label = String::with_capacity(raw.len());
    for &b in raw {
        if b.is_ascii() {
            label.push(b.to_ascii_lowercase() as char);
        }
    }
    let label = label.trim();
    let mapped = match label {
        "utf-8" | "utf8" => "UTF-8",
        "utf-16" => "UTF-16LE",
        "utf-16le" => "UTF-16LE",
        "utf-16be" => "UTF-16BE",
        "gbk" | "gb2312" | "gbk2312" => "GBK",
        "gb18030" => "GB18030",
        "big5" | "big5-hkscs" | "big5_hkscs" => "BIG5",
        "shift_jis" | "shift-jis" | "sjis" => "SHIFT_JIS",
        "euc-jp" => "EUC-JP",
        "euc-kr" => "EUC-KR",
        "iso-8859-1" | "latin1" | "latin-1" | "windows-1252" => "WINDOWS-1252",
        "iso-2022-jp" => "ISO-2022-JP",
        "hz-gb-2312" | "hz" => "HZ-GB-2312",
        "utf-7" => "UTF-7",
        "utf-32" | "utf-32le" => "UTF-32LE",
        "utf-32be" => "UTF-32BE",
        _ => return None,
    };
    Some(mapped)
}

// ---------------------------------------------------------------------------
// Stage: binary backstop
// ---------------------------------------------------------------------------

/// Heuristic check for non-text (binary) data.
///
/// Counts NUL, DEL, and control bytes (excluding tab/newline/CR) in a bounded
/// sample; if they exceed 1% of the sample the input is treated as binary.
/// High bytes (>= 0x80) are *not* counted, so CJK and other 8-bit text pass.
pub fn is_binary(data: &[u8]) -> bool {
    if data.len() < 32 {
        return false;
    }
    let sample_len = data.len().min(8192);
    let sample = &data[..sample_len];
    let mut binary = 0usize;
    for &b in sample {
        if b == 0 || b == 0x7F || b < 0x09 || (b > 0x0D && b < 0x20) {
            binary += 1;
        }
    }
    binary * 100 > sample_len
}
