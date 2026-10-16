//! CJK structural analysis and gating.
//!
//! Each supported CJK encoding has a dedicated analyzer that walks the byte
//! stream once, computing three metrics simultaneously:
//! - `pair_ratio`: valid multi-byte pairs / lead bytes (structural score)
//! - `mb_bytes`: count of non-ASCII bytes in valid multi-byte sequences
//! - `lead_diversity`: count of distinct lead byte values in valid pairs
//!
//! These metrics feed the CJK gating stage, which eliminates false positives
//! on single-byte data that happens to look like CJK.

/// Result of a structural analysis for one encoding.
#[derive(Debug, Clone, Copy)]
pub struct Analysis {
    /// Valid multi-byte pairs divided by total lead bytes encountered.
    pub pair_ratio: f64,
    /// Number of non-ASCII bytes participating in valid multi-byte sequences.
    pub mb_bytes: usize,
    /// Number of distinct lead byte values in valid pairs.
    pub lead_diversity: usize,
}

impl Analysis {
    pub fn new(pair_ratio: f64, mb_bytes: usize, lead_diversity: usize) -> Self {
        Self {
            pair_ratio,
            mb_bytes,
            lead_diversity,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-encoding analyzers
// ---------------------------------------------------------------------------

/// GBK structural analyzer.
///
/// Lead bytes: 0x81-0xFE. Trail bytes: 0x40-0x7E, 0x80-0xFE.
fn analyze_gbk(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0x81..=0xFE).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() {
                let trail = data[i + 1];
                if (0x40..=0x7E).contains(&trail) || (0x80..=0xFE).contains(&trail) {
                    valid_count += 1;
                    leads[b as usize] = true;
                    mb_bytes += 1;
                    if trail > 0x7F {
                        mb_bytes += 1;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// GB18030 / GB2312 structural analyzer.
///
/// Only counts strict GB2312 2-byte pairs (lead 0xA1-0xF7, trail 0xA1-0xFE)
/// and GB18030 4-byte sequences. The broader GBK extension range is
/// intentionally excluded because it is so permissive that unrelated
/// single-byte data can score 1.0.
fn analyze_gb18030(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0x81..=0xFE).contains(&b) {
            lead_count += 1;
            // Try 4-byte first (byte2 in 0x30-0x39 distinguishes from 2-byte)
            if i + 3 < data.len()
                && (0x30..=0x39).contains(&data[i + 1])
                && (0x81..=0xFE).contains(&data[i + 2])
                && (0x30..=0x39).contains(&data[i + 3])
            {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 2;
                i += 4;
                continue;
            }
            // 2-byte GB2312: Lead 0xA1-0xF7, Trail 0xA1-0xFE
            if (0xA1..=0xF7).contains(&b)
                && i + 1 < data.len()
                && (0xA1..=0xFE).contains(&data[i + 1])
            {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 2;
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// Big5 structural analyzer.
///
/// Lead 0xA1-0xF9; Trail 0x40-0x7E, 0xA1-0xFE.
fn analyze_big5(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0xA1..=0xF9).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() {
                let trail = data[i + 1];
                if (0x40..=0x7E).contains(&trail) || (0xA1..=0xFE).contains(&trail) {
                    valid_count += 1;
                    leads[b as usize] = true;
                    mb_bytes += 1;
                    if trail > 0x7F {
                        mb_bytes += 1;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// Big5-HKSCS structural analyzer.
///
/// Lead bytes: 0x87-0xFE. Trail bytes: 0x40-0x7E, 0xA1-0xFE.
fn analyze_big5hkscs(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0x87..=0xFE).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() {
                let trail = data[i + 1];
                if (0x40..=0x7E).contains(&trail) || (0xA1..=0xFE).contains(&trail) {
                    valid_count += 1;
                    leads[b as usize] = true;
                    mb_bytes += 1;
                    if trail > 0x7F {
                        mb_bytes += 1;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// Shift_JIS structural analyzer.
///
/// Lead bytes: 0x81-0x9F, 0xE0-0xEF. Trail bytes: 0x40-0x7E, 0x80-0xFC.
fn analyze_shift_jis(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0x81..=0x9F).contains(&b) || (0xE0..=0xEF).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() {
                let trail = data[i + 1];
                if (0x40..=0x7E).contains(&trail) || (0x80..=0xFC).contains(&trail) {
                    valid_count += 1;
                    leads[b as usize] = true;
                    mb_bytes += 1;
                    if trail > 0x7F {
                        mb_bytes += 1;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// EUC-JP structural analyzer.
///
/// Two-byte: Lead 0xA1-0xFE, Trail 0xA1-0xFE.
/// SS2 (half-width katakana): 0x8E + 0xA1-0xDF.
/// SS3 (JIS X 0212): 0x8F + 0xA1-0xFE + 0xA1-0xFE.
fn analyze_euc_jp(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0x8E {
            // SS2 sequence
            lead_count += 1;
            if i + 1 < data.len() && (0xA1..=0xDF).contains(&data[i + 1]) {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 2;
                i += 2;
                continue;
            }
        } else if b == 0x8F {
            // SS3 sequence
            lead_count += 1;
            if i + 2 < data.len()
                && (0xA1..=0xFE).contains(&data[i + 1])
                && (0xA1..=0xFE).contains(&data[i + 2])
            {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 3;
                i += 3;
                continue;
            }
        } else if (0xA1..=0xFE).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() && (0xA1..=0xFE).contains(&data[i + 1]) {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 2;
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

/// EUC-KR structural analyzer.
///
/// Lead 0xA1-0xFE; Trail 0xA1-0xFE.
fn analyze_euc_kr(data: &[u8]) -> Analysis {
    let mut lead_count = 0usize;
    let mut valid_count = 0usize;
    let mut mb_bytes = 0usize;
    let mut leads = [false; 256];

    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (0xA1..=0xFE).contains(&b) {
            lead_count += 1;
            if i + 1 < data.len() && (0xA1..=0xFE).contains(&data[i + 1]) {
                valid_count += 1;
                leads[b as usize] = true;
                mb_bytes += 2;
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    let pair_ratio = if lead_count > 0 {
        valid_count as f64 / lead_count as f64
    } else {
        0.0
    };
    let lead_diversity = leads.iter().filter(|&&x| x).count();

    Analysis::new(pair_ratio, mb_bytes, lead_diversity)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Analyze the data against a specific encoding's structural rules.
pub fn analyze(data: &[u8], encoding_name: &str) -> Analysis {
    match encoding_name {
        "GBK" => analyze_gbk(data),
        "GB18030" => analyze_gb18030(data),
        "BIG5" => analyze_big5(data),
        "BIG5-HKSCS" => analyze_big5hkscs(data),
        "SHIFT_JIS" => analyze_shift_jis(data),
        "EUC-JP" => analyze_euc_jp(data),
        "EUC-KR" => analyze_euc_kr(data),
        _ => Analysis::new(0.0, 0, 0),
    }
}

// ---------------------------------------------------------------------------
// CJK gating thresholds
// ---------------------------------------------------------------------------

/// Minimum structural pair ratio for a CJK candidate to survive gating.
const MIN_PAIR_RATIO: f64 = 0.05;

/// Minimum non-ASCII byte count for a CJK candidate to survive gating.
const MIN_NON_ASCII: usize = 2;

/// Minimum ratio of non-ASCII bytes that must participate in valid
/// multi-byte sequences for a CJK candidate to survive gating.
const MIN_BYTE_COVERAGE: f64 = 0.35;

/// Minimum number of distinct lead byte values for a CJK candidate to
/// survive gating (only applied when non-ascii count is high enough).
const MIN_LEAD_DIVERSITY: usize = 4;

/// Minimum non-ASCII count before the lead diversity gate applies.
const DIVERSITY_MIN_NON_ASCII: usize = 16;

// ---------------------------------------------------------------------------
// Gating
// ---------------------------------------------------------------------------

/// Gate CJK candidates: eliminate those lacking genuine multi-byte structure.
///
/// Four checks are applied in order:
/// 1. Structural pair ratio must be >= MIN_PAIR_RATIO.
/// 2. At least MIN_NON_ASCII high bytes must be present.
/// 3. Byte coverage must be >= MIN_BYTE_COVERAGE.
/// 4. Lead byte diversity must be >= MIN_LEAD_DIVERSITY (when applicable).
///
/// Returns the surviving candidates along with their analyses.
pub fn gate_cjk<'a>(
    data: &[u8],
    candidates: &[&'a crate::EncodingInfo],
    non_ascii: usize,
) -> Vec<(&'a crate::EncodingInfo, Analysis)> {
    let mut survivors = Vec::new();

    for enc in candidates {
        if !enc.is_multibyte {
            survivors.push((*enc, Analysis::new(0.0, 0, 0)));
            continue;
        }

        let analysis = analyze(data, enc.name);

        if analysis.pair_ratio < MIN_PAIR_RATIO {
            continue;
        }
        if non_ascii < MIN_NON_ASCII {
            continue;
        }

        let byte_coverage = if non_ascii > 0 {
            analysis.mb_bytes as f64 / non_ascii as f64
        } else {
            0.0
        };
        if byte_coverage < MIN_BYTE_COVERAGE {
            continue;
        }

        if non_ascii >= DIVERSITY_MIN_NON_ASCII && analysis.lead_diversity < MIN_LEAD_DIVERSITY {
            continue;
        }

        survivors.push((enc, analysis));
    }

    survivors
}
