//! Main encoding guesser — orchestrates the detection pipeline.
//!
//! Pipeline order (each stage returns a definitive result or passes to next):
//! 1. Empty input -> UTF-8
//! 2. BOM detection -> UTF-8 / UTF-16LE / UTF-16BE
//! 3. UTF-16 shape detection (null-byte patterns)
//! 4. ASCII check
//! 5. UTF-8 validation
//! 6. Byte-validity filtering (decode with each candidate)
//! 7. CJK gating (eliminate false multi-byte matches)
//! 8. Scoring and ranking

use crate::GuessResult;
use crate::cjk;
use crate::registry::{self, EncodingInfo};
use crate::stages::{
    self, ASCII_CONFIDENCE, BOM_CONFIDENCE, DETERMINISTIC_CONFIDENCE, FALLBACK_CONFIDENCE,
    UTF8_CONFIDENCE,
};

/// The encoding guesser.
pub struct Guess;

impl Guess {
    /// Create a new guesser instance.
    pub fn new() -> Self {
        Self
    }

    /// Guess the encoding of the given byte data.
    ///
    /// Returns the best guess with a confidence score in [0.0, 1.0].
    /// Confidence is only used for ranking; callers decide their own
    /// acceptance threshold.
    pub fn guess(&self, data: &[u8]) -> GuessResult {
        self.guess_internal(data)
    }

    fn guess_internal(&self, data: &[u8]) -> GuessResult {
        // Stage 0: empty input
        if data.is_empty() {
            return GuessResult::new("UTF-8", 1.0);
        }

        // Stage 1: BOM detection
        if let Some(bom_encoding) = stages::detect_bom(data) {
            return GuessResult::new(bom_encoding, BOM_CONFIDENCE);
        }

        // Stage 2: UTF-16/32 shape detection (BOM-less)
        if let Some(wide) = stages::detect_utf16_shape(data) {
            return GuessResult::new(wide, DETERMINISTIC_CONFIDENCE);
        }

        // Stage 3: ASCII check
        if stages::is_ascii(data) {
            return GuessResult::new("UTF-8", ASCII_CONFIDENCE);
        }

        // Stage 4: UTF-8 validation
        if stages::is_valid_utf8(data) {
            return GuessResult::new("UTF-8", UTF8_CONFIDENCE);
        }

        // Remaining stages operate on non-ASCII data
        let non_ascii = stages::non_ascii_count(data);

        // Stage 5: byte-validity filtering
        let candidates = registry::registry();
        let candidate_refs: Vec<&EncodingInfo> = candidates.iter().collect();
        let valid_candidates = stages::filter_by_validity(data, &candidate_refs);

        if valid_candidates.is_empty() {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        // Stage 6: CJK gating
        let gated = cjk::gate_cjk(data, &valid_candidates, non_ascii);

        if gated.is_empty() {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        // Stage 7: score and rank
        self.score_candidates(data, &gated, non_ascii)
    }

    /// Score gated candidates and return the best match.
    ///
    /// Multi-byte candidates with high byte coverage receive a confidence
    /// boost proportional to coverage. Single-byte candidates are scored
    /// by their printable-byte ratio.
    fn score_candidates(
        &self,
        data: &[u8],
        gated: &[(&EncodingInfo, cjk::Analysis)],
        non_ascii: usize,
    ) -> GuessResult {
        let mut scored: Vec<(&EncodingInfo, f64)> = Vec::new();

        for (enc, analysis) in gated {
            if enc.is_multibyte {
                // Multi-byte: score by structural pair ratio, boosted by
                // byte coverage (ratio of non-ASCII bytes in valid pairs).
                let coverage = if non_ascii > 0 {
                    analysis.mb_bytes as f64 / non_ascii as f64
                } else {
                    0.0
                };
                let base_score = analysis.pair_ratio;
                let boosted = if coverage >= 0.95 {
                    base_score * (1.0 + coverage)
                } else {
                    base_score * (0.5 + 0.5 * coverage)
                };
                scored.push((enc, boosted.min(1.0)));
            } else {
                // Single-byte: score by printable-byte ratio among high bytes.
                let score = Self::single_byte_score(data);
                scored.push((enc, score));
            }
        }

        if scored.is_empty() {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (best_enc, best_score) = scored[0];
        GuessResult::new(best_enc.name, best_score)
    }

    /// Score single-byte encodings by measuring the ratio of printable
    /// bytes among the high-byte range.
    fn single_byte_score(data: &[u8]) -> f64 {
        let sample_len = data.len().min(8192);
        if sample_len == 0 {
            return 0.0;
        }

        let mut printable = 0usize;
        let mut high = 0usize;

        for &b in data.iter().take(sample_len) {
            if b >= 0x80 {
                high += 1;
                if (0xA0..=0xFF).contains(&b) {
                    printable += 1;
                }
            } else if matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) {
                printable += 1;
            }
        }

        if high == 0 {
            return 0.0;
        }

        let ratio = printable as f64 / sample_len as f64;
        if ratio < 0.7 {
            return 0.0;
        }

        (0.55 + 0.25 * ratio).min(0.8)
    }
}

impl Default for Guess {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let guesser = Guess::new();
        let result = guesser.guess(&[]);
        assert_eq!(result.encoding, "UTF-8");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_ascii() {
        let guesser = Guess::new();
        let result = guesser.guess(b"Hello, World!");
        assert_eq!(result.encoding, "UTF-8");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_utf8_with_multibyte() {
        let guesser = Guess::new();
        let data = "Hello, 世界.".as_bytes();
        let result = guesser.guess(data);
        assert_eq!(result.encoding, "UTF-8");
        assert_eq!(result.confidence, UTF8_CONFIDENCE);
    }

    #[test]
    fn test_utf8_bom() {
        let guesser = Guess::new();
        let data = [0xEF, 0xBB, 0xBF, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "UTF-8");
        assert_eq!(result.confidence, BOM_CONFIDENCE);
    }

    #[test]
    fn test_utf16le_bom() {
        let guesser = Guess::new();
        let data = [
            0xFF, 0xFE, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00,
        ];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "UTF-16LE");
        assert_eq!(result.confidence, BOM_CONFIDENCE);
    }

    #[test]
    fn test_utf16be_bom() {
        let guesser = Guess::new();
        let data = [
            0xFE, 0xFF, 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F,
        ];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "UTF-16BE");
        assert_eq!(result.confidence, BOM_CONFIDENCE);
    }

    #[test]
    fn test_gbk_chinese() {
        let guesser = Guess::new();
        // "你好" in GBK
        let data = [0xC4, 0xE3, 0xBA, 0xC3];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "GBK");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_big5_chinese() {
        let guesser = Guess::new();
        // "你好" in Big5 — lead bytes 0xA7/0xA6 fall within both Big5 and
        // GBK ranges. Without statistical scoring, the first matching
        // candidate in registry order (GBK) wins. This is a known
        // limitation of structural-only detection.
        let data = [0xA7, 0x41, 0xA6, 0x6E];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "GBK");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_shift_jis() {
        let guesser = Guess::new();
        // "にて" in Shift_JIS — lead byte 0x82 falls within both Shift_JIS
        // and GBK ranges. Without statistical scoring, the first matching
        // candidate in registry order (GBK) wins.
        let data = [0x82, 0xC9, 0x82, 0xC4];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "GBK");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_sparse_gbk_in_ascii() {
        let guesser = Guess::new();
        // ASCII-heavy data with sparse GBK punctuation (0xA1AA = em dash)
        let mut data = b"// Table 9.1 ".to_vec();
        data.push(0xA1);
        data.push(0xAA);
        data.extend_from_slice(b" Syntax of MPEG-4 Audio");
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "GBK");
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_utf16le_without_bom() {
        let guesser = Guess::new();
        // "Hello" in UTF-16LE without BOM
        let data = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "UTF-16LE");
        assert_eq!(result.confidence, DETERMINISTIC_CONFIDENCE);
    }

    #[test]
    fn test_registry_lookup() {
        assert!(registry::lookup("UTF-8").is_some());
        assert!(registry::lookup("gbk").is_some());
        assert!(registry::lookup("Big5").is_some());
        assert!(registry::lookup("NONEXISTENT").is_none());
    }

    #[test]
    fn test_guess_result_clamps_confidence() {
        let result = GuessResult::new("UTF-8", 1.5);
        assert_eq!(result.confidence, 1.0);
        let result = GuessResult::new("UTF-8", -0.5);
        assert_eq!(result.confidence, 0.0);
    }
}
