//! Main encoding guesser — orchestrates the detection pipeline.
//!
//! Pipeline order (each stage returns a definitive result or passes to next):
//! 0.  Empty input -> UTF-8
//! 1.  BOM detection -> UTF-8 / UTF-16LE / UTF-16BE
//! 2.  Escape-sequence encodings (ISO-2022 / HZ / UTF-7)
//! 3.  UTF-32 shape detection (BOM-less, detect-only)
//! 4.  UTF-16 shape detection (BOM-less)
//! 5.  Markup charset declaration (HTML / XML / CSS)
//! 6.  ASCII check
//! 7.  UTF-8 validation
//! 8.  Binary backstop
//! 9.  Byte-validity filtering
//! 10. CJK gating
//! 11. Scoring and ranking (+ optional bigram statistical tiebreak)

use crate::GuessResult;
use crate::cjk;
use crate::registry::{self, EncodingInfo};
use crate::stages::{
    self, ASCII_CONFIDENCE, BOM_CONFIDENCE, DETERMINISTIC_CONFIDENCE, FALLBACK_CONFIDENCE,
    MARKUP_CONFIDENCE, UTF8_CONFIDENCE,
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

        // Stage 2: escape-sequence encodings (ISO-2022 / HZ / UTF-7)
        if let Some(esc) = stages::detect_escape_encoding(data) {
            return GuessResult::new(esc, DETERMINISTIC_CONFIDENCE);
        }

        // Stage 3: UTF-32 shape detection (BOM-less, detect-only)
        if let Some(utf32) = stages::detect_utf32_shape(data) {
            return GuessResult::new(utf32, DETERMINISTIC_CONFIDENCE);
        }

        // Stage 4: UTF-16 shape detection (BOM-less)
        if let Some(wide) = stages::detect_utf16_shape(data) {
            return GuessResult::new(wide, DETERMINISTIC_CONFIDENCE);
        }

        // Stage 5: markup charset declaration
        if let Some(markup) = stages::detect_markup_charset(data) {
            return GuessResult::new(markup, MARKUP_CONFIDENCE);
        }

        // Stage 6: ASCII check
        if stages::is_ascii(data) {
            return GuessResult::new("UTF-8", ASCII_CONFIDENCE);
        }

        // Stage 7: UTF-8 validation
        if stages::is_valid_utf8(data) {
            return GuessResult::new("UTF-8", UTF8_CONFIDENCE);
        }

        // Stage 8: binary backstop — skip expensive CJK analysis on non-text.
        // Keeps the common text paths (UTF-8/GBK/UTF-16) completely untouched.
        if stages::is_binary(data) {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        // Remaining stages operate on non-ASCII text data.
        let non_ascii = stages::non_ascii_count(data);

        // Stage 9: byte-validity filtering
        let candidates = registry::registry();
        let candidate_refs: Vec<&EncodingInfo> = candidates.iter().collect();
        let valid_candidates = stages::filter_by_validity(data, &candidate_refs);

        if valid_candidates.is_empty() {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        // Stage 10: CJK gating
        let gated = cjk::gate_cjk(data, &valid_candidates, non_ascii);

        if gated.is_empty() {
            return GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE);
        }

        // Stage 11: score and rank
        self.score_candidates(data, &gated, non_ascii)
    }

    /// Score gated candidates and return the best match.
    ///
    /// Multi-byte candidates with high byte coverage receive a confidence
    /// boost proportional to coverage. Single-byte candidates are scored
    /// by their printable-byte ratio.
    ///
    /// Multi-byte (CJK) candidates are kept in their own priority group: once
    /// byte-validity filtering and CJK gating have confirmed the input is
    /// structurally compatible with at least one CJK encoding, the answer is
    /// always chosen from that group (see `docs/known-limitations.md` #5). This
    /// preserves the crate's CJK-first intent and prevents the single-byte
    /// scorer (which can reach 0.8) from outranking a genuine CJK match.
    ///
    /// When the `bigram` feature is enabled and multiple multi-byte candidates
    /// survive with structurally close scores, a statistical bigram model is
    /// used as a tiebreak *within* the multi-byte group (see `crate::bigram`).
    /// The model is Chinese-biased: when no candidate's statistical signal
    /// clearly dominates, the structural (registry-ordered, GBK-first) result
    /// stands.
    fn score_candidates(
        &self,
        data: &[u8],
        gated: &[(&EncodingInfo, cjk::Analysis)],
        non_ascii: usize,
    ) -> GuessResult {
        let mut mb_scored: Vec<(&EncodingInfo, f64)> = Vec::new();
        let mut sb_scored: Vec<(&EncodingInfo, f64)> = Vec::new();

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
                mb_scored.push((enc, boosted.min(1.0)));
            } else {
                // Single-byte: score by printable-byte ratio among high bytes.
                sb_scored.push((enc, Self::single_byte_score(data)));
            }
        }

        // Prefer the multi-byte (CJK) group whenever any candidate survives
        // gating; the single-byte group is only used when no CJK encoding fits.
        if !mb_scored.is_empty() {
            // Stage 11b (optional): bigram statistical tiebreak for CJK
            // encodings, applied only within the multi-byte group.
            #[cfg(feature = "bigram")]
            Self::apply_bigram_tiebreak(data, &mut mb_scored);

            mb_scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            let (best_enc, best_score) = mb_scored[0];
            return GuessResult::new(best_enc.name, best_score);
        }

        if !sb_scored.is_empty() {
            sb_scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            let (best_enc, best_score) = sb_scored[0];
            return GuessResult::new(best_enc.name, best_score);
        }

        GuessResult::new("WINDOWS-1252", FALLBACK_CONFIDENCE)
    }

    /// Statistical bigram tiebreak (only compiled with `feature = "bigram"`).
    ///
    /// Called only when the multi-byte group has a *cluster* of ≥2 candidates
    /// whose structural scores are within `AMBIGUITY_EPSILON` of the top — the
    /// genuine "CJK ambiguity" case. Among that cluster it picks the candidate
    /// whose statistical bigram model best matches the input, and lifts it just
    /// above the cluster ceiling so it wins the final sort. Its (high)
    /// structural confidence is preserved, so callers still see a confident
    /// result.
    ///
    /// Because each model is built from a per-language corpus, a Chinese input
    /// keeps matching the GBK/GB18030 models best, so the Chinese-first default
    /// is preserved unless another CJK language clearly dominates. When no
    /// candidate's model recognizes the input (`max_stat < STAT_FLOOR`) we leave
    /// the structural ranking untouched.
    #[cfg(feature = "bigram")]
    fn apply_bigram_tiebreak(data: &[u8], scored: &mut [(&EncodingInfo, f64)]) {
        use crate::bigram;

        const AMBIGUITY_EPSILON: f64 = 0.05;
        const STAT_FLOOR: f64 = 0.003;

        // Find the cluster of top structural candidates (within epsilon of max).
        let max_struct = scored.iter().map(|(_, s)| *s).fold(0.0f64, f64::max);
        let cluster: Vec<usize> = scored
            .iter()
            .enumerate()
            .filter(|(_, (_, s))| *s >= max_struct - AMBIGUITY_EPSILON)
            .map(|(i, _)| i)
            .collect();
        if cluster.len() < 2 {
            return;
        }

        // Bounded sample keeps the cost independent of input size.
        let n = data.len().min(4096);
        let sample = &data[..n];
        let stats: Vec<f64> = scored
            .iter()
            .map(|(enc, _)| bigram::score(enc.name, sample))
            .collect();

        // Require a real statistical signal; otherwise keep structural ranking.
        let max_stat = cluster.iter().map(|&i| stats[i]).fold(0.0f64, f64::max);
        if max_stat < STAT_FLOOR {
            return;
        }

        // Pick the candidate in the cluster with the strongest statistical match.
        let mut best = cluster[0];
        for &i in &cluster {
            if stats[i] > stats[best] {
                best = i;
            }
        }

        // Lift it just above every other candidate so it wins the final sort,
        // while keeping its high structural confidence.
        scored[best].1 = max_struct + 0.01;
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
        // limitation of structural-only detection and is preserved when the
        // `bigram` feature is off.
        let data = [0xA7, 0x41, 0xA6, 0x6E];
        let result = guesser.guess(&data);
        #[cfg(not(feature = "bigram"))]
        assert_eq!(result.encoding, "GBK");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_shift_jis() {
        let guesser = Guess::new();
        // "にて" in Shift_JIS — lead byte 0x82 falls within both Shift_JIS
        // and GBK ranges. Without statistical scoring, the first matching
        // candidate in registry order (GBK) wins. With the `bigram` feature
        // the statistical model correctly identifies Shift_JIS.
        let data = [0x82, 0xC9, 0x82, 0xC4];
        let result = guesser.guess(&data);
        #[cfg(not(feature = "bigram"))]
        assert_eq!(result.encoding, "GBK");
        #[cfg(feature = "bigram")]
        assert_eq!(result.encoding, "SHIFT_JIS");
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

    // --- New deterministic-stage tests (P1) ---

    #[test]
    fn test_markup_gbk_declaration() {
        let guesser = Guess::new();
        // A GBK HTML page: not UTF-8, but carries a charset declaration.
        let mut data = b"<html><head><meta charset=\"gbk\"></head><body>".to_vec();
        data.extend_from_slice(&[0xC4, 0xE3, 0xBA, 0xC3]); // 你好 in GBK
        data.extend_from_slice(b"</body></html>");
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "GBK");
        assert_eq!(result.confidence, MARKUP_CONFIDENCE);
    }

    #[test]
    fn test_iso2022jp_escape() {
        let guesser = Guess::new();
        // ISO-2022-JP designation ESC $ B followed by some bytes.
        let data = [0x1B, 0x24, 0x42, 0x21, 0x21, 0x21, 0x22];
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "ISO-2022-JP");
    }

    #[test]
    fn test_utf7_escape() {
        let guesser = Guess::new();
        // UTF-7 shift: "+T2x0" decodes (base64) to a valid UTF-16BE unit with
        // an uppercase base64 char. All bytes are ASCII.
        let data = b"Subject: +T2x0aG8- world";
        let result = guesser.guess(data);
        assert_eq!(result.encoding, "UTF-7");
    }

    #[test]
    fn test_binary_backstop() {
        let guesser = Guess::new();
        // Alternating NUL / 0xFF: invalid UTF-8 (0xFF is not a valid lead),
        // ~50% NUL bytes -> flagged as binary and not valid utf8/ascii.
        let data: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
        assert!(stages::is_binary(&data));
        let result = guesser.guess(&data);
        assert_eq!(result.encoding, "WINDOWS-1252");
        assert_eq!(result.confidence, FALLBACK_CONFIDENCE);
    }

    // --- bigram feature tests (P2) ---

    #[cfg(feature = "bigram")]
    #[test]
    fn test_gbk_still_chinese_first() {
        let guesser = Guess::new();
        // Simplified Chinese encoded as GBK — must stay GBK (Chinese-first).
        let (bytes, _, _) = encoding_rs::GBK.encode("这是一段简体中文测试文本");
        let result = guesser.guess(&bytes);
        assert_eq!(result.encoding, "GBK");
    }

    #[cfg(feature = "bigram")]
    #[test]
    fn test_big5_disambiguation() {
        let guesser = Guess::new();
        // Traditional Chinese encoded as BIG5 — should be distinguished from GBK.
        let (bytes, _, _) = encoding_rs::BIG5.encode("中文測試繁體");
        let result = guesser.guess(&bytes);
        assert_eq!(result.encoding, "BIG5");
    }

    #[cfg(feature = "bigram")]
    #[test]
    fn test_shift_jis_disambiguation() {
        let guesser = Guess::new();
        // Japanese encoded as Shift_JIS — should be distinguished from GBK/Big5.
        let (bytes, _, _) = encoding_rs::SHIFT_JIS.encode("こんにちは世界");
        let result = guesser.guess(&bytes);
        assert_eq!(result.encoding, "SHIFT_JIS");
    }

    #[cfg(feature = "bigram")]
    #[test]
    fn test_euc_kr_disambiguation() {
        let guesser = Guess::new();
        // Korean encoded as EUC-KR — should be distinguished from CJK siblings.
        let (bytes, _, _) = encoding_rs::EUC_KR.encode("안녕하세요 세계");
        let result = guesser.guess(&bytes);
        assert_eq!(result.encoding, "EUC-KR");
    }
}
