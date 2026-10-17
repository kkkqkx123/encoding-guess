//! Optional statistical bigram model for CJK disambiguation.
//!
//! This module is only compiled when the `bigram` Cargo feature is enabled.
//!
//! `encoding-guess` deliberately ships **no external model files** (see
//! `docs/known-limitations.md`). To stay faithful to that constraint while still
//! offering statistical CJK disambiguation, the model is *generated at first
//! use* from a small embedded corpus using `encoding_rs` itself. No file is
//! read at runtime and no new dependency is introduced.
//!
//! The model consists of one 65536-slot table per supported CJK encoding. Each
//! slot corresponds to a byte bigram `(b0, b1)` and stores the *relative
//! frequency* (probability) of that bigram in the encoding's reference corpus,
//! scaled into `u16` (0 = absent, up to 4096 = ~1.0). [`score`] returns the
//! mean probability of an input's byte bigrams under a candidate's table.
//!
//! Because each table is built from a *language-specific* corpus, a Chinese
//! input keeps matching the GBK/GB18030 tables best — so the crate's
//! "Chinese-first" default is preserved, and only a clearly non-Chinese CJK
//! language overrides it.

/// Embedded reference corpora (UTF-8). Small by design — enough to give each
/// language a distinctive bigram signature without bloating the binary. They
/// intentionally include common words (你好/世界, こんにちは世界, 안녕하세요 세계,
/// 測試/繁體…) so short inputs still carry a recognizable signal.
const ZH: &str = "我们是中国人，使用简体中文进行日常交流与软件开发。编码检测是一项基础而重要的技术工作，需要综合考虑字节结构、语言特征与历史兼容性，并为源代码与文本文件提供轻量可靠的字符集识别能力。你好，世界，这是一个测试。";

/// Traditional Chinese corpus (covers the Big5 family).
const ZH_TRAD: &str =
    "我們是中國人，使用繁體中文進行日常交流與軟體開發。編碼偵測是一項基礎而重要的技術工作，需要綜合考量位元組結構、語言特徵與歷史相容性，並為原始碼與文字檔案提供輕量可靠的字元集識別能力。你好，世界，這是一個測試。";

/// Japanese corpus (hiragana / katakana / kanji) — covers Shift_JIS and EUC-JP.
const JA: &str = "これは日本語のテスト文章です。こんにちは世界。文字コードの判定は基礎的で重要な技術であり、バイト列の構造や言語の特徴を総合的に考慮する必要があります。データを解析して、正しくエンコーディングを判定できることを確認します。";

/// Korean corpus (Hangul) — covers EUC-KR.
const KO: &str = "이것은 한국어 테스트 문장입니다. 안녕하세요 세계. 문자 인코딩 판별은 기초적이고 중요한 기술이며, 바이트 열의 구조와 언어의 특징을 종합적으로 고려해야 합니다. 이 프로젝트는 소스 코드와 텍스트 파일에 대하여 가볍고 신뢰할 수 있는 인코딩 판별을 제공합니다.";

use std::sync::OnceLock;

/// A 65536-slot bigram probability table (slot index = `(b0 << 8) | b1`).
/// Each slot stores `relative_frequency * 4096`, clamped to `u16` (0 = absent).
type ModelTable = [u16; 65536];

/// Smallest non-zero probability we can represent (1/4096).
const PROB_SCALE: f64 = 4096.0;

/// Build a bigram probability table for `enc` from `corpus` (UTF-8).
///
/// The corpus is encoded with `encoding_rs` (already a dependency), its byte
/// bigrams are counted, and each bigram's relative frequency is stored scaled
/// into `u16`. Absent bigrams stay `0`, so non-matching languages score ~0 —
/// this is what gives the model its discrimination power (unlike a per-model
/// max-normalized table, which amplifies rare bigrams into false signal).
fn build_model(corpus: &str, enc: &'static encoding_rs::Encoding) -> Box<ModelTable> {
    let mut table = Box::new([0u16; 65536]);
    let (bytes, _out, _had_errors) = enc.encode(corpus);
    if bytes.len() < 2 {
        return table;
    }
    let mut counts = [0u32; 65536];
    let mut total: u32 = 0;
    for w in bytes.windows(2) {
        let code = ((w[0] as u32) << 8) | (w[1] as u32);
        counts[code as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return table;
    }
    for i in 0..65536 {
        if counts[i] > 0 {
            // Relative frequency scaled into u16; absent bigrams remain 0.
            let p = (counts[i] as f64 / total as f64) * PROB_SCALE;
            table[i] = (p.min(PROB_SCALE) as u16).max(1);
        }
    }
    table
}

/// Lazily build and cache all bigram models. Built once per process, only when
/// this module's [`score`] is first called (i.e. only on ambiguous CJK input).
/// Memory: 7 tables × 128 KiB, allocated once.
fn models() -> &'static std::collections::HashMap<&'static str, Box<ModelTable>> {
    static M: OnceLock<std::collections::HashMap<&'static str, Box<ModelTable>>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m: std::collections::HashMap<&'static str, Box<ModelTable>> =
            std::collections::HashMap::new();
        // Simplified Chinese covers both GBK and GB18030 (the latter is a superset).
        m.insert("GBK", build_model(ZH, encoding_rs::GBK));
        m.insert("GB18030", build_model(ZH, encoding_rs::GB18030));
        // Traditional Chinese for the Big5 family.
        m.insert("BIG5", build_model(ZH_TRAD, encoding_rs::BIG5));
        m.insert("BIG5-HKSCS", build_model(ZH_TRAD, encoding_rs::BIG5));
        // Japanese for Shift_JIS and EUC-JP.
        m.insert("SHIFT_JIS", build_model(JA, encoding_rs::SHIFT_JIS));
        m.insert("EUC-JP", build_model(JA, encoding_rs::EUC_JP));
        // Korean for EUC-KR.
        m.insert("EUC-KR", build_model(KO, encoding_rs::EUC_KR));
        m
    })
}

/// Statistical score in `[0, 1]` for how well `data` matches `name`'s bigram
/// model. Returns `0.0` for unknown encodings or too-short input.
///
/// The score is the mean relative frequency of `data`'s byte bigrams under the
/// candidate's table — i.e. "how characteristic of this language are my
/// bigrams". A matching language yields a clearly positive score (typically
/// 0.005–0.05); an unrelated language yields ~0. This makes the ordering
/// robust and directly comparable across candidate encodings.
pub fn score(name: &str, data: &[u8]) -> f64 {
    let table = match models().get(name) {
        Some(t) => t,
        None => return 0.0,
    };
    let n = data.len().min(4096);
    if n < 2 {
        return 0.0;
    }
    let mut sum: u32 = 0;
    let mut total: u32 = 0;
    for w in data[..n].windows(2) {
        let code = ((w[0] as u32) << 8) | (w[1] as u32);
        sum += table[code as usize] as u32;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    (sum as f64 / total as f64) / PROB_SCALE
}
