//! encoding-guess — character encoding detection for source code and text files.
//!
//! Implements a multi-stage detection pipeline inspired by chardet's architecture:
//! BOM sniffing, UTF-8 validation, UTF-16 shape detection, byte-validity filtering,
//! CJK gating, and structural probing — all without external model files.

mod cjk;
mod detector;
mod registry;
mod stages;

pub use detector::Guess;
pub use registry::{EncodingInfo, REGISTRY};

/// Result of an encoding guess.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuessResult {
    pub encoding: &'static str,
    pub confidence: f64,
}

impl GuessResult {
    pub fn new(encoding: &'static str, confidence: f64) -> Self {
        Self {
            encoding,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}
