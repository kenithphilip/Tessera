//! Hidden Unicode tag block (U+E0000..U+E007F) detection.
//!
//! Tag-block characters are invisible in most renderers but some LLM
//! tokenizers decode them. Attackers use them to hide instructions
//! in documents, web pages, or tool outputs that look clean to a
//! human reviewer.
//!
//! This module scans for any code point in the tag block, decodes
//! the hidden payload by mapping each code point back to its ASCII
//! equivalent (`cp - 0xE0000`), and reports the decoded string for
//! forensic inspection.
//!
//! Mirrors `tessera.scanners.unicode` in the Python reference.
//! Source attribution: PurpleLlama HiddenASCIIScanner.

use serde::{Deserialize, Serialize};

use crate::ScannerResult;

const TAG_START: u32 = 0xE0000;
const TAG_END: u32 = 0xE007F;
const PRINTABLE_LO: u32 = 0x20;
const PRINTABLE_HI: u32 = 0x7E;

/// Result of scanning a string for hidden Unicode tag characters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnicodeScanResult {
    pub detected: bool,
    pub hidden_payload: String,
    pub tag_count: usize,
    /// Character indices (not byte offsets) of detected tag characters.
    pub positions: Vec<usize>,
}

impl ScannerResult for UnicodeScanResult {
    fn detected(&self) -> bool {
        self.detected
    }
    fn scanner_name(&self) -> &'static str {
        "unicode_tag"
    }
}

/// Scan `text` for hidden tag-block characters and decode them into
/// the equivalent ASCII payload.
///
/// `positions` are character indices (not byte offsets), matching the
/// Python reference. A tag character outside the printable ASCII
/// projection contributes to `tag_count` and `positions` but adds an
/// empty string to `hidden_payload`.
pub fn scan_unicode_tags(text: &str) -> UnicodeScanResult {
    let mut tag_chars: Vec<(usize, char)> = Vec::new();

    for (i, ch) in text.chars().enumerate() {
        let cp = ch as u32;
        if (TAG_START..=TAG_END).contains(&cp) {
            let ascii_cp = cp - TAG_START;
            let decoded = if (PRINTABLE_LO..=PRINTABLE_HI).contains(&ascii_cp) {
                char::from_u32(ascii_cp).unwrap_or('\u{0000}')
            } else {
                '\u{0000}' // sentinel, omitted from payload below
            };
            tag_chars.push((i, decoded));
        }
    }

    if tag_chars.is_empty() {
        return UnicodeScanResult {
            detected: false,
            hidden_payload: String::new(),
            tag_count: 0,
            positions: Vec::new(),
        };
    }

    let positions: Vec<usize> = tag_chars.iter().map(|(p, _)| *p).collect();
    let hidden_payload: String = tag_chars
        .iter()
        .map(|(_, c)| *c)
        .filter(|c| *c != '\u{0000}')
        .collect();

    UnicodeScanResult {
        detected: true,
        hidden_payload,
        tag_count: tag_chars.len(),
        positions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag_char(ascii: u32) -> char {
        char::from_u32(TAG_START + ascii).unwrap()
    }

    #[test]
    fn ascii_only_text_not_detected() {
        let r = scan_unicode_tags("hello world");
        assert!(!r.detected);
        assert_eq!(r.hidden_payload, "");
        assert_eq!(r.tag_count, 0);
        assert!(r.positions.is_empty());
    }

    #[test]
    fn single_hidden_tag_detected() {
        let mut s = String::from("hi");
        s.push(tag_char(b'X' as u32));
        let r = scan_unicode_tags(&s);
        assert!(r.detected);
        assert_eq!(r.tag_count, 1);
        assert_eq!(r.hidden_payload, "X");
        assert_eq!(r.positions, vec![2]);
    }

    #[test]
    fn full_word_payload_decoded() {
        // Encode "ATTACK" as tag characters interleaved with visible text.
        let mut s = String::from("normal");
        for c in "ATTACK".chars() {
            s.push(tag_char(c as u32));
        }
        s.push_str("text");
        let r = scan_unicode_tags(&s);
        assert!(r.detected);
        assert_eq!(r.hidden_payload, "ATTACK");
        assert_eq!(r.tag_count, 6);
        assert_eq!(r.positions.len(), 6);
    }

    #[test]
    fn non_printable_tag_omitted_from_payload_but_counted() {
        // U+E0001 is the deprecated language tag (non-printable in
        // the projection). Should add to count but not to payload.
        let mut s = String::from("a");
        s.push(char::from_u32(0xE0001).unwrap());
        s.push(tag_char(b'B' as u32));
        let r = scan_unicode_tags(&s);
        assert!(r.detected);
        assert_eq!(r.tag_count, 2);
        assert_eq!(r.hidden_payload, "B");
        assert_eq!(r.positions.len(), 2);
    }

    #[test]
    fn boundary_chars_at_tag_start_and_end() {
        let mut s = String::new();
        s.push(char::from_u32(TAG_START).unwrap());
        s.push(char::from_u32(TAG_END).unwrap());
        let r = scan_unicode_tags(&s);
        assert!(r.detected);
        assert_eq!(r.tag_count, 2);
    }

    #[test]
    fn just_before_tag_block_not_detected() {
        let s: String = char::from_u32(TAG_START - 1).unwrap().into();
        let r = scan_unicode_tags(&s);
        assert!(!r.detected);
    }

    #[test]
    fn just_after_tag_block_not_detected() {
        let s: String = char::from_u32(TAG_END + 1).unwrap().into();
        let r = scan_unicode_tags(&s);
        assert!(!r.detected);
    }

    #[test]
    fn positions_are_character_indices_not_byte_offsets() {
        // Multibyte char before the tag forces byte vs char divergence.
        let multi = "\u{1F600}"; // emoji, 4 bytes UTF-8
        let mut s = String::from(multi);
        s.push(tag_char(b'Z' as u32));
        let r = scan_unicode_tags(&s);
        assert!(r.detected);
        assert_eq!(r.positions, vec![1]); // char index 1, not byte 4
    }

    #[test]
    fn scanner_result_marker_traits() {
        let r = scan_unicode_tags("abc");
        assert!(!ScannerResult::detected(&r));
        assert_eq!(ScannerResult::scanner_name(&r), "unicode_tag");
    }

    #[test]
    fn serialize_round_trip_via_serde_json() {
        let r = scan_unicode_tags("hello");
        let json = serde_json::to_string(&r).unwrap();
        let back: UnicodeScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
