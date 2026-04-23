//! Labeled context segments and `min_trust` taint-tracking.
//!
//! Mirrors `tessera.context` from the Python reference. A [`Context`]
//! is an ordered list of [`LabeledSegment`]s. The load-bearing
//! security property is [`Context::min_trust`]: the policy engine
//! evaluates tool calls against the *minimum* trust level across all
//! segments in the context, so any single untrusted segment drags the
//! whole context down to its level.
//!
//! This module does not enforce the policy decision itself; it just
//! exposes the data structures and the `min_trust` invariant that
//! `policy::Policy::evaluate` reads.

use serde::{Deserialize, Serialize};

use crate::labels::{Origin, TrustLabel, TrustLevel};

/// A chunk of content paired with its signed provenance label.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabeledSegment {
    pub content: String,
    pub label: TrustLabel,
}

impl LabeledSegment {
    pub fn new(content: impl Into<String>, label: TrustLabel) -> Self {
        Self {
            content: content.into(),
            label,
        }
    }
}

/// Ordered collection of labeled segments forming one LLM request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Context {
    pub segments: Vec<LabeledSegment>,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, segment: LabeledSegment) {
        self.segments.push(segment);
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Highest trust level present. Empty contexts return `System`,
    /// matching the Python reference: an empty context has nothing to
    /// taint, so the upper bound is the top of the ladder.
    pub fn max_trust(&self) -> TrustLevel {
        self.segments
            .iter()
            .map(|s| s.label.trust_level)
            .max()
            .unwrap_or(TrustLevel::System)
    }

    /// **Load-bearing.** The minimum trust level present, defaulting to
    /// `System` for an empty context (nothing to taint = floor at top).
    /// Used by [`crate::policy::Policy::evaluate`] to gate side-
    /// effecting tool calls.
    ///
    /// Any change to this method changes the security property the
    /// whole library is built on; the test
    /// `min_trust_drops_to_lowest_segment` pins the invariant.
    pub fn min_trust(&self) -> TrustLevel {
        self.segments
            .iter()
            .map(|s| s.label.trust_level)
            .min()
            .unwrap_or(TrustLevel::System)
    }

    /// Iterator over segments in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, LabeledSegment> {
        self.segments.iter()
    }

    /// Split the context into two: trusted (>=USER) and untrusted
    /// (<USER). Mirrors `tessera.quarantine.split_by_trust`.
    pub fn split_by_trust(&self) -> (Context, Context) {
        let mut trusted = Context::new();
        let mut untrusted = Context::new();
        for seg in &self.segments {
            if seg.label.trust_level >= TrustLevel::User {
                trusted.add(seg.clone());
            } else {
                untrusted.add(seg.clone());
            }
        }
        (trusted, untrusted)
    }
}

/// Construct a freshly signed segment in one step. Convenience helper
/// matching `tessera.context.make_segment`.
pub fn make_segment(
    content: impl Into<String>,
    origin: Origin,
    principal: impl Into<String>,
    signer: &crate::labels::HmacSigner,
    trust_level: Option<TrustLevel>,
) -> LabeledSegment {
    let content = content.into();
    let level = trust_level.unwrap_or_else(|| origin.default_trust());
    let label = TrustLabel::new(origin, principal, level, None);
    let signed = signer.sign(label, &content);
    LabeledSegment::new(content, signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::HmacSigner;

    const KEY: &[u8] = b"test-context-32bytes!!!!!!!!!!!!";

    fn signer() -> HmacSigner {
        HmacSigner::new(KEY)
    }

    #[test]
    fn empty_context_is_at_top_of_ladder() {
        let ctx = Context::new();
        assert_eq!(ctx.min_trust(), TrustLevel::System);
        assert_eq!(ctx.max_trust(), TrustLevel::System);
        assert!(ctx.is_empty());
    }

    #[test]
    fn min_trust_reflects_lowest_segment() {
        let mut ctx = Context::new();
        ctx.add(make_segment("user input", Origin::User, "alice", &signer(), None));
        assert_eq!(ctx.min_trust(), TrustLevel::User);
        // Add a system segment; min stays at User.
        ctx.add(make_segment("sys", Origin::System, "alice", &signer(), None));
        assert_eq!(ctx.min_trust(), TrustLevel::User);
    }

    #[test]
    fn min_trust_drops_to_lowest_segment() {
        // The load-bearing invariant: any single low-trust segment
        // drags the whole context down. This test pins it; do not
        // weaken without updating the security spec.
        let mut ctx = Context::new();
        ctx.add(make_segment("user input", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("system context", Origin::System, "alice", &signer(), None));
        ctx.add(make_segment("evil web", Origin::Web, "alice", &signer(), None));
        assert_eq!(ctx.min_trust(), TrustLevel::Untrusted);
    }

    #[test]
    fn max_trust_reflects_highest_segment() {
        let mut ctx = Context::new();
        ctx.add(make_segment("evil", Origin::Web, "alice", &signer(), None));
        ctx.add(make_segment("user", Origin::User, "alice", &signer(), None));
        assert_eq!(ctx.max_trust(), TrustLevel::User);
    }

    #[test]
    fn add_appends_in_order() {
        let mut ctx = Context::new();
        ctx.add(make_segment("first", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("second", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("third", Origin::User, "alice", &signer(), None));
        let contents: Vec<&str> = ctx.iter().map(|s| s.content.as_str()).collect();
        assert_eq!(contents, vec!["first", "second", "third"]);
    }

    #[test]
    fn split_by_trust_separates_user_threshold() {
        let mut ctx = Context::new();
        ctx.add(make_segment("u1", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("w1", Origin::Web, "alice", &signer(), None));
        ctx.add(make_segment("u2", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("t1", Origin::Tool, "alice", &signer(), None));
        let (trusted, untrusted) = ctx.split_by_trust();
        assert_eq!(trusted.len(), 2);
        assert_eq!(untrusted.len(), 2);
        // Trusted half retains insertion order of qualifying segments.
        assert_eq!(trusted.segments[0].content, "u1");
        assert_eq!(trusted.segments[1].content, "u2");
        // Untrusted half: web (UNTRUSTED) and tool (TOOL).
        assert!(untrusted.segments.iter().all(|s| s.label.trust_level < TrustLevel::User));
    }

    #[test]
    fn make_segment_uses_origin_default_trust_when_unset() {
        let seg = make_segment("hi", Origin::Web, "alice", &signer(), None);
        assert_eq!(seg.label.trust_level, TrustLevel::Untrusted);
        let seg2 = make_segment("hi", Origin::User, "alice", &signer(), None);
        assert_eq!(seg2.label.trust_level, TrustLevel::User);
    }

    #[test]
    fn make_segment_honors_trust_level_override() {
        // Web origin but explicitly trust=Tool (e.g. operator vetted a
        // domain). Override should be respected.
        let seg = make_segment(
            "vetted",
            Origin::Web,
            "alice",
            &signer(),
            Some(TrustLevel::Tool),
        );
        assert_eq!(seg.label.trust_level, TrustLevel::Tool);
    }

    #[test]
    fn segments_round_trip_signature_verification() {
        use crate::labels::HmacVerifier;
        let s = signer();
        let v = HmacVerifier::new(KEY);
        let seg = make_segment("hello world", Origin::User, "alice", &s, None);
        v.verify(&seg.label, &seg.content).expect("verify ok");
    }
}
