//! Tessera core primitives.
//!
//! Two load-bearing types:
//! - [`labels::TrustLabel`]: HMAC-signed provenance label that travels
//!   with every chunk of context entering the LLM.
//! - [`context::Context`]: ordered list of labeled segments with the
//!   `min_trust` taint-tracking invariant the policy engine reads.
//!
//! No I/O, no async, no tokio. This crate is the dependency floor of
//! the whole Tessera Rust workspace; everything else builds on it.

pub mod context;
pub mod label;
pub mod labels;

pub use context::{make_segment, Context, LabeledSegment};
pub use label::{
    InformationCapacity, IntegrityLevel, ProvenanceLabel, PublicMarker, Readers,
    SecrecyLevel, SegmentRef,
};
pub use labels::{
    HmacSigner, HmacVerifier, Origin, TrustLabel, TrustLevel, VerifyError, SYSTEM, TOOL,
    UNTRUSTED, USER,
};
