//! Provider-agnostic LLM client trait.
//!
//! [`LlmClient`] is the seam between primitives that need to call an
//! LLM (the guardrail, the LLM-driven policy builder) and the
//! transport / SDK layer that actually makes the network call. The
//! Rust workspace deliberately does not ship an Anthropic or OpenAI
//! client of its own: callers either supply a Rust impl backed by
//! `reqwest`, or wire a PyO3 callback that delegates to
//! `anthropic.Anthropic()` / `openai.OpenAI()` from a Python host.
//!
//! All methods are async via `async_trait`. The trait is
//! intentionally tiny: send a system prompt + user message, get
//! back the text. Callers parse the response into whatever
//! structured format they need.
//!
//! Mirrors the Python `LLMGuardrail._call_llm` / proposer call path
//! without baking in a specific provider SDK.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

/// Errors an LLM client can return. Kept open-ended so callers can
/// classify failures into "retry" vs "give up" without depending on
/// a provider-specific error type.
#[derive(Debug)]
pub enum LlmError {
    /// Network error, timeout, DNS failure, transport-level issue.
    Transport(String),
    /// The provider responded but the response was malformed or
    /// blocked (rate limit, content filter, etc.).
    Provider(String),
    /// The configuration is wrong (missing API key, unknown model).
    Config(String),
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Transport(m) => write!(f, "llm transport error: {m}"),
            LlmError::Provider(m) => write!(f, "llm provider error: {m}"),
            LlmError::Config(m) => write!(f, "llm config error: {m}"),
        }
    }
}

impl std::error::Error for LlmError {}

/// One LLM completion request. Provider-agnostic: the implementation
/// translates these fields into provider-specific calls.
#[derive(Clone, Debug)]
pub struct LlmRequest {
    pub model: String,
    pub system: String,
    pub user_message: String,
    pub max_tokens: u32,
    /// 0.0 = deterministic, higher = more sampling. Implementations
    /// are free to clamp.
    pub temperature: f32,
}

/// Async LLM client trait. Pluggable via runtime dependency
/// injection: pass an `Arc<dyn LlmClient>` to the guardrail or
/// policy_builder_llm constructor.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Call the LLM and return the raw response text. Implementations
    /// should NOT parse or interpret the response; that is the
    /// caller's job.
    async fn complete(&self, request: LlmRequest) -> Result<String, LlmError>;
}

/// Test-only client that returns canned responses keyed by the user
/// message. Useful for guardrail / policy_builder_llm tests that
/// need to exercise the parse path without making a network call.
#[derive(Clone, Debug, Default)]
pub struct CannedLlmClient {
    inner: Arc<Mutex<CannedLlmInner>>,
}

#[derive(Debug, Default)]
struct CannedLlmInner {
    responses: HashMap<String, String>,
    fallback: Option<String>,
    error: Option<String>,
    call_count: usize,
}

impl CannedLlmClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a response for an exact user-message match.
    pub fn with_response(self, user_message: impl Into<String>, response: impl Into<String>) -> Self {
        self.inner
            .lock()
            .responses
            .insert(user_message.into(), response.into());
        self
    }

    /// Set a fallback response for any unmatched user message.
    pub fn with_fallback(self, response: impl Into<String>) -> Self {
        self.inner.lock().fallback = Some(response.into());
        self
    }

    /// Configure the client to fail every call with the given message.
    pub fn always_fail(self, error_message: impl Into<String>) -> Self {
        self.inner.lock().error = Some(error_message.into());
        self
    }

    pub fn call_count(&self) -> usize {
        self.inner.lock().call_count
    }
}

#[async_trait]
impl LlmClient for CannedLlmClient {
    async fn complete(&self, request: LlmRequest) -> Result<String, LlmError> {
        let mut g = self.inner.lock();
        g.call_count += 1;
        if let Some(err) = &g.error {
            return Err(LlmError::Provider(err.clone()));
        }
        if let Some(canned) = g.responses.get(&request.user_message) {
            return Ok(canned.clone());
        }
        if let Some(fb) = &g.fallback {
            return Ok(fb.clone());
        }
        Err(LlmError::Provider(format!(
            "CannedLlmClient has no response for user_message: {:?}",
            request.user_message
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(msg: &str) -> LlmRequest {
        LlmRequest {
            model: "test-model".to_string(),
            system: "you are a test".to_string(),
            user_message: msg.to_string(),
            max_tokens: 100,
            temperature: 0.0,
        }
    }

    #[tokio::test]
    async fn canned_returns_exact_match() {
        let client = CannedLlmClient::new().with_response("hello", "world");
        let r = client.complete(req("hello")).await.unwrap();
        assert_eq!(r, "world");
        assert_eq!(client.call_count(), 1);
    }

    #[tokio::test]
    async fn canned_falls_back_when_no_exact_match() {
        let client = CannedLlmClient::new().with_fallback("default-response");
        let r = client.complete(req("anything")).await.unwrap();
        assert_eq!(r, "default-response");
    }

    #[tokio::test]
    async fn canned_errors_when_no_match_and_no_fallback() {
        let client = CannedLlmClient::new();
        let r = client.complete(req("missing")).await;
        assert!(matches!(r, Err(LlmError::Provider(_))));
    }

    #[tokio::test]
    async fn always_fail_produces_provider_error() {
        let client = CannedLlmClient::new().always_fail("upstream 500");
        let r = client.complete(req("anything")).await;
        match r {
            Err(LlmError::Provider(m)) => assert_eq!(m, "upstream 500"),
            _ => panic!("expected provider error"),
        }
    }

    #[tokio::test]
    async fn call_count_tracks_every_call() {
        let client = CannedLlmClient::new().with_fallback("ok");
        for _ in 0..5 {
            let _ = client.complete(req("x")).await;
        }
        assert_eq!(client.call_count(), 5);
    }
}
