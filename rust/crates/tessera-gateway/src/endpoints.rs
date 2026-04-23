//! HTTP endpoints exposing the new Rust primitives.
//!
//! Mirrors the AgentMesh proxy's session-keyed REST surface for the
//! load-bearing primitives. Routes here are mounted on top of the
//! existing chat-mediation / A2A router (`build_app` in `lib.rs`); the
//! two surfaces coexist without sharing state.
//!
//! Wired endpoints (matches `agentmesh.proxy` for these primitives):
//!
//! | Endpoint                       | Method | Purpose                                       |
//! |--------------------------------|--------|-----------------------------------------------|
//! | `/healthz`                     | GET    | proxy health, primitive feature flags         |
//! | `/v1/sessions`                 | GET    | active session ids and eviction stats         |
//! | `/v1/context`                  | GET    | one session's context state                   |
//! | `/v1/context/split`            | GET    | trusted / untrusted halves                    |
//! | `/v1/reset`                    | POST   | drop one session                              |
//! | `/v1/evaluate`                 | POST   | full taint-tracking policy decision           |
//! | `/v1/label`                    | POST   | sign and add a tool output to context         |
//! | `/v1/audit/verify`             | GET    | walk the JSONL hash chain                     |
//! | `/v1/ssrf/check`               | POST   | SSRF guard verdict on a URL                   |
//! | `/v1/url-rules/check`          | POST   | static URL rules verdict                      |
//!
//! The router uses `Arc<PrimitivesState>` as its state. Construct it
//! once at startup and clone the Arc per request.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use tessera_audit::audit_log::{verify_chain, AppendEntry, JsonlHashchainSink};
use tessera_core::context::make_segment;
use tessera_core::labels::{HmacSigner, HmacVerifier, Origin, TrustLevel};
use tessera_policy::policy::{DecisionKind, Policy};
use tessera_policy::ssrf_guard::SsrfGuard;
use tessera_policy::url_rules::{RuleVerdict, UrlRulesEngine};
use tessera_runtime::session_context::SessionContextStore;

use crate::simd_extractor::SimdJson;

/// Shared state for the primitives router.
///
/// `policy` and `url_rules` use [`arc_swap::ArcSwap`] for wait-free
/// reads on the request hot path. Updates are still serialized (an
/// `ArcSwap` swap is atomic, but writers must rebuild the whole
/// inner value), which matches our access pattern: read-heavy with
/// rare config-driven updates.
pub struct PrimitivesState {
    pub principal: String,
    pub signer: HmacSigner,
    pub verifier: HmacVerifier,
    pub policy: arc_swap::ArcSwap<Policy>,
    pub contexts: Arc<SessionContextStore>,
    pub audit_sink: Option<Arc<JsonlHashchainSink>>,
    pub audit_seal_key: Option<Vec<u8>>,
    pub ssrf_guard: SsrfGuard,
    pub url_rules: arc_swap::ArcSwap<UrlRulesEngine>,
}

impl PrimitivesState {
    /// Convenience constructor with all defaults: empty policy, no
    /// audit sink, default SSRF guard, empty URL rules. The session
    /// store uses a 1-hour TTL and a 10k cap.
    pub fn with_signing_key(principal: impl Into<String>, signing_key: Vec<u8>) -> Self {
        Self {
            principal: principal.into(),
            signer: HmacSigner::new(signing_key.clone()),
            verifier: HmacVerifier::new(signing_key),
            policy: arc_swap::ArcSwap::from_pointee(Policy::new()),
            contexts: Arc::new(SessionContextStore::new(3600.0, 10_000)),
            audit_sink: None,
            audit_seal_key: None,
            ssrf_guard: SsrfGuard::with_defaults(),
            url_rules: arc_swap::ArcSwap::from_pointee(UrlRulesEngine::default()),
        }
    }

    /// Atomic read-clone-mutate-store helper for the `policy` ArcSwap.
    /// Reads are wait-free; writes are rare config updates, so the
    /// clone is acceptable.
    pub fn update_policy<F: FnOnce(&mut Policy)>(&self, f: F) {
        let mut next = (**self.policy.load()).clone();
        f(&mut next);
        self.policy.store(Arc::new(next));
    }

    /// Same pattern for the URL rules engine.
    pub fn update_url_rules<F: FnOnce(&mut UrlRulesEngine)>(&self, f: F) {
        let mut next = (**self.url_rules.load()).clone();
        f(&mut next);
        self.url_rules.store(Arc::new(next));
    }
}

/// Build the primitives router. Compose with the existing chat /
/// A2A router via `Router::merge`.
pub fn build_router(state: Arc<PrimitivesState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sessions", get(sessions))
        .route("/v1/context", get(context_handler))
        .route("/v1/context/split", get(context_split))
        .route("/v1/reset", post(reset))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/label", post(label))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/ssrf/check", post(ssrf_check))
        .route("/v1/url-rules/check", post(url_rules_check))
        .with_state(state)
}

// ---- request / response shapes ----

#[derive(Deserialize)]
struct SessionQuery {
    #[serde(default = "default_session_id")]
    session_id: String,
}

fn default_session_id() -> String {
    "default".to_string()
}

#[derive(Deserialize)]
struct EvaluateBody {
    tool_name: String,
    #[serde(default = "default_session_id")]
    session_id: String,
}

#[derive(Deserialize)]
struct LabelBody {
    text: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default = "default_session_id")]
    session_id: String,
}

#[derive(Deserialize)]
struct SsrfCheckBody {
    url: String,
}

#[derive(Deserialize)]
struct UrlRulesCheckBody {
    url: String,
    #[serde(default = "default_method")]
    method: String,
}

fn default_method() -> String {
    "GET".to_string()
}

// ---- handlers ----

async fn healthz(State(state): State<Arc<PrimitivesState>>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "tessera-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "active_sessions": state.contexts.len(),
        "session_evictions": state.contexts.evictions(),
        "session_ttl_seconds": state.contexts.ttl().as_secs_f64(),
        "session_max": state.contexts.max_sessions(),
        "policy_requirements": state.policy.load().requirements_count(),
        "url_rules": state.url_rules.load().rule_count(),
        "audit_log_configured": state.audit_sink.is_some(),
    }))
}

async fn sessions(State(state): State<Arc<PrimitivesState>>) -> impl IntoResponse {
    Json(json!({
        "count": state.contexts.len(),
        "session_ids": state.contexts.session_ids(),
        "evictions": state.contexts.evictions(),
        "ttl_seconds": state.contexts.ttl().as_secs_f64(),
        "max_sessions": state.contexts.max_sessions(),
    }))
}

async fn context_handler(
    State(state): State<Arc<PrimitivesState>>,
    Query(q): Query<SessionQuery>,
) -> impl IntoResponse {
    let ctx = match state.contexts.get(&q.session_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let ctx = ctx.lock();
    Json(json!({
        "session_id": q.session_id,
        "segments": ctx.len(),
        "min_trust": ctx.min_trust().as_int(),
        "max_trust": ctx.max_trust().as_int(),
    }))
    .into_response()
}

async fn context_split(
    State(state): State<Arc<PrimitivesState>>,
    Query(q): Query<SessionQuery>,
) -> impl IntoResponse {
    let ctx = match state.contexts.get(&q.session_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let snapshot = {
        let g = ctx.lock();
        g.clone()
    };
    let (trusted, untrusted) = snapshot.split_by_trust();
    Json(json!({
        "session_id": q.session_id,
        "trusted_segments": trusted.len(),
        "untrusted_segments": untrusted.len(),
        "trusted_min_trust": trusted.min_trust().as_int(),
        "untrusted_min_trust": if untrusted.is_empty() { 0 } else { untrusted.min_trust().as_int() },
    }))
    .into_response()
}

async fn reset(
    State(state): State<Arc<PrimitivesState>>,
    Query(q): Query<SessionQuery>,
) -> impl IntoResponse {
    state.contexts.reset(&q.session_id);
    Json(json!({ "status": "context reset", "session_id": q.session_id }))
}

async fn evaluate(
    State(state): State<Arc<PrimitivesState>>,
    SimdJson(body): SimdJson<EvaluateBody>,
) -> impl IntoResponse {
    let ctx_arc = match state.contexts.get(&body.session_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let snapshot = {
        let g = ctx_arc.lock();
        g.clone()
    };
    let policy = state.policy.load();
    let decision = policy.evaluate(&snapshot, &body.tool_name);
    let allowed = decision.allowed();
    let observed = decision.observed_trust.as_int();

    // Append an audit entry for denies; matches Python semantics where
    // allow paths do not emit POLICY_DENY events.
    if !allowed {
        if let Some(sink) = &state.audit_sink {
            let _ = sink.append(AppendEntry {
                timestamp: Utc::now().to_rfc3339(),
                kind: "policy_deny".to_string(),
                principal: state.principal.clone(),
                detail: json!({
                    "tool": decision.tool,
                    "session_id": body.session_id,
                    "required_trust": decision.required_trust.as_int(),
                    "observed_trust": observed,
                    "reason": decision.reason,
                }),
                correlation_id: None,
                trace_id: None,
            });
        }
    }

    Json(json!({
        "allowed": allowed,
        "reason": decision.reason,
        "session_id": body.session_id,
        "trust_level": observed,
        "kind": match decision.kind {
            DecisionKind::Allow => "allow",
            DecisionKind::Deny => "deny",
            DecisionKind::RequireApproval => "require_approval",
        },
    }))
    .into_response()
}

async fn label(
    State(state): State<Arc<PrimitivesState>>,
    SimdJson(body): SimdJson<LabelBody>,
) -> impl IntoResponse {
    // The Rust gateway intentionally does NOT run the Python scanner
    // suite here (that's where the largest behavior delta with
    // AgentMesh lives today). Outputs are labeled UNTRUSTED if they
    // came from a tool we don't recognize, USER otherwise. Operators
    // can call `/v1/ssrf/check` and `/v1/url-rules/check` separately.
    let trust = if body.tool_name.is_empty() {
        TrustLevel::Untrusted
    } else {
        TrustLevel::Tool
    };
    let origin = if matches!(trust, TrustLevel::Untrusted) {
        Origin::Web
    } else {
        Origin::Tool
    };
    let ctx_arc = match state.contexts.get(&body.session_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let segment = make_segment(
        body.text.clone(),
        origin,
        state.principal.clone(),
        &state.signer,
        Some(trust),
    );
    let trust_int = segment.label.trust_level.as_int();
    {
        let mut g = ctx_arc.lock();
        g.add(segment);
    }
    let (segments, min_trust) = {
        let g = ctx_arc.lock();
        (g.len(), g.min_trust().as_int())
    };
    Json(json!({
        "trust_level": trust_int,
        "session_id": body.session_id,
        "context_segments": segments,
        "min_trust": min_trust,
    }))
    .into_response()
}

async fn audit_verify(State(state): State<Arc<PrimitivesState>>) -> impl IntoResponse {
    let Some(sink) = &state.audit_sink else {
        return Json(json!({
            "configured": false,
            "valid": null,
            "records_checked": 0,
        }))
        .into_response();
    };
    let path = sink.path().to_path_buf();
    let result = match verify_chain(&path, state.audit_seal_key.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "configured": true,
                    "valid": false,
                    "reason": e.to_string(),
                })),
            )
                .into_response()
        }
    };
    Json(json!({
        "configured": true,
        "path": path.display().to_string(),
        "valid": result.valid,
        "records_checked": result.records_checked,
        "first_bad_seq": result.first_bad_seq,
        "reason": result.reason,
        "seal_valid": result.seal_valid,
        "last_seq": sink.last_seq(),
        "last_hash": sink.last_hash(),
    }))
    .into_response()
}

async fn ssrf_check(
    State(state): State<Arc<PrimitivesState>>,
    SimdJson(body): SimdJson<SsrfCheckBody>,
) -> impl IntoResponse {
    let decision = state.ssrf_guard.check_url(&body.url);
    Json(json!({
        "allowed": decision.allowed,
        "primary_reason": decision.primary_reason(),
        "findings": decision.findings.iter().map(|f| json!({
            "rule_id": f.rule_id,
            "category": f.category,
            "message": f.message,
            "url": f.url,
            "resolved_ip": f.resolved_ip,
        })).collect::<Vec<_>>(),
    }))
}

async fn url_rules_check(
    State(state): State<Arc<PrimitivesState>>,
    SimdJson(body): SimdJson<UrlRulesCheckBody>,
) -> impl IntoResponse {
    let engine = state.url_rules.load();
    let decision = engine.evaluate(&body.url, &body.method);
    Json(json!({
        "configured": engine.rule_count() > 0,
        "rule_count": engine.rule_count(),
        "verdict": match decision.verdict {
            RuleVerdict::Allow => "allow",
            RuleVerdict::Deny => "deny",
            RuleVerdict::NoMatch => "no_match",
        },
        "rule_id": decision.rule_id,
        "description": decision.description,
        "url": decision.url,
        "method": decision.method,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::Value;
    use tower::ServiceExt;

    fn state() -> Arc<PrimitivesState> {
        Arc::new(PrimitivesState::with_signing_key(
            "tessera-gateway-test",
            b"test-endpoints-32bytes!!!!!!!!!!".to_vec(),
        ))
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_reports_primitive_state() {
        let app = build_router(state());
        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "tessera-gateway");
        assert_eq!(json["active_sessions"], 0);
        assert_eq!(json["audit_log_configured"], false);
    }

    #[tokio::test]
    async fn evaluate_allows_when_context_clean() {
        let s = state();
        let app = build_router(Arc::clone(&s));
        // Empty context defaults min_trust=System => any tool clears
        // the default required_trust=USER.
        let resp = app
            .oneshot(
                Request::post("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tool_name": "send_email"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["allowed"], true);
    }

    #[tokio::test]
    async fn evaluate_denies_when_session_tainted() {
        let s = state();
        s.update_policy(|p| p.require_tool("send_email", TrustLevel::User));
        // Add a Web (Untrusted) segment to alice's context.
        let ctx = s.contexts.get("alice").unwrap();
        let segment = make_segment(
            "evil",
            Origin::Web,
            "alice",
            &s.signer,
            None,
        );
        ctx.lock().add(segment);

        let app = build_router(Arc::clone(&s));
        let resp = app
            .oneshot(
                Request::post("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tool_name":"send_email","session_id":"alice"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["allowed"], false);
        assert_eq!(json["session_id"], "alice");
    }

    #[tokio::test]
    async fn evaluate_isolates_sessions() {
        let s = state();
        s.update_policy(|p| p.require_tool("send_email", TrustLevel::User));
        // Taint alice. Bob stays clean.
        let ctx = s.contexts.get("alice").unwrap();
        ctx.lock().add(make_segment("evil", Origin::Web, "alice", &s.signer, None));

        let app = build_router(Arc::clone(&s));
        let req_alice = Request::post("/v1/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tool_name":"send_email","session_id":"alice"}"#))
            .unwrap();
        let resp_alice = app.clone().oneshot(req_alice).await.unwrap();
        let json_alice = body_json(resp_alice).await;
        assert_eq!(json_alice["allowed"], false);

        let req_bob = Request::post("/v1/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tool_name":"send_email","session_id":"bob"}"#))
            .unwrap();
        let resp_bob = app.oneshot(req_bob).await.unwrap();
        let json_bob = body_json(resp_bob).await;
        assert_eq!(json_bob["allowed"], true);
    }

    #[tokio::test]
    async fn label_adds_to_session_context_and_isolates() {
        let s = state();
        let app = build_router(Arc::clone(&s));

        // Label something into alice's session.
        let req = Request::post("/v1/label")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text":"alice tool output","tool_name":"search","session_id":"alice"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["context_segments"], 1);
        assert_eq!(json["session_id"], "alice");

        // Bob's context is untouched.
        let resp_bob = app
            .oneshot(
                Request::get("/v1/context?session_id=bob")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bob = body_json(resp_bob).await;
        assert_eq!(bob["segments"], 0);
    }

    #[tokio::test]
    async fn ssrf_check_blocks_loopback() {
        let s = state();
        let app = build_router(s);
        let resp = app
            .oneshot(
                Request::post("/v1/ssrf/check")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"url":"http://127.0.0.1/"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["allowed"], false);
        assert_eq!(json["findings"][0]["category"], "loopback");
    }

    #[tokio::test]
    async fn ssrf_check_blocks_aws_metadata_with_specific_id() {
        let s = state();
        let app = build_router(s);
        let resp = app
            .oneshot(
                Request::post("/v1/ssrf/check")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"url":"http://169.254.169.254/latest/meta-data/"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["allowed"], false);
        assert_eq!(json["findings"][0]["rule_id"], "ssrf.cloud_metadata.aws_gcp_azure_oci");
    }

    #[tokio::test]
    async fn url_rules_check_returns_no_match_when_empty() {
        let s = state();
        let app = build_router(s);
        let resp = app
            .oneshot(
                Request::post("/v1/url-rules/check")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"url":"https://example.com/","method":"GET"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["verdict"], "no_match");
    }

    #[tokio::test]
    async fn url_rules_check_returns_deny_for_matching_rule() {
        use tessera_policy::url_rules::{PatternKind, RuleAction, UrlRule};
        let s = state();
        s.update_url_rules(|e| {
            e.add(
                UrlRule::new("github.admin.deny", "https://api.github.com/admin/")
                    .kind(PatternKind::Prefix)
                    .action(RuleAction::Deny)
                    .description("block admin"),
            );
        });
        let app = build_router(s);
        let resp = app
            .oneshot(
                Request::post("/v1/url-rules/check")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"url":"https://api.github.com/admin/users","method":"GET"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["verdict"], "deny");
        assert_eq!(json["rule_id"], "github.admin.deny");
    }

    #[tokio::test]
    async fn sessions_lists_active() {
        let s = state();
        s.contexts.get("alice").unwrap();
        s.contexts.get("bob").unwrap();
        let app = build_router(Arc::clone(&s));
        let resp = app
            .oneshot(Request::get("/v1/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["count"], 2);
        let mut ids: Vec<&str> = json["session_ids"].as_array().unwrap().iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["alice", "bob"]);
    }

    #[tokio::test]
    async fn reset_drops_one_session_only() {
        let s = state();
        let app = build_router(Arc::clone(&s));
        s.contexts.get("alice").unwrap().lock().add(
            make_segment("hi", Origin::User, "alice", &s.signer, None),
        );
        s.contexts.get("bob").unwrap().lock().add(
            make_segment("hi", Origin::User, "bob", &s.signer, None),
        );
        app.clone()
            .oneshot(
                Request::post("/v1/reset?session_id=alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Alice gone, Bob preserved.
        assert_eq!(s.contexts.get("alice").unwrap().lock().len(), 0);
        assert_eq!(s.contexts.get("bob").unwrap().lock().len(), 1);
    }

    #[tokio::test]
    async fn audit_verify_unconfigured_returns_placeholder() {
        let s = state();
        let app = build_router(s);
        let resp = app
            .oneshot(Request::get("/v1/audit/verify").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["configured"], false);
        assert_eq!(json["valid"], Value::Null);
    }

    #[tokio::test]
    async fn audit_verify_after_evaluate_deny_writes_record() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut s = PrimitivesState::with_signing_key(
            "tessera-gateway-test",
            b"test-endpoints-32bytes!!!!!!!!!!".to_vec(),
        );
        s.audit_sink = Some(Arc::new(JsonlHashchainSink::new(&path, 1, None).unwrap()));
        s.update_policy(|p| p.require_tool("send_email", TrustLevel::User));
        // Taint a session.
        let ctx = s.contexts.get("alice").unwrap();
        ctx.lock().add(make_segment("evil", Origin::Web, "alice", &s.signer, None));
        let s = Arc::new(s);
        let app = build_router(Arc::clone(&s));
        // Trigger a deny.
        app.clone()
            .oneshot(
                Request::post("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tool_name":"send_email","session_id":"alice"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Verify the chain.
        let resp = app
            .oneshot(Request::get("/v1/audit/verify").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["configured"], true);
        assert_eq!(json["valid"], true);
        assert_eq!(json["records_checked"], 1);
    }
}
