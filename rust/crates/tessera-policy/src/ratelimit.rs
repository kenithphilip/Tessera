//! Token budget and tool-call rate limiting.
//!
//! Mirrors `tessera.ratelimit` in the Python reference. Two
//! independent primitives:
//!
//! - [`TokenBudget`] tracks cumulative LLM token usage per principal
//!   in a sliding time window. Addresses OWASP LLM10 (Unbounded
//!   Consumption) by giving the proxy layer a knob to deny requests
//!   that would burn through a tenant's budget.
//! - [`ToolCallRateLimit`] enforces three independent caps on
//!   per-session tool calls: a rolling window rate, a short-window
//!   burst detector with cooldown, and an absolute session lifetime
//!   cap. Mitigates Log-To-Leak style covert exfiltration.
//!
//! Both primitives are thread-safe (`parking_lot::Mutex`) and side-
//! effect-free other than the in-memory state they hold; the Python
//! `_emit_exceeded` / `_emit_burst` event-sink emissions are not
//! ported here because `tessera-policy` does not own the event-sink
//! abstraction yet. Callers can check the `Decision` and emit on
//! their own.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// ---- TokenBudget ---------------------------------------------------------

/// Snapshot of one principal's budget state at a point in time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub principal: String,
    pub used: i64,
    pub remaining: i64,
    pub limit: i64,
    pub window_seconds: f64,
    pub exceeded: bool,
}

#[derive(Clone, Debug)]
struct UsageEntry {
    tokens: i64,
    timestamp: DateTime<Utc>,
}

/// Per-principal sliding-window token budget.
///
/// Thread-safe. Tracks token consumption inside `window` and denies
/// requests that would push cumulative usage above `max_tokens`.
pub struct TokenBudget {
    max_tokens: i64,
    window: Duration,
    usage: Mutex<HashMap<String, Vec<UsageEntry>>>,
}

impl TokenBudget {
    /// `window_seconds` defaults to 24 hours when 0 is passed.
    pub fn new(max_tokens: i64, window: Duration) -> Self {
        let window = if window.is_zero() {
            Duration::hours(24)
        } else {
            window
        };
        Self {
            max_tokens,
            window,
            usage: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_default_window(max_tokens: i64) -> Self {
        Self::new(max_tokens, Duration::hours(24))
    }

    /// Attempt to consume `tokens` from `principal`'s budget at time
    /// `at`. Returns `true` when the budget allows the consumption,
    /// `false` when denied. On success, the consumption is recorded.
    pub fn consume_at(&self, principal: &str, tokens: i64, at: DateTime<Utc>) -> bool {
        let mut g = self.usage.lock();
        let entries = g.entry(principal.to_string()).or_default();
        Self::expire_in_place(entries, at, self.window);
        let current: i64 = entries.iter().map(|e| e.tokens).sum();
        if current + tokens > self.max_tokens {
            return false;
        }
        entries.push(UsageEntry {
            tokens,
            timestamp: at,
        });
        true
    }

    /// Convenience: consume at "now".
    pub fn consume(&self, principal: &str, tokens: i64) -> bool {
        self.consume_at(principal, tokens, Utc::now())
    }

    /// Tokens still available for `principal` at time `at`.
    pub fn remaining_at(&self, principal: &str, at: DateTime<Utc>) -> i64 {
        let mut g = self.usage.lock();
        let entries = g.entry(principal.to_string()).or_default();
        Self::expire_in_place(entries, at, self.window);
        let used: i64 = entries.iter().map(|e| e.tokens).sum();
        (self.max_tokens - used).max(0)
    }

    pub fn remaining(&self, principal: &str) -> i64 {
        self.remaining_at(principal, Utc::now())
    }

    pub fn status_at(&self, principal: &str, at: DateTime<Utc>) -> BudgetStatus {
        let mut g = self.usage.lock();
        let entries = g.entry(principal.to_string()).or_default();
        Self::expire_in_place(entries, at, self.window);
        let used: i64 = entries.iter().map(|e| e.tokens).sum();
        let remaining = (self.max_tokens - used).max(0);
        BudgetStatus {
            principal: principal.to_string(),
            used,
            remaining,
            limit: self.max_tokens,
            window_seconds: self.window.num_seconds() as f64,
            exceeded: remaining == 0,
        }
    }

    pub fn status(&self, principal: &str) -> BudgetStatus {
        self.status_at(principal, Utc::now())
    }

    /// Drop usage history for one principal, or all if `principal`
    /// is `None`.
    pub fn reset(&self, principal: Option<&str>) {
        let mut g = self.usage.lock();
        match principal {
            Some(p) => {
                g.remove(p);
            }
            None => g.clear(),
        }
    }

    fn expire_in_place(entries: &mut Vec<UsageEntry>, now: DateTime<Utc>, window: Duration) {
        let cutoff = now - window;
        entries.retain(|e| e.timestamp >= cutoff);
    }
}

// ---- ToolCallRateLimit ---------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallRateStatus {
    pub session_id: String,
    pub calls_in_window: usize,
    pub calls_remaining: usize,
    pub max_calls: usize,
    pub window_seconds: f64,
    pub exceeded: bool,
}

#[derive(Clone, Debug)]
struct CallEntry {
    /// Tool name retained for future audit emission (`_emit_exceeded`,
    /// `_emit_burst` in the Python reference). Not yet read by any
    /// public API in this crate; the underscore prefix and
    /// `dead_code` allowance keep the field around as a forward-
    /// compatible placeholder.
    #[allow(dead_code)]
    tool_name: String,
    timestamp: DateTime<Utc>,
}

/// Per-session tool call rate limiting with burst detection.
///
/// Three independent guards run on every `check`, in order:
/// 1. Cooldown: if a prior burst triggered a cooldown window that
///    has not elapsed yet, the call is denied with the remaining
///    seconds in the reason.
/// 2. Session lifetime cap (when set): once the session has made
///    `session_lifetime_max` calls in total, every subsequent call
///    is denied. Lifetime counts are not affected by the rolling
///    window.
/// 3. Window rate: at most `max_calls` calls in the rolling
///    `window`.
/// 4. Burst: if the current call (counted) would push the count in
///    the last `burst_window` to `burst_threshold` or above, deny
///    and start a `cooldown`.
///
/// Thread-safe. The internal state (call entries, lifetime counts,
/// burst alerts, cooldown deadlines) is guarded by a single
/// `parking_lot::Mutex`.
pub struct ToolCallRateLimit {
    max_calls: usize,
    window: Duration,
    burst_threshold: usize,
    burst_window: Duration,
    cooldown: Duration,
    session_lifetime_max: Option<usize>,
    inner: Mutex<ToolCallRateLimitState>,
}

#[derive(Default)]
struct ToolCallRateLimitState {
    calls: HashMap<String, Vec<CallEntry>>,
    total_calls: HashMap<String, usize>,
    burst_alerts: HashMap<String, usize>,
    cooldown_until: HashMap<String, DateTime<Utc>>,
}

impl ToolCallRateLimit {
    /// All knobs configurable. Pass `Duration::zero()` for any of
    /// the duration parameters to fall back to the documented
    /// defaults (matching Python).
    pub fn new(
        max_calls: usize,
        window: Duration,
        burst_threshold: usize,
        burst_window: Duration,
        cooldown: Duration,
        session_lifetime_max: Option<usize>,
    ) -> Self {
        let window = if window.is_zero() {
            Duration::minutes(5)
        } else {
            window
        };
        let burst_window = if burst_window.is_zero() {
            Duration::seconds(5)
        } else {
            burst_window
        };
        let cooldown = if cooldown.is_zero() {
            Duration::seconds(30)
        } else {
            cooldown
        };
        Self {
            max_calls,
            window,
            burst_threshold,
            burst_window,
            cooldown,
            session_lifetime_max,
            inner: Mutex::new(ToolCallRateLimitState::default()),
        }
    }

    /// Defaults from the Python reference: 50 calls per 5 minutes,
    /// 10 calls in 5 seconds = burst, 30s cooldown, 500-call lifetime.
    pub fn with_defaults() -> Self {
        Self::new(
            50,
            Duration::minutes(5),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            Some(500),
        )
    }

    /// Check (and on success, record) a tool call. Returns
    /// `(allowed, reason_if_denied)`.
    pub fn check_at(
        &self,
        session_id: &str,
        tool_name: &str,
        at: DateTime<Utc>,
    ) -> (bool, Option<String>) {
        let mut g = self.inner.lock();

        // Cooldown.
        if let Some(deadline) = g.cooldown_until.get(session_id).copied() {
            if at < deadline {
                let remaining = (deadline - at).num_seconds().max(0);
                return (
                    false,
                    Some(format!(
                        "cooldown active: {remaining}s remaining after burst"
                    )),
                );
            }
            g.cooldown_until.remove(session_id);
        }

        // Session lifetime.
        if let Some(max) = self.session_lifetime_max {
            let total = g.total_calls.get(session_id).copied().unwrap_or(0);
            if total >= max {
                return (
                    false,
                    Some(format!("session lifetime limit: {total}/{max}")),
                );
            }
        }

        // Window rate.
        let entries = g.calls.entry(session_id.to_string()).or_default();
        let cutoff = at - self.window;
        entries.retain(|e| e.timestamp >= cutoff);
        if entries.len() >= self.max_calls {
            let max = self.max_calls;
            let win = self.window.num_seconds();
            let now_count = entries.len();
            return (
                false,
                Some(format!("rate limit: {now_count}/{max} per {win}s")),
            );
        }

        // Burst (the call being evaluated counts).
        let burst_cutoff = at - self.burst_window;
        let burst_count = entries
            .iter()
            .filter(|e| e.timestamp > burst_cutoff)
            .count()
            + 1;
        if burst_count >= self.burst_threshold {
            *g.burst_alerts.entry(session_id.to_string()).or_insert(0) += 1;
            g.cooldown_until
                .insert(session_id.to_string(), at + self.cooldown);
            let bw = self.burst_window.num_seconds();
            let cd = self.cooldown.num_seconds();
            return (
                false,
                Some(format!(
                    "burst detected: {burst_count} calls in {bw}s, cooldown {cd}s"
                )),
            );
        }

        // Record.
        entries.push(CallEntry {
            tool_name: tool_name.to_string(),
            timestamp: at,
        });
        *g.total_calls.entry(session_id.to_string()).or_insert(0) += 1;
        (true, None)
    }

    pub fn check(&self, session_id: &str, tool_name: &str) -> (bool, Option<String>) {
        self.check_at(session_id, tool_name, Utc::now())
    }

    /// Convenience: same as `check` but returns just the bool.
    pub fn allow(&self, session_id: &str, tool_name: &str) -> bool {
        self.check(session_id, tool_name).0
    }

    pub fn status_at(&self, session_id: &str, at: DateTime<Utc>) -> CallRateStatus {
        let mut g = self.inner.lock();
        let entries = g.calls.entry(session_id.to_string()).or_default();
        let cutoff = at - self.window;
        entries.retain(|e| e.timestamp >= cutoff);
        let count = entries.len();
        let remaining = self.max_calls.saturating_sub(count);
        CallRateStatus {
            session_id: session_id.to_string(),
            calls_in_window: count,
            calls_remaining: remaining,
            max_calls: self.max_calls,
            window_seconds: self.window.num_seconds() as f64,
            exceeded: remaining == 0,
        }
    }

    pub fn status(&self, session_id: &str) -> CallRateStatus {
        self.status_at(session_id, Utc::now())
    }

    pub fn reset(&self, session_id: Option<&str>) {
        let mut g = self.inner.lock();
        match session_id {
            Some(s) => {
                g.calls.remove(s);
            }
            None => g.calls.clear(),
        }
    }

    /// Total calls observed for `session_id` across the lifetime,
    /// independent of the rolling window. Useful for audit.
    pub fn total_calls(&self, session_id: &str) -> usize {
        self.inner
            .lock()
            .total_calls
            .get(session_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn burst_alerts(&self, session_id: &str) -> usize {
        self.inner
            .lock()
            .burst_alerts
            .get(session_id)
            .copied()
            .unwrap_or(0)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    // ---- TokenBudget ----

    #[test]
    fn token_consume_within_budget_allows() {
        let b = TokenBudget::with_default_window(100);
        assert!(b.consume("alice", 30));
        assert!(b.consume("alice", 60));
        assert_eq!(b.remaining("alice"), 10);
    }

    #[test]
    fn token_consume_exceeding_budget_denies() {
        let b = TokenBudget::with_default_window(100);
        assert!(b.consume("alice", 80));
        assert!(!b.consume("alice", 30));
        // The denied call must NOT be recorded.
        assert_eq!(b.remaining("alice"), 20);
    }

    #[test]
    fn token_isolates_per_principal() {
        let b = TokenBudget::with_default_window(100);
        assert!(b.consume("alice", 100));
        assert!(b.consume("bob", 50));
        assert_eq!(b.remaining("alice"), 0);
        assert_eq!(b.remaining("bob"), 50);
    }

    #[test]
    fn token_window_expiration_returns_budget() {
        let b = TokenBudget::new(100, Duration::seconds(60));
        assert!(b.consume_at("alice", 100, t(0)));
        assert_eq!(b.remaining_at("alice", t(30)), 0);
        // After window passes, full budget is back.
        assert_eq!(b.remaining_at("alice", t(61)), 100);
    }

    #[test]
    fn token_status_carries_full_state() {
        let b = TokenBudget::with_default_window(100);
        b.consume("alice", 70);
        let s = b.status("alice");
        assert_eq!(s.principal, "alice");
        assert_eq!(s.used, 70);
        assert_eq!(s.remaining, 30);
        assert_eq!(s.limit, 100);
        assert!(!s.exceeded);
    }

    #[test]
    fn token_status_exceeded_when_full() {
        let b = TokenBudget::with_default_window(100);
        b.consume("alice", 100);
        let s = b.status("alice");
        assert!(s.exceeded);
        assert_eq!(s.remaining, 0);
    }

    #[test]
    fn token_reset_principal_clears_only_that_principal() {
        let b = TokenBudget::with_default_window(100);
        b.consume("alice", 50);
        b.consume("bob", 80);
        b.reset(Some("alice"));
        assert_eq!(b.remaining("alice"), 100);
        assert_eq!(b.remaining("bob"), 20);
    }

    #[test]
    fn token_reset_all_clears_everything() {
        let b = TokenBudget::with_default_window(100);
        b.consume("alice", 50);
        b.consume("bob", 80);
        b.reset(None);
        assert_eq!(b.remaining("alice"), 100);
        assert_eq!(b.remaining("bob"), 100);
    }

    #[test]
    fn token_remaining_for_unseen_principal_is_full_budget() {
        let b = TokenBudget::with_default_window(100);
        assert_eq!(b.remaining("never_seen"), 100);
    }

    #[test]
    fn token_partial_window_expiration_keeps_recent() {
        let b = TokenBudget::new(100, Duration::seconds(60));
        assert!(b.consume_at("alice", 30, t(0)));
        assert!(b.consume_at("alice", 30, t(40)));
        // At t=70, only the t=40 entry survives.
        assert_eq!(b.remaining_at("alice", t(70)), 70);
    }

    // ---- ToolCallRateLimit ----

    #[test]
    fn rate_calls_within_window_allowed() {
        let r = ToolCallRateLimit::new(
            5,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        for _ in 0..5 {
            assert!(r.check_at("s1", "tool", t(0)).0);
        }
        let (allowed, reason) = r.check_at("s1", "tool", t(1));
        assert!(!allowed);
        assert!(reason.unwrap().starts_with("rate limit:"));
    }

    #[test]
    fn rate_window_expiration_resets() {
        let r = ToolCallRateLimit::new(
            3,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        for sec in 0..3 {
            assert!(r.check_at("s1", "tool", t(sec)).0);
        }
        // 4th call within window: deny.
        assert!(!r.check_at("s1", "tool", t(4)).0);
        // 4th call after the window: allow.
        assert!(r.check_at("s1", "tool", t(120)).0);
    }

    #[test]
    fn rate_burst_triggers_cooldown() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(300),
            5,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        // 4 calls inside the 5s burst window are fine (count=5 with current).
        assert!(r.check_at("s1", "t", t(0)).0);
        assert!(r.check_at("s1", "t", t(1)).0);
        assert!(r.check_at("s1", "t", t(2)).0);
        assert!(r.check_at("s1", "t", t(3)).0);
        // 5th call inside burst window triggers detection (4 prior + 1 = 5 >= 5).
        let (allowed, reason) = r.check_at("s1", "t", t(4));
        assert!(!allowed);
        assert!(reason.unwrap().starts_with("burst detected:"));
        // Cooldown is active for 30s.
        assert!(!r.check_at("s1", "t", t(10)).0);
        // After cooldown elapses, allow again.
        assert!(r.check_at("s1", "t", t(40)).0);
    }

    #[test]
    fn rate_session_lifetime_cap_denies() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(300),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            Some(3),
        );
        for sec in 0..3 {
            assert!(r.check_at("s1", "t", t(sec * 10)).0);
        }
        let (allowed, reason) = r.check_at("s1", "t", t(40));
        assert!(!allowed);
        assert!(reason.unwrap().contains("session lifetime"));
    }

    #[test]
    fn rate_isolates_per_session() {
        let r = ToolCallRateLimit::new(
            2,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        assert!(r.check_at("s1", "t", t(0)).0);
        assert!(r.check_at("s1", "t", t(1)).0);
        assert!(!r.check_at("s1", "t", t(2)).0);
        // Different session, fresh budget.
        assert!(r.check_at("s2", "t", t(2)).0);
    }

    #[test]
    fn rate_status_reports_remaining() {
        let r = ToolCallRateLimit::new(
            10,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        for sec in 0..3 {
            r.check_at("s1", "t", t(sec)).0;
        }
        let s = r.status_at("s1", t(3));
        assert_eq!(s.calls_in_window, 3);
        assert_eq!(s.calls_remaining, 7);
        assert!(!s.exceeded);
    }

    #[test]
    fn rate_status_exceeded_when_full() {
        let r = ToolCallRateLimit::new(
            2,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        r.check_at("s1", "t", t(0));
        r.check_at("s1", "t", t(1));
        let s = r.status_at("s1", t(2));
        assert!(s.exceeded);
        assert_eq!(s.calls_remaining, 0);
    }

    #[test]
    fn rate_reset_session_clears_only_that_session() {
        let r = ToolCallRateLimit::new(
            2,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        r.check_at("s1", "t", t(0));
        r.check_at("s1", "t", t(1));
        r.check_at("s2", "t", t(0));
        r.reset(Some("s1"));
        assert_eq!(r.status_at("s1", t(2)).calls_in_window, 0);
        assert_eq!(r.status_at("s2", t(2)).calls_in_window, 1);
    }

    #[test]
    fn rate_total_calls_tracks_across_window() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        for sec in 0..5 {
            r.check_at("s1", "t", t(sec));
        }
        // total_calls is lifetime, not windowed.
        assert_eq!(r.total_calls("s1"), 5);
    }

    #[test]
    fn rate_cooldown_message_includes_seconds() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(300),
            3,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        // Trigger burst.
        r.check_at("s1", "t", t(0));
        r.check_at("s1", "t", t(1));
        let _ = r.check_at("s1", "t", t(2)); // burst trip
        let (allowed, reason) = r.check_at("s1", "t", t(10));
        assert!(!allowed);
        let r_str = reason.unwrap();
        assert!(r_str.starts_with("cooldown active:"));
        assert!(r_str.ends_with("after burst"));
    }

    #[test]
    fn rate_with_defaults_construction_succeeds() {
        let r = ToolCallRateLimit::with_defaults();
        let s = r.status("any-session");
        assert_eq!(s.max_calls, 50);
        assert_eq!(s.window_seconds, 300.0);
    }

    #[test]
    fn rate_burst_alerts_increment_on_each_burst() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(300),
            3,
            Duration::seconds(5),
            Duration::seconds(1), // short cooldown so we can trigger again
            None,
        );
        r.check_at("s1", "t", t(0));
        r.check_at("s1", "t", t(1));
        let _ = r.check_at("s1", "t", t(2)); // burst 1
        // After cooldown:
        r.check_at("s1", "t", t(10));
        r.check_at("s1", "t", t(11));
        let _ = r.check_at("s1", "t", t(12)); // burst 2
        assert!(r.burst_alerts("s1") >= 2);
    }

    #[test]
    fn rate_allow_convenience_returns_bool() {
        let r = ToolCallRateLimit::new(
            1,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        assert!(r.allow("s1", "t"));
        assert!(!r.allow("s1", "t"));
    }

    #[test]
    fn rate_lifetime_cap_unset_means_no_limit() {
        let r = ToolCallRateLimit::new(
            1000,
            Duration::seconds(60),
            10000,
            Duration::seconds(1),
            Duration::seconds(30),
            None,
        );
        for sec in 0..50 {
            assert!(r.check_at("s1", "t", t(sec * 2)).0);
        }
        assert_eq!(r.total_calls("s1"), 50);
    }

    #[test]
    fn rate_reset_all_clears_every_session() {
        let r = ToolCallRateLimit::new(
            10,
            Duration::seconds(60),
            10,
            Duration::seconds(5),
            Duration::seconds(30),
            None,
        );
        r.check_at("s1", "t", t(0));
        r.check_at("s2", "t", t(0));
        r.reset(None);
        assert_eq!(r.status_at("s1", t(1)).calls_in_window, 0);
        assert_eq!(r.status_at("s2", t(1)).calls_in_window, 0);
    }

    #[test]
    fn rate_burst_window_independent_of_main_window() {
        let r = ToolCallRateLimit::new(
            100,
            Duration::seconds(300),
            3,
            Duration::seconds(2),
            Duration::seconds(30),
            None,
        );
        // 2 calls in the burst window, 1 outside.
        r.check_at("s1", "t", t(0));
        r.check_at("s1", "t", t(1));
        // t=10 is outside burst window, so burst count = 1 + current = 2 < 3.
        assert!(r.check_at("s1", "t", t(10)).0);
    }
}
