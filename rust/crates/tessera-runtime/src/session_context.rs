//! Per-session [`Context`] store with TTL and LRU eviction.
//!
//! Mirrors `tessera.session_context` from the Python reference. Each
//! session id gets its own [`Context`]; the store evicts inactive
//! sessions on TTL and caps total session count via LRU. An optional
//! eviction callback fires on TTL, LRU, and explicit reset, so the
//! caller can tear down adjacent per-session state in lockstep.
//!
//! Why this exists: the taint-tracking invariant runs `min_trust` over
//! every segment of the context, so any caller that shared one
//! `Context` across tenants would let user A's web-tainted segments
//! deny user B's tool calls. Per-session contexts make that
//! cross-tenant interference structurally impossible.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use tessera_core::context::Context;

/// Eviction callback. Receives the session id about to be dropped.
/// Exceptions inside the callback are caught and logged-suppressed by
/// the store, so a buggy callback cannot break eviction.
pub type EvictCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Source of monotonic time. Defaults to `Instant::now`; override in
/// tests for deterministic eviction.
pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
struct Entry {
    context: Arc<Mutex<Context>>,
    last_touched: Instant,
    /// Insertion sequence used for LRU ordering; touch increments it.
    /// Lower values are older. We sweep on insert when the cap is hit.
    lru_token: u64,
}

/// Thread-safe per-session [`Context`] store.
pub struct SessionContextStore {
    inner: Mutex<Inner>,
    ttl: Duration,
    max_sessions: usize,
    clock: Box<dyn MonotonicClock>,
    on_evict: Option<EvictCallback>,
}

struct Inner {
    entries: HashMap<String, Entry>,
    /// Monotonically increasing counter used to assign LRU tokens.
    next_token: u64,
    /// Cumulative count of TTL + LRU + reset evictions.
    evictions: u64,
}

impl SessionContextStore {
    /// Create a new store.
    ///
    /// `ttl_seconds` evicts sessions inactive that long. `max_sessions`
    /// caps the live session set; on overflow the LRU is dropped. Set
    /// `max_sessions = 0` to disable the cap.
    pub fn new(ttl_seconds: f64, max_sessions: usize) -> Self {
        Self::builder(ttl_seconds, max_sessions).build()
    }

    pub fn builder(ttl_seconds: f64, max_sessions: usize) -> Builder {
        Builder {
            ttl_seconds,
            max_sessions,
            clock: None,
            on_evict: None,
        }
    }

    /// Return the [`Context`] for `session_id`, creating it if missing.
    /// Updates the last-touched timestamp. Runs lazy eviction of any
    /// sessions that have exceeded the TTL, and enforces the LRU cap.
    pub fn get(&self, session_id: &str) -> Result<Arc<Mutex<Context>>, StoreError> {
        if session_id.is_empty() {
            return Err(StoreError::EmptySessionId);
        }
        let now = self.clock.now();
        let evicted_ids;
        let ctx;
        {
            let mut inner = self.inner.lock();
            evicted_ids = self.evict_expired_locked(&mut inner, now);
            inner.next_token += 1;
            let new_token = inner.next_token;
            if let Some(entry) = inner.entries.get_mut(session_id) {
                entry.last_touched = now;
                entry.lru_token = new_token;
                ctx = Arc::clone(&entry.context);
            } else {
                let entry = Entry {
                    context: Arc::new(Mutex::new(Context::new())),
                    last_touched: now,
                    lru_token: new_token,
                };
                ctx = Arc::clone(&entry.context);
                inner.entries.insert(session_id.to_string(), entry);
                if self.max_sessions > 0 && inner.entries.len() > self.max_sessions {
                    if let Some(victim) = self.find_lru_locked(&inner) {
                        inner.entries.remove(&victim);
                        inner.evictions += 1;
                        self.fire_evictions(std::iter::once(victim));
                    }
                }
            }
        }
        // Fire the eviction callback for TTL-expired entries OUTSIDE
        // the lock so a callback that calls back into the store cannot
        // deadlock us.
        self.fire_evictions(evicted_ids);
        Ok(ctx)
    }

    /// True if the session exists and is not expired. Does not touch.
    pub fn has(&self, session_id: &str) -> bool {
        let now = self.clock.now();
        let inner = self.inner.lock();
        inner
            .entries
            .get(session_id)
            .map(|e| now.duration_since(e.last_touched) <= self.ttl)
            .unwrap_or(false)
    }

    /// Drop one session. Idempotent. Fires the eviction callback iff
    /// the session existed.
    pub fn reset(&self, session_id: &str) {
        let existed = {
            let mut inner = self.inner.lock();
            let removed = inner.entries.remove(session_id).is_some();
            if removed {
                inner.evictions += 1;
            }
            removed
        };
        if existed {
            self.fire_evictions(std::iter::once(session_id.to_string()));
        }
    }

    /// Drop every session. Fires the callback per session.
    pub fn reset_all(&self) {
        let ids: Vec<String> = {
            let mut inner = self.inner.lock();
            let ids: Vec<String> = inner.entries.keys().cloned().collect();
            inner.entries.clear();
            inner.evictions += ids.len() as u64;
            ids
        };
        self.fire_evictions(ids);
    }

    /// Force a TTL sweep. Returns the count evicted.
    pub fn evict_expired(&self) -> usize {
        let now = self.clock.now();
        let evicted = {
            let mut inner = self.inner.lock();
            self.evict_expired_locked(&mut inner, now)
        };
        let count = evicted.len();
        self.fire_evictions(evicted);
        count
    }

    /// Snapshot of currently-active session ids in LRU-to-MRU order.
    pub fn session_ids(&self) -> Vec<String> {
        let inner = self.inner.lock();
        let mut pairs: Vec<(&String, &Entry)> = inner.entries.iter().collect();
        pairs.sort_by_key(|(_, e)| e.lru_token);
        pairs.into_iter().map(|(k, _)| k.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cumulative LRU + TTL + reset evictions since construction.
    pub fn evictions(&self) -> u64 {
        self.inner.lock().evictions
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    // -- internal -----------------------------------------------------

    fn evict_expired_locked(&self, inner: &mut Inner, now: Instant) -> Vec<String> {
        if inner.entries.is_empty() {
            return Vec::new();
        }
        let mut expired: Vec<String> = Vec::new();
        for (sid, entry) in inner.entries.iter() {
            if now.duration_since(entry.last_touched) > self.ttl {
                expired.push(sid.clone());
            }
        }
        for sid in &expired {
            inner.entries.remove(sid);
            inner.evictions += 1;
        }
        expired
    }

    fn find_lru_locked(&self, inner: &Inner) -> Option<String> {
        inner
            .entries
            .iter()
            .min_by_key(|(_, e)| e.lru_token)
            .map(|(k, _)| k.clone())
    }

    fn fire_evictions<I: IntoIterator<Item = String>>(&self, ids: I) {
        let Some(cb) = &self.on_evict else { return };
        for sid in ids {
            // Catch panics so a buggy callback never breaks the store.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(&sid)));
            // Swallow panic: the store cares only about its own state.
            drop(result);
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    EmptySessionId,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::EmptySessionId => write!(f, "session_id must be a non-empty string"),
        }
    }
}

impl std::error::Error for StoreError {}

pub struct Builder {
    ttl_seconds: f64,
    max_sessions: usize,
    clock: Option<Box<dyn MonotonicClock>>,
    on_evict: Option<EvictCallback>,
}

impl Builder {
    pub fn clock(mut self, clock: Box<dyn MonotonicClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn on_evict<F>(mut self, cb: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.on_evict = Some(Arc::new(cb));
        self
    }

    pub fn build(self) -> SessionContextStore {
        assert!(self.ttl_seconds > 0.0, "ttl_seconds must be positive");
        SessionContextStore {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                next_token: 0,
                evictions: 0,
            }),
            ttl: Duration::from_secs_f64(self.ttl_seconds),
            max_sessions: self.max_sessions,
            clock: self.clock.unwrap_or_else(|| Box::new(SystemClock)),
            on_evict: self.on_evict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        fn new() -> Self {
            Self(Mutex::new(Instant::now()))
        }
        fn advance(&self, secs: u64) {
            let mut t = self.0.lock();
            *t += Duration::from_secs(secs);
        }
    }

    impl MonotonicClock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock()
        }
    }

    fn store_with_clock(clock: Arc<FakeClock>, ttl: f64, cap: usize) -> SessionContextStore {
        struct Wrapper(Arc<FakeClock>);
        impl MonotonicClock for Wrapper {
            fn now(&self) -> Instant {
                self.0.now()
            }
        }
        SessionContextStore::builder(ttl, cap)
            .clock(Box::new(Wrapper(clock)))
            .build()
    }

    #[test]
    fn get_creates_context_lazily() {
        let s = SessionContextStore::new(60.0, 10);
        let ctx = s.get("a").unwrap();
        assert!(ctx.lock().is_empty());
    }

    #[test]
    fn empty_session_id_rejected() {
        let s = SessionContextStore::new(60.0, 10);
        assert!(matches!(s.get(""), Err(StoreError::EmptySessionId)));
    }

    #[test]
    fn separate_sessions_isolate() {
        // The headline property: one session's segments cannot leak
        // into another.
        let s = SessionContextStore::new(60.0, 10);
        let a = s.get("alice").unwrap();
        let b = s.get("bob").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        a.lock().add(tessera_core::context::LabeledSegment::new(
            "alice-only",
            tessera_core::labels::TrustLabel::with_nonce(
                tessera_core::labels::Origin::User,
                "alice",
                tessera_core::labels::TrustLevel::User,
                "n",
                None,
            ),
        ));
        assert_eq!(a.lock().len(), 1);
        assert_eq!(b.lock().len(), 0);
    }

    #[test]
    fn ttl_expiry_evicts() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 10.0, 0);
        s.get("doomed").unwrap();
        assert!(s.has("doomed"));
        clock.advance(11);
        // Touching a different session triggers the lazy sweep.
        s.get("trigger").unwrap();
        assert!(!s.has("doomed"));
    }

    #[test]
    fn touch_extends_lifetime() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 10.0, 0);
        s.get("alive").unwrap();
        clock.advance(5);
        s.get("alive").unwrap(); // touch
        clock.advance(7);
        // 12s total since first get, but only 7s since the touch.
        assert!(s.has("alive"));
    }

    #[test]
    fn evict_expired_returns_count() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 5.0, 0);
        s.get("a").unwrap();
        s.get("b").unwrap();
        s.get("c").unwrap();
        clock.advance(6);
        assert_eq!(s.evict_expired(), 3);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn lru_eviction_when_cap_hit() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 3600.0, 2);
        s.get("a").unwrap();
        clock.advance(1);
        s.get("b").unwrap();
        clock.advance(1);
        // Touch "a" so it becomes MRU.
        s.get("a").unwrap();
        clock.advance(1);
        // New session evicts "b" (now LRU).
        s.get("c").unwrap();
        assert!(s.has("a"));
        assert!(!s.has("b"));
        assert!(s.has("c"));
    }

    #[test]
    fn cap_zero_disables_lru() {
        let s = SessionContextStore::new(3600.0, 0);
        for i in 0..50 {
            s.get(&format!("s-{i}")).unwrap();
        }
        assert_eq!(s.len(), 50);
    }

    #[test]
    fn reset_drops_one_session() {
        let s = SessionContextStore::new(60.0, 10);
        s.get("a").unwrap();
        s.get("b").unwrap();
        s.reset("a");
        assert!(!s.has("a"));
        assert!(s.has("b"));
        // Idempotent: reset of missing session is a no-op.
        s.reset("a");
    }

    #[test]
    fn reset_all_drops_everything() {
        let s = SessionContextStore::new(60.0, 10);
        s.get("a").unwrap();
        s.get("b").unwrap();
        s.reset_all();
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn callback_fires_on_ttl_eviction() {
        let clock = Arc::new(FakeClock::new());
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);
        struct Wrapper(Arc<FakeClock>);
        impl MonotonicClock for Wrapper {
            fn now(&self) -> Instant { self.0.now() }
        }
        let s = SessionContextStore::builder(10.0, 0)
            .clock(Box::new(Wrapper(clock.clone())))
            .on_evict(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();
        s.get("a").unwrap();
        s.get("b").unwrap();
        clock.advance(11);
        s.get("trigger").unwrap();
        // Both expired sessions fire the callback once.
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn callback_fires_on_lru_eviction() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);
        let s = SessionContextStore::builder(3600.0, 2)
            .on_evict(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();
        s.get("a").unwrap();
        s.get("b").unwrap();
        s.get("c").unwrap(); // evicts a
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callback_fires_on_explicit_reset() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);
        let s = SessionContextStore::builder(60.0, 0)
            .on_evict(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();
        s.get("a").unwrap();
        s.reset("a");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        s.reset("a"); // idempotent, no callback
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panicking_callback_does_not_break_store() {
        let s = SessionContextStore::builder(10.0, 0)
            .on_evict(|_| panic!("boom"))
            .build();
        s.get("a").unwrap();
        s.reset("a");
        // Store still works.
        assert!(!s.has("a"));
        s.get("b").unwrap();
        assert!(s.has("b"));
    }

    #[test]
    fn session_ids_returns_lru_to_mru_order() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 3600.0, 0);
        s.get("first").unwrap();
        clock.advance(1);
        s.get("second").unwrap();
        clock.advance(1);
        s.get("third").unwrap();
        assert_eq!(s.session_ids(), vec!["first", "second", "third"]);
        clock.advance(1);
        s.get("first").unwrap(); // touch -> MRU
        assert_eq!(s.session_ids(), vec!["second", "third", "first"]);
    }

    #[test]
    fn evictions_counter_visible() {
        let clock = Arc::new(FakeClock::new());
        let s = store_with_clock(clock.clone(), 5.0, 0);
        s.get("a").unwrap();
        clock.advance(6);
        s.evict_expired();
        assert_eq!(s.evictions(), 1);
    }

    #[test]
    fn concurrent_get_for_same_id_yields_same_arc() {
        use std::thread;
        let s = Arc::new(SessionContextStore::new(60.0, 10));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || s.get("contended").unwrap()));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = Arc::clone(&results[0]);
        for r in &results[1..] {
            assert!(Arc::ptr_eq(&first, r));
        }
    }

    #[test]
    fn concurrent_writers_to_distinct_sessions_isolate() {
        use tessera_core::context::LabeledSegment;
        use tessera_core::labels::{Origin, TrustLabel, TrustLevel};
        use std::thread;

        let s = Arc::new(SessionContextStore::new(60.0, 0));
        let mut handles = Vec::new();
        for n in 0..4u32 {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                let sid = format!("s-{n}");
                for i in 0..20 {
                    let ctx = s.get(&sid).unwrap();
                    let label = TrustLabel::with_nonce(
                        Origin::User,
                        sid.clone(),
                        TrustLevel::User,
                        format!("nonce-{i}"),
                        None,
                    );
                    ctx.lock().add(LabeledSegment::new(format!("{sid}-{i}"), label));
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        for n in 0..4u32 {
            let ctx = s.get(&format!("s-{n}")).unwrap();
            assert_eq!(ctx.lock().len(), 20);
        }
    }
}
