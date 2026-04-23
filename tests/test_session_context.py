"""Tests for tessera.session_context.SessionContextStore.

These tests pin the multi-tenant isolation property: separate session
ids get separate Context instances, and one session's segments cannot
influence another session's min_trust.
"""

from __future__ import annotations

import threading

import pytest

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.session_context import SessionContextStore


SIGNING_KEY = b"test-session-context-32bytes!!!!"


class _FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class TestBasicAccess:
    def test_get_creates_context_lazily(self) -> None:
        store = SessionContextStore()
        ctx = store.get("session-a")
        assert isinstance(ctx, Context)
        assert ctx.segments == []

    def test_get_returns_same_context_for_same_id(self) -> None:
        store = SessionContextStore()
        c1 = store.get("session-a")
        c1.add(make_segment(
            "hello", Origin.USER, "alice", key=SIGNING_KEY,
        ))
        c2 = store.get("session-a")
        assert c1 is c2
        assert len(c2.segments) == 1

    def test_empty_session_id_rejected(self) -> None:
        store = SessionContextStore()
        with pytest.raises(ValueError):
            store.get("")
        with pytest.raises(ValueError):
            store.get(None)  # type: ignore[arg-type]

    def test_invalid_ttl_rejected(self) -> None:
        with pytest.raises(ValueError):
            SessionContextStore(ttl_seconds=0)
        with pytest.raises(ValueError):
            SessionContextStore(ttl_seconds=-1)


class TestIsolation:
    """The security property: two sessions never share Context state."""

    def test_separate_sessions_get_separate_contexts(self) -> None:
        store = SessionContextStore()
        ctx_a = store.get("user-a")
        ctx_b = store.get("user-b")
        assert ctx_a is not ctx_b

    def test_one_session_taint_does_not_affect_another(self) -> None:
        """The bug this whole module exists to prevent.

        User A scrapes a web page (UNTRUSTED segment lands in their
        Context). User B sends a USER prompt. The min_trust calculation
        for user B's tool call must be USER (100), not UNTRUSTED (0).
        """
        store = SessionContextStore()
        # User A: web-tainted segment.
        store.get("user-a").add(make_segment(
            "<script>evil</script>",
            Origin.WEB,
            "user-a",
            key=SIGNING_KEY,
            trust_level=TrustLevel.UNTRUSTED,
        ))
        # User B: clean USER prompt only.
        store.get("user-b").add(make_segment(
            "send the report to bob",
            Origin.USER,
            "user-b",
            key=SIGNING_KEY,
            trust_level=TrustLevel.USER,
        ))
        # Each session sees only its own segments.
        assert store.get("user-a").min_trust == TrustLevel.UNTRUSTED
        assert store.get("user-b").min_trust == TrustLevel.USER

    def test_reset_one_session_does_not_touch_another(self) -> None:
        store = SessionContextStore()
        store.get("a").add(make_segment(
            "first", Origin.USER, "a", key=SIGNING_KEY,
        ))
        store.get("b").add(make_segment(
            "second", Origin.USER, "b", key=SIGNING_KEY,
        ))
        store.reset("a")
        assert not store.has("a")
        assert store.has("b")
        # Re-getting "a" produces a fresh empty Context.
        new_a = store.get("a")
        assert new_a.segments == []
        # "b" still has its segment.
        assert len(store.get("b").segments) == 1


class TestTTLEviction:
    def test_session_evicted_after_ttl(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(ttl_seconds=60.0, clock=clock)
        store.get("doomed")
        assert store.has("doomed")
        clock.advance(61.0)
        # Touch a different session to trigger lazy eviction.
        store.get("trigger")
        assert not store.has("doomed")

    def test_touch_extends_lifetime(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(ttl_seconds=60.0, clock=clock)
        store.get("alive")
        clock.advance(45.0)
        store.get("alive")  # touch
        clock.advance(45.0)  # 90s total since first get, but only 45s since touch
        assert store.has("alive")

    def test_evict_expired_returns_count(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(ttl_seconds=10.0, clock=clock)
        store.get("a")
        store.get("b")
        store.get("c")
        clock.advance(11.0)
        evicted = store.evict_expired()
        assert evicted == 3
        assert len(store) == 0

    def test_evict_count_visible_in_property(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(ttl_seconds=10.0, clock=clock)
        store.get("a")
        clock.advance(11.0)
        store.evict_expired()
        assert store.evictions == 1


class TestMaxSessions:
    def test_lru_eviction_when_cap_hit(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(
            max_sessions=2, ttl_seconds=3600, clock=clock,
        )
        store.get("a")
        clock.advance(1.0)
        store.get("b")
        clock.advance(1.0)
        # Accessing "a" makes it MRU; "b" is now LRU.
        store.get("a")
        clock.advance(1.0)
        # New session evicts "b" (the LRU).
        store.get("c")
        assert store.has("a")
        assert not store.has("b")
        assert store.has("c")

    def test_disable_cap_with_zero(self) -> None:
        store = SessionContextStore(max_sessions=0)
        for i in range(50):
            store.get(f"s-{i}")
        assert len(store) == 50


class TestConcurrency:
    def test_concurrent_get_for_same_id_yields_same_context(self) -> None:
        store = SessionContextStore()
        results: list[Context] = []
        lock = threading.Lock()

        def worker() -> None:
            ctx = store.get("contended")
            with lock:
                results.append(ctx)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every thread saw the same Context object.
        assert all(c is results[0] for c in results)

    def test_concurrent_get_across_ids_isolates(self) -> None:
        store = SessionContextStore()
        errors: list[str] = []

        def writer(session_id: str) -> None:
            for i in range(20):
                ctx = store.get(session_id)
                ctx.add(make_segment(
                    f"{session_id}-{i}", Origin.USER, session_id,
                    key=SIGNING_KEY,
                ))

        threads = [
            threading.Thread(target=writer, args=(f"s-{n}",))
            for n in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each session_id ended up with exactly its own 20 segments.
        for n in range(4):
            ctx = store.get(f"s-{n}")
            assert len(ctx.segments) == 20
            for seg in ctx.segments:
                assert seg.content.startswith(f"s-{n}-")


class TestEvictionCallback:
    def test_callback_fires_on_ttl_eviction(self) -> None:
        clock = _FakeClock()
        evicted: list[str] = []
        store = SessionContextStore(
            ttl_seconds=10.0, clock=clock, on_evict=evicted.append,
        )
        store.get("a")
        store.get("b")
        clock.advance(11.0)
        store.get("c")  # triggers TTL sweep
        assert sorted(evicted) == ["a", "b"]

    def test_callback_fires_on_lru_eviction(self) -> None:
        evicted: list[str] = []
        store = SessionContextStore(
            max_sessions=2, ttl_seconds=3600, on_evict=evicted.append,
        )
        store.get("a")
        store.get("b")
        store.get("c")  # evicts "a" as LRU
        assert evicted == ["a"]

    def test_callback_fires_on_explicit_reset(self) -> None:
        evicted: list[str] = []
        store = SessionContextStore(on_evict=evicted.append)
        store.get("a")
        store.reset("a")
        assert evicted == ["a"]
        # Idempotent: second reset on missing session does NOT fire.
        store.reset("a")
        assert evicted == ["a"]

    def test_callback_fires_on_reset_all(self) -> None:
        evicted: list[str] = []
        store = SessionContextStore(on_evict=evicted.append)
        store.get("a")
        store.get("b")
        store.reset_all()
        assert sorted(evicted) == ["a", "b"]

    def test_callback_exception_does_not_break_store(self) -> None:
        def raising(sid: str) -> None:
            raise RuntimeError("boom")
        store = SessionContextStore(
            ttl_seconds=10.0, on_evict=raising,
        )
        store.get("a")
        # Eviction proceeds; callback raises but is swallowed.
        store.reset("a")
        assert not store.has("a")


class TestInspection:
    def test_session_ids_returns_lru_to_mru_order(self) -> None:
        clock = _FakeClock()
        store = SessionContextStore(clock=clock)
        store.get("first")
        clock.advance(1.0)
        store.get("second")
        clock.advance(1.0)
        store.get("third")
        # "first" is the oldest = LRU; "third" is MRU.
        assert store.session_ids() == ["first", "second", "third"]
        # Touch "first" to bump it to MRU.
        clock.advance(1.0)
        store.get("first")
        assert store.session_ids() == ["second", "third", "first"]

    def test_len_matches_active_session_count(self) -> None:
        store = SessionContextStore()
        for sid in ("a", "b", "c"):
            store.get(sid)
        assert len(store) == 3
        store.reset("b")
        assert len(store) == 2

    def test_reset_all_drops_everything(self) -> None:
        store = SessionContextStore()
        for sid in ("a", "b", "c"):
            store.get(sid)
        store.reset_all()
        assert len(store) == 0
        assert store.session_ids() == []
