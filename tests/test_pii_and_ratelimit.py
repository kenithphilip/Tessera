"""Tests for PII detection and token budget rate limiting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tessera.scanners.pii import PIIEntity, PIIScanner
from tessera.ratelimit import TokenBudget


# -- PII scanner (builtin patterns, no Presidio) ------------------------------


def test_detect_email() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("Contact alice@example.com for details")
    assert len(entities) == 1
    assert entities[0].entity_type == "EMAIL"
    assert entities[0].text == "alice@example.com"


def test_detect_phone() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("Call me at 555-123-4567")
    assert any(e.entity_type == "PHONE" for e in entities)


def test_detect_ssn() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("SSN: 123-45-6789")
    assert any(e.entity_type == "SSN" for e in entities)
    assert any(e.text == "123-45-6789" for e in entities)


def test_detect_credit_card() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("Card: 4111 1111 1111 1111")
    assert any(e.entity_type == "CREDIT_CARD" for e in entities)


def test_detect_aws_key() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("key: AKIAIOSFODNN7EXAMPLE")
    assert any(e.entity_type == "AWS_KEY" for e in entities)


def test_detect_github_token() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any(e.entity_type == "GITHUB_TOKEN" for e in entities)


def test_no_pii_in_clean_text() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("The quarterly report shows 15% growth")
    assert len(entities) == 0


def test_multiple_entities() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("Email alice@example.com or call 555-123-4567")
    assert len(entities) >= 2


def test_redact_replaces_entities() -> None:
    scanner = PIIScanner()
    result = scanner.redact("Email alice@example.com for info")
    assert "<EMAIL>" in result
    assert "alice@example.com" not in result


def test_redact_preserves_non_pii() -> None:
    scanner = PIIScanner()
    result = scanner.redact("No PII here, just normal text")
    assert result == "No PII here, just normal text"


def test_redact_multiple_entities() -> None:
    scanner = PIIScanner()
    result = scanner.redact("SSN: 123-45-6789, email: bob@test.org")
    assert "<SSN>" in result
    assert "<EMAIL>" in result
    assert "123-45-6789" not in result
    assert "bob@test.org" not in result


def test_filter_by_entity_type() -> None:
    scanner = PIIScanner(entities=["EMAIL"])
    text = "Email alice@example.com, SSN 123-45-6789"
    entities = scanner.scan(text)
    assert all(e.entity_type == "EMAIL" for e in entities)


def test_score_threshold_filters_low_confidence() -> None:
    scanner = PIIScanner(score_threshold=0.9)
    # IP addresses have score 0.6, should be filtered
    entities = scanner.scan("Server at 192.168.1.1")
    assert not any(e.entity_type == "IP_ADDRESS" for e in entities)


def test_entities_sorted_by_position() -> None:
    scanner = PIIScanner()
    entities = scanner.scan("Call 555-123-4567 or email alice@example.com")
    if len(entities) >= 2:
        assert entities[0].start < entities[1].start


# -- Token budget rate limiter ------------------------------------------------


def test_consume_within_budget() -> None:
    budget = TokenBudget(max_tokens=10000)
    assert budget.consume("alice", 5000) is True
    assert budget.remaining("alice") == 5000


def test_consume_exceeds_budget() -> None:
    budget = TokenBudget(max_tokens=10000)
    budget.consume("alice", 8000)
    assert budget.consume("alice", 5000) is False
    assert budget.remaining("alice") == 2000


def test_separate_principals() -> None:
    budget = TokenBudget(max_tokens=10000)
    budget.consume("alice", 9000)
    assert budget.consume("bob", 9000) is True
    assert budget.remaining("alice") == 1000
    assert budget.remaining("bob") == 1000


def test_usage_expires_after_window() -> None:
    budget = TokenBudget(max_tokens=10000, window=timedelta(hours=1))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    budget.consume("alice", 9000, at=now)
    assert budget.remaining("alice", at=now) == 1000

    # 2 hours later, usage has expired
    later = now + timedelta(hours=2)
    assert budget.remaining("alice", at=later) == 10000
    assert budget.consume("alice", 9000, at=later) is True


def test_partial_expiry() -> None:
    budget = TokenBudget(max_tokens=10000, window=timedelta(minutes=10))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    budget.consume("alice", 3000, at=now)
    budget.consume("alice", 3000, at=now + timedelta(minutes=5))

    # 12 minutes later, first entry expired but second still active
    later = now + timedelta(minutes=12)
    assert budget.remaining("alice", at=later) == 7000


def test_status_reports_full_state() -> None:
    budget = TokenBudget(max_tokens=10000)
    budget.consume("alice", 7000)
    status = budget.status("alice")
    assert status.principal == "alice"
    assert status.used == 7000
    assert status.remaining == 3000
    assert status.limit == 10000
    assert status.exceeded is False


def test_status_exceeded() -> None:
    budget = TokenBudget(max_tokens=1000)
    budget.consume("alice", 1000)
    status = budget.status("alice")
    assert status.exceeded is True
    assert status.remaining == 0


def test_reset_principal() -> None:
    budget = TokenBudget(max_tokens=10000)
    budget.consume("alice", 9000)
    budget.reset("alice")
    assert budget.remaining("alice") == 10000


def test_reset_all() -> None:
    budget = TokenBudget(max_tokens=10000)
    budget.consume("alice", 5000)
    budget.consume("bob", 5000)
    budget.reset()
    assert budget.remaining("alice") == 10000
    assert budget.remaining("bob") == 10000


def test_exact_budget_consumption() -> None:
    budget = TokenBudget(max_tokens=1000)
    assert budget.consume("alice", 1000) is True
    assert budget.consume("alice", 1) is False


def test_zero_token_consumption() -> None:
    budget = TokenBudget(max_tokens=1000)
    assert budget.consume("alice", 0) is True
    assert budget.remaining("alice") == 1000
