"""Benchmarks for ``tessera.quarantine``.

Section 4.5 of the paper claims "Pydantic validation on a structured dict
is microseconds" and that latency is dominated by the LLM calls rather
than validation. These benchmarks produce the numbers that back that
claim.

We measure three things:

1. Direct ``schema.model_validate(dict)`` on a valid payload. This is the
   hot path when the worker returns a Python dict.
2. ``schema.model_validate_json(str)`` on a valid payload. This is the
   hot path when the worker returns a JSON string.
3. The validator's rejection path on a malformed payload. Pydantic's
   error construction dominates here, but it is the cost a compromised
   worker imposes, so it belongs in the report.
"""

from __future__ import annotations

from pydantic import ValidationError

from tessera.quarantine import WorkerReport

_VALID_DICT = {
    "entities": ["Alice", "Bob", "Carol"],
    "urls": ["https://example.com/a", "https://example.com/b"],
    "numbers": {"count": 3.0, "total": 42.5},
    "flags": {"has_pii": False, "has_secrets": False},
}

_VALID_JSON = (
    '{"entities": ["Alice", "Bob", "Carol"],'
    '"urls": ["https://example.com/a", "https://example.com/b"],'
    '"numbers": {"count": 3.0, "total": 42.5},'
    '"flags": {"has_pii": false, "has_secrets": false}}'
)

# Types are all wrong: urls is an int, numbers is a list, entities is a dict.
_INVALID_DICT = {
    "entities": {"not": "a list"},
    "urls": 42,
    "numbers": [1, 2, 3],
    "flags": "nope",
}


def _validate_dict_valid() -> None:
    WorkerReport.model_validate(_VALID_DICT)


def _validate_json_valid() -> None:
    WorkerReport.model_validate_json(_VALID_JSON)


def _validate_dict_invalid() -> None:
    try:
        WorkerReport.model_validate(_INVALID_DICT)
    except ValidationError:
        pass


BENCHMARKS = [
    ("WorkerReport.model_validate, valid dict", _validate_dict_valid),
    ("WorkerReport.model_validate_json, valid JSON", _validate_json_valid),
    ("WorkerReport.model_validate, invalid dict", _validate_dict_invalid),
]
