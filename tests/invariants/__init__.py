"""Invariant test suite.

Property-based tests via Hypothesis that pin algebraic laws and
load-bearing invariants of the v0.12 to v1.0 substrate. Failure
of any test in this directory is a security regression: the
underlying invariant is part of the project's threat model.

Run with::

    pytest tests/invariants/ -v
"""
