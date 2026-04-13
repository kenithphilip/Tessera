"""Head-to-head comparison benchmarks: Baseline vs Tessera vs CaMeL.

Measures per-request overhead of three security strategies processing the
same workload so we can compare latency costs without hand-waving.
All three strategies use deterministic stubs instead of real LLM calls,
isolating the security-layer overhead from model latency.

Run with: ``python -m benchmarks.comparison``
"""
