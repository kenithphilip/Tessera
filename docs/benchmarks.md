# Tessera benchmark results

Microbenchmarks for the Tessera primitives. All measurements are per-call wall-clock time under `timeit`, warmed up, with the minimum of seven rounds (unless `--rounds` says otherwise) used as the headline. See `benchmarks/README.md` for methodology.

## Environment

- **Python:** 3.12.11
- **Platform:** macOS-26.2-arm64-arm-64bit
- **Processor:** arm
- **Run at:** 2026-04-09 20:29:21 UTC


### Labels (HMAC sign/verify)

| Operation | Median | Min | Stdev | Ops/sec |
| --- | ---: | ---: | ---: | ---: |
| sign_label, 112 B content | 3.25 us | 2.91 us | 0.13 us | 343,111 |
| sign_label, 10 KB content | 6.97 us | 6.08 us | 0.40 us | 164,605 |
| verify_label, 112 B content | 2.15 us | 1.90 us | 0.11 us | 526,367 |
| verify_label, 10 KB content | 5.71 us | 5.17 us | 0.25 us | 193,378 |

### Context (segments, min_trust, render)

| Operation | Median | Min | Stdev | Ops/sec |
| --- | ---: | ---: | ---: | ---: |
| make_segment, USER origin | 5.39 us | 4.71 us | 0.28 us | 212,138 |
| make_segment, WEB origin (780 B) | 5.74 us | 5.09 us | 0.29 us | 196,574 |
| Context.min_trust, 3 segments | 0.27 us | 0.24 us | 0.01 us | 4,197,729 |
| Context.min_trust, 10 segments | 0.49 us | 0.43 us | 0.03 us | 2,342,573 |
| Context.min_trust, 50 segments | 1.66 us | 1.46 us | 0.09 us | 686,624 |
| Context.render, 3 segments | 0.45 us | 0.39 us | 0.02 us | 2,568,755 |
| Context.render, 10 segments | 0.83 us | 0.75 us | 0.04 us | 1,329,864 |

### Policy (allow and deny)

| Operation | Median | Min | Stdev | Ops/sec |
| --- | ---: | ---: | ---: | ---: |
| Policy.evaluate, allow (trusted context) | 4.12 us | 3.66 us | 0.19 us | 273,350 |
| Policy.evaluate, allow at TOOL tier (tainted ctx) | 6.20 us | 5.37 us | 0.35 us | 186,058 |
| Policy.evaluate, deny (tainted context, emits event) | 5.78 us | 5.44 us | 0.38 us | 183,991 |

### Quarantine (Pydantic validation)

| Operation | Median | Min | Stdev | Ops/sec |
| --- | ---: | ---: | ---: | ---: |
| WorkerReport.model_validate, valid dict | 1.04 us | 0.92 us | 0.05 us | 1,088,560 |
| WorkerReport.model_validate_json, valid JSON | 1.41 us | 1.22 us | 0.08 us | 821,825 |
| WorkerReport.model_validate, invalid dict | 1.61 us | 1.46 us | 0.06 us | 684,637 |

### End-to-end request path

| Operation | Median | Min | Stdev | Ops/sec |
| --- | ---: | ---: | ---: | ---: |
| E2E: sign 3, verify 3, policy allow | 31.84 us | 28.35 us | 1.42 us | 35,271 |
| E2E: sign 3, verify 3, policy deny + event | 32.38 us | 28.12 us | 1.72 us | 35,564 |

### Summary (median per-call latency)

| Section | Operation | Median |
| --- | --- | ---: |
| Labels (HMAC sign/verify) | sign_label, 112 B content | 3.25 us |
| Labels (HMAC sign/verify) | sign_label, 10 KB content | 6.97 us |
| Labels (HMAC sign/verify) | verify_label, 112 B content | 2.15 us |
| Labels (HMAC sign/verify) | verify_label, 10 KB content | 5.71 us |
| Context (segments, min_trust, render) | make_segment, USER origin | 5.39 us |
| Context (segments, min_trust, render) | make_segment, WEB origin (780 B) | 5.74 us |
| Context (segments, min_trust, render) | Context.min_trust, 3 segments | 0.27 us |
| Context (segments, min_trust, render) | Context.min_trust, 10 segments | 0.49 us |
| Context (segments, min_trust, render) | Context.min_trust, 50 segments | 1.66 us |
| Context (segments, min_trust, render) | Context.render, 3 segments | 0.45 us |
| Context (segments, min_trust, render) | Context.render, 10 segments | 0.83 us |
| Policy (allow and deny) | Policy.evaluate, allow (trusted context) | 4.12 us |
| Policy (allow and deny) | Policy.evaluate, allow at TOOL tier (tainted ctx) | 6.20 us |
| Policy (allow and deny) | Policy.evaluate, deny (tainted context, emits event) | 5.78 us |
| Quarantine (Pydantic validation) | WorkerReport.model_validate, valid dict | 1.04 us |
| Quarantine (Pydantic validation) | WorkerReport.model_validate_json, valid JSON | 1.41 us |
| Quarantine (Pydantic validation) | WorkerReport.model_validate, invalid dict | 1.61 us |
| End-to-end request path | E2E: sign 3, verify 3, policy allow | 31.84 us |
| End-to-end request path | E2E: sign 3, verify 3, policy deny + event | 32.38 us |

## Framing against an LLM round-trip

CaMeL (Debenedetti et al, 2025) reports a 6.6x latency cost for its custom interpreter approach. Tessera's schema-enforced dual-LLM pattern does no dataflow tracking: validation is a Pydantic call on a structured dict, and policy evaluation is a min over the context segments.

The end-to-end row above is the full Tessera per-request overhead: sign three segments, verify three segments, evaluate one tool call. As a fraction of a typical LLM round-trip:

- Allow path (31.84 us per request) vs 200 ms LLM call: 0.0159% overhead.
- Allow path (31.84 us per request) vs 1000 ms LLM call: 0.0032% overhead.
- Deny path (32.38 us per request, emits SecurityEvent) vs 200 ms LLM call: 0.0162% overhead.

We do not claim this is a head-to-head comparison with CaMeL: we did not run CaMeL, and the two systems are doing different work. The point of this report is to pin Tessera's absolute overhead so readers can compute the ratio against whatever LLM latency they care about.
