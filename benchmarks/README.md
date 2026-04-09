# Tessera benchmarks

Microbenchmark suite for the core Tessera primitives. Exists to back the
latency claim in Section 4.5 of the position paper with actual numbers, so
readers do not have to take "Pydantic validation is microseconds" on
faith.

## What is measured

Five sections, each wrapping a small set of `timeit`-based measurements:

- **Labels:** `sign_label` and `verify_label` on short (112 B) and long
  (10 KB) content. Bounds the per-segment HMAC cost.
- **Context:** `make_segment` for USER and WEB origins, `Context.min_trust`
  at 3, 10, and 50 segments, `Context.render` with spotlighting.
- **Policy:** `Policy.evaluate` on allow, tool-tier allow, and deny. The
  deny path includes a `SecurityEvent` emission so it reflects the real
  incident-response hot loop.
- **Quarantine:** `WorkerReport.model_validate` on valid dict, valid JSON,
  and invalid dict. Directly measures the claim in paper Section 4.5.
- **End-to-end:** sign three segments, verify three segments, evaluate one
  tool call. This is the per-request overhead a proxy adds in the common
  case.

## Methodology

- Pure stdlib: `timeit` for timing, `statistics` for aggregation. No new
  dependencies. Anyone who can run the test suite can run this.
- Each benchmark is warmed up for 200 iterations, then `timeit.autorange`
  picks an iteration count such that each timing round is at least 0.2 s.
  This keeps sub-microsecond operations out of the clock-resolution noise
  floor.
- Seven rounds per benchmark by default (configurable via `--rounds`).
  Reported numbers: median, min, population stdev, and ops/sec derived
  from the fastest round.
- Setup is hoisted out of the timed callable wherever possible. We care
  about the marginal cost of the primitive, not the cost of building its
  inputs.
- Sinks are replaced with a no-op during policy benchmarks so stdout
  flushing does not dominate the deny path.

## Running

From the repo root, with the dev environment active:

```bash
pip install -e '.[dev]'
python -m benchmarks                        # print to stdout
python -m benchmarks -o docs/benchmarks.md  # also write to file
python -m benchmarks --rounds 15            # slower, more stable
```

The output is a self-contained markdown report. Paste it into a PR, a
doc, or an issue without post-processing.

## Interpreting the results

The headline number is the end-to-end row. That is the full per-request
overhead a Tessera proxy adds: three segment signings, three
verifications, one policy evaluation. To frame it against a real LLM
round-trip, divide by your expected latency.

If a single LLM call takes 500 ms and Tessera's end-to-end overhead is
50 us, that is 0.01% overhead. Compare with CaMeL's reported 6.6x
(660%) overhead for its interpreter-based dual-LLM pattern. This is not
a head-to-head comparison: we did not run CaMeL, and the two systems do
different work. The point is to pin Tessera's absolute overhead so
readers can compute the ratio against whatever latency budget they care
about.

## What this is NOT

- **Not a CaMeL comparison.** CaMeL requires a custom interpreter and a
  specific LLM toolchain we have not stood up. The paper Section 4.5 is
  the right place to read about that gap. This report measures Tessera
  in isolation.
- **Not a macrobenchmark.** No network, no LLM calls, no FastAPI server.
  Proxy overhead is its own story and belongs in a separate load test.
- **Not a guarantee of your production numbers.** Cryptography is CPU
  bound, Pydantic is roughly constant-time per schema, and policy
  evaluation is linear in segment count. On your hardware with your
  segment sizes, run this yourself.

## Reproducing results in the paper

Section 4.5 of `papers/two-primitives-for-agent-security-meshes.md`
references this suite. When results change meaningfully, update the
paper to match and commit both in the same PR. Appendix A of the paper
is the authoritative index of test-pinned invariants; benchmark results
belong in the paper body, not Appendix A.
