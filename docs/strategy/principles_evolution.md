# Principles evolution: v1 to v2

## Overview

The Tessera action critic evaluates proposed tool calls against a set
of security principles before any backend (LLM or otherwise) is
consulted. Wave 1C-iii shipped six principles (P1-P6) in
`principles/v1.yaml`. Wave 3G expands that set to 20 principles
in `principles/v2.yaml` and introduces a GCG-resistance test suite
that publishes per-principle pass rates as part of the scorecard.

## v1 to v2 changes

### Preserved principles (P01-P06)

The six original principles are carried forward unchanged. Their
ids, ASI codes, and ATLAS codes are identical to v1; only the
document schema version is bumped. Stability of these identifiers
matters because they appear in audit log entries and downstream SIEM
queries. Any rename would break existing correlation rules.

### New principles (P07-P20)

Fourteen principles address gaps identified in the Phase 3 threat
model review:

| ID  | Principle id                  | Primary concern                              |
|-----|-------------------------------|----------------------------------------------|
| P07 | tool_audit_trail_integrity    | Incomplete audit records hide forensic state |
| P08 | input_format_consistency      | Character-class mismatches signal injection  |
| P09 | cross_tool_dependency_check   | Undeclared data flows hide taint propagation |
| P10 | ratelimit_respect             | Runaway loops drain quotas before detection  |
| P11 | secrecy_dont_export           | PRIVATE values must not cross trust boundary |
| P12 | capability_minimization       | Excess capability widens blast radius        |
| P13 | confused_deputy_check         | Cross-principal impersonation at call time   |
| P14 | deterministic_under_replay    | Non-determinism enables approval probing     |
| P15 | readers_audience_match        | Recipient not in reader set equals data leak |
| P16 | unsafe_template_render        | UNTRUSTED segments must not reach HTML/shell |
| P17 | destructive_requires_approval | Human gate on all DESTRUCTIVE-impact calls   |
| P18 | mcp_tier_floor                | COMMUNITY-tier MCP servers need approval     |
| P19 | critic_self_consistency       | Jitter enables adversarial probing           |
| P20 | emergency_brake               | High denial rate triggers DESTRUCTIVE stop   |

P11 (secrecy_dont_export) and P05 (no_exfiltration) are complementary:
P05 checks that the destination audience is a superset of the reader
set; P11 checks that the secrecy level permits the cross-boundary
transfer. P15 (readers_audience_match) adds the positive-direction
check: the recipient must appear in the reader set, not just that the
reader set is non-empty.

## GCG-resistance methodology

Multi-objective Greedy Coordinate Gradient (GCG; arXiv:2510.17276)
finds adversarial suffixes that simultaneously optimize for multiple
loss objectives. In the context of the action critic the attack
objective is to produce an ActionReview that the critic classifies
as ALLOW despite the presence of adversarial signals.

The stub GCG in `tests/adversarial/test_principles_gcg_resistance.py`
implements a deterministic token-substitution hill-climb:

1. A vocabulary of 256 deterministic hex tokens is pre-computed from
   SHA-256 seeds.
2. For each iteration, a candidate adversarial string is assembled by
   selecting two tokens whose indices are derived from the
   (principle_id, iteration) seed. This mirrors the greedy selection
   step in real GCG without requiring a GPU or a model.
3. The candidate is wrapped in an UNTRUSTED-labeled ArgShape inside a
   DESTRUCTIVE ActionReview. The stub critic applies the structural
   rules the deterministic pre-check would enforce.

The stub GCG is not a substitute for a full GPU-bound GCG run against
a live critic model. Its role is to:

- Pin the test harness shape so v0.14 ships the boundary in CI.
- Ensure the structural rules (DENY on UNTRUSTED + integrity principles,
  REQUIRE_APPROVAL on DESTRUCTIVE impact) are always exercised.
- Produce a JSON report the scorecard pipeline can consume.

The full GPU-bound GCG run (with a real Llama-4-Scout or Qwen3-7B
critic) runs out-of-band and its results are published separately.

## Scorecard integration

After each test run the suite writes
`scanners/REPORT_principles_gcg_resistance.json` with:

- Per-principle counts of DENY, REQUIRE_APPROVAL, and ALLOW outcomes.
- Per-principle pass rate (DENY + REQUIRE_APPROVAL / total iterations).
- Summary: total principles, passing count, overall pass rate.

The scorecard pipeline reads this file and publishes the pass rates
alongside the other security metrics. A principle with a pass rate
below 90% is a regression that blocks the release gate.

## Version selection

Set `TESSERA_PRINCIPLES_VERSION=2` in the environment to activate the
20-principle set. The default remains `1` for backward compatibility.
The `load_principles()` function in `tessera.action_critic.principles`
handles version resolution; `deterministic_pre_check` is unchanged.
