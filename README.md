# Tessera

**Signed provenance, delegation-aware taint tracking, and schema-enforced
dual-LLM execution for agent security meshes.**

![tests](https://img.shields.io/badge/tests-166%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-blue)
![license](https://img.shields.io/badge/license-Apache%202.0-blue)
![status](https://img.shields.io/badge/status-experimental-orange)

Tessera is a Python library and sidecar proxy that implements two primitives
recent agent security surveys identify as unimplemented in production:

1. **Signed trust labels on context segments**, with deterministic
   taint tracking at the tool-call boundary. A tool call requiring USER
   trust cannot fire if any segment in the context carries WEB trust,
   regardless of how convincingly that segment impersonates a user
   instruction.

2. **Schema-enforced dual-LLM execution.** The Worker model is
   structurally prevented from returning free-form text by a Pydantic
   validator, closing the convention-based hole in Simon Willison's
   dual-LLM pattern without requiring a custom interpreter.

Both primitives are documented in
[papers/two-primitives-for-agent-security-meshes.md](papers/two-primitives-for-agent-security-meshes.md).

---

## Why this exists

LLM agents concatenate everything they see into one trust-undifferentiated
context: user instructions, scraped web pages, tool outputs, memory entries,
retrieved documents. The model has no structural way to tell them apart.
That is the root cause of indirect prompt injection, and no amount of
system-prompting fixes it.

Existing guardrails are WAFs for LLMs: pattern-matching on strings. Tessera
treats this as an identity and data-flow problem, not a filtering problem.
Every segment of context carries a cryptographic provenance label. The
policy engine evaluates tool calls against the minimum trust level observed
in the data that could have influenced them. The dual-LLM quarantine
executor structurally isolates untrusted content from the model that
emits tool calls.

None of the enforcement happens inside the LLM. It happens in deterministic
Python outside the model. That is the only way to get guarantees against a
probabilistic system.

---

## The core invariant

```
allow(tool, ctx) iff required_trust(tool) <= min_{s in ctx.segments} s.trust_level
```

A tool call may execute only if every segment of context that could have
influenced the decision has a trust level at or above the tool's required
level. The taint-tracking primitive is the use of `min`, not `max`. A
single untrusted segment drags the whole context to the floor.

The invariant is enforced in `tessera.policy.Policy.evaluate`, is
deterministic, and is testable without invoking an LLM. See
[tests/test_policy.py](tests/test_policy.py) for the proofs.

---

## Architecture

```
   +--------+    +------------------------+    +-----------+
   | User   |--> | Tessera sidecar        |--> | LLM API   |
   +--------+    |                        |    +-----------+
                 |  - verify label sigs   |
   +--------+    |  - spotlight untrusted |
   | Web    |--> |  - taint-track context |
   +--------+    |  - gate tool calls     |
                 |  - emit security events|
   +--------+    |                        |
   | MCP    |--> +----+-------------------+
   +--------+         |
                      v
            +--------------------+    +------------------+
            | tessera.policy     |    | tessera.events   |
            | taint-tracking     |    | SIEM webhook,    |
            +--------------------+    | OTel span events |
                                      +------------------+

            +-----------------------------+
            | tessera.quarantine          |
            |                             |
            |   PLANNER      WORKER       |
            |   (tools)   (no tools)      |
            |      ^          |           |
            |      |   strict_worker      |
            |      +-- WorkerReport ------+
            +-----------------------------+
```

Every chunk of text entering the model carries a signed label:

```python
TrustLabel(
    origin="web",           # user | system | tool | memory | web
    principal="alice",      # who the content belongs to
    trust_level=0,          # 0=untrusted, 50=tool, 100=user, 200=system
    nonce="...",            # 128-bit random
    signature="..."         # HMAC-SHA256 or JWT-SVID over content + metadata
)
```

---

## What's in the box

| Module | Purpose |
|---|---|
| `tessera.labels` | Signed `TrustLabel`, HMAC-SHA256 primitives |
| `tessera.signing` | HMAC and JWT-based label signing and verification, with clock-skew leeway |
| `tessera.context` | `LabeledSegment`, `Context`, Spotlighting delimiters |
| `tessera.delegation` | Signed delegation tokens for bounded user-to-agent authority |
| `tessera.provenance` | Signed context segment envelopes and prompt provenance manifests |
| `tessera.identity` | Inbound workload identity tokens, proof-of-possession, replay checks |
| `tessera.mtls` | SPIFFE-aware transport identity extraction from ASGI TLS and trusted XFCC |
| `tessera.policy` | Taint-tracking policy engine with per-tool trust requirements |
| `tessera.policy_backends` | External deny-only policy backends, including OPA integration and audit metadata |
| `tessera.quarantine` | `QuarantinedExecutor`, `strict_worker`, safe-by-default `WorkerReport` |
| `tessera.mcp` | MCP interceptor that auto-labels tool outputs |
| `tessera.a2a` | A2A security context carriage and verification helpers |
| `tessera.spire` | Live SPIRE Workload API adapters for JWT-SVIDs and trust bundles |
| `tessera.registry` | Org-level external-tool registry, registry-wins-on-inclusion |
| `tessera.events` | Structured `SecurityEvent` with stdout, OTel, and webhook sinks |
| `tessera.evidence` | Signed evidence bundles for audit export and offline verification |
| `tessera.telemetry` | Optional OpenTelemetry spans across proxy, MCP, policy, quarantine |
| `tessera.proxy` | FastAPI reference proxy with chat and A2A JSON-RPC mediation |

Reference deployments:

- [`deployment/spire/`](deployment/spire/): SPIRE docker-compose with
  workload registration walkthrough
- [`rust/tessera-gateway/`](rust/tessera-gateway/): Rust data plane with native
  TLS transport identity, chat mediation, and A2A enforcement
- [`examples/injection_blocked.py`](examples/injection_blocked.py):
  minimal offline demo
- [`examples/quarantine_demo.py`](examples/quarantine_demo.py):
  dual-LLM demo with a stub planner and worker, no API key required
- [`examples/quarantine_openai.py`](examples/quarantine_openai.py):
  dual-LLM demo with real OpenAI API calls (gpt-4o-mini as worker,
  gpt-4o as planner), schema-enforced via `EarningsFacts`

---

## Quickstart

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Offline injection demo:

```bash
python examples/injection_blocked.py
python examples/quarantine_demo.py
```

Labeling a segment with HMAC:

```python
from tessera import make_segment, Origin, TrustLevel, Context, Policy

KEY = b"replace-with-a-real-key"

ctx = Context()
ctx.add(make_segment("email bob about the report",
                     origin=Origin.USER, principal="alice", key=KEY))
ctx.add(make_segment("<html>scraped content</html>",
                     origin=Origin.WEB, principal="alice", key=KEY))

policy = Policy()
policy.require("send_email", TrustLevel.USER)

decision = policy.evaluate(ctx, "send_email")
assert not decision.allowed
print(decision.reason)
# context contains a segment at trust_level=0, below required 100 for tool 'send_email'
```

Outbound workload identity with a SPIRE JWT-SVID:

```python
from tessera import SpireJWTSource

source = SpireJWTSource(socket_path="unix:///tmp/spire-agent-api/api.sock")
headers = source.identity_headers(audience="spiffe://example.org/ns/proxy/i/abcd")

assert "ASM-Agent-Identity" in headers
```

Dual-LLM execution with schema enforcement:

```python
from tessera import QuarantinedExecutor, strict_worker, WorkerReport

async def raw_worker(untrusted_ctx):
    # call your Worker LLM, return a dict matching WorkerReport
    ...

worker = strict_worker(WorkerReport, raw_worker)

async def planner(trusted_ctx, report: WorkerReport):
    # planner sees only trusted segments + the validated report
    ...

executor = QuarantinedExecutor(planner=planner, worker=worker)
result = await executor.run(full_context)
```

Security event emission to a SIEM:

```python
from tessera import register_sink, webhook_sink

register_sink(webhook_sink("https://siem.example.com/tessera"))
# Now every POLICY_DENY and WORKER_SCHEMA_VIOLATION is POSTed as JSON.
```

---

## Threat model

Tessera defends against **indirect prompt injection**: an attacker controls
some segment of data entering the agent's context window and tries to
cause the agent to take a privileged action the delegating user did not
authorize.

Tessera does NOT defend against:

- Direct prompt injection by the authenticated user
- Model-level attacks (backdoors, data poisoning, weight extraction)
- Compromise of the underlying tool servers or MCP implementations
- Supply-chain attacks on model weights, system prompts, or tool manifests
- Sandbox escape for agent-generated code (use Firecracker or gVisor)
- Semantic poisoning of the agent's natural-language output to the user

See Section 2 of the paper for the full threat model and explicit
out-of-scope list.

---

## Composition with existing mesh infrastructure

Tessera is designed to slot into any agent mesh, not to replace one:

- **Identity:** custom label JWTs integrate via `JWTSigner` and
  `JWKSVerifier`, while live SPIRE JWT-SVID retrieval and trust-bundle
  verification integrate via `tessera.identity` and `tessera.spire`
- **Transport identity:** the reference proxy can enforce SPIFFE caller
  identity from the ASGI TLS extension, or from `X-Forwarded-Client-Cert`
  when the immediate proxy host is explicitly trusted
- **Policy:** the `Decision` object composes with Cedar or OPA for
  attribute-based rules (evaluate taint first, attributes second)
- **Data plane:** the FastAPI reference proxy now covers chat mediation,
  signed delegation, signed prompt provenance, discovery, and A2A
  JSON-RPC ingress. It is still a reference surface meant to be ported
  into a Rust proxy like agentgateway for production
- **Observability:** OTel spans emit across `proxy.request`,
  `proxy.upstream`, `policy.evaluate`, `mcp.tool_call`, `quarantine.run`
- **Sandbox:** orthogonal, Tessera operates at the application layer

---

## Status

**Experimental.** This is a reference implementation of two primitives,
not a production security control. The invariants are testable and the
primitives compose, but the API will change, the ergonomics will change,
and the integrations with existing mesh infrastructure are not yet
battle-tested at scale.

What is stable:

- The core invariant and its test coverage
- The `TrustLabel` structure (HMAC and JWT-SVID signing modes)
- The `strict_worker` contract and the safe-by-default `WorkerReport`

What is likely to change:

- The FastAPI proxy shape (production deployments should port primitives
  into a Rust data plane)
- The MCP interceptor interface as MCP SEP-1913 lands
- The `SecurityEvent` sink API as we integrate with more SIEMs

---

## Contributing

Tessera is a draft-for-discussion reference implementation accompanying
the position paper in [`papers/`](papers/). Contributions are welcome,
particularly:

- Benchmarks against CaMeL's reported 6.6x latency cost
- Integrations with Cedar or OPA as a policy backend
- A Rust port of the proxy into agentgateway or an equivalent data plane
- MCP SEP-1913 interop once the standard lands
- Additional test coverage for edge cases in the taint-tracking invariant

Open an issue with questions, corrections, or proposals. Pull requests
should include tests that pin the invariant being added or changed.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

The accompanying paper in [`papers/`](papers/) is licensed under
CC BY 4.0.

---

## Citation

If you use Tessera or the primitives described in the paper:

```
Philip, K. (2026). Two Primitives for Agent Security Meshes:
Trust-Labeled Context and Schema-Enforced Dual-LLM Execution.
Draft for discussion. https://github.com/kenithphilip/Tessera
```

---

## Author

Kenith Philip.

Questions, corrections, and implementation feedback are welcome via
GitHub issues once the repository is published publicly.
