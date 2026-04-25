# Red-Team Probe Corpus Manifest

Version: v2 (2026.Q4)
Schema: `corpus/schema/probe_v1.json`
License: CC-BY-4.0 (all seed entries)

## Files

| File | Entries | Categories | Source Tag | Notes |
|---|---|---|---|---|
| `lakera_gandalf.jsonl` | 80 | `prompt_injection`, `jailbreak` | `lakera_gandalf_patterns` | v1 seed; Lakera Gandalf challenge patterns |
| `tensor_trust.jsonl` | 60 | `prompt_injection`, `jailbreak` | `tensor_trust_v1` | v1 seed; Tensor Trust dataset patterns |
| `agentdojo_seed.jsonl` | 60 | `prompt_injection`, `tool_description_injection` | `agentdojo_*_suite` | v1 seed; AgentDojo task-level attack patterns |
| `jailbreak_personas.jsonl` | 200 | `jailbreak`, `prompt_injection` | `jailbreak_personas_v2` | v2; persona-style jailbreaks (DAN, AIM, STAN, DUDE, UCAR, FREEDOM mode, roleplay, authority impersonation) |
| `encoding_obfuscation.jsonl` | 150 | `prompt_injection`, `jailbreak`, `exfil` | `encoding_obfuscation_v2` | v2; base64, hex, ROT13, leetspeak, Unicode homoglyphs, zero-width chars, steganography |
| `multi_turn_setup.jsonl` | 150 | `prompt_injection`, `jailbreak`, `exfil` | `multi_turn_setup_v2` | v2; turn-1 priming and turn-2 exploit pairs; turns encoded in payload as `TURN_1: ... TURN_2: ...` |
| `tool_call_payloads.jsonl` | 150 | `prompt_injection`, `tool_description_injection` | `tool_call_payloads_v2` | v2; tool argument boundary attacks: path traversal, SSRF, injection, oversized inputs, supply chain |
| `exfiltration_patterns.jsonl` | 150 | `exfil`, `url_manipulation` | `exfiltration_patterns_v2` | v2; data exfiltration via URL params, DNS, image beacons, webhooks, email, cloud storage, encoded channels |

## Totals

| Version | Files | Entries |
|---|---|---|
| v1 | 3 | 200 |
| v2 | 8 | 1000 |

## Category Coverage

| Category | Count (v2 total) |
|---|---|
| `prompt_injection` | ~390 |
| `jailbreak` | ~360 |
| `exfil` | ~175 |
| `tool_description_injection` | ~85 |
| `url_manipulation` | ~50 |

Exact counts can be computed from the JSONL files or queried with the dedup tool report flag.

## ID Prefix Conventions

Each file uses a distinct UUID v4 prefix for its seed entries, making file provenance identifiable from the probe_id alone.

| File | ID Prefix | Hex block 1 |
|---|---|---|
| `lakera_gandalf.jsonl` | `EXAMPLE_1a2b3c4d-0001-4000-8000-` | `1a2b3c4d` |
| `tensor_trust.jsonl` | `EXAMPLE_2b3c4d5e-0002-4000-8000-` | `2b3c4d5e` |
| `agentdojo_seed.jsonl` | `EXAMPLE_3c4d5e6f-0003-4000-8000-` | `3c4d5e6f` |
| `jailbreak_personas.jsonl` | `EXAMPLE_4d5e6f7a-0004-4000-8000-` | `4d5e6f7a` |
| `encoding_obfuscation.jsonl` | `EXAMPLE_5e6f7a8b-0005-4000-8000-` | `5e6f7a8b` |
| `multi_turn_setup.jsonl` | `EXAMPLE_6f7a8b9c-0006-4000-8000-` | `6f7a8b9c` |
| `tool_call_payloads.jsonl` | `EXAMPLE_7a8b9c0d-0007-4000-8000-` | `7a8b9c0d` |
| `exfiltration_patterns.jsonl` | `EXAMPLE_8b9c0d1e-0008-4000-8000-` | `8b9c0d1e` |

## Multi-Turn Payload Encoding

The `multi_turn_setup.jsonl` entries encode both conversation turns in the `payload` field because the `probe_v1.json` schema has `additionalProperties: false` and no `metadata` field. The format is:

```
TURN_1: <priming message> TURN_2: <exploit message>
```

Consumers evaluating multi-turn probes should split on `TURN_2:` to extract both turns.

## Deduplication

Near-duplicate detection uses 128-permutation minhash with 5-character shingles at Jaccard >= 0.85. Run:

```bash
python corpus/tools/dedup.py corpus/probes/*.jsonl --dry-run --report=/tmp/dedup-report.json
```

The `--report` flag writes a JSON file with per-file input counts, deduped counts, and removed probe_ids.

## Adding New Entries

Community contributions must follow the `probe_v1.json` schema. Use a proper UUID v4 (without the `EXAMPLE_` prefix) for community entries. See `corpus/README.md` for the full contribution workflow.
