# Tessera Red-Team Corpus v2 Release Notes

Release tag: `tessera-redteam-corpus-v2026.Q4`
Date: 2026-04-25
Schema: `probe_v1.json` (unchanged from v1)

## Summary

Corpus v2 expands the seed payload count from 200 (v1) to 1000 (v2), adding five new JSONL files that cover attack classes absent from the v1 seed. The schema is unchanged and fully backward compatible. All new entries are CC-BY-4.0 licensed synthetic probes.

## What Changed

### New Files

Five new JSONL files were added under `corpus/probes/`:

`jailbreak_personas.jsonl` (200 entries): Persona-style jailbreak payloads covering the most commonly observed roleplay-based bypass patterns: DAN, AIM, STAN, DUDE, UCAR, FREEDOM mode, JailbreakGPT, developer override, fictional AI personas, philosophical bypass arguments, authority impersonation (legal, medical, national security), and agent takeover patterns. These probes directly test the `jailbreak` classifier and the taint-tracking policy.

`encoding_obfuscation.jsonl` (150 entries): Payloads that attempt to bypass content filters using character-level obfuscation: base64 with decode instructions, hex encoding, ROT13, leetspeak, reversed strings, URL percent-encoding, HTML entities, Morse code, zero-width Unicode characters, Unicode fullwidth and homoglyph substitution (Cyrillic, Greek), binary, octal, pig latin, braille, zalgo text, Unicode right-to-left override, whitespace steganography, and injection hidden in HTML comments, CSS, YAML, SQL, markdown, JWT claims, and DNS labels.

`multi_turn_setup.jsonl` (150 entries): Turn-pair probes encoding a priming turn and an exploit turn in the `payload` field using the format `TURN_1: <priming> TURN_2: <exploit>`. Attack patterns include: trust-building then privilege escalation, persona priming then activation, tool confirmation then scope escalation, codeword establishment, operator impersonation, roleplay setup, gradual compliance escalation, and false prior-conversation claims. These probe the multi-turn attack surface described in Section 3.1 of the Tessera paper.

`tool_call_payloads.jsonl` (150 entries): Tool argument boundary attacks: SQL injection, path traversal, command injection, oversized inputs, malformed dates, SSRF (including cloud metadata endpoint probes), LDAP injection, CRLF injection, template injection, NoSQL injection, XML external entity inclusion, negative integers and floats, regular expression denial of service, prototype pollution, zip and decompression bomb references, race condition triggers, salami attacks, format string attacks, argument injection, supply chain attack vectors, OAuth token manipulation, DNS hijacking, certificate authority abuse, routing table manipulation, and tool description injection via fake manifest updates.

`exfiltration_patterns.jsonl` (150 entries): Payloads that instruct an agent to ship data to attacker-controlled endpoints. Patterns include: URL query parameter exfiltration, DNS subdomain tunneling, tracking pixel injection, webhook POST with context data, email CC to attacker address, cloud storage upload (S3, SFTP, Git remote), Referer header leakage, steganographic embedding in responses, encoded channel exfiltration (base64, JSON, compressed), federated learning gradient upload, and attacker-controlled endpoint substitution for legitimate API URLs. The `url_manipulation` category covers cases where the attacker redirects a legitimate API call rather than adding a new one.

### Updated Files

`corpus/tools/dedup.py`: Added `--report` flag. When specified, the dedup tool writes a JSON report to the given path containing per-file statistics (input count, deduped count, removed probe_ids) and global totals. This is useful for CI and release pipelines.

`corpus/probes/MANIFEST.md`: New file. Records all probe files, entry counts, categories, source tags, and ID prefix conventions.

`tests/test_redteam_corpus_seed.py`: Updated minimum total from 200 to 1000. Added the five new files to `_REQUIRED_FILES`. Added per-file minimum entry count assertions. Added global probe_id uniqueness assertion across all eight files. Verified all five valid categories appear at least 5 times each in the combined corpus.

`benchmarks/scanner_eval/corpora/tessera_community_v1.jsonl`: Extended with 150 new payloads from the v2 probe files.

`benchmarks/scanner_eval/corpora/tessera_community_v2.jsonl`: New canonical benchmark corpus path containing all 352 benchmark entries (202 from v1 plus 150 new). Label 1 for malicious, label 0 for benign.

## Schema Stability

The `probe_v1.json` schema is unchanged. No new fields were added. The `additionalProperties: false` constraint remains. The `category` enum remains:

- `prompt_injection`
- `exfil`
- `jailbreak`
- `tool_description_injection`
- `url_manipulation`

The `expected_outcome` enum remains: `refuse`, `block`, `sanitize`.

Multi-turn probes encode turn structure in the `payload` field (see MANIFEST.md) rather than introducing a `metadata` field, preserving schema stability.

## Deduplication Results

Running minhash dedup (128 permutations, 5-shingle, Jaccard >= 0.85) across all 1000 entries found no near-duplicate pairs. The five v2 files are designed to cover distinct attack surfaces and use sufficiently varied language that no cross-file near-duplicates arise.

## ID Space

Each file uses a distinct UUID v4 prefix (see MANIFEST.md for the full table). This makes file provenance identifiable from the `probe_id` alone without parsing the `source` field, and ensures no ID collisions across files.

## v2.1 Roadmap

The following categories are planned for the v2.1 release:

- `model_extraction`: Probes targeting model weight or capability fingerprinting via carefully crafted queries.
- `context_window_overflow`: Probes designed to push context past effective attention range, causing policy-relevant segments to be ignored.
- `multimodal_injection`: Payloads embedded in synthetic image alt text, PDF metadata, or audio transcripts for agents with multimodal tool access.
- Translations of v2 payloads into five languages for non-English model evaluation.
- Community contribution pipeline via GitHub Issues with automated schema validation and dedup checking.

## Verification

```bash
# Dedup check with report
python corpus/tools/dedup.py corpus/probes/*.jsonl --dry-run \
    --report=/tmp/dedup-report.json

# Schema and count validation
pytest tests/test_redteam_corpus_seed.py -v

# Full test suite
pytest tests/ -q
```
