# tessera-redteam-corpus

A community-maintained corpus of red-team probes for evaluating agent
security defenses. Designed to be vendored into Tessera's benchmark suite
and released as a quarterly OCI artifact.

## Purpose

This corpus tests defenses against indirect prompt injection and related
agent attack classes. It is the empirical counterpart to Tessera's
load-bearing invariants: if a defense claim is to be trusted, it must
survive these probes.

## Repository bootstrap

This scaffold lives inside the Tessera repo at `corpus/`. To spin up a
standalone corpus repo:

```
cp -R corpus/ ../tessera-redteam-corpus/
cd ../tessera-redteam-corpus/
git init
git commit --allow-empty -m "initial"
```

DCO sign-off is required for all contributions (see CONTRIBUTING.md).

## Probe schema

Each line in `probes/*.jsonl` is a JSON object conforming to
`schema/probe_v1.json`. Fields:

| Field | Type | Description |
|---|---|---|
| probe_id | string (UUID) | Stable unique identifier |
| category | string (enum) | Attack class (see schema) |
| payload | string | The attack string verbatim |
| expected_outcome | string (enum) | What a correct defense should do |
| source | string | Dataset of origin |
| license | string | SPDX identifier for the payload's license |
| submitted_at | string (date) | ISO 8601 date of contribution |

## Categories

- `prompt_injection`: attempts to override or hijack the model's instructions
- `exfil`: attempts to exfiltrate context, credentials, or user data
- `jailbreak`: attempts to bypass safety or policy constraints
- `tool_description_injection`: malicious content embedded in tool manifests or descriptions
- `url_manipulation`: payloads that redirect or weaponize URLs

## OCI release cadence

Quarterly snapshots are published as OCI artifacts (via `oras`) to
`ghcr.io/kenithphilip/tessera-redteam-corpus`. The `tools/build_oci.sh`
script produces the artifact. Each release tag follows `vYYYY.QN` (e.g.,
`v2026.Q2`).

## Deduplication

All contributions are deduplicated at ingest using minhash (128 permutations,
5-shingle, Jaccard >= 0.85). Run `tools/dedup.py` before submitting a batch.
See CONTRIBUTING.md for details.

## What this corpus does NOT contain

- Real PII (names, emails, phone numbers belonging to real people)
- Working CSAM bypass payloads
- Content that is illegal in the contributor's jurisdiction

Contributions violating these rules will be rejected and the submitter
will be blocked. See CONTRIBUTING.md for the full rejection policy.

## License

Probe entries carry per-entry SPDX license fields. The corpus tooling
(`tools/`) and schema (`schema/`) are licensed Apache-2.0.
