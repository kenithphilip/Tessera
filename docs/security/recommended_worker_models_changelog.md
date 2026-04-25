# Recommended worker models: changelog

This document tracks updates to `recommended_worker_models.md` as new hardened checkpoints are published and techniques evolve.

## Latest update

2026-04-25: Initial document. ASIDE and SecAlign techniques documented with current publication citations and public checkpoints. Meta-SecAlign documented with provisional citation pending preprint publication.

## 2026-Q2 milestones

- Meta-SecAlign preprint publication (arXiv ID assignment expected)
- First production-ready Meta-SecAlign checkpoint expected on HuggingFace
- SecAlign checkpoint refresh cycle (new adversarial corpus, improved APR estimates)

## 2026-Q3 roadmap

- Extended APR evaluation against emerging attack patterns
- Integration examples with agentmesh control plane
- Comparative latency benchmarks (ASIDE vs SecAlign vs Meta-SecAlign on Tessera workloads)

## Model checkpoint URLs (for reference)

Updated quarterly. Check HuggingFace primary repos:

- **ASIDE**: `meta-llama/Llama-2-*-aside-*` (exact variants by size; see HuggingFace search)
- **SecAlign**: `mistralai/mistral-*-secalign`, `Qwen/qwen-*-secalign`
- **Meta-SecAlign**: (TBD, awaiting preprint and public checkpoint release)

## Prior versions

None (initial release).
