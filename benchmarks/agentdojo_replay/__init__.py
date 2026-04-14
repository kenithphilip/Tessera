"""AgentDojo replay evaluator: measures Tessera APR and utility without LLM calls.

Uses AgentDojo's GroundTruthPipeline to replay deterministic tool call
sequences, then intercepts them with Tessera's labeler + guard to measure
what gets blocked.
"""

from __future__ import annotations

from benchmarks.agentdojo_replay.evaluator import ReplayEvaluator, ReplayReport

__all__ = ["ReplayEvaluator", "ReplayReport"]
