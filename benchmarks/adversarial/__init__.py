"""Adversarial testing harness for Tessera.

Runs structured injection attack patterns against a Tessera-protected
pipeline and reports attack success rate (ASV), matching rate (MR),
and baseline task accuracy (PNA-T).

Source attribution: attack strategies from Open-Prompt-Injection
(attackers/), YAML dataset format from Compliant-LLM (data.yaml),
metric definitions from Open-Prompt-Injection (evaluator/Evaluator.py).
"""
