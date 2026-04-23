"""CEL deny-rule engine (`CelRule`, `CelPolicyEngine`).

Parity with the Python `tessera.cel_engine` module: rules are
deny-only refinements that fire after the taint floor passes. Pass
the engine to ``Policy.set_cel_engine`` to wire it into the policy
evaluator.

Example::

    from tessera_rs.cel import CelRule, CelPolicyEngine
    from tessera_rs.policy import Policy

    engine = CelPolicyEngine([
        CelRule(
            name="block-prod-deletes",
            expression='tool == "delete_database" && min_trust < 200',
            action="deny",
            message="prod deletes require system trust",
        ),
    ])
    policy = Policy()
    policy.set_cel_engine(engine)
"""

from __future__ import annotations

from tessera_rs._native import CelPolicyEngine, CelRule

__all__ = ["CelPolicyEngine", "CelRule"]
