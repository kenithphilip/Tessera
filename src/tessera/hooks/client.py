"""HTTP client for calling remote extension servers.

Remote hooks are called via HTTP POST. On any error (timeout,
network failure, non-2xx response), the client fails closed,
treating the result as a deny.
"""

from __future__ import annotations

from typing import Any

import httpx

from tessera.policy import Decision, DecisionKind


class RemoteHookClient:
    """Call a remote extension server via HTTP POST.

    Implements the PostPolicyEvaluateHook protocol so it can be
    registered directly with HookDispatcher.register_policy_hook.
    """

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self._url = url
        self._timeout = timeout

    def __call__(
        self, tool: str, principal: str, decision: Decision
    ) -> Decision | None:
        return self.post_policy_evaluate(tool, principal, decision)

    def post_policy_evaluate(
        self, tool: str, principal: str, decision: Decision
    ) -> Decision | None:
        """POST to the remote hook and return the modified decision, or None.

        On timeout or error, fails closed by returning a DENY decision.
        """
        payload = {
            "tool": tool,
            "principal": principal,
            "decision_kind": str(decision.kind),
            "reason": decision.reason,
            "required_trust": int(decision.required_trust),
            "observed_trust": int(decision.observed_trust),
        }
        try:
            resp = httpx.post(
                self._url,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            body = resp.json()
        except Exception:
            return Decision(
                kind=DecisionKind.DENY,
                reason="remote hook unavailable, failing closed",
                tool=tool,
                required_trust=decision.required_trust,
                observed_trust=decision.observed_trust,
            )

        new_kind = body.get("decision_kind")
        if new_kind is None:
            return None

        # Deny-only: only accept downgrades to DENY.
        if new_kind == DecisionKind.DENY and decision.kind != DecisionKind.DENY:
            return Decision(
                kind=DecisionKind.DENY,
                reason=body.get("reason", "denied by remote hook"),
                tool=tool,
                required_trust=decision.required_trust,
                observed_trust=decision.observed_trust,
            )
        return None
