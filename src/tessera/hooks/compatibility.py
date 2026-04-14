"""Decision-event compatibility matrix for hook validation.

Validates that a decision type is meaningful for the hook event
it is attached to. Catches authoring errors at configuration time,
not runtime.

Source attribution: DecisionEventMatrix concept from Cupcake
(decision_event_matrix.rs).
"""

from __future__ import annotations

from enum import StrEnum

from tessera.policy import DecisionKind


class HookEvent(StrEnum):
    """Hook event types that can trigger policy decisions."""

    POST_POLICY_EVALUATE = "post_policy_evaluate"
    POST_TOOL_CALL_GATE = "post_tool_call_gate"
    POST_DELEGATION_VERIFY = "post_delegation_verify"


# Which decision kinds are valid for which hook events.
# If a decision kind is not in the set for an event, it is
# an authoring error.
_COMPATIBILITY: dict[HookEvent, frozenset[DecisionKind]] = {
    HookEvent.POST_POLICY_EVALUATE: frozenset({
        DecisionKind.ALLOW,
        DecisionKind.DENY,
        DecisionKind.REQUIRE_APPROVAL,
        DecisionKind.MODIFY,
        DecisionKind.ADD_CONTEXT,
        DecisionKind.CONFIRM,
    }),
    HookEvent.POST_TOOL_CALL_GATE: frozenset({
        DecisionKind.ALLOW,
        DecisionKind.DENY,
        DecisionKind.MODIFY,
        # ADD_CONTEXT not valid here: the tool is about to execute,
        # adding context to the LLM prompt is too late.
        # CONFIRM not valid here: the decision was already made.
    }),
    HookEvent.POST_DELEGATION_VERIFY: frozenset({
        DecisionKind.ALLOW,
        DecisionKind.DENY,
        # Only allow/deny is meaningful for delegation verification.
        # MODIFY, ADD_CONTEXT, CONFIRM, REQUIRE_APPROVAL do not apply.
    }),
}


class IncompatibleDecisionError(ValueError):
    """Raised when a decision kind is not valid for the hook event."""

    def __init__(self, event: HookEvent, decision: DecisionKind) -> None:
        valid = sorted(_COMPATIBILITY.get(event, frozenset()))
        super().__init__(
            f"Decision {decision!r} is not valid for hook event {event!r}. "
            f"Valid decisions: {valid}"
        )
        self.event = event
        self.decision = decision


def validate_decision(event: HookEvent, decision: DecisionKind) -> None:
    """Validate that a decision kind is compatible with a hook event.

    Args:
        event: The hook event type.
        decision: The decision kind to validate.

    Raises:
        IncompatibleDecisionError: If the decision is not valid for the event.
    """
    valid = _COMPATIBILITY.get(event, frozenset())
    if decision not in valid:
        raise IncompatibleDecisionError(event, decision)


def valid_decisions(event: HookEvent) -> frozenset[DecisionKind]:
    """Return the set of valid decision kinds for a hook event.

    Args:
        event: The hook event type.

    Returns:
        Frozenset of valid DecisionKind values.
    """
    return _COMPATIBILITY.get(event, frozenset())
