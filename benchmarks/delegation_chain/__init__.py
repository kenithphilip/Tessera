"""Delegation chain attack benchmark.

Tests multi-agent delegation where agent B is compromised. Agent A
delegates to agent B with a scoped delegation token. Agent B attempts
to exceed the delegated authority by calling tools outside the scope.

The expected behavior: Tessera's delegation token verification should
block tool calls that exceed the delegated action set, even when the
compromised agent has valid identity credentials.
"""
