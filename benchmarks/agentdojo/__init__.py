"""AgentDojo APR evaluation harness for Tessera.

Standalone reproduction of the AgentDojo evaluation protocol that measures
Attack Prevention Rate (APR) and utility without requiring the agentdojo
package. When agentdojo IS installed, AGENTDOJO_AVAILABLE is True and callers
can optionally use real task suites.
"""

from __future__ import annotations

from benchmarks.agentdojo.harness import AGENTDOJO_AVAILABLE, AgentDojoHarness
from benchmarks.agentdojo.tasks import APRReport

__all__ = ["AgentDojoHarness", "APRReport", "AGENTDOJO_AVAILABLE"]
