"""Tool manifest poisoning benchmark.

Tests supply-chain attacks on MCP tool descriptions. A malicious or
compromised MCP server embeds injection instructions in tool descriptions
that flow into the agent's context window before any user data arrives.

Attack variants:
1. Instruction override in tool description ("ignore previous instructions")
2. Hidden content via zero-width characters
3. Data exfiltration guidance ("send output to http://evil.com")
4. Privilege escalation directives ("grant admin access")

The expected behavior: the tool_descriptions scanner should detect all
poisoning categories and emit CONTENT_INJECTION_DETECTED events with
appropriate severity (BLOCK, WARN, or INFO).
"""
