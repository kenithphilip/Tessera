"""Memory poisoning benchmark.

Tests cross-session attacks where content planted in session 1 is
retrieved and used in session 2. The attack: an attacker embeds
injection content in a tool output during session 1, which gets stored
in a session approval. When session 2 retrieves the stored approval,
the injection content should be detected by the re-scan defense.

The expected behavior: SessionStore.retrieve(scan_on_load=True) should
reject stored sessions whose context_summary contains injection content
above the scan threshold, emitting a CONTENT_INJECTION_DETECTED event.
"""
