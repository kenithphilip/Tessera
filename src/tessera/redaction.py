"""Credential isolation at the Tessera proxy boundary.

The pattern this module implements is the GitHub Agent Workflow Firewall
approach to credential handling: the proxy holds the real secret values,
and any attempt to move those values across the proxy boundary (into a
prompt the LLM will read, or back out in a model response the agent will
read) is rewritten to an opaque marker before the bytes leave the proxy.

In practice this looks like::

    from tessera.proxy import create_app
    from tessera.redaction import SecretRegistry

    secrets = SecretRegistry()
    secrets.add("GITHUB_TOKEN", os.environ["GITHUB_TOKEN"])
    secrets.add("OPENAI_API_KEY", os.environ["OPENAI_API_KEY"])

    app = create_app(key=hmac_key, upstream=upstream, secrets=secrets)

The proxy will then scrub any occurrence of the registered values from
both outbound chat-completion payloads and inbound responses, emitting a
``SECRET_REDACTED`` security event whenever a hit fires. A compromised
agent that tries to read ``os.environ["GITHUB_TOKEN"]`` and stuff the
result into a chat prompt finds that the LLM only ever sees
``<REDACTED:GITHUB_TOKEN>``.

This is defense-in-depth. The right long-term answer is that the agent
process should not hold the real values at all: it should hold
placeholder tokens and the proxy substitutes on egress to downstream
services. Reference architectures for that are tracked in the roadmap.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Values shorter than this are almost always going to cause false-positive
# redactions on benign substrings ("123", "abc", short usernames). The
# guard is a hard error at registration time rather than a silent loss of
# signal at redaction time.
_MIN_SECRET_LENGTH = 8


@dataclass(frozen=True)
class Secret:
    """One named secret the proxy must never pass through to an LLM."""

    name: str
    value: str


@dataclass
class SecretRegistry:
    """Ordered collection of secrets subject to redaction.

    The registry is deliberately append-only through ``add`` so callers
    cannot accidentally shadow an existing secret with a new one under
    the same name or value. Clearing the registry is explicit (``clear``)
    to make that operation audit-visible in code review.
    """

    _secrets: list[Secret] = field(default_factory=list)

    def add(self, name: str, value: str) -> None:
        """Register a secret for redaction.

        Args:
            name: Human-readable identifier used in the redaction marker
                (for example ``GITHUB_TOKEN``). Must be non-empty.
            value: The literal bytes that must not leave the proxy. Must
                be at least 8 characters to avoid benign substring matches.

        Raises:
            ValueError: if ``name`` or ``value`` is empty, if ``value``
                is shorter than 8 characters, or if either the name or
                the value is already registered.
        """
        if not name:
            raise ValueError("secret name must be non-empty")
        if not value:
            raise ValueError(f"secret value for {name!r} must be non-empty")
        if len(value) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"refusing to register secret {name!r}: values under "
                f"{_MIN_SECRET_LENGTH} characters are too likely to match "
                "benign substrings and will cause false-positive redactions"
            )
        for existing in self._secrets:
            if existing.name == name:
                raise ValueError(f"secret {name!r} is already registered")
            if existing.value == value:
                raise ValueError(
                    f"that value is already registered under the name "
                    f"{existing.name!r}"
                )
        self._secrets.append(Secret(name=name, value=value))

    def clear(self) -> None:
        """Drop every registered secret. Intended for tests and shutdown."""
        self._secrets.clear()

    def __len__(self) -> int:
        return len(self._secrets)

    @property
    def names(self) -> list[str]:
        """Return the registered names in registration order."""
        return [s.name for s in self._secrets]

    @classmethod
    def from_env(cls, *names: str) -> "SecretRegistry":
        """Build a registry from current process environment variables.

        Missing, empty, or too-short environment variables are skipped
        silently so the same startup code can run in dev and in
        production with different subsets of secrets available. Dev
        environments sometimes set tokens to placeholders like
        ``"dev"``; those are not worth registering.

        Args:
            *names: Environment variable names to register.

        Returns:
            A new SecretRegistry. Empty if none of the requested
            variables were present or long enough.
        """
        reg = cls()
        for var in names:
            value = os.environ.get(var, "")
            if value and len(value) >= _MIN_SECRET_LENGTH:
                reg.add(var, value)
        return reg

    def redact(self, text: str) -> tuple[str, list[str]]:
        """Replace every registered secret value in ``text`` with a marker.

        The replacement marker is ``<REDACTED:NAME>`` where ``NAME`` is
        the name the secret was registered under. Secrets are processed
        in descending length order so a longer secret is replaced before
        any shorter secret that might be its prefix.

        Args:
            text: The string to scrub. Non-string callers should route
                through :func:`redact_nested` instead.

        Returns:
            A 2-tuple of ``(redacted_text, hit_names)``. ``hit_names`` is
            the ordered list of secret names that matched at least once,
            suitable for a security event detail field. Empty if the
            text did not contain any registered secret.
        """
        if not self._secrets:
            return text, []
        hits: list[str] = []
        ordered = sorted(self._secrets, key=lambda s: -len(s.value))
        for secret in ordered:
            if secret.value in text:
                text = text.replace(secret.value, f"<REDACTED:{secret.name}>")
                hits.append(secret.name)
        return text, hits


def redact_nested(obj, registry: SecretRegistry) -> tuple[object, list[str]]:
    """Recursively redact secret values inside a JSON-shaped object.

    Walks dicts and lists in place, rewriting string leaves that contain
    a registered secret. Dict keys are left untouched on the assumption
    that secrets appear in values, not in field names; a caller that
    needs key-side redaction can do so explicitly.

    Args:
        obj: A dict, list, str, or primitive. Nested containers are
            walked. Non-string leaves are left alone.
        registry: The SecretRegistry to consult.

    Returns:
        A 2-tuple of ``(same_object_possibly_rewritten, all_hit_names)``.
        The first element is the same reference that was passed in for
        dicts and lists (mutation is in place) and a new string for
        top-level string inputs.
    """
    all_hits: list[str] = []

    def _walk(node):  # type: ignore[no-untyped-def]
        if isinstance(node, str):
            redacted, hits = registry.redact(node)
            all_hits.extend(hits)
            return redacted
        if isinstance(node, dict):
            for k, v in node.items():
                node[k] = _walk(v)
            return node
        if isinstance(node, list):
            for i, v in enumerate(node):
                node[i] = _walk(v)
            return node
        return node

    rewritten = _walk(obj)
    return rewritten, all_hits
