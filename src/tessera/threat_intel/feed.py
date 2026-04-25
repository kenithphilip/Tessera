"""Threat-intel feed reader, consumer, and refresher (Wave 3F).

Three classes cover the typical lifecycle of a file-based threat-intel feed:

- ``FeedReader``: parse and validate a feed from a local file or URL.
- ``FeedConsumer``: in-memory IOC lookup, suitable for wiring into scanner
  pipelines. Checks a value against all loaded IOCs for a given kind.
- ``FeedRefresher``: background thread that re-fetches a file-based feed on
  a configurable interval and fires a ``SecurityEvent`` on each refresh.

Feed *hosting* remains out of scope per ADR-0002. ``FeedReader`` supports
``http://`` and ``file://`` URIs for consumer testing, but the Tessera OSS
repository does not operate a live feed endpoint.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Callable

from tessera.events import EventKind, SecurityEvent, emit
from tessera.threat_intel.schema import (
    IOC,
    IOCKind,
    InjectionPattern,
    MaliciousMcpServer,
    ThreatIntelFeed,
    validate_feed,
)


class FeedReader:
    """Read and validate a ``ThreatIntelFeed`` from a file path or URL.

    Accepts local ``Path`` objects, ``file://`` URIs, and ``http(s)://``
    URLs. The feed is validated against the v1 schema on each call to
    ``parse``; callers receive a validated ``ThreatIntelFeed`` or a
    ``pydantic.ValidationError`` if the payload is malformed.

    Args:
        source: A ``Path``, ``file://`` URI string, or ``http(s)://`` URL.

    Example::

        reader = FeedReader(Path("sample_feed.json"))
        feed = reader.parse()
        for ioc in reader.iter_iocs(feed):
            print(ioc.kind, ioc.value)
    """

    def __init__(self, source: Path | str) -> None:
        self._source = source

    def _fetch_bytes(self) -> bytes:
        """Fetch raw bytes from the configured source.

        Returns:
            Raw bytes of the feed payload.

        Raises:
            OSError: For file read failures.
            urllib.error.URLError: For HTTP fetch failures.
        """
        if isinstance(self._source, Path):
            return self._source.read_bytes()

        src = str(self._source)
        if src.startswith("file://"):
            path = Path(src[len("file://"):])
            return path.read_bytes()

        # http / https
        with urllib.request.urlopen(src, timeout=10) as resp:  # noqa: S310
            return resp.read()

    def parse(self) -> ThreatIntelFeed:
        """Fetch and validate the feed.

        Returns:
            A fully-validated ``ThreatIntelFeed`` instance.

        Raises:
            pydantic.ValidationError: If the payload does not match the schema.
            OSError: If the source file cannot be read.
            urllib.error.URLError: If the HTTP fetch fails.
            json.JSONDecodeError: If the payload is not valid JSON.
        """
        raw = self._fetch_bytes()
        return validate_feed(raw)

    @staticmethod
    def iter_iocs(feed: ThreatIntelFeed) -> Iterator[IOC]:
        """Yield every IOC from the feed in insertion order.

        Args:
            feed: A validated ``ThreatIntelFeed``.

        Yields:
            Each ``IOC`` sub-type instance.
        """
        yield from feed.iocs


class FeedConsumer:
    """In-memory IOC lookup for scanner pipeline integration.

    Load a feed once, then query it with ``is_blocked`` for each candidate
    value. The consumer normalises values to lower-case for MCP URI and model
    fingerprint checks so that case differences do not create blind spots.

    Injection patterns with ``pattern_type="regex"`` are compiled at load
    time. Patterns that fail to compile are skipped with a warning rather
    than raising, because a corrupt pattern in the feed must not take down
    the scanner pipeline.

    Args:
        feed: A validated ``ThreatIntelFeed`` to load.

    Example::

        consumer = FeedConsumer.from_file(Path("sample_feed.json"))
        blocked = consumer.is_blocked("https://evil.example.com/mcp", IOCKind.MCP_SERVER_URI)
    """

    def __init__(self, feed: ThreatIntelFeed) -> None:
        self._mcp_uris: frozenset[str] = frozenset(
            ioc.value.lower()
            for ioc in feed.iocs
            if ioc.kind == IOCKind.MCP_SERVER_URI
        )
        self._model_values: frozenset[str] = frozenset(
            ioc.value.lower()
            for ioc in feed.iocs
            if ioc.kind == IOCKind.MODEL_FINGERPRINT
        )
        self._injection_substrings: list[str] = [
            ioc.pattern_value
            for ioc in feed.iocs
            if isinstance(ioc, InjectionPattern) and ioc.pattern_type == "substring"
        ]
        self._injection_regexes: list[re.Pattern[str]] = []
        for ioc in feed.iocs:
            if not isinstance(ioc, InjectionPattern) or ioc.pattern_type != "regex":
                continue
            try:
                self._injection_regexes.append(re.compile(ioc.pattern_value))
            except re.error:
                # A bad pattern in the feed must not crash the consumer.
                pass

    @classmethod
    def from_file(cls, path: Path) -> "FeedConsumer":
        """Convenience constructor that reads and validates a feed file.

        Args:
            path: Local path to the feed JSON file.

        Returns:
            A ``FeedConsumer`` loaded from the file.
        """
        return cls(FeedReader(path).parse())

    def is_blocked(self, value: str, kind: IOCKind) -> bool:
        """Check whether ``value`` matches any IOC of the given ``kind``.

        For ``MCP_SERVER_URI`` and ``MODEL_FINGERPRINT``: exact lower-case
        string match.

        For ``INJECTION_PATTERN``: substring containment check followed by
        regex search. Returns ``True`` on the first match.

        Args:
            value: The candidate string to check.
            kind: The ``IOCKind`` to restrict the search to.

        Returns:
            ``True`` if ``value`` matches at least one IOC, ``False``
            otherwise.
        """
        if kind == IOCKind.MCP_SERVER_URI:
            return value.lower() in self._mcp_uris

        if kind == IOCKind.MODEL_FINGERPRINT:
            return value.lower() in self._model_values

        if kind == IOCKind.INJECTION_PATTERN:
            for sub in self._injection_substrings:
                if sub in value:
                    return True
            for pattern in self._injection_regexes:
                if pattern.search(value):
                    return True

        return False


class FeedRefresher:
    """Background thread that re-fetches a feed on a fixed interval.

    On each successful refresh, the refresher calls the supplied callback
    with the new ``ThreatIntelFeed`` and emits a ``SecurityEvent`` so
    SIEM tooling can track feed rotation. On fetch or validation failure,
    the previous feed is retained and an error is recorded in the event.

    The refresher must be stopped explicitly by calling ``stop()``. It is
    designed for use in long-running agent processes where a new feed file
    is dropped onto disk periodically by an external process (cron, CI
    artifact, etc.).

    Args:
        source: Path or URI of the feed file to refresh.
        interval: Seconds between refreshes. Default 300 (5 minutes).
        on_refresh: Callback invoked with the new ``ThreatIntelFeed``
            on each successful refresh.

    Example::

        def update_consumer(feed: ThreatIntelFeed) -> None:
            global consumer
            consumer = FeedConsumer(feed)

        refresher = FeedRefresher(Path("sample_feed.json"), on_refresh=update_consumer)
        refresher.start()
        ...
        refresher.stop()
    """

    def __init__(
        self,
        source: Path | str,
        *,
        interval: float = 300.0,
        on_refresh: Callable[[ThreatIntelFeed], None] | None = None,
    ) -> None:
        self._reader = FeedReader(source)
        self._interval = interval
        self._on_refresh = on_refresh
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background refresh thread.

        Safe to call once. Calling again after the thread is running is a no-op.
        """
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the refresh thread to stop and wait for it.

        Args:
            timeout: Seconds to wait for the thread to join.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        """Main loop: refresh once, then sleep until the next interval."""
        while not self._stop_event.is_set():
            self._refresh()
            # Use event.wait so stop() wakes us up immediately.
            self._stop_event.wait(timeout=self._interval)

    def _refresh(self) -> None:
        """Fetch, validate, call the callback, and emit the SecurityEvent."""
        error_detail: str | None = None
        feed: ThreatIntelFeed | None = None
        try:
            feed = self._reader.parse()
        except Exception as exc:  # broad catch: feed errors must not crash the agent
            error_detail = str(exc)

        detail: dict[str, object] = {
            "source": str(self._reader._source),
            "ioc_count": len(feed.iocs) if feed is not None else 0,
            "success": feed is not None,
        }
        if error_detail:
            detail["error"] = error_detail

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal="tessera.threat_intel.FeedRefresher",
                detail=detail,
            )
        )

        if feed is not None and self._on_refresh is not None:
            self._on_refresh(feed)


__all__ = ["FeedReader", "FeedConsumer", "FeedRefresher"]
