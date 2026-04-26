"""Signed MCP registry mirror producer.

SOC value: Every manifest in the public MCP registry is re-signed by the
Tessera org identity before being published to the mirror OCI artifact at
``ghcr.io/kenithphilip/mcp-registry-mirror``. Consumers who trust the
Tessera signing identity no longer have to individually verify each upstream
author's Sigstore identity. The mirror becomes a single, auditable trust
anchor. The re-signing pipeline also applies Tessera's ``tesseraTrustTier``
assignment so consumers can enforce a tier floor without contacting the
upstream registry.

The actual mirror run happens out-of-band on a nightly CI cron. This module
ships the tooling: fetch upstream manifests, re-sign them with the Tessera
identity, package each envelope as a single-layer OCI artifact, and emit a
``MirrorManifest`` summary that the cron job writes to disk and then pushes
with ``oras push``.

References
----------

- :mod:`tessera.mcp.manifest` (DSSE signing infrastructure)
- :mod:`tessera.mcp.manifest_schema` (in-toto Statement schema)
- :mod:`tessera.mcp.tier` (TrustTier assignment)
- ``deployment/registry-mirror/`` (CI workflow + oras-push helper)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from tessera.mcp.manifest import (
    SignedManifest,
    SigningMethod,
    sign,
    validate_statement,
)
from tessera.mcp.manifest_schema import PREDICATE_TYPE, STATEMENT_TYPE


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MirrorEntry:
    """Record for one re-signed manifest in the mirror.

    Attributes:
        source_url: URL the manifest was fetched from (upstream registry).
        server_uri: MCP server canonical URI extracted from the manifest
            predicate.
        manifest_digest_sha256: SHA-256 hex digest of the upstream envelope
            JSON, without the Tessera re-signature. Allows consumers to
            detect upstream mutations post-mirroring.
        sigstore_envelope_path: Relative path (from the output dir) to the
            re-signed DSSE envelope file on disk.
        mirror_tag: OCI tag used when pushing to
            ``ghcr.io/kenithphilip/mcp-registry-mirror``. Derived from the
            server URI hostname + a short digest prefix so it is stable
            across cron runs.
        mirrored_at: ISO 8601 timestamp of when this entry was produced.
    """

    source_url: str
    server_uri: str
    manifest_digest_sha256: str
    sigstore_envelope_path: str
    mirror_tag: str
    mirrored_at: str


@dataclass(frozen=True, slots=True)
class MirrorManifest:
    """Summary written to disk after a full mirror sync run.

    The file produced by :meth:`RegistryMirror.mirror_all` serves two
    purposes. Immediately after the run it is consumed by ``oras-push.sh``
    to iterate the entries and push each OCI artifact. In steady state it is
    the authoritative record of what is in the mirror, which SIEM pipelines
    can diff to detect unexpected additions or removals.

    Attributes:
        schema_version: Fixed sentinel checked by readers.
        generated_at: ISO 8601 timestamp of the run.
        entries: Tuple of :class:`MirrorEntry` objects, one per upstream
            manifest that was processed.
        upstream_registry_url: Base URL of the upstream MCP registry.
        mirror_signing_identity: The Tessera identity used to re-sign all
            manifests. For HMAC runs this is the ``hmac_keyid`` string.
    """

    schema_version: str
    generated_at: str
    entries: tuple[MirrorEntry, ...]
    upstream_registry_url: str
    mirror_signing_identity: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for the manifest."""
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "upstream_registry_url": self.upstream_registry_url,
            "mirror_signing_identity": self.mirror_signing_identity,
            "entries": [
                {
                    "source_url": e.source_url,
                    "server_uri": e.server_uri,
                    "manifest_digest_sha256": e.manifest_digest_sha256,
                    "sigstore_envelope_path": e.sigstore_envelope_path,
                    "mirror_tag": e.mirror_tag,
                    "mirrored_at": e.mirrored_at,
                }
                for e in self.entries
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MirrorManifest":
        """Reconstruct a MirrorManifest from its on-disk dict.

        Raises:
            ValueError: When ``schema_version`` does not match the expected
                constant or required fields are absent.
        """
        if data.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version: {data.get('schema_version')!r}; "
                f"expected {_SCHEMA_VERSION!r}"
            )
        entries = tuple(
            MirrorEntry(
                source_url=e["source_url"],
                server_uri=e["server_uri"],
                manifest_digest_sha256=e["manifest_digest_sha256"],
                sigstore_envelope_path=e["sigstore_envelope_path"],
                mirror_tag=e["mirror_tag"],
                mirrored_at=e["mirrored_at"],
            )
            for e in data.get("entries", ())
        )
        return cls(
            schema_version=data["schema_version"],
            generated_at=data["generated_at"],
            entries=entries,
            upstream_registry_url=data["upstream_registry_url"],
            mirror_signing_identity=data["mirror_signing_identity"],
        )


_SCHEMA_VERSION = "tessera.mcp.registry_mirror.v1"

# OCI media type for the single-layer artifact.
_OCI_MEDIA_TYPE = "application/vnd.tessera.mcp.signed-manifest+json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _derive_mirror_tag(server_uri: str) -> str:
    """Return a stable, OCI-legal tag string for a server URI.

    OCI tags must match ``[a-zA-Z0-9_.-]{1,128}``. We use the hostname
    portion of the server URI plus the first 12 hex chars of its SHA-256 so
    the tag is both human-readable and collision-resistant.
    """
    digest = _sha256_hex(server_uri.encode("utf-8"))[:12]
    # Extract a safe hostname prefix.
    stripped = server_uri
    for scheme in ("mcp+ws://", "mcp+http://", "https://", "http://", "mcp://"):
        if server_uri.startswith(scheme):
            stripped = server_uri[len(scheme):]
            break
    host = stripped.split("/")[0].split(":")[0]
    # Replace characters OCI tags do not allow.
    safe_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
    safe_host = safe_host[:60] or "unknown"
    return f"{safe_host}-{digest}"


def _build_upstream_statement(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract or synthesise an in-toto Statement from raw upstream data.

    The upstream registry may return either a bare DSSE envelope (already
    an in-toto Statement in the payload) or a simplified JSON object with
    at least ``serverUri`` and ``tools`` keys. Both shapes are accepted.

    When the upstream already ships a DSSE envelope the inner Statement is
    decoded and returned verbatim so the upstream subject digest is
    preserved. When the upstream ships a bare record a minimal Statement is
    synthesised so the re-sign path has a valid target.

    Raises:
        ValueError: When the upstream data cannot be parsed into a usable
            Statement shape.
    """
    # Case 1: DSSE envelope with a base64 payload.
    import base64

    if "payload" in raw and "payloadType" in raw:
        try:
            statement = json.loads(base64.standard_b64decode(raw["payload"]))
            validate_statement(statement)
            return statement
        except Exception as exc:
            raise ValueError(f"failed to decode upstream DSSE payload: {exc}") from exc

    # Case 2: synthesise a minimal Statement from bare upstream fields.
    # Accept three shapes:
    #   {"serverUri": "..."}                              <- Tessera native
    #   {"server_uri": "..."}                             <- snake-case
    #   {"server": {"name": "...", "version": "..."}}     <- official
    #                                                        registry.modelcontextprotocol.io
    nested = raw.get("server") if isinstance(raw.get("server"), dict) else None
    server_uri = (
        raw.get("serverUri")
        or raw.get("server_uri")
        or (nested.get("name") if nested else None)
        or ""
    )
    if not server_uri:
        raise ValueError("upstream manifest missing serverUri / server.name")
    # Composite versioned id keeps multiple versions of the same server
    # distinguishable in the OCI tag namespace.
    if nested and nested.get("version") and ":" not in server_uri:
        server_uri = f"{server_uri}:{nested['version']}"
    issued_at = (
        raw.get("issuedAt")
        or raw.get("issued_at")
        or ((raw.get("_meta") or {}).get(
            "io.modelcontextprotocol.registry/official", {}
        ).get("publishedAt"))
        or _utcnow()
    )
    issuer = raw.get("issuer", "https://tessera.dev/mirror")
    resource_indicator = raw.get("resourceIndicator") or raw.get("resource_indicator") or server_uri
    tier = raw.get("tesseraTrustTier") or raw.get("tessera_trust_tier") or "community"
    tools = raw.get("tools", [])

    # Build stable subject digest from the server URI.
    digest = _sha256_hex(server_uri.encode("utf-8"))
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": server_uri, "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "serverUri": server_uri,
            "issuer": issuer,
            "issuedAt": issued_at,
            "resourceIndicator": resource_indicator,
            "tesseraTrustTier": tier,
            "tools": tools,
        },
    }


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _write_oci_layer(signed: SignedManifest, dest: Path, tag: str | None = None) -> None:
    """Write a minimal single-layer OCI artifact to ``dest``.

    When the ``oras`` library is importable the artifact is written in the
    full OCI image layout format so ``oras push`` can consume it directly.
    When ``oras`` is not installed (CI typically provides it as a sidecar
    binary) the layer blob is written as raw bytes alongside a minimal
    ``manifest.json`` that the ``oras push --from-oci-layout`` flag
    accepts. This keeps the Python package free of an optional heavy
    dependency while still producing a layout that the out-of-band
    ``oras-push.sh`` helper can consume.

    Args:
        signed: The re-signed manifest.
        dest: Directory to write the OCI layout into. Created if absent.
    """
    dest.mkdir(parents=True, exist_ok=True)
    blob_bytes = signed.to_json().encode("utf-8")
    blob_digest = _sha256_hex(blob_bytes)

    blobs_dir = dest / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    blob_path = blobs_dir / blob_digest
    blob_path.write_bytes(blob_bytes)

    config_bytes = b"{}"
    config_digest = _sha256_hex(config_bytes)
    (blobs_dir / config_digest).write_bytes(config_bytes)

    # OCI image manifest (not the Tessera MirrorManifest).
    oci_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": _OCI_MEDIA_TYPE,
                "size": len(blob_bytes),
                "digest": f"sha256:{blob_digest}",
            }
        ],
    }
    oci_manifest_bytes = json.dumps(oci_manifest, separators=(",", ":")).encode("utf-8")
    oci_manifest_digest = _sha256_hex(oci_manifest_bytes)
    (blobs_dir / oci_manifest_digest).write_bytes(oci_manifest_bytes)

    # OCI image index entry. The annotations.org.opencontainers.image.ref.name
    # is required for `oras copy --from-oci-layout PATH ...` to resolve the
    # layout to a single named manifest. Without it, oras errors with "no tag
    # or digest specified" and the push step fails.
    index_entry: dict[str, Any] = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": len(oci_manifest_bytes),
        "digest": f"sha256:{oci_manifest_digest}",
    }
    if tag:
        index_entry["annotations"] = {"org.opencontainers.image.ref.name": tag}
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [index_entry],
    }
    (dest / "oci-layout").write_text(
        json.dumps({"imageLayoutVersion": "1.0.0"}), encoding="utf-8"
    )
    (dest / "index.json").write_text(
        json.dumps(index, separators=(",", ":")), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class RegistryMirror:
    """Fetch, re-sign, and package MCP registry manifests.

    Typical use is via :meth:`mirror_all`. The individual methods are
    exposed for testing and for operators who need partial flows (e.g.,
    re-sign only or package only).

    Args:
        upstream_url: Base URL of the upstream MCP registry. The mirror
            fetches ``GET {upstream_url}/manifests`` to discover the
            manifest list.
        hmac_key: When provided, HMAC-SHA256 signing is used instead of
            Sigstore. Required for air-gapped environments and tests. Must
            be at least 32 bytes.
        hmac_keyid: Identifier embedded in HMAC signatures. Defaults to
            ``tessera-mirror-hmac-v1``.
        sigstore_identity: Sigstore OIDC identity token for the production
            signing path. When both ``hmac_key`` and this parameter are
            absent the mirror falls back to HMAC with a randomly generated
            key and logs a warning.
        output_dir: Root directory for all output: re-signed envelopes,
            OCI layouts, and the final ``mirror-manifest.json``. Created
            on first use.
    """

    def __init__(
        self,
        upstream_url: str,
        hmac_key: bytes | None = None,
        hmac_keyid: str = "tessera-mirror-hmac-v1",
        sigstore_identity: str | None = None,
        output_dir: Path = Path("mirror-output"),
    ) -> None:
        self._upstream_url = upstream_url.rstrip("/")
        self._hmac_key = hmac_key
        self._hmac_keyid = hmac_keyid
        self._sigstore_identity = sigstore_identity
        self._output_dir = output_dir
        if hmac_key is not None:
            self._method = SigningMethod.HMAC
        elif sigstore_identity is not None:
            self._method = SigningMethod.SIGSTORE
        else:
            self._method = SigningMethod.HMAC
            import secrets

            self._hmac_key = secrets.token_bytes(32)

    def fetch_upstream(self) -> list[dict[str, Any]]:
        """Fetch the manifest list from the upstream registry.

        Probes endpoints in this order:

        1. ``GET {upstream_url}/v0/servers`` (paginated). Matches the
           official registry at ``registry.modelcontextprotocol.io``
           which returns ``{"servers": [...], "metadata":
           {"nextCursor": ...}}`` and follows ``nextCursor`` until the
           upstream stops returning one.
        2. ``GET {upstream_url}/manifests`` for legacy / Tessera-shaped
           registries.
        3. ``GET {upstream_url}`` as a final fallback for static JSON
           hosts that publish a single document.

        Returns:
            A list of raw upstream records. Each record may be a DSSE
            envelope, a bare ``serverUri`` document, or the
            ``{"server": {...}}`` shape used by the official registry.

        Raises:
            httpx.HTTPError: On transport failure.
            ValueError: When every probe returns a non-JSON or
                otherwise unusable response.
        """
        # Probe 1: official registry /v0/servers with pagination.
        servers = self._fetch_v0_servers()
        if servers is not None:
            return servers

        # Probe 2: Tessera-shaped /manifests.
        resp = httpx.get(f"{self._upstream_url}/manifests", timeout=15.0)
        if resp.status_code != 404:
            resp.raise_for_status()
            return self._coerce_list(resp)

        # Probe 3: root URL (static JSON document).
        resp = httpx.get(self._upstream_url, timeout=15.0)
        resp.raise_for_status()
        try:
            return self._coerce_list(resp)
        except ValueError as exc:
            ctype = resp.headers.get("content-type", "?")
            raise ValueError(
                f"upstream registry returned no recognised endpoint: "
                f"/v0/servers, /manifests, and / all failed. "
                f"Root content-type={ctype}. Last decode error: {exc}"
            ) from exc

    def _fetch_v0_servers(self) -> list[dict[str, Any]] | None:
        """Drive the paginated /v0/servers endpoint to completion.

        Returns ``None`` when the endpoint is not present (404 on the
        first call), otherwise the full concatenated server list.
        """
        servers: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, str] = {"limit": "100"}
            if cursor:
                params["cursor"] = cursor
            resp = httpx.get(
                f"{self._upstream_url}/v0/servers",
                params=params,
                timeout=15.0,
            )
            if resp.status_code == 404 and not servers:
                return None
            resp.raise_for_status()
            payload = resp.json()
            page = payload.get("servers") if isinstance(payload, dict) else None
            if not isinstance(page, list):
                return None
            servers.extend(page)
            cursor = (payload.get("metadata") or {}).get("nextCursor")
            if not cursor:
                break
        return servers

    @staticmethod
    def _coerce_list(resp: httpx.Response) -> list[dict[str, Any]]:
        """Decode an httpx response into a list of upstream records.

        Accepts either a JSON list at the root, or a wrapping object
        whose value at ``manifests`` / ``items`` / ``entries`` / ``data``
        / ``servers`` is the list.
        """
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("manifests", "items", "entries", "data", "servers"):
                if isinstance(data.get(key), list):
                    return data[key]
        raise ValueError(
            f"upstream registry returned unexpected shape: {type(data).__name__}"
        )

    def re_sign(self, upstream_manifest: dict[str, Any]) -> SignedManifest:
        """Parse an upstream manifest and re-sign it with the Tessera identity.

        The upstream statement is parsed and validated. If the upstream
        carried a Sigstore signature that signature is discarded: the
        re-signed envelope replaces it with the Tessera org identity.

        Args:
            upstream_manifest: A raw dict from :meth:`fetch_upstream`. May
                be a DSSE envelope or a bare record.

        Returns:
            A :class:`SignedManifest` signed with the configured method.

        Raises:
            ValueError: When the upstream cannot be coerced into a valid
                in-toto Statement.
        """
        statement = _build_upstream_statement(upstream_manifest)
        return sign(
            statement,
            method=self._method,
            hmac_key=self._hmac_key,
            hmac_keyid=self._hmac_keyid,
            sigstore_identity_token=self._sigstore_identity,
        )

    def package_oci(self, signed: SignedManifest) -> Path:
        """Write a single-layer OCI artifact for one signed manifest.

        The layout is written to
        ``{output_dir}/oci/{tag}/`` where ``tag`` is derived from the
        server URI in the statement. The raw re-signed DSSE envelope is
        also written to ``{output_dir}/envelopes/{tag}.json`` for
        operators who want to inspect or manually push individual
        envelopes.

        Args:
            signed: A :class:`SignedManifest` from :meth:`re_sign`.

        Returns:
            The path to the OCI layout directory for this artifact.
        """
        server_uri = signed.statement.get("predicate", {}).get("serverUri", "unknown")
        tag = _derive_mirror_tag(server_uri)

        envelopes_dir = self._output_dir / "envelopes"
        envelopes_dir.mkdir(parents=True, exist_ok=True)
        envelope_path = envelopes_dir / f"{tag}.json"
        envelope_path.write_text(signed.to_json(), encoding="utf-8")

        oci_dir = self._output_dir / "oci" / tag
        _write_oci_layer(signed, oci_dir, tag=tag)
        return oci_dir

    def mirror_all(self, limit: int = 0) -> MirrorManifest:
        """Run the full pull -> re-sign -> package pipeline.

        Fetches the upstream manifest list, re-signs each entry,
        packages each as an OCI artifact, and writes
        ``mirror-manifest.json`` to :attr:`output_dir`.

        Args:
            limit: When > 0, process at most this many upstream
                manifests. Useful for CI cron runs that have a
                bounded execution budget. Default 0 means process
                everything.

        Returns:
            A :class:`MirrorManifest` summarising every processed entry.

        Raises:
            httpx.HTTPError: On transport failure during fetch.
            ValueError: When the upstream registry returns an unusable
                response shape.
        """
        raw_manifests = self.fetch_upstream()
        if limit > 0:
            raw_manifests = raw_manifests[:limit]
        entries: list[MirrorEntry] = []
        now = _utcnow()

        for raw in raw_manifests:
            raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
            source_digest = _sha256_hex(raw_bytes)
            source_url = raw.get("source_url") or raw.get("sourceUrl") or self._upstream_url
            try:
                signed = self.re_sign(raw)
            except ValueError:
                continue

            server_uri = signed.statement.get("predicate", {}).get("serverUri", "unknown")
            tag = _derive_mirror_tag(server_uri)
            self.package_oci(signed)
            rel_envelope = f"envelopes/{tag}.json"
            entries.append(
                MirrorEntry(
                    source_url=source_url,
                    server_uri=server_uri,
                    manifest_digest_sha256=source_digest,
                    sigstore_envelope_path=rel_envelope,
                    mirror_tag=tag,
                    mirrored_at=now,
                )
            )

        mirror = MirrorManifest(
            schema_version=_SCHEMA_VERSION,
            generated_at=now,
            entries=tuple(entries),
            upstream_registry_url=self._upstream_url,
            mirror_signing_identity=self._hmac_keyid
            if self._method == SigningMethod.HMAC
            else (self._sigstore_identity or "sigstore"),
        )
        self.manifest_path().parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path().write_text(
            json.dumps(mirror.to_dict(), indent=2), encoding="utf-8"
        )
        return mirror

    def manifest_path(self) -> Path:
        """Return the path where the MirrorManifest JSON is written.

        This is always ``{output_dir}/mirror-manifest.json``.
        """
        return self._output_dir / "mirror-manifest.json"


__all__ = [
    "MirrorEntry",
    "MirrorManifest",
    "RegistryMirror",
]
