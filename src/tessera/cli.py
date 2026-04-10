"""Minimal CLI. `tessera serve` brings up the proxy against an OpenAI upstream."""

from __future__ import annotations

import argparse
from datetime import timedelta
import os
import sys
from typing import Any

import httpx
import uvicorn

from tessera.control_plane import (
    ControlPlaneState,
    PolicyDistributionInput,
    RegistryDistributionInput,
    create_control_plane_app,
)
from tessera.identity import JWKSAgentIdentityVerifier
from tessera.policy import Policy
from tessera.policy_backends import OPAPolicyBackend
from tessera.proxy import create_app
from tessera.spire import create_spire_identity_verifier


def _openai_upstream(api_key: str, base_url: str):
    async def call(payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{base_url}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tessera")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the Tessera proxy")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument(
        "--upstream",
        default="https://api.openai.com",
        help="base URL of the upstream LLM API",
    )
    serve.add_argument(
        "--agent-id",
        default=os.environ.get("TESSERA_AGENT_ID"),
        help="SPIFFE workload identity for discovery, defaults to TESSERA_AGENT_ID",
    )
    serve.add_argument(
        "--agent-name",
        default=os.environ.get("TESSERA_AGENT_NAME", "Tessera Proxy"),
        help="discovery display name, defaults to TESSERA_AGENT_NAME",
    )
    serve.add_argument(
        "--agent-description",
        default=os.environ.get("TESSERA_AGENT_DESCRIPTION"),
        help="discovery description, defaults to TESSERA_AGENT_DESCRIPTION",
    )
    serve.add_argument(
        "--agent-url",
        default=os.environ.get("TESSERA_AGENT_URL"),
        help="public base URL for discovery, defaults to TESSERA_AGENT_URL",
    )
    serve.add_argument(
        "--identity-jwks-url",
        default=os.environ.get("TESSERA_IDENTITY_JWKS_URL"),
        help="JWKS URL for inbound ASM-Agent-Identity verification",
    )
    serve.add_argument(
        "--identity-spire",
        action="store_true",
        help="verify inbound ASM-Agent-Identity with live JWT bundles from the local SPIRE Workload API",
    )
    serve.add_argument(
        "--identity-issuer",
        default=os.environ.get("TESSERA_IDENTITY_ISSUER"),
        help="expected issuer for inbound ASM-Agent-Identity",
    )
    serve.add_argument(
        "--identity-audience",
        default=os.environ.get("TESSERA_IDENTITY_AUDIENCE"),
        help="expected audience for inbound ASM-Agent-Identity",
    )
    serve.add_argument(
        "--allow-anonymous",
        action="store_true",
        help="allow requests without ASM-Agent-Identity even when identity verification is configured",
    )
    serve.add_argument(
        "--require-mtls",
        action="store_true",
        help="require a verified transport client certificate identity on inbound requests",
    )
    serve.add_argument(
        "--trust-xfcc",
        action="store_true",
        help="trust Envoy X-Forwarded-Client-Cert only from explicitly trusted proxy hosts",
    )
    serve.add_argument(
        "--trusted-proxy-host",
        action="append",
        default=None,
        help="immediate proxy host allowed to supply X-Forwarded-Client-Cert, may be repeated",
    )
    serve.add_argument(
        "--mtls-trust-domain",
        action="append",
        default=None,
        help="allowed SPIFFE trust domain for transport client certificate identities, may be repeated",
    )
    serve.add_argument(
        "--spiffe-endpoint-socket",
        default=os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
        help="SPIFFE Workload API socket, defaults to SPIFFE_ENDPOINT_SOCKET",
    )
    serve.add_argument(
        "--policy-opa-url",
        default=os.environ.get("TESSERA_POLICY_OPA_URL"),
        help="OPA base URL for external deny-only policy checks",
    )
    serve.add_argument(
        "--policy-opa-path",
        default=os.environ.get(
            "TESSERA_POLICY_OPA_PATH",
            "/v1/data/tessera/authz/allow",
        ),
        help="OPA Data API decision path, defaults to /v1/data/tessera/authz/allow",
    )
    serve.add_argument(
        "--policy-opa-token",
        default=os.environ.get("TESSERA_POLICY_OPA_TOKEN"),
        help="Bearer token for OPA API authentication",
    )

    control_plane = sub.add_parser("control-plane", help="run the Tessera control plane")
    control_plane.add_argument("--host", default="127.0.0.1")
    control_plane.add_argument("--port", type=int, default=8090)
    control_plane.add_argument(
        "--auth-token",
        default=os.environ.get("TESSERA_CONTROL_AUTH_TOKEN"),
        help="bearer token required for control-plane API access",
    )
    control_plane.add_argument(
        "--allow-unauthenticated",
        action="store_true",
        help="allow unauthenticated control-plane access, intended only for local development",
    )
    control_plane.add_argument(
        "--policy-file",
        default=os.environ.get("TESSERA_CONTROL_POLICY_FILE"),
        help="optional JSON file for the initial policy distribution document",
    )
    control_plane.add_argument(
        "--registry-file",
        default=os.environ.get("TESSERA_CONTROL_REGISTRY_FILE"),
        help="optional JSON file for the initial registry distribution document",
    )
    control_plane.add_argument(
        "--agent-ttl-seconds",
        type=int,
        default=int(os.environ.get("TESSERA_CONTROL_AGENT_TTL_SECONDS", "300")),
        help="heartbeat freshness window for status reporting",
    )

    args = parser.parse_args(argv)
    if args.cmd == "control-plane":
        if not args.auth_token and not args.allow_unauthenticated:
            print(
                "control-plane auth is required, set --auth-token or --allow-unauthenticated",
                file=sys.stderr,
            )
            return 2
        state = ControlPlaneState(agent_ttl=timedelta(seconds=args.agent_ttl_seconds))
        if args.policy_file:
            with open(args.policy_file, "r", encoding="utf-8") as handle:
                state.update_policy(PolicyDistributionInput.model_validate_json(handle.read()))
        if args.registry_file:
            with open(args.registry_file, "r", encoding="utf-8") as handle:
                state.update_registry(RegistryDistributionInput.model_validate_json(handle.read()))
        uvicorn.run(
            create_control_plane_app(
                state,
                bearer_token=args.auth_token,
                allow_unauthenticated=args.allow_unauthenticated,
            ),
            host=args.host,
            port=args.port,
        )
        return 0
    if args.cmd != "serve":
        parser.print_help()
        return 2

    key = os.environ.get("TESSERA_HMAC_KEY", "").encode("utf-8")
    if not key:
        print("TESSERA_HMAC_KEY is required", file=sys.stderr)
        return 1

    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("OPENAI_API_KEY is required", file=sys.stderr)
        return 1

    if args.identity_spire and args.identity_jwks_url:
        print(
            "choose either --identity-spire or --identity-jwks-url, not both",
            file=sys.stderr,
        )
        return 2

    identity_verifier = None
    if args.identity_spire:
        identity_verifier = create_spire_identity_verifier(
            socket_path=args.spiffe_endpoint_socket,
            expected_issuer=args.identity_issuer,
        )
    elif args.identity_jwks_url:
        def fetch_jwks() -> dict[str, Any]:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(args.identity_jwks_url)
                response.raise_for_status()
                return response.json()

        identity_verifier = JWKSAgentIdentityVerifier(
            fetch_jwks=fetch_jwks,
            expected_issuer=args.identity_issuer,
        )

    trusted_proxy_hosts = args.trusted_proxy_host
    if trusted_proxy_hosts is None:
        raw_hosts = os.environ.get("TESSERA_TRUSTED_PROXY_HOSTS", "")
        trusted_proxy_hosts = [host.strip() for host in raw_hosts.split(",") if host.strip()]

    mtls_trust_domains = args.mtls_trust_domain
    if mtls_trust_domains is None:
        raw_domains = os.environ.get("TESSERA_MTLS_TRUST_DOMAINS", "")
        mtls_trust_domains = [domain.strip() for domain in raw_domains.split(",") if domain.strip()]

    policy_backend = (
        None
        if not args.policy_opa_url
        else OPAPolicyBackend(
            base_url=args.policy_opa_url,
            decision_path=args.policy_opa_path,
            bearer_token=args.policy_opa_token,
        )
    )

    app = create_app(
        key=key,
        upstream=_openai_upstream(api_key, args.upstream),
        policy=Policy(backend=policy_backend),
        identity_verifier=identity_verifier,
        identity_audience=args.identity_audience or args.agent_id or "proxy://tessera",
        agent_id=args.agent_id,
        agent_name=args.agent_name,
        agent_description=args.agent_description,
        agent_url=args.agent_url,
        require_identity=identity_verifier is not None and not args.allow_anonymous,
        require_mtls=args.require_mtls,
        trust_xfcc=args.trust_xfcc,
        trusted_proxy_hosts=tuple(trusted_proxy_hosts),
        mtls_trust_domains=tuple(mtls_trust_domains) if mtls_trust_domains else None,
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0
