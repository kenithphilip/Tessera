"""Minimal CLI. `tessera serve` brings up the proxy against an OpenAI upstream."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import httpx
import uvicorn

from tessera.policy import Policy
from tessera.proxy import create_app


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

    args = parser.parse_args(argv)
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

    app = create_app(
        key=key,
        upstream=_openai_upstream(api_key, args.upstream),
        policy=Policy(),
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0
