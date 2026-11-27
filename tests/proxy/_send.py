"""Send one request through the proxy app with a mocked upstream; shared by the sec3 tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
MAIL = "erika.beispiel@firma-test.de"
IBAN = "DE89370400440532013000"
CONVERSATION = "0b1c2d3e-5f6a-4b7c-8d9e-0a1b2c3d4e5f"
BASE: dict[str, Any] = {
    "model": "claude-x",
    "max_tokens": 16,
    "metadata": {"user_id": f"user_a_account_b_session_{CONVERSATION}"},
    "messages": [{"role": "user", "content": [{"type": "text", "text": "hallo"}]}],
}


def ok_upstream(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})


@dataclass
class Run:
    status: int
    body: bytes
    sent: list[httpx.Request]
    entries: list[dict]


def entries(audit_dir: Path) -> list[dict]:
    return [
        json.loads(line)
        for path in sorted(audit_dir.glob("audit-*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


async def send(
    gateway: Any,
    tmp_path: Path,
    body: dict | None,
    handler: Callable[[httpx.Request], httpx.Response] = ok_upstream,
    headers: dict[str, str] | None = None,
    method: str = "POST",
    path: str = "/v1/messages",
    **overrides: Any,
) -> Run:
    seen: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    audit_dir = tmp_path / "audit"
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir, **overrides)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = server.create_app(settings, gateway, client=client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as proxy:
        content = json.dumps(body).encode() if body is not None else None
        response = await proxy.request(method, path, content=content, headers=headers or {})
    return Run(response.status_code, response.content, seen, entries(audit_dir))
