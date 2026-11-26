"""Secrets in escaped JSON inside a tool_result never reach the upstream."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

SECRET = "Fake9secret7Value42xyz"
IBAN = "DE89370400440532013000"
SETTINGS = ProxySettings(upstream_base_url="https://upstream.test")
SESSION = "user_abc_account_def_session_0b1c2d3e-1a2b-4c3d-8e4f-5a6b7c8d9e0f"


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    with Gateway() as instance:
        yield instance


def tool_output(levels: int) -> str:
    text = json.dumps({"password": SECRET, "csrf_token": SECRET, "iban": IBAN, "user": "bob"})
    for _ in range(levels):
        text = json.dumps({"stdout": text})
    return text


def body(output: str) -> dict:
    return {
        "model": "claude-x",
        "max_tokens": 64,
        "metadata": {"user_id": SESSION},
        "messages": [
            {"role": "user", "content": "Lies die Datei."},
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {}}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": output}],
            },
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("levels", [1, 2, 3])
async def test_escaped_json_in_a_tool_result_is_cleaned(gateway: Gateway, levels: int) -> None:
    seen: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content)
        return httpx.Response(
            200, json={"id": "m", "content": [{"type": "text", "text": "ok"}]}
        )

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(SETTINGS, gateway, client=upstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        response = await client.post("/v1/messages", json=body(tool_output(levels)))

    assert response.status_code == 200
    (sent,) = seen
    text = sent.decode("utf-8")
    assert SECRET not in text
    assert IBAN not in text
    assert "bob" in text
