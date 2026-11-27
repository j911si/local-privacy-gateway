"""A request without a session key gets a session of its own, not a shared one (R2-05#2)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

from ._send import IBAN, UPSTREAM

TOKEN_RE = re.compile(r"<IBAN_\d{3}>")
CC_A = f"user_{'0' * 64}_account__session_0b1c2d3e-5f6a-4b7c-8d9e-0a1b2c3d4e5f"
CC_B = f"user_{'0' * 64}_account__session_1c2d3e4f-6a7b-4c8d-9e0f-1a2b3c4d5e6f"


def _body(text: str, user_id: str | None = None, stream: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": "claude-x",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": text}],
    }
    if user_id is not None:
        body["metadata"] = {"user_id": user_id}
    if stream:
        body["stream"] = True
    return body


def _sse(text: str) -> bytes:
    events = [
        ("message_start", {"type": "message_start", "message": {"id": "m", "content": []}}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    ]
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()


class Echo:
    """Upstream that answers with the first IBAN token it ever saw."""

    def __init__(self) -> None:
        self.token: str | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        match = TOKEN_RE.search(request.content.decode())
        if match and self.token is None:
            self.token = match.group(0)
        text = f"Konto {self.token}"
        if json.loads(request.content).get("stream") is True:
            return httpx.Response(
                200, content=_sse(text), headers={"content-type": "text/event-stream"}
            )
        return httpx.Response(200, json={"content": [{"type": "text", "text": text}]})


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


async def _run(
    gateway: Gateway,
    tmp_path: Path,
    bodies: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
    **overrides: Any,
) -> list[httpx.Response]:
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=tmp_path / "audit", **overrides)
    client = httpx.AsyncClient(transport=httpx.MockTransport(Echo()))
    app = server.create_app(settings, gateway, client=client)
    responses = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as proxy:
        for body in bodies:
            responses.append(
                await proxy.post("/v1/messages", content=json.dumps(body), headers=headers or {})
            )
    return responses


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("second_user_id", [None, "not-a-claude-code-id"])
async def test_clients_without_a_session_key_are_isolated(
    gateway: Gateway, tmp_path: Path, stream: bool, second_user_id: str | None
) -> None:
    one, two = await _run(
        gateway,
        tmp_path,
        [
            _body(f"Meine IBAN ist {IBAN}", stream=stream),
            _body("Welches Konto?", second_user_id, stream=stream),
        ],
    )

    assert one.status_code == 200 and two.status_code == 200
    assert IBAN in one.text
    assert IBAN not in two.text
    assert TOKEN_RE.search(two.text)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_a_request_session_restores_its_own_answer_and_is_purged(
    gateway: Gateway, tmp_path: Path, stream: bool
) -> None:
    before = len(gateway.vault.list_sessions())

    (response,) = await _run(gateway, tmp_path, [_body(f"Meine IBAN ist {IBAN}", stream=stream)])

    assert response.status_code == 200
    assert IBAN in response.text
    assert len(gateway.vault.list_sessions()) == before


@pytest.mark.asyncio
async def test_a_blocked_request_session_is_purged(gateway: Gateway, tmp_path: Path) -> None:
    before = len(gateway.vault.list_sessions())
    body = {**_body(f"Meine IBAN ist {IBAN}"), "x_extra": {"note": f"IBAN {IBAN}"}}

    (response,) = await _run(gateway, tmp_path, [body])

    assert response.status_code == 422
    assert len(gateway.vault.list_sessions()) == before


@pytest.mark.asyncio
async def test_a_get_without_a_session_key_leaves_no_session(
    gateway: Gateway, tmp_path: Path
) -> None:
    before = len(gateway.vault.list_sessions())
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=tmp_path / "audit")
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    app = server.create_app(settings, gateway, client=client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as proxy:
        response = await proxy.get("/v1/models")

    assert response.status_code == 200
    assert len(gateway.vault.list_sessions()) == before


@pytest.mark.asyncio
async def test_claude_code_keeps_one_session_per_conversation(
    gateway: Gateway, tmp_path: Path
) -> None:
    one, same, other = await _run(
        gateway,
        tmp_path,
        [_body(f"Meine IBAN ist {IBAN}", CC_A), _body("Welches?", CC_A), _body("Welches?", CC_B)],
    )

    assert IBAN in one.text
    assert IBAN in same.text
    assert IBAN not in other.text


@pytest.mark.asyncio
async def test_the_session_header_keeps_a_shared_session(gateway: Gateway, tmp_path: Path) -> None:
    one, two = await _run(
        gateway,
        tmp_path,
        [_body(f"Meine IBAN ist {IBAN}"), _body("Welches Konto?")],
        headers={"x-pgw-session": "team-a"},
    )

    assert IBAN in one.text
    assert IBAN in two.text


@pytest.mark.asyncio
async def test_the_single_strategy_keeps_its_one_session(gateway: Gateway, tmp_path: Path) -> None:
    one, two = await _run(
        gateway,
        tmp_path,
        [_body(f"Meine IBAN ist {IBAN}"), _body("Welches Konto?")],
        session_strategy="single",
    )

    assert IBAN in one.text
    assert IBAN in two.text
