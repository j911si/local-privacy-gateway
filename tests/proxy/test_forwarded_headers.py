"""Forwarded header values are scanned and proxy-irrelevant headers are dropped (R2-05#3)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway

from ._send import BASE, IBAN, MAIL, send

DROPPED = {
    "cookie": "internal_sso=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlcmlrYSJ9.c2lnbmF0dXJl",
    "x-forwarded-user": MAIL,
    "x-forwarded-for": "203.0.113.9",
    "x-forwarded-proto": "https",
    "forwarded": "for=203.0.113.9;proto=https",
    "x-real-ip": "203.0.113.9",
    "via": "1.1 gateway.internal.test",
}
# Header set as Claude Code sends it (values synthetic, credentials fake).
CLAUDE_CODE = {
    "accept": "application/json",
    "anthropic-beta": (
        "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,"
        "fine-grained-tool-streaming-2025-05-14,context-management-2025-06-27"
    ),
    "anthropic-dangerous-direct-browser-access": "true",
    "anthropic-version": "2023-06-01",
    "authorization": "Bearer sk-ant-oat01-" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7" * 3,
    "x-api-key": "sk-ant-api03-" + "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1" * 3,
    "content-type": "application/json",
    "user-agent": "claude-cli/2.1.322 (external, cli)",
    "x-app": "cli",
    "x-claude-code-session-id": "0b1c2d3e-1111-2222-3333-444444444444",
    "x-stainless-arch": "x64",
    "x-stainless-helper-method": "stream",
    "x-stainless-lang": "js",
    "x-stainless-os": "Linux",
    "x-stainless-package-version": "0.60.0",
    "x-stainless-retry-count": "0",
    "x-stainless-runtime": "node",
    "x-stainless-runtime-version": "v24.3.0",
    "x-stainless-timeout": "600",
    "anthropic-client-sha": "4f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
    "x-client-request-id": "1a2b3c4d-1111-2222-3333-444444444444",
}
REQUESTS = [
    ("POST", "/v1/messages", BASE),
    ("POST", "/v1/messages", {**BASE, "stream": True}),
    ("POST", "/v1/messages/count_tokens", BASE),
    ("GET", "/v1/models", None),
]


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), REQUESTS)
async def test_proxy_irrelevant_headers_are_not_forwarded(
    gateway: Gateway, tmp_path: Path, method: str, path: str, body: dict | None
) -> None:
    run = await send(gateway, tmp_path, body, headers=DROPPED, method=method, path=path)

    assert run.status == 200
    (sent,) = run.sent
    assert not any(name in sent.headers for name in DROPPED)


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), REQUESTS)
@pytest.mark.parametrize(("name", "value"), [("x-user-mail", MAIL), ("x-account", f"IBAN {IBAN}")])
async def test_a_sensitive_header_value_blocks(
    gateway: Gateway,
    tmp_path: Path,
    method: str,
    path: str,
    body: dict | None,
    name: str,
    value: str,
) -> None:
    run = await send(gateway, tmp_path, body, headers={name: value}, method=method, path=path)

    assert run.status == 422
    assert run.sent == []
    assert json.loads(run.body)["error"]["type"] == "privacy_gateway_leak"
    (entry,) = run.entries
    assert entry["verdict"] == "blocked"
    findings = entry["outgoing"]["rescan"]["findings"]
    assert findings and all(item["path"].startswith("headers[") for item in findings)
    log = json.dumps(run.entries)
    assert value not in log and MAIL not in log and IBAN not in log and name not in log


@pytest.mark.asyncio
async def test_with_allow_a_header_is_forwarded(gateway: Gateway, tmp_path: Path) -> None:
    run = await send(
        gateway, tmp_path, BASE, headers={"x-user-mail": MAIL}, unchecked_fields="allow"
    )

    assert run.status == 200
    assert run.sent[0].headers["x-user-mail"] == MAIL


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), REQUESTS)
async def test_claude_code_headers_pass_unchanged(
    gateway: Gateway, tmp_path: Path, method: str, path: str, body: dict | None
) -> None:
    run = await send(gateway, tmp_path, body, headers=CLAUDE_CODE, method=method, path=path)

    assert run.status == 200, run.body
    (sent,) = run.sent
    for name, value in CLAUDE_CODE.items():
        assert sent.headers[name] == value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "Bearer sk-ant-oat01-" + "Q" * 80,
        "Basic ZXJpa2E6Z2VoZWltMTIz",
        f"Bearer {MAIL}",
    ],
)
async def test_the_upstream_credentials_are_not_scanned(
    gateway: Gateway, tmp_path: Path, value: str
) -> None:
    headers = {"authorization": value, "x-api-key": "sk-ant-api03-" + "x" * 90}

    run = await send(gateway, tmp_path, BASE, headers=headers)

    assert run.status == 200
    assert run.sent[0].headers["authorization"] == value


@pytest.mark.asyncio
async def test_a_card_like_uuid_in_another_header_still_blocks(
    gateway: Gateway, tmp_path: Path
) -> None:
    run = await send(
        gateway, tmp_path, BASE, headers={"x-request-ref": "0b1c2d3e-1111-2222-3333-444444444444"}
    )

    assert run.status == 422
    assert run.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["x-claude-code-session-id", "x-client-request-id"])
async def test_the_id_header_exemption_is_only_for_a_uuid(
    gateway: Gateway, tmp_path: Path, name: str
) -> None:
    run = await send(gateway, tmp_path, BASE, headers={name: MAIL})

    assert run.status == 422
    assert run.sent == []
