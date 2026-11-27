"""Values in paths and queries are scanned, and no log line carries a path segment or error text."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

CARD = "4111111111111111"
MAIL = "erika.beispiel@firma-test.de"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


async def _call(gateway: Gateway, tmp_path: Path, method: str, url: str, upstream=None):
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return upstream(request) if upstream else httpx.Response(200, json={})

    settings = ProxySettings(upstream_base_url="https://upstream.test", audit_dir=tmp_path / "a")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(settings, gateway, client=client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as proxy:
        body = b'{"model":"x","max_tokens":1,"messages":[]}' if method == "POST" else None
        response = await proxy.request(method, url, content=body)
    audit = "".join(p.read_text() for p in (tmp_path / "a").glob("*.jsonl"))
    return response.status_code, sent, audit


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url", [f"/v1/models/{CARD}", f"/v1/models?after_id={CARD}", f"/v1/files/x?before_id={CARD}"]
)
async def test_card_in_path_or_query_is_not_forwarded(
    gateway: Gateway, tmp_path: Path, url: str
) -> None:
    status, sent, _ = await _call(gateway, tmp_path, "GET", url)
    assert status == 400
    assert not sent


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        f"/v1/messages?beta={CARD}",
        f"/v1/skills/skill_01AbCdEfGhIjKlMnOpQrStUv/versions/{CARD}",
        f"/v1/files/versions/{CARD}",
    ],
)
async def test_card_in_a_transformed_query_or_after_versions_is_not_forwarded(
    gateway: Gateway, tmp_path: Path, url: str
) -> None:
    method = "POST" if url.startswith("/v1/messages") else "GET"
    status, sent, _ = await _call(gateway, tmp_path, method, url)
    assert status == 400
    assert not sent


@pytest.mark.asyncio
async def test_a_numeric_skill_version_is_still_forwarded(gateway: Gateway, tmp_path: Path) -> None:
    url = "/v1/skills/skill_01AbCdEfGhIjKlMnOpQrStUv/versions/1759178010641129"
    status, sent, _ = await _call(gateway, tmp_path, "GET", url)
    assert status == 200
    assert len(sent) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [f"/v1/{MAIL}/x/y", f"/{MAIL}", f"/v1/files/{MAIL}"])
async def test_a_rejected_path_leaves_no_value_in_the_audit(
    gateway: Gateway, tmp_path: Path, url: str
) -> None:
    status, sent, audit = await _call(gateway, tmp_path, "GET", url)
    assert status == 400
    assert not sent
    assert audit
    assert MAIL not in audit
    assert MAIL not in server.short_path(url)


@pytest.mark.asyncio
async def test_upstream_error_text_stays_out_of_the_log(
    gateway: Gateway, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        error = {"type": "authentication_error", "message": f"Rejected account {MAIL}"}
        return httpx.Response(401, json={"type": "error", "error": error})

    with caplog.at_level(logging.WARNING, logger="privacy_gateway_proxy"):
        status, _, _ = await _call(gateway, tmp_path, "POST", "/v1/messages", upstream)
    assert status == 401
    assert "authentication_error" in caplog.text
    assert MAIL not in caplog.text
    assert "Rejected account" not in caplog.text


def test_error_type_ignores_unexpected_bodies() -> None:
    assert server._error_type(b"not json") == "-"
    assert server._error_type(json.dumps({"error": {"type": MAIL}}).encode()) == "-"
    unknown = {"error": {"message": "x" * 500, "type": "sommerregen_im_projektarchiv"}}
    assert server._error_type(json.dumps(unknown).encode()) == "-"
    assert server._error_type(b"[" * 5000 + b"]" * 5000) == "-"
    assert server._error_type(json.dumps({"error": {"type": "rate_limit_error"}}).encode()) == (
        "rate_limit_error"
    )


@pytest.mark.parametrize(
    ("path", "logged"),
    [("/v1/geheimes-kundenprojekt", "/v1/…"), ("/v1/files/x/y", "/v1/files/…")],
)
def test_short_path_shows_only_route_words(path: str, logged: str) -> None:
    assert server.short_path(path) == logged


@pytest.mark.asyncio
async def test_a_deeply_nested_upstream_error_keeps_its_status(
    gateway: Gateway, tmp_path: Path
) -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"[" * 5000 + b"]" * 5000)

    status, _, _ = await _call(gateway, tmp_path, "POST", "/v1/messages", upstream)
    assert status == 429
