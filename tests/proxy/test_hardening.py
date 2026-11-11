"""Path normalization, the allowlist for requests with content, the auth token, header filter."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
TOKEN = "tok-3f9c1d7a5b2e4c68-canary"
CONVERSATION = "0b1c2d3e-1111-2222-3333-444444444444"
MESSAGE = {
    "model": "claude-x",
    "max_tokens": 16,
    "metadata": {"user_id": f"user_a_account_b_session_{CONVERSATION}"},
    "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
}
MESSAGE_BYTES = json.dumps(MESSAGE).encode()


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


class Proxy:
    """The app under test plus the upstream requests it produced."""

    def __init__(self, gateway: Gateway, audit_dir: Path, **overrides: Any) -> None:
        self.seen: list[httpx.Request] = []
        self.audit_dir = audit_dir
        settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir, **overrides)
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(self._handler))
        self.app = server.create_app(settings, gateway, client=upstream)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    async def call(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        """Drive the ASGI app with an exact raw path, which httpx would normalize."""
        pairs = {"host": "127.0.0.1:8787", "content-type": "application/json"}
        pairs.update(headers or {})
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": unquote(raw_path),
            "raw_path": raw_path.encode("ascii"),
            "root_path": "",
            "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in pairs.items()],
            "server": ("127.0.0.1", 8787),
            "client": ("127.0.0.1", 50000),
        }
        sent: list[dict] = []

        delivered: list[bool] = []

        async def receive() -> dict:
            if delivered:
                await asyncio.Event().wait()
            delivered.append(True)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict) -> None:
            sent.append(message)

        await self.app(scope, receive, send)
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, data

    def log_text(self) -> str:
        return "".join(p.read_text(encoding="utf-8") for p in self.audit_dir.glob("audit-*.jsonl"))

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in self.log_text().splitlines()]


@pytest.fixture
def make_proxy(gateway: Gateway, tmp_path: Path) -> Callable[..., Proxy]:
    def factory(**overrides: Any) -> Proxy:
        return Proxy(gateway, tmp_path / "state" / "audit", **overrides)

    return factory


def error_type(data: bytes) -> str:
    return json.loads(data)["error"]["type"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_path",
    [
        "/v1/./messages",
        "/v1/x/../messages",
        "/v1//messages",
        "/v1/%6Dessages",
        "/v1/%2e/messages",
        "/v1/messages%2Fcount_tokens",
        "/v1/%2E%2E/v1/messages",
    ],
)
async def test_non_normal_paths_are_rejected_without_upstream(
    make_proxy: Callable[..., Proxy], raw_path: str
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call("POST", raw_path, MESSAGE_BYTES)

    assert status == 400
    assert error_type(data) == "privacy_gateway_rejected"
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_a_non_normal_get_path_is_rejected_too(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("GET", "/v1/x/../models")

    assert status == 400
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_the_normal_messages_path_still_works(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("POST", "/v1/messages", MESSAGE_BYTES)

    assert status == 200
    assert str(proxy.seen[0].url) == f"{UPSTREAM}/v1/messages"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/files"),
        ("POST", "/v1/complete"),
        ("PUT", "/v1/messages"),
        ("PATCH", "/v1/files/file_1"),
        ("DELETE", "/v1/messages/x"),
    ],
)
async def test_content_methods_outside_the_allowlist_get_422(
    make_proxy: Callable[..., Proxy], method: str, path: str
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call(method, path, b'{"x": 1}')

    assert status == 422
    assert error_type(data) == "privacy_gateway_rejected"
    assert proxy.seen == []
    (entry,) = proxy.entries()
    assert entry["event"] == "proxy_request"
    assert entry["path"] == path


@pytest.mark.asyncio
async def test_a_configured_passthrough_path_is_forwarded(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(passthrough_paths=("/v1/files",))

    status, _ = await proxy.call("POST", "/v1/files", b"raw-bytes")

    assert status == 200
    assert proxy.seen[0].content == b"raw-bytes"
    assert str(proxy.seen[0].url) == f"{UPSTREAM}/v1/files"
    other, _ = await proxy.call("DELETE", "/v1/files/f1")
    assert other == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/v1/models"), ("HEAD", "/api/hello"), ("OPTIONS", "/v1/messages")],
)
async def test_bodyless_reads_are_still_forwarded(
    make_proxy: Callable[..., Proxy], method: str, path: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call(method, path)

    assert status == 200
    assert len(proxy.seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_a_read_with_a_body_is_rejected(
    make_proxy: Callable[..., Proxy], method: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call(method, "/v1/models", b'{"smuggled": true}')

    assert status == 422
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_without_a_token_nothing_is_demanded(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("GET", "/v1/models")

    assert status == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{}, {"x-pgw-auth": "wrong"}, {"x-pgw-auth": TOKEN + "x"}])
async def test_a_missing_or_wrong_token_is_401(
    make_proxy: Callable[..., Proxy], headers: dict[str, str]
) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    for method, path, body in [
        ("POST", "/v1/messages", MESSAGE_BYTES),
        ("GET", "/v1/models", b""),
    ]:
        status, data = await proxy.call(method, path, body, headers)
        assert status == 401
        assert error_type(data) == "privacy_gateway_unauthorized"
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_the_right_token_passes_and_is_not_forwarded(
    make_proxy: Callable[..., Proxy], tmp_path: Path
) -> None:
    debug_dir = tmp_path / "dump"
    proxy = make_proxy(auth_token=TOKEN, debug_dir=debug_dir)
    headers = {"x-pgw-auth": TOKEN, "x-pgw-session": "abc", "x-api-key": "sk-test"}

    status, _ = await proxy.call("POST", "/v1/messages", MESSAGE_BYTES, headers)
    read_status, _ = await proxy.call("GET", "/v1/models", b"", headers)

    assert (status, read_status) == (200, 200)
    assert len(proxy.seen) == 2
    for request in proxy.seen:
        assert "x-pgw-auth" not in request.headers
        assert "x-pgw-session" not in request.headers
        assert request.headers["x-api-key"] == "sk-test"
        assert TOKEN not in str(request.headers)
    assert TOKEN not in proxy.log_text()
    dumps = list(debug_dir.glob("*.json"))
    assert dumps
    assert all(TOKEN not in p.read_text(encoding="utf-8") for p in dumps)


@pytest.mark.asyncio
async def test_a_rejected_request_does_not_log_the_token(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    await proxy.call("POST", "/v1/files", b"{}", {"x-pgw-auth": TOKEN})

    assert TOKEN not in proxy.log_text()


@pytest.mark.asyncio
async def test_health_needs_no_token(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    status, data = await proxy.call("GET", "/health")

    assert status == 200
    assert json.loads(data) == {"status": "ok"}


@pytest.mark.asyncio
async def test_the_session_header_is_not_forwarded_without_a_token(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(session_strategy="header")

    await proxy.call("POST", "/v1/messages", MESSAGE_BYTES, {"x-pgw-session": "abc"})

    assert "x-pgw-session" not in proxy.seen[0].headers
