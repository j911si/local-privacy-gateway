"""A non-loopback bind needs an auth token unless the operator opts out explicitly."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.model import ConfigError
from privacy_gateway_proxy import cli, server
from privacy_gateway_proxy.settings import ProxySettings, load_settings

UPSTREAM = "https://upstream.test"
TOKEN = "tok-5d1e9a2c7b4f3e80-canary"
NON_LOOPBACK = ["0.0.0.0", "::", "[::]", "100.101.102.103", "192.168.1.20", "198.51.100.7"]
LOOPBACK = ["127.0.0.1", "localhost", "[::1]", "::1"]
ENV_NAMES = (
    "PGW_PROXY_LISTEN",
    "PGW_PROXY_AUTH_TOKEN",
    "PGW_PROXY_AUTH_TOKEN_FILE",
    "PGW_PROXY_ALLOW_UNAUTHENTICATED",
)
MESSAGE = {
    "model": "claude-x",
    "max_tokens": 16,
    "metadata": {"user_id": "user_a_account_b_session_0b1c2d3e-1111-2222-3333-444444444444"},
    "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _token_file(tmp_path: Path) -> Path:
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_a_non_loopback_bind_without_a_token_is_refused(host: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_settings(env={}, listen_host=host)

    assert "PGW_PROXY_AUTH_TOKEN_FILE" in str(caught.value)
    assert "PGW_PROXY_ALLOW_UNAUTHENTICATED" in str(caught.value)


@pytest.mark.parametrize("listen", ["0.0.0.0:8787", "[::]:8787", ":::8787", "100.64.0.1:8787"])
def test_a_non_loopback_listen_env_without_a_token_is_refused(listen: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_LISTEN": listen})


@pytest.mark.parametrize("host", LOOPBACK)
def test_a_loopback_bind_needs_no_token(host: str) -> None:
    assert load_settings(env={}, listen_host=host).auth_token == ""


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_a_non_loopback_bind_with_a_token_is_allowed(host: str, tmp_path: Path) -> None:
    by_env = load_settings(env={"PGW_PROXY_AUTH_TOKEN": TOKEN}, listen_host=host)
    by_file = load_settings(
        env={"PGW_PROXY_AUTH_TOKEN_FILE": str(_token_file(tmp_path))}, listen_host=host
    )

    assert by_env.auth_token == TOKEN
    assert by_file.auth_token == TOKEN


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_the_explicit_opt_out_allows_an_unauthenticated_bind(value: str) -> None:
    settings = load_settings(
        env={"PGW_PROXY_ALLOW_UNAUTHENTICATED": value, "PGW_PROXY_LISTEN": "0.0.0.0:8787"}
    )

    assert settings.allow_unauthenticated is True
    assert settings.auth_token == ""


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_anything_but_a_truthy_opt_out_keeps_the_refusal(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(
            env={"PGW_PROXY_ALLOW_UNAUTHENTICATED": value, "PGW_PROXY_LISTEN": "0.0.0.0:8787"}
        )


def test_the_opt_out_is_off_by_default() -> None:
    assert ProxySettings().allow_unauthenticated is False
    assert load_settings(env={}).allow_unauthenticated is False


@pytest.mark.parametrize("listen", ["0.0.0.0:8787", "[::]:8787", "100.101.102.103:8787"])
def test_serve_refuses_to_start_a_non_loopback_bind_without_a_token(
    listen: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    started: list[dict] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.append(kw))

    code = cli.main(["serve", "--listen", listen])

    assert code == cli.EXIT_ERROR
    assert started == []
    assert "auth token" in capsys.readouterr().err


def test_serve_starts_a_non_loopback_bind_with_a_token_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[dict] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.append(kw))
    monkeypatch.setenv("PGW_PROXY_AUTH_TOKEN_FILE", str(_token_file(tmp_path)))

    assert cli.main(["serve", "--listen", "100.101.102.103:8787"]) == cli.EXIT_OK
    assert started == [{"host": "100.101.102.103", "port": 8787, "log_level": "info"}]


def test_serve_with_the_opt_out_starts_and_warns_loudly(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    started: list[dict] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.append(kw))
    monkeypatch.setenv("PGW_PROXY_ALLOW_UNAUTHENTICATED", "1")

    with caplog.at_level(logging.WARNING):
        assert cli.main(["serve", "--listen", "0.0.0.0:8787"]) == cli.EXIT_OK

    assert started and started[0]["host"] == "0.0.0.0"
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("PGW_PROXY_ALLOW_UNAUTHENTICATED" in text for text in warnings)
    assert any("UNAUTHENTICATED" in text and "restore" in text for text in warnings)


def test_install_launchd_refuses_a_non_loopback_bind_without_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed: list[object] = []
    monkeypatch.setattr(cli.launchd, "install", lambda *args: installed.append(args))
    monkeypatch.setenv("PGW_PROXY_LISTEN", "0.0.0.0:8787")

    code = cli.main(["install-launchd", "--log-dir", str(tmp_path)])

    assert code == cli.EXIT_ERROR
    assert installed == []


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_create_app_refuses_a_non_loopback_bind_without_a_token(
    host: str, gateway: Gateway, tmp_path: Path
) -> None:
    settings = ProxySettings(upstream_base_url=UPSTREAM, listen_host=host, audit_dir=tmp_path)

    with pytest.raises(ConfigError):
        server.create_app(settings, gateway, client=httpx.AsyncClient())


def _app(gateway: Gateway, tmp_path: Path, seen: list[httpx.Request]):
    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    settings = ProxySettings(
        upstream_base_url=UPSTREAM,
        listen_host="0.0.0.0",
        auth_token=TOKEN,
        audit_dir=tmp_path,
        passthrough_paths=("/v1/files",),
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    return server.create_app(settings, gateway, client=client)


REQUESTS = [
    ("POST", "/v1/messages", MESSAGE),
    ("POST", "/v1/messages", {**MESSAGE, "stream": True}),
    ("POST", "/v1/messages/count_tokens", MESSAGE),
    ("GET", "/v1/models", None),
    ("POST", "/v1/files", {"name": "x"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), REQUESTS)
@pytest.mark.parametrize(
    "headers", [{}, {"x-pgw-auth": "wrong"}, {"x-pgw-auth": TOKEN[:-1] + "X"}]
)
async def test_every_data_endpoint_checks_the_token_on_a_non_loopback_bind(
    gateway: Gateway, tmp_path: Path, method: str, path: str, body: dict | None,
    headers: dict[str, str],
) -> None:
    seen: list[httpx.Request] = []
    transport = httpx.ASGITransport(app=_app(gateway, tmp_path, seen))
    async with httpx.AsyncClient(transport=transport, base_url="http://192.0.2.10:8787") as c:
        content = json.dumps(body).encode() if body is not None else None
        response = await c.request(method, path, content=content, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["type"] == "privacy_gateway_unauthorized"
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), REQUESTS)
async def test_the_right_token_is_accepted_on_a_non_loopback_bind(
    gateway: Gateway, tmp_path: Path, method: str, path: str, body: dict | None
) -> None:
    seen: list[httpx.Request] = []
    transport = httpx.ASGITransport(app=_app(gateway, tmp_path, seen))
    async with httpx.AsyncClient(transport=transport, base_url="http://192.0.2.10:8787") as c:
        content = json.dumps(body).encode() if body is not None else None
        response = await c.request(method, path, content=content, headers={"x-pgw-auth": TOKEN})

    assert response.status_code == 200
    assert len(seen) == 1
    assert "x-pgw-auth" not in seen[0].headers


@pytest.mark.asyncio
async def test_health_answers_without_a_token_and_carries_no_data(
    gateway: Gateway, tmp_path: Path
) -> None:
    seen: list[httpx.Request] = []
    transport = httpx.ASGITransport(app=_app(gateway, tmp_path, seen))
    async with httpx.AsyncClient(transport=transport, base_url="http://192.0.2.10:8787") as c:
        response = await c.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert seen == []
