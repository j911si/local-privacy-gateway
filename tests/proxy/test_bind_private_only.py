"""Only loopback and explicit private addresses may be bound without an opt-out (R2-05#1)."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.model import ConfigError
from privacy_gateway_proxy import cli, server
from privacy_gateway_proxy.settings import ProxySettings, is_private_address, load_settings

TOKEN = "tok-5d1e9a2c7b4f3e80-canary"
PUBLIC = [
    "0.0.0.0",
    "::",
    "[::]",
    "198.51.100.7",
    "8.8.8.8",
    "2001:db8::1",
    "[2001:db8::1]",
    "169.254.1.1",
    "fe80::1",
    "172.32.0.1",
    "100.128.0.1",
    "::ffff:10.0.0.1",
    "proxy.example.test",
    "",
]
PRIVATE = [
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.20",
    "100.64.0.1",
    "100.127.255.254",
    "fd12:3456:789a::1",
    "[fd12:3456:789a::1]",
    "fc00::1",
]
ENV_NAMES = (
    "PGW_PROXY_LISTEN",
    "PGW_PROXY_AUTH_TOKEN",
    "PGW_PROXY_AUTH_TOKEN_FILE",
    "PGW_PROXY_ALLOW_UNAUTHENTICATED",
    "PGW_PROXY_ALLOW_PUBLIC_BIND",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("host", PUBLIC)
def test_a_wildcard_or_public_bind_with_a_token_is_refused(host: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_settings(env={"PGW_PROXY_AUTH_TOKEN": TOKEN}, listen_host=host)

    assert "PGW_PROXY_ALLOW_PUBLIC_BIND" in str(caught.value)
    assert "TLS" in str(caught.value)


@pytest.mark.parametrize("listen", ["0.0.0.0:8787", "[::]:8787", ":::8787", "203.0.113.5:8787"])
def test_a_wildcard_listen_env_with_a_token_is_refused(listen: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_LISTEN": listen, "PGW_PROXY_AUTH_TOKEN": TOKEN})


@pytest.mark.parametrize("host", PUBLIC)
def test_the_unauthenticated_opt_out_does_not_open_a_public_bind(host: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_ALLOW_UNAUTHENTICATED": "1"}, listen_host=host)


@pytest.mark.parametrize("host", PRIVATE)
def test_a_private_bind_with_a_token_is_allowed(host: str) -> None:
    assert load_settings(env={"PGW_PROXY_AUTH_TOKEN": TOKEN}, listen_host=host).listen_host == host


@pytest.mark.parametrize("host", PRIVATE)
def test_a_private_bind_still_needs_a_token(host: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={}, listen_host=host)


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_the_explicit_opt_out_allows_a_public_bind_with_a_token(value: str) -> None:
    settings = load_settings(
        env={
            "PGW_PROXY_ALLOW_PUBLIC_BIND": value,
            "PGW_PROXY_AUTH_TOKEN": TOKEN,
            "PGW_PROXY_LISTEN": "0.0.0.0:8787",
        }
    )

    assert settings.allow_public_bind is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_anything_but_a_truthy_public_opt_out_keeps_the_refusal(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(
            env={
                "PGW_PROXY_ALLOW_PUBLIC_BIND": value,
                "PGW_PROXY_AUTH_TOKEN": TOKEN,
                "PGW_PROXY_LISTEN": "0.0.0.0:8787",
            }
        )


def test_the_public_opt_out_still_needs_a_token() -> None:
    with pytest.raises(ConfigError) as caught:
        load_settings(env={"PGW_PROXY_ALLOW_PUBLIC_BIND": "1", "PGW_PROXY_LISTEN": "0.0.0.0:8787"})

    assert "auth token" in str(caught.value)


def test_the_public_opt_out_is_off_by_default() -> None:
    assert ProxySettings().allow_public_bind is False
    assert load_settings(env={}).allow_public_bind is False


@pytest.mark.parametrize("host", PRIVATE)
def test_private_addresses(host: str) -> None:
    assert is_private_address(host)


@pytest.mark.parametrize("host", PUBLIC)
def test_not_private_addresses(host: str) -> None:
    assert not is_private_address(host)


def test_serve_refuses_a_wildcard_bind_with_a_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    started: list[dict] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.append(kw))
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_PROXY_AUTH_TOKEN", TOKEN)

    assert cli.main(["serve", "--listen", "0.0.0.0:8787"]) == cli.EXIT_ERROR
    assert started == []
    assert "PGW_PROXY_ALLOW_PUBLIC_BIND" in capsys.readouterr().err


def test_serve_with_the_public_opt_out_warns_about_missing_tls(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    started: list[dict] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.append(kw))
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_PROXY_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("PGW_PROXY_ALLOW_PUBLIC_BIND", "1")

    with caplog.at_level(logging.WARNING):
        assert cli.main(["serve", "--listen", "0.0.0.0:8787"]) == cli.EXIT_OK

    assert started and started[0]["host"] == "0.0.0.0"
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("PGW_PROXY_ALLOW_PUBLIC_BIND" in text and "TLS" in text for text in warnings)


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "198.51.100.7"])
def test_create_app_refuses_a_public_bind_with_a_token(
    host: str, gateway: Gateway, tmp_path
) -> None:
    settings = ProxySettings(listen_host=host, auth_token=TOKEN, audit_dir=tmp_path)

    with pytest.raises(ConfigError):
        server.create_app(settings, gateway, client=httpx.AsyncClient())
