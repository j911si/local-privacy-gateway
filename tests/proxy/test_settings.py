import re
from pathlib import Path

import pytest

from privacy_gateway.model import ConfigError
from privacy_gateway_proxy.settings import ProxySettings, load_settings, parse_listen


def test_defaults_without_env() -> None:
    settings = load_settings(env={})

    assert settings == ProxySettings()
    assert settings.listen_host == "127.0.0.1"
    assert settings.listen_port == 8787
    assert settings.upstream_base_url == "https://api.anthropic.com"
    assert settings.session_strategy == "metadata"
    assert settings.header_name == "x-pgw-session"
    assert settings.config_path is None
    assert settings.debug_dir is None
    assert settings.transform_system is True
    assert settings.placeholder_notice is True
    assert settings.debug_originals is False


def test_default_session_key_is_random_per_process() -> None:
    settings = load_settings(env={})

    assert settings.default_session_key != "default"
    assert re.fullmatch(r"[0-9a-f]{16}", settings.default_session_key)
    assert load_settings(env={}).default_session_key == settings.default_session_key


def test_an_explicit_default_session_key_wins() -> None:
    settings = load_settings(
        env={"PGW_PROXY_SESSION_STRATEGY": "single"}, default_session_key="fixed"
    )

    assert settings.default_session_key == "fixed"


@pytest.mark.parametrize(
    "value",
    ["https://api.anthropic.com", "http://127.0.0.1:1234", "http://localhost:1234"],
)
def test_allowed_upstream_urls(value: str) -> None:
    assert load_settings(env={"PGW_PROXY_UPSTREAM": value}).upstream_base_url == value


@pytest.mark.parametrize(
    "value",
    ["http://evil.test", "http://10.0.0.1:8080", "ftp://127.0.0.1", "http://127.0.0.1.evil.test"],
)
def test_rejected_upstream_urls(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_UPSTREAM": value})


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_debug_originals_is_enabled_by_truthy_env(value: str) -> None:
    assert load_settings(env={"PGW_PROXY_DEBUG_ORIGINALS": value}).debug_originals is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_debug_originals_stays_disabled_otherwise(value: str) -> None:
    assert load_settings(env={"PGW_PROXY_DEBUG_ORIGINALS": value}).debug_originals is False


def test_env_values_are_applied() -> None:
    settings = load_settings(
        env={
            "PGW_PROXY_LISTEN": "0.0.0.0:9000",
            "PGW_PROXY_UPSTREAM": "http://localhost:1234/",
            "PGW_PROXY_SESSION_STRATEGY": "header",
            "PGW_CONFIG": "/tmp/pgw.yaml",
            "PGW_PROXY_DEBUG_DIR": "/tmp/pgw-debug",
        }
    )

    assert settings.listen_host == "0.0.0.0"
    assert settings.listen_port == 9000
    assert settings.upstream_base_url == "http://localhost:1234"
    assert settings.session_strategy == "header"
    assert settings.config_path == Path("/tmp/pgw.yaml")
    assert settings.debug_dir == Path("/tmp/pgw-debug")


def test_overrides_beat_env_and_none_is_ignored() -> None:
    settings = load_settings(
        env={"PGW_PROXY_LISTEN": "0.0.0.0:9000", "PGW_PROXY_UPSTREAM": "http://localhost:1"},
        listen_port=7777,
        upstream_base_url=None,
    )

    assert settings.listen_host == "0.0.0.0"
    assert settings.listen_port == 7777
    assert settings.upstream_base_url == "http://localhost:1"


def test_unknown_override_is_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(env={}, listen="127.0.0.1:1")


@pytest.mark.parametrize("value", ["127.0.0.1", "127.0.0.1:abc", "127.0.0.1:0", ":8787", ""])
def test_bad_listen_string(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_LISTEN": value})


def test_parse_listen_returns_host_and_port() -> None:
    assert parse_listen("127.0.0.1:8787") == ("127.0.0.1", 8787)


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off", " Off "])
def test_transform_system_is_disabled_by_falsy_env(value: str) -> None:
    settings = load_settings(env={"PGW_PROXY_TRANSFORM_SYSTEM": value})

    assert settings.transform_system is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", ""])
def test_transform_system_stays_enabled_otherwise(value: str) -> None:
    settings = load_settings(env={"PGW_PROXY_TRANSFORM_SYSTEM": value})

    assert settings.transform_system is True


def test_transform_system_override_beats_env() -> None:
    settings = load_settings(env={"PGW_PROXY_TRANSFORM_SYSTEM": "0"}, transform_system=True)

    assert settings.transform_system is True


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off", " Off "])
def test_placeholder_notice_is_disabled_by_falsy_env(value: str) -> None:
    settings = load_settings(env={"PGW_PROXY_PLACEHOLDER_NOTICE": value})

    assert settings.placeholder_notice is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", ""])
def test_placeholder_notice_stays_enabled_otherwise(value: str) -> None:
    settings = load_settings(env={"PGW_PROXY_PLACEHOLDER_NOTICE": value})

    assert settings.placeholder_notice is True


def test_placeholder_notice_override_beats_env() -> None:
    settings = load_settings(env={"PGW_PROXY_PLACEHOLDER_NOTICE": "0"}, placeholder_notice=True)

    assert settings.placeholder_notice is True


def test_unknown_session_strategy_is_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_SESSION_STRATEGY": "magic"})


def test_env_defaults_to_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGW_PROXY_LISTEN", "127.0.0.1:1234")

    assert load_settings().listen_port == 1234
