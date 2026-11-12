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


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1", "-0.5", "abc"])
def test_an_unusable_rescan_budget_is_an_error(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_RESCAN_BUDGET": value})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0.0, -1.0])
def test_an_unusable_rescan_budget_override_is_an_error(value: float) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={}, rescan_budget_s=value)


def test_a_finite_positive_rescan_budget_is_kept() -> None:
    assert load_settings(env={"PGW_PROXY_RESCAN_BUDGET": "2.5"}).rescan_budget_s == 2.5


def test_passthrough_paths_default_to_empty_and_parse_a_list() -> None:
    assert load_settings(env={}).passthrough_paths == ()
    parsed = load_settings(env={"PGW_PROXY_PASSTHROUGH_PATHS": "/v1/files, /v1/x ,"})
    assert parsed.passthrough_paths == ("/v1/files", "/v1/x")


@pytest.mark.parametrize("value", ["v1/files", "/v1/../files", "/v1//files", "/v1/%66iles"])
def test_a_passthrough_path_must_be_a_normal_absolute_path(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_PASSTHROUGH_PATHS": value})


def test_the_auth_token_comes_from_env_and_stays_out_of_repr() -> None:
    settings = load_settings(env={"PGW_PROXY_AUTH_TOKEN": "tok-canary-123"})

    assert settings.auth_token == "tok-canary-123"
    assert "tok-canary-123" not in repr(settings)
    assert load_settings(env={}).auth_token == ""


def _token_file(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "token"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_the_auth_token_file_is_read_and_stripped(tmp_path: Path) -> None:
    path = _token_file(tmp_path, "tok-from-file\n")

    assert load_settings(env={"PGW_PROXY_AUTH_TOKEN_FILE": str(path)}).auth_token == "tok-from-file"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
def test_an_open_token_file_is_an_error(tmp_path: Path, mode: int) -> None:
    path = _token_file(tmp_path, "tok-from-file\n", mode)

    with pytest.raises(ConfigError) as caught:
        load_settings(env={"PGW_PROXY_AUTH_TOKEN_FILE": str(path)})

    assert "tok-from-file" not in str(caught.value)


def test_a_missing_or_empty_token_file_is_an_error(tmp_path: Path) -> None:
    empty = _token_file(tmp_path, "\n")

    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_AUTH_TOKEN_FILE": str(tmp_path / "missing")})
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_AUTH_TOKEN_FILE": str(empty)})


def test_token_and_token_file_together_are_an_error(tmp_path: Path) -> None:
    path = _token_file(tmp_path, "a\n")

    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_AUTH_TOKEN": "b", "PGW_PROXY_AUTH_TOKEN_FILE": str(path)})
