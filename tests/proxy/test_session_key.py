import json

from privacy_gateway_proxy.session_key import is_valid_key, session_key_for
from privacy_gateway_proxy.settings import ProxySettings

UUID = "0b1c2d3e-1111-2222-3333-444444444444"
USER_ID = f"user_abc_account_def_session_{UUID}"
CLAUDE_CODE_SESSION = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
CLAUDE_CODE_USER_ID = json.dumps(
    {
        "device_id": "9f" * 32,
        "account_uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "session_id": CLAUDE_CODE_SESSION,
    }
)
SETTINGS = ProxySettings(default_session_key="default")


def test_metadata_strategy_uses_session_uuid() -> None:
    body = {"metadata": {"user_id": USER_ID}}

    assert session_key_for({}, body, SETTINGS) == UUID


def test_metadata_strategy_uses_json_session_id() -> None:
    body = {"metadata": {"user_id": CLAUDE_CODE_USER_ID}}

    assert session_key_for({}, body, SETTINGS) == CLAUDE_CODE_SESSION


def test_metadata_strategy_ignores_malformed_json_user_id() -> None:
    body = {"metadata": {"user_id": '{"device_id": "abc", "session_id"'}}

    assert session_key_for({}, body, SETTINGS) == "default"


def test_metadata_strategy_ignores_json_without_session_id() -> None:
    body = {"metadata": {"user_id": json.dumps({"device_id": "9f" * 32})}}

    assert session_key_for({}, body, SETTINGS) == "default"


def test_metadata_strategy_ignores_json_with_unusable_session_id() -> None:
    blank = {"metadata": {"user_id": json.dumps({"session_id": "  "})}}
    number = {"metadata": {"user_id": json.dumps({"session_id": 42})}}

    assert session_key_for({}, blank, SETTINGS) == "default"
    assert session_key_for({}, number, SETTINGS) == "default"


def test_metadata_strategy_falls_back_to_header() -> None:
    headers = {"X-PGW-Session": "team-a"}

    assert session_key_for(headers, {"metadata": {}}, SETTINGS) == "team-a"


def test_metadata_strategy_falls_back_to_default() -> None:
    assert session_key_for({}, None, SETTINGS) == "default"


def test_metadata_strategy_ignores_user_id_without_session() -> None:
    body = {"metadata": {"user_id": "user_abc_account_def"}}

    assert session_key_for({}, body, SETTINGS) == "default"


def test_metadata_strategy_ignores_non_string_user_id() -> None:
    body = {"metadata": {"user_id": 42}}

    assert session_key_for({}, body, SETTINGS) == "default"


def test_header_strategy_uses_header_only() -> None:
    settings = ProxySettings(session_strategy="header", default_session_key="default")
    body = {"metadata": {"user_id": USER_ID}}

    assert session_key_for({"x-pgw-session": "team-b"}, body, settings) == "team-b"
    assert session_key_for({}, body, settings) == "default"


def test_single_strategy_always_returns_default() -> None:
    settings = ProxySettings(session_strategy="single", default_session_key="only")
    body = {"metadata": {"user_id": USER_ID}}

    assert session_key_for({"x-pgw-session": "team-b"}, body, settings) == "only"


def test_blank_header_is_ignored() -> None:
    settings = ProxySettings(session_strategy="header", default_session_key="default")

    assert session_key_for({"x-pgw-session": "  "}, {}, settings) == "default"


def test_valid_session_keys() -> None:
    assert is_valid_key(UUID)
    assert is_valid_key("team-a")
    assert is_valid_key("a.b_c-1")


def test_invalid_session_keys() -> None:
    assert not is_valid_key("")
    assert not is_valid_key("../../etc/passwd")
    assert not is_valid_key("team a")
    assert not is_valid_key("team\na")
    assert not is_valid_key("x" * 65)
