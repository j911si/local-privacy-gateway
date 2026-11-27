"""Secrets inside escaped JSON (one to three escape levels) and CSRF/XSRF spellings."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway

SECRET = "Fake9secret7Value42xyz"
IBAN = "DE89370400440532013000"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def escaped(document: object, levels: int) -> str:
    """`document` as JSON, then `levels` times embedded as a JSON string value body."""
    text = json.dumps(document)
    for _ in range(levels):
        text = json.dumps(text)[1:-1]
    return text


def assert_only_secret_replaced(gateway: Gateway, text: str, secret: str, marker: str) -> None:
    session = gateway.session()
    out = session.pseudonymize(text)
    assert secret not in out
    assert out.count(marker) == text.count(secret)
    assert session.restore_text(out) == text.replace(secret, marker)


KEYS = [
    ("password", "<PASSWORD_REDACTED>"),
    ("access_token", "<ACCESS_TOKEN_REDACTED>"),
    ("api_key", "<API_KEY_REDACTED>"),
    ("client_secret", "<CLIENT_SECRET_REDACTED>"),
    ("refresh_token", "<REFRESH_TOKEN_REDACTED>"),
    ("private_key", "<PRIVATE_KEY_REDACTED>"),
    ("csrf_token", "<CSRF_TOKEN_REDACTED>"),
    ("sessionid", "<SESSION_ID_REDACTED>"),
]


@pytest.mark.parametrize("levels", [0, 1, 2, 3])
@pytest.mark.parametrize(("key", "marker"), KEYS)
def test_secret_in_escaped_json_is_redacted_in_place(
    gateway: Gateway, key: str, marker: str, levels: int
) -> None:
    text = "log: " + escaped({key: SECRET, "user": "bob"}, levels) + " end"
    assert_only_secret_replaced(gateway, text, SECRET, marker)


@pytest.mark.parametrize("levels", [1, 2])
def test_json_as_string_value_inside_json(gateway: Gateway, levels: int) -> None:
    inner = escaped({"password": SECRET}, levels - 1)
    text = json.dumps({"tool": "read", "output": inner})
    assert_only_secret_replaced(gateway, text, SECRET, "<PASSWORD_REDACTED>")


def test_escaped_quote_inside_an_escaped_password(gateway: Gateway) -> None:
    text = escaped({"password": 'Fake9"tail42x', "user": "bob"}, 1)
    out = gateway.session().pseudonymize(text)
    assert "Fake9" not in out
    assert "tail42x" not in out
    assert "bob" in out


@pytest.mark.parametrize("levels", [1, 2, 3])
def test_tokenized_values_in_escaped_json_restore_byte_for_byte(
    gateway: Gateway, levels: int
) -> None:
    text = escaped({"iban": IBAN, "note": "ok"}, levels)
    session = gateway.session()
    out = session.pseudonymize(text)
    assert IBAN not in out
    assert session.restore_text(out) == text


@pytest.mark.parametrize(
    "text",
    [
        f'{{"csrf_token": "{SECRET}"}}',
        f'{{"csrfToken": "{SECRET}"}}',
        f'{{"_csrf": "{SECRET}"}}',
        f"X-CSRF-Token: {SECRET}",
        f"x-xsrf-token: {SECRET}",
        f"xsrf-token={SECRET}",
        f'{{"XSRF-TOKEN": "{SECRET}"}}',
        f"csrfmiddlewaretoken={SECRET}",
        f"Cookie: XSRF-TOKEN={SECRET}; theme=dark",
        f"Set-Cookie: csrftoken={SECRET}; Path=/",
    ],
)
def test_csrf_and_xsrf_spellings_are_redacted(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert SECRET not in out


@pytest.mark.parametrize(
    "text",
    [
        "The CSRF token is missing in the form.",
        "xsrfCookieName: 'XSRF-TOKEN', xsrfHeaderName: 'X-XSRF-TOKEN'",
        "csrf_token = {{ csrf_token }}",
        "csrf_token = get_token(request)",
        '{\\"user\\": \\"bob\\", \\"theme\\": \\"dark\\"}',
        '{\\"password_hint\\": \\"Name of first pet\\"}',
        '{\\"token_type\\": \\"bearer\\"}',
    ],
)
def test_lookalikes_stay(gateway: Gateway, text: str) -> None:
    assert gateway.session().pseudonymize(text) == text
