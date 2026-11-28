from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "fake12\\"tail99"}',
        "{'password': 'fake12\\'tail99'}",
        'passwort = "fake12\\"tail99"',
        'sshpass -p "fake12\\"tail99" ssh host',
        '{"api_secret": "fake12345678\\"tail99"}',
        '{"client_secret": "fake12345678\\"tail99"}',
        '{"access_token": "fake1234567890ab\\"tail99"}',
        '{"refresh_token": "fake1234567890ab\\"tail99"}',
        'csrf_token: "fake1234\\"tail99"',
        '{"private_key": "fake1234567890ab\\"tail99"}',
        '{"api_key": "fake1234567890ab\\"tail99"}',
    ],
)
def test_the_part_after_an_escaped_quote_is_redacted(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert "fake12" not in out
    assert "tail99" not in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"password": "fake12\\\\", "user": "bob"}', '"user": "bob"'),
        ('password = "C:\\temp\\"', 'password = "<PASSWORD_REDACTED>"'),
        (
            'access_token=fake1234567890ab\\", \\"user\\": \\"bob\\"',
            '\\", \\"user\\": \\"bob\\"',
        ),
    ],
)
def test_the_closing_quote_still_ends_the_value(
    gateway: Gateway, text: str, expected: str
) -> None:
    out = gateway.session().pseudonymize(text)
    assert "fake12" not in out
    assert "temp" not in out
    assert expected in out
