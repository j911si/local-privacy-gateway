"""An IBAN or card number followed by a word or number group is still found."""

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
    ("text", "secret", "rest"),
    [
        ("IBAN AT611904300234573201 EUR", "AT611904300234573201", " EUR"),
        ("IBAN ES9121000418450200051332 PAID", "ES9121000418450200051332", " PAID"),
        ("IBAN DE89 3704 0044 0532 0130 00 EUR", "DE89 3704 0044 0532 0130 00", " EUR"),
        ("card 4111 1111 1111 1111 123", "4111 1111 1111 1111", " 123"),
        ("Karte 4111 1111 1111 1111 12/27", "4111 1111 1111 1111", " 12/27"),
        ("Karte 4111-1111-1111-1111-123", "4111-1111-1111-1111", "-123"),
    ],
)
def test_valid_prefix_is_replaced(gateway: Gateway, text: str, secret: str, rest: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert secret not in out
    assert out.endswith(">" + rest)


@pytest.mark.parametrize(
    "text", ["Bestellnummer 1234 5678 9012 3456 7", "IBAN DE00 1234 5678 9012 3456 78 X"]
)
def test_invalid_numbers_stay(gateway: Gateway, text: str) -> None:
    assert gateway.session().pseudonymize(text) == text
