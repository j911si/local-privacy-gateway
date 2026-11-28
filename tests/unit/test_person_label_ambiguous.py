"""A full name after an account-holder label is a person even with an ambiguous first name."""

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
        "Kontoinhaber: Max Mustermann",
        "Kontoinhaber: Max Fruehaufer",
        "Karteninhaberin: Rosa Beispiel",
        "Account holder: Max Fruehaufer",
    ],
)
def test_name_after_person_label_is_replaced(gateway: Gateway, text: str) -> None:
    name = text.split(": ")[1]
    assert name.split()[1] not in gateway.session().pseudonymize(text)


@pytest.mark.parametrize("text", ["Kontoinhaber: Max", "Name: Golden Gate"])
def test_single_word_or_generic_label_keeps_the_filter(gateway: Gateway, text: str) -> None:
    assert gateway.session().pseudonymize(text) == text
