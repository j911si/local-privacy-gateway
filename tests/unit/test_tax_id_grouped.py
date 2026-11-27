"""Grouped Steuer-IDs after `Identifikationsnummer` or `Steuerbescheid` are tokenized."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from test_regex_linearity import _hard_timeout, assert_linear, finditer  # noqa: F401

from privacy_gateway import Gateway
from privacy_gateway.config import Config

TAX_ID = "71 358 952 543"
WRONG_CHECK = "71 358 952 544"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize(
    "text",
    [
        f"Identifikationsnummer {TAX_ID} liegt vor.",
        f"Steuerbescheid: Identifikationsnummer {TAX_ID}",
        f"Ihre steuerliche Identifikationsnummer: {TAX_ID}",
        f"Steuerbescheid 2025, Nr. {TAX_ID}",
        f"Steueridentifikationsnummer {TAX_ID}",
        f"Steuer-ID: {TAX_ID}",
        f"tax {TAX_ID}",
    ],
)
def test_grouped_tax_id_is_tokenized(gateway: Gateway, text: str) -> None:
    session = gateway.session()
    out = session.pseudonymize(text)
    assert TAX_ID not in out
    assert "<TAX_ID_" in out
    assert not session.rescan(out)


@pytest.mark.parametrize(
    "text",
    [
        f"Steuerbescheid 2025, Nr. {WRONG_CHECK}",
        f"Rufen Sie {TAX_ID} an.",
        "Bestellnummer 71358952543 versandt.",
        "Bestellung 71358952543 versandt.",
        f"Telefon {TAX_ID}",
        f"Identifikationsnummer {WRONG_CHECK}",
        "Geräte-Identifikationsnummer 12 345 678 901",
    ],
)
def test_lookalikes_stay(gateway: Gateway, text: str) -> None:
    assert "<TAX_ID_" not in gateway.session().pseudonymize(text)


@pytest.mark.parametrize(
    "text",
    [f"steuerliche Identifikationsnummer {WRONG_CHECK}", f"Steuer-ID: {WRONG_CHECK}"],
)
def test_labelled_value_is_tokenized_without_check_digit(gateway: Gateway, text: str) -> None:
    """Deliberate: a labelled Steuer-ID skips the validator, as for `Steuer-ID:`."""
    out = gateway.session().pseudonymize(text)
    assert WRONG_CHECK not in out
    assert "<TAX_ID_" in out


@pytest.mark.parametrize("word", ["Identifikationsnummer", "steuerliche", "steuerliche  "])
def test_new_label_after_long_blank_runs(default_config: Config, word: str) -> None:
    for source in default_config.registry.get("TAX_ID").patterns:
        pattern = re.compile(source, re.MULTILINE)
        assert_linear(finditer(pattern), lambda n: word + " " * n + "fehlt")
        assert_linear(finditer(pattern), lambda n: (word + " 7") * (n // (len(word) + 2)))
