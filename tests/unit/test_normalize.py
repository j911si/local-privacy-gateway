"""Unicode normalization in front of the pipeline: format characters must not hide values."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway

IBAN_PARTS = ("DE89", "3704", "0044", "0532", "0130", "00")
IBAN_PLAIN = "".join(IBAN_PARTS)

NBSP = chr(0x00A0)
COMBINING_DIAERESIS = chr(0x0308)
SOFT_HYPHEN = chr(0x00AD)
TYPOGRAPHIC_SPACES = [NBSP, chr(0x202F), chr(0x2009), chr(0x2007)]
INVISIBLES = [SOFT_HYPHEN, chr(0x200B), chr(0x200D), chr(0xFEFF)]


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    """A gateway whose vault, key and audit log live inside tmp_path."""
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    with Gateway() as instance:
        yield instance


def roundtrip(gateway: Gateway, text: str) -> str:
    """Pseudonymize, assert the restore is byte-identical and return the masked text."""
    result = gateway.pseudonymize(text)
    assert gateway.restore(result.text, result.session_id).text == text
    return result.text


@pytest.mark.parametrize("separator", TYPOGRAPHIC_SPACES)
def test_iban_with_typographic_spaces_is_fully_masked(gateway: Gateway, separator: str) -> None:
    text = f"IBAN {separator.join(IBAN_PARTS)} gutgeschrieben."
    assert roundtrip(gateway, text) == "IBAN <IBAN_001> gutgeschrieben."


@pytest.mark.parametrize("invisible", INVISIBLES)
def test_iban_with_invisible_characters_is_fully_masked(gateway: Gateway, invisible: str) -> None:
    text = f"IBAN {IBAN_PLAIN[:12]}{invisible}{IBAN_PLAIN[12:]} gutgeschrieben."
    assert roundtrip(gateway, text) == "IBAN <IBAN_001> gutgeschrieben."


def test_decomposed_name_is_fully_masked(gateway: Gateway) -> None:
    text = f"Frau Anna Mu{COMBINING_DIAERESIS}ller hat angerufen."
    assert roundtrip(gateway, text) == "Frau <PERSON_FEMALE_001> hat angerufen."


def test_phone_with_non_breaking_space_is_fully_masked(gateway: Gateway) -> None:
    text = f"Tel. +49{NBSP}211{NBSP}1234567 erreichbar."
    assert roundtrip(gateway, text) == "Tel. <PHONE_001> erreichbar."


def test_plain_text_keeps_its_behaviour(gateway: Gateway) -> None:
    text = "IBAN DE89 3704 0044 0532 0130 00 gutgeschrieben."
    assert roundtrip(gateway, text) == "IBAN <IBAN_001> gutgeschrieben."


def test_normalized_text_does_not_shift_neighbouring_spans(gateway: Gateway) -> None:
    name = f"Frau Anna Mu{COMBINING_DIAERESIS}ller"
    iban = f"{IBAN_PLAIN[:8]}{SOFT_HYPHEN}{IBAN_PLAIN[8:]}"
    assert roundtrip(gateway, f"{name}, IBAN {iban}.") == "Frau <PERSON_FEMALE_001>, IBAN <IBAN_001>."
