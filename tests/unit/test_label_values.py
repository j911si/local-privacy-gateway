"""Label-driven values: words between label and value, the separator after a value, tax-id label."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


def _run(gateway: Gateway, line: str) -> str:
    result = gateway.pseudonymize(line)
    if "_REDACTED>" not in result.text:
        assert gateway.restore(result.text, result.session_id).text == line
    return result.text


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        ("PIN 482913", "482913"),
        ("PIN: 482913", "482913"),
        ("pin=482913", "482913"),
        ("Zugangs-PIN für das Online-Banking: 482913, Kontoinhaber Brandtner.", "482913"),
        ("Online-Banking PIN = 4829", "4829"),
        ("TAN für die Überweisung: 482913", "482913"),
        ("Die TAN lautet leider: 48291356", "48291356"),
        ("OTP für den Login: 482913", "482913"),
        ("Einmalcode zur Anmeldung: 482913", "482913"),
    ],
)
def test_pin_tan_otp_with_words_before_the_separator(
    gateway: Gateway, line: str, secret: str
) -> None:
    assert secret not in _run(gateway, line)


@pytest.mark.parametrize(
    "line",
    [
        "Die PIN ist 4-stellig",
        "pin 12",
        "Pinnwand: 123456",
        "mapping: 123456",
        "PIN-Länge: 6",
        "spin: 123456",
        "Die PIN ist 4-stellig und die TAN: 6-stellig",
        "PIN\nKontostand: 123456",
        "Die PIN wurde 2 Mal falsch eingegeben: 123456",
    ],
)
def test_pin_counterexamples_stay(gateway: Gateway, line: str) -> None:
    assert _run(gateway, line) == line


def test_credit_card_keeps_the_space_behind_it(gateway: Gateway) -> None:
    line = "bitte buche die Gebühr auf 4539 1488 0343 6467 ab."
    out = _run(gateway, line)
    assert "4539" not in out
    assert out.endswith("> ab.")


@pytest.mark.parametrize(
    "line",
    [
        "Karte 4539-1488-0343-6467 - gesperrt",
        "Karte 4539148803436467 ab",
        "Karte 4539 1488 0343 6467, ok",
    ],
)
def test_credit_card_keeps_following_character(gateway: Gateway, line: str) -> None:
    out = _run(gateway, line)
    assert "4539" not in out
    assert out.startswith("Karte <") and out.split(">", 1)[1][0] in " ,"


@pytest.mark.parametrize(
    "line",
    [
        "IBAN DE89 3704 0044 0532 0130 00 ab.",
        "IBAN DE89370400440532013000 ab.",
        "Tel: +49 (0) 30 123456 ab.",
    ],
)
def test_other_values_keep_the_space_behind_them(gateway: Gateway, line: str) -> None:
    out = _run(gateway, line)
    assert out.endswith("> ab.")


@pytest.mark.parametrize(
    "line",
    [
        "Steuer-ID: 12345678901",
        "Steuer-ID 12345678901.",
        "Steuer-IdNr: 12 345 678 901",
        "Steueridentifikationsnummer = 12345678901",
        "IdNr 12345678901",
        "TIN: 12345678901",
        "Tax ID: 12345678901",
        "Steuernummer: 12345678901",
        "Steuer-ID: 86095742719",
    ],
)
def test_labelled_tax_id_without_valid_check_digit(gateway: Gateway, line: str) -> None:
    out = _run(gateway, line)
    assert "123" not in out and "860957" not in out
    assert "<TAX_ID_" in out


@pytest.mark.parametrize(
    "line",
    [
        "Steuerklasse: 3",
        "Steuersatz: 19",
        "Bestellnummer: 12345678901",
        "Steuer 2024: 12345678901 Euro",
    ],
)
def test_tax_id_counterexamples(gateway: Gateway, line: str) -> None:
    assert "<TAX_ID_" not in _run(gateway, line)
