"""Names behind a person label and a birth date in front of a health statement."""

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


def _round(gateway: Gateway, line: str) -> str:
    result = gateway.pseudonymize(line)
    assert gateway.restore(result.text, session_id=result.session_id).text == line
    return result.text


NAMED = [
    ("Name: Gisela Hollerbacher", "Gisela"),
    ("Name: Tobias Kreuzeder", "Kreuzeder"),
    ("Zugangs-PIN für das Online-Banking: 482913, Kontoinhaber Hans Brandmeier.", "Brandmeier"),
    ("Kontoinhaber Ute Zeilhofer.", "Zeilhofer"),
    ("Kontoinhaberin: Mirela Dantzer", "Dantzer"),
    ("Inhaber Karl Wesnitzer", "Wesnitzer"),
    ("Karteninhaber: Olga Prenzlauer", "Prenzlauer"),
    ("Patientin Rita Sommerlacher", "Sommerlacher"),
    ("Patient: Egon Vetterlich", "Vetterlich"),
    ("Versicherte Heide Marquardsen", "Marquardsen"),
    ("Kunde: Bernd Oltersdorf", "Oltersdorf"),
    ("Kundin: Ilka Brunsmeyer", "Brunsmeyer"),
    ("Empfänger Walter Ostenfeldt", "Ostenfeldt"),
    ("Ansprechpartner: Jörg Lindtnerig", "Lindtnerig"),
    ("Mitarbeiterin Sabine Wolkenhauer", "Wolkenhauer"),
    ("Vor- und Nachname: Lena Fruehaufer", "Fruehaufer"),
    ("Full name: Peter Quandelt", "Quandelt"),
    ("Account holder Maria Teschenmacher", "Teschenmacher"),
    ("Cardholder: Tim Roggenkamp", "Roggenkamp"),
    ("Customer: Anna von Bleichenbach", "Bleichenbach"),
    ("Nachname: Ostrowsky", "Ostrowsky"),
]

KEPT = [
    "name: my-service",
    '"name": "privacy-gateway"',
    "Name: Local Privacy Gateway",
    'name = "test_runner"',
    "Name: README.md",
    "Kontoinhaber ist nicht bekannt",
    "Der Kunde hat angerufen",
    "Patient wurde entlassen",
    "Name: Docker Compose",
    "Name: New York",
    "Customer: Hollerbacher Consulting",
    "Der Patient Max Test",
]


@pytest.mark.parametrize(("line", "word"), NAMED)
def test_label_name_is_replaced(gateway: Gateway, line: str, word: str) -> None:
    assert word not in _round(gateway, line)


@pytest.mark.parametrize("line", KEPT)
def test_non_person_label_values_stay(gateway: Gateway, line: str) -> None:
    out = _round(gateway, line)
    assert "PERSON" not in out


def test_company_is_not_a_person(gateway: Gateway) -> None:
    out = _round(gateway, "Customer: ACME GmbH")
    assert "PERSON" not in out


def test_learned_name_is_replaced_later_without_label(gateway: Gateway) -> None:
    session = gateway.session()
    session.pseudonymize("Name: Gisela Hollerbacher")
    later = session.pseudonymize("Gisela Hollerbacher hat angerufen. Hollerbacherei bleibt.")
    assert later.startswith("<PERSON_")
    assert "Hollerbacherei" in later


def test_birth_date_before_health_statement(gateway: Gateway) -> None:
    out = _round(
        gateway,
        "Der Patient wurde am 14.03.1962 geboren und leidet an chronischer Niereninsuffizienz.",
    )
    assert "14.03" not in out
    assert "1962" not in out
    assert "DATE_OF_BIRTH" in out
    assert "Niereninsuffizienz" not in out
    assert "14.03.<" not in out


def test_born_on_form(gateway: Gateway) -> None:
    out = _round(gateway, "She was born on 14.03.1962 and has diabetes.")
    assert "1962" not in out


def test_diagnosis_line_stays_one_health_token(gateway: Gateway) -> None:
    out = _round(gateway, "Diagnose: Typ-2-Diabetes seit 2019, Metformin 850 mg täglich")
    assert out == "<HEALTH_INFORMATION_001>"


def test_release_date_is_not_a_birth_date(gateway: Gateway) -> None:
    out = _round(gateway, "Das Release wurde am 14.03.2024 gebaut")
    assert "DATE_OF_BIRTH" not in out
