"""A learned full name also teaches the session its first and last name as exact words."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.api import GatewaySession

INTRO = "Name: Gisela Hollerbacher"


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


def _learned(gateway: Gateway, intro: str = INTRO) -> GatewaySession:
    session = gateway.session()
    session.pseudonymize(intro)
    return session


def _round(session: GatewaySession, text: str) -> str:
    out = session.pseudonymize(text)
    assert session.restore_text(out) == text
    return out


@pytest.mark.parametrize(
    ("text", "word"),
    [
        ("Hollerbacher hat angerufen", "Hollerbacher"),
        ("Gisela ruft zurück", "Gisela"),
        ("Danke an Hollerbacher, Gisela und Co.", "Hollerbacher"),
        ("Hollerbacher's Brief", "Hollerbacher"),
    ],
)
def test_a_later_part_is_replaced(gateway: Gateway, text: str, word: str) -> None:
    session = _learned(gateway)
    assert word not in _round(session, text)


def test_parts_of_a_name_learned_by_salutation(gateway: Gateway) -> None:
    session = _learned(gateway, "Sehr geehrte Frau Gisela Hollerbacher,")
    assert "Hollerbacher" not in _round(session, "Hollerbacher hat angerufen")


@pytest.mark.parametrize(
    "text",
    [
        "Die Hollerbacherei im Ort",
        "hollerbacher.py",
        "/srv/hollerbacher/data",
        "gisela_test",
        "hollerbacher",
        "HOLLERBACHER",
        "Gisela_test",
        "Hollerbacher_data.csv",
        "import Hollerbacher.utils",
        "src/Hollerbacher/main.py",
    ],
)
def test_identifiers_and_other_spellings_stay(gateway: Gateway, text: str) -> None:
    session = _learned(gateway)
    assert _round(session, text) == text


def test_a_blocked_part_is_not_learned(gateway: Gateway) -> None:
    session = _learned(gateway, "Name: Max Stein")
    text = "Max kam und Stein auch"
    assert _round(session, text) == text


def test_a_particle_is_not_learned(gateway: Gateway) -> None:
    session = _learned(gateway, "Customer: Anna von Bleichenbach")
    text = "Das Gut von Hof zu Tal"
    assert _round(session, text) == text
    assert "Bleichenbach" not in _round(session, "Bleichenbach schrieb")


def test_a_part_gets_a_token_of_its_own_and_restores_exactly(gateway: Gateway) -> None:
    session = _learned(gateway)
    out = _round(session, "Hollerbacher und Gisela Hollerbacher")
    assert out.count("<") == 2


def test_a_part_never_blocks_a_later_text(gateway: Gateway) -> None:
    session = _learned(gateway)
    texts = ["Hollerbacher.", "(Gisela)", "Gisela-Marie", "Xx Hollerbacher\nGisela\tHollerbacher"]
    for text in texts:
        _round(session, text)


def test_rescan_accepts_the_output_with_a_learned_part(gateway: Gateway) -> None:
    session = _learned(gateway)
    out = session.pseudonymize("Hollerbacher hat angerufen, Hollerbacherei auch")
    assert "Hollerbacher " not in out
    assert session.rescan(out) == []


def test_rescan_reports_a_raw_part(gateway: Gateway) -> None:
    session = _learned(gateway)
    assert session.rescan("Hollerbacher hat angerufen") != []
    assert session.rescan("hollerbacher.py und Hollerbacherei") == []
