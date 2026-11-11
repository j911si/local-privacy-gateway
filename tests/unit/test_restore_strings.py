"""Realistic strings a model echoes back (shell lines, paths, JSON) restore around their tokens."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway

INTRO = (
    "Arbeitsverzeichnis: /home/annika/projekte/akten. Ich bin Annika Sommerfeld "
    "(annika.sommerfeld@kanzlei-sommerfeld.de). Kundennummer: 48151623. "
    "Server db01.intern.kanzlei-sommerfeld.de, IP 192.168.178.23. IBAN DE02 1203 0000 0000 2020 51."
)

EXACT = [
    "/home/annika/annika_notes.md",
    "tar czf backup_annika.tar /home/annika",
    'config = {"owner": "annika.sommerfeld@kanzlei-sommerfeld.de", "ip": "192.168.178.23"}',
    "owner = 'annika'",
    "Der Benutzer `annika` hat die Kundennummer `48151623`.",
    "ssh annika@db01.intern.kanzlei-sommerfeld.de",
    "/home/annika/projekte/akten/48151623_annika_export.csv",
    'grep -rn annika /home/annika/projekte | head -3\n/home/annika/projekte/a.py:12:USER = "annika"',
    "echo 192.168.178.23:8080 > hosts_192.168.178.23.txt",
    "host_db01.intern.kanzlei-sommerfeld.de_key",
]

# The text already differs before the model sees it (a detected span swallowed "Rechnung" or the
# genitive "s", one token stands for several spellings), so only the canonical value comes back.
CANONICAL = [
    ("mv Rechnung48151623.pdf /home/annika/archiv/", "mv 48151623.pdf /home/annika/archiv/"),
    ("ls /home/annika/Annika/ANNIKA", "ls /home/annika/annika/annika"),
    (
        "scp x annika@192.168.178.23:/home/annika/annikas-ordner/",
        "scp x annika@192.168.178.23:/home/annika/annika-ordner/",
    ),
    (
        "IBAN=DE02120300000000202051; iban_fmt='DE02 1203 0000 0000 2020 51'",
        "IBAN=DE02 1203 0000 0000 2020 51; iban_fmt='DE02 1203 0000 0000 2020 51'",
    ),
]


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault" / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault" / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(tmp_path / "audit" / "audit.jsonl"))
    with Gateway() as instance:
        yield instance


def _echo(gateway: Gateway, text: str) -> str:
    session = gateway.session("restore-strings")
    session.pseudonymize(INTRO)
    return session.restore(session.pseudonymize(text), mode="lenient").text


@pytest.mark.parametrize("text", EXACT)
def test_string_comes_back_byte_identical(gateway: Gateway, text: str) -> None:
    assert _echo(gateway, text) == text


@pytest.mark.parametrize(("text", "expected"), CANONICAL)
def test_string_comes_back_with_canonical_values(
    gateway: Gateway, text: str, expected: str
) -> None:
    assert _echo(gateway, text) == expected
