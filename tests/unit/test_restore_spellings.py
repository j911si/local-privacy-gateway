"""One token per spelling: replacing each token by its vault value gives back the exact input."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from privacy_gateway import Gateway
from privacy_gateway.api import GatewaySession
from privacy_gateway.tokens import NUMBERED_TOKEN

INTRO = (
    "Arbeitsverzeichnis: /home/annika/projekte/akten. Ich bin Annika Sommerfeld. "
    "Kundennummer: 48151623. Telefon +49 30 12345678. "
    "IBAN DE02 1203 0000 0000 2020 51. Das Passwort ist wendland."
)

SEVEN = [
    "ls /home/annika/Annika/ANNIKA",
    "sed -i 's/annika/Annika/g' notes.txt",
    'IBAN = "DE02120300000000202051"',
    "mv Rechnung48151623.pdf /home/annika/archiv/",
    "cd /home/annika/annikas-ordner",
    "call 0049 30 12345678 now",
    "pw=wendland2024",
]


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault" / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault" / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(tmp_path / "audit" / "audit.jsonl"))
    monkeypatch.setenv("PGW_AUDIT_LOG_DIR", str(tmp_path / "audit-dir"))
    with Gateway() as instance:
        yield instance


def substitute(session: GatewaySession, text: str) -> str:
    """The invariant: plain string replacement of each token by its value, no counters."""
    entries = session.entries()
    return NUMBERED_TOKEN.sub(
        lambda m: entries[m.group(0)].value if m.group(0) in entries else m.group(0), text
    )


@pytest.mark.parametrize("text", SEVEN)
def test_a_known_value_in_another_spelling_comes_back_byte_identical(
    gateway: Gateway, text: str
) -> None:
    session = gateway.session("spellings")
    session.pseudonymize(INTRO)
    masked = session.pseudonymize(text)
    assert substitute(session, masked) == text
    assert session.restore(masked, mode="lenient").text == text
    assert session.restore(masked, mode="strict").text == text
    assert session.pseudonymize(text) == masked


def test_a_leading_zero_zero_does_not_leave_a_plus_inside_the_text(gateway: Gateway) -> None:
    session = gateway.session("spellings")
    session.pseudonymize(INTRO)
    masked = session.pseudonymize("call 0049 30 12345678 now")
    assert "0049" not in masked and "00<" not in masked


_WORDS = st.sampled_from(["annika", "Annika", "ANNIKA", "annikas", "annika_x", "Xannika", "wendland"])
_NUMBERS = st.sampled_from(
    [
        "48151623",
        "Rechnung48151623",
        "x48151623y",
        "DE02120300000000202051",
        "DE02 1203 0000 0000 2020 51",
        "+49 30 12345678",
        "+493012345678",
        "0049 30 12345678",
        "030 12345678",
    ]
)
_SEPARATORS = st.sampled_from([" ", "/", "\n", "_", "-", ":", ".", '"', "'", "`"])


@st.composite
def documents(draw: st.DrawFn) -> list[str]:
    texts = []
    for _ in range(draw(st.integers(1, 3))):
        pieces = draw(st.lists(st.tuples(st.one_of(_WORDS, _NUMBERS), _SEPARATORS), max_size=6))
        texts.append("".join(piece + sep for piece, sep in pieces))
    return texts


@settings(
    max_examples=int(__import__("os").environ.get("PGW_SPELLING_EXAMPLES", "60")),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(texts=documents())
def test_replacing_tokens_by_values_gives_back_the_input(
    gateway: Gateway, texts: list[str]
) -> None:
    session = gateway.session()
    session.pseudonymize(INTRO)
    for text in texts:
        if re.search(r"<[A-Z]", text):
            continue
        masked = session.pseudonymize(text)
        assert substitute(session, masked) == text
        assert session.restore(masked, mode="lenient").text == text
        assert session.restore(masked, mode="strict").text == text
        assert session.pseudonymize(text) == masked
