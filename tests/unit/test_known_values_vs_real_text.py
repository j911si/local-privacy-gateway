"""A gateway that knows many values must not block ordinary text: code, logs, tables, docs."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import LeakageError

ROOT = Path(__file__).resolve().parents[2]
SKIPPED = {".png", ".jpg", ".ico", ".db", ".lock"}
CHUNK = 4000

KNOWN_VALUES = (
    "Tel. +49 30 12345678, Mobil 0171 2345678, Fax 089 987654, Konto 4711, Konto 31337, "
    "Kundennummer 98765432, Kundennummer 2024001, IBAN DE89 3704 0044 0532 0130 00, "
    "Karte 4111 1111 1111 1111, Mail an anna.berg@example-firma.de, Brief an Anna Berg, "
    "Siehe https://git.beispiel-firma.de/r1?id=ab123cd456 und http://10.20.30.40:8080/v2/x?n=1234567."
)


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return [name for name in out if name and Path(name).suffix not in SKIPPED]


def _chunks(text: str) -> list[str]:
    lines, chunks, current, size = text.split("\n"), [], [], 0
    for line in lines:
        current.append(line)
        size += len(line) + 1
        if size >= CHUNK:
            chunks.append("\n".join(current))
            current, size = [], 0
    if current:
        chunks.append("\n".join(current))
    return chunks


@pytest.mark.parametrize("name", _tracked_files())
def test_known_values_never_block_a_tracked_file(default_config: Config, name: str) -> None:
    try:
        text = (ROOT / name).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        pytest.skip("not a text file")
    with Gateway(default_config) as gateway:
        session = gateway.session()
        session.pseudonymize(KNOWN_VALUES)
        for index, chunk in enumerate(_chunks(text)):
            try:
                session.pseudonymize(chunk)
            except LeakageError as error:
                kinds = [(leak.kind, leak.data_class) for leak in error.leaks]
                pytest.fail(f"{name} chunk {index} blocked: {kinds}")
