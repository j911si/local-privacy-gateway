"""A vault written by 0.1.0 (6a146c8, synthetic values, test-only key) works with this code."""

from __future__ import annotations

import os
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.model import VaultError
from privacy_gateway.vault import Vault

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vault_v010"
SESSION_KEY = "fixture-v010"
SESSION_ID = "5801f003a32648e7866b25acf9270815"
IBAN_SPACED = "DE89 3704 0044 0532 0130 00"
IBAN_COMPACT = "DE89370400440532013000"


@pytest.fixture
def vault_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Copy the 0.1.0 vault and its test key into tmp_path and point the gateway at them."""
    db_path = tmp_path / "vault" / "vault.db"
    key_file = tmp_path / "vault" / "vault.key"
    db_path.parent.mkdir(mode=0o700)
    shutil.copyfile(FIXTURE / "vault.sqlite3", db_path)
    key = bytes.fromhex((FIXTURE / "test-key.hex").read_text(encoding="ascii").strip())
    descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, key)
    finally:
        os.close(descriptor)
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(db_path))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(key_file))
    return db_path, key_file


@pytest.fixture
def gateway(vault_paths: tuple[Path, Path]) -> Iterator[Gateway]:
    with Gateway() as instance:
        yield instance


def _schema(db_path: Path) -> list[tuple[str, str]]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
        ).fetchall()
    finally:
        conn.close()
    return rows


def _row_counts(db_path: Path) -> list[int]:
    conn = sqlite3.connect(db_path)
    try:
        return [
            conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("sessions", "mappings", "surface_forms")
        ]
    finally:
        conn.close()


def test_schema_matches_a_fresh_vault(vault_paths: tuple[Path, Path], tmp_path: Path) -> None:
    db_path, key_file = vault_paths
    with Vault(db_path, key_file):
        pass
    fresh = tmp_path / "fresh" / "vault.db"
    with Vault(fresh, key_file):
        pass
    assert _schema(db_path) == _schema(fresh)


def test_entries_written_by_v010_decrypt(gateway: Gateway) -> None:
    assert gateway.vault.find_session(SESSION_KEY) == SESSION_ID
    entries = gateway.vault.load(SESSION_ID)
    assert sorted(entries) == ["<EMAIL_001>", "<IBAN_001>", "<PERSON_FEMALE_001>"]
    assert entries["<IBAN_001>"].value == IBAN_SPACED
    assert entries["<IBAN_001>"].surface_forms == [IBAN_SPACED, IBAN_COMPACT]
    assert entries["<PERSON_FEMALE_001>"].surface_forms == ["Erika Beispiel", "ERIKA"]
    assert gateway.vault.max_counters(SESSION_ID) == {"EMAIL": 1, "IBAN": 1, "PERSON": 1}


def test_restore_of_v010_output_uses_the_first_spelling(gateway: Gateway) -> None:
    output = (FIXTURE / "output.txt").read_text(encoding="utf-8")
    original = (FIXTURE / "input.txt").read_text(encoding="utf-8")
    result = gateway.restore(output, SESSION_ID, "strict")
    assert result.unknown_tokens == []
    assert result.restored_count == 5
    # Only the second spellings differ; every value with a single spelling is byte-exact.
    expected = original.replace("ERIKA BEISPIEL", "Erika Beispiel BEISPIEL").replace(
        f"IBAN {IBAN_COMPACT}", f"IBAN {IBAN_SPACED}"
    )
    assert result.text == expected
    assert result.text != original


def test_session_continues_with_known_tokens_and_counters(gateway: Gateway) -> None:
    text = (
        f"Frau Erika Beispiel zahlt auf {IBAN_SPACED} bzw. {IBAN_COMPACT}.\n"
        "Neu: Herr Max Mustermann, max.mustermann@example.org, Kopie an "
        "erika.beispiel@example.com.\n"
    )
    session = gateway.session(SESSION_KEY)
    assert session.session_id == SESSION_ID
    pseudonymized = session.pseudonymize(text)
    assert pseudonymized == (
        "Frau <PERSON_FEMALE_001> zahlt auf <IBAN_001> bzw. <IBAN_002>.\n"
        "Neu: Herr <PERSON_MALE_002>, <EMAIL_002>, Kopie an <EMAIL_001>.\n"
    )
    assert gateway.restore(pseudonymized, SESSION_ID, "strict").text == text


def test_purge_removes_the_v010_session(
    gateway: Gateway, vault_paths: tuple[Path, Path]
) -> None:
    gateway.vault.purge(SESSION_ID)
    assert gateway.vault.find_session(SESSION_KEY) is None
    assert _row_counts(vault_paths[0]) == [0, 0, 0]


def test_v010_token_keeps_its_value_against_a_second_connection(
    vault_paths: tuple[Path, Path],
) -> None:
    db_path, key_file = vault_paths
    with Vault(db_path, key_file) as first, Vault(db_path, key_file) as second:
        with pytest.raises(VaultError):
            second.store(SESSION_ID, "<IBAN_001>", "IBAN", "DE02120300000000202051", [], {})
        first.store(SESSION_ID, "<IBAN_001>", "IBAN", IBAN_SPACED, [IBAN_SPACED], {})
        assert first.load(SESSION_ID)["<IBAN_001>"].value == IBAN_SPACED
    conn = sqlite3.connect(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO mappings (session_id, token, data_class, nonce, ciphertext, "
                "attributes_json) VALUES (?, '<IBAN_001>', 'IBAN', x'00', x'00', '{}')",
                (SESSION_ID,),
            )
    finally:
        conn.close()
