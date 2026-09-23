"""Tests for the encrypted vault."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from privacy_gateway.model import VaultError
from privacy_gateway.vault import Vault, load_or_create_key

SECRET_VALUE = "Müller-Lüdenscheidt 🔐 DE89370400440532013000"


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[Vault]:
    with Vault(tmp_path / "vault.db", tmp_path / "vault.key") as open_vault:
        yield open_vault


def _backdate(db_path: Path, session_id: str, days: int) -> None:
    moment = datetime.now(UTC) - timedelta(days=days)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE sessions SET created_at = ? WHERE id = ?", (moment.isoformat(), session_id))
    conn.commit()
    conn.close()


def test_load_or_create_key_creates_32_bytes_with_mode_600(tmp_path: Path) -> None:
    key_file = tmp_path / "keys" / "vault.key"
    key = load_or_create_key(key_file)
    assert len(key) == 32
    assert os.stat(key_file).st_mode & 0o777 == 0o600
    assert os.stat(key_file.parent).st_mode & 0o777 == 0o700


def test_load_or_create_key_returns_existing_key(tmp_path: Path) -> None:
    key_file = tmp_path / "vault.key"
    first = load_or_create_key(key_file)
    assert load_or_create_key(key_file) == first


def test_load_or_create_key_rejects_world_readable_file(tmp_path: Path) -> None:
    key_file = tmp_path / "vault.key"
    load_or_create_key(key_file)
    os.chmod(key_file, 0o644)
    with pytest.raises(VaultError):
        load_or_create_key(key_file)


def test_load_or_create_key_announces_a_new_key_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file = tmp_path / "vault.key"
    load_or_create_key(key_file)
    first = capsys.readouterr().err
    load_or_create_key(key_file)

    assert str(key_file) in first
    assert "new vault key" in first
    assert capsys.readouterr().err == ""


def test_load_or_create_key_rejects_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.key"
    load_or_create_key(target)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(OSError):
        load_or_create_key(link)


def test_load_or_create_key_rejects_wrong_length(tmp_path: Path) -> None:
    key_file = tmp_path / "vault.key"
    key_file.write_bytes(b"short")
    os.chmod(key_file, 0o600)
    with pytest.raises(VaultError):
        load_or_create_key(key_file)


def test_database_uses_wal_and_foreign_keys(vault: Vault, tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "vault.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()


def test_existing_database_files_are_restricted_to_0600(tmp_path: Path) -> None:
    db_path = tmp_path / "store" / "vault.db"
    db_path.parent.mkdir()
    os.chmod(db_path.parent, 0o755)
    db_path.touch()
    os.chmod(db_path, 0o644)

    with Vault(db_path, tmp_path / "vault.key") as open_vault:
        session_id = open_vault.create_session("sha", "cfg")
        open_vault.store(session_id, "<IBAN_001>", "IBAN", "DE89", [], {})
        for path in tmp_path.glob("store/vault.db*"):
            assert os.stat(path).st_mode & 0o777 == 0o600, path
    assert os.stat(db_path.parent).st_mode & 0o777 == 0o700


def test_round_trip_with_umlauts_and_emoji(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(
        session_id,
        "<PERSON_001>",
        "PERSON_LAST_NAME",
        SECRET_VALUE,
        ["Müller", "MÜLLER 🔐"],
        {"gender": "female"},
    )
    entries = vault.load(session_id)
    assert set(entries) == {"<PERSON_001>"}
    entry = entries["<PERSON_001>"]
    assert entry.value == SECRET_VALUE
    assert entry.data_class == "PERSON_LAST_NAME"
    assert entry.surface_forms == ["Müller", "MÜLLER 🔐"]
    assert entry.attributes == {"gender": "female"}


def test_store_without_surface_forms(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<IBAN_001>", "IBAN", "DE89", [], {})
    assert vault.load(session_id)["<IBAN_001>"].surface_forms == []


def test_ciphertext_columns_do_not_contain_plaintext(vault: Vault, tmp_path: Path) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", SECRET_VALUE, [SECRET_VALUE], {})
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("vault.db*"))
    conn = sqlite3.connect(tmp_path / "vault.db")
    blobs = conn.execute("SELECT ciphertext FROM mappings").fetchall()
    blobs += conn.execute("SELECT ciphertext FROM surface_forms").fetchall()
    conn.close()
    assert blobs
    for (blob,) in blobs:
        assert SECRET_VALUE.encode("utf-8") not in blob
    assert SECRET_VALUE.encode("utf-8") not in raw


def test_load_with_different_key_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    with Vault(db_path, tmp_path / "a.key") as first:
        session_id = first.create_session("sha", "cfg")
        first.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", SECRET_VALUE, [], {})
    with Vault(db_path, tmp_path / "b.key") as second, pytest.raises(VaultError) as excinfo:
        second.load(session_id)
    assert "decryption failed" in str(excinfo.value)
    assert SECRET_VALUE not in str(excinfo.value)


def test_swapped_ciphertexts_fail_authentication(vault: Vault, tmp_path: Path) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", [], {})
    vault.store(session_id, "<PERSON_002>", "PERSON_LAST_NAME", "Schmidt", [], {})
    conn = sqlite3.connect(tmp_path / "vault.db")
    rows = dict(
        conn.execute("SELECT token, ciphertext FROM mappings WHERE session_id = ?", (session_id,))
    )
    nonces = dict(
        conn.execute("SELECT token, nonce FROM mappings WHERE session_id = ?", (session_id,))
    )
    conn.execute(
        "UPDATE mappings SET ciphertext = ?, nonce = ? WHERE session_id = ? AND token = ?",
        (rows["<PERSON_002>"], nonces["<PERSON_002>"], session_id, "<PERSON_001>"),
    )
    conn.execute(
        "UPDATE mappings SET ciphertext = ?, nonce = ? WHERE session_id = ? AND token = ?",
        (rows["<PERSON_001>"], nonces["<PERSON_001>"], session_id, "<PERSON_002>"),
    )
    conn.commit()
    conn.close()
    with pytest.raises(VaultError) as excinfo:
        vault.load(session_id)
    assert "decryption failed" in str(excinfo.value)


def test_load_unknown_session_raises(vault: Vault) -> None:
    with pytest.raises(VaultError):
        vault.load("does-not-exist")


def test_store_on_unknown_session_raises(vault: Vault) -> None:
    with pytest.raises(VaultError) as excinfo:
        vault.store("does-not-exist", "<PERSON_001>", "PERSON_LAST_NAME", SECRET_VALUE, [], {})
    assert SECRET_VALUE not in str(excinfo.value)


def test_purge_removes_mappings_and_surface_forms(vault: Vault, tmp_path: Path) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller"], {})
    vault.purge(session_id)
    conn = sqlite3.connect(tmp_path / "vault.db")
    assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM mappings").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM surface_forms").fetchone()[0] == 0
    conn.close()
    with pytest.raises(VaultError):
        vault.load(session_id)


def test_purge_removes_the_bytes_from_the_database_files(vault: Vault, tmp_path: Path) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", SECRET_VALUE, [SECRET_VALUE], {})
    conn = sqlite3.connect(tmp_path / "vault.db")
    blobs = [row[0] for row in conn.execute("SELECT ciphertext FROM mappings")]
    blobs += [row[0] for row in conn.execute("SELECT ciphertext FROM surface_forms")]
    conn.close()
    assert blobs

    vault.purge(session_id)

    raw = b"".join(path.read_bytes() for path in sorted(tmp_path.glob("vault.db*")))
    for blob in blobs:
        assert blob not in raw
    assert b"<PERSON_001>" not in raw
    assert session_id.encode("ascii") not in raw


def test_purge_unknown_session_is_silent(vault: Vault) -> None:
    vault.purge("does-not-exist")


def test_purge_older_than_keeps_recent_sessions(vault: Vault, tmp_path: Path) -> None:
    old = vault.create_session("sha", "cfg")
    vault.store(old, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller"], {})
    recent = vault.create_session("sha", "cfg")
    _backdate(tmp_path / "vault.db", old, days=5)
    assert vault.purge_older_than(1) == 1
    assert [info.id for info in vault.list_sessions()] == [recent]
    conn = sqlite3.connect(tmp_path / "vault.db")
    assert conn.execute("SELECT count(*) FROM mappings").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM surface_forms").fetchone()[0] == 0
    conn.close()


def test_purge_older_than_zero_removes_backdated_sessions(vault: Vault, tmp_path: Path) -> None:
    first = vault.create_session("sha", "cfg")
    second = vault.create_session("sha", "cfg")
    _backdate(tmp_path / "vault.db", first, days=1)
    _backdate(tmp_path / "vault.db", second, days=1)
    assert vault.purge_older_than(0) == 2
    assert vault.list_sessions() == []


def test_list_sessions_reports_token_count_and_created_at(vault: Vault) -> None:
    first = vault.create_session("sha1", "cfg")
    vault.store(first, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", [], {})
    vault.store(first, "<PERSON_002>", "PERSON_LAST_NAME", "Schmidt", [], {})
    second = vault.create_session("sha2", "cfg")
    sessions = {info.id: info for info in vault.list_sessions()}
    assert sessions[first].token_count == 2
    assert sessions[second].token_count == 0
    assert datetime.fromisoformat(sessions[first].created_at).tzinfo is not None


def test_sessions_are_independent(vault: Vault) -> None:
    first = vault.create_session("sha1", "cfg")
    second = vault.create_session("sha2", "cfg")
    vault.store(first, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", [], {})
    vault.store(second, "<PERSON_001>", "PERSON_LAST_NAME", "Schmidt", [], {})
    assert vault.load(first)["<PERSON_001>"].value == "Müller"
    assert vault.load(second)["<PERSON_001>"].value == "Schmidt"


def test_session_id_is_hex_and_unique(vault: Vault) -> None:
    ids = {vault.create_session("sha", "cfg") for _ in range(5)}
    assert len(ids) == 5
    for session_id in ids:
        assert len(session_id) == 32
        int(session_id, 16)


def test_get_or_create_session_returns_the_same_id_for_one_key(vault: Vault) -> None:
    first = vault.get_or_create_session("conv-1", "cfg")
    assert vault.get_or_create_session("conv-1", "cfg") == first
    assert vault.get_or_create_session("conv-2", "cfg") != first


def test_get_or_create_session_warns_when_the_config_hash_differs(
    vault: Vault, capsys: pytest.CaptureFixture[str]
) -> None:
    first = vault.get_or_create_session("conv-1", "cfg-a")
    capsys.readouterr()

    assert vault.get_or_create_session("conv-1", "cfg-b") == first
    assert "configuration" in capsys.readouterr().err

    assert vault.get_or_create_session("conv-1", "cfg-a") == first
    assert capsys.readouterr().err == ""


def test_find_session_returns_none_for_unknown_key(vault: Vault) -> None:
    assert vault.find_session("conv-1") is None
    session_id = vault.get_or_create_session("conv-1", "cfg")
    assert vault.find_session("conv-1") == session_id


def test_external_key_is_unique_and_anonymous_sessions_stay_allowed(
    vault: Vault, tmp_path: Path
) -> None:
    vault.get_or_create_session("conv-1", "cfg")
    vault.create_session("sha", "cfg")
    vault.create_session("sha", "cfg")
    conn = sqlite3.connect(tmp_path / "vault.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO sessions (id, created_at, doc_sha256, config_hash, external_key) "
            "VALUES ('x', 'now', '', 'cfg', 'conv-1')"
        )
    conn.close()


def test_old_database_without_external_key_is_migrated(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        "CREATE TABLE sessions (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, "
        "doc_sha256 TEXT NOT NULL, config_hash TEXT NOT NULL);"
        "INSERT INTO sessions VALUES ('old', '2026-01-01T00:00:00+00:00', 'sha', 'cfg');"
    )
    conn.commit()
    conn.close()

    with Vault(db_path, tmp_path / "vault.key") as migrated:
        assert migrated.find_session("conv-1") is None
        session_id = migrated.get_or_create_session("conv-1", "cfg")
        assert [info.id for info in migrated.list_sessions()] == ["old", session_id]


def test_max_counters_uses_the_base_label(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_FEMALE_001>", "PERSON_LAST_NAME", "Müller", [], {})
    vault.store(session_id, "<PERSON_MALE_004>", "PERSON_LAST_NAME", "Schmidt", [], {})
    vault.store(session_id, "<IBAN_002>", "IBAN", "DE89", [], {})
    vault.store(session_id, "<JWT_REDACTED>", "JWT", "x", [], {})

    assert vault.max_counters(session_id) == {"PERSON": 4, "IBAN": 2}


def test_max_counters_is_empty_for_a_fresh_session(vault: Vault) -> None:
    assert vault.max_counters(vault.create_session("sha", "cfg")) == {}


def test_delete_tokens_removes_mappings_and_surface_forms(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller"], {})
    vault.store(session_id, "<IBAN_001>", "IBAN", "DE89", ["DE89"], {})

    vault.delete_tokens(session_id, ["<IBAN_001>"])

    assert set(vault.load(session_id)) == {"<PERSON_001>"}


def test_store_rejects_a_second_value_for_the_same_token(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", [], {})

    with pytest.raises(VaultError) as excinfo:
        vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", SECRET_VALUE, [], {})

    assert "token already assigned" in str(excinfo.value)
    assert SECRET_VALUE not in str(excinfo.value)
    assert vault.load(session_id)["<PERSON_001>"].value == "Müller"


def test_store_replaces_the_surface_forms_of_an_unchanged_value(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller", "MÜLLER"], {})

    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller"], {})

    assert vault.load(session_id)["<PERSON_001>"].surface_forms == ["Müller"]


def test_append_surface_forms_keeps_the_existing_order(vault: Vault) -> None:
    session_id = vault.create_session("sha", "cfg")
    vault.store(session_id, "<PERSON_001>", "PERSON_LAST_NAME", "Müller", ["Müller"], {})

    vault.append_surface_forms(session_id, "<PERSON_001>", ["MÜLLER", "Mueller"])

    entry = vault.load(session_id)["<PERSON_001>"]
    assert entry.surface_forms == ["Müller", "MÜLLER", "Mueller"]
    assert entry.value == "Müller"
