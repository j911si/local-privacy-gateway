"""The vault fsyncs at WAL checkpoints, not per commit, and its warnings name no session."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from privacy_gateway.vault import Vault


def test_wal_with_normal_sync(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        assert vault._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert vault._conn.execute("PRAGMA synchronous").fetchone()[0] == 1
    finally:
        vault.close()



def test_config_warning_names_no_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        session = vault.get_or_create_session("named", "cfg-a")
        capsys.readouterr()
        assert vault.get_or_create_session("named", "cfg-b") == session
        err = capsys.readouterr().err
        assert "different configuration" in err
        assert session not in err
    finally:
        vault.close()


def test_purge_commits_with_full_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        session = vault.create_session("", "cfg")
        seen: list[int] = []
        commit = vault._conn.commit

        class Spy:
            def __getattr__(self, name: str) -> object:
                return getattr(conn, name)

            def commit(self) -> None:
                seen.append(conn.execute("PRAGMA synchronous").fetchone()[0])
                commit()

        conn = vault._conn
        monkeypatch.setattr(vault, "_conn", Spy())
        vault.purge(session)
        assert seen[0] == 2
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1
    finally:
        monkeypatch.undo()
        vault.close()


def _reclaims(vault: Vault, monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    calls: list[bool] = []
    reclaim = vault._reclaim
    monkeypatch.setattr(vault, "_reclaim", lambda: (calls.append(True), reclaim())[1])
    return calls


def test_purge_of_a_session_without_mappings_skips_vacuum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        calls = _reclaims(vault, monkeypatch)
        vault.purge(vault.create_session("", "cfg"))
        assert calls == []
        session = vault.create_session("", "cfg")
        vault.store(session, "<EMAIL_001>", "EMAIL", "a@firma-test.de", [], {})
        vault.purge(session)
        assert calls == [True]
    finally:
        vault.close()


def test_failed_purge_rolls_back_and_keeps_the_error(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        session = vault.create_session("", "cfg")
        vault.store(session, "<EMAIL_001>", "EMAIL", "a@firma-test.de", ["A@firma-test.de"], {})
        vault._conn.execute(
            "CREATE TRIGGER stop BEFORE DELETE ON mappings BEGIN SELECT RAISE(ABORT, 'x'); END"
        )
        vault._conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            vault.purge(session)
        assert not vault._conn.in_transaction
        assert vault._conn.execute("PRAGMA synchronous").fetchone()[0] == 1
        vault._conn.execute("DROP TRIGGER stop")
        vault.create_session("", "cfg")
        assert vault.load(session)["<EMAIL_001>"].surface_forms == ["A@firma-test.de"]
    finally:
        vault.close()


def test_purge_of_a_named_session_without_mappings_still_reclaims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        calls = _reclaims(vault, monkeypatch)
        vault.purge(vault.get_or_create_session("demo-kunde-042", "cfg"))
        assert calls == [True]
    finally:
        vault.close()
