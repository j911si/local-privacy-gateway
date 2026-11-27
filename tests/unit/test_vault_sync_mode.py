"""The vault fsyncs at WAL checkpoints, not per commit, and its warnings name no session."""

from __future__ import annotations

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
