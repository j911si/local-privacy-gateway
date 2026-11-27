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
