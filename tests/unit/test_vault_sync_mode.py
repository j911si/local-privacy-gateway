"""The vault fsyncs at WAL checkpoints, not on every commit."""

from __future__ import annotations

from pathlib import Path

from privacy_gateway.vault import Vault


def test_wal_with_normal_sync(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "vault.key")
    try:
        assert vault._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert vault._conn.execute("PRAGMA synchronous").fetchone()[0] == 1
    finally:
        vault.close()

