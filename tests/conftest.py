from __future__ import annotations

from pathlib import Path

import pytest

from privacy_gateway.config import Config, load_config

SKIP_USER_CONFIG_ENV = {"PGW_SKIP_USER_CONFIG": "1"}


@pytest.fixture(autouse=True)
def _audit_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep the daily proxy audit log of every test inside its tmp_path."""
    directory = tmp_path / "audit-v2" / "audit"
    monkeypatch.setenv("PGW_AUDIT_LOG_DIR", str(directory))
    for name, value in _private_paths(tmp_path).items():
        monkeypatch.setenv(name, value)
    return directory


def _private_paths(tmp_path: Path) -> dict[str, str]:
    """Vault, key and audit file under tmp_path, never the user's real ones."""
    root = tmp_path / "pgw-private"
    return {
        "PGW_VAULT_DB": str(root / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(root / "vault.key"),
        "PGW_AUDIT_LOG": str(root / "audit.jsonl"),
    }


@pytest.fixture
def default_config(tmp_path: Path) -> Config:
    """Bundled defaults only; the user's ~/.config file is ignored."""
    return load_config(env={**SKIP_USER_CONFIG_ENV, **_private_paths(tmp_path)})
