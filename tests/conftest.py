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
    return directory


@pytest.fixture
def default_config() -> Config:
    """Bundled defaults only; the user's ~/.config file is ignored."""
    return load_config(env=SKIP_USER_CONFIG_ENV)
