from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def gateway_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Redirect vault, key file and audit log into tmp_path and ignore the user config."""
    env = {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(tmp_path / "vault" / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(tmp_path / "vault" / "vault.key"),
        "PGW_AUDIT_LOG": str(tmp_path / "audit" / "audit.jsonl"),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return env


@pytest.fixture
def gateway(gateway_env: dict[str, str]) -> Iterator[Gateway]:
    """A gateway whose vault, key and audit log live inside tmp_path."""
    with Gateway() as instance:
        yield instance


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR
