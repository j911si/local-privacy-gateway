"""Tests never touch the user's real vault, key or audit log (see tests/conftest.py)."""

from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy.settings import ProxySettings, audit_dir_for

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)

DEFAULT_PATHS = ("PGW_VAULT_DB", "PGW_VAULT_KEY_FILE", "PGW_AUDIT_LOG", "PGW_AUDIT_LOG_DIR")


def test_home_points_into_tmp_path(tmp_path: Path) -> None:
    assert Path.home() == tmp_path / "home"
    assert Path.home() != REAL_HOME


def test_the_bundled_defaults_land_under_the_test_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in DEFAULT_PATHS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    home = tmp_path / "home"

    with Gateway() as gateway:
        gateway.pseudonymize("Sehr geehrte Frau Müller")
        assert gateway.config.vault.db_path == home / ".local/share/privacy-gateway/vault.db"
        assert gateway.config.audit.path == home / ".local/share/privacy-gateway/audit.jsonl"

    assert (home / ".local/share/privacy-gateway/audit.jsonl").is_file()
    assert (home / ".local/share/privacy-gateway/vault.db").is_file()
    assert (home / ".config/privacy-gateway/vault.key").is_file()
    assert audit_dir_for(ProxySettings(), env={}) == home / ".local/state/privacy-gateway/audit"
