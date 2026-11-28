from __future__ import annotations

import gc
import inspect
import os
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from types import ModuleType

import pytest
from isolation_guard import Guard, GuardPlugin, protected_roots, real_homes

from privacy_gateway.config import Config, load_config

pytest_plugins = ("pytester",)

GUARD = Guard(roots=protected_roots(os.environ), homes=real_homes(os.environ))
GUARD.install()


def pytest_configure(config: pytest.Config) -> None:
    config.pluginmanager.register(GuardPlugin(GUARD), "isolation-guard")


@cache
def _measures_time(module: ModuleType) -> bool:
    try:
        return "time.process_time()" in inspect.getsource(module)
    except (OSError, TypeError):
        return False


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    """Timing tests run with the cyclic GC paused after a collection.

    GC pauses depend on the heap that earlier tests left, not on the input of the measured
    call, so in a full run they made a linear scan look superlinear.
    """
    module = getattr(item, "module", None)
    if module is None or not _measures_time(module) or not gc.isenabled():
        yield
        return
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


SKIP_USER_CONFIG_ENV = {"PGW_SKIP_USER_CONFIG": "1"}
HOME_DIRS = {
    "XDG_CONFIG_HOME": ".config",
    "XDG_DATA_HOME": ".local/share",
    "XDG_STATE_HOME": ".local/state",
    "XDG_CACHE_HOME": ".cache",
}
UNSET_ENV = ("PGW_CONFIG", "PGW_PROXY_DEBUG_DIR", "PGW_PROXY_DEBUG_ORIGINALS")


@pytest.fixture(autouse=True)
def _audit_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep the daily proxy audit log of every test inside its tmp_path.

    HOME and the XDG directories point into tmp_path as well, so a test that drops one of
    the PGW_* paths below falls back to a `~` default under tmp_path, never the user's own
    vault, key or audit log.
    """
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    for name, relative in HOME_DIRS.items():
        monkeypatch.setenv(name, str(home / relative))
    for name in UNSET_ENV:
        monkeypatch.delenv(name, raising=False)
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
