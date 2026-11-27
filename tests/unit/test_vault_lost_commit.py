"""Mappings lost with the last commit (power loss under synchronous=NORMAL) never yield plaintext."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import AuditConfig, Config, VaultConfig, load_config
from privacy_gateway.model import RestoreError

FIRST = "IBAN DE89 3704 0044 0532 0130 00, Mail erika.beispiel@firma-test.de"
SECOND = "IBAN DE02 1203 0000 0000 2020 51, Mail jonas.test@beispiel-firma.de"
LOST = ("DE02 1203 0000 0000 2020 51", "jonas.test@beispiel-firma.de")
NEW_IBAN = "DE44 5001 0517 5407 3249 31"


def _config(default_config: Config, tmp_path: Path) -> Config:
    return replace(
        default_config,
        vault=VaultConfig(tmp_path / "vault.db", tmp_path / "vault.key"),
        audit=AuditConfig(None),
    )


def _pseudonymize(config: Config, text: str) -> str:
    with Gateway(config) as gateway:
        return gateway.session("conv").pseudonymize(text)


def _vault_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("vault.db*"))


@pytest.fixture
def lost_second_commit(default_config: Config, tmp_path: Path) -> tuple[Config, str]:
    """The second request reached the upstream, its vault commit did not reach the disk."""
    config = _config(default_config, tmp_path)
    _pseudonymize(config, FIRST)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    for path in _vault_files(tmp_path):
        shutil.copy2(path, snapshot / path.name)
    sent = _pseudonymize(config, SECOND)
    for path in _vault_files(tmp_path):
        path.unlink()
    for path in _vault_files(snapshot):
        shutil.copy2(path, tmp_path / path.name)
    return config, sent


def test_answer_with_lost_tokens_keeps_placeholders(lost_second_commit: tuple[Config, str]) -> None:
    config, sent = lost_second_commit
    assert all(value not in sent for value in LOST)
    with Gateway(config) as gateway:
        session = gateway.session("conv")
        lenient = session.restore(f"Antwort zu {sent}", mode="lenient")
        assert lenient.unknown_tokens
        assert all(value not in lenient.text for value in LOST)
        with pytest.raises(RestoreError):
            session.restore(f"Antwort zu {sent}", mode="strict")


def test_new_value_never_reuses_a_lost_token(lost_second_commit: tuple[Config, str]) -> None:
    config, sent = lost_second_commit
    lost_iban = next(token for token in sent.split() if token.startswith("<IBAN_"))
    history = f"Assistent schrieb: {lost_iban}. Nutzer: bitte an {NEW_IBAN} ueberweisen"
    with Gateway(config) as gateway:
        session = gateway.session("conv")
        out = session.pseudonymize(history)
        assert NEW_IBAN not in out
        assert out.count(lost_iban) == 1
        assert not session.rescan(out)
        restored = session.restore(f"Gemeint ist {lost_iban}.", mode="lenient").text
        assert NEW_IBAN not in restored
        assert lost_iban in restored


CHILD = """
import os, signal, sys
from privacy_gateway import Gateway
gateway = Gateway()
print(gateway.session("conv").pseudonymize(sys.argv[1]), flush=True)
os.kill(os.getpid(), signal.SIGKILL)
"""


def test_killed_process_keeps_its_committed_mappings(tmp_path: Path) -> None:
    paths = {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(tmp_path / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(tmp_path / "vault.key"),
        "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }
    env = {key: value for key, value in os.environ.items() if not key.startswith("PGW_")}
    env.update(paths, HOME=str(tmp_path))
    child = subprocess.run(
        [sys.executable, "-c", CHILD, SECOND], env=env, capture_output=True, text=True, check=False
    )
    assert child.returncode == -signal.SIGKILL
    with Gateway(load_config(env=paths)) as gateway:
        restored = gateway.session("conv").restore(child.stdout.strip(), mode="strict").text
    assert all(value in restored for value in LOST)
