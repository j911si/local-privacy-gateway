"""Rescan and the leak check apply the same exemptions for hits next to a token."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway, GatewaySession
from privacy_gateway.config import load_config


@pytest.fixture(scope="module")
def gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gateway]:
    base: Path = tmp_path_factory.mktemp("rescan")
    env = {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(base / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(base / "vault.key"),
        "PGW_AUDIT_LOG": str(base / "audit.jsonl"),
    }
    with Gateway(load_config(env=env)) as gw:
        yield gw


def _seeded(gateway: Gateway, *pairs: tuple[str, str]) -> GatewaySession:
    session_id = gateway.vault.create_session("", gateway.config.hash())
    numbers: dict[str, int] = {}
    for value, data_class in pairs:
        label = gateway.config.registry.label_for(data_class)
        numbers[label] = numbers.get(label, 0) + 1
        token = f"<{label}_{numbers[label]:03d}>"
        gateway.vault.store(session_id, token, data_class, value, [value], {})
    return GatewaySession(gateway, session_id)


def test_rescan_accepts_a_short_hit_that_touches_a_token(gateway: Gateway) -> None:
    session = _seeded(gateway, ("annika", "PERSON_USERNAME"))
    assert session.rescan("use <PERSON_001>::1;") == []


def test_rescan_still_reports_a_full_email_next_to_a_token(gateway: Gateway) -> None:
    session = _seeded(gateway, ("annika", "PERSON_USERNAME"))
    leaks = session.rescan("use <PERSON_001> mail max.mustermann@firma.de")
    assert [leak.data_class for leak in leaks] == ["EMAIL"]
