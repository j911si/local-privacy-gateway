"""Object keys that collide after replacement: no false block, no leak, exact roundtrip."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import audit_trail, transform

INTRO = "Frau Annika Sommerfeld, Herr Wendland."


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


def _send(gateway: Gateway, payload: dict) -> tuple[dict, audit_trail.Rescan, Any]:
    session = gateway.session("keys")
    session.pseudonymize_many([INTRO])
    block = {"type": "tool_use", "id": "t", "name": "X", "input": payload}
    body = {
        "messages": [
            {"role": "user", "content": INTRO},
            {"role": "assistant", "content": [block]},
            {"role": "user", "content": "go on"},
        ]
    }
    new_body, _ = transform.pseudonymize_request(
        body, audit_trail.Recorder(session), include_system=True, notice=False
    )
    checked = audit_trail.checked_refs(transform, body, True, False)
    rescan = audit_trail.rescan_body(session, new_body, checked, None)
    return new_body["messages"][1]["content"][0]["input"], rescan, session


def _roundtrip(session: Any, sent: dict) -> dict:
    class Restorer:
        def restore_text(self, text: str) -> str:
            return session.restore(text, mode="lenient").text

    reply = {"content": [{"type": "tool_use", "id": "t", "name": "X", "input": sent}]}
    return transform.restore_response(reply, Restorer())["content"][0]["input"]


def test_two_redacted_keys_are_not_blocked_and_leak_nothing(gateway: Gateway) -> None:
    sent, rescan, _ = _send(gateway, {"password=abc12345": 1, "password=xyz98765": 2})

    assert rescan.blocking == []
    assert len(sent) == 2
    assert "abc12345" not in json.dumps(sent)
    assert "xyz98765" not in json.dumps(sent)


def test_two_redacted_keys_come_back_distinct_with_their_values(gateway: Gateway) -> None:
    sent, _, session = _send(gateway, {"password=abc12345": 1, "password=xyz98765": 2})

    back = _roundtrip(session, sent)

    assert list(back.values()) == [1, 2]
    assert len(back) == 2


def test_a_plaintext_key_with_a_hash_suffix_is_still_replaced(gateway: Gateway) -> None:
    sent, rescan, _ = _send(gateway, {"password=abc12345#2": 1})

    assert rescan.blocking == []
    assert "abc12345" not in json.dumps(sent)


def test_a_suffixed_key_with_a_real_value_in_front_is_still_found(gateway: Gateway) -> None:
    session = gateway.session("keys")
    leaves = [transform.TextRef((transform.KeyAt(0),), "password=abc12345<IBAN_001>#2")]

    hits = audit_trail.scan(session, leaves)

    assert hits


@pytest.mark.parametrize(
    "payload",
    [
        {"<PERSON_001>#2": 1, "Herr Wendland": 2, "Herr  Wendland": 3},
        {"Herr Wendland": 1, "Herr  Wendland": 2, "<PERSON_001>#2": 3},
        {"<PERSON_001>#2": 1, "<PERSON_001>": 2, "Herr Wendland": 3, "Herr  Wendland": 4},
        {"Herr Wendland": 1, "Herr  Wendland": 2, "Herr   Wendland": 3},
    ],
)
def test_keys_that_look_like_suffixed_tokens_roundtrip_byte_equal(
    gateway: Gateway, payload: dict
) -> None:
    sent, rescan, session = _send(gateway, payload)

    back = _roundtrip(session, sent)

    assert rescan.blocking == []
    assert json.dumps(back) == json.dumps(payload)
