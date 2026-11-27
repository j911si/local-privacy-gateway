"""Keys outside `tool_use.input` are rescanned and never logged in clear (R2-06#2)."""

from __future__ import annotations

import gc
import json
import signal
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import audit_trail, transform

from ._send import BASE, CONVERSATION, IBAN, MAIL, send


def _tool(schema: dict[str, Any]) -> dict[str, Any]:
    return {
        **BASE,
        "tools": [{"name": "T", "description": "Ein Werkzeug.", "input_schema": schema}],
    }


KEY_CASES = {
    "top_level": {**BASE, MAIL: "x"},
    "top_level_number": {**BASE, MAIL: 1},
    "tool_schema_property": _tool({"type": "object", "properties": {MAIL: {"type": "string"}}}),
    "metadata": {**BASE, "metadata": {**BASE["metadata"], MAIL: True}},
    "message_field": {
        **BASE,
        "messages": [{"role": "user", "content": "hallo", MAIL: None}],
    },
    "block_field": {
        **BASE,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hallo", MAIL: 2}]}],
    },
    "nested_iban": {**BASE, "x_extra": {"a": {f"IBAN {IBAN}": []}}},
}
LOGGED = {
    "top_level_forwarded": ({**BASE, "x_note": "x"}, "x_note", {"unchecked_fields": "allow"}),
    "top_level_mail": ({**BASE, MAIL: "x"}, MAIL, {"unchecked_fields": "allow"}),
    "schema_blocked": (
        _tool(
            {
                "type": "object",
                "properties": {MAIL: {"type": "string", "description": f"IBAN {IBAN}"}},
            }
        ),
        MAIL,
        {},
    ),
    "session_key_blocked": ({**BASE, CONVERSATION: MAIL}, CONVERSATION, {}),
    "session_key_allowed": (
        {**BASE, CONVERSATION: MAIL},
        CONVERSATION,
        {"unchecked_fields": "allow"},
    ),
}


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(KEY_CASES))
async def test_a_sensitive_key_blocks_before_the_upstream(
    gateway: Gateway, tmp_path: Path, case: str
) -> None:
    run = await send(gateway, tmp_path, KEY_CASES[case])

    assert run.status == 422
    assert run.sent == []
    (entry,) = run.entries
    assert entry["verdict"] == "blocked"
    assert any(item["path"].endswith("#key") for item in entry["outgoing"]["rescan"]["findings"])


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(KEY_CASES))
async def test_with_allow_the_key_is_forwarded_and_reported(
    gateway: Gateway, tmp_path: Path, case: str
) -> None:
    run = await send(gateway, tmp_path, KEY_CASES[case], unchecked_fields="allow")

    assert run.status == 200
    (entry,) = run.entries
    assert entry["verdict"] == "ok_with_unchecked_findings"


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(LOGGED))
async def test_a_key_never_reaches_the_audit_log(
    gateway: Gateway, tmp_path: Path, case: str
) -> None:
    body, secret, overrides = LOGGED[case]

    run = await send(gateway, tmp_path, body, **overrides)

    assert run.entries
    log = json.dumps(run.entries)
    assert secret not in log
    assert "<key>" in log


@pytest.mark.asyncio
async def test_plain_property_names_of_a_tool_schema_do_not_block(
    gateway: Gateway, tmp_path: Path
) -> None:
    names = ["file_path", "old_string", "replace_all", "command", "timeout", "run_in_background"]
    schema = {
        "type": "object",
        "properties": {name: {"type": "string", "description": "x"} for name in names},
        "required": names[:2],
    }
    run = await send(gateway, tmp_path, _tool(schema))

    assert run.status == 200
    (entry,) = run.entries
    assert entry["verdict"] == "ok"


def test_schema_keys_stay_readable_and_others_become_placeholders() -> None:
    path = ("tools", 0, "input_schema", "properties", "file_path", "description")

    assert transform.format_path(path) == "tools[0].input_schema.properties.<key>.description"
    assert transform.format_path((MAIL, transform.KEY_OF)) == "<key>#key"
    assert transform.format_path(("metadata", "user_id")) == "metadata.user_id"


def test_schema_keys_are_not_scanned_as_keys() -> None:
    leaves = audit_trail.scannable_strings({**BASE, "x_note": "y"})
    keys = [leaf.text for leaf in leaves if leaf.path[-1] is transform.KEY_OF]

    assert keys == ["x_note"]


def _alarm(signum: int, frame: object) -> None:
    raise TimeoutError("key collection did not finish in time")


def _timed(body: dict[str, Any]) -> float:
    """Best of three; the cyclic GC is paused so its pauses over many tuples do not count."""
    best = float("inf")
    gc.collect()
    gc.disable()
    try:
        for _ in range(3):
            started = time.perf_counter()
            audit_trail.scannable_strings(body)
            transform.collect_unchecked(body)
            best = min(best, time.perf_counter() - started)
    finally:
        gc.enable()
    return best


def _wide(n: int) -> dict[str, Any]:
    return {**BASE, "x_extra": {f"k{index}": {"v": 1} for index in range(n)}}


def test_collecting_keys_is_linear() -> None:
    n = 20_000
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(30)
    try:
        small = _timed(_wide(n))
        large = _timed(_wide(4 * n))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    print(f"key collection n={n}: {small:.4f}s, 4n: {large:.4f}s, factor {large / small:.2f}")
    assert large < 5.0
    assert large / small < 8
