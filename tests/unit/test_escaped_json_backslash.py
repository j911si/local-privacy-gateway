"""Escaped-JSON passwords that end in a literal backslash are redacted (R2-01#3)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from test_escaped_json import escaped
from test_regex_linearity import _hard_timeout, assert_linear, finditer  # noqa: F401

MARKER = "<PASSWORD_REDACTED>"
VALUES = [
    "Geheim42\\",
    "Geheim42\\\\",
    'Geh"eim42\\',
    'Geheim42"',
    "a1\\b2\"c3\\",
    "Geheim\\n42\\",
]


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def encoded(value: str, levels: int) -> str:
    for _ in range(levels + 1):
        value = json.dumps(value)[1:-1]
    return value


@pytest.mark.parametrize("levels", [1, 2, 3])
@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("extra", [True, False])
def test_password_ending_in_backslash_is_redacted_in_place(
    gateway: Gateway, value: str, levels: int, extra: bool
) -> None:
    document = {"password": value, "user": "bob"} if extra else {"password": value}
    text = "log: " + escaped(document, levels) + " end"
    session = gateway.session()
    out = session.pseudonymize(text)
    assert "Geh" not in out and "a1" not in out
    assert out == text.replace(encoded(value, levels), MARKER, 1)
    assert not session.rescan(out)


def test_json_in_json_password_with_trailing_backslash(gateway: Gateway) -> None:
    text = json.dumps({"payload": json.dumps({"password": "Geheim42\\"})})
    session = gateway.session()
    out = session.pseudonymize(text)
    assert "Geheim42" not in out
    assert not session.rescan(out)
    assert json.loads(json.loads(out)["payload"]) == {"password": MARKER}


@pytest.mark.parametrize(
    "text",
    [
        '{\\"password_hint\\": \\"Name of first pet\\"}',
        '{\\"path\\": \\"C:\\\\\\\\tmp\\\\\\\\\\"}',
        '{\\"user\\": \\"bob\\\\\\\\\\", \\"theme\\": \\"dark\\"}',
    ],
)
def test_lookalikes_with_backslashes_stay(gateway: Gateway, text: str) -> None:
    assert gateway.session().pseudonymize(text) == text


UNITS = [
    'password\\": \\"a1',
    'password\\": \\"a1\\\\\\\\',
    'password\\\\\\": \\\\\\"a1\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\',
    "\\\\",
    "\\",
]


@pytest.mark.parametrize("unit", UNITS)
def test_escaped_password_rule_stays_linear(default_config: Config, unit: str) -> None:
    pattern = re.compile(
        next(p for p in default_config.registry.get("PASSWORD").patterns if "(?P<q>" in p),
        re.MULTILINE,
    )
    assert_linear(finditer(pattern), lambda n: unit * (n // len(unit)))
    assert_linear(finditer(pattern), lambda n: 'password\\": \\"a1' + "\\" * n + " x")
    assert_linear(finditer(pattern), lambda n: ('password\\": \\"a1' + "\\" * 600) * (n // 615))
