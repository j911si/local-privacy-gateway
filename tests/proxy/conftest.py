"""Shared fixtures for the proxy tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

TOKEN_TABLE = {
    "Frau Müller": "Frau <PERSON_FEMALE_001>",
    "DE89370400440532013000": "<IBAN_001>",
    "Alpenbank AG": "<CUSTOMER_NAME_001>",
}

ORIGINAL_VALUES = ("Frau Müller", "Müller", "DE89370400440532013000", "Alpenbank AG")


class FakeSession:
    """A `TextSession` backed by a fixed replacement table."""

    def __init__(self, table: dict[str, str] | None = None) -> None:
        self.table = dict(TOKEN_TABLE if table is None else table)
        self.pseudonymize_calls: list[list[str]] = []
        self.restore_calls: list[str] = []

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        self.pseudonymize_calls.append(list(texts))
        return [_replace_all(self.table, text) for text in texts]

    def restore_text(self, text: str) -> str:
        self.restore_calls.append(text)
        inverse = {token: value for value, token in self.table.items()}
        return _replace_all(inverse, text)


def _replace_all(table: dict[str, str], text: str) -> str:
    for source, target in table.items():
        text = text.replace(source, target)
    return text


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def fake_session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def request_body() -> dict:
    return load_fixture("request_claude_code.json")


@pytest.fixture
def response_body() -> dict:
    return load_fixture("response_tool_use.json")
