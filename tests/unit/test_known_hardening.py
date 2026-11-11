"""Known values that stick to other characters: rescan, substring sweep, escapes, neighbors."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway, GatewaySession
from privacy_gateway.config import load_config
from privacy_gateway.leakage import check_leakage
from privacy_gateway.model import DetectionReport, LeakageError, VaultEntry
from privacy_gateway.tokens import ANY_TOKEN

WENDLAND = ("Wendland", "PERSON_LAST_NAME")
ANNIKA = ("Annika", "PERSON_FIRST_NAME")


@pytest.fixture(scope="module")
def gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gateway]:
    base: Path = tmp_path_factory.mktemp("hardening")
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


def _plain(output: str) -> str:
    return ANY_TOKEN.sub("\x00", output).replace("\u200b", "").lower()


@pytest.mark.parametrize(
    "text",
    [
        "Wendland\u200bAnnika",
        "WendlandAnnika",
        "AnnikaWendland x",
        "wendlandannika",
        "WendlandWendland",
    ],
)
def test_two_known_values_without_separator_are_both_replaced(gateway: Gateway, text: str) -> None:
    session = _seeded(gateway, WENDLAND, ANNIKA)
    output = session.pseudonymize(text)
    assert "wendland" not in _plain(output)
    assert "annika" not in _plain(output)


def test_a_known_value_behind_a_zero_width_character_next_to_another_is_replaced(
    gateway: Gateway,
) -> None:
    session = _seeded(gateway, WENDLAND, ("Meier", "PERSON_LAST_NAME"))
    output = session.pseudonymize("Wendland\u200bMeier")
    assert output.count("<PERSON_") == 2
    assert session.restore(output).text == "Wendland\u200bMeier"


@pytest.mark.parametrize(
    ("value", "data_class", "text"),
    [
        ("annika", "PERSON_USERNAME", "annika2024"),
        ("Wendland", "PERSON_LAST_NAME", "RechnungWendland.pdf"),
        ("Wendland", "PERSON_LAST_NAME", "backup_Wendland"),
        ("Wendland", "PERSON_LAST_NAME", "7Wendland"),
    ],
)
def test_a_known_name_stuck_to_digits_or_a_case_change_is_replaced(
    gateway: Gateway, value: str, data_class: str, text: str
) -> None:
    session = _seeded(gateway, (value, data_class))
    output = session.pseudonymize(text)
    assert value.lower() not in _plain(output)
    assert session.restore(output).text == text


def test_a_name_inside_a_longer_word_is_left_alone(gateway: Gateway) -> None:
    session = _seeded(gateway, ("Stein", "PERSON_LAST_NAME"))
    output = session.pseudonymize("Steinbruch, Meilenstein und Stein")
    assert output.startswith("Steinbruch, Meilenstein und <PERSON_")


@pytest.mark.parametrize("escape", ["\\n", "\\t", "\\r"])
def test_a_known_value_after_a_literal_escape_is_replaced(gateway: Gateway, escape: str) -> None:
    session = _seeded(gateway, WENDLAND)
    text = f'printf "Name:{escape}Wendland{escape}"'
    output = session.pseudonymize(text)
    assert "wendland" not in _plain(output)
    assert session.restore(output).text == text


def test_a_literal_escaped_quote_before_a_known_value_is_replaced(gateway: Gateway) -> None:
    session = _seeded(gateway, WENDLAND)
    text = '{"a": \\"Wendland\\"}'
    output = session.pseudonymize(text)
    assert "wendland" not in _plain(output)
    assert session.restore(output).text == text


def test_ordinary_words_after_a_literal_escape_stay(gateway: Gateway) -> None:
    session = _seeded(gateway, WENDLAND)
    assert session.pseudonymize("nichts \\nichts \\tabelle") == "nichts \\nichts \\tabelle"


@pytest.mark.parametrize(
    "pairs",
    [
        [("hmu0a", "HOSTNAME"), ("rmgnß84a", "HOSTNAME")],
        [("änbf990a", "HOSTNAME"), ("sucdnhm.äbldts", "PERSON_USERNAME")],
    ],
)
def test_two_known_values_glued_together_do_not_block(
    gateway: Gateway, pairs: list[tuple[str, str]]
) -> None:
    session = _seeded(gateway, *pairs)
    text = pairs[0][0] + pairs[1][0] + "_"
    output = session.pseudonymize(text)
    assert not any(value.lower() in _plain(output) for value, _ in pairs)
    assert session.restore(output).text == text


def test_the_same_number_twice_in_a_row_is_replaced_twice(gateway: Gateway) -> None:
    session = _seeded(gateway, ("1558847146", "CUSTOMER_ID"))
    output = session.pseudonymize("15588471461558847146")
    assert "1558847146" not in _plain(output)
    assert session.restore(output).text == "15588471461558847146"


def test_a_three_letter_value_glued_to_a_longer_one_is_replaced(gateway: Gateway) -> None:
    session = _seeded(gateway, ("Lak", "PERSON_LAST_NAME"), ("nüfen552", "PERSON_USERNAME"))
    output = session.pseudonymize("a\nnüfen552\u200blAK\tb")
    assert "nüfen552" not in _plain(output)
    assert "lak" not in _plain(output)


def test_values_under_the_minimum_length_are_not_searched_inside_words(gateway: Gateway) -> None:
    session = _seeded(gateway, ("Lak", "PERSON_LAST_NAME"), ("1234", "CUSTOMER_ID"))
    text = "Laktat, Lak2 und 123456, 51234"
    assert session.pseudonymize(text) == text


def test_the_leak_check_flags_a_known_value_the_word_bound_search_misses(
    gateway: Gateway,
) -> None:
    registry = gateway.config.registry
    entries = {"<PERSON_001>": VaultEntry("Wendland", "PERSON_LAST_NAME", ["Wendland"], {})}

    def empty(_text: str) -> DetectionReport:
        return DetectionReport(findings=[], entities={}, stage_stats={})

    with pytest.raises(LeakageError):
        check_leakage("<PERSON_001> und Wendland2024", entries, empty, registry)
    check_leakage("<PERSON_001> und Wendlandstrasse", entries, empty, registry)
    check_leakage("Wendland2024", entries, empty, registry, sweep=False)
