"""International phone numbers (+ and country code) are found without a context word."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config, load_config
from privacy_gateway.detect import Pipeline
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.detect.validators import phone_international_valid

CLASS = "PHONE_INTERNATIONAL"


def stage_values(text: str, config: Config) -> list[str]:
    findings = PatternStage().run(text, config, [])
    return [text[f.span.start : f.span.end] for f in findings if f.data_class == CLASS]


def phone_classes(text: str, config: Config) -> list[tuple[str, str]]:
    report = Pipeline(config).run(text)
    return [
        (f.data_class, text[f.span.start : f.span.end])
        for f in report.findings
        if "PHONE" in f.data_class
    ]


@pytest.mark.parametrize(
    "number",
    [
        "+49 171 2345678",
        "+49 (0) 171 2345678",
        "+49(0)171-2345678",
        "+49 (171) 2345678",
        "+4917123456789",
        "+49-171-2345678",
        "+49 30 / 1234567",
        "+1 415 555 0132",
        "+44 20 7946 0958",
        "+41 44 668 18 00",
        "+43 1 5131234",
        "+7 495 123 45 67",
        "+353 1 234 5678",
    ],
)
def test_international_number_is_found_without_context(
    default_config: Config, number: str
) -> None:
    text = f"Rückruf {number} bitte"
    assert stage_values(text, default_config) == [number]
    assert phone_classes(text, default_config) == [("PHONE", number)]


def test_number_at_line_edges_and_in_brackets(default_config: Config) -> None:
    assert stage_values("+49 171 2345678", default_config) == ["+49 171 2345678"]
    assert stage_values("(+49 171 2345678)", default_config) == ["+49 171 2345678"]
    assert stage_values("a\n+49 171 2345678\nb", default_config) == ["+49 171 2345678"]
    assert stage_values("+49 171 2345678.", default_config) == ["+49 171 2345678"]


@pytest.mark.parametrize(
    "text",
    [
        "+1",
        "+49",
        "+49 171",
        "a +49 171",
        "x+4917123",
        "x+49 171 2345678",
        "+123 -45",
        "@@ -1,5 +1,7 @@",
        "+0200",
        "UTC+01:00",
        "2026-11-11T10:00:00+0200",
        "+15%",
        "+3.5",
        "+10 points",
        "+999 123 4567",
        "+0 171 2345678",
        "+49 171 2345678901234",
        "+49 171 234567 89 12 34",
        "Version 1.2+3456789012",
        "0171 2345678",
        "Hotel 0211 4455667",
    ],
)
def test_expressions_diffs_zones_and_numbers_are_no_phone(
    default_config: Config, text: str
) -> None:
    assert stage_values(text, default_config) == []
    assert [c for c, _ in phone_classes(text, default_config) if c == CLASS] == []


def test_national_number_still_needs_a_context_word(default_config: Config) -> None:
    assert phone_classes("Rückruf 0171 2345678", default_config) == []
    assert [c for c, _ in phone_classes("Tel. 0171 2345678", default_config)] == ["PHONE"]


def test_context_word_keeps_the_plain_phone_class(default_config: Config) -> None:
    assert phone_classes("Tel. +49 171 2345678", default_config) == [
        ("PHONE", "+49 171 2345678")
    ]
    assert phone_classes("Mobil: +49 171 2345678", default_config) == [
        ("MOBILE_PHONE", "+49 171 2345678")
    ]


@pytest.mark.parametrize(
    "value",
    ["+49 171 2345678", "+1 415 555 0132", "+49 (0) 171 2345678", "+4917123456789"],
)
def test_validator_accepts(value: str) -> None:
    assert phone_international_valid(value)


@pytest.mark.parametrize(
    "value",
    [
        "+49 171",
        "+1234567",
        "+0 171 2345678",
        "+999 123 4567",
        "+49 1712345678901234",
        "49 171 2345678",
    ],
)
def test_validator_rejects(value: str) -> None:
    assert not phone_international_valid(value)


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    for name, value in {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(tmp_path / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(tmp_path / "vault.key"),
        "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }.items():
        monkeypatch.setenv(name, value)
    with Gateway(load_config()) as instance:
        yield instance


def test_numbers_round_trip_through_the_gateway(gateway: Gateway) -> None:
    text = "Rückruf an +49 171 2345678 oder +44 20 7946 0958; Diff +123 -45, Zone +0200."
    result = gateway.pseudonymize(text)

    assert "2345678" not in result.text and "7946" not in result.text
    assert "<PHONE_001>" in result.text and "<PHONE_002>" in result.text
    assert "+123 -45" in result.text and "+0200" in result.text
    assert gateway.restore(result.text, result.session_id).text == text


def test_text_without_numbers_is_unchanged(gateway: Gateway) -> None:
    text = "x+4917123, +15% und +3.5, @@ -1,5 +1,7 @@, UTC+01:00"
    assert gateway.pseudonymize(text).text == text


def test_one_number_in_two_spellings_gets_one_token(gateway: Gateway) -> None:
    session = gateway.session()
    first = session.pseudonymize("Telefon: +49 171 2345678 ist erreichbar.")
    second = session.pseudonymize("Ruf an unter +49 171 2345678 oder +491712345678.")
    assert first == "Telefon: <PHONE_001> ist erreichbar."
    assert second == "Ruf an unter <PHONE_001> oder <PHONE_001>."
