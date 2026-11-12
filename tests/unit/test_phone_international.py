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
        "+49-171-2345678",
        "+49 30 / 1234567",
        "+1 415 555 0132",
        "+44 20 7946 0958",
        "+41 44 668 18 00",
        "+43 1 5131234",
        "+7 495 123 45 67",
        "+353 1 234 5678",
        "+420 224 123 456",
        "+48 22 123 45 67",
    ],
)
def test_international_number_is_found_without_context(
    default_config: Config, number: str
) -> None:
    text = f"Rückruf {number} bitte"
    assert stage_values(text, default_config) == [number]
    assert phone_classes(text, default_config) == [("PHONE", number)]


def test_number_in_brackets_and_at_the_end_of_a_line(default_config: Config) -> None:
    assert stage_values("Tel (+49 171 2345678)", default_config) == ["+49 171 2345678"]
    assert stage_values("a\nRuf +49 171 2345678\nb", default_config) == ["+49 171 2345678"]
    assert stage_values("Ruf +49 171 2345678.", default_config) == ["+49 171 2345678"]


@pytest.mark.parametrize(
    "text",
    [
        "+49 171 2345678",
        "a\n+49 171 2345678\nb",
        "+1 415 555 0132 ruft an",
        "Signatur\nAnnika Sommerfeld\n+49 30 12345678",
        "Kontaktliste:\n+49 30 12345678\n+49 151 23456789\n+43 1 58858-0",
        "Signatur\nAnnika Sommerfeld\n+49 30 12345678\nannika@kanzlei.example",
    ],
)
def test_number_in_column_zero_is_found_outside_a_diff(default_config: Config, text: str) -> None:
    assert stage_values(text, default_config) != []
    assert all(("PHONE", v) in phone_classes(text, default_config) for v in stage_values(
        text, default_config
    ))


@pytest.mark.parametrize(
    "text",
    [
        "@@ -1,3 +1,4 @@\n line\n+49 30 12345678 neue Zeile",
        "@@ -1,3 +1,4 @@\n+49 30 12345678",
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n foo\n+49 30 12345678",
        "@@ -1,2 +1,3 @@\n+49 passed, 3 failed\n+1 415 lines changed\n+44 20 files",
        "@@ -9,2 +9,3 @@\n+44 20 7946 0958 Zeilen\n+1 415 555 2671",
    ],
)
def test_number_in_column_zero_of_a_diff_block_is_not_found(
    default_config: Config, text: str
) -> None:
    assert stage_values(text, default_config) == []


@pytest.mark.parametrize(
    "text",
    [
        "+49 passed, 3 failed",
        "+1 415 lines changed",
        "+44 20 files",
        "@@ -1,3 +1,4 @@\n+49 passed, 3 failed\n+1 415 lines changed\n+44 20 files",
        "+2025-01-15 09:30:00 INFO",
        "x\n+2025-01-15 09:30:00 INFO\n+0200\n+15%\n+3.5\n=+86400000\n+1700000000",
    ],
)
def test_diff_excerpts_and_log_lines_give_no_finding(default_config: Config, text: str) -> None:
    assert phone_classes(text, default_config) == []


def test_compact_number_needs_a_context_word(default_config: Config) -> None:
    assert stage_values("Rückruf +4917123456789 bitte", default_config) == []
    assert phone_classes("Rückruf +4917123456789 bitte", default_config) == []
    assert phone_classes("Tel. +4917123456789", default_config) == [("PHONE", "+4917123456789")]
    assert phone_classes("Mobil: +4917123456789", default_config) == [
        ("MOBILE_PHONE", "+4917123456789")
    ]


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
        "Rückruf +4917123456789",
        "x = y +31536000",
        "timeout=+86400000 und +1700000000",
        "Wert a=+49 171 2345678",
    ],
)
def test_expressions_diffs_zones_and_numbers_are_no_phone(
    default_config: Config, text: str
) -> None:
    assert stage_values(text, default_config) == []
    assert [c for c, _ in phone_classes(text, default_config) if c == CLASS] == []


@pytest.mark.parametrize(
    "text",
    [
        "+2026-11-10: Fehler behoben",
        "+49152 65535",
        "+1700000000",
        "+31536000",
        "timeout=+86400000",
        "+12 345 678 Bytes",
        "x = y +31536000",
        "+2024/11/10 12:00",
        "+12-31-2024",
        "Zeile +12345678 hinzugefuegt",
        "+1 2 3 4 5 6 7 8",
        "+10000000",
        "+65536 4096",
        "version +20241110",
        "+33 44 55 66 77",
        "+90 180 270 360",
        "+2025-01-15 09:30:00 INFO start",
        "+27017 27018 27019",
        "+998244353",
        "+3141592653",
        "+255 255 255 0",
    ],
)
def test_logs_numbers_and_dates_are_no_phone(default_config: Config, text: str) -> None:
    """The 21 false positives from the acceptance run, bare and after a word."""
    for variant in (text, f"Ruf {text}", f"Ruf ({text})"):
        assert stage_values(variant, default_config) == []
        assert phone_classes(variant, default_config) == []


@pytest.mark.parametrize(
    "number",
    ["(+49) 30 1234567", "(+49) 30 12345678", "0049 30 1234567", "0049 30 12345678", "0041 44 668 18 00"],
)
def test_bracketed_plus_and_double_zero_prefix_are_found(
    default_config: Config, number: str
) -> None:
    for text in (f"Rückruf {number} bitte", f"contact: {number}", number):
        assert stage_values(text, default_config) == [number]


@pytest.mark.parametrize(
    "text",
    [
        "0049",
        "0049 30",
        "00 49 30",
        "1.0049 30 1234567",
        "x0049 30 1234567",
        "0099 30 1234567",
        "00123456789",
        "0049 30 1234567890123",
        "(+49) 30",
        "(+49)",
        "f(+49) 30 1234567",
        "(+999) 30 1234567",
        "002026 11 10 12 00",
        "000 111 222 333",
    ],
)
def test_bracketed_plus_and_double_zero_negatives(default_config: Config, text: str) -> None:
    assert stage_values(text, default_config) == []


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
    ["+49 171 2345678", "+1 415 555 0132", "+49 (0) 171 2345678", "+41 44 668 18 00"],
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
        "+4917123456789",
        "+49152 65535",
        "+12-31-2024",
        "+33 44 55 66 77",
        "+90 180 270 360",
        "+255 255 255 0",
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


def test_one_number_in_two_spellings_gets_one_token_per_spelling(gateway: Gateway) -> None:
    session = gateway.session()
    first = session.pseudonymize("Telefon: +49 171 2345678 ist erreichbar.")
    second = session.pseudonymize("Ruf an unter +49 171 2345678 oder +491712345678.")
    assert first == "Telefon: <PHONE_001> ist erreichbar."
    assert second == "Ruf an unter <PHONE_001> oder <PHONE_002>."
    assert session.restore_text(second) == "Ruf an unter +49 171 2345678 oder +491712345678."


def test_compact_spelling_of_a_known_number_gets_its_own_token(gateway: Gateway) -> None:
    """The compact form is found by the session stage and restores to its exact spelling."""
    session = gateway.session()
    session.pseudonymize("Telefon: +49 171 2345678 ist erreichbar.")
    second = session.pseudonymize("Ruf an unter +49 171 2345678 oder +491712345678.")
    assert "2345678" not in second
    assert second.count("<PHONE_001>") == 1 and second.count("<PHONE_002>") == 1


@pytest.mark.parametrize(
    "text",
    [
        "Kontakte:\n- Zentrale\n+49 30 12345678",
        "--- Kontakt ---\n+49 30 12345678",
        "Anna\n+49 171 2345678\n-> bitte anrufen",
        "+ Neu: Rückrufnummer\n+49 30 12345678",
    ],
)
def test_a_list_or_signature_line_next_to_the_number_is_no_diff(
    default_config: Config, text: str
) -> None:
    assert len(stage_values(text, default_config)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "Vergleich:\n--- alt\n+++ neu\nErreichbar:\n+49 30 12345678",
        "--- alt\n+++ neu\n\n+49 30 12345678",
        "@@ -1,2 +1,2 @@\n x\n\nSignatur\nAnna\n+49 30 12345678",
    ],
)
def test_a_header_does_not_cover_a_number_after_prose_or_a_blank_line(
    default_config: Config, text: str
) -> None:
    assert len(stage_values(text, default_config)) == 1


def test_added_line_with_a_plus_number_inside_a_hunk_is_found(default_config: Config) -> None:
    text = "@@ -1,2 +1,2 @@\n-+49 30 12345678\n++49 30 12345679"
    assert stage_values(text, default_config) == ["+49 30 12345678", "+49 30 12345679"]


@pytest.mark.parametrize("text", ["+++49 30 12345678", "a ++49 30 12345678", "x\n+++49 30 12345678"])
def test_more_plus_signs_are_still_no_number(default_config: Config, text: str) -> None:
    assert stage_values(text, default_config) == []


@pytest.mark.parametrize(
    "text",
    [
        "diff --git a/x b/x\nKontakt:\n+49 30 12345678",
        "@@ -1 +1 @@\n+foo\nRuf an:\n+49 30 12345678",
    ],
)
def test_a_line_that_is_no_diff_line_ends_the_diff_block(
    default_config: Config, text: str
) -> None:
    assert stage_values(text, default_config) == ["+49 30 12345678"]
