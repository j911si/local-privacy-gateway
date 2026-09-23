from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.config import Config
from privacy_gateway.leakage import check_leakage
from privacy_gateway.model import DetectionReport, Finding, LeakageError, Span, VaultEntry

IBAN_SPACED = "DE89 3704 0044 0532 0130 00"
IBAN_PLAIN = "DE89370400440532013000"


def _entry(value: str, data_class: str, surface_forms: list[str] | None = None) -> VaultEntry:
    return VaultEntry(
        value=value,
        data_class=data_class,
        surface_forms=surface_forms if surface_forms is not None else [value],
        attributes={},
    )


def _empty_scan(text: str) -> DetectionReport:
    return DetectionReport(findings=[], entities={}, stage_stats={})


def _scan_for(value: str, data_class: str) -> Callable[[str], DetectionReport]:
    def scan(text: str) -> DetectionReport:
        start = text.index(value)
        finding = Finding(
            span=Span(start, start + len(value)),
            data_class=data_class,
            stage="pattern",
            confidence=0.95,
        )
        return DetectionReport(findings=[finding], entities={}, stage_stats={})

    return scan


def _with_policy(config: Config, name: str, policy: Policy) -> Config:
    classes = [
        replace(data_class, policy=policy) if data_class.name == name else data_class
        for data_class in config.registry
    ]
    return replace(config, registry=ClassRegistry(classes))


def test_clean_text_passes(default_config: Config) -> None:
    entries = {"<ACCOUNT_ID_001>": _entry("4711", "ACCOUNT_ID")}

    text = "<ACCOUNT_ID_001> is fine."

    assert check_leakage(text, entries, _empty_scan, default_config.registry) is None


def test_original_value_in_output_is_a_leak(default_config: Config) -> None:
    entries = {"<IBAN_001>": _entry(IBAN_PLAIN, "IBAN")}

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(f"IBAN {IBAN_PLAIN} ok", entries, _empty_scan, default_config.registry)

    assert [leak.kind for leak in excinfo.value.leaks] == ["original_value"]
    assert excinfo.value.leaks[0].data_class == "IBAN"


def test_short_numeric_value_is_a_leak(default_config: Config) -> None:
    entries = {"<ACCOUNT_ID_001>": _entry("4711", "ACCOUNT_ID")}

    with pytest.raises(LeakageError) as excinfo:
        check_leakage("Konto 4711", entries, _empty_scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "original_value"


def test_case_and_whitespace_variant_is_a_leak(default_config: Config) -> None:
    entries = {"<PERSON_001>": _entry("Anna Müller", "PERSON_FULL_NAME")}

    with pytest.raises(LeakageError) as excinfo:
        check_leakage("Hallo anna  müller!", entries, _empty_scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "original_value"


def test_digits_only_variant_is_a_leak(default_config: Config) -> None:
    entries = {"<IBAN_001>": _entry(IBAN_SPACED, "IBAN")}

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(f"IBAN {IBAN_PLAIN} ok", entries, _empty_scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "original_value"


def test_surface_form_is_searched_too(default_config: Config) -> None:
    entries = {"<PERSON_001>": _entry("Müller", "PERSON_LAST_NAME", ["Müller", "MÜLLER"])}

    with pytest.raises(LeakageError):
        check_leakage("Hier steht MÜLLER.", entries, _empty_scan, default_config.registry)


def test_value_inside_a_longer_word_is_no_leak(default_config: Config) -> None:
    entries = {"<COUNTRY_001>": _entry("Schweiz", "COUNTRY")}

    text = "die schweizerische Post"

    assert check_leakage(text, entries, _empty_scan, default_config.registry) is None


def test_value_inside_an_identifier_is_a_leak(default_config: Config) -> None:
    entries = {"<CUSTOMER_NAME_001>": _entry("northwind", "CUSTOMER_NAME")}

    with pytest.raises(LeakageError) as excinfo:
        check_leakage("project_northwind_x", entries, _empty_scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "original_value"


def test_genitive_form_of_a_value_is_a_leak(default_config: Config) -> None:
    entries = {"<PERSON_001>": _entry("Nikki", "PERSON_FULL_NAME")}

    with pytest.raises(LeakageError):
        check_leakage("Nikkis Quelle", entries, _empty_scan, default_config.registry)


def test_numeric_value_inside_a_word_is_a_leak(default_config: Config) -> None:
    entries = {"<ACCOUNT_ID_001>": _entry("4711", "ACCOUNT_ID")}

    with pytest.raises(LeakageError):
        check_leakage("AB4711CD", entries, _empty_scan, default_config.registry)


def test_word_value_as_a_whole_word_is_a_leak(default_config: Config) -> None:
    entries = {"<MESSENGER_ID_001>": _entry("that", "MESSENGER_ID")}

    with pytest.raises(LeakageError):
        check_leakage("a signal that matches", entries, _empty_scan, default_config.registry)


def test_value_shorter_than_four_chars_matches_only_whole_words(default_config: Config) -> None:
    entries = {"<USER_ID_001>": _entry("ab", "USER_ID")}

    assert check_leakage("abcd only", entries, _empty_scan, default_config.registry) is None

    with pytest.raises(LeakageError):
        check_leakage("ab cd", entries, _empty_scan, default_config.registry)


def test_residual_finding_is_a_leak(default_config: Config) -> None:
    text = "card 4111 1111 1111 1111"
    scan = _scan_for("4111 1111 1111 1111", "CREDIT_CARD")

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(text, {}, scan, default_config.registry)

    leak = excinfo.value.leaks[0]
    assert leak.kind == "residual_finding"
    assert leak.data_class == "CREDIT_CARD"
    assert (leak.start, leak.end) == (5, len(text))


def test_finding_inside_a_token_is_not_a_leak(default_config: Config) -> None:
    entries = {"<ACCOUNT_ID_001>": _entry("4711", "ACCOUNT_ID")}
    scan = _scan_for("001", "ACCOUNT_ID")
    text = "value <ACCOUNT_ID_001> here"

    assert check_leakage(text, entries, scan, default_config.registry) is None


def test_ignored_class_finding_is_not_a_leak(default_config: Config) -> None:
    config = _with_policy(default_config, "SALUTATION", Policy.IGNORE)
    scan = _scan_for("Frau", "SALUTATION")

    assert check_leakage("Sehr geehrte Frau,", {}, scan, config.registry) is None


def test_unknown_token_is_a_leak(default_config: Config) -> None:
    with pytest.raises(LeakageError) as excinfo:
        check_leakage("see <FOO_009> here", {}, _empty_scan, default_config.registry)

    leak = excinfo.value.leaks[0]
    assert leak.kind == "unknown_token"
    assert leak.data_class == ""


def test_redacted_token_is_not_an_unknown_token(default_config: Config) -> None:
    assert check_leakage("see <JWT_REDACTED>", {}, _empty_scan, default_config.registry) is None


def test_error_message_never_contains_a_value(default_config: Config) -> None:
    entries = {"<IBAN_001>": _entry(IBAN_PLAIN, "IBAN", [IBAN_PLAIN, IBAN_SPACED])}
    text = f"IBAN {IBAN_PLAIN} and {IBAN_SPACED}"

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(text, entries, _empty_scan, default_config.registry)

    message = str(excinfo.value)
    assert IBAN_PLAIN not in message
    assert IBAN_SPACED not in message
    assert "original_value" in message


def test_four_digit_unknown_token_is_a_leak(default_config: Config) -> None:
    with pytest.raises(LeakageError) as excinfo:
        check_leakage("see <IBAN_1000> here", {}, _empty_scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "unknown_token"


def test_value_in_angle_brackets_is_a_residual_leak(default_config: Config) -> None:
    text = f"IBAN: <{IBAN_PLAIN}>"
    scan = _scan_for(IBAN_PLAIN, "IBAN")

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(text, {}, scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "residual_finding"


def test_email_in_angle_brackets_is_a_residual_leak(default_config: Config) -> None:
    text = "From: <anna@example.com>"
    scan = _scan_for("anna@example.com", "EMAIL")

    with pytest.raises(LeakageError) as excinfo:
        check_leakage(text, {}, scan, default_config.registry)

    assert excinfo.value.leaks[0].kind == "residual_finding"


def test_finding_inside_a_four_digit_token_is_not_a_leak(default_config: Config) -> None:
    entries = {"<ACCOUNT_ID_1000>": _entry("4711", "ACCOUNT_ID")}
    scan = _scan_for("1000", "ACCOUNT_ID")

    assert check_leakage("v <ACCOUNT_ID_1000> x", entries, scan, default_config.registry) is None
