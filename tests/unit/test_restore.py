from __future__ import annotations

import pytest

from privacy_gateway.model import RestoreError, VaultEntry
from privacy_gateway.restore import restore_text


def _entry(value: str, data_class: str, surface_forms: list[str]) -> VaultEntry:
    return VaultEntry(
        value=value,
        data_class=data_class,
        surface_forms=surface_forms,
        attributes={},
    )


PERSON_ENTRIES = {
    "<PERSON_001>": _entry("Müller", "PERSON_LAST_NAME", ["Müller", "MÜLLER"]),
}
FEMALE_ENTRIES = {
    "<PERSON_FEMALE_001>": _entry("Anna", "PERSON_FIRST_NAME", ["Anna", "ANNA"]),
}


def test_strict_restores_surface_forms_in_occurrence_order() -> None:
    result = restore_text("<PERSON_001> und <PERSON_001>", PERSON_ENTRIES)

    assert result.text == "Müller und MÜLLER"
    assert result.restored_count == 2
    assert result.unknown_tokens == []


def test_occurrence_beyond_surface_forms_uses_canonical_value() -> None:
    result = restore_text("<PERSON_001> <PERSON_001> <PERSON_001>", PERSON_ENTRIES)

    assert result.text == "Müller MÜLLER Müller"
    assert result.restored_count == 3


def test_strict_unknown_token_raises_with_token_name_only() -> None:
    with pytest.raises(RestoreError) as excinfo:
        restore_text("<PERSON_001> and <FOO_009>", PERSON_ENTRIES)

    message = str(excinfo.value)
    assert "<FOO_009>" in message
    assert "Müller" not in message


def test_redacted_token_is_untouched() -> None:
    result = restore_text("secret <JWT_REDACTED> here", PERSON_ENTRIES)

    assert result.text == "secret <JWT_REDACTED> here"
    assert result.restored_count == 0


def test_lenient_restores_wrapped_and_lowercase_tokens() -> None:
    text = '"PERSON_FEMALE_001" and `<PERSON_FEMALE_001>` and `person_female_001`'

    result = restore_text(text, FEMALE_ENTRIES, mode="lenient")

    assert result.text == "Anna and ANNA and Anna"
    assert result.restored_count == 3
    assert result.unknown_tokens == []


def test_lenient_leaves_bare_identifiers_alone() -> None:
    text = "person_female_001 and report_001 and PERSON_FEMALE_001"

    result = restore_text(text, FEMALE_ENTRIES, mode="lenient")

    assert result.text == text
    assert result.restored_count == 0
    assert result.unknown_tokens == []


def test_strict_four_digit_token_is_unknown() -> None:
    with pytest.raises(RestoreError) as excinfo:
        restore_text("Konto <IBAN_1000> hier", PERSON_ENTRIES)

    assert "<IBAN_1000>" in str(excinfo.value)


def test_lenient_four_digit_token_is_listed_as_unknown() -> None:
    result = restore_text("Konto <IBAN_1000> hier", PERSON_ENTRIES, mode="lenient")

    assert result.text == "Konto <IBAN_1000> hier"
    assert result.unknown_tokens == ["<IBAN_1000>"]


def test_four_digit_token_is_restored() -> None:
    entries = {"<PERSON_1000>": _entry("Müller", "PERSON_LAST_NAME", ["Müller"])}

    assert restore_text("<PERSON_1000>", entries).text == "Müller"


def test_lenient_keeps_and_lists_unknown_tokens() -> None:
    text = "<PERSON_001> then <FOO_009> then <FOO_009>"

    result = restore_text(text, PERSON_ENTRIES, mode="lenient")

    assert result.text == "Müller then <FOO_009> then <FOO_009>"
    assert result.unknown_tokens == ["<FOO_009>"]
    assert result.restored_count == 1


def test_lenient_leaves_redacted_tokens_alone() -> None:
    result = restore_text("<JWT_REDACTED>", PERSON_ENTRIES, mode="lenient")

    assert result.text == "<JWT_REDACTED>"
    assert result.unknown_tokens == []


def test_unknown_mode_raises() -> None:
    with pytest.raises(RestoreError):
        restore_text("<PERSON_001>", PERSON_ENTRIES, mode="loose")


def test_text_without_tokens_is_unchanged() -> None:
    result = restore_text("nothing to do here", PERSON_ENTRIES)

    assert result.text == "nothing to do here"
    assert result.restored_count == 0
