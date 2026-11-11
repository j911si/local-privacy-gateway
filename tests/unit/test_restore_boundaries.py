"""Restore replaces exactly the token and nothing around it, in both modes."""

from __future__ import annotations

import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from privacy_gateway.model import VaultEntry
from privacy_gateway.restore import LENIENT, STRICT, restore_text


def _entry(value: str, data_class: str, surface_forms: list[str] | None = None) -> VaultEntry:
    return VaultEntry(
        value=value,
        data_class=data_class,
        surface_forms=surface_forms if surface_forms is not None else [value],
        attributes={},
    )


ENTRIES = {
    "<PERSON_001>": _entry("annika", "PERSON_FIRST_NAME"),
    "<EMAIL_001>": _entry("x@y.de", "EMAIL"),
    "<HOSTNAME_003>": _entry("db01", "HOSTNAME"),
}
VALUES = {token: entry.value for token, entry in ENTRIES.items()}


@pytest.mark.parametrize("mode", [STRICT, LENIENT])
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("backup_<PERSON_001>.tar", "backup_annika.tar"),
        ("<PERSON_001>2024", "annika2024"),
        ("x<HOSTNAME_003>y", "xdb01y"),
        ("<PERSON_001><PERSON_001>", "annikaannika"),
        ("_<PERSON_001>_", "_annika_"),
        ("<PERSON_001>>", "annika>"),
        ("<<PERSON_001>", "<annika"),
    ],
)
def test_a_bracketed_token_is_restored_whatever_stands_next_to_it(
    mode: str, text: str, expected: str
) -> None:
    assert restore_text(text, ENTRIES, mode).text == expected


@pytest.mark.parametrize("mode", [STRICT, LENIENT])
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"owner": "<EMAIL_001>"', '"owner": "x@y.de"'),
        ("owner = '<PERSON_001>'", "owner = 'annika'"),
        ("user `<PERSON_001>` ok", "user `annika` ok"),
        ('{"a": "<EMAIL_001>", "b": \'<HOSTNAME_003>\'}', '{"a": "x@y.de", "b": \'db01\'}'),
    ],
)
def test_quotes_and_backticks_around_a_bracketed_token_stay(
    mode: str, text: str, expected: str
) -> None:
    assert restore_text(text, ENTRIES, mode).text == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('say "PERSON_001" now', 'say "annika" now'),
        ("say 'person_001' now", "say 'annika' now"),
        ("say `Person_001` now", "say `annika` now"),
        ('"<person_001>"', '"annika"'),
        ("<Person_001> and <EMAIL_001>", "annika and x@y.de"),
        ('["PERSON_001", "EMAIL_001"]', '["annika", "x@y.de"]'),
    ],
)
def test_lenient_variants_replace_only_the_token_itself(text: str, expected: str) -> None:
    assert restore_text(text, ENTRIES, LENIENT).text == expected


def test_lenient_still_leaves_bare_identifiers_alone() -> None:
    text = "PERSON_001 and person_001 and x_PERSON_001 and 'PERSON_001x'"

    assert restore_text(text, ENTRIES, LENIENT).text == text


SPELLINGS = {
    "<PERSON_001>": _entry("annika", "PERSON_FIRST_NAME", ["annika", "Annika", "ANNIKA"]),
    "<EMAIL_001>": _entry("x@y.de", "EMAIL"),
}


def test_lenient_restores_the_canonical_value_not_a_surface_form() -> None:
    text = "<PERSON_001> <PERSON_001> <PERSON_001> <PERSON_001>"

    assert restore_text(text, SPELLINGS, LENIENT).text == "annika annika annika annika"


def test_lenient_result_does_not_depend_on_how_often_or_in_which_order_tokens_come() -> None:
    once = restore_text("<EMAIL_001>", SPELLINGS, LENIENT).text
    reordered = restore_text("<EMAIL_001> <PERSON_001> <PERSON_001>", SPELLINGS, LENIENT)

    assert once == "x@y.de"
    assert reordered.text == "x@y.de annika annika"
    assert reordered.restored_count == 3


def test_strict_keeps_the_spellings_of_the_unchanged_text_in_order() -> None:
    text = "<PERSON_001> <PERSON_001> <PERSON_001> <PERSON_001>"

    assert restore_text(text, SPELLINGS, STRICT).text == "annika Annika ANNIKA annika"


_CHARS = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12)
_TOKENS = st.sampled_from(sorted(ENTRIES))
_TOKEN_LIKE = re.compile(r"<[A-Za-z][A-Za-z0-9_]*_\d{3,}>|([`\"'])[A-Za-z][A-Za-z0-9_]*_\d{3,}\1")


@st.composite
def documents(draw: st.DrawFn) -> tuple[str, str]:
    """Random characters around known tokens, plus the text with every token replaced."""
    pieces = draw(st.lists(st.one_of(_CHARS, _TOKENS), max_size=8))
    text = "".join(pieces)
    expected = "".join(VALUES.get(piece, piece) for piece in pieces)
    # The random characters could by chance spell a token of their own; the oracle does not
    # cover that, so such a text is discarded.
    assume(not _TOKEN_LIKE.search("".join(p for p in pieces if p not in VALUES)))
    assume(
        not _TOKEN_LIKE.search(
            text.replace("<PERSON_001>", "")
            .replace("<EMAIL_001>", "")
            .replace("<HOSTNAME_003>", "")
        )
    )
    return text, expected


@pytest.mark.parametrize("mode", [STRICT, LENIENT])
@given(document=documents())
def test_restore_replaces_every_token_by_its_value_and_nothing_else(
    mode: str, document: tuple[str, str]
) -> None:
    text, expected = document

    assert restore_text(text, ENTRIES, mode).text == expected
