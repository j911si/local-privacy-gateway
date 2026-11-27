"""The first-word fold keeps every pair `re.IGNORECASE` matches equal, at the same length."""

from __future__ import annotations

import re
import sys

import pytest

from privacy_gateway.detect.session import _coarse_fold


def test_fold_keeps_the_length() -> None:
    text = "İstanbul ſtraße KÄTHE Kelvin Æø森"
    assert len(_coarse_fold(text)) == len(text)


@pytest.mark.parametrize("plane", [range(0x10000), range(0x10000, sys.maxunicode + 1)])
def test_characters_ignorecase_pairs_fold_equal(plane: range) -> None:
    # ponytail: re pairs characters with equal simple lowercase and those in re._casefix.
    by_lower: dict[str, str] = {}
    for code in plane:
        char = chr(code)
        lower = char.lower()
        if len(lower) != 1:
            assert _coarse_fold(char) == "?"
            continue
        folded = _coarse_fold(char)
        assert by_lower.setdefault(lower, folded) == folded, hex(code)
    from re._casefix import _EXTRA_CASES

    for lower, others in _EXTRA_CASES.items():
        for other in others:
            assert re.fullmatch(re.escape(chr(lower)), chr(other), re.IGNORECASE)
            assert _coarse_fold(chr(lower)) == _coarse_fold(chr(other)) == "?"


def test_distinct_cjk_words_get_distinct_keys() -> None:
    assert _coarse_fold("森林木") != _coarse_fold("山川口")


def test_fold_table_stays_bounded() -> None:
    from privacy_gateway.detect import session

    _coarse_fold("".join(chr(code) for code in range(0x4E00, 0x4E00 + 3 * session.MAX_FOLD_ENTRIES)))
    assert len(session._FOLD) <= session.MAX_FOLD_ENTRIES + 128
