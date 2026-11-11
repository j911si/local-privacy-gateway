"""Linear-time `finditer` for patterns whose first token consumes a whole character run.

`ADDRESS_RE`, `ORGANIZATION_RE` and `EMAIL_RE` start with a greedy character class that must be
followed by a character outside that class (whitespace or `@`). A match starting anywhere in a run
of class characters therefore always extends to the end of that run, and the rest of the match does
not depend on where in the run it started. So the first eligible start of a run decides for the
whole run: if it fails, every later start in that run fails too. Plain `finditer` tries every
start and rescans the run each time, which is quadratic on long runs such as base64.
"""

from __future__ import annotations

import re
from collections.abc import Iterator


def run_finditer(
    pattern: re.Pattern[str],
    text: str,
    run: re.Pattern[str],
    first: re.Pattern[str] | None = None,
) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields, trying one start per `run` match."""
    position = 0
    for segment in run.finditer(text):
        start, end = segment.span()
        if end <= position:
            continue
        start = max(start, position)
        if first is not None:
            eligible = first.search(text, start, end)
            if eligible is None:
                continue
            start = eligible.start()
        match = pattern.match(text, start)
        if match is not None:
            yield match
            position = match.end()


FQDN_PATTERN = r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,}\b"
MAX_LABEL = 63
_FQDN_START = re.compile(r"\b(?=[A-Za-z0-9])")
_LABEL_RUN = re.compile(rf"[A-Za-z0-9-]{{0,{MAX_LABEL + 1}}}")
_LETTERS = re.compile(r"[A-Za-z]*")
_WORD = re.compile(r"\w")


def fqdn_finditer(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields for `FQDN_PATTERN`, in linear time.

    A label cannot contain a dot and must be followed by one, so it always spans the whole
    `[A-Za-z0-9-]` run up to the next dot (1 to 63 chars, alphanumeric at both ends). The TLD
    must be followed by `\\b`, so it is the whole ASCII-letter run at its position (2 or more
    letters, then a non-word character or the end). A match from start `s` therefore exists
    exactly when `s` is a valid label and some position later in its chain of labels carries a
    TLD. That is decided once per position and memoized; `pattern.match` then produces the
    real match object, so spans are those of the regex itself. The pre-check only skips starts;
    a check that is too loose costs time, never a finding. Plain `finditer` re-walks the whole
    chain from every start, which is quadratic on text like `A.A.A.`.
    """
    if "." not in text:
        return
    has_tld: dict[int, bool] = {}
    position = 0
    for candidate in _FQDN_START.finditer(text):
        start = candidate.start()
        if start < position:
            continue
        after = _label_end(text, start)
        if after is None or not _tld_ahead(text, after, has_tld):
            continue
        match = pattern.match(text, start)
        if match is not None:
            yield match
            position = match.end()


def _label_end(text: str, start: int) -> int | None:
    end = _LABEL_RUN.match(text, start).end()  # type: ignore[union-attr]
    length = end - start
    if not 1 <= length <= MAX_LABEL or end >= len(text) or text[end] != ".":
        return None
    if text[start] == "-" or text[end - 1] == "-":
        return None
    return end + 1


def _is_tld(text: str, start: int) -> bool:
    end = _LETTERS.match(text, start).end()  # type: ignore[union-attr]
    return end - start >= 2 and (end == len(text) or _WORD.match(text, end) is None)


def _tld_ahead(text: str, start: int, memo: dict[int, bool]) -> bool:
    chain: list[int] = []
    position: int | None = start
    result = False
    while position is not None:
        if position in memo:
            result = memo[position]
            break
        chain.append(position)
        if _is_tld(text, position):
            result = True
            break
        position = _label_end(text, position)
    for visited in reversed(chain):
        result = result or memo.get(visited, False)
        memo[visited] = result
    return result
