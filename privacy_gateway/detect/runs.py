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


JWT_PATTERN = r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
_JWT_START = re.compile(r"\beyJ")


def jwt_finditer(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields for `JWT_PATTERN`, in linear time.

    The header part runs to the end of its `[A-Za-z0-9_-]` run (a dot cannot be inside it), so
    the first `eyJ` of a run decides for the whole run, as in `run_finditer`.
    """
    return run_finditer(pattern, text, _JWT_RUN, _JWT_START)


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


PASS_PW_PATTERN = (
    r"""(?i)(?<![\w.\-])(?:pass|pw)[ \t]*:(?!=)[ \t]*+(?!["'$(<{])(?=\S*\d)(?=\S*[A-Za-z])"""
    r"(\S{6,}?)[.,;:)\]]*(?=\s|$)"
)
_PASS_PW_PREFIX = re.compile(r"""(?i)(?<![\w.\-])(?:pass|pw)[ \t]*:(?!=)[ \t]*+(?!["'$(<{])""")
_NON_SPACE = re.compile(r"\S*")
_PASS_PW_LINEAR = (
    _PASS_PW_PREFIX.pattern
    + r"(?=\S*\d)(?=\S*[A-Za-z])(\S{6}(?:\S*[^\s.,;:)\]])?)[.,;:)\]]*+(?=\s|$)"
)


def pass_pw_finditer(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields for `PASS_PW_PATTERN`, in linear time.

    After the prefix, success depends only on the non-space run from the value start (a digit,
    a letter, six characters). Such a test passes for a run if it passes for any suffix of it,
    so once a value start fails, every later value start inside the same run fails too and is
    skipped. Plain `finditer` rescans the run from every `pw:` in it. The lazy value can only
    end where the rest of its run is trailing punctuation, which is after the last other character
    or after six characters; `_PASS_PW_LINEAR` takes that end directly instead of trying each
    length against the punctuation run.
    """
    linear = re.compile(_PASS_PW_LINEAR, pattern.flags)
    position = 0
    dead_end = -1
    while (prefix := _PASS_PW_PREFIX.search(text, position)) is not None:
        value = prefix.end()
        if value < dead_end:
            position = prefix.start() + 1
            continue
        match = linear.match(text, prefix.start())
        if match is not None:
            yield match
            position = match.end()
            continue
        dead_end = _NON_SPACE.match(text, value).end()  # type: ignore[union-attr]
        position = prefix.start() + 1


LINE_KEYWORD_SHAPE = re.compile(r"\\b(?:\(\?:[a-z|]+\)|[a-z]+)\\b(?=\[\^\\n\]\*\?)")


def line_keyword_finditer(
    pattern: re.Pattern[str], text: str, keyword: re.Pattern[str]
) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields for `\\bKEYWORD\\b[^\\n]*?REST`.

    REST is tried at every position from the keyword end to the line end, and whether it
    matches at a position does not depend on where the match started. A later keyword on the
    same line sees a subset of those positions, so once a keyword fails the rest of its line
    is skipped. Plain `finditer` rescans the line from every keyword.
    """
    position = 0
    while (found := keyword.search(text, position)) is not None:
        match = pattern.match(text, found.start())
        if match is not None:
            yield match
            position = match.end()
            continue
        newline = text.find("\n", found.end())
        if newline == -1:
            return
        position = newline + 1


COLON_PREFIX = (
    '(?i)(?<![A-Za-z0-9])(?:(?:ht|pg)?(?:password|passwd|passphrase)|pwd|kennwort|pas'
    'swort|(?<=[_.\\-])pass)["\']?\\]?[ \\t]*:(?!=)[ \t]*+'
)
COLON_GUARD = (
    '(?!["\']|\\$|\\(|(?:none|null|nil|undefined|true|false|str|int|bool|bytes|float|opt'
    'ional|secretstr)\\b|[\\w.]+[(\\[]|(?:[A-Za-z_]+(?:\\.[A-Za-z_]+)+|(?-i:[a-z]+(?:_[a-'
    'z]+)+))[ \\t]*[.,;:)\\]]*$)'
)
COLON_MUST = (
    "(?!(?:must|muss|should|sollte)(?![\\w'])[^\\n]*\\b\\d+\\+?[ \\t]+(?:characters?|chars|"
    'digits?|letters?|zeichen|ziffern|buchstaben)\\b[A-Za-zÄÖÜäöüß \\t,.()]*$)'
)
COLON_STOP = (
    '(?!(?:wird|werden|wurde|ist|sind|war|siehe|oben|unten|per|mit|ohne|und|oder|der|'
    'die|das|dem|den|ein|eine|einer|einem|nicht|kein|keine|bitte|nur|auch|wie|wenn|da'
    'nn|bei|von|vom|zum|zur|im|am|auf|aus|an|in|für|fuer|über|ueber|nach|vor|the|a|an'
    '|is|are|was|will|be|see|by|via|with|without|and|or|not|no|to|for|of|on|at|from|y'
    'our|you|must|should|can|please|here|enter|all|has|have|been|this|that|it|as|if|s'
    "uccessfully|updated|changed|required)(?![\\w'])(?![^\\n]*\\d))"
)
COLON_VALUE = (
    '(\\S[^\\n]{3}(?=[ \\t]*+[.,;:)\\]]*+$)|\\S[^\\n]{2,}?(?:[^ \\t\\n.,;:)\\]]|[.,;:)\\]](?=[ '
    '\\t]))(?=[ \\t]*+[.,;:)\\]]*+$))[ \\t]*[.,;:)\\]]*$'
)
COLON_PATTERN = COLON_PREFIX + COLON_GUARD + COLON_MUST + COLON_STOP + COLON_VALUE
_COLON_PREFIX_RE = re.compile(COLON_PREFIX)
_COLON_MUST_RE = re.compile("(?i)" + COLON_MUST[3 : COLON_MUST.index("[^\\n]*")])
_COLON_STOP_RE = re.compile("(?i)" + COLON_STOP[3 : COLON_STOP.index("(?![^\\n]*\\d)")])
_COLON_HEAD_RE = re.compile(
    "(?i)" + COLON_MUST[COLON_MUST.index("\\b\\d+") : COLON_MUST.index("[A-Za-z\u00c4")]
)
_COLON_TAIL_CHAR = re.compile(
    "(?i)" + COLON_MUST[COLON_MUST.index("[A-Za-z\u00c4") : COLON_MUST.rindex("]") + 1]
)
_DIGIT = re.compile(r"\d")


def colon_finditer(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields for `COLON_PATTERN`, in linear time.

    The prefix fixes the value start `v`. Two lookaheads at `v` scan to the line end: a stopword
    fails the match when no digit follows on the line, and `must ... 8 characters` fails it when
    such a phrase ends the line somewhere after the word. Both only depend on `v` and two numbers
    per line (the last digit and the last such phrase start), which are computed once per line.
    When neither applies, the rule without these two lookaheads decides; the lookaheads sit at
    the same position as the remaining guard, so dropping them does not change any other match.
    """
    plain = re.compile(COLON_PREFIX + COLON_GUARD + COLON_VALUE, pattern.flags)
    line = [0, -1, -1, -1]
    position = 0
    while (prefix := _COLON_PREFIX_RE.search(text, position)) is not None:
        if not _colon_blocked(text, prefix.end(), line):
            match = plain.match(text, prefix.start())
            if match is not None:
                yield match
                position = match.end()
                continue
        position = prefix.start() + 1


def _colon_blocked(text: str, value: int, line: list[int]) -> bool:
    must = _COLON_MUST_RE.match(text, value)
    stop = _COLON_STOP_RE.match(text, value)
    if must is None and stop is None:
        return False
    if not line[0] <= value <= line[1]:
        start = text.rfind("\n", max(line[1], 0) if value > line[1] else 0, value) + 1
        end = text.find("\n", value)
        end = len(text) if end == -1 else end
        line[:] = [start, end, *_line_facts(text, start, end)]
    _, _, last_digit, last_phrase = line
    if stop is not None and last_digit < value:
        return True
    return must is not None and last_phrase >= must.end()


def _line_facts(text: str, start: int, end: int) -> tuple[int, int]:
    """Last digit and last `N characters` phrase start whose tail runs to the line end."""
    last_digit = end - 1
    while last_digit >= start and _DIGIT.match(text, last_digit) is None:
        last_digit -= 1
    tail = end
    while tail > start and _COLON_TAIL_CHAR.match(text, tail - 1) is not None:
        tail -= 1
    last_phrase = -1
    for head in _COLON_HEAD_RE.finditer(text, start, end):
        if head.end() >= tail:
            last_phrase = head.start()
    return last_digit, last_phrase
