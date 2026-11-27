"""Known values of a session: one search that replacing and leak checking both use."""

from __future__ import annotations

import itertools
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache, lru_cache
from typing import TYPE_CHECKING

from privacy_gateway.classes import ClassRegistry
from privacy_gateway.detect.dictionaries import TrieMatcher, allows_genitive
from privacy_gateway.detect.normalize import normalized, offset_map
from privacy_gateway.detect.spans import (
    TOKEN_ATTRIBUTE,
    SpanIndex,
    compact_digit_run,
    mostly_digits,
)
from privacy_gateway.model import Finding, Span
from privacy_gateway.tokens import ANY_TOKEN

if TYPE_CHECKING:
    from privacy_gateway.config import Config

SESSION_CONFIDENCE = 1.0
MIN_DIGITS_FOR_DIGIT_SEARCH = 6
MIN_DIGITS_FOR_PLAIN_NUMBER = 4
MIN_LENGTH_FOR_SUBSTRING_SEARCH = 4
MIN_LENGTH_FOR_SWEEP = 4
MIN_DIGITS_FOR_SWEEP = 6
MIN_LENGTH_FOR_GLUED = 3
LITERAL_ESCAPE_LETTERS = "ntr"
PATTERN_CACHE_SIZE = 4096
INDEX_FROM_SEARCHES = 32
SPACE_RUN_RE = re.compile(r"\s+")

Known = tuple[str, str]
Hit = tuple[Span, Known]


@lru_cache(maxsize=PATTERN_CACHE_SIZE)
def _word_pattern(words: tuple[str, ...], genitive: bool) -> re.Pattern[str]:
    body = r"\s+".join(re.escape(word) for word in words)
    ending = "s?" if genitive else ""
    return re.compile(rf"(?<![^\W_]){body}{ending}(?![^\W_])", re.IGNORECASE)


@lru_cache(maxsize=PATTERN_CACHE_SIZE)
def _substring_pattern(words: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"\s+".join(re.escape(word) for word in words), re.IGNORECASE)


def _value_span(text: str, start: int, end: int, long_value: bool) -> Span | None:
    """Widen a run of digits to its word; bare digits inside a longer number or before a letter.

    A short number inside a longer number is no match (None).
    """
    if end < len(text) and text[end].isdigit():
        return None
    if start and text[start - 1].isdigit():
        return Span(start, end) if long_value else None
    if end < len(text) and text[end].isalnum():
        return Span(start, end)
    while start and text[start - 1].isalnum():
        start -= 1
    return Span(start, end)


def _is_short_mixed(value: str) -> bool:
    """A short value of letters and digits, which says nothing when it sits inside a word."""
    return (
        len(value) < MIN_DIGITS_FOR_DIGIT_SEARCH
        and value.isalnum()
        and any(char.isdigit() for char in value)
        and any(char.isalpha() for char in value)
    )


@dataclass(frozen=True)
class _Substring:
    pattern: re.Pattern[str]
    value: Known
    short_number: bool
    mostly_digits: bool
    words: tuple[str, ...]
    digits: str


@cache
def _digit_re() -> re.Pattern[str]:
    """Every character for which `str.isdigit` is true."""
    chars = (chr(code) for code in range(sys.maxunicode + 1))
    return re.compile("[" + "".join(re.escape(char) for char in chars if char.isdigit()) + "]")


class _Digits:
    """The digits of a text in order, and where each wanted digit string occurs among them.

    `tight` digit strings stand in one piece in every value that uses them, `compact` ones are
    numbers whose grouping may differ: a start counts only where the text has the digits in one
    piece, or with no letter between them. Both checks are O(1) through prefix counts, so a text
    like `1x1x1x…` stores nothing for them.
    """

    def __init__(
        self,
        text: str,
        wanted: set[str],
        tight: frozenset[str] = frozenset(),
        compact: frozenset[str] = frozenset(),
    ) -> None:
        self.offsets = [match.start() for match in _digit_re().finditer(text)]
        self.projection = "".join(text[index] for index in self.offsets)
        self._tight = tight
        self._compact = compact
        self._letters = [0]
        for left, right in itertools.pairwise(self.offsets):
            gap = text[left + 1 : right]
            self._letters.append(self._letters[-1] + _has_letter(gap))
        self._found: dict[str, list[int]] | None = None
        if len(wanted) >= INDEX_FROM_SEARCHES:
            self._found = {digits: [] for digits in wanted}
            for size in {len(digits) for digits in wanted}:
                for start in range(len(self.projection) - size + 1):
                    digits = self.projection[start : start + size]
                    found = self._found.get(digits)
                    if found is not None and self._counts(digits, start):
                        found.append(start)

    def _counts(self, digits: str, start: int) -> bool:
        last = start + len(digits) - 1
        if digits in self._tight:
            return self.offsets[last] - self.offsets[start] == last - start
        if digits in self._compact:
            return self._letters[last] == self._letters[start]
        return True

    def compact(self, digits: str) -> bool:
        """True when `occurrences(digits)` already holds only starts without a letter between."""
        return digits in self._compact

    def occurrences(self, digits: str) -> list[int]:
        """Every start of `digits` in the projection that may match, overlapping ones included."""
        if self._found is not None:
            return self._found[digits]
        found = []
        start = self.projection.find(digits)
        while start != -1:
            if self._counts(digits, start):
                found.append(start)
            start = self.projection.find(digits, start + 1)
        return found


def _split_digits(word: str) -> bool:
    """True when a non-digit stands between two digits (`str.isdigit`, as the projection)."""
    places = [index for index, char in enumerate(word) if char.isdigit()]
    return any(right - left > 1 for left, right in itertools.pairwise(places))


def _has_letter(gap: str) -> bool:
    return any(char.isalpha() for char in gap)


def _anchored_matches(
    text: str,
    pattern: re.Pattern[str],
    words: tuple[str, ...],
    digits: str,
    index: _Digits,
    spaces: dict[int, int],
) -> list[re.Match[str]]:
    """Exactly `pattern.finditer(text)` for words joined by `\\s+`, tried where `digits` occur.

    Digits match only themselves and the words match fixed lengths, so the digits of a match
    are `digits` in a row in the projection, and its start follows from where its first digit
    sits: back over the word, then over each whitespace run and word before it.
    """
    word = next(index for index, part in enumerate(words) if any(c.isdigit() for c in part))
    offset = next(index for index, char in enumerate(words[word]) if char.isdigit())
    starts: list[int] = []
    for occurrence in index.occurrences(digits):
        start = index.offsets[occurrence] - offset
        for before in reversed(words[:word]):
            if start <= 0 or not text[start - 1].isspace():
                start = -1
                break
            start = _space_start(text, start, spaces) - len(before)
        if start >= 0:
            starts.append(start)
    return _first_matches(pattern, text, starts)


def _first_matches(pattern: re.Pattern[str], text: str, starts: list[int]) -> list[re.Match[str]]:
    """What `finditer` yields when every start of a match is among `starts`."""
    found: list[re.Match[str]] = []
    end = 0
    for start in sorted(set(starts)):
        if start < end:
            continue
        match = pattern.match(text, start)
        if match is not None:
            found.append(match)
            end = match.end()
    return found


def _extra_cases() -> frozenset[int]:
    """Code points `re.IGNORECASE` pairs beyond equal lowercase, plus `i`, `k`, `s`."""
    try:
        from re._casefix import _EXTRA_CASES
    except ImportError:
        return frozenset()
    points = {ord("i"), ord("k"), ord("s")}
    for lower, others in _EXTRA_CASES.items():
        points.add(lower)
        points.update(others)
    return frozenset(points)


_EXTRA = _extra_cases()
MAX_FOLD_ENTRIES = 4096


class _FoldTable(dict[int, int]):
    """`str.translate` table: a character's lowercase, or `?` where `re` may pair it otherwise."""

    def __missing__(self, code: int) -> int:
        lower = chr(code).lower()
        if _EXTRA:
            unsafe = len(lower) != 1 or code in _EXTRA or ord(lower) in _EXTRA
        else:
            unsafe = code > 0x7F or lower in "iks"
        folded = ord("?") if unsafe else ord(lower)
        if code <= 0x7F or len(self) < MAX_FOLD_ENTRIES:
            # ponytail: a text with every code point must not grow the table without bound.
            self[code] = folded
        return folded


_FOLD = _FoldTable()


def _coarse_fold(text: str) -> str:
    """A fold of the same length under which characters `re.IGNORECASE` pairs are equal.

    A character becomes its lowercase, or `?` when `re` may pair it with a character of
    another lowercase (the `re._casefix` table, `i`, `k`, `s`) or its lowercase has more than
    one character. Without that table every non-ASCII character becomes `?`, as before.
    """
    return text.translate(_FOLD)


class _FirstWords:
    """Where a value of words joined by `\\s+` can start: its first word before a space run.

    `\\s+` takes the whole run, as the next word starts with a non-space character, so the
    first word ends where a whitespace run starts.
    """

    def __init__(self, text: str, values: list[tuple[str, ...]]) -> None:
        folded = _coarse_fold(text)
        runs = [match.start() for match in SPACE_RUN_RE.finditer(text)]
        wanted = {(len(words[0]), _coarse_fold(words[0])) for words in values}
        self._starts: dict[tuple[int, str], list[int]] = {}
        for size in {size for size, _ in wanted}:
            for run in runs:
                key = (size, folded[run - size : run])
                if run >= size and key in wanted:
                    self._starts.setdefault(key, []).append(run - size)

    def starts(self, words: tuple[str, ...]) -> list[int]:
        """Every position where the first word of `words` may start a match."""
        return self._starts.get((len(words[0]), _coarse_fold(words[0])), [])


def _spaced_matches(
    text: str, rules: list[tuple[re.Pattern[str], tuple[str, ...]]]
) -> list[list[re.Match[str]]]:
    """`pattern.finditer(text)` per rule of words joined by `\\s+`, through one index if many."""
    if len(rules) < INDEX_FROM_SEARCHES:
        return [list(pattern.finditer(text)) for pattern, _ in rules]
    index = _FirstWords(text, [words for _, words in rules])
    return [_first_matches(pattern, text, index.starts(words)) for pattern, words in rules]


class KnownMatcher:
    """Finds every occurrence of known values; the strictest rule of replacing and checking."""

    def __init__(self, known: Mapping[str, Known], registry: ClassRegistry) -> None:
        self._values: dict[str, Known] = {}
        terms: list[tuple[str, str]] = []
        genitive: list[str] = []
        self._spaced: list[tuple[re.Pattern[str], Known, tuple[str, ...], str]] = []
        self._substrings: list[_Substring] = []
        self._by_digits: dict[str, Known] = {}
        self._signed_digits: set[str] = set()
        for form, value in known.items():
            words = normalized(form).split()
            if not words:
                continue
            key = " ".join(words)
            folded = key.lower()
            if folded in self._values:
                continue
            self._values[folded] = value
            allows = allows_genitive(registry, value[0])
            if len(words) == 1:
                terms.append((key, folded))
                if allows:
                    genitive.append(folded)
            else:
                digits = "".join(char for char in key if char.isdigit())
                self._spaced.append(
                    (_word_pattern(tuple(words), allows), value, tuple(words), digits)
                )
            self._add_digit_rules(key, tuple(words), value)
        self._trie = TrieMatcher(terms, case_insensitive=True, genitive=genitive) if terms else None

    def _add_digit_rules(self, key: str, words: tuple[str, ...], value: Known) -> None:
        digits = "".join(char for char in key if char.isdigit())
        if not digits:
            return
        plain = digits == key and len(digits) >= MIN_DIGITS_FOR_PLAIN_NUMBER
        long_number = len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH and mostly_digits(key)
        if plain or long_number:
            self._by_digits.setdefault(digits, value)
            if key.startswith("+"):
                self._signed_digits.add(digits)
        if len(key) >= MIN_LENGTH_FOR_SUBSTRING_SEARCH and not _is_short_mixed(key):
            self._substrings.append(
                _Substring(
                    _substring_pattern(words),
                    value,
                    key.isdigit() and len(key) < MIN_DIGITS_FOR_DIGIT_SEARCH,
                    mostly_digits(key),
                    words,
                    digits,
                )
            )

    def find(self, text: str) -> list[Hit]:
        """Non-overlapping hits, longest first; spans point into `text`."""
        mapping = offset_map(text)
        work = text if mapping is None else mapping.text
        covered = bytearray(len(work))
        hits: list[Hit] = []

        def add(start: int, end: int, value: Known) -> None:
            if covered.find(1, start, end) != -1:
                return
            covered[start:end] = b"\x01" * (end - start)
            span = Span(start, end)
            hits.append((span if mapping is None else mapping.original(span), value))

        candidates: list[tuple[int, int, Known]] = []
        if self._trie is not None:
            for span, folded in self._trie.find(work):
                candidates.append((span.start, span.end, self._values[folded]))
        wanted = {*self._by_digits, *(rule.digits for rule in self._substrings)}
        wanted.update(digits for *_, digits in self._spaced if digits)
        tight, compact = self._digit_checks()
        index = _Digits(work, wanted, tight, compact) if wanted else None
        spaces: dict[int, int] = {}
        plain = iter(
            _spaced_matches(work, [(rule[0], rule[2]) for rule in self._spaced if not rule[3]])
        )
        for pattern, value, words, digits in self._spaced:
            if digits and index is not None:
                matches = _anchored_matches(work, pattern, words, digits, index, spaces)
            else:
                matches = next(plain)
            candidates.extend((m.start(), m.end(), value) for m in matches)
        if index is not None:
            candidates.extend((s.start, s.end, v) for s, v in self._digit_hits(work, index))
            for rule in self._substrings:
                for m in _anchored_matches(
                    work, rule.pattern, rule.words, rule.digits, index, spaces
                ):
                    if not self._inside_longer_number(work, m.start(), m.end(), rule):
                        candidates.append((m.start(), m.end(), rule.value))
        candidates.sort(key=lambda candidate: candidate[0] - candidate[1])
        for start, end, value in candidates:
            add(start, end, value)
        return hits

    @staticmethod
    def _inside_longer_number(text: str, start: int, end: int, rule: _Substring) -> bool:
        digit_after = end < len(text) and text[end].isdigit()
        if rule.short_number:
            return digit_after or (start > 0 and text[start - 1].isdigit())
        return rule.mostly_digits and digit_after

    def _digit_checks(self) -> tuple[frozenset[str], frozenset[str]]:
        """(tight, compact): digits in one piece in every word rule; numbers without letters.

        A digit string that some word rule splits with letters (`a1b2`) gets neither check.
        """
        split: set[str] = set()
        whole: set[str] = set()
        rules = [(rule.words, rule.digits) for rule in self._substrings]
        rules.extend((words, digits) for _, _, words, digits in self._spaced if digits)
        for words, digits in rules:
            (split if _split_digits(" ".join(words)) else whole).add(digits)
        numbers = set(self._by_digits)
        return frozenset(whole - numbers - split), frozenset(numbers - split)

    def _digit_hits(self, text: str, index: _Digits) -> list[Hit]:
        """Known numbers that differ from the text only in grouping.

        Every check runs before the leftmost non-overlapping starts are taken, so a start that
        fails one (a letter inside, a digit right before) cannot hide a valid one it overlaps.
        """
        offsets = index.offsets
        result: list[Hit] = []
        for digits, value in self._by_digits.items():
            size = len(digits)
            accepted: list[tuple[int, Span]] = []
            for start in index.occurrences(digits):
                first, last = offsets[start], offsets[start + size - 1] + 1
                if not index.compact(digits) and not compact_digit_run(text, first, last):
                    continue
                span = self._number_span(text, digits, first, last)
                if span is not None:
                    accepted.append((start, span))
            spans = dict(accepted)
            for start in _non_overlapping([start for start, _ in accepted], size):
                result.append((spans[start], value))
        return result

    def _number_span(self, text: str, digits: str, first: int, last: int) -> Span | None:
        """The span of a known number at `first`..`last`, or None when it is part of another."""
        international = False
        if first and text[first - 1].isdigit():
            international = (
                digits in self._signed_digits
                and text[first - 2 : first] == "00"
                and not (first > 2 and text[first - 3].isdigit())
            )
            if not international:
                return None
        span = _value_span(text, first, last, len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH)
        if span is None:
            return None
        if international:
            span = Span(first - 2, span.end)
        if digits in self._signed_digits and text[span.start - 1 : span.start] == "+":
            span = Span(span.start - 1, span.end)
        return span


def _non_overlapping(starts: list[int], length: int) -> list[int]:
    """The starts `re.finditer` keeps for a literal of `length`: leftmost, then after it."""
    kept: list[int] = []
    end = 0
    for start in starts:
        if start >= end:
            kept.append(start)
            end = start + length
    return kept


def _space_start(text: str, end: int, memo: dict[int, int]) -> int:
    """Start of the whitespace run that ends at `end`."""
    start = memo.get(end)
    if start is None:
        start = end
        while start > 0 and text[start - 1].isspace():
            start -= 1
        memo[end] = start
    return start


def _lower(text: str) -> str:
    """Lowercase that keeps the length, so offsets stay valid."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(char.lower() if len(char.lower()) == 1 else char for char in text)


def _left_boundary(text: str, start: int) -> bool:
    """No letter before `start`, a literal `\\n`/`\\t`/`\\r` before it, or a camelCase break."""
    if start == 0:
        return True
    before = text[start - 1]
    if not before.isalpha():
        return True
    if before in LITERAL_ESCAPE_LETTERS and start >= 2 and text[start - 2] == "\\":
        return True
    return before.islower() and text[start].isupper()


def _right_boundary(text: str, end: int, numeric: bool) -> bool:
    if end == len(text):
        return True
    after = text[end]
    if numeric and after.isdigit():
        return False
    if not after.isalpha():
        return True
    return after.isupper() and text[end - 1].islower()


class SubstringSweep:
    """A plain substring search for known values, independent of `KnownMatcher`.

    It finds a value where the word-bound search cannot: next to digits, after a literal
    escape, at a camelCase break, or glued to another known value. A pure-letter value inside a
    longer word ("Stein" in "Steinbruch") is no hit, and a short mixed value ("B2C4") is a hit
    only next to a non-alphanumeric character or another hit. Values under four characters
    (digit-only under six) are not searched, except a three-letter value glued to a hit.
    """

    def __init__(self, known: Mapping[str, Known]) -> None:
        self._values: dict[str, Known] = {}
        self._spaced: list[tuple[re.Pattern[str], Known, tuple[str, ...]]] = []
        self._short_mixed: set[str] = set()
        self._glued_only: set[str] = set()
        for form, value in known.items():
            words = normalized(form).split()
            key = _lower(" ".join(words))
            if key in self._values or not self._long_enough(key):
                continue
            self._values[key] = value
            if _is_short_mixed(key):
                self._short_mixed.add(key)
            if len(key) < MIN_LENGTH_FOR_SWEEP:
                self._glued_only.add(key)
            if len(words) > 1:
                self._spaced.append((_substring_pattern(tuple(words)), value, tuple(words)))

    @staticmethod
    def _long_enough(key: str) -> bool:
        if key.isdigit():
            return len(key) >= MIN_DIGITS_FOR_SWEEP
        return len(key) >= MIN_LENGTH_FOR_GLUED

    @staticmethod
    def _free_left(text: str, start: int) -> bool:
        return start == 0 or not text[start - 1].isalnum()

    @staticmethod
    def _free_right(text: str, end: int) -> bool:
        return end == len(text) or not text[end].isalnum()

    def find(self, text: str) -> list[Hit]:
        """Hits outside literal tokens, spans pointing into `text`."""
        mapping = offset_map(text)
        work = text if mapping is None else mapping.text
        lowered = _lower(work)
        tokens = SpanIndex(Span(match.start(), match.end()) for match in ANY_TOKEN.finditer(work))
        raw: list[tuple[int, int, Known]] = []
        for key, value in self._values.items():
            if " " in key:
                continue
            start = lowered.find(key)
            while start != -1:
                raw.append((start, start + len(key), value))
                start = lowered.find(key, start + 1)
        spaced = _spaced_matches(work, [(pattern, words) for pattern, _, words in self._spaced])
        for (_, value, _), matches in zip(self._spaced, spaced, strict=True):
            raw.extend((m.start(), m.end(), value) for m in matches)
        raw = [hit for hit in raw if not tokens.overlaps(Span(hit[0], hit[1]))]
        raw.sort(key=lambda hit: (hit[0] - hit[1], hit[0]))
        chosen: list[tuple[int, int, Known]] = []
        starts: set[int] = set()
        ends: set[int] = set()
        while raw:
            covered = bytearray(len(work))
            for start, end, _ in chosen:
                covered[start:end] = b"\x01" * (end - start)
            taken: list[tuple[int, int, Known]] = []
            for start, end, value in raw:
                if covered.find(1, start, end) == -1:
                    covered[start:end] = b"\x01" * (end - start)
                    taken.append((start, end, value))
            for start, end, _ in taken:
                if lowered[start:end] not in self._glued_only:
                    starts.add(start)
                    ends.add(end)
            rejected = False
            for start, end, value in taken:
                if self._valid(work, lowered[start:end], start, end, starts, ends):
                    chosen.append((start, end, value))
                else:
                    rejected = True
            if not rejected:
                break
            removed = set(taken)
            raw = [hit for hit in raw if hit not in removed]
        hits: list[Hit] = []
        for start, end, value in sorted(chosen):
            span = Span(start, end)
            hits.append((span if mapping is None else mapping.original(span), value))
        return hits

    def _valid(
        self, work: str, key: str, start: int, end: int, starts: set[int], ends: set[int]
    ) -> bool:
        """Boundaries of one candidate; `starts`/`ends` are the candidates taken so far."""
        if key in self._glued_only:
            glued_left = start in ends and _right_boundary(work, end, False)
            glued_right = end in starts and _left_boundary(work, start)
            return glued_left or glued_right
        if key in self._short_mixed:
            return (self._free_left(work, start) or start in ends) and (
                self._free_right(work, end) or end in starts
            )
        numeric = mostly_digits(work[start:end])
        return (_left_boundary(work, start) or start in ends) and (
            _right_boundary(work, end, numeric) or end in starts
        )


def known_occurrences(text: str, known: Mapping[str, Known], registry: ClassRegistry) -> list[Hit]:
    """Every occurrence of a known form (form -> (data class, token)) in `text`."""
    return KnownMatcher(known, registry).find(text)


class SessionStage:
    """Emits findings for the known surface forms of an ongoing session."""

    name = "session"

    def __init__(self, known: Mapping[str, Known]) -> None:
        # ponytail: no name-part derivation; a stored part ("Alex") makes the
        # case-insensitive leak check reject every "/home/alex/" in later text
        self._known = {form: value for form, value in known.items() if form}
        self._matcher: KnownMatcher | None = None
        self._sweep: SubstringSweep | None = None

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return findings for known values; earlier findings are not inspected."""
        if self._matcher is None:
            self._matcher = KnownMatcher(self._known, config.registry)
        if self._sweep is None:
            self._sweep = SubstringSweep(self._known)
        hits = self._matcher.find(text)
        taken = bytearray(len(text))
        for span, _ in hits:
            taken[span.start : span.end] = b"\x01" * len(span)
        hits += [
            (span, value)
            for span, value in self._sweep.find(text)
            if taken.find(1, span.start, span.end) == -1
        ]
        return [self._finding(span, value) for span, value in hits]

    def _finding(self, span: Span, value: Known) -> Finding:
        data_class, token = value
        return Finding(
            span=span,
            data_class=data_class,
            stage=self.name,
            confidence=SESSION_CONFIDENCE,
            attributes={TOKEN_ATTRIBUTE: token},
        )
