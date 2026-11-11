"""Known values of a session: one search that replacing and leak checking both use."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from privacy_gateway.classes import ClassRegistry
from privacy_gateway.detect.context import learnable_name_part
from privacy_gateway.detect.dictionaries import TrieMatcher, allows_genitive
from privacy_gateway.detect.normalize import normalized, offset_map
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE, compact_digit_run, mostly_digits
from privacy_gateway.model import Finding, Span, VaultEntry
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
FULL_NAME = "PERSON_FULL_NAME"
FIRST_NAME = "PERSON_FIRST_NAME"
LAST_NAME = "PERSON_LAST_NAME"

Known = tuple[str, str]
Hit = tuple[Span, Known]


class KnownForms(dict[str, Known]):
    """Known forms; `exact` lists name parts that match only in their own spelling."""

    exact: frozenset[str] = frozenset()


def known_forms(entries: Mapping[str, VaultEntry]) -> KnownForms:
    """Every known form of a session's entries, plus the first and last name of full names."""
    known = KnownForms()
    for token, entry in entries.items():
        for form in [entry.value, *entry.surface_forms]:
            if form:
                known.setdefault(form, (entry.data_class, token))
    exact: set[str] = set()
    for token, entry in entries.items():
        words = entry.value.split()
        if entry.data_class != FULL_NAME or len(words) < 2:
            continue
        for part, data_class in ((words[0], FIRST_NAME), (words[-1], LAST_NAME)):
            if learnable_name_part(part):
                exact.add(part)
                known.setdefault(part, (data_class, token))
    known.exact = frozenset(exact)
    return known


@lru_cache(maxsize=PATTERN_CACHE_SIZE)
def _exact_pattern(word: str, genitive: bool) -> re.Pattern[str]:
    ending = "s?" if genitive else ""
    return re.compile(rf"(?<![\w/\\@.-]){re.escape(word)}{ending}(?![\w@/\\])(?![.-]\w)")


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


class KnownMatcher:
    """Finds every occurrence of known values; the strictest rule of replacing and checking."""

    def __init__(self, known: Mapping[str, Known], registry: ClassRegistry) -> None:
        self._values: dict[str, Known] = {}
        terms: list[tuple[str, str]] = []
        genitive: list[str] = []
        self._spaced: list[tuple[re.Pattern[str], Known]] = []
        self._substrings: list[_Substring] = []
        self._by_digits: dict[str, Known] = {}
        self._signed_digits: set[str] = set()
        self._exact: list[tuple[re.Pattern[str], Known]] = []
        exact = getattr(known, "exact", frozenset())
        for form, value in known.items():
            if form in exact:
                self._exact.append((_exact_pattern(form, allows_genitive(registry, value[0])), value))
                continue
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
                self._spaced.append((_word_pattern(tuple(words), allows), value))
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
        for pattern, value in self._spaced:
            candidates.extend((m.start(), m.end(), value) for m in pattern.finditer(work))
        for pattern, value in self._exact:
            candidates.extend((m.start(), m.end(), value) for m in pattern.finditer(work))
        candidates.extend((s.start, s.end, v) for s, v in self._digit_hits(work))
        for substring in self._substrings:
            for match in substring.pattern.finditer(work):
                if not self._inside_longer_number(work, match.start(), match.end(), substring):
                    candidates.append((match.start(), match.end(), substring.value))
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

    def _digit_hits(self, text: str) -> list[Hit]:
        """Known numbers that differ from the text only in grouping."""
        if not self._by_digits:
            return []
        offsets = [index for index, char in enumerate(text) if char.isdigit()]
        projection = "".join(text[index] for index in offsets)
        result: list[Hit] = []
        for digits, value in self._by_digits.items():
            for match in re.finditer(re.escape(digits), projection):
                first, last = offsets[match.start()], offsets[match.end() - 1] + 1
                if not compact_digit_run(text, first, last):
                    continue
                lead = first
                while lead and text[lead - 1].isdigit():
                    lead -= 1
                international = digits in self._signed_digits and text[lead:first] == "00"
                if lead < first and not international:
                    continue
                span = _value_span(text, first, last, len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH)
                if span is None:
                    continue
                if international:
                    span = Span(lead, span.end)
                if digits in self._signed_digits and text[span.start - 1 : span.start] == "+":
                    span = Span(span.start - 1, span.end)
                result.append((span, value))
        return result


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
        self._spaced: list[tuple[re.Pattern[str], Known]] = []
        self._short_mixed: set[str] = set()
        self._glued_only: set[str] = set()
        exact = getattr(known, "exact", frozenset())
        for form, value in known.items():
            if form in exact:
                continue
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
                self._spaced.append((_substring_pattern(tuple(words)), value))

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
        tokens = [Span(match.start(), match.end()) for match in ANY_TOKEN.finditer(work)]
        raw: list[tuple[int, int, Known]] = []
        for key, value in self._values.items():
            if " " in key:
                continue
            start = lowered.find(key)
            while start != -1:
                raw.append((start, start + len(key), value))
                start = lowered.find(key, start + 1)
        for pattern, value in self._spaced:
            raw.extend((m.start(), m.end(), value) for m in pattern.finditer(work))
        raw = [
            hit
            for hit in raw
            if not any(token.overlaps(Span(hit[0], hit[1])) for token in tokens)
        ]
        raw.sort(key=lambda hit: (hit[0] - hit[1], hit[0]))
        chosen: list[tuple[int, int, Known]] = []
        covered = bytearray(len(work))
        for start, end, value in raw:
            if covered.find(1, start, end) == -1:
                covered[start:end] = b"\x01" * (end - start)
                chosen.append((start, end, value))
        full = [hit for hit in chosen if lowered[hit[0] : hit[1]] not in self._glued_only]
        starts = {start for start, _, _ in full}
        ends = {end for _, end, _ in full}
        hits: list[Hit] = []
        for start, end, value in sorted(chosen):
            if lowered[start:end] in self._glued_only:
                glued_left = start in ends and _right_boundary(work, end, False)
                glued_right = end in starts and _left_boundary(work, start)
                if not (glued_left or glued_right):
                    continue
            elif lowered[start:end] in self._short_mixed:
                if not (self._free_left(work, start) or start in ends):
                    continue
                if not (self._free_right(work, end) or end in starts):
                    continue
            else:
                numeric = mostly_digits(work[start:end])
                if not (_left_boundary(work, start) or start in ends):
                    continue
                if not (_right_boundary(work, end, numeric) or end in starts):
                    continue
            span = Span(start, end)
            hits.append((span if mapping is None else mapping.original(span), value))
        return hits


def known_occurrences(text: str, known: Mapping[str, Known], registry: ClassRegistry) -> list[Hit]:
    """Every occurrence of a known form (form -> (data class, token)) in `text`."""
    return KnownMatcher(known, registry).find(text)


class SessionStage:
    """Emits findings for the known surface forms of an ongoing session."""

    name = "session"

    def __init__(self, known: Mapping[str, Known]) -> None:
        self._known = KnownForms((form, value) for form, value in known.items() if form)
        self._known.exact = getattr(known, "exact", frozenset())
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
