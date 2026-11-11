"""Known values of a session: one search that replacing and leak checking both use."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from privacy_gateway.classes import ClassRegistry
from privacy_gateway.detect.dictionaries import TrieMatcher, allows_genitive
from privacy_gateway.detect.normalize import normalized, offset_map
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE, compact_digit_run, mostly_digits
from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

SESSION_CONFIDENCE = 1.0
MIN_DIGITS_FOR_DIGIT_SEARCH = 6
MIN_DIGITS_FOR_PLAIN_NUMBER = 4
MIN_LENGTH_FOR_SUBSTRING_SEARCH = 4
PATTERN_CACHE_SIZE = 4096

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


class KnownMatcher:
    """Finds every occurrence of known values; the strictest rule of replacing and checking."""

    def __init__(self, known: Mapping[str, Known], registry: ClassRegistry) -> None:
        self._values: dict[str, Known] = {}
        terms: list[tuple[str, str]] = []
        genitive: list[str] = []
        self._spaced: list[tuple[re.Pattern[str], Known]] = []
        self._substrings: list[_Substring] = []
        self._by_digits: dict[str, Known] = {}
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
                span = _value_span(text, first, last, len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH)
                if span is not None:
                    result.append((span, value))
        return result


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

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return findings for known values; earlier findings are not inspected."""
        if self._matcher is None:
            self._matcher = KnownMatcher(self._known, config.registry)
        return [self._finding(span, value) for span, value in self._matcher.find(text)]

    def _finding(self, span: Span, value: Known) -> Finding:
        data_class, token = value
        return Finding(
            span=span,
            data_class=data_class,
            stage=self.name,
            confidence=SESSION_CONFIDENCE,
            attributes={TOKEN_ATTRIBUTE: token},
        )
