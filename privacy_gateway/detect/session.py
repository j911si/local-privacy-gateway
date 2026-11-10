"""Session stage: re-detects values that already carry a token in this session."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from privacy_gateway.detect.dictionaries import TrieMatcher, allows_genitive
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE, compact_digit_run, mostly_digits
from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

SESSION_CONFIDENCE = 1.0
MIN_DIGITS_FOR_DIGIT_SEARCH = 6
MIN_DIGITS_FOR_PLAIN_NUMBER = 4


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


class SessionStage:
    """Emits findings for the known surface forms of an ongoing session."""

    name = "session"

    def __init__(self, known: Mapping[str, tuple[str, str]]) -> None:
        # ponytail: no name-part derivation; a stored part ("Alex") makes the
        # case-insensitive leak check reject every "/home/alex/" in later text
        self._known = {form: value for form, value in known.items() if form}
        self._by_digits: dict[str, tuple[str, str]] = {}
        for form, value in self._known.items():
            digits = "".join(char for char in form if char.isdigit())
            plain = digits == form and len(digits) >= MIN_DIGITS_FOR_PLAIN_NUMBER
            long_number = len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH and mostly_digits(form)
            if long_number or plain:
                self._by_digits.setdefault(digits, value)
        self._matcher: TrieMatcher | None = None
        self._spaced: list[tuple[re.Pattern[str], tuple[str, str]]] | None = None

    def _spaced_for(self, config: Config) -> list[tuple[re.Pattern[str], tuple[str, str]]]:
        """Multi-word forms as patterns that accept any whitespace between the words."""
        if self._spaced is None:
            self._spaced = []
            seen: set[str] = set()
            for form, value in self._known.items():
                words = form.split()
                key = " ".join(words).lower()
                if len(words) < 2 or key in seen:
                    continue
                seen.add(key)
                ending = "s?" if allows_genitive(config.registry, value[0]) else ""
                body = r"\s+".join(re.escape(word) for word in words)
                pattern = re.compile(rf"(?<![^\W_]){body}{ending}(?![^\W_])", re.IGNORECASE)
                self._spaced.append((pattern, value))
        return self._spaced

    def _matcher_for(self, config: Config) -> TrieMatcher:
        if self._matcher is None:
            self._matcher = TrieMatcher(
                ((form, form) for form in self._known),
                case_insensitive=True,
                genitive=[
                    form
                    for form, (data_class, _) in self._known.items()
                    if allows_genitive(config.registry, data_class)
                ],
            )
        return self._matcher

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return findings for known values; earlier findings are not inspected."""
        result: list[Finding] = []
        taken: list[Span] = []
        for span, form in self._matcher_for(config).find(text):
            taken.append(span)
            result.append(self._finding(span, self._known[form]))
        for pattern, value in self._spaced_for(config):
            for match in pattern.finditer(text):
                span = Span(match.start(), match.end())
                if any(span.overlaps(other) for other in taken):
                    continue
                taken.append(span)
                result.append(self._finding(span, value))
        result.extend(self._digit_findings(text, taken))
        return result

    def _digit_findings(self, text: str, taken: list[Span]) -> list[Finding]:
        """Match known values that differ from the text only in grouping."""
        if not self._by_digits:
            return []
        offsets = [index for index, char in enumerate(text) if char.isdigit()]
        projection = "".join(text[index] for index in offsets)
        result: list[Finding] = []
        for digits, value in self._by_digits.items():
            for match in re.finditer(re.escape(digits), projection):
                first, last = offsets[match.start()], offsets[match.end() - 1] + 1
                if not compact_digit_run(text, first, last):
                    continue
                span = _value_span(text, first, last, len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH)
                if span is None:
                    continue
                if any(span.overlaps(other) for other in taken):
                    continue
                taken.append(span)
                result.append(self._finding(span, value))
        return result

    def _finding(self, span: Span, value: tuple[str, str]) -> Finding:
        data_class, token = value
        return Finding(
            span=span,
            data_class=data_class,
            stage=self.name,
            confidence=SESSION_CONFIDENCE,
            attributes={TOKEN_ATTRIBUTE: token},
        )
