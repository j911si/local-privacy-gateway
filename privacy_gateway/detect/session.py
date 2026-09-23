"""Session stage: re-detects values that already carry a token in this session."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from privacy_gateway.detect.dictionaries import TrieMatcher, allows_genitive
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE
from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

SESSION_CONFIDENCE = 1.0
MIN_DIGITS_FOR_DIGIT_SEARCH = 6


def _value_span(text: str, start: int, end: int) -> Span | None:
    """Widen a run of digits to the word it belongs to, or None when it is a fragment."""
    if start and text[start - 1].isdigit():
        return None
    if end < len(text) and text[end].isalnum():
        return None
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
            if len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH:
                self._by_digits.setdefault(digits, value)
        self._matcher: TrieMatcher | None = None

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
                span = _value_span(text, offsets[match.start()], offsets[match.end() - 1] + 1)
                if span is None or any(span.overlaps(other) for other in taken):
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
