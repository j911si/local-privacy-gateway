"""Fail-closed validation that pseudonymized text carries no original data."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.model import DetectionReport, Leak, LeakageError, Span, VaultEntry

MIN_DIGITS_FOR_DIGIT_SEARCH = 6
MIN_LENGTH_FOR_FUZZY_SEARCH = 4

_ANY_TOKEN = re.compile(r"<[A-Z][A-Z_]*?_(?:\d{3,}|REDACTED)>")
_NUMBERED_TOKEN = re.compile(r"<[A-Z][A-Z_]*?_\d{3,}>")
_WHITESPACE = re.compile(r"\s+")


def _collapsed(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    offsets: list[int] = []
    previous_space = False
    for index, char in enumerate(text):
        if char.isspace():
            if previous_space:
                continue
            chars.append(" ")
            previous_space = True
        else:
            chars.append(char)
            previous_space = False
        offsets.append(index)
    return "".join(chars), offsets


def _digits_only(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    offsets: list[int] = []
    for index, char in enumerate(text):
        if char.isdigit():
            chars.append(char)
            offsets.append(index)
    return "".join(chars), offsets


def _needle_pattern(needle: str, *, bounded: bool) -> re.Pattern[str]:
    body = re.escape(needle)
    if not bounded:
        return re.compile(body, re.IGNORECASE)
    prefix = r"(?<![^\W_])" if needle[:1].isalnum() else ""
    suffix = r"s?(?![^\W_])" if needle[-1:].isalnum() else ""
    return re.compile(prefix + body + suffix, re.IGNORECASE)


def _projected_hits(
    projection: str, offsets: list[int], needle: str, *, bounded: bool
) -> set[tuple[int, int]]:
    if not needle:
        return set()
    hits: set[tuple[int, int]] = set()
    for match in _needle_pattern(needle, bounded=bounded).finditer(projection):
        if match.end() == match.start():
            continue
        hits.add((offsets[match.start()], offsets[match.end() - 1] + 1))
    return hits


def _merged(hits: set[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(hits):
        if merged and start < merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
            continue
        merged.append((start, end))
    return merged


class _Projections:
    """The whole-text views a leak search needs, each built at most once per text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.collapsed = _collapsed(text)
        self._digits: tuple[str, list[int]] | None = None

    def digits(self) -> tuple[str, list[int]]:
        """The digits of the text with their original offsets."""
        if self._digits is None:
            self._digits = _digits_only(self.text)
        return self._digits


def _occurrences(views: _Projections, value: str) -> set[tuple[int, int]]:
    if not value:
        return set()
    text = views.text
    hits: set[tuple[int, int]] = set()
    if len(value) < MIN_LENGTH_FOR_FUZZY_SEARCH:
        pattern = rf"(?<!\w){re.escape(value)}(?!\w)"
        return {(m.start(), m.end()) for m in re.finditer(pattern, text)}
    digits = "".join(char for char in value if char.isdigit())
    bounded = not digits
    for match in _needle_pattern(value, bounded=bounded).finditer(text):
        hits.add((match.start(), match.end()))
    projection, offsets = views.collapsed
    collapsed_value = _WHITESPACE.sub(" ", value).strip()
    hits |= _projected_hits(projection, offsets, collapsed_value, bounded=bounded)
    if len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH:
        projection, offsets = views.digits()
        hits |= _projected_hits(projection, offsets, digits, bounded=False)
    return hits


def _policy(registry: ClassRegistry, data_class: str) -> Policy:
    if data_class in registry:
        return registry.get(data_class).policy
    return Policy.TOKENIZE


def _deduplicate(leaks: list[Leak]) -> list[Leak]:
    seen: set[Leak] = set()
    unique: list[Leak] = []
    for leak in leaks:
        if leak in seen:
            continue
        seen.add(leak)
        unique.append(leak)
    return unique


def check_leakage(
    text: str,
    entries: Mapping[str, VaultEntry],
    scan: Callable[[str], DetectionReport],
    registry: ClassRegistry,
) -> None:
    """Raise `LeakageError` when the pseudonymized text still exposes data."""
    leaks: list[Leak] = []
    token_spans = [Span(match.start(), match.end()) for match in _ANY_TOKEN.finditer(text)]

    for finding in scan(text).findings:
        if _policy(registry, finding.data_class) is Policy.IGNORE:
            continue
        if any(token.contains(finding.span) for token in token_spans):
            continue
        leaks.append(
            Leak("residual_finding", finding.data_class, finding.span.start, finding.span.end)
        )

    views = _Projections(text)
    for entry in entries.values():
        hits: set[tuple[int, int]] = set()
        for value in dict.fromkeys([entry.value, *entry.surface_forms]):
            hits |= _occurrences(views, value)
        for start, end in _merged(hits):
            leaks.append(Leak("original_value", entry.data_class, start, end))

    for match in _NUMBERED_TOKEN.finditer(text):
        if match.group(0) not in entries:
            leaks.append(Leak("unknown_token", "", match.start(), match.end()))

    if leaks:
        raise LeakageError(_deduplicate(leaks))
