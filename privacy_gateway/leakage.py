"""Fail-closed validation that pseudonymized text carries no original data."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.detect.session import SubstringSweep, known_occurrences
from privacy_gateway.model import DetectionReport, Finding, Leak, LeakageError, Span, VaultEntry
from privacy_gateway.tokens import ANY_TOKEN, NUMBERED_TOKEN

MIN_LENGTH_FOR_FUZZY_SEARCH = 4
REDACTED_SUFFIX = "_REDACTED>"


def glued_to_token(finding: Finding, tokens: list[Span]) -> bool:
    """A handle that starts right after a token is the host part of `user@host`, not a handle."""
    return finding.data_class == "SOCIAL_MEDIA_HANDLE" and any(
        token.end == finding.span.start for token in tokens
    )


def _short_touching_token(start: int, end: int, tokens: list[Span]) -> bool:
    """A short hit right next to a token was part of a longer word before the token went in."""
    return end - start < MIN_LENGTH_FOR_FUZZY_SEARCH and any(
        token.end == start or token.start == end for token in tokens
    )


def _short_fragment_next_to_token(text: str, start: int, end: int, tokens: list[Span]) -> bool:
    """A short known value next to a token that runs on into letters or digits on its other side.

    A complete short value next to a token (`<PHONE_001>li`) is a leak.
    """
    if end - start >= MIN_LENGTH_FOR_FUZZY_SEARCH:
        return False
    after = end < len(text) and text[end].isalnum() and any(t.end == start for t in tokens)
    before = start > 0 and text[start - 1].isalnum() and any(t.start == end for t in tokens)
    return after or before


def _only_tokens(text: str, span: Span, tokens: list[Span]) -> bool:
    """Nothing but tokens and punctuation inside `span`, so it carries no value."""
    rest = list(text[span.start : span.end])
    for token in tokens:
        for index in range(max(token.start, span.start), min(token.end, span.end)):
            rest[index - span.start] = " "
    return not any(char.isalnum() for char in rest)


def exempt_from_residual(finding: Finding, tokens: list[Span], text: str) -> bool:
    """A residual finding that is part of a token or glued to one is no leak."""
    return (
        any(token.contains(finding.span) for token in tokens)
        or _only_tokens(text, finding.span, tokens)
        or glued_to_token(finding, tokens)
        or _short_touching_token(finding.span.start, finding.span.end, tokens)
    )


def redacted_token(data_class: str) -> str:
    """The marker that replaces a value of a redacted class."""
    return f"<{data_class}{REDACTED_SUFFIX}"


def issued_token_spans(text: str, entries: Mapping[str, VaultEntry]) -> list[Span]:
    """Spans of the tokens a session issued and of redaction markers, not of other look-alikes."""
    return [
        Span(match.start(), match.end())
        for match in ANY_TOKEN.finditer(text)
        if match.group(0) in entries or match.group(0).endswith(REDACTED_SUFFIX)
    ]


def numbered_tokens(text: str) -> frozenset[str]:
    """Every numbered token-shaped string in `text`."""
    return frozenset(match.group(0) for match in NUMBERED_TOKEN.finditer(text))


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
    literal_tokens: frozenset[str] = frozenset(),
    *,
    sweep: bool = True,
    redacted: Mapping[str, str] | None = None,
) -> None:
    """Raise `LeakageError` when the pseudonymized text still exposes data.

    `literal_tokens` are token-shaped strings that were already in the input text. With `sweep`
    a plain substring search for known values runs beside `known_occurrences`. `redacted` maps
    values that were redacted (held in memory only) to their class; a copy left is a leak.
    """
    leaks: list[Leak] = []
    token_spans = issued_token_spans(text, entries)

    report = scan(text)
    for finding in report.findings:
        if _policy(registry, finding.data_class) is Policy.IGNORE:
            continue
        if exempt_from_residual(finding, token_spans, text):
            continue
        leaks.append(
            Leak("residual_finding", finding.data_class, finding.span.start, finding.span.end)
        )

    known: dict[str, tuple[str, str]] = {}
    for token, entry in entries.items():
        for form in [entry.value, *entry.surface_forms]:
            if form:
                known.setdefault(form, (entry.data_class, token))
    for value, data_class in (redacted or {}).items():
        known.setdefault(value, (data_class, redacted_token(data_class)))
    for span, (data_class, _) in known_occurrences(text, known, registry):
        if any(token.contains(span) for token in token_spans):
            continue
        if _short_fragment_next_to_token(text, span.start, span.end, token_spans):
            continue
        if data_class == "SOCIAL_MEDIA_HANDLE" and any(t.end == span.start for t in token_spans):
            continue
        leaks.append(Leak("original_value", data_class, span.start, span.end))

    if sweep:
        ignored = [
            finding.span
            for finding in report.findings
            if _policy(registry, finding.data_class) is Policy.IGNORE
        ]
        for span, (data_class, _) in SubstringSweep(known).find(text):
            if any(token.contains(span) for token in token_spans):
                continue
            if any(span.overlaps(other) for other in ignored):
                continue
            if data_class == "SOCIAL_MEDIA_HANDLE" and any(t.end == span.start for t in token_spans):
                continue
            leaks.append(Leak("original_value", data_class, span.start, span.end))

    for match in NUMBERED_TOKEN.finditer(text):
        if match.group(0) not in entries and match.group(0) not in literal_tokens:
            leaks.append(Leak("unknown_token", "", match.start(), match.end()))

    if leaks:
        raise LeakageError(_deduplicate(leaks))
