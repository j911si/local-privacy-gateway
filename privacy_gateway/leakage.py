"""Fail-closed validation that pseudonymized text carries no original data."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.detect.session import SubstringSweep, known_occurrences
from privacy_gateway.model import DetectionReport, Finding, Leak, LeakageError, Span, VaultEntry
from privacy_gateway.tokens import ANY_TOKEN, NUMBERED_TOKEN

MIN_LENGTH_FOR_FUZZY_SEARCH = 4


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


def exempt_from_residual(finding: Finding, tokens: list[Span]) -> bool:
    """A residual finding that is part of a token or glued to one is no leak."""
    return (
        any(token.contains(finding.span) for token in tokens)
        or glued_to_token(finding, tokens)
        or _short_touching_token(finding.span.start, finding.span.end, tokens)
    )


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
) -> None:
    """Raise `LeakageError` when the pseudonymized text still exposes data.

    `literal_tokens` are token-shaped strings that were already in the input text. With `sweep`
    a plain substring search for known values runs beside `known_occurrences`.
    """
    leaks: list[Leak] = []
    token_spans = [Span(match.start(), match.end()) for match in ANY_TOKEN.finditer(text)]

    report = scan(text)
    for finding in report.findings:
        if _policy(registry, finding.data_class) is Policy.IGNORE:
            continue
        if exempt_from_residual(finding, token_spans):
            continue
        leaks.append(
            Leak("residual_finding", finding.data_class, finding.span.start, finding.span.end)
        )

    known: dict[str, tuple[str, str]] = {}
    for token, entry in entries.items():
        for form in [entry.value, *entry.surface_forms]:
            if form:
                known.setdefault(form, (entry.data_class, token))
    for span, (data_class, _) in known_occurrences(text, known, registry):
        if any(token.contains(span) for token in token_spans):
            continue
        if _short_touching_token(span.start, span.end, token_spans):
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
