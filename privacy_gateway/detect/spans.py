"""Overlap resolution: turn overlapping candidates into one clean sequence."""

from __future__ import annotations

import bisect
import heapq
from dataclasses import replace

from privacy_gateway.classes import ClassRegistry
from privacy_gateway.model import Finding, Span

STRUCTURED_STAGE = "structured"
TOKEN_ATTRIBUTE = "token"
STAGE_ORDER: dict[str, int] = {
    "session": -1,
    "structured": 0,
    "pattern": 1,
    "dictionary": 2,
    "context": 3,
    "correlation": 4,
}


def mostly_digits(value: str) -> bool:
    """True when at least half of a value's letters and digits are digits."""
    chars = [char for char in value if char.isalnum()]
    return bool(chars) and sum(char.isdigit() for char in chars) * 2 >= len(chars)


def compact_digit_run(text: str, start: int, end: int) -> bool:
    """True when only digits and separators sit between the ends of a digit-only match."""
    return not any(char.isalpha() for char in text[start:end])


def _order(finding: Finding) -> tuple[int, int]:
    return (finding.span.start, -len(finding.span))


def resolve_overlaps(findings: list[Finding], registry: ClassRegistry) -> list[Finding]:
    """Return non-overlapping findings sorted by span start, losers cut to their rest.

    Candidates leave a heap in (start, -length, arrival) order, which is the order of the
    stable re-sorted list this replaces. The kept findings never overlap each other, so sorted
    by (start, end) their ends are sorted too and the ones overlapping a candidate form one
    run found by bisection; of that run the earliest kept one decides, as before.
    """
    pending: list[tuple[int, int, int, Finding]] = []
    arrival = 0

    def push(finding: Finding) -> None:
        nonlocal arrival
        heapq.heappush(pending, (finding.span.start, -len(finding.span), arrival, finding))
        arrival += 1

    for finding in sorted(findings, key=_order):
        push(finding)
    keys: list[tuple[int, int, int]] = []
    ends: list[int] = []
    kept: dict[int, Finding] = {}
    joined = 0
    while pending:
        finding = heapq.heappop(pending)[3]
        low = bisect.bisect_right(ends, finding.span.start)
        high = bisect.bisect_left(keys, (finding.span.end,))
        if low >= high:
            index = bisect.bisect_right(keys, (finding.span.start, finding.span.end, joined))
            keys.insert(index, (finding.span.start, finding.span.end, joined))
            ends.insert(index, finding.span.end)
            kept[joined] = finding
            joined += 1
            continue
        index = min(range(low, high), key=lambda position: keys[position][2])
        existing = kept[keys[index][2]]
        if _loses(finding, existing, registry):
            for rest in _remainders(finding, existing.span):
                push(rest)
        else:
            del kept[keys[index][2]]
            del keys[index]
            del ends[index]
            for rest in _remainders(existing, finding.span):
                push(rest)
            push(finding)
    return [kept[order] for _, _, order in sorted(keys, key=lambda key: (key[0], key[2]))]


def _loses(candidate: Finding, existing: Finding, registry: ClassRegistry) -> bool:
    contained = existing.span.contains(candidate.span)
    if contained and _has_token(candidate) and len(existing.span) > len(candidate.span):
        return True
    if contained and existing.stage == STRUCTURED_STAGE and not _has_token(candidate):
        return True
    return _rank(candidate, registry) <= _rank(existing, registry)


def _remainders(finding: Finding, covered: Span) -> list[Finding]:
    """The parts of `finding` that `covered` leaves open, as fresh findings."""
    rests = [
        Span(finding.span.start, min(finding.span.end, covered.start)),
        Span(max(finding.span.start, covered.end), finding.span.end),
    ]
    return [
        replace(finding, span=rest, entity_id=None, attributes={}, children=[])
        for rest in rests
        if rest.start < rest.end
    ]


def _has_token(finding: Finding) -> bool:
    return finding.attributes.get(TOKEN_ATTRIBUTE) is not None


def _rank(finding: Finding, registry: ClassRegistry) -> tuple[int, int, int, int, int]:
    return (
        int(_has_token(finding)),
        registry.priority_for(finding.data_class),
        len(finding.span),
        -STAGE_ORDER.get(finding.stage, len(STAGE_ORDER)),
        -finding.span.start,
    )
