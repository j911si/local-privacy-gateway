"""Overlap resolution: turn overlapping candidates into one clean sequence."""

from __future__ import annotations

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


def _order(finding: Finding) -> tuple[int, int]:
    return (finding.span.start, -len(finding.span))


def resolve_overlaps(findings: list[Finding], registry: ClassRegistry) -> list[Finding]:
    """Return non-overlapping findings sorted by span start, losers cut to their rest."""
    kept: list[Finding] = []
    pending = sorted(findings, key=_order)
    while pending:
        finding = pending.pop(0)
        for existing in kept:
            if not existing.span.overlaps(finding.span):
                continue
            if _loses(finding, existing, registry):
                pending.extend(_remainders(finding, existing.span))
            else:
                kept.remove(existing)
                pending.extend(_remainders(existing, finding.span))
                pending.append(finding)
            pending.sort(key=_order)
            break
        else:
            kept.append(finding)
    return sorted(kept, key=lambda f: f.span.start)


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
