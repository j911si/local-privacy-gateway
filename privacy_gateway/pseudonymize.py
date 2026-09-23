"""Replaces detected spans with stable, context-preserving tokens."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from privacy_gateway.classes import PERSON_LABEL, ClassRegistry, Policy
from privacy_gateway.config import Config
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE
from privacy_gateway.model import DetectionReport, Finding, Span

GENDER_SUFFIXES = ("female", "male")
REUSED_ATTRIBUTE = "reused"

_WHITESPACE = re.compile(r"\s+")
_TOKEN_LITERAL = re.compile(r"<(?P<label>[A-Z][A-Z_]*?)_(?P<number>\d{3,})>")
_GENDER_LABELS = tuple(f"{PERSON_LABEL}_{suffix.upper()}" for suffix in GENDER_SUFFIXES)


@dataclass
class TokenAssignment:
    """One token and every span it replaced."""

    token: str
    data_class: str
    entity_id: str | None
    spans: list[Span]
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class PseudonymizedText:
    """Rewritten text plus the mapping that restoration needs."""

    text: str
    assignments: list[TokenAssignment]


def _normalize(value: str) -> str:
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value).casefold()).strip()


def _attributes_for(finding: Finding, report: DetectionReport) -> dict[str, str]:
    attributes = dict(finding.attributes)
    if finding.entity_id is not None:
        entity = report.entities.get(finding.entity_id)
        if entity is not None:
            attributes.update(entity.attributes)
    return attributes


def _reserved_numbers(text: str) -> dict[str, set[int]]:
    """Token numbers the text already carries as literals, keyed by counter base."""
    reserved: dict[str, set[int]] = {}
    for match in _TOKEN_LITERAL.finditer(text):
        label = match.group("label")
        base = PERSON_LABEL if label in _GENDER_LABELS else label
        reserved.setdefault(base, set()).add(int(match.group("number")))
    return reserved


def _allocate_token(
    registry: ClassRegistry,
    data_class: str,
    attributes: dict[str, str],
    counters: dict[str, int],
    reserved: dict[str, set[int]],
) -> str:
    base = registry.label_for(data_class)
    label = base
    if base == PERSON_LABEL and attributes.get("gender") in GENDER_SUFFIXES:
        label = f"{base}_{attributes['gender'].upper()}"
    number = counters.get(base, 0) + 1
    while number in reserved.get(base, ()):
        number += 1
    counters[base] = number
    return f"<{label}_{number:03d}>"


def _entity_key(text: str, finding: Finding) -> object:
    if finding.entity_id is not None:
        return finding.entity_id
    return (finding.data_class, _normalize(text[finding.span.start : finding.span.end]))


def _known_tokens(text: str, report: DetectionReport) -> dict[object, str]:
    tokens: dict[object, str] = {}
    for finding in report.findings:
        token = finding.attributes.get(TOKEN_ATTRIBUTE)
        if token is not None:
            tokens.setdefault(_entity_key(text, finding), token)
    return tokens


def pseudonymize_text(
    text: str,
    report: DetectionReport,
    config: Config,
    *,
    counters: dict[str, int] | None = None,
) -> PseudonymizedText:
    """Rewrite every non-ignored finding into a token or a redaction marker."""
    registry = config.registry
    counters = {} if counters is None else counters
    known_tokens = _known_tokens(text, report)
    reserved = _reserved_numbers(text)
    by_key: dict[object, TokenAssignment] = {}
    assignments: list[TokenAssignment] = []
    replacements: list[tuple[Span, str]] = []

    for finding in report.findings:
        data_class = registry.get(finding.data_class)
        if data_class.policy is Policy.IGNORE:
            continue
        if data_class.policy is Policy.REDACT:
            replacements.append((finding.span, f"<{data_class.name}_REDACTED>"))
            continue
        attributes = _attributes_for(finding, report)
        key = _entity_key(text, finding)
        assignment = by_key.get(key)
        if assignment is None:
            token = known_tokens.get(key)
            if token is None:
                token = _allocate_token(
                    registry, data_class.name, attributes, counters, reserved
                )
            else:
                attributes[REUSED_ATTRIBUTE] = "true"
            assignment = TokenAssignment(
                token=token,
                data_class=finding.data_class,
                entity_id=finding.entity_id,
                spans=[],
                attributes=attributes,
            )
            by_key[key] = assignment
            assignments.append(assignment)
        assignment.spans.append(finding.span)
        replacements.append((finding.span, assignment.token))

    rewritten = text
    for span, replacement in sorted(replacements, key=lambda item: item[0].start, reverse=True):
        rewritten = rewritten[: span.start] + replacement + rewritten[span.end :]

    for assignment in assignments:
        assignment.spans.sort()

    return PseudonymizedText(text=rewritten, assignments=assignments)
