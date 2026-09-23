"""Entity correlation: group findings that refer to the same real-world subject."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field

from privacy_gateway.config import Config
from privacy_gateway.model import Entity, Finding

DIGIT_ONLY_CLASSES = frozenset(
    {"PHONE", "MOBILE_PHONE", "FAX", "IBAN", "CREDIT_CARD", "BANK_ACCOUNT"}
)
PERSON_FULL_NAME = "PERSON_FULL_NAME"
PERSON_LAST_NAME = "PERSON_LAST_NAME"
PERSON_FIRST_NAME = "PERSON_FIRST_NAME"
PERSON_INITIALS = "PERSON_INITIALS"
PERSON_USERNAME = "PERSON_USERNAME"
EMAIL = "EMAIL"
PERSON_CLASSES = frozenset({PERSON_FULL_NAME, PERSON_LAST_NAME, PERSON_FIRST_NAME})
GENERIC_ID = "GENERIC_ID"
ENTITY_CONFIDENCE = 0.5
CANONICAL_HASH_LENGTH = 16
PROMOTED_CONFIDENCE = 0.9
GENDER = "gender"
GENDER_CONFLICT = "gender_conflict"
LINKED_ENTITY = "linked_entity"
TOKEN = "token"
FOLDINGS = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}


@dataclass
class _Group:
    """Findings sharing one class and one normalized key."""

    data_class: str
    key: str
    findings: list[Finding] = field(default_factory=list)
    entity_id: str = ""
    merged: bool = False

    @property
    def start(self) -> int:
        return min(f.span.start for f in self.findings)

    @property
    def confidence(self) -> float:
        return max(f.confidence for f in self.findings)


def correlate(
    text: str, findings: list[Finding], config: Config
) -> tuple[list[Finding], dict[str, Entity]]:
    """Set entity ids and attributes on findings and return the entities they belong to."""
    groups = _build_groups(text, findings)
    _resolve_persons(groups)
    _resolve_generic_ids(groups)
    entities = _assign_entities(groups)
    _apply_gender(groups, entities)
    _apply_token(groups, entities)
    _link_emails(text, findings, groups)
    return list(findings), entities


def _hashed(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:CANONICAL_HASH_LENGTH]


def _normalize_text(raw: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", raw).casefold().split())


def _fold(value: str) -> str:
    for source, target in FOLDINGS.items():
        value = value.replace(source, target)
    return value


def _letters(value: str) -> str:
    return "".join(char for char in value if char.isalpha())


def _key(text: str, finding: Finding) -> str:
    raw = text[finding.span.start : finding.span.end]
    if finding.data_class in DIGIT_ONLY_CLASSES:
        return "".join(char for char in raw if char.isdigit())
    return _normalize_text(raw)


def _build_groups(text: str, findings: list[Finding]) -> list[_Group]:
    groups: dict[tuple[str, str], _Group] = {}
    for finding in sorted(findings, key=lambda f: (f.span.start, f.span.end)):
        identity = (finding.data_class, _key(text, finding))
        group = groups.get(identity)
        if group is None:
            group = _Group(data_class=identity[0], key=identity[1])
            groups[identity] = group
        group.findings.append(finding)
    return list(groups.values())


def _name_parts(group: _Group) -> tuple[str | None, str | None]:
    if group.data_class == PERSON_FULL_NAME:
        parts = group.key.split()
        if len(parts) >= 2:
            return parts[0], parts[-1]
        return None, parts[0] if parts else None
    if group.data_class == PERSON_LAST_NAME:
        return None, group.key
    return group.key, None


def _initials(parts: tuple[str | None, str | None]) -> str:
    first, last = parts
    if not first or not last:
        return ""
    return first[0] + last[0]


def _join_target(
    group: _Group, people: list[_Group], names: dict[int, tuple[str | None, str | None]]
) -> _Group | None:
    candidates = [g for g in people if g is not group and not g.merged]
    if group.data_class == PERSON_LAST_NAME:
        matches = [g for g in candidates if names[id(g)][1] == group.key]
    elif group.data_class == PERSON_FIRST_NAME:
        matches = [g for g in candidates if names[id(g)][0] == group.key]
    elif group.data_class == PERSON_INITIALS:
        wanted = _letters(group.key)
        matches = [g for g in candidates if wanted and _initials(names[id(g)]) == wanted]
    else:
        return None
    return matches[0] if len(matches) == 1 else None


def _resolve_persons(groups: list[_Group]) -> None:
    people = [
        g for g in groups if g.data_class in PERSON_CLASSES and g.confidence >= ENTITY_CONFIDENCE
    ]
    names = {id(g): _name_parts(g) for g in people}
    for group in list(groups):
        if group.merged:
            continue
        target = _join_target(group, people, names)
        if target is None:
            continue
        for finding in group.findings:
            finding.confidence = max(finding.confidence, PROMOTED_CONFIDENCE)
        target.findings.extend(group.findings)
        group.merged = True
        groups.remove(group)


def _resolve_generic_ids(groups: list[_Group]) -> None:
    for group in [g for g in groups if g.data_class == GENERIC_ID]:
        matches = [g for g in groups if g is not group and g.key == group.key and not g.merged]
        if len(matches) != 1:
            continue
        matches[0].findings.extend(group.findings)
        group.merged = True
        groups.remove(group)


def _assign_entities(groups: list[_Group]) -> dict[str, Entity]:
    entities: dict[str, Entity] = {}
    for index, group in enumerate(sorted(groups, key=lambda g: g.start), start=1):
        entity_id = f"e{index}"
        group.entity_id = entity_id
        for finding in group.findings:
            finding.entity_id = entity_id
        entities[entity_id] = Entity(
            id=entity_id,
            data_class=group.data_class,
            canonical_norm=_hashed(group.key),
            spans=sorted({f.span for f in group.findings}),
        )
    return entities


def _apply_gender(groups: list[_Group], entities: dict[str, Entity]) -> None:
    for group in groups:
        entity = entities[group.entity_id]
        values = {f.attributes[GENDER] for f in group.findings if GENDER in f.attributes}
        if not values:
            continue
        if len(values) == 1:
            gender = values.pop()
            entity.attributes[GENDER] = gender
            for finding in group.findings:
                finding.attributes[GENDER] = gender
            continue
        entity.attributes[GENDER_CONFLICT] = "true"
        for finding in group.findings:
            finding.attributes.pop(GENDER, None)
            finding.attributes[GENDER_CONFLICT] = "true"


def _apply_token(groups: list[_Group], entities: dict[str, Entity]) -> None:
    for group in groups:
        values = {f.attributes[TOKEN] for f in group.findings if TOKEN in f.attributes}
        if len(values) != 1:
            continue
        token = values.pop()
        entities[group.entity_id].attributes[TOKEN] = token
        for finding in group.findings:
            finding.attributes[TOKEN] = token


def _link_emails(text: str, findings: list[Finding], groups: list[_Group]) -> None:
    last_names: list[tuple[str, str]] = []
    for group in groups:
        if group.data_class not in PERSON_CLASSES:
            continue
        last = _name_parts(group)[1]
        if last:
            last_names.append((_fold(last), group.entity_id))
    if not last_names:
        return
    for finding in findings:
        if finding.data_class != EMAIL:
            continue
        for child in finding.children:
            if child.data_class != PERSON_USERNAME:
                continue
            local = _fold(_normalize_text(text[child.span.start : child.span.end]))
            matches = {entity_id for last, entity_id in last_names if last in local}
            if len(matches) == 1:
                finding.attributes[LINKED_ENTITY] = matches.pop()
                break
