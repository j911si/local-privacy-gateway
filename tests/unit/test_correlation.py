from __future__ import annotations

import re

from privacy_gateway.config import Config
from privacy_gateway.detect.correlation import correlate
from privacy_gateway.model import Entity, Finding, Span


def _finding(
    text: str,
    value: str,
    data_class: str,
    confidence: float,
    *,
    stage: str = "context",
    start: int = 0,
    children: list[Finding] | None = None,
    **attributes: str,
) -> Finding:
    offset = text.index(value, start)
    return Finding(
        span=Span(offset, offset + len(value)),
        data_class=data_class,
        stage=stage,
        confidence=confidence,
        attributes=dict(attributes),
        children=children or [],
    )


def _entity_of(entities: dict[str, Entity], finding: Finding) -> Entity:
    assert finding.entity_id is not None
    return entities[finding.entity_id]


def test_full_name_bare_last_name_and_initials_form_one_entity(default_config: Config) -> None:
    text = "Sehr geehrte Frau Anna Müller, Müller meldet sich. A. M. dankt."
    salutation = _finding(text, "Frau", "SALUTATION", 0.95)
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95, gender="female")
    bare = _finding(text, "Müller", "PERSON_LAST_NAME", 0.3, start=30, bundled="true")
    initials = _finding(text, "A. M.", "PERSON_INITIALS", 0.4)

    findings, entities = correlate(text, [salutation, full, bare, initials], default_config)

    assert full.entity_id == bare.entity_id == initials.entity_id
    person = _entity_of(entities, full)
    assert person.spans == [full.span, bare.span, initials.span]
    assert person.attributes["gender"] == "female"
    assert bare.confidence == 0.9
    assert initials.confidence == 0.9
    assert salutation.entity_id != full.entity_id
    assert findings == [salutation, full, bare, initials]


def test_different_last_names_yield_two_entities(default_config: Config) -> None:
    text = "Anna Müller und Peter Schmidt."
    mueller = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    schmidt = _finding(text, "Peter Schmidt", "PERSON_FULL_NAME", 0.95)

    _, entities = correlate(text, [mueller, schmidt], default_config)

    assert mueller.entity_id != schmidt.entity_id
    assert {mueller.entity_id, schmidt.entity_id} <= set(entities)


def test_entity_ids_are_numbered_by_first_span(default_config: Config) -> None:
    text = "Anna Müller und Peter Schmidt."
    mueller = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    schmidt = _finding(text, "Peter Schmidt", "PERSON_FULL_NAME", 0.95)

    _, entities = correlate(text, [schmidt, mueller], default_config)

    assert mueller.entity_id == "e1"
    assert schmidt.entity_id == "e2"
    assert list(entities) == ["e1", "e2"]


def test_conflicting_gender_is_removed_and_flagged(default_config: Config) -> None:
    text = "Frau Müller sprach mit Herr Müller."
    female = _finding(text, "Müller", "PERSON_LAST_NAME", 0.95, gender="female")
    male = _finding(text, "Müller", "PERSON_LAST_NAME", 0.95, start=20, gender="male")

    _, entities = correlate(text, [female, male], default_config)

    assert female.entity_id == male.entity_id
    person = _entity_of(entities, female)
    assert "gender" not in person.attributes
    assert person.attributes["gender_conflict"] == "true"
    assert "gender" not in female.attributes
    assert male.attributes["gender_conflict"] == "true"


def test_same_iban_in_two_surface_forms_is_one_entity(default_config: Config) -> None:
    text = "DE89 3704 0044 0532 0130 00 alias DE89370400440532013000"
    spaced = _finding(text, "DE89 3704 0044 0532 0130 00", "IBAN", 0.95, stage="pattern")
    plain = _finding(text, "DE89370400440532013000", "IBAN", 0.95, stage="pattern")

    _, entities = correlate(text, [spaced, plain], default_config)

    assert spaced.entity_id == plain.entity_id
    assert len(_entity_of(entities, spaced).spans) == 2


def test_email_username_links_to_person_entity(default_config: Config) -> None:
    text = "Anna Müller schreibt von a.mueller@example.com."
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    username = _finding(text, "a.mueller", "PERSON_USERNAME", 0.98, stage="structured", start=20)
    email = _finding(
        text,
        "a.mueller@example.com",
        "EMAIL",
        0.98,
        stage="structured",
        children=[username],
    )

    _, _entities = correlate(text, [full, email], default_config)

    assert email.attributes["linked_entity"] == full.entity_id


def test_ambiguous_bare_last_name_stays_unlinked(default_config: Config) -> None:
    text = "Anna Müller und Peter Müller. Müller ruft an."
    anna = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    peter = _finding(text, "Peter Müller", "PERSON_FULL_NAME", 0.95)
    bare = _finding(text, "Müller", "PERSON_LAST_NAME", 0.3, start=29)

    _, _entities = correlate(text, [anna, peter, bare], default_config)

    assert bare.entity_id not in {anna.entity_id, peter.entity_id}
    assert bare.confidence == 0.3


def test_bundled_first_name_joins_matching_entity(default_config: Config) -> None:
    text = "Anna Müller kam. Anna ging."
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    bare = _finding(text, "Anna", "PERSON_FIRST_NAME", 0.3, start=15, bundled="true")

    _, _entities = correlate(text, [full, bare], default_config)

    assert bare.entity_id == full.entity_id
    assert bare.confidence == 0.9


def test_low_confidence_findings_are_not_dropped(default_config: Config) -> None:
    text = "Bonn"
    city = _finding(text, "Bonn", "CITY", 0.3, stage="dictionary", bundled="true")

    findings, entities = correlate(text, [city], default_config)

    assert findings == [city]
    assert city.entity_id in entities


def test_session_token_reaches_the_merged_entity_and_its_findings(default_config: Config) -> None:
    text = "Anna Müller ruft an."
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)
    known = _finding(
        text, "Müller", "PERSON_LAST_NAME", 1.0, stage="session", start=5, token="<PERSON_001>"
    )

    _, entities = correlate(text, [full, known], default_config)

    assert full.entity_id == known.entity_id
    assert _entity_of(entities, full).attributes["token"] == "<PERSON_001>"
    assert full.attributes["token"] == "<PERSON_001>"


def test_two_session_tokens_in_one_entity_are_not_propagated(default_config: Config) -> None:
    text = "Anna Müller und Müller."
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95, token="<PERSON_001>")
    bare = _finding(
        text, "Müller", "PERSON_LAST_NAME", 1.0, stage="session", start=16, token="<PERSON_002>"
    )

    _, entities = correlate(text, [full, bare], default_config)

    assert full.entity_id == bare.entity_id
    assert "token" not in _entity_of(entities, full).attributes
    assert full.attributes["token"] == "<PERSON_001>"
    assert bare.attributes["token"] == "<PERSON_002>"


def test_canonical_norm_is_not_copied_into_finding_attributes(default_config: Config) -> None:
    text = "Anna Müller"
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)

    correlate(text, [full], default_config)

    assert "canonical_norm" not in full.attributes
    assert "anna müller" not in full.attributes.values()


def test_entity_canonical_norm_is_a_hash(default_config: Config) -> None:
    text = "Anna Müller"
    full = _finding(text, "Anna Müller", "PERSON_FULL_NAME", 0.95)

    _, entities = correlate(text, [full], default_config)

    entity = _entity_of(entities, full)
    assert re.fullmatch(r"[0-9a-f]{16}", entity.canonical_norm)
    assert "müller" not in repr(entity).casefold()
