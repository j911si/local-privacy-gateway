from __future__ import annotations

from dataclasses import replace

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.config import Config
from privacy_gateway.model import DetectionReport, Entity, Finding, Span
from privacy_gateway.pseudonymize import pseudonymize_text

SPEC_TEXT = (
    "Sehr geehrte Frau Anna Müller,\n\n"
    "bitte kontaktieren Sie Herrn Thomas Schmidt regarding account 4711."
)


def _finding(
    text: str,
    value: str,
    data_class: str,
    *,
    entity_id: str | None = None,
    attributes: dict[str, str] | None = None,
    occurrence: int = 0,
) -> Finding:
    start = -1
    for _ in range(occurrence + 1):
        start = text.index(value, start + 1)
    return Finding(
        span=Span(start, start + len(value)),
        data_class=data_class,
        stage="context",
        confidence=0.9,
        entity_id=entity_id,
        attributes=dict(attributes or {}),
    )


def _report(findings: list[Finding], entities: dict[str, Entity] | None = None) -> DetectionReport:
    return DetectionReport(findings=findings, entities=entities or {}, stage_stats={})


def _with_policy(config: Config, name: str, policy: Policy) -> Config:
    classes = [
        replace(data_class, policy=policy) if data_class.name == name else data_class
        for data_class in config.registry
    ]
    return replace(config, registry=ClassRegistry(classes))


def _entity(entity_id: str, data_class: str, gender: str) -> Entity:
    return Entity(
        id=entity_id,
        data_class=data_class,
        canonical_norm="",
        spans=[],
        attributes={"gender": gender},
    )


def _spec_report() -> DetectionReport:
    findings = [
        _finding(SPEC_TEXT, "Frau", "SALUTATION"),
        _finding(SPEC_TEXT, "Anna Müller", "PERSON_FULL_NAME", entity_id="e1"),
        _finding(SPEC_TEXT, "Herrn", "SALUTATION"),
        _finding(SPEC_TEXT, "Thomas Schmidt", "PERSON_FULL_NAME", entity_id="e2"),
        _finding(SPEC_TEXT, "4711", "ACCOUNT_ID"),
    ]
    entities = {
        "e1": _entity("e1", "PERSON_FULL_NAME", "female"),
        "e2": _entity("e2", "PERSON_FULL_NAME", "male"),
    }
    return _report(findings, entities)


def test_spec_example_with_salutation_ignored(default_config: Config) -> None:
    config = _with_policy(default_config, "SALUTATION", Policy.IGNORE)

    result = pseudonymize_text(SPEC_TEXT, _spec_report(), config)

    assert result.text == (
        "Sehr geehrte Frau <PERSON_FEMALE_001>,\n\n"
        "bitte kontaktieren Sie Herrn <PERSON_MALE_002> regarding account <ACCOUNT_ID_001>."
    )
    assert [a.token for a in result.assignments] == [
        "<PERSON_FEMALE_001>",
        "<PERSON_MALE_002>",
        "<ACCOUNT_ID_001>",
    ]


def test_default_config_leaves_salutations_readable(default_config: Config) -> None:
    result = pseudonymize_text(SPEC_TEXT, _spec_report(), default_config)

    assert result.text == (
        "Sehr geehrte Frau <PERSON_FEMALE_001>,\n\n"
        "bitte kontaktieren Sie Herrn <PERSON_MALE_002> regarding account <ACCOUNT_ID_001>."
    )
    assert "SALUTATION" not in [a.data_class for a in result.assignments]


def test_same_entity_twice_gets_one_token_and_both_spans(default_config: Config) -> None:
    text = "Müller kam. Später rief Müller an."
    findings = [
        _finding(text, "Müller", "PERSON_LAST_NAME", entity_id="e1"),
        _finding(text, "Müller", "PERSON_LAST_NAME", entity_id="e1", occurrence=1),
    ]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "<PERSON_001> kam. Später rief <PERSON_001> an."
    assert len(result.assignments) == 1
    assert result.assignments[0].spans == [Span(0, 6), Span(24, 30)]


def test_same_class_and_value_without_entity_share_one_token(default_config: Config) -> None:
    text = "Konto 4711 und Konto  4711 sind gleich."
    findings = [
        _finding(text, "4711", "ACCOUNT_ID"),
        _finding(text, "4711", "ACCOUNT_ID", occurrence=1),
    ]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "Konto <ACCOUNT_ID_001> und Konto  <ACCOUNT_ID_001> sind gleich."


def test_spans_are_stored_left_to_right(default_config: Config) -> None:
    text = "4711 und 4711"
    findings = [
        _finding(text, "4711", "ACCOUNT_ID", occurrence=1),
        _finding(text, "4711", "ACCOUNT_ID"),
    ]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "<ACCOUNT_ID_001> und <ACCOUNT_ID_001>"
    assert result.assignments[0].spans == [Span(0, 4), Span(9, 13)]


def test_two_persons_share_the_person_counter(default_config: Config) -> None:
    text = "Müller und Schmidt"
    findings = [
        _finding(text, "Müller", "PERSON_LAST_NAME", entity_id="e1"),
        _finding(text, "Schmidt", "PERSON_LAST_NAME", entity_id="e2"),
    ]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "<PERSON_001> und <PERSON_002>"


def test_gender_from_finding_attributes_is_used(default_config: Config) -> None:
    text = "Müller"
    findings = [_finding(text, "Müller", "PERSON_LAST_NAME", attributes={"gender": "female"})]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "<PERSON_FEMALE_001>"


def test_redact_policy_yields_redacted_marker_without_assignment(default_config: Config) -> None:
    text = "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop rest"
    value = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
    findings = [_finding(text, value, "JWT")]

    result = pseudonymize_text(text, _report(findings), default_config)

    assert result.text == "token <JWT_REDACTED> rest"
    assert result.assignments == []


def test_ignore_policy_leaves_text_unchanged(default_config: Config) -> None:
    config = _with_policy(default_config, "SALUTATION", Policy.IGNORE)
    text = "Sehr geehrte Frau,"
    findings = [_finding(text, "Frau", "SALUTATION")]

    result = pseudonymize_text(text, _report(findings), config)

    assert result.text == text
    assert result.assignments == []


def test_counters_continue_from_the_given_state(default_config: Config) -> None:
    text = "Müller und Schmidt"
    findings = [
        _finding(text, "Müller", "PERSON_LAST_NAME", entity_id="e1"),
        _finding(text, "Schmidt", "PERSON_LAST_NAME", entity_id="e2"),
    ]
    counters = {"PERSON": 2}

    result = pseudonymize_text(text, _report(findings), default_config, counters=counters)

    assert result.text == "<PERSON_003> und <PERSON_004>"
    assert counters == {"PERSON": 4}


def test_counters_continue_across_gender_labels(default_config: Config) -> None:
    text = "Müller"
    findings = [_finding(text, "Müller", "PERSON_LAST_NAME", attributes={"gender": "female"})]
    counters = {"PERSON": 2}

    result = pseudonymize_text(text, _report(findings), default_config, counters=counters)

    assert result.text == "<PERSON_FEMALE_003>"
    assert counters == {"PERSON": 3}


def test_known_token_is_reused_and_does_not_consume_a_number(default_config: Config) -> None:
    text = "Müller und Schmidt"
    findings = [
        _finding(
            text,
            "Müller",
            "PERSON_LAST_NAME",
            entity_id="e1",
            attributes={"token": "<PERSON_FEMALE_001>"},
        ),
        _finding(text, "Schmidt", "PERSON_LAST_NAME", entity_id="e2"),
    ]
    counters = {"PERSON": 1}

    result = pseudonymize_text(text, _report(findings), default_config, counters=counters)

    assert result.text == "<PERSON_FEMALE_001> und <PERSON_002>"
    assert counters == {"PERSON": 2}
    reused, fresh = result.assignments
    assert reused.attributes["reused"] == "true"
    assert "reused" not in fresh.attributes


def test_known_token_covers_every_occurrence_of_the_entity(default_config: Config) -> None:
    text = "Müller kam. Später rief Müller an."
    findings = [
        _finding(
            text,
            "Müller",
            "PERSON_LAST_NAME",
            entity_id="e1",
            attributes={"token": "<PERSON_001>"},
        ),
        _finding(text, "Müller", "PERSON_LAST_NAME", entity_id="e1", occurrence=1),
    ]

    result = pseudonymize_text(text, _report(findings), default_config, counters={})

    assert result.text == "<PERSON_001> kam. Später rief <PERSON_001> an."
    assert len(result.assignments) == 1


def test_assignment_carries_class_entity_and_attributes(default_config: Config) -> None:
    text = "Anna Müller"
    findings = [_finding(text, "Anna Müller", "PERSON_FULL_NAME", entity_id="e1")]
    entities = {"e1": _entity("e1", "PERSON_FULL_NAME", "female")}

    result = pseudonymize_text(text, _report(findings, entities), default_config)

    assignment = result.assignments[0]
    assert assignment.data_class == "PERSON_FULL_NAME"
    assert assignment.entity_id == "e1"
    assert assignment.attributes["gender"] == "female"


def test_token_literal_in_the_text_is_skipped_by_the_counter(default_config: Config) -> None:
    text = "Beispiel <IBAN_001> und echte IBAN: DE89370400440532013000"
    report = _report([_finding(text, "DE89370400440532013000", "IBAN")])

    result = pseudonymize_text(text, report, default_config)

    assert result.text == "Beispiel <IBAN_001> und echte IBAN: <IBAN_002>"
    assert [a.token for a in result.assignments] == ["<IBAN_002>"]


def test_gendered_token_literal_reserves_the_person_counter(default_config: Config) -> None:
    text = "<PERSON_FEMALE_001> schrieb an Anna Müller"
    report = _report(
        [_finding(text, "Anna Müller", "PERSON_FULL_NAME", entity_id="e1")],
        {"e1": _entity("e1", "PERSON_FULL_NAME", "female")},
    )

    result = pseudonymize_text(text, report, default_config)

    assert result.text == "<PERSON_FEMALE_001> schrieb an <PERSON_FEMALE_002>"
