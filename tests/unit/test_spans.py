from __future__ import annotations

from privacy_gateway.config import Config
from privacy_gateway.detect.spans import resolve_overlaps
from privacy_gateway.model import Finding, Span


def _finding(
    start: int,
    end: int,
    data_class: str,
    stage: str = "pattern",
    confidence: float = 0.9,
    children: list[Finding] | None = None,
    attributes: dict[str, str] | None = None,
) -> Finding:
    return Finding(
        span=Span(start, end),
        data_class=data_class,
        stage=stage,
        confidence=confidence,
        children=children or [],
        attributes=dict(attributes or {}),
    )


def _session(start: int, end: int, data_class: str, token: str) -> Finding:
    return _finding(start, end, data_class, stage="session", attributes={"token": token})


def test_higher_priority_class_wins_on_identical_span(default_config: Config) -> None:
    card = _finding(0, 19, "CREDIT_CARD")
    phone = _finding(0, 19, "PHONE")

    assert [f.data_class for f in resolve_overlaps([phone, card], default_config.registry)] == [
        "CREDIT_CARD"
    ]
    assert [f.data_class for f in resolve_overlaps([card, phone], default_config.registry)] == [
        "CREDIT_CARD"
    ]


def test_structured_parent_keeps_contained_finding_out(default_config: Config) -> None:
    url = _finding(0, 40, "URL", stage="structured", confidence=0.98)
    email = _finding(10, 30, "EMAIL", stage="structured", confidence=0.98)

    kept = resolve_overlaps([url, email], default_config.registry)

    assert [f.data_class for f in kept] == ["URL"]


def test_structured_parent_keeps_its_children(default_config: Config) -> None:
    child = _finding(8, 20, "FQDN", stage="structured", confidence=0.98)
    url = _finding(0, 40, "URL", stage="structured", confidence=0.98, children=[child])

    kept = resolve_overlaps([url], default_config.registry)

    assert kept[0].children == [child]


def test_adjacent_spans_are_both_kept(default_config: Config) -> None:
    first = _finding(0, 10, "ACCOUNT_ID")
    second = _finding(10, 20, "ACCOUNT_ID")

    kept = resolve_overlaps([first, second], default_config.registry)

    assert [(f.span.start, f.span.end) for f in kept] == [(0, 10), (10, 20)]


def test_equal_priority_longer_span_wins(default_config: Config) -> None:
    short = _finding(5, 12, "ACCOUNT_ID")
    long = _finding(0, 10, "ACCOUNT_ID")

    kept = resolve_overlaps([short, long], default_config.registry)

    assert [(f.span.start, f.span.end) for f in kept] == [(0, 10), (10, 12)]


def test_equal_priority_and_length_structured_beats_pattern(default_config: Config) -> None:
    pattern = _finding(0, 10, "ACCOUNT_ID", stage="pattern")
    structured = _finding(0, 10, "ACCOUNT_ID", stage="structured")

    kept = resolve_overlaps([pattern, structured], default_config.registry)

    assert [f.stage for f in kept] == ["structured"]
    assert resolve_overlaps([structured, pattern], default_config.registry)[0].stage == "structured"


def test_output_is_sorted_by_start(default_config: Config) -> None:
    findings = [
        _finding(30, 35, "ACCOUNT_ID"),
        _finding(0, 5, "ACCOUNT_ID"),
        _finding(10, 15, "ACCOUNT_ID"),
    ]

    kept = resolve_overlaps(findings, default_config.registry)

    assert [f.span.start for f in kept] == [0, 10, 30]


def test_empty_input_returns_empty_list(default_config: Config) -> None:
    assert resolve_overlaps([], default_config.registry) == []


def test_dictionary_internal_domain_outranks_generic_fqdn(default_config: Config) -> None:
    fqdn = _finding(0, 29, "FQDN", stage="pattern", confidence=0.95)
    internal = _finding(0, 29, "INTERNAL_DOMAIN", stage="dictionary", confidence=0.95)

    assert [f.data_class for f in resolve_overlaps([fqdn, internal], default_config.registry)] == [
        "INTERNAL_DOMAIN"
    ]
    assert [f.data_class for f in resolve_overlaps([internal, fqdn], default_config.registry)] == [
        "INTERNAL_DOMAIN"
    ]


def test_session_finding_beats_a_higher_priority_class(default_config: Config) -> None:
    card = _finding(0, 19, "CREDIT_CARD")
    session = _session(0, 19, "ACCOUNT_ID", "<ACCOUNT_ID_001>")

    assert [f.stage for f in resolve_overlaps([card, session], default_config.registry)] == [
        "session"
    ]
    assert [f.stage for f in resolve_overlaps([session, card], default_config.registry)] == [
        "session"
    ]


def test_session_finding_beats_a_partially_overlapping_span(default_config: Config) -> None:
    other = _finding(0, 8, "PERSON_FULL_NAME")
    session = _session(5, 11, "PERSON_LAST_NAME", "<PERSON_001>")

    kept = resolve_overlaps([other, session], default_config.registry)

    assert [(f.stage, f.span.start, f.span.end) for f in kept] == [
        ("pattern", 0, 5),
        ("session", 5, 11),
    ]


def test_a_strictly_containing_finding_beats_a_session_finding(default_config: Config) -> None:
    full = _finding(0, 11, "PERSON_FULL_NAME")
    session = _session(5, 11, "PERSON_LAST_NAME", "<PERSON_FEMALE_001>")

    kept = resolve_overlaps([full, session], default_config.registry)

    assert [(f.stage, f.span.start, f.span.end) for f in kept] == [("pattern", 0, 11)]
    assert resolve_overlaps([session, full], default_config.registry) == kept


def test_structured_url_beats_a_session_finding_inside_it(default_config: Config) -> None:
    url = _finding(0, 40, "URL", stage="structured", confidence=0.98)
    session = _session(8, 28, "FQDN", "<FQDN_001>")

    kept = resolve_overlaps([url, session], default_config.registry)

    assert [(f.data_class, f.span.start, f.span.end) for f in kept] == [("URL", 0, 40)]


def test_session_finding_keeps_a_finding_it_contains_out(default_config: Config) -> None:
    session = _session(0, 11, "PERSON_FULL_NAME", "<PERSON_001>")
    inner = _finding(5, 11, "PERSON_LAST_NAME")

    kept = resolve_overlaps([session, inner], default_config.registry)

    assert [(f.stage, f.span.start, f.span.end) for f in kept] == [("session", 0, 11)]


def test_session_finding_survives_a_structured_parent(default_config: Config) -> None:
    url = _finding(0, 40, "URL", stage="structured", confidence=0.98)
    session = _session(0, 40, "URL", "<URL_001>")

    assert [f.stage for f in resolve_overlaps([url, session], default_config.registry)] == [
        "session"
    ]
    assert [f.stage for f in resolve_overlaps([session, url], default_config.registry)] == [
        "session"
    ]


def test_url_outranks_an_fqdn_inside_it(default_config: Config) -> None:
    url = _finding(0, 40, "URL", stage="structured", confidence=0.98)
    fqdn = _finding(8, 28, "FQDN", stage="pattern", confidence=0.95)

    kept = resolve_overlaps([fqdn, url], default_config.registry)

    assert [f.data_class for f in kept] == ["URL"]
    assert default_config.registry.priority_for("URL") > default_config.registry.priority_for(
        "FQDN"
    )


def test_loser_keeps_its_uncovered_tail(default_config: Config) -> None:
    phone = _finding(0, 10, "PHONE")
    card = _finding(5, 25, "CREDIT_CARD")

    kept = resolve_overlaps([phone, card], default_config.registry)

    assert [(f.data_class, f.span.start, f.span.end) for f in kept] == [
        ("PHONE", 0, 5),
        ("CREDIT_CARD", 5, 25),
    ]


def test_loser_keeps_its_uncovered_head(default_config: Config) -> None:
    card = _finding(0, 20, "CREDIT_CARD")
    phone = _finding(15, 25, "PHONE")

    kept = resolve_overlaps([card, phone], default_config.registry)

    assert [(f.data_class, f.span.start, f.span.end) for f in kept] == [
        ("CREDIT_CARD", 0, 20),
        ("PHONE", 20, 25),
    ]


def test_a_chain_of_overlaps_keeps_every_uncovered_rest(default_config: Config) -> None:
    first = _finding(0, 10, "PHONE")
    middle = _finding(5, 25, "CREDIT_CARD")
    last = _finding(20, 30, "PHONE")

    kept = resolve_overlaps([first, middle, last], default_config.registry)

    assert [(f.data_class, f.span.start, f.span.end) for f in kept] == [
        ("PHONE", 0, 5),
        ("CREDIT_CARD", 5, 25),
        ("PHONE", 25, 30),
    ]


def test_a_remainder_drops_the_entity_of_its_loser(default_config: Config) -> None:
    phone = _finding(0, 10, "PHONE", attributes={"gender": "female"})
    phone.entity_id = "e1"
    card = _finding(5, 25, "CREDIT_CARD")

    rest = resolve_overlaps([phone, card], default_config.registry)[0]

    assert (rest.span.start, rest.span.end) == (0, 5)
    assert rest.entity_id is None
    assert rest.attributes == {}
