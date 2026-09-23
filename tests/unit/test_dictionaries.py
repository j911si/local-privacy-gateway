from __future__ import annotations

import dataclasses

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect.dictionaries import (
    BUNDLED_LISTS,
    DictionaryStage,
    TrieMatcher,
    load_terms,
)
from privacy_gateway.model import Finding


def run_stage(text: str, config: Config) -> list[Finding]:
    return DictionaryStage().run(text, config, [])


def classes_at(findings: list[Finding], text: str, value: str) -> list[Finding]:
    start = text.index(value)
    span = (start, start + len(value))
    return [f for f in findings if (f.span.start, f.span.end) == span]


def test_stage_name() -> None:
    assert DictionaryStage.name == "dictionary"


def test_longest_match_wins() -> None:
    matcher = TrieMatcher([("New York", "CITY"), ("New York City", "CITY")])
    text = "We met in New York City."
    hits = matcher.find(text)
    assert [(text[s.start : s.end], cls) for s, cls in hits] == [("New York City", "CITY")]


def test_whole_word_only() -> None:
    matcher = TrieMatcher([("Bonn", "CITY")])
    assert matcher.find("Bonnie went south") == []
    assert len(matcher.find("Bonn is small")) == 1


def test_underscore_is_a_boundary() -> None:
    matcher = TrieMatcher([("northwind", "CUSTOMER_NAME")])
    text = "project_northwind_account_advisory.md"
    hits = matcher.find(text)
    assert [text[s.start : s.end] for s, _ in hits] == ["northwind"]


def test_genitive_s_is_included_for_listed_terms_only() -> None:
    text = "Nikkis Quelle"
    ((span, _),) = TrieMatcher([("Nikki", "PERSON")], genitive=["PERSON"]).find(text)
    assert text[span.start : span.end] == "Nikkis"
    assert TrieMatcher([("Nikki", "PERSON")]).find(text) == []


def test_term_followed_by_another_letter_does_not_match() -> None:
    assert TrieMatcher([("Schweiz", "COUNTRY")], genitive=["COUNTRY"]).find("Schweizerische") == []


def test_multi_word_term_with_punctuation() -> None:
    matcher = TrieMatcher([("St. Gallen", "CITY")])
    hits = matcher.find("Büro in St. Gallen, Schweiz")
    assert len(hits) == 1


def test_matches_do_not_overlap() -> None:
    matcher = TrieMatcher([("Anna", "PERSON_FIRST_NAME"), ("Anna Maria", "PERSON_FULL_NAME")])
    hits = matcher.find("Anna Maria Anna")
    assert [cls for _, cls in hits] == ["PERSON_FULL_NAME", "PERSON_FIRST_NAME"]


def test_case_insensitive_is_optional() -> None:
    assert TrieMatcher([("bonn", "CITY")], case_insensitive=True).find("BONN")
    assert TrieMatcher([("Bonn", "CITY")], case_insensitive=False).find("bonn") == []


def test_spans_stay_aligned_when_lowercasing_expands_a_character() -> None:
    text = "İstanbul und Bonn"
    hits = TrieMatcher([("bonn", "CITY")], case_insensitive=True).find(text)
    assert [(text[span.start : span.end], cls) for span, cls in hits] == [("Bonn", "CITY")]


def test_configured_list_yields_high_confidence(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"CUSTOMER_NAME": ["Contoso GmbH"]})
    text = "Kunde ist Contoso GmbH seit 2019."
    findings = [f for f in run_stage(text, config) if f.data_class == "CUSTOMER_NAME"]
    assert len(findings) == 1
    assert findings[0].confidence == 0.95
    assert findings[0].stage == "dictionary"
    assert text[findings[0].span.start : findings[0].span.end] == "Contoso GmbH"
    assert "bundled" not in findings[0].attributes


def test_configured_list_is_case_insensitive(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"CUSTOMER_NAME": ["Contoso GmbH"]})
    findings = run_stage("rechnung an contoso gmbh", config)
    assert [f.data_class for f in findings if f.data_class == "CUSTOMER_NAME"] == ["CUSTOMER_NAME"]


def test_configured_term_inside_a_file_name_is_found(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"CUSTOMER_NAME": ["northwind"]})
    text = "siehe project_northwind_account_advisory.md"
    findings = [f for f in run_stage(text, config) if f.data_class == "CUSTOMER_NAME"]
    assert len(findings) == 1
    assert text[findings[0].span.start : findings[0].span.end] == "northwind"


def test_configured_person_term_inside_a_snake_case_name(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"PERSON_FULL_NAME": ["Nikki"]})
    findings = run_stage("feedback_nikki_sparsam", config)
    assert [f.data_class for f in findings if f.data_class == "PERSON_FULL_NAME"] == [
        "PERSON_FULL_NAME"
    ]


def test_configured_person_term_takes_the_genitive_s(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"PERSON_FULL_NAME": ["Nikki"]})
    text = "Nikkis Quelle"
    (finding,) = [f for f in run_stage(text, config) if f.data_class == "PERSON_FULL_NAME"]
    assert text[finding.span.start : finding.span.end] == "Nikkis"


def test_configured_country_term_does_not_match_a_longer_word(default_config: Config) -> None:
    config = dataclasses.replace(default_config, dictionaries={"COUNTRY": ["Schweiz"]})
    assert [f for f in run_stage("Schweizerische Post", config) if f.data_class == "COUNTRY"] == []


def test_bundled_first_name_is_low_confidence(default_config: Config) -> None:
    findings = run_stage("Anna kommt morgen.", default_config)
    names = [f for f in findings if f.data_class == "PERSON_FIRST_NAME"]
    assert len(names) == 1
    assert names[0].confidence == 0.3
    assert names[0].attributes == {"bundled": "true"}


def test_lowercase_bundled_name_is_ignored(default_config: Config) -> None:
    findings = run_stage("anna kommt morgen.", default_config)
    assert [f for f in findings if f.data_class == "PERSON_FIRST_NAME"] == []


def test_bundled_last_name_and_city(default_config: Config) -> None:
    text = "Müller wohnt in Bonn."
    findings = run_stage(text, default_config)
    assert classes_at(findings, text, "Müller")[0].data_class == "PERSON_LAST_NAME"
    assert classes_at(findings, text, "Bonn")[0].data_class == "CITY"


def test_medical_term_confidence(default_config: Config) -> None:
    findings = run_stage("Diabetes ist bestätigt.", default_config)
    medical = [f for f in findings if f.data_class == "MEDICAL_INFORMATION"]
    assert len(medical) == 1
    assert medical[0].confidence == 0.8
    assert medical[0].attributes == {"bundled": "true"}


def test_disabled_class_produces_no_findings(default_config: Config) -> None:
    registry = default_config.registry
    patched = dataclasses.replace(registry.get("CITY"), enabled=False)
    classes = [patched if c.name == "CITY" else c for c in registry]
    config = dataclasses.replace(default_config, registry=type(registry)(classes))
    assert [f for f in run_stage("Bonn", config) if f.data_class == "CITY"] == []


def test_findings_never_carry_values(default_config: Config) -> None:
    findings = run_stage("Anna Müller in Bonn hat Diabetes.", default_config)
    assert findings
    for finding in findings:
        assert all("Anna" not in v and "Müller" not in v for v in finding.attributes.values())


@pytest.mark.parametrize(
    ("filename", "minimum"),
    [
        ("first_names_de_en.txt", 300),
        ("last_names_de_en.txt", 300),
        ("cities_de_en.txt", 200),
        ("medical_terms_de_en.txt", 150),
    ],
)
def test_bundled_data_files_meet_minimum_size(filename: str, minimum: int) -> None:
    terms = load_terms(filename)
    assert len(terms) >= minimum
    assert len(set(terms)) == len(terms)
    assert all(term and not term.startswith("#") for term in terms)


def test_bundled_lists_cover_the_required_classes() -> None:
    assert {entry[1] for entry in BUNDLED_LISTS} == {
        "PERSON_FIRST_NAME",
        "PERSON_LAST_NAME",
        "CITY",
        "MEDICAL_INFORMATION",
    }
