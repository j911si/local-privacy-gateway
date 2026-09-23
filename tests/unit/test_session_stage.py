from __future__ import annotations

from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline
from privacy_gateway.detect.session import SessionStage
from privacy_gateway.model import Finding

URL = "https://intern.example.com/kunden/mueller"
PERSON_TOKEN = "<PERSON_FEMALE_001>"
KNOWN_PERSON = {"Müller": ("PERSON_LAST_NAME", PERSON_TOKEN)}


def _stage_findings(
    known: dict[str, tuple[str, str]], text: str, config: Config
) -> list[Finding]:
    return SessionStage(known).run(text, config, [])


def test_stage_emits_token_attribute_and_full_confidence(default_config: Config) -> None:
    text = "Grüße an Müller."

    (finding,) = _stage_findings(KNOWN_PERSON, text, default_config)

    assert finding.stage == "session"
    assert finding.data_class == "PERSON_LAST_NAME"
    assert finding.confidence == 1.0
    assert finding.attributes == {"token": PERSON_TOKEN}
    assert text[finding.span.start : finding.span.end] == "Müller"


def test_stage_matches_case_insensitively_and_whole_words_only(default_config: Config) -> None:
    text = "Müllermeier und MÜLLER"

    spans = [f.span for f in _stage_findings(KNOWN_PERSON, text, default_config)]

    assert [text[span.start : span.end] for span in spans] == ["MÜLLER"]
    assert spans[0].start == text.rindex("MÜLLER")


def test_known_host_is_found_in_a_different_case(default_config: Config) -> None:
    text = "Siehe GitHub.com fuer Details."
    known = {"github.com": ("FQDN", "<FQDN_003>")}

    (finding,) = _stage_findings(known, text, default_config)

    assert text[finding.span.start : finding.span.end] == "GitHub.com"


def test_known_multi_word_form_does_not_match_its_first_word(default_config: Config) -> None:
    known = {"Post CH": ("CUSTOMER_NAME", "<CUSTOMER_NAME_001>")}

    assert _stage_findings(known, "post alone", default_config) == []


def test_known_form_inside_an_identifier_is_found(default_config: Config) -> None:
    text = "project_northwind_account_advisory.md"
    known = {"northwind": ("CUSTOMER_NAME", "<CUSTOMER_NAME_001>")}

    (finding,) = _stage_findings(known, text, default_config)

    assert text[finding.span.start : finding.span.end] == "northwind"


def test_known_person_form_takes_the_genitive_s(default_config: Config) -> None:
    text = "Nikkis Quelle"
    known = {"Nikki": ("PERSON_FULL_NAME", PERSON_TOKEN)}

    (finding,) = _stage_findings(known, text, default_config)

    assert text[finding.span.start : finding.span.end] == "Nikkis"


def test_known_country_does_not_match_a_longer_word(default_config: Config) -> None:
    known = {"Schweiz": ("COUNTRY", "<COUNTRY_001>")}

    assert _stage_findings(known, "Schweizerische Post", default_config) == []


def test_stage_prefers_the_longest_known_form(default_config: Config) -> None:
    known = {
        "Müller": ("PERSON_LAST_NAME", PERSON_TOKEN),
        "Anna Müller": ("PERSON_FULL_NAME", "<PERSON_FEMALE_002>"),
    }
    text = "Anna Müller schreibt."

    (finding,) = _stage_findings(known, text, default_config)

    assert text[finding.span.start : finding.span.end] == "Anna Müller"
    assert finding.attributes["token"] == "<PERSON_FEMALE_002>"


def test_unknown_text_yields_no_session_findings(default_config: Config) -> None:
    assert _stage_findings(KNOWN_PERSON, "Nothing sensitive here.", default_config) == []


def test_pipeline_runs_the_session_stage_first(default_config: Config) -> None:
    report = Pipeline(default_config).run("Grüße an Müller.", KNOWN_PERSON)

    assert next(iter(report.stage_stats)) == "session"
    assert report.stage_stats["session"] == 1


def test_pipeline_without_known_values_has_no_session_stage(default_config: Config) -> None:
    report = Pipeline(default_config).run("Grüße an Müller.")

    assert "session" not in report.stage_stats


def test_known_url_wins_over_the_structured_url_parent(default_config: Config) -> None:
    text = f"Siehe {URL} fuer Details."

    report = Pipeline(default_config).run(text, {URL: ("URL", "<URL_001>")})

    (finding,) = report.findings
    assert finding.stage == "session"
    assert finding.attributes["token"] == "<URL_001>"
    assert text[finding.span.start : finding.span.end] == URL


def test_known_last_name_inside_a_salutation_keeps_the_salutation(default_config: Config) -> None:
    text = "Sehr geehrte Frau Müller, danke."

    report = Pipeline(default_config).run(text, KNOWN_PERSON)

    matched = {f.data_class: (text[f.span.start : f.span.end], f.stage) for f in report.findings}
    assert matched["PERSON_LAST_NAME"] == ("Müller", "session")
    assert matched["SALUTATION"][0] == "Frau"
