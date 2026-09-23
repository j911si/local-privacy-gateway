from __future__ import annotations

import dataclasses

import pytest

from privacy_gateway.config import Config, PersonConfig
from privacy_gateway.detect.context import COUNTRIES, SALUTATIONS, ContextStage
from privacy_gateway.detect.dictionaries import DictionaryStage
from privacy_gateway.model import Finding


def detect(text: str, config: Config) -> list[Finding]:
    earlier = DictionaryStage().run(text, config, [])
    return ContextStage().run(text, config, earlier)


def of_class(findings: list[Finding], data_class: str) -> list[Finding]:
    return [f for f in findings if f.data_class == data_class]


def value_of(text: str, finding: Finding) -> str:
    return text[finding.span.start : finding.span.end]


def without_gender(config: Config) -> Config:
    return dataclasses.replace(
        config, person=PersonConfig(record_gender_from_salutation=False)
    )


def test_stage_name() -> None:
    assert ContextStage.name == "context"


def test_salutations_constant_is_gender_only() -> None:
    assert SALUTATIONS["Frau"] == "female"
    assert SALUTATIONS["Herrn"] == "male"
    assert SALUTATIONS["Mx"] is None
    assert SALUTATIONS["Dr."] is None
    assert set(SALUTATIONS.values()) <= {"female", "male", None}


def test_countries_constant_has_enough_entries() -> None:
    assert len(COUNTRIES) >= 60
    assert len(set(COUNTRIES)) == len(COUNTRIES)


def test_female_salutation(default_config: Config) -> None:
    text = "Sehr geehrte Frau Müller,"
    findings = detect(text, default_config)
    salutation = of_class(findings, "SALUTATION")
    last_name = of_class(findings, "PERSON_LAST_NAME")
    assert [value_of(text, f) for f in salutation] == ["Frau"]
    assert [value_of(text, f) for f in last_name] == ["Müller"]
    assert last_name[0].attributes["gender"] == "female"
    assert last_name[0].attributes["source"] == "salutation"
    assert last_name[0].confidence == 0.95


def test_male_salutation_with_academic_title(default_config: Config) -> None:
    text = "Herrn Dr. Schmidt"
    findings = detect(text, default_config)
    assert [value_of(text, f) for f in of_class(findings, "ACADEMIC_TITLE")] == ["Dr."]
    last_name = of_class(findings, "PERSON_LAST_NAME")
    assert [value_of(text, f) for f in last_name] == ["Schmidt"]
    assert last_name[0].attributes["gender"] == "male"


def test_two_token_name_becomes_full_name(default_config: Config) -> None:
    text = "Sehr geehrter Herr Max Mustermann,"
    findings = detect(text, default_config)
    full = of_class(findings, "PERSON_FULL_NAME")
    assert [value_of(text, f) for f in full] == ["Max Mustermann"]
    assert full[0].attributes["gender"] == "male"


def test_neutral_salutation_has_no_gender(default_config: Config) -> None:
    text = "Dear Mx Taylor"
    findings = detect(text, default_config)
    last_name = of_class(findings, "PERSON_LAST_NAME")
    assert [value_of(text, f) for f in last_name] == ["Taylor"]
    assert "gender" not in last_name[0].attributes


def test_gender_recording_can_be_disabled(default_config: Config) -> None:
    text = "Sehr geehrte Frau Müller,"
    findings = detect(text, without_gender(default_config))
    assert all("gender" not in f.attributes for f in findings)


def test_first_name_alone_never_yields_gender(default_config: Config) -> None:
    for text in ("Anna", "Anna Müller"):
        findings = detect(text, default_config)
        assert all("gender" not in f.attributes for f in findings)


def test_bundled_first_and_last_name_pair(default_config: Config) -> None:
    text = "Anna Müller hat angerufen."
    findings = detect(text, default_config)
    full = of_class(findings, "PERSON_FULL_NAME")
    assert [value_of(text, f) for f in full] == ["Anna Müller"]
    assert full[0].confidence == 0.85
    assert "gender" not in full[0].attributes


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Anna  Müller hat angerufen.", "Anna  Müller"),
        ("Anna\tMüller hat angerufen.", "Anna\tMüller"),
        ("Anna\nMüller hat angerufen.", "Anna\nMüller"),
        ("| Anna | Müller |", "Anna | Müller"),
        ("Müller, Anna", "Müller, Anna"),
        ("Anna Müller-Schmidt hat angerufen.", "Anna Müller-Schmidt"),
    ],
)
def test_name_pair_separators_and_double_names(
    text: str, expected: str, default_config: Config
) -> None:
    full = of_class(detect(text, default_config), "PERSON_FULL_NAME")
    assert [value_of(text, f) for f in full] == [expected]


def test_lowercase_name_pair_stays_unmatched(default_config: Config) -> None:
    text = "anna müller hat angerufen."
    assert of_class(detect(text, default_config), "PERSON_FULL_NAME") == []


def test_key_value_marker_without_separator(default_config: Config) -> None:
    text = "Konto 4711"
    account = of_class(detect(text, default_config), "ACCOUNT_ID")
    assert [value_of(text, f) for f in account] == ["4711"]
    assert account[0].confidence == 0.85


def test_key_value_marker_with_number_word(default_config: Config) -> None:
    text = "account number: 4711"
    account = of_class(detect(text, default_config), "ACCOUNT_ID")
    assert [value_of(text, f) for f in account] == ["4711"]


def test_ticket_marker(default_config: Config) -> None:
    text = "Ticket INC-2024-0042 wurde eskaliert."
    ticket = of_class(detect(text, default_config), "TICKET_ID")
    assert [value_of(text, f) for f in ticket] == ["INC-2024-0042"]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Ticketnummer AK-2026-0917", "AK-2026-0917"),
        ("Ticket-Nr. 4711", "4711"),
        ("Ticket-Nummer 4711", "4711"),
        ("TicketID: 8812", "8812"),
        ("Ticket no. 8812", "8812"),
        ("Ticket number 8812", "8812"),
    ],
)
def test_compound_ticket_markers(default_config: Config, text: str, value: str) -> None:
    ticket = of_class(detect(text, default_config), "TICKET_ID")
    assert [value_of(text, f) for f in ticket] == [value]


def test_compound_customer_marker(default_config: Config) -> None:
    text = "Kundennr 993"
    customer = of_class(detect(text, default_config), "CUSTOMER_ID")
    assert [value_of(text, f) for f in customer] == ["993"]


def test_marker_with_a_plural_suffix_is_not_a_marker(default_config: Config) -> None:
    assert of_class(detect("Tickets are stale", default_config), "TICKET_ID") == []


def test_marker_value_drops_trailing_punctuation(default_config: Config) -> None:
    text = "Ticket: AK-2026-0917."
    ticket = of_class(detect(text, default_config), "TICKET_ID")
    assert [value_of(text, f) for f in ticket] == ["AK-2026-0917"]


@pytest.mark.parametrize(
    "text", ["Ticketnummer AK-2026-0917..", "Ticket: AK-2026-0917.)", "Ticket AK-2026-0917.'"]
)
def test_marker_value_drops_every_trailing_punctuation_mark(
    default_config: Config, text: str
) -> None:
    ticket = of_class(detect(text, default_config), "TICKET_ID")
    assert [value_of(text, f) for f in ticket] == ["AK-2026-0917"]


def test_namespace_marker(default_config: Config) -> None:
    text = "namespace: payments-prod"
    namespace = of_class(detect(text, default_config), "NAMESPACE")
    assert [value_of(text, f) for f in namespace] == ["payments-prod"]


def test_key_value_marker_needs_separator_or_digit(default_config: Config) -> None:
    text = "Account Advisory – Alpenbank AG"
    assert of_class(detect(text, default_config), "ACCOUNT_ID") == []


def test_gateway_marker_without_separator_or_digit(default_config: Config) -> None:
    text = "Airlock Gateway vor https://x.example"
    assert of_class(detect(text, default_config), "GATEWAY_NAME") == []


def test_marker_rejects_plain_lowercase_words(default_config: Config) -> None:
    text = "the ticket: are stale\nproject: Apollo\ntenant: acme-01"
    findings = detect(text, default_config)
    assert of_class(findings, "TICKET_ID") == []
    assert [value_of(text, f) for f in of_class(findings, "PROJECT_NAME")] == ["Apollo"]
    assert [value_of(text, f) for f in of_class(findings, "TENANT_NAME")] == ["acme-01"]


def test_marker_ignores_boolean_literals(default_config: Config) -> None:
    text = "Is a git repository: false\nbranch: main\ncluster: none"
    findings = detect(text, default_config)
    assert of_class(findings, "REPOSITORY_NAME") == []
    assert of_class(findings, "CLUSTER_NAME") == []


def test_gateway_marker_with_separator(default_config: Config) -> None:
    text = "gateway: edge-fra-01"
    gateway = of_class(detect(text, default_config), "GATEWAY_NAME")
    assert [value_of(text, f) for f in gateway] == ["edge-fra-01"]


def test_customer_id_marker_with_digits(default_config: Config) -> None:
    text = "Kundennummer 88213"
    customer = of_class(detect(text, default_config), "CUSTOMER_ID")
    assert [value_of(text, f) for f in customer] == ["88213"]


def test_compound_identifier_is_not_a_marker(default_config: Config) -> None:
    text = "seo-cluster: Semantic topic"
    assert of_class(detect(text, default_config), "CLUSTER_NAME") == []


def test_cluster_marker_with_separator(default_config: Config) -> None:
    text = "cluster: prod-eu-1"
    cluster = of_class(detect(text, default_config), "CLUSTER_NAME")
    assert [value_of(text, f) for f in cluster] == ["prod-eu-1"]


def test_key_value_marker_skips_stop_words(default_config: Config) -> None:
    text = "Das Konto der Firma"
    assert of_class(detect(text, default_config), "ACCOUNT_ID") == []


def test_key_value_marker_ignores_classes_with_patterns(default_config: Config) -> None:
    text = "IBAN abcdef"
    assert of_class(detect(text, default_config), "IBAN") == []


def test_department_marker(default_config: Config) -> None:
    text = "Abteilung: IT-Security"
    department = of_class(detect(text, default_config), "DEPARTMENT")
    assert [value_of(text, f) for f in department] == ["IT-Security"]


def test_job_title(default_config: Config) -> None:
    text = "Sie ist Geschäftsführerin der GmbH."
    titles = of_class(detect(text, default_config), "JOB_TITLE")
    assert [value_of(text, f) for f in titles] == ["Geschäftsführerin"]
    assert titles[0].confidence == 0.8


def test_address_grammar_with_children(default_config: Config) -> None:
    text = "Musterstraße 12, 40210 Düsseldorf"
    address = of_class(detect(text, default_config), "ADDRESS")
    assert len(address) == 1
    assert value_of(text, address[0]) == text
    assert address[0].confidence == 0.9
    children = {c.data_class: value_of(text, c) for c in address[0].children}
    assert children == {
        "STREET": "Musterstraße",
        "HOUSE_NUMBER": "12",
        "POSTAL_CODE": "40210",
        "CITY": "Düsseldorf",
    }


def test_standalone_postal_code(default_config: Config) -> None:
    text = "PLZ: 40210"
    codes = of_class(detect(text, default_config), "POSTAL_CODE")
    assert [value_of(text, f) for f in codes] == ["40210"]


def test_place_of_birth(default_config: Config) -> None:
    text = "geboren in Köln"
    places = of_class(detect(text, default_config), "PLACE_OF_BIRTH")
    assert [value_of(text, f) for f in places] == ["Köln"]


def test_health_sentence(default_config: Config) -> None:
    text = "Befund vom Montag. Diagnose: Diabetes Typ 2. Therapie folgt."
    health = of_class(detect(text, default_config), "HEALTH_INFORMATION")
    assert len(health) == 1
    assert value_of(text, health[0]) == "Diagnose: Diabetes Typ 2"
    assert health[0].confidence == 0.95


def test_medical_term_without_marker_is_not_health_information(default_config: Config) -> None:
    text = "Diabetes ist weit verbreitet"
    assert of_class(detect(text, default_config), "HEALTH_INFORMATION") == []


def test_initials(default_config: Config) -> None:
    text = "Gezeichnet A. M."
    initials = of_class(detect(text, default_config), "PERSON_INITIALS")
    assert [value_of(text, f) for f in initials] == ["A. M."]
    assert initials[0].confidence == 0.4


def test_social_media_handle(default_config: Config) -> None:
    text = "Schreib @max_muster an."
    handles = of_class(detect(text, default_config), "SOCIAL_MEDIA_HANDLE")
    assert [value_of(text, f) for f in handles] == ["@max_muster"]
    assert handles[0].confidence == 0.8


def test_email_is_not_a_handle(default_config: Config) -> None:
    assert of_class(detect("max@example.com", default_config), "SOCIAL_MEDIA_HANDLE") == []


def test_messenger_id(default_config: Config) -> None:
    text = "Telegram: @maxmuster"
    ids = of_class(detect(text, default_config), "MESSENGER_ID")
    assert [value_of(text, f) for f in ids] == ["@maxmuster"]


def test_messenger_word_in_prose_is_not_an_id(default_config: Config) -> None:
    text = "A signal that pattern-matches may have a different cause."
    assert of_class(detect(text, default_config), "MESSENGER_ID") == []


def test_messenger_platform_list_is_not_an_id(default_config: Config) -> None:
    assert of_class(detect("Slack, email, GitHub", default_config), "MESSENGER_ID") == []


def test_messenger_id_with_a_phone_number(default_config: Config) -> None:
    assert of_class(detect("signal: +4917612345678", default_config), "MESSENGER_ID") != []


def test_messenger_id_without_a_separator_needs_a_digit(default_config: Config) -> None:
    assert of_class(detect("whatsapp 0176 1234567", default_config), "MESSENGER_ID") != []


def test_messenger_value_needs_more_than_a_separator(default_config: Config) -> None:
    assert of_class(detect("telegram: configure", default_config), "MESSENGER_ID") == []


@pytest.mark.parametrize("text", ["plugin:telegram:telegram", "/telegram:access"])
def test_messenger_platform_in_an_identifier_is_not_an_id(
    default_config: Config, text: str
) -> None:
    assert of_class(detect(text, default_config), "MESSENGER_ID") == []


def test_sip_address(default_config: Config) -> None:
    text = "Anruf an sip:max@pbx.example.com bitte"
    sip = of_class(detect(text, default_config), "SIP_ADDRESS")
    assert [value_of(text, f) for f in sip] == ["sip:max@pbx.example.com"]
    assert sip[0].confidence == 0.95


def test_country(default_config: Config) -> None:
    text = "Der Sitz ist in Deutschland."
    countries = of_class(detect(text, default_config), "COUNTRY")
    assert [value_of(text, f) for f in countries] == ["Deutschland"]
    assert countries[0].confidence == 0.8


def test_findings_are_new_and_value_free(default_config: Config) -> None:
    text = "Sehr geehrte Frau Müller, Ihr Konto 4711 in Düsseldorf."
    earlier = DictionaryStage().run(text, default_config, [])
    findings = ContextStage().run(text, default_config, earlier)
    assert all(f not in earlier for f in findings)
    assert all(f.stage == "context" for f in findings)
    for finding in findings:
        for value in finding.attributes.values():
            assert value not in ("Müller", "4711", "Düsseldorf")


def test_hostname_marker(default_config: Config) -> None:
    text = "hostname: payments-edge-07"
    hosts = of_class(detect(text, default_config), "HOSTNAME")
    assert [value_of(text, f) for f in hosts] == ["payments-edge-07"]


def test_organization_with_legal_form(default_config: Config) -> None:
    text = "Musterbank AG"
    orgs = of_class(detect(text, default_config), "ORGANIZATION_NAME")
    assert [value_of(text, f) for f in orgs] == ["Musterbank AG"]
    assert orgs[0].confidence == 0.85


def test_organization_with_compound_legal_form(default_config: Config) -> None:
    text = "Contoso GmbH & Co. KG"
    orgs = of_class(detect(text, default_config), "ORGANIZATION_NAME")
    assert [value_of(text, f) for f in orgs] == [text]


def test_legal_form_inside_a_word_is_not_an_organization(default_config: Config) -> None:
    assert of_class(detect("Der AG-Vorstand", default_config), "ORGANIZATION_NAME") == []


def test_organization_after_a_marker(default_config: Config) -> None:
    text = "Lieferant: Fabrikam Ltd."
    orgs = of_class(detect(text, default_config), "ORGANIZATION_NAME")
    assert [value_of(text, f) for f in orgs] == ["Fabrikam Ltd."]


@pytest.mark.parametrize(
    "text",
    [
        "geboren am 12.03.1980 in Bremen",
        "born on 1980-03-12 in Bremen",
        "geb. 12.03.1980 in Bremen",
    ],
)
def test_place_of_birth_after_a_date(default_config: Config, text: str) -> None:
    places = of_class(detect(text, default_config), "PLACE_OF_BIRTH")
    assert [value_of(text, f) for f in places] == ["Bremen"]
