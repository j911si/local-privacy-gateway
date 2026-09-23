from __future__ import annotations

from dataclasses import replace

import pytest

from privacy_gateway.classes import Category, ClassRegistry, DataClass, Policy
from privacy_gateway.config import Config
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.model import Finding, Span

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


def run_stage(text: str, config: Config, findings: list[Finding] | None = None) -> list[Finding]:
    return PatternStage().run(text, config, [] if findings is None else findings)


def classes_of(findings: list[Finding]) -> list[str]:
    return [f.data_class for f in findings]


def only(findings: list[Finding], data_class: str) -> Finding:
    matching = [f for f in findings if f.data_class == data_class]
    assert len(matching) == 1, classes_of(findings)
    return matching[0]


def value_of(text: str, finding: Finding) -> str:
    return text[finding.span.start : finding.span.end]


def config_with(base: Config, *classes: DataClass) -> Config:
    return replace(base, registry=ClassRegistry(classes))


def test_stage_name() -> None:
    assert PatternStage().name == "pattern"


def test_credit_card_with_context_is_detected(default_config: Config) -> None:
    text = "Karte: 4111 1111 1111 1111"
    finding = only(run_stage(text, default_config), "CREDIT_CARD")
    assert value_of(text, finding) == "4111 1111 1111 1111"
    assert finding.stage == "pattern"
    assert finding.confidence >= 0.95


def test_credit_card_failing_luhn_is_dropped(default_config: Config) -> None:
    findings = run_stage("Nummer 4111 1111 1111 1112", default_config)
    assert "CREDIT_CARD" not in classes_of(findings)


def test_iban_is_detected(default_config: Config) -> None:
    text = "IBAN DE89370400440532013000"
    finding = only(run_stage(text, default_config), "IBAN")
    assert value_of(text, finding) == "DE89370400440532013000"


def test_uppercase_word_without_context_is_not_a_bic(default_config: Config) -> None:
    findings = run_stage("Generates docs/CODEMAPS/*", default_config)
    assert "BIC" not in classes_of(findings)


def test_bic_with_a_marker_is_detected(default_config: Config) -> None:
    text = "BIC: COBADEFFXXX"
    finding = only(run_stage(text, default_config), "BIC")
    assert value_of(text, finding) == "COBADEFFXXX"


def test_bic_after_an_iban_is_detected(default_config: Config) -> None:
    text = "IBAN DE89370400440532013000, SWIFT COBADEFF"
    finding = only(run_stage(text, default_config), "BIC")
    assert value_of(text, finding) == "COBADEFF"


def test_ip_addresses_get_scope_attribute_and_scope_findings(default_config: Config) -> None:
    text = "host 10.0.0.5 and 8.8.8.8"
    findings = run_stage(text, default_config)
    ips = [f for f in findings if f.data_class == "IP_ADDRESS"]
    assert [value_of(text, f) for f in ips] == ["10.0.0.5", "8.8.8.8"]
    assert [f.attributes["scope"] for f in ips] == ["private", "public"]
    private = only(findings, "PRIVATE_IP")
    public = only(findings, "PUBLIC_IP")
    assert private.span == ips[0].span
    assert public.span == ips[1].span


def test_cvv_requires_a_context_word(default_config: Config) -> None:
    assert "CVV" in classes_of(run_stage("CVV 123", default_config))
    assert run_stage("Seite 123", default_config) == []


def test_context_word_must_be_within_forty_characters(default_config: Config) -> None:
    near = "CVV" + " " * 36 + "123"
    far = "CVV" + " " * 45 + "123"
    assert "CVV" in classes_of(run_stage(near, default_config))
    assert run_stage(far, default_config) == []


def test_context_words_match_whole_words_only(default_config: Config) -> None:
    assert "PHONE" not in classes_of(run_stage("Hotel 0211 4455667", default_config))
    assert "PHONE" in classes_of(run_stage("Tel. 0211 4455667", default_config))


def test_password_span_is_the_capture_group(default_config: Config) -> None:
    text = "password: hunter22"
    finding = only(run_stage(text, default_config), "PASSWORD")
    assert value_of(text, finding) == "hunter22"


def test_bearer_token_is_detected(default_config: Config) -> None:
    text = "Authorization: Bearer abcdefghijklmnop.qrst"
    finding = only(run_stage(text, default_config), "ACCESS_TOKEN")
    assert value_of(text, finding) == "abcdefghijklmnop.qrst"


def test_aws_access_key_is_detected(default_config: Config) -> None:
    text = "AKIAIOSFODNN7EXAMPLE"
    finding = only(run_stage(text, default_config), "AWS_ACCESS_KEY")
    assert value_of(text, finding) == text


def test_jwt_is_detected(default_config: Config) -> None:
    text = f"token {JWT_SAMPLE}"
    finding = only(run_stage(text, default_config), "JWT")
    assert value_of(text, finding) == JWT_SAMPLE


def test_date_of_birth_needs_a_birth_marker(default_config: Config) -> None:
    text = "geboren am 12.03.1980"
    finding = only(run_stage(text, default_config), "DATE_OF_BIRTH")
    assert value_of(text, finding) == "12.03.1980"
    assert "DATE_OF_BIRTH" not in classes_of(run_stage("am 12.03.1980", default_config))


def test_invalid_date_is_dropped(default_config: Config) -> None:
    assert "DATE_OF_BIRTH" not in classes_of(run_stage("geboren am 31.02.2020", default_config))


def test_confidence_rules(default_config: Config) -> None:
    mac = only(run_stage("00:1A:2B:3C:4D:5E", default_config), "MAC_ADDRESS")
    assert mac.confidence == pytest.approx(0.95)
    jwt = only(run_stage(JWT_SAMPLE, default_config), "JWT")
    assert jwt.confidence == pytest.approx(0.9)
    card = only(run_stage("Karte: 4111 1111 1111 1111", default_config), "CREDIT_CARD")
    assert card.confidence == pytest.approx(0.98)


def test_context_bonus_without_validator(default_config: Config) -> None:
    data_class = DataClass(
        name="TICKET_ID",
        category=Category.TICKET,
        policy=Policy.TOKENIZE,
        patterns=(r"\bT-\d{4}\b",),
        context_words=("ticket",),
    )
    config = config_with(default_config, data_class)
    assert only(run_stage("T-1234", config), "TICKET_ID").confidence == pytest.approx(0.9)
    assert only(run_stage("ticket T-1234", config), "TICKET_ID").confidence == pytest.approx(0.93)


def test_group_one_defines_the_span_when_present(default_config: Config) -> None:
    data_class = DataClass(
        name="TICKET_ID",
        category=Category.TICKET,
        policy=Policy.TOKENIZE,
        patterns=(r"ticket=(\d{4})",),
    )
    text = "ticket=1234"
    finding = only(run_stage(text, config_with(default_config, data_class)), "TICKET_ID")
    assert value_of(text, finding) == "1234"


def test_disabled_classes_are_skipped(default_config: Config) -> None:
    data_class = DataClass(
        name="TICKET_ID",
        category=Category.TICKET,
        policy=Policy.TOKENIZE,
        patterns=(r"\bT-\d{4}\b",),
        enabled=False,
    )
    assert run_stage("T-1234", config_with(default_config, data_class)) == []


def test_previous_findings_are_not_returned_again(default_config: Config) -> None:
    earlier = Finding(span=Span(0, 4), data_class="URL", stage="structured", confidence=0.98)
    findings = run_stage("Karte: 4111 1111 1111 1111", default_config, [earlier])
    assert earlier not in findings
    assert all(f.stage == "pattern" for f in findings)


def test_findings_are_sorted_by_span_start(default_config: Config) -> None:
    findings = run_stage("host 10.0.0.5 and 8.8.8.8", default_config)
    assert findings == sorted(findings, key=lambda f: f.span.start)


def test_repr_never_contains_the_matched_value(default_config: Config) -> None:
    text = "Karte: 4111 1111 1111 1111"
    for finding in run_stage(text, default_config):
        assert "4111" not in repr(finding)


def test_standalone_fqdn_is_detected(default_config: Config) -> None:
    text = "Host: api.corp.example.com"
    finding = only(run_stage(text, default_config), "FQDN")
    assert value_of(text, finding) == "api.corp.example.com"


def test_mixed_case_fqdn_is_detected(default_config: Config) -> None:
    text = "Host: GitHub.com"
    finding = only(run_stage(text, default_config), "FQDN")
    assert value_of(text, finding) == "GitHub.com"


@pytest.mark.parametrize("text", ["AK-2026-0917", "INC-2024-0042", "TCK-88213"])
def test_generic_id_without_a_marker(default_config: Config, text: str) -> None:
    finding = only(run_stage(text, default_config), "GENERIC_ID")
    assert value_of(text, finding) == text
    assert finding.confidence == pytest.approx(0.9)


def test_generic_id_in_prose(default_config: Config) -> None:
    text = "Der Vorgang AK-2026-0917 ist noch offen."
    finding = only(run_stage(text, default_config), "GENERIC_ID")
    assert value_of(text, finding) == "AK-2026-0917"


@pytest.mark.parametrize(
    "text", ["ISO-27001", "RFC-2616", "SHA-256", "CVE-2024-1234", "UTF-8"]
)
def test_standard_prefixes_are_not_generic_ids(default_config: Config, text: str) -> None:
    assert "GENERIC_ID" not in classes_of(run_stage(text, default_config))


@pytest.mark.parametrize(
    "text",
    [
        "see notes.txt",
        "checkout-client/2.4.1",
        "Gilt z.B. für alle Kunden",
        "see Next.js docs",
        "E.g. this",
    ],
)
def test_non_host_dotted_strings_are_not_fqdns(default_config: Config, text: str) -> None:
    assert "FQDN" not in classes_of(run_stage(text, default_config))


ANTHROPIC_KEY = "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" * 2 + "-KLmnopQR"
OPENAI_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0T"
STRIPE_KEY = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0"
AZURE_SECRET_VALUE = "Abc123def456ghi789jkl012mno345pqr678"


def test_anthropic_api_key_is_detected(default_config: Config) -> None:
    text = f"Der Schlüssel {ANTHROPIC_KEY} gehört in 1Password."
    finding = only(run_stage(text, default_config), "ANTHROPIC_API_KEY")
    assert value_of(text, finding) == ANTHROPIC_KEY
    assert "OPENAI_API_KEY" not in classes_of(run_stage(text, default_config))


def test_openai_project_key_is_detected(default_config: Config) -> None:
    text = f"OPENAI_API_KEY={OPENAI_KEY}"
    finding = only(run_stage(text, default_config), "OPENAI_API_KEY")
    assert value_of(text, finding) == OPENAI_KEY


def test_stripe_secret_key_is_detected(default_config: Config) -> None:
    text = f"Stripe: {STRIPE_KEY} nicht committen."
    finding = only(run_stage(text, default_config), "STRIPE_SECRET_KEY")
    assert value_of(text, finding) == STRIPE_KEY


@pytest.mark.parametrize("text", ["task-list-eintrag-fuer-den-kunden", "Risk-Assessment-Bericht"])
def test_sk_inside_a_word_is_no_secret(default_config: Config, text: str) -> None:
    secret_classes = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "STRIPE_SECRET_KEY"}
    assert not secret_classes & set(classes_of(run_stage(text, default_config)))


def test_azure_client_secret_env_assignment_has_context(default_config: Config) -> None:
    text = f"AZURE_CLIENT_SECRET={AZURE_SECRET_VALUE}"
    finding = only(run_stage(text, default_config), "AZURE_SECRET")
    assert value_of(text, finding) == AZURE_SECRET_VALUE


def test_unquoted_password_covers_the_rest_of_the_line(default_config: Config) -> None:
    text = "Passwort: geheim 123"
    finding = only(run_stage(text, default_config), "PASSWORD")
    assert value_of(text, finding) == "geheim 123"


def test_unquoted_password_drops_trailing_punctuation(default_config: Config) -> None:
    text = "Das Passwort: geheim 123.\nDanach neu setzen."
    finding = only(run_stage(text, default_config), "PASSWORD")
    assert value_of(text, finding) == "geheim 123"


def test_quoted_password_covers_the_whole_quoted_value(default_config: Config) -> None:
    text = 'password="a b c"'
    finding = only(run_stage(text, default_config), "PASSWORD")
    assert value_of(text, finding) == "a b c"
