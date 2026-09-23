from __future__ import annotations

import re
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.classes import Policy

TOKEN_RE = re.compile(r"<[A-Z][A-Z_]*_\d{3}>")

FIXTURE_CLASSES: dict[str, tuple[str, ...]] = {
    "customer_letter_de": (
        "ADDRESS",
        "SALUTATION",
        "ACADEMIC_TITLE",
        "PERSON_LAST_NAME",
        "PERSON_FULL_NAME",
        "ORGANIZATION_NAME",
        "PLACE_OF_BIRTH",
        "CUSTOMER_ID",
        "ACCOUNT_ID",
        "IBAN",
        "PHONE",
        "EMAIL",
        "DATE_OF_BIRTH",
    ),
    "incident_ticket_en": (
        "TICKET_ID",
        "INCIDENT_ID",
        "SALUTATION",
        "PERSON_LAST_NAME",
        "PRIVATE_IP",
        "PUBLIC_IP",
        "URL",
        "FQDN",
        "AWS_ACCESS_KEY",
        "JWT",
    ),
    "k8s_log_excerpt": (
        "NAMESPACE",
        "POD_NAME",
        "CONTAINER_NAME",
        "CLUSTER_NAME",
        "DATABASE_CONNECTION_STRING",
        "KUBERNETES_SECRET",
    ),
    "http_request_dump": (
        "ACCESS_TOKEN",
        "COOKIE",
        "CUSTOM_HEADER",
        "EMAIL",
        "PASSWORD",
        "API_KEY",
        "URL",
        "FQDN",
    ),
    "invoice_de": (
        "ADDRESS",
        "INVOICE_ID",
        "CUSTOMER_ID",
        "TAX_ID",
        "IBAN",
        "BIC",
        "PAYMENT_REFERENCE",
        "CREDIT_CARD",
        "CARD_EXPIRY",
    ),
}
FIXTURE_NAMES = tuple(FIXTURE_CLASSES)
REVERSIBLE_FIXTURES = ("customer_letter_de", "invoice_de")


def read(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / f"{name}.txt").read_text(encoding="utf-8")


def expected_restore(text: str, gateway: Gateway) -> str:
    """The original with irreversible findings replaced by their redaction marker."""
    registry = gateway.config.registry
    result = text
    findings = sorted(gateway.scan(text).findings, key=lambda f: f.span.start, reverse=True)
    for finding in findings:
        data_class = registry.get(finding.data_class)
        if data_class.policy is Policy.REDACT:
            marker = f"<{data_class.name}_REDACTED>"
            result = result[: finding.span.start] + marker + result[finding.span.end :]
    return result


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_no_stored_value_survives_pseudonymization(
    gateway: Gateway, fixtures_dir: Path, name: str
) -> None:
    text = read(fixtures_dir, name)
    result = gateway.pseudonymize(text)
    for entry in gateway.vault.load(result.session_id).values():
        assert entry.value not in result.text
        for form in entry.surface_forms:
            assert form not in result.text


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_expected_classes_are_detected(
    gateway: Gateway, fixtures_dir: Path, name: str
) -> None:
    result = gateway.pseudonymize(read(fixtures_dir, name))
    missing = [cls for cls in FIXTURE_CLASSES[name] if cls not in result.report.counts]
    assert missing == []


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_restore_reproduces_everything_that_is_reversible(
    gateway: Gateway, fixtures_dir: Path, name: str
) -> None:
    text = read(fixtures_dir, name)
    result = gateway.pseudonymize(text)
    restored = gateway.restore(result.text, result.session_id)
    assert restored.text == expected_restore(text, gateway)
    assert restored.unknown_tokens == []


@pytest.mark.parametrize("name", REVERSIBLE_FIXTURES)
def test_round_trip_is_byte_equal_without_redactions(
    gateway: Gateway, fixtures_dir: Path, name: str
) -> None:
    text = read(fixtures_dir, name)
    result = gateway.pseudonymize(text)
    assert "_REDACTED>" not in result.text
    assert gateway.restore(result.text, result.session_id).text == text


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_lenient_restore_handles_a_reordered_llm_answer(
    gateway: Gateway, fixtures_dir: Path, name: str
) -> None:
    result = gateway.pseudonymize(read(fixtures_dir, name))
    tokens = TOKEN_RE.findall(result.text)
    quoted = [f"`{token[1:-1].lower()}`" for token in reversed(tokens)]
    answer = "Summary of the document:\n" + "\n".join(f"- {token}" for token in quoted)
    restored = gateway.restore(answer, result.session_id, mode="lenient")
    assert restored.unknown_tokens == []
    assert restored.restored_count == len(tokens)


def test_two_documents_get_independent_sessions(
    gateway: Gateway, fixtures_dir: Path
) -> None:
    first = gateway.pseudonymize(read(fixtures_dir, "customer_letter_de"))
    second = gateway.pseudonymize(read(fixtures_dir, "invoice_de"))
    assert first.session_id != second.session_id
    assert first.report.tokens[0].endswith("_001>")
    assert second.report.tokens[0].endswith("_001>")
    assert set(gateway.vault.load(first.session_id)) != set(
        gateway.vault.load(second.session_id)
    )


def test_url_wins_over_the_fqdn_inside_it(gateway: Gateway, fixtures_dir: Path) -> None:
    result = gateway.pseudonymize(read(fixtures_dir, "incident_ticket_en"))

    assert "<URL_001>" in result.text
    assert "corp.example.com" not in result.text
    assert "Affected host: <FQDN_001>" in result.text
