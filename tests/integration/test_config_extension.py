from __future__ import annotations

from pathlib import Path

import pytest

from privacy_gateway import Gateway

CONFIG = """
classes:
  PROJECT_CODE:
    category: PROJECT
    policy: tokenize
    patterns: ['\\bPRJ-\\d{5}\\b']
  API_KEY:
    policy: tokenize
dictionaries:
  CUSTOMER_NAME: [Contoso GmbH]
  INTERNAL_DOMAIN: [dashboard.example.com]
  files:
    EMPLOYEE_ID: ./employee_ids.txt
"""
EMPLOYEE_IDS = "# one id per line\nEMP-4711\nEMP-4712\n"
TEXT = (
    "Contoso GmbH runs PRJ-40815.\n"
    "The integration uses api_key: pk_live_8Xq2Rm4Tn7Vz1Cb5.\n"
    "Owner is EMP-4711.\n"
    "The console lives at dashboard.example.com.\n"
)


@pytest.fixture
def extended_gateway(gateway_env: dict[str, str], tmp_path: Path) -> Gateway:
    (tmp_path / "employee_ids.txt").write_text(EMPLOYEE_IDS, encoding="utf-8")
    config_path = tmp_path / "extension.yaml"
    config_path.write_text(CONFIG, encoding="utf-8")
    return Gateway(config_path)


def test_custom_class_dictionary_and_override_are_applied(
    extended_gateway: Gateway,
) -> None:
    with extended_gateway as gateway:
        result = gateway.pseudonymize(TEXT)
        assert "<PROJECT_CODE_001>" in result.text
        assert "<CUSTOMER_NAME_001>" in result.text
        assert "<API_KEY_001>" in result.text
        assert "<EMPLOYEE_ID_001>" in result.text
        assert gateway.restore(result.text, result.session_id).text == TEXT


def test_dictionary_domain_wins_over_generic_fqdn(extended_gateway: Gateway) -> None:
    with extended_gateway as gateway:
        result = gateway.pseudonymize(TEXT)
        assert "<INTERNAL_DOMAIN_001>" in result.text
        assert "<FQDN_" not in result.text


def test_overridden_secret_is_restorable(extended_gateway: Gateway) -> None:
    with extended_gateway as gateway:
        result = gateway.pseudonymize(TEXT)
        assert "_REDACTED>" not in result.text
        assert "pk_live_8Xq2Rm4Tn7Vz1Cb5" in gateway.restore(
            result.text, result.session_id
        ).text
