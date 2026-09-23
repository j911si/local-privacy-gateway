from __future__ import annotations

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect.validators import (
    VALIDATORS,
    bic_valid,
    date_valid,
    fqdn_valid,
    iban_valid,
    ip_scope,
    luhn_valid,
    mac_valid,
    phone_valid,
    ssn_valid,
    tax_id_valid,
    vin_valid,
)

EXPECTED_KEYS = {
    "luhn",
    "iban",
    "bic",
    "ip",
    "mac",
    "vin",
    "phone",
    "date",
    "tax_id",
    "ssn",
    "fqdn",
}


def test_validators_dict_has_the_documented_keys() -> None:
    assert set(VALIDATORS) == EXPECTED_KEYS


def test_every_validator_used_by_the_default_config_exists(default_config: Config) -> None:
    used = {c.validator for c in default_config.registry if c.validator is not None}
    assert used
    assert used <= set(VALIDATORS)


@pytest.mark.parametrize(
    "value",
    ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"],
)
def test_luhn_accepts_a_valid_card_with_separators(value: str) -> None:
    assert luhn_valid(value) is True


@pytest.mark.parametrize("value", ["4111111111111112", "abcd", ""])
def test_luhn_rejects_invalid_input(value: str) -> None:
    assert luhn_valid(value) is False


@pytest.mark.parametrize(
    "value",
    ["DE89 3704 0044 0532 0130 00", "DE89370400440532013000", "GB82WEST12345698765432"],
)
def test_iban_accepts_valid_numbers(value: str) -> None:
    assert iban_valid(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "DE89370400440532013001",
        "DE88370400440532013000",
        "GB82WEST12345698765431",
        "DE89",
    ],
)
def test_iban_rejects_wrong_length_or_check_digits(value: str) -> None:
    assert iban_valid(value) is False


def test_bic_accepts_eight_and_eleven_character_codes() -> None:
    assert bic_valid("COBADEFFXXX") is True
    assert bic_valid("DEUTDEFF") is True


@pytest.mark.parametrize("value", ["DEUTXXFF", "DEUTDEF", "deutdeff"])
def test_bic_rejects_bad_country_or_shape(value: str) -> None:
    assert bic_valid(value) is False


@pytest.mark.parametrize(
    ("value", "scope"),
    [
        ("10.1.2.3", "private"),
        ("192.168.0.1", "private"),
        ("127.0.0.1", "private"),
        ("8.8.8.8", "public"),
        ("::1", "private"),
        ("fe80::1", "private"),
        ("2001:db8::1", "public"),
    ],
)
def test_ip_scope_classifies_addresses(value: str, scope: str) -> None:
    assert ip_scope(value) == scope


@pytest.mark.parametrize("value", ["999.1.1.1", "10.0.0", "not-an-ip"])
def test_ip_scope_returns_none_for_invalid_addresses(value: str) -> None:
    assert ip_scope(value) is None


def test_mac_accepts_colon_and_dash_separators() -> None:
    assert mac_valid("00:1A:2B:3C:4D:5E") is True
    assert mac_valid("00-1A-2B-3C-4D-5E") is True


@pytest.mark.parametrize("value", ["00:1A:2B:3C:4D", "00:1A:2B:3C:4D:5G"])
def test_mac_rejects_invalid_addresses(value: str) -> None:
    assert mac_valid(value) is False


def test_vin_check_digit() -> None:
    assert vin_valid("1HGCM82633A004352") is True
    assert vin_valid("1HGCM82633A004353") is False


@pytest.mark.parametrize("value", ["1HGCM82633A00435", "1HGCM82633I004352"])
def test_vin_rejects_wrong_length_or_forbidden_letters(value: str) -> None:
    assert vin_valid(value) is False


def test_phone_requires_seven_to_fifteen_digits() -> None:
    assert phone_valid("+49 211 1234567") is True
    assert phone_valid("0211/1234567") is True
    assert phone_valid("12345") is False
    assert phone_valid("+49 211 12345678901234") is False


def test_phone_rejects_unexpected_characters() -> None:
    assert phone_valid("+49 211 1234ABC") is False


@pytest.mark.parametrize("value", ["29.02.2020", "29/02/2020", "2020-02-29", "1.3.1980"])
def test_date_accepts_real_calendar_dates(value: str) -> None:
    assert date_valid(value) is True


@pytest.mark.parametrize("value", ["31.02.2020", "12.13.1980", "1880-01-01", "12.03.80"])
def test_date_rejects_impossible_dates_and_years_out_of_range(value: str) -> None:
    assert date_valid(value) is False


def test_tax_id_checks_the_german_check_digit() -> None:
    assert tax_id_valid("86095742719") is True
    assert tax_id_valid("86095742710") is False


def test_tax_id_accepts_eu_vat_shape() -> None:
    assert tax_id_valid("DE123456789") is True
    assert tax_id_valid("XX123456789") is False


def test_ssn_checks_the_german_check_digit() -> None:
    assert ssn_valid("65 170839 J 003") is True
    assert ssn_valid("65170839J003") is True
    assert ssn_valid("65 170839 J 004") is False


def test_ssn_accepts_us_shape() -> None:
    assert ssn_valid("123-45-6789") is True
    assert ssn_valid("000-45-6789") is False


@pytest.mark.parametrize(
    "value",
    [
        "payments-edge-07.corp.example.com",
        "api.corp.example.com",
        "db-primary.internal",
        "Example.COM",
        "GitHub.com",
    ],
)
def test_fqdn_accepts_dotted_host_names_in_any_case(value: str) -> None:
    assert fqdn_valid(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "config.yaml",
        "notes.txt",
        "z.B.",
        "checkout-client/2.4.1",
        "localhost",
        "host." + "a" * 64 + ".com",
    ],
)
def test_fqdn_rejects_file_names_single_labels_and_bad_shapes(value: str) -> None:
    assert fqdn_valid(value) is False
