"""IPv6 in compressed form, with zone id and prefix length."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config, load_config
from privacy_gateway.detect import Pipeline
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.detect.validators import ip_scope, ip_valid

IP_CLASSES = {"IP_ADDRESS", "PRIVATE_IP", "PUBLIC_IP"}


def stage_values(text: str, config: Config, data_class: str = "IP_ADDRESS") -> list[str]:
    findings = PatternStage().run(text, config, [])
    return [text[f.span.start : f.span.end] for f in findings if f.data_class == data_class]


def pipeline_ip_values(text: str, config: Config) -> list[str]:
    report = Pipeline(config).run(text)
    return [text[f.span.start : f.span.end] for f in report.findings if f.data_class in IP_CLASSES]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Adresse fe80::1 am Interface", "fe80::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("Server ::1 lokal", "::1"),
        ("Host 2001:db8:85a3::8a2e:370:7334.", "2001:db8:85a3::8a2e:370:7334"),
        ("inet6 fe80::1%eth0 scope link", "fe80::1%eth0"),
        ("inet6 fe80::1ff:fe23:4567:890a/64 scope link", "fe80::1ff:fe23:4567:890a/64"),
        ("Netz 2001:db8::/32 ist", "2001:db8::/32"),
        ("bind [2001:db8::1]:443", "2001:db8::1"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        ("link fe80:: up", "fe80::"),
    ],
)
def test_ipv6_is_found_as_one_value(default_config: Config, text: str, value: str) -> None:
    assert stage_values(text, default_config) == [value]
    assert value in pipeline_ip_values(text, default_config)


def test_two_addresses_with_punctuation_are_two_values(default_config: Config) -> None:
    text = "Gateway fe80::1, DNS 2001:db8::53;"
    assert stage_values(text, default_config) == ["fe80::1", "2001:db8::53"]


def test_ipv6_gets_the_scope_class(default_config: Config) -> None:
    assert stage_values("fe80::1", default_config, "PRIVATE_IP") == ["fe80::1"]
    assert stage_values("2001:db8::1", default_config, "PUBLIC_IP") == ["2001:db8::1"]
    assert stage_values("::1", default_config, "PRIVATE_IP") == ["::1"]


@pytest.mark.parametrize(
    "text",
    [
        "Zeit 12:30:45 Uhr",
        "std::vector<int> v; Foo::bar(); crate::mod::item",
        "Add::add und a::b und A::B",
        "let x = a[::2]; b = a[1::2]; c = a[::]; d = a[::-1]",
        "x[:, ::2]",
        "::",
        "x = ::",
        "a :: b",
        "SELECT id::text, 1::int FROM t",
        "3a:7f:21:9c:de:ad:be:ef:12:34:56:78:90:ab:cd:ef:11:22:33:44",
        "3a:7f:21:9c:de:ad:be:ef:12:34:56:78:90:ab:cd:ef:11:22:33:44:55:66:77:88:99:aa:bb:cc",
        "dead:beef:cafe",
        "1:2:3:4:5:6:7",
        "12345::1",
        "fe80:::1",
        "2001:db8::1::2",
        "Meeting 10:30 - 11:45, Raum 3",
    ],
)
def test_no_ipv6_in_code_times_and_hashes(default_config: Config, text: str) -> None:
    assert pipeline_ip_values(text, default_config) == []


@pytest.mark.parametrize("text", ["MAC 00:1A:2B:3C:4D:5E", "MAC 00-1A-2B-3C-4D-5E"])
def test_mac_addresses_stay_mac_addresses(default_config: Config, text: str) -> None:
    report = Pipeline(default_config).run(text)
    classes = {f.data_class for f in report.findings}
    assert "MAC_ADDRESS" in classes
    assert not classes & IP_CLASSES


@pytest.mark.parametrize(
    "value",
    [
        "fe80::1",
        "::1",
        "2001:db8::1",
        "fe80::1%eth0",
        "2001:db8::/32",
        "fe80::1ff:fe23:4567:890a/64",
    ],
)
def test_validator_accepts_compressed_addresses(value: str) -> None:
    assert ip_valid(value)


@pytest.mark.parametrize(
    "value",
    ["::", "::2", "1::2", "a::b", "Add::add", "::-1", "fe80::1/129", "fe80::1/x", "1.2.3.4/24"],
)
def test_validator_rejects_look_alikes(value: str) -> None:
    assert not ip_valid(value)


def test_scope_ignores_zone_and_prefix() -> None:
    assert ip_scope("fe80::1%eth0") == "private"
    assert ip_scope("fe80::1/64") == "private"
    assert ip_scope("2001:db8::/32") == "public"


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    for name, value in {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(tmp_path / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(tmp_path / "vault.key"),
        "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }.items():
        monkeypatch.setenv(name, value)
    with Gateway(load_config()) as instance:
        yield instance


IPV6_TEXT = (
    "ip -6 addr: inet6 fe80::1%eth0 and 2001:db8::1/64, router 2001:db8:85a3::8a2e:370:7334, "
    "loopback ::1.\nGateway fe80::1ff:fe23:4567:890a reachable; times 12:30:45 stay."
)
IPV6_VALUES = (
    "fe80::1%eth0",
    "2001:db8::1/64",
    "2001:db8:85a3::8a2e:370:7334",
    "fe80::1ff:fe23:4567:890a",
)


def test_ipv6_text_round_trips_through_the_gateway(gateway: Gateway) -> None:
    result = gateway.pseudonymize(IPV6_TEXT)

    assert not any(value in result.text for value in IPV6_VALUES)
    assert "12:30:45" in result.text
    assert gateway.restore(result.text, result.session_id).text == IPV6_TEXT


def test_text_without_ipv6_is_unchanged(gateway: Gateway) -> None:
    text = "std::vector<int> v; x = a[::2]; Zeit 12:30:45; MAC aa:bb:cc:dd:ee:ff?"
    result = gateway.pseudonymize(text)
    assert "std::vector<int>" in result.text and "a[::2]" in result.text
