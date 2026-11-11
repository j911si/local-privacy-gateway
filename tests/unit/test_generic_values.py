"""Everyday words, system names and token-shaped values are never learned as sensitive values."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import AuditConfig, Config, VaultConfig, load_config
from privacy_gateway.detect import Pipeline
from privacy_gateway.detect.context import ContextStage
from privacy_gateway.model import Finding

ENV = {"PGW_SKIP_USER_CONFIG": "1"}


def scan(text: str, config: Config) -> list[tuple[str, str]]:
    report = Pipeline(config).run(text)
    return [(f.data_class, text[f.span.start : f.span.end]) for f in report.findings]


def values_of(text: str, config: Config, data_class: str) -> list[str]:
    return [value for name, value in scan(text, config) if name == data_class]


@pytest.mark.parametrize(
    "path",
    [
        "/Users/Shared/Library",
        "/home/runner/work/repo",
        "C:\\Users\\Public\\Documents",
        "/home/ubuntu/app",
        "/home/EC2-USER/x",
        "/Users/Administrator/Desktop",
        "/home/www-data/site",
    ],
)
def test_system_names_in_paths_are_not_usernames(path: str, default_config: Config) -> None:
    assert values_of(f"Datei {path} liegt dort.", default_config, "PERSON_USERNAME") == []


@pytest.mark.parametrize("path", ["/home/annaberg/work", "/Users/michaelj/Documents"])
def test_real_usernames_in_paths_are_still_found(path: str, default_config: Config) -> None:
    assert values_of(f"Datei {path} liegt dort.", default_config, "PERSON_USERNAME")


def test_system_username_list_is_overridable_in_yaml(tmp_path: Path) -> None:
    extra = tmp_path / "extra.yaml"
    extra.write_text("system_usernames: [buildbot]\n", encoding="utf-8")
    config = load_config(extra, env=ENV)
    assert values_of("Pfad /home/buildbot/x", config, "PERSON_USERNAME") == []
    assert values_of("Pfad /home/runner/x", config, "PERSON_USERNAME") == []


def test_dictionary_username_is_kept_even_if_it_is_a_system_name(tmp_path: Path) -> None:
    extra = tmp_path / "me.yaml"
    extra.write_text("dictionaries:\n  PERSON_USERNAME: [runner]\n", encoding="utf-8")
    config = load_config(extra, env=ENV)
    assert values_of("Pfad /home/runner/x", config, "PERSON_USERNAME") == ["runner"]


@pytest.mark.parametrize(
    "text",
    [
        "Account: Admin",
        "Service: API",
        "Account: ADMINISTRATOR",
        "Service: HTTPS",
        "Service: Prod",
        "Account: N/A",
        "Service: TODO",
        "Account: Default",
    ],
)
def test_generic_marker_values_are_not_findings(text: str, default_config: Config) -> None:
    assert ContextStage().run(text, default_config, []) == []


@pytest.mark.parametrize("text", ["Service: API-GW-01", "Account: admin42"])
def test_generic_word_with_digit_or_separator_stays_a_finding(
    text: str, default_config: Config
) -> None:
    assert ContextStage().run(text, default_config, [])


@pytest.mark.parametrize("value", ["HOST_001", "ACCOUNT_ID_001", "PERSON_FULL_NAME_012"])
def test_token_shaped_values_are_not_context_findings(value: str, default_config: Config) -> None:
    text = f"Kundennummer: {value} und Service: {value}"
    found: list[Finding] = ContextStage().run(text, default_config, [])
    assert all(text[f.span.start : f.span.end] != value for f in found)


def test_token_like_value_with_fewer_digits_is_not_token_shaped(default_config: Config) -> None:
    found = ContextStage().run("Kundennummer: HOST_01", default_config, [])
    assert [f.data_class for f in found]


def test_full_name_is_still_replaced_but_lone_first_name_is_not(default_config: Config) -> None:
    text = "Max Klein schrieb. Max antwortete. Klein auch."
    assert values_of(text, default_config, "PERSON_FULL_NAME") == ["Max Klein"]
    assert values_of(text, default_config, "PERSON_FIRST_NAME") == []
    assert values_of(text, default_config, "PERSON_LAST_NAME") == []


def test_uncommon_lone_first_name_is_still_promoted(default_config: Config) -> None:
    text = "Anna Müller schrieb. Anna antwortete."
    assert "Anna" in values_of(text, default_config, "PERSON_FIRST_NAME")


def test_last_name_after_salutation_is_still_found(default_config: Config) -> None:
    text = "Sehr geehrter Herr Klein, danke."
    assert values_of(text, default_config, "PERSON_LAST_NAME") == ["Klein"]


def test_name_from_user_dictionary_is_not_affected(tmp_path: Path) -> None:
    extra = tmp_path / "me.yaml"
    extra.write_text(
        "dictionaries:\n  PERSON_LAST_NAME: [Klein]\n  PERSON_FIRST_NAME: [Max]\n",
        encoding="utf-8",
    )
    config = load_config(extra, env=ENV)
    text = "Max Klein schrieb. Max antwortete. Klein auch."
    assert values_of(text, config, "PERSON_FIRST_NAME") == ["Max"]
    assert values_of(text, config, "PERSON_LAST_NAME") == ["Klein"]


@pytest.fixture
def plain_gateway(default_config: Config, tmp_path: Path) -> Gateway:
    config = replace(
        default_config,
        vault=VaultConfig(tmp_path / "vault.db", tmp_path / "vault.key"),
        audit=AuditConfig(None),
    )
    return Gateway(config)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("Pfad /home/runner/work und /Users/Shared/x", "Der runner und Shared laufen."),
        ("Max Klein schrieb. Max antwortete.", "max_tokens=5; Math.max(a, b); max wins"),
        ("Account: Admin, Service: API", "Der Admin ruft die API auf."),
        ("Kundennummer: HOST_001", "Siehe HOST_001 und <HOST_001>."),
    ],
)
def test_session_does_not_learn_generic_values(
    plain_gateway: Gateway, first: str, second: str
) -> None:
    session = plain_gateway.session("generic")
    session.pseudonymize(first)
    assert session.pseudonymize(second) == second
