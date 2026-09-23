from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from privacy_gateway.classes import (
    CATEGORY_PRIORITY,
    Category,
    ClassRegistry,
    DataClass,
    Policy,
)
from privacy_gateway.model import ConfigError


def make(name: str, category: Category, **kwargs: object) -> DataClass:
    return DataClass(  # type: ignore[arg-type]
        name=name, category=category, policy=Policy.TOKENIZE, **kwargs
    )


def test_policy_values() -> None:
    assert Policy.TOKENIZE.value == "tokenize"
    assert Policy.REDACT.value == "redact"
    assert Policy.IGNORE.value == "ignore"
    assert Policy("redact") is Policy.REDACT


def test_category_values_equal_names() -> None:
    for category in Category:
        assert category.value == category.name


def test_category_covers_the_documented_set() -> None:
    expected = {
        "PERSON", "ROLE", "ORGANIZATION", "CONTACT", "LOCATION", "BIRTH", "IDENTIFIER",
        "FINANCIAL", "HEALTH", "NETWORK", "DOMAIN", "URL", "APPLICATION", "KUBERNETES",
        "DATABASE", "TENANT", "PROJECT", "EDGE", "REPOSITORY", "TICKET", "SECRET", "HTTP",
    }
    assert {c.name for c in Category} == expected


def test_category_priority_values() -> None:
    assert CATEGORY_PRIORITY[Category.SECRET] == 220
    assert CATEGORY_PRIORITY[Category.FINANCIAL] == 210
    assert CATEGORY_PRIORITY[Category.IDENTIFIER] == 200
    assert CATEGORY_PRIORITY[Category.HEALTH] == 190
    assert CATEGORY_PRIORITY[Category.CONTACT] == 180
    assert CATEGORY_PRIORITY[Category.NETWORK] == 170
    assert CATEGORY_PRIORITY[Category.URL] == 160
    assert CATEGORY_PRIORITY[Category.DOMAIN] == 150
    assert CATEGORY_PRIORITY[Category.PERSON] == 140
    assert CATEGORY_PRIORITY[Category.ORGANIZATION] == 130
    assert CATEGORY_PRIORITY[Category.LOCATION] == 120
    assert CATEGORY_PRIORITY[Category.BIRTH] == 110
    assert CATEGORY_PRIORITY[Category.ROLE] == 100
    assert CATEGORY_PRIORITY[Category.HTTP] == 80
    for category in (
        Category.APPLICATION, Category.KUBERNETES, Category.DATABASE, Category.TENANT,
        Category.PROJECT, Category.EDGE, Category.REPOSITORY, Category.TICKET,
    ):
        assert CATEGORY_PRIORITY[category] == 90


def test_category_priority_is_complete() -> None:
    assert set(CATEGORY_PRIORITY) == set(Category)


def test_data_class_defaults() -> None:
    data_class = make("IBAN", Category.FINANCIAL)
    assert data_class.priority == CATEGORY_PRIORITY[Category.FINANCIAL]
    assert data_class.enabled is True
    assert data_class.token_label is None
    assert data_class.patterns == ()
    assert data_class.validator is None
    assert data_class.context_words == ()
    assert data_class.context_required is False


def test_data_class_explicit_priority_wins() -> None:
    assert make("PRIVATE_IP", Category.NETWORK, priority=171).priority == 171


def test_data_class_is_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        make("IBAN", Category.FINANCIAL).name = "OTHER"  # type: ignore[misc]


def test_registry_get_unknown_raises_config_error() -> None:
    registry = ClassRegistry([make("EMAIL", Category.CONTACT)])
    with pytest.raises(ConfigError):
        registry.get("NOPE")


def test_registry_get_returns_class() -> None:
    email = make("EMAIL", Category.CONTACT)
    assert ClassRegistry([email]).get("EMAIL") is email


def test_registry_contains_and_iter() -> None:
    registry = ClassRegistry([make("EMAIL", Category.CONTACT), make("IBAN", Category.FINANCIAL)])
    assert "EMAIL" in registry
    assert "NOPE" not in registry
    assert [c.name for c in registry] == ["EMAIL", "IBAN"]
    assert len(list(registry)) == 2


def test_registry_enabled_filters_disabled_classes() -> None:
    registry = ClassRegistry(
        [
            make("EMAIL", Category.CONTACT),
            make("IBAN", Category.FINANCIAL, enabled=False),
        ]
    )
    assert [c.name for c in registry.enabled()] == ["EMAIL"]


def test_label_for_person_classes_collapses_to_person() -> None:
    registry = ClassRegistry(
        [
            make("PERSON_FIRST_NAME", Category.PERSON),
            make("PERSON_LAST_NAME", Category.PERSON, token_label="PERSON"),
            make("IBAN", Category.FINANCIAL),
        ]
    )
    assert registry.label_for("PERSON_FIRST_NAME") == "PERSON"
    assert registry.label_for("PERSON_LAST_NAME") == "PERSON"
    assert registry.label_for("IBAN") == "IBAN"


def test_label_for_explicit_token_label() -> None:
    registry = ClassRegistry([make("MOBILE_PHONE", Category.CONTACT, token_label="PHONE")])
    assert registry.label_for("MOBILE_PHONE") == "PHONE"


def test_label_for_unknown_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        ClassRegistry([]).label_for("NOPE")


def test_priority_for_uses_category_default() -> None:
    registry = ClassRegistry(
        [
            make("IBAN", Category.FINANCIAL),
            make("PRIVATE_IP", Category.NETWORK, priority=171),
        ]
    )
    assert registry.priority_for("IBAN") == 210
    assert registry.priority_for("PRIVATE_IP") == 171


def test_priority_for_unknown_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        ClassRegistry([]).priority_for("NOPE")
