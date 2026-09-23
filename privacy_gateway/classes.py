"""Data classes, categories, policies and the class registry."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum

from privacy_gateway.model import ConfigError

PRIORITY_UNSET = -1


class Policy(str, Enum):
    """What the pseudonymizer does with a finding."""

    TOKENIZE = "tokenize"
    REDACT = "redact"
    IGNORE = "ignore"


class Category(str, Enum):
    """Coarse grouping used for overlap priority and defaults."""

    PERSON = "PERSON"
    ROLE = "ROLE"
    ORGANIZATION = "ORGANIZATION"
    CONTACT = "CONTACT"
    LOCATION = "LOCATION"
    BIRTH = "BIRTH"
    IDENTIFIER = "IDENTIFIER"
    FINANCIAL = "FINANCIAL"
    HEALTH = "HEALTH"
    NETWORK = "NETWORK"
    DOMAIN = "DOMAIN"
    URL = "URL"
    APPLICATION = "APPLICATION"
    KUBERNETES = "KUBERNETES"
    DATABASE = "DATABASE"
    TENANT = "TENANT"
    PROJECT = "PROJECT"
    EDGE = "EDGE"
    REPOSITORY = "REPOSITORY"
    TICKET = "TICKET"
    SECRET = "SECRET"
    HTTP = "HTTP"


CATEGORY_PRIORITY: dict[Category, int] = {
    Category.SECRET: 220,
    Category.FINANCIAL: 210,
    Category.IDENTIFIER: 200,
    Category.HEALTH: 190,
    Category.CONTACT: 180,
    Category.NETWORK: 170,
    Category.URL: 160,
    Category.DOMAIN: 150,
    Category.PERSON: 140,
    Category.ORGANIZATION: 130,
    Category.LOCATION: 120,
    Category.BIRTH: 110,
    Category.ROLE: 100,
    Category.APPLICATION: 90,
    Category.KUBERNETES: 90,
    Category.DATABASE: 90,
    Category.TENANT: 90,
    Category.PROJECT: 90,
    Category.EDGE: 90,
    Category.REPOSITORY: 90,
    Category.TICKET: 90,
    Category.HTTP: 80,
}

PERSON_PREFIX = "PERSON_"
PERSON_LABEL = "PERSON"


@dataclass(frozen=True)
class DataClass:
    """One registered kind of sensitive data."""

    name: str
    category: Category
    policy: Policy
    priority: int = PRIORITY_UNSET
    enabled: bool = True
    token_label: str | None = None
    patterns: tuple[str, ...] = ()
    validator: str | None = None
    context_words: tuple[str, ...] = ()
    context_required: bool = False

    def __post_init__(self) -> None:
        if self.priority == PRIORITY_UNSET:
            object.__setattr__(self, "priority", CATEGORY_PRIORITY[self.category])


class ClassRegistry:
    """Lookup of registered data classes by name, in registration order."""

    def __init__(self, classes: Iterable[DataClass]) -> None:
        self._classes: dict[str, DataClass] = {c.name: c for c in classes}

    def get(self, name: str) -> DataClass:
        try:
            return self._classes[name]
        except KeyError:
            raise ConfigError(f"unknown data class: {name}") from None

    def __contains__(self, name: str) -> bool:
        return name in self._classes

    def __iter__(self) -> Iterator[DataClass]:
        return iter(self._classes.values())

    def enabled(self) -> list[DataClass]:
        return [c for c in self._classes.values() if c.enabled]

    def label_for(self, name: str) -> str:
        data_class = self.get(name)
        if data_class.token_label is not None:
            return data_class.token_label
        if name.startswith(PERSON_PREFIX):
            return PERSON_LABEL
        return name

    def priority_for(self, name: str) -> int:
        return self.get(name).priority
