"""Dictionary matching for configured term lists and the bundled reference lists."""

from __future__ import annotations

from collections.abc import Iterable
from functools import cache
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from privacy_gateway.classes import Category, ClassRegistry
from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

DATA_PACKAGE = "privacy_gateway.data"
CONFIGURED_CONFIDENCE = 0.95
GENITIVE_CATEGORIES = frozenset({Category.PERSON, Category.ORGANIZATION})
GENITIVE_CLASSES = frozenset({"CUSTOMER_NAME", "PARTNER_NAME", "SUPPLIER_NAME"})
BUNDLED_LISTS: tuple[tuple[str, str, float], ...] = (
    ("first_names_de_en.txt", "PERSON_FIRST_NAME", 0.3),
    ("last_names_de_en.txt", "PERSON_LAST_NAME", 0.3),
    ("cities_de_en.txt", "CITY", 0.3),
    ("medical_terms_de_en.txt", "MEDICAL_INFORMATION", 0.8),
)

_TERMINAL = object()


@cache
def load_terms(filename: str) -> tuple[str, ...]:
    """Read one term per line from a bundled data file, skipping blanks and comments."""
    raw = files(DATA_PACKAGE).joinpath(filename).read_text(encoding="utf-8")
    return tuple(
        stripped
        for line in raw.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    )


def _fold_char(char: str) -> str:
    lowered = char.lower()
    return lowered if len(lowered) == 1 else char


def allows_genitive(registry: ClassRegistry, data_class: str) -> bool:
    """Whether a trailing genitive `s` belongs to the term of this data class."""
    if data_class in GENITIVE_CLASSES:
        return True
    return data_class in registry and registry.get(data_class).category in GENITIVE_CATEGORIES


class TrieMatcher:
    """Whole-word, longest-match, non-overlapping matcher over a fixed term list."""

    def __init__(
        self,
        terms: Iterable[tuple[str, str]],
        *,
        case_insensitive: bool = True,
        genitive: Iterable[str] = (),
    ) -> None:
        self._case_insensitive = case_insensitive
        self._genitive = frozenset(genitive)
        self._root: dict[Any, Any] = {}
        for term, data_class in terms:
            key = self._fold(term)
            if not key:
                continue
            node = self._root
            for char in key:
                node = node.setdefault(char, {})
            node[_TERMINAL] = data_class

    def _fold(self, text: str) -> str:
        if not self._case_insensitive:
            return text
        lowered = text.lower()
        if len(lowered) == len(text):
            return lowered
        return "".join(_fold_char(char) for char in text)

    def find(self, text: str) -> list[tuple[Span, str]]:
        """Return the longest non-overlapping whole-word matches, left to right."""
        folded = self._fold(text)
        length = len(text)
        hits: list[tuple[Span, str]] = []
        index = 0
        while index < length:
            if index and text[index - 1].isalnum():
                index += 1
                continue
            end, data_class = self._longest_at(text, folded, index)
            if data_class is None:
                index += 1
                continue
            hits.append((Span(index, end), data_class))
            index = end
        return hits

    def _longest_at(self, text: str, folded: str, start: int) -> tuple[int, str | None]:
        node: dict[Any, Any] | None = self._root
        cursor = start
        end = start
        data_class: str | None = None
        while cursor < len(text) and node is not None:
            node = node.get(folded[cursor])
            if node is None:
                break
            cursor += 1
            terminal = node.get(_TERMINAL)
            if terminal is None:
                continue
            stop = self._boundary_end(text, folded, cursor, terminal)
            if stop is not None:
                end, data_class = stop, terminal
        return end, data_class

    def _boundary_end(self, text: str, folded: str, cursor: int, terminal: str) -> int | None:
        if cursor == len(text) or not text[cursor].isalnum():
            return cursor
        if terminal not in self._genitive or folded[cursor] != "s":
            return None
        if cursor + 1 == len(text) or not text[cursor + 1].isalnum():
            return cursor + 1
        return None


@cache
def _bundled_matcher(filename: str, data_class: str, genitive: bool) -> TrieMatcher:
    return TrieMatcher(
        ((term, data_class) for term in load_terms(filename)),
        genitive=(data_class,) if genitive else (),
    )


class DictionaryStage:
    """Emits findings for configured dictionaries and the bundled reference lists."""

    name = "dictionary"

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return dictionary findings; earlier findings are not inspected."""
        enabled = {data_class.name for data_class in config.registry.enabled()}
        result = self._configured(text, config, enabled)
        result.extend(self._bundled(text, config, enabled))
        result.sort(key=lambda finding: (finding.span.start, finding.span.end))
        return result

    def _configured(self, text: str, config: Config, enabled: set[str]) -> list[Finding]:
        terms = [
            (term, data_class)
            for data_class, values in config.dictionaries.items()
            if data_class in enabled
            for term in values
        ]
        if not terms:
            return []
        return [
            Finding(
                span=span,
                data_class=data_class,
                stage=self.name,
                confidence=CONFIGURED_CONFIDENCE,
            )
            for span, data_class in TrieMatcher(
                terms,
                genitive=[name for _, name in terms if allows_genitive(config.registry, name)],
            ).find(text)
        ]

    def _bundled(self, text: str, config: Config, enabled: set[str]) -> list[Finding]:
        result: list[Finding] = []
        for filename, data_class, confidence in BUNDLED_LISTS:
            if data_class not in enabled:
                continue
            genitive = allows_genitive(config.registry, data_class)
            for span, _ in _bundled_matcher(filename, data_class, genitive).find(text):
                if not text[span.start].isupper():
                    continue
                result.append(
                    Finding(
                        span=span,
                        data_class=data_class,
                        stage=self.name,
                        confidence=confidence,
                        attributes={"bundled": "true"},
                    )
                )
        return result
