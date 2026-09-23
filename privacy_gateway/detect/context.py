"""Deterministic context rules for salutations, markers, addresses and health sentences."""

from __future__ import annotations

import re
from functools import cache
from importlib.resources import files
from typing import TYPE_CHECKING

import yaml

from privacy_gateway.detect.dictionaries import DATA_PACKAGE, TrieMatcher
from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config


def _load_salutations() -> dict[str, str | None]:
    raw = yaml.safe_load(
        files(DATA_PACKAGE).joinpath("salutations.yaml").read_text(encoding="utf-8")
    )
    return {str(word): None if gender is None else str(gender) for word, gender in raw.items()}


SALUTATIONS: dict[str, str | None] = _load_salutations()

COUNTRIES: tuple[str, ...] = (
    "Deutschland",
    "Germany",
    "Österreich",
    "Austria",
    "Schweiz",
    "Switzerland",
    "Frankreich",
    "France",
    "Italien",
    "Italy",
    "Spanien",
    "Spain",
    "Portugal",
    "Niederlande",
    "Netherlands",
    "Belgien",
    "Belgium",
    "Luxemburg",
    "Luxembourg",
    "Dänemark",
    "Denmark",
    "Schweden",
    "Sweden",
    "Norwegen",
    "Norway",
    "Finnland",
    "Finland",
    "Iceland",
    "Irland",
    "Ireland",
    "Vereinigtes Königreich",
    "United Kingdom",
    "Großbritannien",
    "Great Britain",
    "England",
    "Schottland",
    "Scotland",
    "Wales",
    "Polen",
    "Poland",
    "Tschechien",
    "Czech Republic",
    "Slowakei",
    "Slovakia",
    "Ungarn",
    "Hungary",
    "Slowenien",
    "Slovenia",
    "Kroatien",
    "Croatia",
    "Serbien",
    "Serbia",
    "Rumänien",
    "Romania",
    "Bulgarien",
    "Bulgaria",
    "Griechenland",
    "Greece",
    "Türkei",
    "Russland",
    "Ukraine",
    "Estland",
    "Estonia",
    "Lettland",
    "Latvia",
    "Litauen",
    "Lithuania",
    "Vereinigte Staaten",
    "United States",
    "Kanada",
    "Canada",
    "Mexiko",
    "Mexico",
    "Brasilien",
    "Brazil",
    "Argentinien",
    "Argentina",
    "Australien",
    "Australia",
    "Neuseeland",
    "New Zealand",
    "Japan",
    "Indien",
    "India",
    "Südkorea",
    "South Korea",
    "Singapur",
    "Singapore",
    "Israel",
    "Ägypten",
    "Egypt",
    "Südafrika",
    "South Africa",
    "Marokko",
    "Morocco",
    "Nigeria",
    "Kenia",
    "Kenya",
)

STOP_WORDS = frozenset(
    {
        "true",
        "false",
        "yes",
        "no",
        "none",
        "null",
        "nein",
        "ja",
        "der",
        "die",
        "das",
        "the",
        "and",
        "und",
        "of",
        "von",
        "for",
        "für",
        "is",
        "ist",
        "am",
        "im",
        "in",
        "on",
    }
)

HEALTH_MARKERS = (
    "diagnose",
    "diagnosis",
    "diagnosed",
    "leidet an",
    "suffers from",
    "befund",
    "therapie",
    "treatment",
    "medikation",
    "medication",
)
HEALTH_MARKER_WINDOW = 60
SENTENCE_BOUNDARIES = ".\n"

SALUTATION_RE = re.compile(
    r"(?:Sehr geehrte[r]?|Dear|Hallo|Hi|Liebe[r]?)?\s*"
    r"\b(Frau|Herr|Herrn|Mrs\.?|Mr\.?|Ms\.?|Mx\.?)\s+"
    r"((?:(?:Dr|Prof|Dipl\.-Ing)\.\s+)*)"
    r"([A-ZÄÖÜ][\wäöüß-]+(?:\s+[A-ZÄÖÜ][\wäöüß-]+)?)"
)
MARKER_TAIL = (
    r"\s*((?:[:#=]|-?\s*nr\.?|no\.?|number|nummer)?\s*[:#=]?)\s*"
    r"([A-Za-z0-9][A-Za-z0-9_\-./]{2,})"
)
MARKER_SUFFIX = r"(?:[-\s]?(?:nummer|nr\.?|number|no\.?|id))?(?!\w)"
MARKER_TRAILING = ".,;:)]\"'"
DEPARTMENT_RE = re.compile(
    r"(?i)\b(?:Abteilung|Department|Dept\.?)\s*[:=]?\s*([A-ZÄÖÜ][\w&/ -]{2,40})"
)
JOB_TITLE_RE = re.compile(
    r"\b(CEO|CTO|CFO|CISO|Geschäftsführer(?:in)?|Leiter(?:in)?|Head of [A-Z][a-z]+"
    r"|Senior [A-Z][a-z]+ Engineer|Product Owner|Projektleiter(?:in)?)\b"
)
ADDRESS_RE = re.compile(
    r"([A-ZÄÖÜ][\wäöüß.-]+"
    r"(?:straße|strasse|str\.|weg|allee|platz|gasse|ring|damm|ufer"
    r"|Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane))"
    r"\s+(\d{1,4}[a-zA-Z]?)\s*,?\s*(\d{4,5})\s+([A-ZÄÖÜ][\wäöüß -]+)"
)
POSTAL_CODE_RE = re.compile(r"(?i)\b(?:PLZ|Postleitzahl|zip)\s*[:=]?\s*(\d{4,5})")
PLACE_OF_BIRTH_RE = re.compile(
    r"(?i)\b(?:(?:geboren|geb\.|born)(?:\s+(?:am|on))?\s+(?:\d[\d./-]{5,}\s+)?in"
    r"|Geburtsort[:=]?)\s+([A-ZÄÖÜ][\wäöüß -]+)"
)
ORGANIZATION_RE = re.compile(
    r"((?:[A-ZÄÖÜ][\wäöüß&.-]*\s){1,4}?)"
    r"(GmbH & Co\. KG|GmbH|AG|SE|KGaA|KG|OHG|e\.V\.|eG|Ltd\.?|LLC|Inc\.?|Corp\.?|PLC"
    r"|S\.A\.|B\.V\.|N\.V\.|S\.r\.l\.|Oy|AB|AS)(?![\w-])"
)
INITIALS_RE = re.compile(r"\b([A-ZÄÖÜ]\.\s?[A-ZÄÖÜ]\.)")
HANDLE_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,30}\b")
IDENTIFIER_PREFIX = r"(?<![-_./:\w])"
MESSENGER_RE = re.compile(
    r"(?i)" + IDENTIFIER_PREFIX + r"(?:telegram|signal|whatsapp|teams|slack)"
    r"(?:\s*[:=]\s*|\s+)(@?[A-Za-z0-9_.+-]{3,})"
)
SIP_RE = re.compile(r"sip:[^\s>]+")
NAME_GAP_RE = re.compile(r"[\s|]+")
NAME_COMMA_RE = re.compile(r",\s+")
NAME_WORD_RE = re.compile(r"[^\W\d_]+(?:-[^\W\d_]+)*")


@cache
def _marker_re(word: str) -> re.Pattern[str]:
    body = r"[-\s]?".join(re.escape(part) for part in word.split("-"))
    boundary = MARKER_SUFFIX if word[-1:].isalnum() else r"\b"
    return re.compile(r"(?i)" + IDENTIFIER_PREFIX + body + boundary + MARKER_TAIL)


@cache
def _country_matcher() -> TrieMatcher:
    return TrieMatcher((country, "COUNTRY") for country in COUNTRIES)


def _trimmed_span(text: str, start: int, end: int) -> Span:
    while end > start and text[end - 1].isspace():
        end -= 1
    while start < end and text[start].isspace():
        start += 1
    return Span(start, end)


def _group_span(text: str, match: re.Match[str], group: int) -> Span:
    return _trimmed_span(text, match.start(group), match.end(group))


def _marker_value_span(text: str, match: re.Match[str]) -> Span:
    span = _group_span(text, match, 2)
    end = span.end
    while end > span.start and text[end - 1] in MARKER_TRAILING:
        end -= 1
    return Span(span.start, end)


def _sentence_fragment(text: str, start: int, end: int) -> Span:
    left = start
    while left > 0 and text[left - 1] not in SENTENCE_BOUNDARIES:
        left -= 1
    right = end
    while right < len(text) and text[right] not in SENTENCE_BOUNDARIES:
        right += 1
    return _trimmed_span(text, left, right)


class ContextStage:
    """Applies deterministic DE/EN context rules on top of earlier findings."""

    name = "context"

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return only the findings produced by the context rules."""
        out: list[Finding] = []
        self._salutations(text, config, out)
        self._name_pairs(text, config, findings, out)
        self._markers(text, config, out)
        self._roles(text, config, out)
        self._addresses(text, config, out)
        self._place_of_birth(text, config, out)
        self._health(text, config, findings, out)
        self._initials(text, config, out)
        self._handles(text, config, out)
        self._countries(text, config, out)
        return self._deduplicate(out)

    def _emit(
        self,
        config: Config,
        out: list[Finding],
        span: Span,
        data_class: str,
        confidence: float,
        attributes: dict[str, str] | None = None,
        children: list[Finding] | None = None,
    ) -> Finding | None:
        if data_class not in config.registry or not config.registry.get(data_class).enabled:
            return None
        finding = Finding(
            span=span,
            data_class=data_class,
            stage=self.name,
            confidence=confidence,
            attributes=dict(attributes or {}),
            children=list(children or []),
        )
        out.append(finding)
        return finding

    def _build(
        self, config: Config, span: Span, data_class: str, confidence: float
    ) -> Finding | None:
        if data_class not in config.registry or not config.registry.get(data_class).enabled:
            return None
        return Finding(span=span, data_class=data_class, stage=self.name, confidence=confidence)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, int, int]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.data_class, finding.span.start, finding.span.end)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        unique.sort(key=lambda finding: (finding.span.start, finding.span.end))
        return unique

    def _salutations(self, text: str, config: Config, out: list[Finding]) -> None:
        for match in SALUTATION_RE.finditer(text):
            word = match.group(1)
            attributes = {"source": "salutation"}
            gender = SALUTATIONS.get(word)
            if gender is not None and config.person.record_gender_from_salutation:
                attributes["gender"] = gender
            self._emit(config, out, _group_span(text, match, 1), "SALUTATION", 0.95, attributes)
            if match.group(2).strip():
                self._emit(
                    config,
                    out,
                    _group_span(text, match, 2),
                    "ACADEMIC_TITLE",
                    0.95,
                    {"source": "salutation"},
                )
            name_span = _group_span(text, match, 3)
            name = text[name_span.start : name_span.end]
            data_class = "PERSON_FULL_NAME" if " " in name else "PERSON_LAST_NAME"
            self._emit(config, out, name_span, data_class, 0.95, attributes)

    def _name_pairs(
        self, text: str, config: Config, findings: list[Finding], out: list[Finding]
    ) -> None:
        bundled = [f for f in findings if f.attributes.get("bundled") == "true"]
        first_names = {f.span.start: f for f in bundled if f.data_class == "PERSON_FIRST_NAME"}
        last_starts = {f.span.start for f in bundled if f.data_class == "PERSON_LAST_NAME"}
        for start in sorted(first_names):
            word = self._name_word(text, first_names[start].span.end, NAME_GAP_RE)
            if word is None or not any(word.start <= s < word.end for s in last_starts):
                continue
            self._emit(config, out, Span(start, word.end), "PERSON_FULL_NAME", 0.85)
        for start in sorted(last_starts):
            last_word = NAME_WORD_RE.match(text, start)
            if last_word is None:
                continue
            word = self._name_word(text, last_word.end(), NAME_COMMA_RE)
            if word is None or word.start not in first_names:
                continue
            self._emit(config, out, Span(start, word.end), "PERSON_FULL_NAME", 0.85)

    @staticmethod
    def _name_word(text: str, start: int, separator: re.Pattern[str]) -> Span | None:
        """The name-shaped word that follows `start` after one separator, hyphens included."""
        gap = separator.match(text, start)
        if gap is None:
            return None
        word = NAME_WORD_RE.match(text, gap.end())
        return None if word is None else Span(word.start(), word.end())

    def _markers(self, text: str, config: Config, out: list[Finding]) -> None:
        vocabulary = {
            word.lower()
            for data_class in config.registry.enabled()
            for word in data_class.context_words
        }
        for data_class in config.registry.enabled():
            if not data_class.context_words or data_class.patterns:
                continue
            for word in data_class.context_words:
                for match in _marker_re(word).finditer(text):
                    span = _marker_value_span(text, match)
                    value = text[span.start : span.end]
                    if value.lower() in STOP_WORDS or value.lower() in vocabulary:
                        continue
                    if not match.group(1).strip() and not any(c.isdigit() for c in value):
                        continue
                    if value.isalpha() and value.islower():
                        continue
                    self._emit(config, out, span, data_class.name, 0.85)

    def _roles(self, text: str, config: Config, out: list[Finding]) -> None:
        for match in DEPARTMENT_RE.finditer(text):
            self._emit(config, out, _group_span(text, match, 1), "DEPARTMENT", 0.8)
        for match in JOB_TITLE_RE.finditer(text):
            self._emit(config, out, _group_span(text, match, 1), "JOB_TITLE", 0.8)
        for match in ORGANIZATION_RE.finditer(text):
            span = _trimmed_span(text, match.start(), match.end())
            self._emit(config, out, span, "ORGANIZATION_NAME", 0.85)

    def _addresses(self, text: str, config: Config, out: list[Finding]) -> None:
        components = ("STREET", "HOUSE_NUMBER", "POSTAL_CODE", "CITY")
        for match in ADDRESS_RE.finditer(text):
            children = [
                child
                for index, name in enumerate(components, start=1)
                if (child := self._build(config, _group_span(text, match, index), name, 0.9))
            ]
            span = _trimmed_span(text, match.start(), match.end())
            self._emit(config, out, span, "ADDRESS", 0.9, None, children)
        for match in POSTAL_CODE_RE.finditer(text):
            self._emit(config, out, _group_span(text, match, 1), "POSTAL_CODE", 0.85)

    def _place_of_birth(self, text: str, config: Config, out: list[Finding]) -> None:
        for match in PLACE_OF_BIRTH_RE.finditer(text):
            self._emit(config, out, _group_span(text, match, 1), "PLACE_OF_BIRTH", 0.85)

    def _health(
        self, text: str, config: Config, findings: list[Finding], out: list[Finding]
    ) -> None:
        for finding in findings:
            if finding.data_class != "MEDICAL_INFORMATION":
                continue
            if finding.attributes.get("bundled") != "true":
                continue
            window = text[max(0, finding.span.start - HEALTH_MARKER_WINDOW) : finding.span.start]
            if not any(marker in window.lower() for marker in HEALTH_MARKERS):
                continue
            span = _sentence_fragment(text, finding.span.start, finding.span.end)
            self._emit(config, out, span, "HEALTH_INFORMATION", 0.95)

    def _initials(self, text: str, config: Config, out: list[Finding]) -> None:
        for match in INITIALS_RE.finditer(text):
            self._emit(config, out, _group_span(text, match, 1), "PERSON_INITIALS", 0.4)

    def _handles(self, text: str, config: Config, out: list[Finding]) -> None:
        for match in HANDLE_RE.finditer(text):
            span = _trimmed_span(text, match.start(), match.end())
            self._emit(config, out, span, "SOCIAL_MEDIA_HANDLE", 0.8)
        for match in MESSENGER_RE.finditer(text):
            value = match.group(1)
            if not value.startswith("@") and not any(
                char.isdigit() or char in "_." for char in value
            ):
                continue
            self._emit(config, out, _group_span(text, match, 1), "MESSENGER_ID", 0.8)
        for match in SIP_RE.finditer(text):
            span = _trimmed_span(text, match.start(), match.end())
            self._emit(config, out, span, "SIP_ADDRESS", 0.95)

    def _countries(self, text: str, config: Config, out: list[Finding]) -> None:
        for span, data_class in _country_matcher().find(text):
            self._emit(config, out, span, data_class, 0.8)
