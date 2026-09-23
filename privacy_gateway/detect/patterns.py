"""Regex detection stage with per-class validators and context requirements."""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import cache
from typing import TYPE_CHECKING

from privacy_gateway.classes import DataClass
from privacy_gateway.detect.validators import VALIDATORS, ip_scope
from privacy_gateway.model import ConfigError, Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

CONTEXT_WINDOW = 40
BASE_CONFIDENCE = 0.9
VALIDATED_CONFIDENCE = 0.95
CONTEXT_BONUS = 0.03
MAX_CONFIDENCE = 0.99
IP_CLASS = "IP_ADDRESS"
IP_SCOPE_CLASSES = {"private": "PRIVATE_IP", "public": "PUBLIC_IP"}
GENERIC_ID_CLASS = "GENERIC_ID"
STANDARD_PREFIXES = frozenset(
    {
        "ISO", "IEC", "RFC", "IEEE", "DIN", "EN", "SHA", "MD", "UTF", "HTTP", "TLS", "SSL",
        "GPT", "COVID", "CVE", "CWE", "OWASP", "PCI", "DSS", "NIST", "GDPR", "DSGVO", "BGB",
        "HGB", "SGB", "VDE", "ANSI", "ASCII", "JSON", "XML", "HTML", "CSS", "IPV", "WCAG",
        "ECMA", "POSIX", "UTC", "GMT", "ISBN", "ISSN",
    }
)


@cache
def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.MULTILINE))
        except re.error as exc:
            raise ConfigError(f"invalid pattern '{pattern}': {exc}") from exc
    return tuple(compiled)


def _validator_for(data_class: DataClass) -> Callable[[str], bool] | None:
    if data_class.validator is None:
        return None
    try:
        return VALIDATORS[data_class.validator]
    except KeyError:
        raise ConfigError(
            f"unknown validator '{data_class.validator}' for class '{data_class.name}'"
        ) from None


@cache
def _context_re(words: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(word) for word in words)
    return re.compile(
        rf"(?<![A-Za-z0-9])(?:{alternatives})(?![A-Za-z0-9])", re.IGNORECASE
    )


def _has_context(text: str, start: int, words: tuple[str, ...]) -> bool:
    if not words:
        return False
    window = text[max(0, start - CONTEXT_WINDOW) : start]
    return _context_re(words).search(window) is not None


def _is_standard_reference(value: str) -> bool:
    return value.split("-", 1)[0].upper() in STANDARD_PREFIXES


def _span_of(match: re.Match[str]) -> Span:
    if match.re.groups >= 1 and match.group(1) is not None:
        return Span(*match.span(1))
    return Span(*match.span(0))


class PatternStage:
    """Emits one finding per regex match that survives validator and context checks."""

    name = "pattern"

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return only the findings produced by this stage."""
        new: list[Finding] = []
        for data_class in config.registry.enabled():
            if not data_class.patterns:
                continue
            validator = _validator_for(data_class)
            for regex in _compile(data_class.patterns):
                for match in regex.finditer(text):
                    new.extend(self._for_match(text, match, data_class, validator, config))
        new.sort(key=lambda f: (f.span.start, f.span.end, f.data_class))
        return new

    def _for_match(
        self,
        text: str,
        match: re.Match[str],
        data_class: DataClass,
        validator: Callable[[str], bool] | None,
        config: Config,
    ) -> list[Finding]:
        span = _span_of(match)
        value = text[span.start : span.end]
        if data_class.name == GENERIC_ID_CLASS and _is_standard_reference(value):
            return []
        if validator is not None and not validator(value):
            return []
        has_context = _has_context(text, match.start(), data_class.context_words)
        if data_class.context_required and not has_context:
            return []
        confidence = VALIDATED_CONFIDENCE if validator is not None else BASE_CONFIDENCE
        if has_context:
            confidence = min(MAX_CONFIDENCE, confidence + CONTEXT_BONUS)
        finding = Finding(
            span=span, data_class=data_class.name, stage=self.name, confidence=confidence
        )
        if data_class.name != IP_CLASS:
            return [finding]
        return [finding, *self._scope_findings(finding, value, confidence, config)]

    def _scope_findings(
        self, finding: Finding, value: str, confidence: float, config: Config
    ) -> list[Finding]:
        scope = ip_scope(value)
        if scope is None:
            return []
        finding.attributes["scope"] = scope
        scope_class = IP_SCOPE_CLASSES[scope]
        if scope_class not in config.registry or not config.registry.get(scope_class).enabled:
            return []
        return [
            Finding(
                span=finding.span,
                data_class=scope_class,
                stage=self.name,
                confidence=confidence,
                attributes={"scope": scope},
            )
        ]
