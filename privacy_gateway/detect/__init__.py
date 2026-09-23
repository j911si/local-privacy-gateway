"""Detection pipeline: the only place that knows the stage order."""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import TYPE_CHECKING

from privacy_gateway.detect.base import Stage
from privacy_gateway.detect.context import ContextStage
from privacy_gateway.detect.correlation import correlate
from privacy_gateway.detect.dictionaries import DictionaryStage
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.detect.session import SessionStage
from privacy_gateway.detect.spans import resolve_overlaps
from privacy_gateway.detect.structured import StructuredStage
from privacy_gateway.model import DetectionReport, Entity, Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

STAGE_TYPES = (StructuredStage, PatternStage, DictionaryStage, ContextStage)

__all__ = ["Pipeline", "Stage"]


class _OffsetMap:
    """Normalized text plus, per normalized character, the original cluster it came from."""

    def __init__(self, text: str) -> None:
        chars: list[str] = []
        self.starts: list[int] = []
        self.ends: list[int] = []
        index = 0
        while index < len(text):
            char = text[index]
            if unicodedata.category(char) == "Cf":
                # ponytail: "Cf" already covers U+00AD and every zero-width character.
                index += 1
                continue
            cluster_end = index + 1
            while cluster_end < len(text) and unicodedata.combining(text[cluster_end]):
                cluster_end += 1
            if unicodedata.category(char) == "Zs":
                # ponytail: a spacing separator never carries combining marks.
                chunk = " "
            else:
                chunk = unicodedata.normalize("NFC", text[index:cluster_end])
            chars.extend(chunk)
            self.starts.extend([index] * len(chunk))
            self.ends.extend([cluster_end] * len(chunk))
            index = cluster_end
        self.text = "".join(chars)

    def original(self, span: Span) -> Span:
        return Span(self.starts[span.start], self.ends[span.end - 1])


def _offset_map(text: str) -> _OffsetMap | None:
    """Return the map, or None when the text needs no normalization."""
    if text.isascii():
        # ponytail: every character we would touch is non-ASCII.
        return None
    mapping = _OffsetMap(text)
    return None if mapping.text == text else mapping


def _remap(mapping: _OffsetMap, findings: list[Finding], entities: dict[str, Entity]) -> None:
    for finding in findings:
        finding.span = mapping.original(finding.span)
        _remap(mapping, finding.children, {})
    for entity in entities.values():
        entity.spans = [mapping.original(span) for span in entity.spans]


class Pipeline:
    """Runs every detection stage, correlates entities and resolves overlaps."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._stages: list[Stage] = [stage_type() for stage_type in STAGE_TYPES]
        self._known: Mapping[str, tuple[str, str]] | None = None
        self._session_stage: SessionStage | None = None

    def _session_stage_for(self, known: Mapping[str, tuple[str, str]]) -> SessionStage:
        """Reuse the stage while the caller passes the same known-set object."""
        if self._session_stage is None or self._known is not known:
            self._known = known
            self._session_stage = SessionStage(known)
        return self._session_stage

    def run(
        self, text: str, known: Mapping[str, tuple[str, str]] | None = None
    ) -> DetectionReport:
        """Return the resolved detection report for one text."""
        mapping = _offset_map(text)
        if mapping is not None:
            text = mapping.text
        findings: list[Finding] = []
        stage_stats: dict[str, int] = {}
        stages = [self._session_stage_for(known), *self._stages] if known else self._stages
        for stage in stages:
            produced = stage.run(text, self._config, list(findings))
            stage_stats[stage.name] = len(produced)
            findings.extend(produced)
        correlated, entities = correlate(text, findings, self._config)
        confident = [f for f in correlated if f.confidence >= self._config.min_confidence]
        resolved = resolve_overlaps(confident, self._config.registry)
        if mapping is not None:
            _remap(mapping, resolved, entities)
        return DetectionReport(findings=resolved, entities=entities, stage_stats=stage_stats)
