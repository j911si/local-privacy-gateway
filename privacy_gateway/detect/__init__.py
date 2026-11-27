"""Detection pipeline: the only place that knows the stage order."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING

from privacy_gateway.classes import Policy
from privacy_gateway.detect.base import Stage
from privacy_gateway.detect.context import ContextStage
from privacy_gateway.detect.correlation import correlate
from privacy_gateway.detect.dictionaries import DictionaryStage
from privacy_gateway.detect.normalize import OffsetMap, offset_map
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.detect.session import SessionStage
from privacy_gateway.detect.spans import resolve_overlaps
from privacy_gateway.detect.structured import StructuredStage
from privacy_gateway.model import DetectionReport, Entity, Finding

if TYPE_CHECKING:
    from privacy_gateway.config import Config

STAGE_TYPES = (StructuredStage, PatternStage, DictionaryStage, ContextStage)

__all__ = ["Pipeline", "Stage"]


def _remap(mapping: OffsetMap, findings: list[Finding], entities: dict[str, Entity]) -> None:
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
        self._session: tuple[Mapping[str, tuple[str, str]], SessionStage] | None = None

    def _session_stage_for(self, known: Mapping[str, tuple[str, str]]) -> SessionStage:
        """Reuse the stage while the caller passes the same known-set object."""
        cached = self._session
        if cached is not None and cached[0] is known:
            return cached[1]
        stage = SessionStage(known)
        self._session = (known, stage)
        return stage

    def run(
        self, text: str, known: Mapping[str, tuple[str, str]] | None = None
    ) -> DetectionReport:
        """Return the resolved detection report for one text."""
        mapping = offset_map(text)
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
        registry = self._config.registry
        redactions = [
            replace(finding, children=[])
            for finding in confident
            if finding.data_class in registry
            and registry.get(finding.data_class).policy is Policy.REDACT
        ]
        resolved = resolve_overlaps(confident, registry)
        if mapping is not None:
            _remap(mapping, resolved, entities)
            _remap(mapping, redactions, {})
        return DetectionReport(
            findings=resolved, entities=entities, stage_stats=stage_stats, redactions=redactions
        )
