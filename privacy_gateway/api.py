"""Gateway facade: detection, pseudonymization, leakage validation and restoration."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import TracebackType
from typing import Self

from privacy_gateway.audit import AuditLog
from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.config import Config, load_config
from privacy_gateway.detect import Pipeline
from privacy_gateway.detect.public import is_public_reference
from privacy_gateway.detect.spans import TOKEN_ATTRIBUTE, SpanIndex
from privacy_gateway.leakage import (
    MIN_LENGTH_FOR_FUZZY_SEARCH,
    REDACTED_SUFFIX,
    check_leakage,
    exempt_from_residual,
    issued_token_spans,
    numbered_tokens,
    redacted_token,
)
from privacy_gateway.model import (
    DetectionReport,
    FieldFinding,
    Finding,
    Leak,
    LeakageError,
    PseudonymizeResult,
    RestoreResult,
    Span,
    SummaryReport,
    VaultEntry,
    VaultError,
)
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text
from privacy_gateway.restore import restore_text
from privacy_gateway.vault import Vault

PSEUDONYMIZE_STAGE = "pseudonymize"
SESSION_STAGE = "session_pseudonymize"
RESULT_CACHE_SIZE = 256
RESCAN_CACHE_SIZE = 1024
AUDIT_ID_BYTES = 6
AUDIT_ID_CACHE_SIZE = 4096
MAX_PASSES = 4
REDACTED_TRIM = " \t\r\n\"'`,;"


class Gateway:
    """Entry point for pseudonymizing a document and restoring the answer."""

    def __init__(self, config: str | Path | Config | None = None) -> None:
        self.config = config if isinstance(config, Config) else load_config(config, env=os.environ)
        self.audit = AuditLog(self.config.audit.path)
        self._pipeline = Pipeline(self.config)
        self._vault: Vault | None = None
        self._audit_ids: OrderedDict[str, str] = OrderedDict()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def vault(self) -> Vault:
        """The encrypted vault, opened on first use."""
        if self._vault is None:
            self._vault = Vault(self.config.vault.db_path, self.config.vault.key_file)
        return self._vault

    def scan(self, text: str) -> DetectionReport:
        """Detect without rewriting anything."""
        return self._pipeline.run(text)

    def session(self, key: str | None = None) -> GatewaySession:
        """Open a session that keeps its token mapping across calls."""
        if key is None:
            session_id = self.vault.create_session("", self.config.hash())
        else:
            session_id = self.vault.get_or_create_session(key, self.config.hash())
        return GatewaySession(self, session_id)

    def pseudonymize(self, text: str) -> PseudonymizeResult:
        """Replace every detected value with a token; fails closed on any leak."""
        started = time.perf_counter()
        session_id = ""
        try:
            session = self.session()
            session_id = session.session_id
            pseudonymized, report, _, _ = session._run(text)
        except LeakageError:
            self._discard(session_id)
            self.audit.pseudonymize(
                self._audit_id(session_id), {}, 0, "failed", _elapsed_ms(started)
            )
            raise
        except Exception as exc:
            self._discard(session_id)
            self.audit.error(type(exc).__name__, PSEUDONYMIZE_STAGE)
            raise
        summary = SummaryReport(
            counts=report.counts_by_class(),
            tokens=[assignment.token for assignment in pseudonymized.assignments],
            leakage="ok",
            duration_ms=_elapsed_ms(started),
        )
        self.audit.pseudonymize(
            self._audit_id(session_id),
            summary.counts,
            len(summary.tokens),
            summary.leakage,
            summary.duration_ms,
        )
        return PseudonymizeResult(
            text=pseudonymized.text, session_id=session_id, report=summary
        )

    def restore(self, text: str, session_id: str, mode: str | None = None) -> RestoreResult:
        """Map tokens back to the values recorded for that session."""
        resolved = mode if mode is not None else self.config.restore.mode
        entries = self.vault.load(session_id)
        result = restore_text(text, entries, resolved)
        self.audit.restore(
            self._audit_id(session_id),
            result.restored_count,
            len(result.unknown_tokens),
            resolved,
        )
        return result

    def close(self) -> None:
        """Close the vault connection if it was opened."""
        if self._vault is not None:
            self._vault.close()
            self._vault = None

    def _audit_id(self, session_id: str) -> str:
        """A random 12-hex-digit id per vault session, held only in this process's memory.

        It is drawn by `secrets` and never derived from the session id, which restores the
        session through `pgw restore` and so must not reach any log. A restart or an evicted
        session gets a new id.
        """
        value = self._audit_ids.pop(session_id, None) or secrets.token_hex(AUDIT_ID_BYTES)
        self._audit_ids[session_id] = value
        while len(self._audit_ids) > AUDIT_ID_CACHE_SIZE:
            self._audit_ids.popitem(last=False)
        return value

    def _discard(self, session_id: str) -> None:
        if session_id and self._vault is not None:
            self._vault.purge(session_id)


class GatewaySession:
    """One conversation: every value keeps the token it received on the first call.

    A cached result was leak-checked when it was first produced, so a repeat of the same
    text is returned unchanged without re-running the pipeline or the leak check. The cache is
    dropped whenever the set of known values changes, because an earlier result may then
    still carry a value that is only known now.
    """

    def __init__(self, gateway: Gateway, session_id: str) -> None:
        self.session_id = session_id
        self._gateway = gateway
        self._entries: dict[str, VaultEntry] = gateway.vault.load(session_id)
        self._counters: dict[str, int] = gateway.vault.max_counters(session_id)
        self._results: OrderedDict[str, tuple[str, list[FieldFinding]]] = OrderedDict()
        self._rescans: OrderedDict[str, list[Leak]] = OrderedDict()
        self._known_cache: dict[str, tuple[str, str]] | None = None
        self._values: dict[tuple[str, str], str] | None = None
        self._redacted: dict[str, str] = {}
        self._generation = 0

    def entries(self) -> Mapping[str, VaultEntry]:
        """Every token mapping this session knows."""
        return dict(self._entries)

    def pseudonymize(self, text: str) -> str:
        """Replace values with tokens, reusing the ones this session already assigned."""
        return self.pseudonymize_report(text)[0]

    def pseudonymize_report(self, text: str) -> tuple[str, list[FieldFinding]]:
        """Pseudonymized text plus its value-free findings, offsets in the original text."""
        started = time.perf_counter()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = self._results.get(digest)
        if cached is not None:
            self._results.move_to_end(digest)
            self._gateway.audit.session_pseudonymize(
                self._gateway._audit_id(self.session_id), 0, 0, "ok", _elapsed_ms(started)
            )
            return cached[0], list(cached[1])
        try:
            pseudonymized, report, written, reused = self._run(text)
        except LeakageError:
            self._gateway.audit.session_pseudonymize(
                self._gateway._audit_id(self.session_id), 0, 0, "failed", _elapsed_ms(started)
            )
            raise
        except Exception as exc:
            self._gateway.audit.error(type(exc).__name__, SESSION_STAGE)
            if isinstance(exc, VaultError):
                self._reload()
            raise
        self._gateway.audit.session_pseudonymize(
            self._gateway._audit_id(self.session_id),
            len(written),
            len(reused),
            "ok",
            _elapsed_ms(started),
        )
        findings = _field_findings(report, pseudonymized, self._gateway.config.registry)
        self._remember(digest, (pseudonymized.text, findings))
        return pseudonymized.text, list(findings)

    def _run(self, text: str) -> tuple[PseudonymizedText, DetectionReport, list[str], list[str]]:
        """Replace, check and learn until the check passes; rolls back and re-raises on failure."""
        counters = dict(self._counters)
        written: list[str] = []
        reused: list[str] = []
        redacted: list[str] = []
        pipeline = self._gateway._pipeline
        registry = self._gateway.config.registry
        literal_tokens = numbered_tokens(text)
        try:
            for attempt in range(MAX_PASSES):
                generation = self._generation
                known = self._known()
                report = self._bind_tokens(
                    text, _with_glued_short(text, pipeline.run(text, known), known, registry)
                )
                pseudonymized = pseudonymize_text(
                    text, report, self._gateway.config, counters=self._counters
                )
                self._write(text, pseudonymized, written, reused)
                self._learn_redacted(text, report, redacted)
                try:
                    check_leakage(
                        pseudonymized.text,
                        self._entries,
                        lambda candidate, known=known: pipeline.run(candidate, known),
                        self._gateway.config.registry,
                        literal_tokens,
                        redacted=self._redacted,
                    )
                except LeakageError as exc:
                    if attempt + 1 < MAX_PASSES and (
                        self._generation != generation
                        or self._learn_residue(
                            pseudonymized.text, exc.leaks, known, written, reused, redacted
                        )
                    ):
                        continue
                    raise
                break
        except Exception:
            self._rollback(written, counters, redacted)
            raise
        return pseudonymized, report, written, reused

    def rescan(self, text: str) -> list[Leak]:
        """Findings in text about to be sent that are not a token this session issued."""
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = self._rescans.get(digest)
        if cached is not None:
            self._rescans.move_to_end(digest)
            return list(cached)
        registry = self._gateway.config.registry
        tokens = SpanIndex(issued_token_spans(text, self._entries))
        leaks: list[Leak] = []
        for finding in self._gateway._pipeline.run(text, self._known()).findings:
            if _ignored(registry, finding.data_class):
                continue
            if exempt_from_residual(finding, tokens, text):
                continue
            if is_public_reference(text[finding.span.start : finding.span.end]):
                continue
            leaks.append(Leak("rescan", finding.data_class, finding.span.start, finding.span.end))
        self._rescans[digest] = leaks
        while len(self._rescans) > RESCAN_CACHE_SIZE:
            self._rescans.popitem(last=False)
        return list(leaks)

    def _remember(self, digest: str, result: tuple[str, list[FieldFinding]]) -> None:
        self._results[digest] = result
        while len(self._results) > RESULT_CACHE_SIZE:
            self._results.popitem(last=False)

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        """Pseudonymize several texts in order, sharing counters and known values."""
        return [text for text, _ in self.pseudonymize_report_many(texts)]

    def pseudonymize_report_many(self, texts: list[str]) -> list[tuple[str, list[FieldFinding]]]:
        """Like `pseudonymize_report` per text, repeated until no text adds a known value."""
        while True:
            generation = self._generation
            results = []
            for index, text in enumerate(texts):
                try:
                    results.append(self.pseudonymize_report(text))
                except LeakageError as exc:
                    exc.text_index = index
                    raise
            if self._generation == generation:
                return results

    def restore(self, text: str, mode: str | None = None) -> RestoreResult:
        """Map tokens back to the values recorded for this session."""
        resolved = mode if mode is not None else self._gateway.config.restore.mode
        result = restore_text(text, self._entries, resolved)
        self._gateway.audit.restore(
            self._gateway._audit_id(self.session_id),
            result.restored_count,
            len(result.unknown_tokens),
            resolved,
        )
        return result

    def restore_text(self, text: str) -> str:
        """Restored text only."""
        return self.restore(text).text

    def _known(self) -> dict[str, tuple[str, str]]:
        if self._known_cache is not None:
            return self._known_cache
        known: dict[str, tuple[str, str]] = {}
        for token, entry in self._entries.items():
            for form in [entry.value, *entry.surface_forms]:
                if form:
                    known.setdefault(form, (entry.data_class, token))
        for value, data_class in self._redacted.items():
            known.setdefault(value, (data_class, redacted_token(data_class)))
        self._known_cache = known
        return known

    def _value_index(self) -> dict[tuple[str, str], str]:
        if self._values is None:
            self._values = {}
            for token, entry in self._entries.items():
                self._values.setdefault((entry.data_class, entry.value), token)
        return self._values

    def _bind_tokens(self, text: str, report: DetectionReport) -> DetectionReport:
        """Give a finding the token whose value is exactly its text, and none otherwise.

        The session stage also finds other spellings of a known value; those get a token of their
        own, so every token restores to the exact bytes it replaced.
        """
        index = self._value_index()
        findings = []
        for finding in report.findings:
            span = finding.span
            token = index.get((finding.data_class, text[span.start : span.end]))
            attributes = {k: v for k, v in finding.attributes.items() if k != TOKEN_ATTRIBUTE}
            if token is not None:
                attributes[TOKEN_ATTRIBUTE] = token
            findings.append(replace(finding, attributes=attributes))
        return replace(report, findings=findings)

    def _write(
        self,
        text: str,
        pseudonymized: PseudonymizedText,
        written: list[str],
        reused: list[str],
    ) -> None:
        if pseudonymized.assignments:
            known = self._known()
            if any(
                text[span.start : span.end] not in known
                for assignment in pseudonymized.assignments
                for span in assignment.spans
            ):
                self._known_changed()
            self._known_cache = None
            self._values = None
            self._rescans.clear()
        for assignment in pseudonymized.assignments:
            first = assignment.spans[0]
            value = text[first.start : first.end]
            if assignment.token in self._entries:
                reused.append(assignment.token)
                continue
            self._gateway.vault.store(
                self.session_id,
                assignment.token,
                assignment.data_class,
                value,
                [value],
                assignment.attributes,
            )
            self._entries[assignment.token] = VaultEntry(
                value=value,
                data_class=assignment.data_class,
                surface_forms=[value],
                attributes=dict(assignment.attributes),
            )
            written.append(assignment.token)

    def _learn_redacted(self, text: str, report: DetectionReport, learned: list[str]) -> None:
        """Keep redacted values in memory only, so every later copy is redacted too."""
        registry = self._gateway.config.registry
        count = len(learned)
        for finding in report.findings:
            data_class = registry.get(finding.data_class)
            value = text[finding.span.start : finding.span.end].strip(REDACTED_TRIM)
            if data_class.policy is not Policy.REDACT or not value:
                continue
            if value in self._redacted:
                continue
            self._redacted[value] = data_class.name
            learned.append(value)
        if len(learned) > count:
            self._known_cache = None
            self._rescans.clear()
            self._known_changed()

    def _learn_residue(
        self,
        output: str,
        leaks: list[Leak],
        known: dict[str, tuple[str, str]],
        written: list[str],
        reused: list[str],
        redacted: list[str],
    ) -> bool:
        """Make values the output check found a known value, so the next pass replaces them.

        Replacing shortens text, so a context word can come into range of a value that the
        original text had out of range.
        """
        spans = {
            (leak.start, leak.end, leak.data_class)
            for leak in leaks
            if leak.kind == "residual_finding"
        }
        if not spans:
            return False
        report = self._bind_tokens(output, self._gateway._pipeline.run(output, known))
        kept = [
            finding
            for finding in report.findings
            if (finding.span.start, finding.span.end, finding.data_class) in spans
            and "<" not in output[finding.span.start : finding.span.end]
        ]
        if not kept:
            return False
        generation = self._generation
        residue = replace(report, findings=kept)
        learned = pseudonymize_text(output, residue, self._gateway.config, counters=self._counters)
        self._write(output, learned, written, reused)
        self._learn_redacted(output, residue, redacted)
        return self._generation != generation

    def _rollback(
        self,
        written: list[str],
        counters: dict[str, int],
        redacted: list[str],
    ) -> None:
        self._known_cache = None
        self._values = None
        self._rescans.clear()
        if written:
            self._known_changed()
        self._gateway.vault.delete_tokens(self.session_id, written)
        for token in written:
            self._entries.pop(token, None)
        for value in redacted:
            self._redacted.pop(value, None)
        if redacted:
            self._known_changed()
        self._counters = counters

    def _reload(self) -> None:
        """Take the mappings and counters another process may have written from the vault."""
        vault = self._gateway.vault
        self._entries = vault.load(self.session_id)
        stored = vault.max_counters(self.session_id)
        self._counters = {
            label: max(self._counters.get(label, 0), stored.get(label, 0))
            for label in {*self._counters, *stored}
        }
        self._known_changed()

    def _known_changed(self) -> None:
        self._generation += 1
        self._results.clear()


def _with_glued_short(
    text: str, report: DetectionReport, known: Mapping[str, tuple[str, str]], registry: ClassRegistry
) -> DetectionReport:
    """Add short known values glued to a replaced finding, which the leak check sees whole."""
    spans = [f.span for f in report.findings if not _ignored(registry, f.data_class)]
    if not spans:
        return report
    starts = {span.start for span in spans}
    ends = {span.end for span in spans}
    added: list[Finding] = []
    for form, (data_class, _) in known.items():
        if len(form) >= MIN_LENGTH_FOR_FUZZY_SEARCH:
            continue
        for match in re.finditer(re.escape(form), text, re.IGNORECASE):
            start, end = match.start(), match.end()
            free_left = start == 0 or not text[start - 1].isalnum() or start in ends
            free_right = end == len(text) or not text[end].isalnum() or end in starts
            if not ((start in ends and free_right) or (end in starts and free_left)):
                continue
            span = Span(start, end)
            if any(span.overlaps(other) for other in spans):
                continue
            spans.append(span)
            added.append(
                Finding(span=span, data_class=data_class, stage="session", confidence=1.0)
            )
    if not added:
        return report
    findings = sorted([*report.findings, *added], key=lambda finding: finding.span.start)
    return replace(report, findings=findings)


def _ignored(registry: ClassRegistry, data_class: str) -> bool:
    return data_class in registry and registry.get(data_class).policy is Policy.IGNORE


def _field_findings(
    report: DetectionReport, pseudonymized: PseudonymizedText, registry: ClassRegistry
) -> list[FieldFinding]:
    tokens = {
        span: assignment.token
        for assignment in pseudonymized.assignments
        for span in assignment.spans
    }
    findings: list[FieldFinding] = []
    for finding in report.findings:
        data_class = registry.get(finding.data_class)
        if data_class.policy is Policy.IGNORE:
            continue
        if data_class.policy is Policy.REDACT:
            token: str | None = f"<{data_class.name}{REDACTED_SUFFIX}"
        else:
            token = tokens.get(finding.span)
        findings.append(
            FieldFinding(
                data_class=finding.data_class,
                start=finding.span.start,
                end=finding.span.end,
                token=token,
                policy=data_class.policy.value,
                confidence=finding.confidence,
                stage=finding.stage,
            )
        )
    return findings


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
