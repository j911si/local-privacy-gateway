"""Gateway facade: detection, pseudonymization, leakage validation and restoration."""

from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Self

from privacy_gateway.audit import AuditLog
from privacy_gateway.config import Config, load_config
from privacy_gateway.detect import Pipeline
from privacy_gateway.leakage import check_leakage
from privacy_gateway.model import (
    DetectionReport,
    LeakageError,
    PseudonymizeResult,
    RestoreResult,
    SummaryReport,
    VaultEntry,
)
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text
from privacy_gateway.restore import restore_text
from privacy_gateway.vault import Vault

PSEUDONYMIZE_STAGE = "pseudonymize"
SESSION_STAGE = "session_pseudonymize"
RESULT_CACHE_SIZE = 256


class Gateway:
    """Entry point for pseudonymizing a document and restoring the answer."""

    def __init__(self, config: str | Path | Config | None = None) -> None:
        self.config = config if isinstance(config, Config) else load_config(config, env=os.environ)
        self.audit = AuditLog(self.config.audit.path)
        self._pipeline = Pipeline(self.config)
        self._vault: Vault | None = None

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
            report = self._pipeline.run(text)
            session_id = self.vault.create_session("", self.config.hash())
            pseudonymized = pseudonymize_text(text, report, self.config)
            for assignment in pseudonymized.assignments:
                first = assignment.spans[0]
                self.vault.store(
                    session_id,
                    assignment.token,
                    assignment.data_class,
                    text[first.start : first.end],
                    [text[span.start : span.end] for span in assignment.spans],
                    assignment.attributes,
                )
            entries = self.vault.load(session_id)
            check_leakage(pseudonymized.text, entries, self._pipeline.run, self.config.registry)
        except LeakageError:
            self._discard(session_id)
            self.audit.pseudonymize(session_id, {}, 0, "failed", _elapsed_ms(started))
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
            session_id,
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
            session_id, result.restored_count, len(result.unknown_tokens), resolved
        )
        return result

    def close(self) -> None:
        """Close the vault connection if it was opened."""
        if self._vault is not None:
            self._vault.close()
            self._vault = None

    def _discard(self, session_id: str) -> None:
        if session_id and self._vault is not None:
            self._vault.purge(session_id)


class GatewaySession:
    """One conversation: every value keeps the token it received on the first call.

    A cached result was leak-checked when it was first produced, so a repeat of the same
    text is returned unchanged without re-running the pipeline or the leak check.
    """

    def __init__(self, gateway: Gateway, session_id: str) -> None:
        self.session_id = session_id
        self._gateway = gateway
        self._entries: dict[str, VaultEntry] = gateway.vault.load(session_id)
        self._counters: dict[str, int] = gateway.vault.max_counters(session_id)
        self._results: OrderedDict[str, str] = OrderedDict()
        self._known_cache: dict[str, tuple[str, str]] | None = None

    def entries(self) -> Mapping[str, VaultEntry]:
        """Every token mapping this session knows."""
        return dict(self._entries)

    def pseudonymize(self, text: str) -> str:
        """Replace values with tokens, reusing the ones this session already assigned."""
        started = time.perf_counter()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = self._results.get(digest)
        if cached is not None:
            self._results.move_to_end(digest)
            self._gateway.audit.session_pseudonymize(
                self.session_id, 0, 0, "ok", _elapsed_ms(started)
            )
            return cached
        known = self._known()
        counters = dict(self._counters)
        written: list[str] = []
        appended: list[tuple[str, list[str]]] = []
        pipeline = self._gateway._pipeline
        try:
            report = pipeline.run(text, known)
            pseudonymized = pseudonymize_text(
                text, report, self._gateway.config, counters=self._counters
            )
            self._write(text, pseudonymized, written, appended)
            check_leakage(
                pseudonymized.text,
                self._entries,
                lambda candidate: pipeline.run(candidate, known),
                self._gateway.config.registry,
            )
        except LeakageError:
            self._rollback(written, appended, counters)
            self._gateway.audit.session_pseudonymize(
                self.session_id, 0, 0, "failed", _elapsed_ms(started)
            )
            raise
        except Exception as exc:
            self._rollback(written, appended, counters)
            self._gateway.audit.error(type(exc).__name__, SESSION_STAGE)
            raise
        self._gateway.audit.session_pseudonymize(
            self.session_id, len(written), len(appended), "ok", _elapsed_ms(started)
        )
        self._remember(digest, pseudonymized.text)
        return pseudonymized.text

    def _remember(self, digest: str, result: str) -> None:
        self._results[digest] = result
        while len(self._results) > RESULT_CACHE_SIZE:
            self._results.popitem(last=False)

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        """Pseudonymize several texts in order, sharing counters and known values."""
        return [self.pseudonymize(text) for text in texts]

    def restore(self, text: str, mode: str | None = None) -> RestoreResult:
        """Map tokens back to the values recorded for this session."""
        resolved = mode if mode is not None else self._gateway.config.restore.mode
        result = restore_text(text, self._entries, resolved)
        self._gateway.audit.restore(
            self.session_id, result.restored_count, len(result.unknown_tokens), resolved
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
        self._known_cache = known
        return known

    def _write(
        self,
        text: str,
        pseudonymized: PseudonymizedText,
        written: list[str],
        appended: list[tuple[str, list[str]]],
    ) -> None:
        if pseudonymized.assignments:
            self._known_cache = None
        for assignment in pseudonymized.assignments:
            forms = [text[span.start : span.end] for span in assignment.spans]
            entry = self._entries.get(assignment.token)
            if entry is None:
                self._gateway.vault.store(
                    self.session_id,
                    assignment.token,
                    assignment.data_class,
                    forms[0],
                    forms,
                    assignment.attributes,
                )
                self._entries[assignment.token] = VaultEntry(
                    value=forms[0],
                    data_class=assignment.data_class,
                    surface_forms=list(forms),
                    attributes=dict(assignment.attributes),
                )
                written.append(assignment.token)
                continue
            appended.append((assignment.token, list(entry.surface_forms)))
            self._gateway.vault.append_surface_forms(self.session_id, assignment.token, forms)
            entry.surface_forms.extend(forms)

    def _rollback(
        self,
        written: list[str],
        appended: list[tuple[str, list[str]]],
        counters: dict[str, int],
    ) -> None:
        self._known_cache = None
        self._gateway.vault.delete_tokens(self.session_id, written)
        for token in written:
            self._entries.pop(token, None)
        for token, forms in appended:
            entry = self._entries[token]
            entry.surface_forms = list(forms)
            self._gateway.vault.store(
                self.session_id, token, entry.data_class, entry.value, forms, entry.attributes
            )
        self._counters = counters


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
