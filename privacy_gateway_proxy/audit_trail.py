"""Builds the value-free `proxy_request` v2 entry of the daily audit log."""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from privacy_gateway.audit import NO_HMAC_CLASSES, RequestAuditLog
from privacy_gateway.model import FieldFinding, Leak, LeakageError
from privacy_gateway_proxy.transform import (
    Path,
    TextRef,
    UncheckedRef,
    collect_keyed,
    collect_strings,
    format_path,
)

SESSION_HASH_CHARS = 12
REDACT_POLICY = "redact"
BASE64_TYPE = "base64"
TIMEOUT = "timeout"
OK = "ok"
OK_WITH_UNCHECKED_FINDINGS = "ok_with_unchecked_findings"


@dataclass(frozen=True)
class Hit:
    """One rescan finding at a string leaf of the body."""

    path: Path
    data_class: str
    start: int
    end: int


class Recorder:
    """Wraps a session and keeps the findings of every text in call order."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self.findings: list[list[FieldFinding]] = []
        self.failed_index: int | None = None
        self.failed_leaks: list[Leak] = []

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        """Pseudonymize like the session, remembering each text's findings."""
        detailed = getattr(self._session, "pseudonymize_report_many", None)
        if detailed is None:
            return self._session.pseudonymize_many(texts)
        try:
            results = detailed(texts)
        except LeakageError as exc:
            self.failed_index, self.failed_leaks = exc.text_index, list(exc.leaks)
            raise
        self.findings = [findings for _, findings in results]
        return [text for text, _ in results]

    def restore_text(self, text: str) -> str:
        """Restore like the session."""
        return self._session.restore_text(text)


@dataclass
class Rescan:
    """Outcome of scanning every string about to be sent."""

    status: str
    hits: list[Hit] = field(default_factory=list)
    blocking: list[Hit] = field(default_factory=list)
    reason: str | None = None


def rescan_body(
    session: Any, sent: dict, checked: list[TextRef], budget_s: float | None = None
) -> Rescan:
    """Scan every string of the sent body; hits in a checked field block the request.

    Past `budget_s` seconds the scan stops after the current string with reason `timeout`.
    """
    deadline = None if budget_s is None else time.perf_counter() + budget_s
    hits = scan(session, scannable_strings(sent), deadline)
    if hits is None:
        return Rescan("skipped")
    if deadline is not None and time.perf_counter() > deadline:
        return Rescan("skipped", hits, reason=TIMEOUT)
    checked_paths = {ref.path for ref in checked}
    blocking = [hit for hit in hits if hit.path in checked_paths]
    return Rescan("findings" if hits else "clean", hits, blocking)


def as_leaks(hits: list[Hit]) -> list[Leak]:
    """Rescan hits as value-free leaks for the fail-closed response."""
    return [Leak("rescan", hit.data_class, hit.start, hit.end) for hit in hits]


def checked_refs(transform: Any, body: dict, include_system: bool, notice: bool) -> list[TextRef]:
    """The checked fields of the sent body, or none when the transform cannot list them."""
    refs = getattr(transform, "request_refs", None)
    return refs(body, include_system=include_system, notice=notice) if refs else []


def unchecked_refs(transform: Any, body: dict, include_system: bool) -> list[UncheckedRef]:
    """The unchecked fields, or none when the transform cannot list them."""
    refs = getattr(transform, "collect_unchecked", None)
    return refs(body, include_system=include_system) if refs else []


def entry(
    log: RequestAuditLog,
    *,
    session_key: str,
    path: str,
    streaming: bool,
    duration_ms: int,
    verdict: str,
    checked: list[TextRef],
    findings: list[list[FieldFinding]],
    unchecked: list[UncheckedRef],
    observed: list[Hit] | None,
    leakage: str,
    payload: bytes | None,
    rescan: Rescan,
    failed_index: int | None = None,
    failed_leaks: list[Leak] | None = None,
) -> dict[str, object]:
    """The `proxy_request` v2 fields (without `v`, `event`, `ts`); never carries a value."""
    fields: list[dict[str, object]] = []
    for index, ref in enumerate(checked):
        field_findings = findings[index] if index < len(findings) else []
        item: dict[str, object] = {
            "path": format_path(ref.path),
            "status": "checked",
            "chars": len(ref.text),
            "findings": [_finding(log, ref.text, found) for found in field_findings],
        }
        if index == failed_index and failed_leaks:
            item["leaks"] = [
                {"kind": leak.kind, "cls": leak.data_class, "start": leak.start, "end": leak.end}
                for leak in failed_leaks
            ]
        fields.append(item)
    for ref in unchecked:
        fields.append(_unchecked(ref, observed or []))
    if verdict == OK and any(item["observed"] for item in fields if item["status"] == "unchecked"):
        verdict = OK_WITH_UNCHECKED_FINDINGS
    return {
        "request_id": str(uuid.uuid4()),
        "session": hashlib.sha256(session_key.encode("utf-8")).hexdigest()[:SESSION_HASH_CHARS],
        "path": path,
        "streaming": streaming,
        "duration_ms": duration_ms,
        "verdict": verdict,
        "coverage": {"checked_fields": len(checked), "unchecked_fields": len(unchecked)},
        "fields": fields,
        "outgoing": {
            "sha256": hashlib.sha256(payload).hexdigest() if payload is not None else None,
            "bytes": len(payload) if payload is not None else 0,
            "leakage": leakage,
            "rescan": {
                "status": rescan.status,
                **({"reason": rescan.reason} if rescan.reason is not None else {}),
                "findings": [
                    {
                        "path": format_path(hit.path),
                        "cls": hit.data_class,
                        "start": hit.start,
                        "end": hit.end,
                    }
                    for hit in rescan.hits
                ],
            },
        },
    }


def unchecked_leaves(unchecked: list[UncheckedRef]) -> list[TextRef]:
    """Every scannable string leaf of the unchecked fields, with full paths."""
    leaves: list[TextRef] = []
    for ref in unchecked:
        leaves.extend(scannable_strings(ref.value, ref.path))
    return leaves


def scannable_strings(value: Any, path: Path = ()) -> list[TextRef]:
    """String leaves except the `data` of a base64 source, which detection cannot scan fast.

    The input of a `tool_use` block is scanned with its keys, addressed by position.
    """
    if isinstance(value, dict):
        leaves: list[TextRef] = []
        for key, item in value.items():
            if key == "data" and value.get("type") == BASE64_TYPE:
                continue
            if key == "input" and value.get("type") == "tool_use":
                leaves.extend(collect_keyed(item, (*path, key)))
                continue
            leaves.extend(scannable_strings(item, (*path, key)))
        return leaves
    if isinstance(value, list):
        return [
            leaf
            for index, item in enumerate(value)
            for leaf in scannable_strings(item, (*path, index))
        ]
    return collect_strings(value, path)


def scan(
    session: Any, leaves: list[TextRef], deadline: float | None = None
) -> list[Hit] | None:
    """Scan each leaf with the session's full detection; None when it cannot scan."""
    rescan = getattr(session, "rescan", None)
    if rescan is None:
        return None
    hits: list[Hit] = []
    for leaf in leaves:
        if deadline is not None and time.perf_counter() > deadline:
            break
        for leak in rescan(leaf.text):
            hits.append(Hit(leaf.path, leak.data_class, leak.start, leak.end))
    return hits


def _finding(log: RequestAuditLog, text: str, item: FieldFinding) -> dict[str, object]:
    record: dict[str, object] = {"cls": item.data_class, "start": item.start, "end": item.end}
    if item.token is not None:
        record["token"] = item.token
    record["policy"] = item.policy
    record["confidence"] = round(item.confidence, 4)
    record["stage"] = item.stage
    if item.policy != REDACT_POLICY and item.data_class not in NO_HMAC_CLASSES:
        record["hmac"] = log.value_hmac(text[item.start : item.end])
    return record


def _unchecked(ref: UncheckedRef, observed: list[Hit]) -> dict[str, object]:
    width = len(ref.path)
    counts = Counter(hit.data_class for hit in observed if hit.path[:width] == ref.path)
    return {
        "path": format_path(ref.path),
        "status": "unchecked",
        "reason": ref.reason,
        "chars": sum(len(leaf.text) for leaf in collect_strings(ref.value)),
        "observed": [{"cls": cls, "count": count} for cls, count in sorted(counts.items())],
    }
