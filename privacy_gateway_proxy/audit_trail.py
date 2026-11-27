"""Builds the value-free `proxy_request` v2 entry of the daily audit log."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
import uuid
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any

from privacy_gateway.model import FieldFinding, Leak, LeakageError
from privacy_gateway_proxy.session_key import is_claude_code_user_id
from privacy_gateway_proxy.transform import (
    KEY_OF,
    KEY_SUFFIX_RE,
    SCHEMA_KEYS,
    KeyAt,
    Path,
    TextRef,
    UncheckedRef,
    collect_keyed,
    collect_strings,
    format_path,
)

AUDIT_ID_BYTES = 6
AUDIT_ID_CACHE_SIZE = 4096
BASE64_TYPE = "base64"
BASE64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
ATTACHMENT_MEDIA_TYPES = {
    "image": frozenset({"image/jpeg", "image/png", "image/gif", "image/webp"}),
    "document": frozenset({"application/pdf"}),
}
TIMEOUT = "timeout"
OK = "ok"
OK_WITH_UNCHECKED_FINDINGS = "ok_with_unchecked_findings"
UNCHECKED_BLOCKING_CLASSES = frozenset(
    {
        "API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "STRIPE_SECRET_KEY", "API_SECRET",
        "CLIENT_SECRET", "PASSWORD", "PIN", "TAN", "OTP", "ACCESS_TOKEN", "REFRESH_TOKEN", "JWT",
        "OAUTH_CODE", "SESSION_ID", "SESSION_COOKIE", "AUTH_COOKIE", "CSRF_TOKEN", "PRIVATE_KEY",
        "SSH_PRIVATE_KEY", "TLS_PRIVATE_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AZURE_SECRET",
        "GCP_CREDENTIAL", "KUBERNETES_SECRET", "GITHUB_TOKEN", "GITLAB_TOKEN",
        "PERSONAL_ACCESS_TOKEN", "DATABASE_CONNECTION_STRING", "SIGNED_URL", "SAS_TOKEN",
        "CUSTOM_HEADER", "HEADER_VALUE", "COOKIE", "COOKIE_VALUE",
        "PERSON_FIRST_NAME", "PERSON_LAST_NAME", "PERSON_FULL_NAME", "PERSON_ALIAS",
        "PERSON_USERNAME", "CARDHOLDER",
        "EMAIL", "PHONE", "MOBILE_PHONE", "PHONE_INTERNATIONAL", "FAX",
        "IBAN", "CREDIT_CARD", "DEBIT_CARD", "CVV", "BANK_ACCOUNT",
        "TAX_ID", "SOCIAL_SECURITY_ID", "PASSPORT_ID", "NATIONAL_ID", "DATE_OF_BIRTH",
    }
)
BILLING_LINE_RE = re.compile(
    r"x-anthropic-billing-header: cc_version=[0-9][A-Za-z0-9.]{0,31}; "
    r"cc_entrypoint=[a-z0-9_-]{1,32};"
)


_audit_ids: OrderedDict[str, str] = OrderedDict()


def audit_id(session_key: str) -> str:
    """A random 12-hex-digit id per session key, held only in this process's memory.

    It is drawn by `secrets` and never derived from the key, which restores a session
    through the proxy and so must not reach any log. A restart or an evicted key gets a new id.
    """
    value = _audit_ids.pop(session_key, None) or secrets.token_hex(AUDIT_ID_BYTES)
    _audit_ids[session_key] = value
    while len(_audit_ids) > AUDIT_ID_CACHE_SIZE:
        _audit_ids.popitem(last=False)
    return value


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


def unchecked_blocking(hits: list[Hit], body: dict, include_system: bool) -> list[Hit]:
    """Hits of a sensitive class outside a known client value; they block the request."""
    return [
        hit
        for hit in hits
        if hit.data_class in UNCHECKED_BLOCKING_CLASSES
        and not _known_client_value(body, hit.path, include_system)
    ]


def _known_client_value(body: dict, path: Path, include_system: bool) -> bool:
    """True for the exact Claude Code `metadata.user_id` and billing line in `system[0]`."""
    if path == ("metadata", "user_id"):
        metadata = body.get("metadata")
        return isinstance(metadata, dict) and is_claude_code_user_id(metadata.get("user_id"))
    if path == ("system", 0, "text") and not include_system:
        system = body.get("system")
        block = system[0] if isinstance(system, list) and system else None
        return (
            isinstance(block, dict)
            and set(block) == {"type", "text"}
            and block["type"] == "text"
            and isinstance(block["text"], str)
            and BILLING_LINE_RE.fullmatch(block["text"]) is not None
        )
    return False


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
    upstream_status: int | None = None,
) -> dict[str, object]:
    """The `proxy_request` v2 fields (without `v`, `event`, `ts`); never carries a value."""
    fields: list[dict[str, object]] = []
    clean_keys = 0
    for index, ref in enumerate(checked):
        field_findings = findings[index] if index < len(findings) else []
        if isinstance(ref.path[-1], KeyAt) and not field_findings and index != failed_index:
            clean_keys += 1
            continue
        item: dict[str, object] = {
            "path": format_path(ref.path),
            "status": "checked",
            "chars": len(ref.text),
            "findings": [_finding(found) for found in field_findings],
        }
        if index == failed_index and failed_leaks:
            item["leaks"] = [
                {"kind": leak.kind, "cls": leak.data_class, "start": leak.start, "end": leak.end}
                for leak in failed_leaks
            ]
        fields.append(item)
    counts = _counts_by_prefix(observed or [])
    for ref in unchecked:
        fields.append(_unchecked(ref, counts))
    if verdict == OK and any(item["observed"] for item in fields if item["status"] == "unchecked"):
        verdict = OK_WITH_UNCHECKED_FINDINGS
    return {
        "request_id": str(uuid.uuid4()),
        "session": audit_id(session_key),
        "path": path,
        "streaming": streaming,
        "duration_ms": duration_ms,
        "verdict": verdict,
        "coverage": {
            "checked_fields": len(checked) - clean_keys,
            "checked_keys": clean_keys,
            "unchecked_fields": len(unchecked),
        },
        "fields": fields,
        "outgoing": {
            "sha256": hashlib.sha256(payload).hexdigest() if payload is not None else None,
            "bytes": len(payload) if payload is not None else 0,
            "leakage": leakage,
            "upstream_status": upstream_status,
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
    """String leaves except the `data` of an attachment source, which detection cannot scan fast.

    Only the base64 `source` of an `image` or `document` block in a message (or in a
    `tool_result` of one) with an allowed `media_type` and well-formed base64 is skipped;
    any other `data` is scanned. The input of a `tool_use` block is scanned with its keys,
    addressed by position; elsewhere every key outside `SCHEMA_KEYS` is scanned as well.
    """
    if isinstance(value, dict):
        leaves: list[TextRef] = []
        for key, item in value.items():
            if key and key not in SCHEMA_KEYS:
                leaves.append(TextRef((*path, key, KEY_OF), key))
            if key == "source" and _attachment_source(value, path):
                data_path = (*path, key, "data")
                leaves.extend(
                    leaf for leaf in scannable_strings(item, (*path, key)) if leaf.path != data_path
                )
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


def _attachment_source(block: dict, path: Path) -> bool:
    """True for a message block of an attachment type whose source is valid base64."""
    block_type = block.get("type")
    media_types = ATTACHMENT_MEDIA_TYPES.get(block_type) if isinstance(block_type, str) else None
    source = block.get("source")
    if media_types is None or not _block_position(path) or not isinstance(source, dict):
        return False
    media_type, data = source.get("media_type"), source.get("data")
    return (
        source.get("type") == BASE64_TYPE
        and isinstance(media_type, str)
        and media_type in media_types
        and isinstance(data, str)
        and len(data) % 4 == 0
        and BASE64_RE.fullmatch(data) is not None
    )


def _block_position(path: Path) -> bool:
    """True for `messages[i].content[j]` and `messages[i].content[j].content[k]`."""
    if len(path) not in (4, 6) or path[0] != "messages" or not isinstance(path[1], int):
        return False
    rest = path[2:]
    return all(
        part == "content" if index % 2 == 0 else isinstance(part, int)
        for index, part in enumerate(rest)
    )


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
        for leak in rescan(_scanned_text(leaf)):
            hits.append(Hit(leaf.path, leak.data_class, leak.start, leak.end))
    return hits


MAX_SUFFIX_DIGITS = 3


def _scanned_text(leaf: TextRef) -> str:
    """The leaf text, without the `#n` suffix the proxy itself added to a colliding key."""
    match = KEY_SUFFIX_RE.fullmatch(leaf.text) if isinstance(leaf.path[-1], KeyAt) else None
    if match is None or len(match.group("number")) > MAX_SUFFIX_DIGITS:
        return leaf.text
    return match.group("base")


def _finding(item: FieldFinding) -> dict[str, object]:
    record: dict[str, object] = {"cls": item.data_class, "start": item.start, "end": item.end}
    if item.token is not None:
        record["token"] = item.token
    record["policy"] = item.policy
    record["confidence"] = round(item.confidence, 4)
    record["stage"] = item.stage
    return record


def _counts_by_prefix(observed: list[Hit]) -> dict[tuple, Counter[str]]:
    """Per path prefix, how often each class was observed at or below it."""
    counts: dict[tuple, Counter[str]] = {}
    for hit in observed:
        for width in range(len(hit.path) + 1):
            counts.setdefault(hit.path[:width], Counter())[hit.data_class] += 1
    return counts


def _unchecked(ref: UncheckedRef, by_prefix: dict[tuple, Counter[str]]) -> dict[str, object]:
    counts = by_prefix.get(tuple(ref.path), Counter())
    return {
        "path": format_path(ref.path),
        "status": "unchecked",
        "reason": ref.reason,
        "chars": sum(len(leaf.text) for leaf in collect_strings(ref.value)),
        "observed": [{"cls": cls, "count": count} for cls, count in sorted(counts.items())],
    }
