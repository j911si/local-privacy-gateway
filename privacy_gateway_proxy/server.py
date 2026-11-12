"""Starlette application that pseudonymizes requests and restores responses."""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from privacy_gateway.audit import RequestAuditLog
from privacy_gateway.model import LeakageError
from privacy_gateway_proxy import audit_trail
from privacy_gateway_proxy.session_key import is_valid_key, session_key_for
from privacy_gateway_proxy.settings import (
    ProxySettings,
    audit_dir_for,
    is_loopback,
    is_normal_path,
)
from privacy_gateway_proxy.transform import TextRef

TRANSFORMED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
QUERY_NAMES = frozenset({"beta", "limit", "before_id", "after_id"})
QUERY_VALUE_RE = re.compile(r"[A-Za-z0-9_.:-]{0,128}")
CONTENT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_HEADER = "x-pgw-auth"
MAX_BODY_BYTES = 32 * 1024 * 1024
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
REQUEST_DROP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "x-pgw-session",
    AUTH_HEADER,
}
RESPONSE_DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}
UPSTREAM_TIMEOUT = httpx.Timeout(600.0, connect=10.0)
SESSION_CACHE_SIZE = 64
DEBUG_FILE_MODE = 0o600
DEBUG_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")
LOGGED_SEGMENTS = 2
ID_SEGMENT_RE = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|\d+")

_transform: Any
_stream_restorer_factory: Any

try:
    from privacy_gateway_proxy import transform as _transform
except ImportError:
    _transform = None

try:
    from privacy_gateway_proxy.streaming import StreamRestorer as _stream_restorer_factory
except ImportError:
    _stream_restorer_factory = None


def create_app(settings: ProxySettings, gateway: Any, client: httpx.AsyncClient | None = None):
    """Build the proxy application for one gateway and one upstream client."""
    upstream = client if client is not None else httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT)
    sessions: OrderedDict[str, Any] = OrderedDict()
    trail = RequestAuditLog(audit_dir_for(settings))

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def proxy(request: Request) -> Response:
        return await _dispatch(request, settings, gateway, upstream, sessions, trail)

    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/{path:path}", proxy, methods=PROXY_METHODS),
        ]
    )
    app.state.settings = settings
    app.state.gateway = gateway
    app.state.client = upstream
    app.state.sessions = sessions
    app.state.trail = trail
    _redact_access_log()
    return app


class _QueryRedactingFilter(logging.Filter):
    """Cuts the query string off the request line of the uvicorn access log."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], short_path(args[2].partition("?")[0]), *args[3:])
        return True


def short_path(path: str) -> str:
    """The first two segments of a path plus `/…` when more follow; known paths unchanged."""
    segments = path.split("/")
    if len(segments) <= LOGGED_SEGMENTS + 1 or path in TRANSFORMED_PATHS:
        return path
    return "/".join(segments[: LOGGED_SEGMENTS + 1]) + "/…"


def _redact_access_log() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, _QueryRedactingFilter) for item in access.filters):
        access.addFilter(_QueryRedactingFilter())


async def _dispatch(
    request: Request,
    settings: ProxySettings,
    gateway: Any,
    client: httpx.AsyncClient,
    sessions: OrderedDict[str, Any],
    trail: RequestAuditLog,
) -> Response:
    if is_loopback(settings.listen_host) and not _host_allowed(request.headers.get("host", "")):
        return _error("privacy_gateway_forbidden", "host header is not loopback", 403)
    if not _authorized(request, settings):
        return _error("privacy_gateway_unauthorized", "missing or wrong auth token", 401)
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return _error("privacy_gateway_too_large", "request body is too large", 413)
    path = _normal_path(request)
    if path is None:
        return _rejected(
            gateway, request, settings, trail, "-", "request path is not in normal form", 400
        )
    if not _query_allowed(request.url.query):
        return _malformed(gateway, settings, trail, path, "query string is not allowed")
    if not (request.method == "POST" and path in TRANSFORMED_PATHS):
        blocked = _path_findings(request, settings, gateway, sessions)
        if blocked:
            return _malformed(
                gateway, settings, trail, short_path(path),
                f"request path contains sensitive data ({blocked})",
            )
    if request.method in CONTENT_METHODS:
        if request.method == "POST" and path in TRANSFORMED_PATHS:
            if request.headers.get("content-encoding"):
                return _rejected(
                    gateway, request, settings, trail, path,
                    "request body is not a transformable JSON object",
                )
            body = _parse_json(raw)
            if not isinstance(body, dict):
                return _malformed(
                    gateway, settings, trail, path, "request body must be a JSON object"
                )
            problem = _shape_error(body)
            if problem is not None:
                return _malformed(gateway, settings, trail, path, problem)
            return await _transformed(request, body, settings, gateway, client, sessions, trail)
        if path not in settings.passthrough_paths:
            return _rejected(
                gateway, request, settings, trail, path,
                "request method or path is not allowed",
            )
    elif raw:
        return _rejected(
            gateway, request, settings, trail, path, "request must not carry a body"
        )
    return await _passthrough(request, raw, settings, client)


def _path_findings(
    request: Request, settings: ProxySettings, gateway: Any, sessions: OrderedDict[str, Any]
) -> str:
    """Classes found in the decoded path segments by the read-only scan, comma-joined."""
    key = session_key_for(request.headers, None, settings)
    if not is_valid_key(key):
        return ""
    leaves = [
        TextRef(("path", index), segment)
        for index, segment in enumerate(unquote(request.url.path).split("/"))
        if segment and ID_SEGMENT_RE.fullmatch(segment) is None
    ]
    hits = audit_trail.scan(_session_for(gateway, sessions, key), leaves) or []
    return ", ".join(sorted({hit.data_class for hit in hits}))


def _query_allowed(query: str) -> bool:
    """True for no query, or only known parameter names with plain identifier-like values."""
    if not query:
        return True
    for pair in query.split("&"):
        name, _, value = pair.partition("=")
        if name not in QUERY_NAMES or QUERY_VALUE_RE.fullmatch(value) is None:
            return False
    return True


def _shape_error(body: dict) -> str | None:
    check = getattr(_transform, "request_shape_error", None)
    return check(body) if check is not None else None


def _authorized(request: Request, settings: ProxySettings) -> bool:
    if not settings.auth_token:
        return True
    given = request.headers.get(AUTH_HEADER, "").encode("utf-8")
    return hmac.compare_digest(given, settings.auth_token.encode("utf-8"))


def _normal_path(request: Request) -> str | None:
    """The request path when raw and decoded form agree and are normal, else None."""
    raw_path = request.scope.get("raw_path")
    raw = raw_path.decode("latin-1") if raw_path else request.url.path
    path = request.url.path
    return path if raw == path and is_normal_path(path) else None


async def _transformed(
    request: Request,
    body: dict,
    settings: ProxySettings,
    gateway: Any,
    client: httpx.AsyncClient,
    sessions: OrderedDict[str, Any],
    trail: RequestAuditLog,
) -> Response:
    started = time.perf_counter()
    path = request.url.path
    key = session_key_for(request.headers, body, settings)
    if not is_valid_key(key):
        return _error("privacy_gateway_session", "session key has an unusable form", 400)
    session = _session_for(gateway, sessions, key)
    streaming = body.get("stream") is True
    include_system = settings.transform_system
    notice = settings.placeholder_notice
    fields = _field_count(body, include_system)
    recorder = audit_trail.Recorder(session)
    checked = audit_trail.checked_refs(_transform, body, include_system, notice)

    def record(verdict: str, leakage: str, **parts: Any) -> None:
        _record(trail, key, path, streaming, started, verdict, leakage, checked, recorder, **parts)

    try:
        new_body, fields = _transform.pseudonymize_request(
            body,
            recorder,
            include_system=include_system,
            notice=notice,
        )
    except LeakageError as exc:
        _audit(gateway, key, path, fields, session, "failed", streaming, started, include_system)
        unchecked = audit_trail.unchecked_refs(_transform, body, include_system)
        observed = audit_trail.scan(session, audit_trail.unchecked_leaves(unchecked))
        record("blocked", "fail", unchecked=unchecked, observed=observed)
        if settings.debug_originals:
            _debug_dump(settings, f"{key}-FAILED-original", body)
        return _leak_response(exc)

    payload = json.dumps(new_body).encode("utf-8")
    unchecked = audit_trail.unchecked_refs(_transform, new_body, include_system)
    rescan = audit_trail.rescan_body(session, new_body, checked, settings.rescan_budget_s)
    outcome = {
        "unchecked": unchecked, "observed": rescan.hits, "payload": payload, "rescan": rescan
    }
    if rescan.reason == audit_trail.TIMEOUT:
        _audit(gateway, key, path, fields, session, "failed", streaming, started, include_system)
        record("error", "ok", **outcome)
        return _error("privacy_gateway_timeout", "rescan exceeded its time budget", 503)
    if rescan.blocking:
        _audit(gateway, key, path, fields, session, "failed", streaming, started, include_system)
        record("blocked", "ok", **outcome)
        return _leak_response(LeakageError(audit_trail.as_leaks(rescan.blocking)))

    _debug_dump(settings, key, new_body)
    upstream_request = client.build_request(
        "POST",
        _upstream_url(request, settings),
        content=payload,
        headers=_request_headers(request.headers, len(payload), settings),
    )
    try:
        response = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        _audit(
            gateway, key, path, fields, session, "upstream_error", streaming, started,
            include_system,
        )
        record("error", "ok", **outcome)
        return _upstream_error(exc)

    _audit(gateway, key, path, fields, session, "ok", streaming, started, include_system)
    record("ok", "ok", upstream_status=response.status_code, **outcome)
    headers = _response_headers(response.headers)
    if response.status_code >= 400:
        try:
            raw_body = await response.aread()
        finally:
            await response.aclose()
        limits = {
            k: v
            for k, v in response.headers.items()
            if k.lower().startswith("anthropic-ratelimit") or k.lower() == "retry-after"
        }
        logging.getLogger("privacy_gateway_proxy").warning(
            "upstream %s on %s: %s %s",
            response.status_code,
            path,
            raw_body[:400].decode("utf-8", "replace"),
            limits,
        )
        return Response(raw_body, status_code=response.status_code, headers=headers)
    lenient = _LenientSession(session)
    if streaming:
        restorer = _stream_restorer_factory(lenient.restore_text)
        return StreamingResponse(
            _restored_stream(response, restorer),
            status_code=response.status_code,
            headers=headers,
        )
    try:
        raw_body = await response.aread()
    finally:
        await response.aclose()
    data = _parse_json(raw_body)
    if not isinstance(data, dict):
        return Response(raw_body, status_code=response.status_code, headers=headers)
    restored = _transform.restore_response(data, lenient)
    return JSONResponse(restored, status_code=response.status_code, headers=headers)


class _LenientSession:
    """A session whose restore leaves unknown tokens standing instead of failing."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        return self._session.pseudonymize_many(texts)

    def restore_text(self, text: str) -> str:
        return self._session.restore(text, mode="lenient").text


async def _passthrough(
    request: Request, raw: bytes, settings: ProxySettings, client: httpx.AsyncClient
) -> Response:
    upstream_request = client.build_request(
        request.method,
        _upstream_url(request, settings),
        content=raw or None,
        headers=_request_headers(request.headers, len(raw) if raw else None, settings),
    )
    try:
        response = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        return _upstream_error(exc)
    return StreamingResponse(
        _forwarded_stream(response),
        status_code=response.status_code,
        headers=_response_headers(response.headers),
    )


async def _restored_stream(response: httpx.Response, restorer: Any) -> AsyncIterator[bytes]:
    try:
        async for chunk in _raw_chunks(response):
            restored = restorer.feed(chunk)
            if restored:
                yield restored
        tail = restorer.finish()
        if tail:
            yield tail
    finally:
        await response.aclose()


async def _forwarded_stream(response: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in _raw_chunks(response):
            yield chunk
    finally:
        await response.aclose()


USAGE_RE = re.compile(rb'"usage":\s*(\{[^{}]*\})')


def _log_usage(chunk: bytes) -> None:
    if b'"message_start"' not in chunk:
        return
    match = USAGE_RE.search(chunk)
    if match:
        logging.getLogger("privacy_gateway_proxy").info(
            "upstream usage %s", match.group(1).decode("utf-8", "replace")
        )


async def _raw_chunks(response: httpx.Response) -> AsyncIterator[bytes]:
    if response.is_stream_consumed:
        yield await response.aread()
        return
    async for chunk in response.aiter_bytes():
        _log_usage(chunk)
        yield chunk


def _session_for(gateway: Any, sessions: OrderedDict[str, Any], key: str) -> Any:
    session = sessions.pop(key, None)
    if session is None:
        session = gateway.session(key)
    sessions[key] = session
    while len(sessions) > SESSION_CACHE_SIZE:
        sessions.popitem(last=False)
    return session


def _field_count(body: dict, include_system: bool) -> int:
    collect = getattr(_transform, "collect_request_texts", None)
    if collect is None:
        return 0
    return len(collect(body, include_system=include_system))


def _debug_dump(settings: ProxySettings, session_key: str, body: dict) -> None:
    directory = settings.debug_dir
    if directory is None:
        return
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%f")
    name = f"{stamp}-{UNSAFE_NAME_CHARS.sub('_', session_key)}.json"
    descriptor = os.open(directory / name, DEBUG_FILE_FLAGS, DEBUG_FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(body, handle, ensure_ascii=False)


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _upstream_url(request: Request, settings: ProxySettings) -> str:
    url = f"{settings.upstream_base_url.rstrip('/')}{request.url.path}"
    query = request.url.query
    return f"{url}?{query}" if query else url


def _request_headers(
    headers: Mapping[str, str], content_length: int | None, settings: ProxySettings
) -> dict[str, str]:
    dropped = REQUEST_DROP_HEADERS | {settings.header_name.lower()}
    forwarded = {name: value for name, value in headers.items() if name.lower() not in dropped}
    forwarded["accept-encoding"] = "identity"
    if content_length is not None:
        forwarded["content-length"] = str(content_length)
    return forwarded


def _response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in RESPONSE_DROP_HEADERS
    }


def _host_allowed(value: str) -> bool:
    host = value.strip().lower()
    if host.startswith("["):
        host = f"{host.partition(']')[0]}]"
    else:
        host = host.partition(":")[0]
    return is_loopback(host)


def _error(kind: str, message: str, status: int) -> Response:
    return JSONResponse(
        {"type": "error", "error": {"type": kind, "message": message}}, status_code=status
    )


def _rejected(
    gateway: Any,
    request: Request,
    settings: ProxySettings,
    trail: RequestAuditLog,
    path: str,
    message: str,
    status: int = 422,
) -> Response:
    """Refuse a request the proxy must not forward, without an upstream call."""
    started = time.perf_counter()
    _audit(gateway, "-", path, 0, None, "rejected", False, started, settings.transform_system)
    _record(trail, "-", path, False, started, "error", "ok", [], None)
    return _error("privacy_gateway_rejected", message, status)


def _malformed(
    gateway: Any, settings: ProxySettings, trail: RequestAuditLog, path: str, message: str
) -> Response:
    """Refuse a request of unexpected form with an Anthropic-style 400 and a `blocked` audit line."""
    started = time.perf_counter()
    _audit(gateway, "-", path, 0, None, "rejected", False, started, settings.transform_system)
    _record(trail, "-", path, False, started, "blocked", "ok", [], None)
    return _error("invalid_request_error", message, 400)


def _leak_response(exc: LeakageError) -> Response:
    classes = sorted({leak.data_class for leak in exc.leaks if leak.data_class})
    message = (
        f"fail-closed: {len(exc.leaks)} potential leak(s) "
        f"(classes: {', '.join(classes) or 'none'})"
    )
    return _error("privacy_gateway_leak", message, 422)


def _upstream_error(exc: httpx.HTTPError) -> Response:
    return _error(
        "privacy_gateway_upstream", f"upstream request failed: {type(exc).__name__}", 502
    )


def _record(
    trail: RequestAuditLog,
    session_key: str,
    path: str,
    streaming: bool,
    started: float,
    verdict: str,
    leakage: str,
    checked: list[Any],
    recorder: audit_trail.Recorder | None,
    *,
    unchecked: list[Any] | None = None,
    observed: list[Any] | None = None,
    payload: bytes | None = None,
    rescan: audit_trail.Rescan | None = None,
    upstream_status: int | None = None,
) -> None:
    fields = audit_trail.entry(
        trail,
        session_key=session_key,
        path=path,
        streaming=streaming,
        duration_ms=int((time.perf_counter() - started) * 1000),
        verdict=verdict,
        checked=checked,
        findings=recorder.findings if recorder is not None else [],
        unchecked=unchecked or [],
        observed=observed,
        leakage=leakage,
        payload=payload,
        rescan=rescan if rescan is not None else audit_trail.Rescan("skipped"),
        failed_index=recorder.failed_index if recorder is not None else None,
        failed_leaks=recorder.failed_leaks if recorder is not None else None,
        upstream_status=upstream_status,
    )
    trail.write("proxy_request", fields)


def _audit(
    gateway: Any,
    session_key: str,
    path: str,
    fields: int,
    session: Any,
    leakage: str,
    streaming: bool,
    started: float,
    system_transformed: bool,
) -> None:
    event = getattr(getattr(gateway, "audit", None), "proxy_request", None)
    if event is None:
        return
    event(
        session_key=session_key,
        path=path,
        fields=fields,
        tokens=_token_count(session),
        leakage=leakage,
        streaming=streaming,
        duration_ms=int((time.perf_counter() - started) * 1000),
        system_transformed=system_transformed,
    )


def _token_count(session: Any) -> int:
    entries = getattr(session, "entries", None)
    return len(entries()) if entries is not None else 0
