"""Starlette application that pseudonymizes requests and restores responses."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from privacy_gateway.model import LeakageError
from privacy_gateway_proxy.session_key import is_valid_key, session_key_for
from privacy_gateway_proxy.settings import ProxySettings, is_loopback

TRANSFORMED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
MESSAGES_PREFIX = "/v1/messages"
MAX_BODY_BYTES = 32 * 1024 * 1024
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
REQUEST_DROP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
}
RESPONSE_DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}
UPSTREAM_TIMEOUT = httpx.Timeout(600.0, connect=10.0)
SESSION_CACHE_SIZE = 64
DEBUG_FILE_MODE = 0o600
DEBUG_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")

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

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def proxy(request: Request) -> Response:
        return await _dispatch(request, settings, gateway, upstream, sessions)

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
    return app


async def _dispatch(
    request: Request,
    settings: ProxySettings,
    gateway: Any,
    client: httpx.AsyncClient,
    sessions: OrderedDict[str, Any],
) -> Response:
    if is_loopback(settings.listen_host) and not _host_allowed(request.headers.get("host", "")):
        return _error("privacy_gateway_forbidden", "host header is not loopback", 403)
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return _error("privacy_gateway_too_large", "request body is too large", 413)
    if request.method == "POST" and request.url.path.startswith(MESSAGES_PREFIX):
        encoded = bool(request.headers.get("content-encoding"))
        body = None if encoded else _parse_json(raw)
        if not isinstance(body, dict) or request.url.path not in TRANSFORMED_PATHS:
            return _rejected(gateway, request, settings)
        return await _transformed(request, body, settings, gateway, client, sessions)
    return await _passthrough(request, raw, settings, client)


async def _transformed(
    request: Request,
    body: dict,
    settings: ProxySettings,
    gateway: Any,
    client: httpx.AsyncClient,
    sessions: OrderedDict[str, Any],
) -> Response:
    started = time.perf_counter()
    path = request.url.path
    key = session_key_for(request.headers, body, settings)
    if not is_valid_key(key):
        return _error("privacy_gateway_session", "session key has an unusable form", 400)
    session = _session_for(gateway, sessions, key)
    streaming = body.get("stream") is True
    include_system = settings.transform_system
    fields = _field_count(body, include_system)
    try:
        new_body, fields = _transform.pseudonymize_request(
            body,
            session,
            include_system=include_system,
            notice=settings.placeholder_notice,
        )
    except LeakageError as exc:
        _audit(gateway, key, path, fields, session, "failed", streaming, started, include_system)
        if settings.debug_originals:
            _debug_dump(settings, f"{key}-FAILED-original", body)
        return _leak_response(exc)

    _debug_dump(settings, key, new_body)
    payload = json.dumps(new_body).encode("utf-8")
    upstream_request = client.build_request(
        "POST",
        _upstream_url(request, settings),
        content=payload,
        headers=_request_headers(request.headers, len(payload)),
    )
    try:
        response = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        _audit(
            gateway, key, path, fields, session, "upstream_error", streaming, started,
            include_system,
        )
        return _upstream_error(exc)

    _audit(gateway, key, path, fields, session, "ok", streaming, started, include_system)
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
        headers=_request_headers(request.headers, len(raw) if raw else None),
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


def _request_headers(headers: Mapping[str, str], content_length: int | None) -> dict[str, str]:
    forwarded = {
        name: value
        for name, value in headers.items()
        if name.lower() not in REQUEST_DROP_HEADERS
    }
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


# ponytail: kein Auth-Token; ergänzen, wenn mehrere lokale Accounts den Proxy teilen
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


def _rejected(gateway: Any, request: Request, settings: ProxySettings) -> Response:
    """Refuse a `/v1/messages` POST the proxy cannot transform, without an upstream call."""
    _audit(
        gateway, "-", request.url.path, 0, None, "rejected", False,
        time.perf_counter(), settings.transform_system,
    )
    return _error(
        "privacy_gateway_rejected", "request body is not a transformable JSON object", 422
    )


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
