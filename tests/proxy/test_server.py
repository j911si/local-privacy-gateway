import json
import stat
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from privacy_gateway.model import Leak, LeakageError
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
SETTINGS = ProxySettings(upstream_base_url=UPSTREAM)
SECRET = "Frau Müller"
TOKEN = "<PERSON_FEMALE_001>"


class StubSession:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.restore_modes: list[str | None] = []

    def pseudonymize_many(self, texts: list[str]) -> list[str]:
        return [text.replace(SECRET, TOKEN) for text in texts]

    def restore(self, text: str, mode: str | None = None) -> SimpleNamespace:
        self.restore_modes.append(mode)
        return SimpleNamespace(text=self.restore_text(text))

    def restore_text(self, text: str) -> str:
        return text.replace(TOKEN, SECRET)

    def entries(self) -> dict[str, str]:
        return {TOKEN: SECRET}


class StubAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def proxy_request(self, **fields: Any) -> None:
        self.events.append(fields)


class StubGateway:
    def __init__(self) -> None:
        self.audit = StubAudit()
        self.keys: list[str] = []
        self.sessions: list[StubSession] = []

    def session(self, key: str | None = None) -> StubSession:
        self.keys.append(key or "")
        session = StubSession(f"sid-{key}")
        self.sessions.append(session)
        return session


class StubRestorer:
    def __init__(self, restore: Callable[[str], str]) -> None:
        self._restore = restore
        self.chunks: list[bytes] = []

    def feed(self, chunk: bytes) -> bytes:
        self.chunks.append(chunk)
        return self._restore(chunk.decode("utf-8")).encode("utf-8")

    def finish(self) -> bytes:
        return b"event: done\n\n"


def stub_transform(leak: LeakageError | None = None) -> SimpleNamespace:
    notices: list[bool] = []

    def _texts(body: dict, include_system: bool) -> list[str]:
        texts = [str(message["content"]) for message in body["messages"]]
        if include_system and isinstance(body.get("system"), str):
            texts.append(body["system"])
        return texts

    def collect_request_texts(body: dict, *, include_system: bool = True) -> list[str]:
        return _texts(body, include_system)

    def pseudonymize_request(
        body: dict, sess: Any, *, include_system: bool = True, notice: bool = False
    ) -> tuple[dict, int]:
        notices.append(notice)
        if leak is not None:
            raise leak
        texts = _texts(body, include_system)
        replaced = sess.pseudonymize_many(texts)
        new_body = json.loads(json.dumps(body))
        messages = new_body["messages"]
        for message, text in zip(messages, replaced[: len(messages)], strict=True):
            message["content"] = text
        if len(replaced) > len(messages):
            new_body["system"] = replaced[-1]
        return new_body, len(replaced)

    def restore_response(body: dict, sess: Any) -> dict:
        restored = json.loads(json.dumps(body))
        for block in restored["content"]:
            block["text"] = sess.restore_text(block["text"])
        return restored

    return SimpleNamespace(
        collect_request_texts=collect_request_texts,
        pseudonymize_request=pseudonymize_request,
        restore_response=restore_response,
        notices=notices,
    )


def build(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    transform: SimpleNamespace | None = None,
    settings: ProxySettings = SETTINGS,
) -> tuple[httpx.AsyncClient, StubGateway, list[StubRestorer]]:
    restorers: list[StubRestorer] = []

    def factory(restore: Callable[[str], str]) -> StubRestorer:
        restorer = StubRestorer(restore)
        restorers.append(restorer)
        return restorer

    monkeypatch.setattr(server, "_transform", transform or stub_transform())
    monkeypatch.setattr(server, "_stream_restorer_factory", factory)
    gateway = StubGateway()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(settings, gateway, client=upstream)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    )
    return client, gateway, restorers


def request_body(stream: bool = False) -> dict:
    body = {
        "model": "claude-x",
        "max_tokens": 16,
        "metadata": {"user_id": "user_a_session_0b1c2d3e-1111-2222-3333-444444444444"},
        "messages": [{"role": "user", "content": f"Hallo {SECRET}"}],
    }
    if stream:
        body["stream"] = True
    return body


@pytest.mark.asyncio
async def test_health() -> None:
    app = server.create_app(SETTINGS, StubGateway(), client=httpx.AsyncClient())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_non_streaming_request_is_pseudonymized_and_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        assert SECRET not in request.content.decode("utf-8")
        assert payload["messages"][0]["content"] == f"Hallo {TOKEN}"
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": f"Guten Tag {TOKEN}"}]}
        )

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body())

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == f"Guten Tag {SECRET}"
    assert str(seen[0].url) == f"{UPSTREAM}/v1/messages"
    assert gateway.keys == ["0b1c2d3e-1111-2222-3333-444444444444"]
    event = gateway.audit.events[0]
    assert event["path"] == "/v1/messages"
    assert event["fields"] == 1
    assert event["leakage"] == "ok"
    assert event["streaming"] is False
    assert event["session_key"] == "0b1c2d3e-1111-2222-3333-444444444444"
    assert event["system_transformed"] is True


@pytest.mark.asyncio
async def test_system_prompt_is_forwarded_untouched_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": []})

    settings = ProxySettings(upstream_base_url=UPSTREAM, transform_system=False)
    client, gateway, _ = build(monkeypatch, handler, settings=settings)
    body = request_body()
    body["system"] = f"Du bist Claude. {SECRET}"
    async with client:
        response = await client.post("/v1/messages", json=body)

    assert response.status_code == 200
    payload = json.loads(seen[0].content)
    assert payload["system"] == f"Du bist Claude. {SECRET}"
    assert payload["messages"][0]["content"] == f"Hallo {TOKEN}"
    event = gateway.audit.events[0]
    assert event["fields"] == 1
    assert event["system_transformed"] is False


@pytest.mark.asyncio
async def test_system_prompt_is_transformed_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": []})

    client, gateway, _ = build(monkeypatch, handler)
    body = request_body()
    body["system"] = f"Du bist Claude. {SECRET}"
    async with client:
        await client.post("/v1/messages", json=body)

    payload = json.loads(seen[0].content)
    assert payload["system"] == f"Du bist Claude. {TOKEN}"
    assert gateway.audit.events[0]["fields"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_placeholder_notice_setting_reaches_the_transform(
    monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    transform = stub_transform()
    settings = ProxySettings(upstream_base_url=UPSTREAM, placeholder_notice=enabled)
    client, _, _ = build(monkeypatch, handler, transform=transform, settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    assert transform.notices == [enabled]


@pytest.mark.asyncio
async def test_streaming_response_is_piped_through_the_restorer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield f"event: content_block_delta\ndata: {TOKEN}\n\n".encode()
        yield b"event: message_stop\ndata: {}\n\n"

    def handler(request: httpx.Request) -> httpx.Response:
        assert SECRET not in request.content.decode("utf-8")
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=chunks()
        )

    client, gateway, restorers = build(monkeypatch, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(stream=True))

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/event-stream"
    assert response.text == (
        f"event: content_block_delta\ndata: {SECRET}\n\n"
        "event: message_stop\ndata: {}\n\n"
        "event: done\n\n"
    )
    assert len(restorers[0].chunks) == 2
    assert gateway.audit.events[0]["streaming"] is True


@pytest.mark.asyncio
async def test_leak_returns_422_and_never_calls_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return httpx.Response(200, json={})

    leak = LeakageError([Leak("value", "IBAN", 0, 22)])
    client, gateway, _ = build(monkeypatch, handler, transform=stub_transform(leak))
    async with client:
        response = await client.post("/v1/messages", json=request_body())

    assert response.status_code == 422
    body = response.json()
    assert body["type"] == "error"
    assert body["error"]["type"] == "privacy_gateway_leak"
    assert "IBAN" in body["error"]["message"]
    assert called == []
    event = gateway.audit.events[0]
    assert event["leakage"] == "failed"
    assert event["fields"] == 1
    assert event["tokens"] == 1


@pytest.mark.asyncio
async def test_headers_are_filtered_for_the_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": []})

    client, _, _ = build(monkeypatch, handler)
    async with client:
        await client.post(
            "/v1/messages",
            json=request_body(),
            headers={
                "x-api-key": "sk-test",
                "authorization": "Bearer abc",
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
                "user-agent": "claude-cli/2.0.0",
                "x-unknown-header": "keep-me",
                "accept-encoding": "gzip",
            },
        )

    headers = seen[0].headers
    assert headers["x-api-key"] == "sk-test"
    assert headers["authorization"] == "Bearer abc"
    assert headers["anthropic-version"] == "2023-06-01"
    assert headers["anthropic-beta"] == "claude-code-20250219,oauth-2025-04-20"
    assert headers["user-agent"] == "claude-cli/2.0.0"
    assert headers["x-unknown-header"] == "keep-me"
    assert headers["accept-encoding"] == "identity"
    assert headers["host"] == "upstream.test"
    assert headers["content-length"] == str(len(seen[0].content))


@pytest.mark.asyncio
async def test_other_paths_are_proxied_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            201, headers={"x-request-id": "req-1"}, content=b'{"data":["m"]}'
        )

    transform = SimpleNamespace(
        pseudonymize_request=_unexpected, restore_response=_unexpected
    )
    client, gateway, _ = build(monkeypatch, handler, transform=transform)
    async with client:
        response = await client.get("/v1/models?limit=2")

    assert response.status_code == 201
    assert response.content == b'{"data":["m"]}'
    assert response.headers["x-request-id"] == "req-1"
    assert str(seen[0].url) == f"{UPSTREAM}/v1/models?limit=2"
    assert seen[0].method == "GET"
    assert gateway.audit.events == []


@pytest.mark.asyncio
async def test_upstream_error_returns_502(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client, _, _ = build(monkeypatch, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body())

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "privacy_gateway_upstream"


@pytest.mark.asyncio
async def test_non_json_upstream_body_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"<html>boom</html>")

    client, _, _ = build(monkeypatch, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body())

    assert response.status_code == 500
    assert response.content == b"<html>boom</html>"


@pytest.mark.asyncio
async def test_audit_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    client, gateway, _ = build(monkeypatch, handler)
    gateway.audit = SimpleNamespace()
    async with client:
        response = await client.post("/v1/messages", json=request_body())

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_one_session_instance_serves_a_whole_conversation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        await client.post("/v1/messages", json=request_body())
        await client.post("/v1/messages", json=request_body())
        other = request_body()
        other["metadata"] = {"user_id": "user_a_session_99999999-1111-2222-3333-444444444444"}
        await client.post("/v1/messages", json=other)

    assert gateway.keys == [
        "0b1c2d3e-1111-2222-3333-444444444444",
        "99999999-1111-2222-3333-444444444444",
    ]
    assert len(gateway.sessions) == 2


@pytest.mark.asyncio
async def test_a_leaking_request_keeps_the_cached_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    leak = LeakageError([Leak("value", "IBAN", 0, 22)])
    client, gateway, _ = build(monkeypatch, handler, transform=stub_transform(leak))
    async with client:
        await client.post("/v1/messages", json=request_body())
        await client.post("/v1/messages", json=request_body())

    assert len(gateway.sessions) == 1


@pytest.mark.asyncio
async def test_the_session_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    client, gateway, _ = build(monkeypatch, handler)
    first = request_body()
    async with client:
        await client.post("/v1/messages", json=first)
        for index in range(server.SESSION_CACHE_SIZE):
            body = request_body()
            body["metadata"] = {
                "user_id": f"user_a_session_{index:08d}-1111-2222-3333-444444444444"
            }
            await client.post("/v1/messages", json=body)
        await client.post("/v1/messages", json=first)

    assert gateway.keys.count("0b1c2d3e-1111-2222-3333-444444444444") == 2


@pytest.mark.asyncio
async def test_query_string_is_transformed_and_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        assert payload["messages"][0]["content"] == f"Hallo {TOKEN}"
        return httpx.Response(200, json={"content": [{"type": "text", "text": TOKEN}]})

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        response = await client.post("/v1/messages?beta=true", json=request_body())

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == SECRET
    assert str(seen[0].url) == f"{UPSTREAM}/v1/messages?beta=true"
    assert gateway.audit.events[0]["path"] == "/v1/messages"


@pytest.mark.asyncio
async def test_debug_dir_receives_the_transformed_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    settings = ProxySettings(upstream_base_url=UPSTREAM, debug_dir=tmp_path / "dumps")
    client, _, _ = build(monkeypatch, handler, settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    dumps = sorted((tmp_path / "dumps").glob("*.json"))
    assert len(dumps) == 1
    assert dumps[0].name.endswith("-0b1c2d3e-1111-2222-3333-444444444444.json")
    written = dumps[0].read_text(encoding="utf-8")
    assert json.loads(written)["messages"][0]["content"] == f"Hallo {TOKEN}"
    assert SECRET not in written
    assert stat.S_IMODE(dumps[0].stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_debug_dir_gets_only_the_failed_original_on_a_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    leak = LeakageError([Leak("value", "IBAN", 0, 22)])
    settings = ProxySettings(
        upstream_base_url=UPSTREAM, debug_dir=tmp_path, debug_originals=True
    )
    client, _, _ = build(monkeypatch, handler, transform=stub_transform(leak), settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    dumps = list(tmp_path.glob("*.json"))
    assert len(dumps) == 1
    assert dumps[0].name.endswith("-FAILED-original.json")
    assert json.loads(dumps[0].read_text(encoding="utf-8")) == request_body()


def _unexpected(*args: Any, **kwargs: Any) -> None:
    raise AssertionError("transform must not be used on passthrough paths")


def _recording_handler(calls: list[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"content": []})

    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "content", "headers"),
    [
        ("/v1/messages", b"{not json", {"content-type": "application/json"}),
        ("/v1/messages", b'["a"]', {"content-type": "application/json"}),
        ("/v1/messages", b"", {"content-type": "application/json"}),
        (
            "/v1/messages",
            b'{"messages":[]}',
            {"content-type": "application/json", "content-encoding": "gzip"},
        ),
        ("/v1/messages/", b'{"messages":[]}', {"content-type": "application/json"}),
        ("/v1/messages/batches", b'{"requests":[]}', {"content-type": "application/json"}),
    ],
)
async def test_unparsable_message_posts_are_rejected_without_upstream(
    monkeypatch: pytest.MonkeyPatch, path: str, content: bytes, headers: dict[str, str]
) -> None:
    called: list[httpx.Request] = []
    client, gateway, _ = build(monkeypatch, _recording_handler(called))
    async with client:
        response = await client.post(path, content=content, headers=headers)

    assert response.status_code == 422
    assert response.json()["error"]["type"] == "privacy_gateway_rejected"
    assert called == []
    event = gateway.audit.events[0]
    assert event["leakage"] == "rejected"
    assert event["path"] == path
    assert event["fields"] == 0


@pytest.mark.asyncio
async def test_a_get_on_a_messages_path_still_passes_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[httpx.Request] = []
    client, _, _ = build(monkeypatch, _recording_handler(called))
    async with client:
        response = await client.get("/v1/messages/batches/batch_1")

    assert response.status_code == 200
    assert len(called) == 1


@pytest.mark.asyncio
async def test_a_foreign_host_header_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[httpx.Request] = []
    client, _, _ = build(monkeypatch, _recording_handler(called))
    async with client:
        response = await client.post(
            "/v1/messages", json=request_body(), headers={"host": "attacker.test"}
        )

    assert response.status_code == 403
    assert response.json()["error"]["type"] == "privacy_gateway_forbidden"
    assert called == []


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8787", "localhost:8787", "[::1]:8787"])
async def test_loopback_host_headers_are_accepted(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    client, _, _ = build(monkeypatch, _recording_handler([]))
    async with client:
        response = await client.post(
            "/v1/messages", json=request_body(), headers={"host": host}
        )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_no_host_check_when_bound_to_a_public_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = ProxySettings(upstream_base_url=UPSTREAM, listen_host="0.0.0.0")
    client, _, _ = build(monkeypatch, _recording_handler([]), settings=settings)
    async with client:
        response = await client.post(
            "/v1/messages", json=request_body(), headers={"host": "somewhere.test"}
        )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_an_unusable_session_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[httpx.Request] = []
    settings = ProxySettings(upstream_base_url=UPSTREAM, session_strategy="header")
    client, _, _ = build(monkeypatch, _recording_handler(called), settings=settings)
    async with client:
        response = await client.post(
            "/v1/messages", json=request_body(), headers={"x-pgw-session": "../../etc"}
        )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "privacy_gateway_session"
    assert called == []


@pytest.mark.asyncio
async def test_an_oversized_body_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[httpx.Request] = []
    client, _, _ = build(monkeypatch, _recording_handler(called))
    body = request_body()
    body["messages"][0]["content"] = "x" * (server.MAX_BODY_BYTES + 1)
    async with client:
        response = await client.post("/v1/messages", json=body)

    assert response.status_code == 413
    assert called == []


@pytest.mark.asyncio
async def test_an_upstream_error_is_audited_as_such(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        await client.post("/v1/messages", json=request_body())

    assert gateway.audit.events[0]["leakage"] == "upstream_error"


@pytest.mark.asyncio
async def test_the_response_is_restored_leniently(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": [{"type": "text", "text": TOKEN}]})

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        await client.post("/v1/messages", json=request_body())

    assert gateway.sessions[0].restore_modes == ["lenient"]


@pytest.mark.asyncio
async def test_the_stream_is_restored_leniently(monkeypatch: pytest.MonkeyPatch) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield f"data: {TOKEN}\n\n".encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=chunks()
        )

    client, gateway, _ = build(monkeypatch, handler)
    async with client:
        await client.post("/v1/messages", json=request_body(stream=True))

    assert gateway.sessions[0].restore_modes == ["lenient"]


@pytest.mark.asyncio
async def test_the_debug_directory_is_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    directory = tmp_path / "dumps"
    settings = ProxySettings(upstream_base_url=UPSTREAM, debug_dir=directory)
    client, _, _ = build(monkeypatch, handler, settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.asyncio
async def test_no_original_dump_without_the_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    leak = LeakageError([Leak("value", "IBAN", 0, 22)])
    settings = ProxySettings(upstream_base_url=UPSTREAM, debug_dir=tmp_path)
    client, _, _ = build(monkeypatch, handler, transform=stub_transform(leak), settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    assert list(tmp_path.glob("*.json")) == []


@pytest.mark.asyncio
async def test_the_original_dump_needs_the_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []})

    leak = LeakageError([Leak("value", "IBAN", 0, 22)])
    settings = ProxySettings(
        upstream_base_url=UPSTREAM, debug_dir=tmp_path, debug_originals=True
    )
    client, _, _ = build(monkeypatch, handler, transform=stub_transform(leak), settings=settings)
    async with client:
        await client.post("/v1/messages", json=request_body())

    dumps = list(tmp_path.glob("*.json"))
    assert len(dumps) == 1
    assert dumps[0].name.endswith("-FAILED-original.json")
    assert stat.S_IMODE(dumps[0].stat().st_mode) == 0o600
