"""Path normalization, the allowlist for requests with content, the auth token, header filter."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
TOKEN = "tok-3f9c1d7a5b2e4c68-canary"
CONVERSATION = "0b1c2d3e-1111-2222-3333-444444444444"
MESSAGE = {
    "model": "claude-x",
    "max_tokens": 16,
    "metadata": {"user_id": f"user_a_account_b_session_{CONVERSATION}"},
    "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
}
MESSAGE_BYTES = json.dumps(MESSAGE).encode()


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


class Proxy:
    """The app under test plus the upstream requests it produced."""

    def __init__(self, gateway: Gateway, audit_dir: Path, **overrides: Any) -> None:
        self.seen: list[httpx.Request] = []
        self.reply: Callable[[httpx.Request], httpx.Response] | None = None
        self.audit_dir = audit_dir
        settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir, **overrides)
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(self._handler))
        self.app = server.create_app(settings, gateway, client=upstream)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if self.reply is not None:
            return self.reply(request)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    async def call(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        query: str = "",
    ) -> tuple[int, bytes]:
        """Drive the ASGI app with an exact raw path, which httpx would normalize."""
        pairs = {"host": "127.0.0.1:8787", "content-type": "application/json"}
        pairs.update(headers or {})
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": unquote(raw_path),
            "raw_path": raw_path.encode("ascii"),
            "root_path": "",
            "query_string": query.encode("ascii"),
            "headers": [(k.encode(), v.encode()) for k, v in pairs.items()],
            "server": ("127.0.0.1", 8787),
            "client": ("127.0.0.1", 50000),
        }
        sent: list[dict] = []

        delivered: list[bool] = []

        async def receive() -> dict:
            if delivered:
                await asyncio.Event().wait()
            delivered.append(True)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict) -> None:
            sent.append(message)

        await self.app(scope, receive, send)
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, data

    def log_text(self) -> str:
        return "".join(p.read_text(encoding="utf-8") for p in self.audit_dir.glob("audit-*.jsonl"))

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in self.log_text().splitlines()]


@pytest.fixture
def make_proxy(gateway: Gateway, tmp_path: Path) -> Callable[..., Proxy]:
    def factory(**overrides: Any) -> Proxy:
        return Proxy(gateway, tmp_path / "state" / "audit", **overrides)

    return factory


def error_type(data: bytes) -> str:
    return json.loads(data)["error"]["type"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_path",
    [
        "/v1/./messages",
        "/v1/x/../messages",
        "/v1//messages",
        "/v1/%6Dessages",
        "/v1/%2e/messages",
        "/v1/messages%2Fcount_tokens",
        "/v1/%2E%2E/v1/messages",
    ],
)
async def test_non_normal_paths_are_rejected_without_upstream(
    make_proxy: Callable[..., Proxy], raw_path: str
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call("POST", raw_path, MESSAGE_BYTES)

    assert status == 400
    assert error_type(data) == "privacy_gateway_rejected"
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_a_non_normal_get_path_is_rejected_too(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("GET", "/v1/x/../models")

    assert status == 400
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_the_normal_messages_path_still_works(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("POST", "/v1/messages", MESSAGE_BYTES)

    assert status == 200
    assert str(proxy.seen[0].url) == f"{UPSTREAM}/v1/messages"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/files"),
        ("POST", "/v1/complete"),
        ("PUT", "/v1/messages"),
        ("PATCH", "/v1/files/file_1"),
        ("DELETE", "/v1/messages/x"),
    ],
)
async def test_content_methods_outside_the_allowlist_get_422(
    make_proxy: Callable[..., Proxy], method: str, path: str
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call(method, path, b'{"x": 1}')

    assert status == 422
    assert error_type(data) == "privacy_gateway_rejected"
    assert proxy.seen == []
    (entry,) = proxy.entries()
    assert entry["event"] == "proxy_request"
    assert entry["path"] == path


@pytest.mark.asyncio
async def test_a_configured_passthrough_path_is_forwarded(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(passthrough_paths=("/v1/files",))

    status, _ = await proxy.call("POST", "/v1/files", b"raw-bytes")

    assert status == 200
    assert proxy.seen[0].content == b"raw-bytes"
    assert str(proxy.seen[0].url) == f"{UPSTREAM}/v1/files"
    other, _ = await proxy.call("DELETE", "/v1/files/f1")
    assert other == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/v1/models"), ("HEAD", "/api/hello"), ("OPTIONS", "/v1/messages")],
)
async def test_bodyless_reads_are_still_forwarded(
    make_proxy: Callable[..., Proxy], method: str, path: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call(method, path)

    assert status == 200
    assert len(proxy.seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_a_read_with_a_body_is_rejected(
    make_proxy: Callable[..., Proxy], method: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call(method, "/v1/models", b'{"smuggled": true}')

    assert status == 422
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_without_a_token_nothing_is_demanded(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("GET", "/v1/models")

    assert status == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{}, {"x-pgw-auth": "wrong"}, {"x-pgw-auth": TOKEN + "x"}])
async def test_a_missing_or_wrong_token_is_401(
    make_proxy: Callable[..., Proxy], headers: dict[str, str]
) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    for method, path, body in [
        ("POST", "/v1/messages", MESSAGE_BYTES),
        ("GET", "/v1/models", b""),
    ]:
        status, data = await proxy.call(method, path, body, headers)
        assert status == 401
        assert error_type(data) == "privacy_gateway_unauthorized"
    assert proxy.seen == []


@pytest.mark.asyncio
async def test_the_right_token_passes_and_is_not_forwarded(
    make_proxy: Callable[..., Proxy], tmp_path: Path
) -> None:
    debug_dir = tmp_path / "dump"
    proxy = make_proxy(auth_token=TOKEN, debug_dir=debug_dir)
    headers = {"x-pgw-auth": TOKEN, "x-pgw-session": "abc", "x-api-key": "sk-test"}

    status, _ = await proxy.call("POST", "/v1/messages", MESSAGE_BYTES, headers)
    read_status, _ = await proxy.call("GET", "/v1/models", b"", headers)

    assert (status, read_status) == (200, 200)
    assert len(proxy.seen) == 2
    for request in proxy.seen:
        assert "x-pgw-auth" not in request.headers
        assert "x-pgw-session" not in request.headers
        assert request.headers["x-api-key"] == "sk-test"
        assert TOKEN not in str(request.headers)
    assert TOKEN not in proxy.log_text()
    dumps = list(debug_dir.glob("*.json"))
    assert dumps
    assert all(TOKEN not in p.read_text(encoding="utf-8") for p in dumps)


@pytest.mark.asyncio
async def test_a_rejected_request_does_not_log_the_token(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    await proxy.call("POST", "/v1/files", b"{}", {"x-pgw-auth": TOKEN})

    assert TOKEN not in proxy.log_text()


@pytest.mark.asyncio
async def test_health_needs_no_token(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy(auth_token=TOKEN)

    status, data = await proxy.call("GET", "/health")

    assert status == 200
    assert json.loads(data) == {"status": "ok"}


@pytest.mark.asyncio
async def test_the_session_header_is_not_forwarded_without_a_token(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(session_strategy="header")

    await proxy.call("POST", "/v1/messages", MESSAGE_BYTES, {"x-pgw-session": "abc"})

    assert "x-pgw-session" not in proxy.seen[0].headers


SECRET_MAIL = "geheim.person@beispiel-firma.de"
SECRET_IBAN = "DE89370400440532013000"
CLEAN = {
    **MESSAGE,
    "metadata": {"user_id": "user_a_account_b_session_0b1c2d3e-5f6a-4b7c-8d9e-0a1b2c3d4e5f"},
}


def message_with(blocks: list[dict[str, Any]], **extra: Any) -> bytes:
    body = {**CLEAN, **extra, "messages": [{"role": "assistant", "content": blocks}]}
    return json.dumps(body).encode()


def tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": "toolu_1", "name": "Lookup", "input": payload}


def sent_input(proxy: Proxy, index: int = 0) -> dict[str, Any]:
    return json.loads(proxy.seen[index].content)["messages"][0]["content"][0]["input"]


@pytest.mark.asyncio
async def test_a_sensitive_key_in_tool_use_input_never_leaves_in_clear(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    nested = {"outer": [{SECRET_MAIL: "x", "plain": "y"}]}
    body = message_with([tool_use({SECRET_MAIL: "x", "n": nested, "ok": "1"})])

    status, _ = await proxy.call("POST", "/v1/messages", body)

    assert status == 200
    sent = proxy.seen[0].content.decode()
    assert "geheim.person" not in sent
    assert "beispiel-firma" not in sent
    sent_in = sent_input(proxy)
    assert list(sent_in)[1:] == ["n", "ok"]
    assert list(sent_in["n"]["outer"][0])[1] == "plain"
    assert "geheim.person" not in proxy.log_text()
    (entry,) = proxy.entries()
    assert entry["verdict"] == "ok"
    key_fields = [f for f in entry["fields"] if f["path"].endswith("#key") and f["findings"]]
    assert {f["path"] for f in key_fields} == {
        "messages[0].content[0].input{0}#key",
        "messages[0].content[0].input{1}{0}[0]{0}#key",
    }


@pytest.mark.asyncio
async def test_keys_without_findings_stay_byte_identical(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    payload = {"file_path": "a", "z": {"b": 1, "a": 2}}

    await proxy.call("POST", "/v1/messages", message_with([tool_use(payload)]))

    assert sent_input(proxy) == payload
    assert list(sent_input(proxy)["z"]) == ["b", "a"]
    assert b'"input": {"file_path": "a", "z": {"b": 1, "a": 2}}' in proxy.seen[0].content


@pytest.mark.asyncio
async def test_a_token_key_in_the_response_is_restored(make_proxy: Callable[..., Proxy]) -> None:
    proxy = make_proxy()

    def reply(request: httpx.Request) -> httpx.Response:
        sent_keys = json.loads(request.content)["messages"][0]["content"][0]["input"]
        (token_key,) = sent_keys
        block = {"type": "tool_use", "id": "t2", "name": "Lookup", "input": {token_key: "v"}}
        return httpx.Response(200, json={"content": [block]})

    proxy.reply = reply

    status, data = await proxy.call(
        "POST", "/v1/messages", message_with([tool_use({SECRET_MAIL: "x"})])
    )

    assert status == 200
    assert json.loads(data)["content"][0]["input"] == {SECRET_MAIL: "v"}


@pytest.mark.asyncio
async def test_a_key_collision_is_suffixed_stable_and_leaks_nothing(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    await proxy.call("POST", "/v1/messages", message_with([tool_use({SECRET_MAIL: "1"})]))
    (token,) = sent_input(proxy)
    proxy.seen.clear()
    upper = SECRET_MAIL.upper()
    clash = message_with([tool_use({SECRET_MAIL: "1", token: "2", "x": upper})])

    status, _ = await proxy.call("POST", "/v1/messages", clash)
    again, _ = await proxy.call("POST", "/v1/messages", clash)

    assert (status, again) == (200, 200)
    assert SECRET_MAIL not in proxy.seen[0].content.decode()
    assert len(sent_input(proxy)) == 3
    assert proxy.seen[0].content == proxy.seen[1].content
    assert SECRET_MAIL not in proxy.log_text()
    assert proxy.entries()[-1]["verdict"] != "blocked"


@pytest.mark.asyncio
async def test_a_sensitive_value_under_any_key_is_still_tokenized(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()

    await proxy.call("POST", "/v1/messages", message_with([tool_use({"iban": SECRET_IBAN})]))

    assert SECRET_IBAN not in proxy.seen[0].content.decode()
    assert "iban" in sent_input(proxy)


@pytest.mark.asyncio
async def test_unchecked_findings_change_the_verdict_but_do_not_block(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    tools = [{"name": "T", "description": f"Mail {SECRET_MAIL}", "input_schema": {}}]

    status, _ = await proxy.call(
        "POST", "/v1/messages", json.dumps({**CLEAN, "tools": tools}).encode()
    )

    assert status == 200
    (entry,) = proxy.entries()
    assert entry["verdict"] == "ok_with_unchecked_findings"
    assert entry["outgoing"]["leakage"] == "ok"
    assert SECRET_MAIL in proxy.seen[0].content.decode()


@pytest.mark.asyncio
async def test_clean_unchecked_fields_keep_the_verdict_ok(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    body = {**CLEAN, "tools": [{"name": "T", "description": "Reads a file", "input_schema": {}}]}

    await proxy.call("POST", "/v1/messages", json.dumps(body).encode())

    (entry,) = proxy.entries()
    assert entry["verdict"] == "ok"


@pytest.mark.asyncio
async def test_findings_in_an_untransformed_system_prompt_change_the_verdict(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy(transform_system=False)
    body = {**CLEAN, "system": f"Kontakt {SECRET_MAIL}"}

    await proxy.call("POST", "/v1/messages", json.dumps(body).encode())

    (entry,) = proxy.entries()
    assert entry["verdict"] == "ok_with_unchecked_findings"


@pytest.mark.asyncio
async def test_well_formed_unknown_blocks_are_forwarded_and_counted_unchecked(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    block = {"type": "future_block", "payload": {"mail": SECRET_MAIL}}

    status, _ = await proxy.call("POST", "/v1/messages", message_with([block]))

    assert status == 200
    (entry,) = proxy.entries()
    assert entry["verdict"] == "ok_with_unchecked_findings"


MALFORMED = {
    "messages_is_a_string": {**MESSAGE, "messages": f"Hallo {SECRET_MAIL}"},
    "messages_missing": {k: v for k, v in MESSAGE.items() if k != "messages"},
    "message_is_a_string": {**MESSAGE, "messages": [f"Hallo {SECRET_MAIL}"]},
    "content_is_a_dict": {
        **MESSAGE,
        "messages": [{"role": "user", "content": {"type": "text", "text": SECRET_MAIL}}],
    },
    "content_missing": {**MESSAGE, "messages": [{"role": "user"}]},
    "block_is_a_string": {**MESSAGE, "messages": [{"role": "user", "content": [SECRET_MAIL]}]},
    "block_without_type": {
        **MESSAGE,
        "messages": [{"role": "user", "content": [{"text": SECRET_MAIL}]}],
    },
    "text_is_a_list": {
        **MESSAGE,
        "messages": [{"role": "user", "content": [{"type": "text", "text": [SECRET_MAIL]}]}],
    },
    "tool_result_content_is_a_dict": {
        **MESSAGE,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": {"type": "text", "text": "x"}}],
            }
        ],
    },
    "tool_result_item_is_a_string": {
        **MESSAGE,
        "messages": [
            {"role": "user", "content": [{"type": "tool_result", "content": [SECRET_MAIL]}]}
        ],
    },
    "system_is_a_number": {**MESSAGE, "system": 5},
    "system_block_is_a_string": {**MESSAGE, "system": [SECRET_MAIL]},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(MALFORMED))
@pytest.mark.parametrize("path", ["/v1/messages", "/v1/messages/count_tokens"])
async def test_a_malformed_body_gets_400_without_upstream(
    make_proxy: Callable[..., Proxy], name: str, path: str
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call("POST", path, json.dumps(MALFORMED[name]).encode())

    assert status == 400
    assert error_type(data) == "invalid_request_error"
    assert json.loads(data)["type"] == "error"
    assert SECRET_MAIL not in data.decode()
    assert proxy.seen == []
    (entry,) = proxy.entries()
    assert entry["verdict"] == "blocked"
    assert entry["path"] == path
    assert SECRET_MAIL not in proxy.log_text()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw", [b"{not json", b'["a"]', b'"text"', b"null", b"42", b"", b'{"messages": [}']
)
async def test_a_body_that_is_not_a_json_object_gets_400(
    make_proxy: Callable[..., Proxy], raw: bytes
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call("POST", "/v1/messages", raw)

    assert status == 400
    assert error_type(data) == "invalid_request_error"
    assert proxy.seen == []
    assert proxy.entries()[0]["verdict"] == "blocked"


@pytest.mark.asyncio
async def test_a_realistic_claude_code_request_is_not_newly_blocked(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    body = {
        "model": "claude-x",
        "max_tokens": 64,
        "stream": True,
        "metadata": {"user_id": f"user_a_account_b_session_{CONVERSATION}"},
        "system": [
            {"type": "text", "text": "You are Claude Code."},
            {"type": "text", "text": "Dir", "cache_control": {"type": "ephemeral"}},
        ],
        "tools": [{"name": "Read", "description": "Reads", "input_schema": {"type": "object"}}],
        "messages": [
            {"role": "user", "content": "Hallo"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "hm", "signature": "c2ln"},
                    {"type": "text", "text": "Ich lese."},
                    {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a"}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "inhalt"},
                    {
                        "type": "tool_result",
                        "tool_use_id": "t2",
                        "content": [{"type": "text", "text": "x"}],
                        "is_error": False,
                    },
                    {"type": "tool_result", "tool_use_id": "t3"},
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"},
                    },
                    {"type": "text", "text": "weiter", "cache_control": {"type": "ephemeral"}},
                ],
            },
        ],
    }

    for path in ("/v1/messages", "/v1/messages/count_tokens"):
        status, _ = await proxy.call("POST", path, json.dumps(body).encode())
        assert status == 200
    assert len(proxy.seen) == 2


@pytest.mark.asyncio
async def test_a_get_query_with_free_text_is_refused_and_never_logged(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()

    status, data = await proxy.call("GET", "/v1/models", query=f"q={SECRET_MAIL}")

    assert status == 400
    assert error_type(data) == "invalid_request_error"
    assert proxy.seen == []
    assert SECRET_MAIL not in proxy.log_text()
    assert proxy.entries()[0]["verdict"] == "blocked"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "query"),
    [
        ("GET", "/v1/models", "limit=20"),
        ("GET", "/v1/models", "limit=20&after_id=model_01-x"),
        ("POST", "/v1/messages", "beta=true"),
        ("POST", "/v1/messages/count_tokens", "beta=true"),
    ],
)
async def test_the_known_query_parameters_are_forwarded(
    make_proxy: Callable[..., Proxy], method: str, path: str, query: str
) -> None:
    proxy = make_proxy()
    body = MESSAGE_BYTES if method == "POST" else b""

    status, _ = await proxy.call(method, path, body, query=query)

    assert status == 200
    assert proxy.seen[0].url.query.decode() == query


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query",
    [
        f"beta={SECRET_MAIL}",
        "limit=20%40x",
        "x=1",
        "beta=true&q=a",
        "beta=" + "a" * 200,
        "limit=1;x=2",
    ],
)
async def test_other_query_parameters_and_values_are_refused(
    make_proxy: Callable[..., Proxy], query: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("POST", "/v1/messages", MESSAGE_BYTES, query=query)

    assert status == 400
    assert proxy.seen == []
    assert SECRET_MAIL not in proxy.log_text()


def test_the_access_log_drops_the_query_string(make_proxy: Callable[..., Proxy]) -> None:
    make_proxy()
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", f"/v1/models?q={SECRET_MAIL}", "1.1", 400),
        None,
    )

    assert logging.getLogger("uvicorn.access").filter(record)
    assert SECRET_MAIL not in record.getMessage()
    assert "/v1/models" in record.getMessage()


KNOWN_PATHS = [
    ("GET", "/v1/models"),
    ("GET", "/v1/models/claude-sonnet-4-5-20250929"),
    ("GET", "/v1/models/claude-opus-4-1"),
    ("GET", "/api/hello"),
    ("HEAD", "/api/hello"),
    ("GET", "/health-check"),
    ("GET", "/v1/messages/batches/msgbatch_01HkcTjaV5uDC8jWR4ZsDV8d"),
    ("GET", "/v1/files/file_011CNha8iCJcU1wXNR6q4V8w"),
    ("GET", "/v1/files/file_011CNha8iCJcU1wXNR6q4V8w/content"),
    ("GET", "/v1/messages/batches/msgbatch_01HkcTjaV5uDC8jWR4ZsDV8d/results"),
    ("GET", "/v1/messages/msg_01AbCdEfGhIjKlMnOpQrStUv"),
    ("GET", "/v1/organizations/0b1c2d3e-1111-2222-3333-444444444444"),
    ("GET", "/v1/skills/skill_01AbCdEfGhIjKlMnOpQrStUv/versions"),
    ("GET", "/v1/skills/skill_01AbCdEfGhIjKlMnOpQrStUv/versions/1759178010641129"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), KNOWN_PATHS)
async def test_known_id_shaped_paths_are_still_forwarded(
    make_proxy: Callable[..., Proxy], method: str, path: str
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call(method, path)

    assert status == 200
    assert len(proxy.seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        f"/v1/files/{SECRET_MAIL}",
        f"/v1/files/{SECRET_IBAN}",
        f"/v1/models/x/{SECRET_MAIL}/content",
    ],
)
async def test_a_sensitive_path_segment_is_refused_and_never_logged(
    make_proxy: Callable[..., Proxy], path: str, caplog: pytest.LogCaptureFixture
) -> None:
    proxy = make_proxy()
    caplog.set_level(logging.DEBUG)

    status, data = await proxy.call("GET", path)

    assert status == 400
    assert error_type(data) == "invalid_request_error"
    assert proxy.seen == []
    (entry,) = proxy.entries()
    assert entry["verdict"] == "blocked"
    assert entry["path"].endswith("/…")
    assert SECRET_MAIL not in proxy.log_text() + data.decode() + caplog.text
    assert SECRET_IBAN not in proxy.log_text() + data.decode() + caplog.text


@pytest.mark.asyncio
async def test_a_sensitive_path_hit_does_not_teach_the_session(
    make_proxy: Callable[..., Proxy], gateway: Gateway
) -> None:
    proxy = make_proxy()

    await proxy.call("GET", f"/v1/files/{SECRET_MAIL}")

    session = gateway.session("default")
    assert dict(session.entries()) == {}


@pytest.mark.asyncio
async def test_a_url_encoded_sensitive_segment_never_reaches_upstream(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("GET", "/v1/files/geheim.person%40beispiel-firma.de")

    assert status == 400
    assert proxy.seen == []
    assert "beispiel-firma" not in proxy.log_text()


@pytest.mark.parametrize(
    ("path", "short"),
    [
        ("/v1/files/geheim.person@beispiel-firma.de", "/v1/files/…"),
        ("/v1/models", "/v1/models"),
        ("/health", "/health"),
        ("/a/b/c/d", "/a/b/…"),
    ],
)
def test_logged_paths_are_shortened_to_two_segments(path: str, short: str) -> None:
    assert server.short_path(path) == short


def test_the_access_log_shortens_the_path(make_proxy: Callable[..., Proxy]) -> None:
    make_proxy()
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", f"/v1/files/{SECRET_MAIL}?x=1", "1.1", 400),
        None,
    )

    assert logging.getLogger("uvicorn.access").filter(record)
    assert SECRET_MAIL not in record.getMessage()
    assert "/v1/files/…" in record.getMessage()


@pytest.mark.asyncio
async def test_a_sensitive_path_on_a_rejected_method_is_cut_in_the_log(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()

    status, _ = await proxy.call("PATCH", f"/v1/files/{SECRET_MAIL}", b'{"x": 1}')

    assert status == 400
    assert proxy.seen == []
    assert SECRET_MAIL not in proxy.log_text()
    assert proxy.entries()[0]["path"] == "/v1/files/…"


@pytest.mark.asyncio
async def test_clean_keys_are_counted_not_listed_in_the_audit_line(
    make_proxy: Callable[..., Proxy],
) -> None:
    proxy = make_proxy()
    blocks = [
        {
            "type": "tool_use",
            "id": f"toolu_{index}",
            "name": "Edit",
            "input": {"file_path": "a.py", "old_string": "a", "new_string": "b", "n": 1},
        }
        for index in range(20)
    ]
    blocks[3]["input"][SECRET_MAIL] = "x"

    status, _ = await proxy.call("POST", "/v1/messages", message_with(blocks))

    assert status == 200
    entry = proxy.entries()[-1]
    key_fields = [f for f in entry["fields"] if f["path"].endswith("#key")]
    assert len(key_fields) == 1
    assert key_fields[0]["findings"]
    coverage = entry["coverage"]
    assert coverage["checked_keys"] == 20 * 4
    assert coverage["checked_fields"] == len(
        [f for f in entry["fields"] if f["status"] == "checked"]
    )
    assert SECRET_MAIL not in proxy.log_text()
