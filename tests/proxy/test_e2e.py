"""End-to-end tests: real gateway sessions, real transforms, fake upstream."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import DetectionReport
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings
from privacy_gateway_proxy.transform import NOTICE_TEXT

CUSTOMER = "Alpenbank AG"
IBAN = "DE89370400440532013000"
LAST_NAME = "Müller"
SECRETS = (CUSTOMER, IBAN, LAST_NAME)
CUSTOMER_TOKEN = "<CUSTOMER_NAME_001>"
PERSON_TOKEN = "<PERSON_FEMALE_001>"
IBAN_TOKEN = "<IBAN_001>"
CONFIG = f"dictionaries:\n  CUSTOMER_NAME: [{CUSTOMER}]\n"
UPSTREAM = "https://upstream.test"
SETTINGS = ProxySettings(upstream_base_url=UPSTREAM)
CONVERSATION = "0b1c2d3e-1111-2222-3333-444444444444"
OTHER_CONVERSATION = "9f8e7d6c-5555-6666-7777-888888888888"
LETTER = (
    f"Sehr geehrte Frau {LAST_NAME}, die {CUSTOMER} bucht von IBAN {IBAN} ab."
)
TOKEN_PATTERN = re.compile(r"<[A-Z][A-Z_]*_\d{3}>")


@pytest.fixture
def audit_log(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def gateway(tmp_path: Path, audit_log: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    config_path = tmp_path / "proxy_config.yaml"
    config_path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(audit_log))
    monkeypatch.setenv("PGW_CONFIG", str(config_path))
    with Gateway() as instance:
        yield instance


def build(
    gateway: Gateway, handler: Callable[[httpx.Request], httpx.Response]
) -> httpx.AsyncClient:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(SETTINGS, gateway, client=upstream)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    )


def request_body(text: str, *, stream: bool = False, conversation: str = CONVERSATION) -> dict:
    body: dict = {
        "model": "claude-x",
        "max_tokens": 128,
        "metadata": {"user_id": f"user_abc_account_def_session_{conversation}"},
        "system": "Du bist ein Assistent.",
        "messages": [{"role": "user", "content": text}],
    }
    if stream:
        body["stream"] = True
    return body


def assert_clean(request: httpx.Request) -> None:
    body = request.content.decode("utf-8")
    for secret in SECRETS:
        assert secret not in body


def sent_content(request: httpx.Request) -> list[dict] | str:
    return json.loads(request.content)["messages"][0]["content"]


def sent_text(request: httpx.Request) -> str:
    content = sent_content(request)
    if isinstance(content, str):
        return content
    return [block["text"] for block in content if block.get("type") == "text"][-1]


def stream_text(raw: str) -> str:
    parts: list[str] = []
    for line in raw.splitlines():
        if not line.startswith("data: "):
            continue
        payload = json.loads(line[len("data: ") :])
        delta = payload.get("delta")
        if isinstance(delta, dict) and delta.get("type") == "text_delta":
            parts.append(delta["text"])
    return "".join(parts)


def sse_stream(text: str, chunk_size: int) -> Callable[[], AsyncIterator[bytes]]:
    events = [
        'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1"}}\n\n',
        (
            'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
            '"content_block":{"type":"text","text":""}}\n\n'
        ),
    ]
    for start in range(0, len(text), 4):
        piece = json.dumps(text[start : start + 4])
        events.append(
            "event: content_block_delta\n"
            'data: {"type":"content_block_delta","index":0,'
            f'"delta":{{"type":"text_delta","text":{piece}}}}}\n\n'
        )
    events.append('event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
    events.append('event: message_stop\ndata: {"type":"message_stop"}\n\n')
    raw = "".join(events).encode("utf-8")

    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(raw), chunk_size):
            yield raw[start : start + chunk_size]

    return chunks


def audit_events(path: Path, event: str) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [record for record in map(json.loads, lines) if record["event"] == event]


@pytest.mark.asyncio
async def test_non_streaming_roundtrip_hides_values_and_restores_the_answer(
    gateway: Gateway, audit_log: Path
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert_clean(request)
        tokens = TOKEN_PATTERN.findall(sent_text(request))
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "content": [
                    {"type": "text", "text": f"Notiz zu {' und '.join(tokens)}."},
                    {
                        "type": "tool_use",
                        "id": "tu_1",
                        "name": "Write",
                        "input": {"file_path": "/tmp/n.md", "content": f"Kunde {tokens[1]}"},
                    },
                ],
            },
        )

    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER))

    assert response.status_code == 200
    blocks = response.json()["content"]
    assert blocks[0]["text"] == f"Notiz zu {LAST_NAME} und {CUSTOMER} und {IBAN}."
    assert blocks[1]["input"]["content"] == f"Kunde {CUSTOMER}"
    assert TOKEN_PATTERN.findall(sent_text(seen[0])) == [PERSON_TOKEN, CUSTOMER_TOKEN, IBAN_TOKEN]

    (event,) = audit_events(audit_log, "proxy_request")
    assert event["path"] == "/v1/messages"
    assert event["session_key"] == CONVERSATION
    assert event["leakage"] == "ok"
    assert event["streaming"] is False
    assert event["fields"] == 3
    content = audit_log.read_text(encoding="utf-8")
    for secret in SECRETS:
        assert secret not in content


@pytest.mark.asyncio
async def test_streaming_answer_is_restored_for_the_client(gateway: Gateway) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert_clean(request)
        answer = f"Antwort fuer {PERSON_TOKEN} von {CUSTOMER_TOKEN} zur IBAN {IBAN_TOKEN}."
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=sse_stream(answer, chunk_size=7)(),
        )

    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER, stream=True))

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/event-stream"
    assert stream_text(response.text) == (
        f"Antwort fuer {LAST_NAME} von {CUSTOMER} zur IBAN {IBAN}."
    )
    assert "message_start" in response.text
    assert "<PERSON" not in response.text


@pytest.mark.asyncio
async def test_a_second_request_of_the_conversation_reuses_the_token(gateway: Gateway) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert_clean(request)
        return httpx.Response(200, json={"content": []})

    client = build(gateway, handler)
    async with client:
        await client.post("/v1/messages", json=request_body(LETTER))
        await client.post(
            "/v1/messages", json=request_body(f"Bitte der {CUSTOMER} antworten.")
        )

    assert sent_text(seen[1]) == f"Bitte der {CUSTOMER_TOKEN} antworten."


@pytest.mark.asyncio
async def test_a_different_conversation_starts_at_001_again(gateway: Gateway) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert_clean(request)
        return httpx.Response(200, json={"content": []})

    client = build(gateway, handler)
    async with client:
        await client.post("/v1/messages", json=request_body(LETTER))
        await client.post(
            "/v1/messages",
            json=request_body(
                f"Sehr geehrte Frau Schmidt, die {CUSTOMER} meldet sich.",
                conversation=OTHER_CONVERSATION,
            ),
        )

    assert sent_text(seen[1]) == (
        f"Sehr geehrte Frau {PERSON_TOKEN}, die {CUSTOMER_TOKEN} meldet sich."
    )


@pytest.mark.asyncio
async def test_the_notice_is_the_first_block_of_the_first_user_message(
    gateway: Gateway,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert_clean(request)
        return httpx.Response(200, json={"content": []})

    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER))

    assert response.status_code == 200
    payload = json.loads(seen[0].content)
    assert payload["messages"][0]["content"][0] == {"type": "text", "text": NOTICE_TEXT}
    assert payload["system"] == "Du bist ein Assistent."
    assert NOTICE_TEXT not in payload["system"]
    assert sent_text(seen[0]) == (
        f"Sehr geehrte Frau {PERSON_TOKEN}, die {CUSTOMER_TOKEN} bucht von IBAN {IBAN_TOKEN} ab."
    )


@pytest.mark.asyncio
async def test_the_notice_is_disabled_by_its_setting(gateway: Gateway) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": []})

    settings = ProxySettings(upstream_base_url=UPSTREAM, placeholder_notice=False)
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(settings, gateway, client=upstream)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    )
    async with client:
        await client.post("/v1/messages", json=request_body(LETTER))

    assert isinstance(sent_content(seen[0]), str)
    assert NOTICE_TEXT not in seen[0].content.decode("utf-8")


@pytest.mark.asyncio
async def test_models_endpoint_is_proxied_verbatim(gateway: Gateway) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": [{"id": "claude-x"}]})

    client = build(gateway, handler)
    async with client:
        response = await client.get("/v1/models", headers={"x-api-key": "sk-test"})

    assert response.status_code == 200
    assert response.json() == {"data": [{"id": "claude-x"}]}
    assert str(seen[0].url) == f"{UPSTREAM}/v1/models"
    assert seen[0].headers["x-api-key"] == "sk-test"


@pytest.mark.asyncio
async def test_a_leaking_request_returns_422_and_never_reaches_upstream(
    gateway: Gateway, audit_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return httpx.Response(200, json={"content": []})

    def leaking(
        text: str,
        report: DetectionReport,
        config: Config,
        *,
        counters: dict[str, int] | None = None,
    ) -> PseudonymizedText:
        real = pseudonymize_text(text, report, config, counters=counters)
        return PseudonymizedText(text=text, assignments=real.assignments)

    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", leaking)
    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER))

    assert response.status_code == 422
    assert response.json()["error"]["type"] == "privacy_gateway_leak"
    assert called == []
    (event,) = audit_events(audit_log, "proxy_request")
    assert event["leakage"] == "failed"


@pytest.mark.asyncio
async def test_an_unknown_token_in_the_answer_does_not_break_the_reply(
    gateway: Gateway,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": "Notiz zu <PERSON_FEMALE_777>."}]}
        )

    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER))

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == "Notiz zu <PERSON_FEMALE_777>."


@pytest.mark.asyncio
async def test_an_unknown_token_in_a_stream_does_not_break_the_reply(gateway: Gateway) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=sse_stream("Notiz zu <PERSON_FEMALE_777>.", chunk_size=7)(),
        )

    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=request_body(LETTER, stream=True))

    assert response.status_code == 200
    assert stream_text(response.text) == "Notiz zu <PERSON_FEMALE_777>."


@pytest.mark.asyncio
async def test_a_text_document_block_is_pseudonymized_and_restored(gateway: Gateway) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert_clean(request)
        return httpx.Response(200, json={"content": [{"type": "text", "text": IBAN_TOKEN}]})

    body = request_body("Anbei das Dokument.")
    body["messages"][0]["content"] = [
        {"type": "text", "text": "Anbei das Dokument."},
        {
            "type": "document",
            "source": {"type": "text", "media_type": "text/plain", "data": f"IBAN {IBAN}"},
        },
    ]
    client = build(gateway, handler)
    async with client:
        response = await client.post("/v1/messages", json=body)

    assert response.status_code == 200
    document = json.loads(seen[0].content)["messages"][0]["content"][-1]
    assert document["source"]["data"] == f"IBAN {IBAN_TOKEN}"
    assert response.json()["content"][0]["text"] == IBAN
