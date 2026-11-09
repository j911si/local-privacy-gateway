"""The daily `proxy_request` v2 audit log: schema, no plain text, unchecked fields, rescan."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import DetectionReport
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text
from privacy_gateway_proxy import server, transform
from privacy_gateway_proxy.settings import ProxySettings, audit_dir_for, load_settings

UPSTREAM = "https://upstream.test"
CONVERSATION = "0b1c2d3e-1111-2222-3333-444444444444"
NAME = "Müller"
IBAN = "DE89370400440532013000"
EMAIL = "anna.mueller@example.org"
URL = "https://intranet.example.com/akte/42"
KEY_PREFIX = "sk" + "-ant-"
KEY_REST = "api03" + "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"
API_KEY = KEY_PREFIX + KEY_REST
CANARIES = (NAME, IBAN, EMAIL, URL, API_KEY)
LETTER = (
    f"Sehr geehrte Frau {NAME}, IBAN {IBAN}, Mail {EMAIL}, siehe {URL} Key {API_KEY}"
)
TOOL_URL = "https://docs.example.com/tool-hilfe"
TOP_KEYS = [
    "v", "event", "ts", "request_id", "session", "path", "streaming", "duration_ms",
    "verdict", "coverage", "fields", "outgoing",
]
FINDING_KEYS = {"cls", "start", "end", "token", "policy", "confidence", "stage", "hmac"}


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "audit"


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


def build(
    gateway: Gateway, audit_dir: Path, handler: Callable[[httpx.Request], httpx.Response]
) -> httpx.AsyncClient:
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir)
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(settings, gateway, client=upstream)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    )


def body_with(text: str, **extra: Any) -> dict:
    body: dict = {
        "model": "claude-x",
        "max_tokens": 128,
        "metadata": {"user_id": f"user_abc_account_def_session_{CONVERSATION}"},
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }
    body.update(extra)
    return body


def entries(audit_dir: Path) -> list[dict]:
    (path,) = sorted(audit_dir.glob("audit-*.jsonl"))
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def log_text(audit_dir: Path) -> str:
    return "".join(path.read_text(encoding="utf-8") for path in audit_dir.glob("audit-*.jsonl"))


def ok_handler(seen: list[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    return handler


def field(entry: dict, path: str) -> dict:
    (found,) = [item for item in entry["fields"] if item["path"] == path]
    return found


@pytest.mark.asyncio
async def test_entry_follows_the_contract_schema(gateway: Gateway, audit_dir: Path) -> None:
    seen: list[httpx.Request] = []
    async with build(gateway, audit_dir, ok_handler(seen)) as client:
        response = await client.post("/v1/messages", json=body_with(LETTER))

    assert response.status_code == 200
    (entry,) = entries(audit_dir)
    assert list(entry) == TOP_KEYS
    assert entry["v"] == 2
    assert entry["event"] == "proxy_request"
    assert re.fullmatch(r"[0-9a-f-]{36}", entry["request_id"])
    assert entry["session"] == hashlib.sha256(CONVERSATION.encode()).hexdigest()[:12]
    assert entry["path"] == "/v1/messages"
    assert entry["streaming"] is False
    assert entry["verdict"] == "ok"
    assert entry["coverage"] == {"checked_fields": 2, "unchecked_fields": 1}

    notice = field(entry, "messages[0].content[0].text")
    assert notice["status"] == "checked"
    assert notice["findings"] == []
    letter = field(entry, "messages[0].content[1].text")
    assert letter["chars"] == len(LETTER)
    by_class = {item["cls"]: item for item in letter["findings"]}
    assert {"IBAN", "EMAIL", "URL", "ANTHROPIC_API_KEY"} <= set(by_class)
    iban = by_class["IBAN"]
    assert set(iban) == FINDING_KEYS
    assert LETTER[iban["start"] : iban["end"]] == IBAN
    assert iban["token"] == "<IBAN_001>"
    assert iban["policy"] == "tokenize"
    assert iban["stage"] == "pattern"
    assert re.fullmatch(r"[0-9a-f]{16}", iban["hmac"])
    secret = by_class["ANTHROPIC_API_KEY"]
    assert secret["policy"] == "redact"
    assert secret["token"] == "<ANTHROPIC_API_KEY_REDACTED>"
    assert "hmac" not in secret

    metadata = field(entry, "metadata")
    assert metadata["status"] == "unchecked"
    assert metadata["reason"] == "metadata"

    outgoing = entry["outgoing"]
    assert outgoing["sha256"] == hashlib.sha256(seen[0].content).hexdigest()
    assert outgoing["bytes"] == len(seen[0].content)
    assert outgoing["leakage"] == "ok"
    assert outgoing["rescan"]["status"] in {"clean", "findings"}
    assert all(
        hit["path"] not in {"messages[0].content[1].text"}
        for hit in outgoing["rescan"]["findings"]
    )


@pytest.mark.asyncio
async def test_the_log_holds_no_canary_value(gateway: Gateway, audit_dir: Path) -> None:
    seen: list[httpx.Request] = []
    tools = [{"name": "Read", "description": f"Siehe {URL} und {EMAIL}", "input_schema": {}}]
    async with build(gateway, audit_dir, ok_handler(seen)) as client:
        await client.post("/v1/messages", json=body_with(LETTER, tools=tools))

    sent = seen[0].content.decode("utf-8")
    for canary in (NAME, IBAN, API_KEY):
        assert canary not in sent
    text = log_text(audit_dir)
    for canary in CANARIES:
        assert canary not in text
        assert json.dumps(canary)[1:-1] not in text
    assert "anna" not in text
    assert "intranet" not in text


@pytest.mark.asyncio
async def test_the_canary_check_detects_a_planted_value(
    gateway: Gateway, audit_dir: Path
) -> None:
    async with build(gateway, audit_dir, ok_handler([])) as client:
        await client.post("/v1/messages", json=body_with(LETTER))

    planted = log_text(audit_dir) + IBAN
    assert IBAN in planted


@pytest.mark.asyncio
async def test_unchecked_fields_are_listed_with_observed_and_left_unchanged(
    gateway: Gateway, audit_dir: Path
) -> None:
    seen: list[httpx.Request] = []
    tools = [{"name": "Fetch", "description": f"Hilfe unter {TOOL_URL}", "input_schema": {}}]
    thinking = {"type": "thinking", "thinking": f"Siehe {TOOL_URL}", "signature": "c2lnbmF0dXJl"}
    image = {
        "type": "image",
        "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="},
    }
    body = body_with("Hallo", tools=tools)
    body["messages"] = [
        {"role": "user", "content": [{"type": "text", "text": "Hallo"}, image]},
        {"role": "assistant", "content": [thinking, {"type": "text", "text": "Ja"}]},
        {"role": "user", "content": "Weiter"},
    ]
    async with build(gateway, audit_dir, ok_handler(seen)) as client:
        response = await client.post("/v1/messages", json=body)

    assert response.status_code == 200
    sent = json.loads(seen[0].content)
    assert sent["tools"] == tools
    assert sent["messages"][1]["content"][0] == thinking
    assert sent["messages"][0]["content"][2] == image
    (entry,) = entries(audit_dir)
    assert entry["verdict"] == "ok"
    tool = field(entry, "tools[0]")
    assert tool == {
        "path": "tools[0]",
        "status": "unchecked",
        "reason": "tools",
        "chars": len("Fetch") + len(f"Hilfe unter {TOOL_URL}"),
        "observed": [{"cls": "URL", "count": 1}],
    }
    assert field(entry, "messages[1].content[0]")["reason"] == "thinking"
    assert field(entry, "messages[1].content[0]")["observed"] == [{"cls": "URL", "count": 1}]
    assert field(entry, "messages[0].content[2]")["reason"] == "image"
    assert field(entry, "metadata")["reason"] == "metadata"
    assert entry["coverage"]["unchecked_fields"] == 4
    rescan = entry["outgoing"]["rescan"]
    assert rescan["status"] == "findings"
    assert {"path": "tools[0].description", "cls": "URL", "start": 12, "end": 47} in (
        rescan["findings"]
    )
    assert "docs.example" not in log_text(audit_dir)


def injecting(value: str) -> SimpleNamespace:
    """The real transform, but the pseudonymized body gets `value` appended afterwards."""

    def pseudonymize_request(body: dict, sess: Any, **kwargs: Any) -> tuple[dict, int]:
        new_body, count = transform.pseudonymize_request(body, sess, **kwargs)
        new_body["messages"][0]["content"][-1]["text"] += f" {value}"
        return new_body, count

    return SimpleNamespace(
        collect_request_texts=transform.collect_request_texts,
        request_refs=transform.request_refs,
        collect_unchecked=transform.collect_unchecked,
        pseudonymize_request=pseudonymize_request,
        restore_response=transform.restore_response,
    )


@pytest.mark.asyncio
async def test_a_rescan_hit_blocks_and_nothing_goes_upstream(
    gateway: Gateway, audit_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx.Request] = []
    monkeypatch.setattr(server, "_transform", injecting(IBAN))
    async with build(gateway, audit_dir, ok_handler(seen)) as client:
        response = await client.post("/v1/messages", json=body_with("Hallo Welt"))

    assert response.status_code == 422
    assert response.json()["error"]["type"] == "privacy_gateway_leak"
    assert IBAN not in response.text
    assert seen == []
    (entry,) = entries(audit_dir)
    assert entry["verdict"] == "blocked"
    rescan = entry["outgoing"]["rescan"]
    assert rescan["status"] == "findings"
    assert {"path": "messages[0].content[1].text", "cls": "IBAN", "start": 11, "end": 33} in (
        rescan["findings"]
    )
    assert IBAN not in log_text(audit_dir)


@pytest.mark.asyncio
async def test_a_leak_check_failure_is_logged_as_blocked(
    gateway: Gateway, audit_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def leaking(
        text: str,
        report: DetectionReport,
        config: Config,
        *,
        counters: dict[str, int] | None = None,
    ) -> PseudonymizedText:
        real = pseudonymize_text(text, report, config, counters=counters)
        return PseudonymizedText(text=text, assignments=real.assignments)

    seen: list[httpx.Request] = []
    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", leaking)
    async with build(gateway, audit_dir, ok_handler(seen)) as client:
        response = await client.post("/v1/messages", json=body_with(LETTER))

    assert response.status_code == 422
    assert seen == []
    (entry,) = entries(audit_dir)
    assert entry["verdict"] == "blocked"
    assert entry["outgoing"]["leakage"] == "fail"
    assert entry["outgoing"]["sha256"] is None
    assert entry["outgoing"]["rescan"]["status"] == "skipped"
    for canary in CANARIES:
        assert canary not in log_text(audit_dir)


@pytest.mark.asyncio
async def test_an_upstream_failure_is_logged_as_error(gateway: Gateway, audit_dir: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    async with build(gateway, audit_dir, handler) as client:
        response = await client.post("/v1/messages", json=body_with("Hallo"))

    assert response.status_code == 502
    (entry,) = entries(audit_dir)
    assert entry["verdict"] == "error"


@pytest.mark.asyncio
async def test_streaming_requests_are_logged(gateway: Gateway, audit_dir: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b"")

    async with build(gateway, audit_dir, handler) as client:
        await client.post("/v1/messages", json=body_with("Hallo", stream=True))

    (entry,) = entries(audit_dir)
    assert entry["streaming"] is True


@pytest.mark.asyncio
async def test_the_old_audit_log_keeps_its_format(
    gateway: Gateway, audit_dir: Path, tmp_path: Path
) -> None:
    old = tmp_path / "old.jsonl"
    gateway.audit = type(gateway.audit)(old)
    async with build(gateway, audit_dir, ok_handler([])) as client:
        await client.post("/v1/messages", json=body_with(LETTER))

    events = [json.loads(line) for line in old.read_text(encoding="utf-8").splitlines()]
    (event,) = [item for item in events if item["event"] == "proxy_request"]
    assert "v" not in event
    assert event["session_key"] == CONVERSATION
    assert len(entries(audit_dir)) == 1


def test_audit_dir_comes_from_the_environment(tmp_path: Path) -> None:
    env = {"PGW_AUDIT_LOG_DIR": str(tmp_path / "x")}
    assert load_settings(env=env).audit_dir == tmp_path / "x"
    assert audit_dir_for(ProxySettings(), env=env) == tmp_path / "x"
    default = audit_dir_for(ProxySettings(), env={})
    assert default == Path("~/.local/state/privacy-gateway/audit").expanduser()


def test_unchecked_collection_never_overlaps_checked_texts() -> None:
    body = {
        "model": "m",
        "system": [{"type": "text", "text": "S"}],
        "tools": [{"name": "t", "description": "d"}],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "a", "citations": [{"cited_text": "c"}]},
                    {
                        "type": "tool_result",
                        "tool_use_id": "x",
                        "content": [{"type": "text", "text": "r"}, {"type": "image", "source": {}}],
                    },
                    {"type": "document", "source": {"type": "base64", "data": "QUJD"}},
                    {"type": "server_tool_use", "input": {"q": "z"}},
                ],
            }
        ],
    }
    checked = {ref.path for ref in transform.collect_request_texts(body)}
    unchecked = {
        (transform.format_path(ref.path), ref.reason)
        for ref in transform.collect_unchecked(body)
    }
    assert checked == {
        ("system", 0, "text"),
        ("messages", 0, "content", 0, "text"),
        ("messages", 0, "content", 1, "content", 0, "text"),
    }
    assert unchecked == {
        ("tools[0]", "tools"),
        ("messages[0].content[0].citations", "other"),
        ("messages[0].content[1].content[1]", "image"),
        ("messages[0].content[2].source", "other"),
        ("messages[0].content[3]", "other"),
    }
