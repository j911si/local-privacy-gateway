"""A synthetic request shaped like a Claude Code request passes the default unchecked mode."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
IBAN = "DE89370400440532013000"
MAIL = "erika.beispiel@firma-test.de"
NAME = "Frau Müller"
VALUES = (IBAN, MAIL, "Müller")
USER_ID = (
    '{"device_id":"' + "5e" * 32 + '","account_uuid":"3fa85f64-5717-4562-b3fc-2c963f66afa6",'
    '"session_id":"0b1c2d3e-1a2b-4c3d-8e4f-5a6b7c8d9e0f"}'
)
BILLING = "x-anthropic-billing-header: cc_version=2.1.332.18b; cc_entrypoint=cli;"


def claude_code_body(system_text: str, *, stream: bool) -> dict[str, Any]:
    """Synthetic body with the key layout of a Claude Code request; no copied Anthropic text."""
    return {
        "context_management": {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
        "max_tokens": 32000,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": f"Bitte schreib an {NAME} ({MAIL}), IBAN {IBAN}.",
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            },
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "Erst die Datei lesen.", "signature": "c2ln"},
                    {"type": "text", "text": "Ich lese die Vorlage."},
                    {
                        "type": "tool_use",
                        "id": "toolu_01Synthetic",
                        "name": "Read",
                        "input": {"file_path": "/srv/vorlagen/brief.md"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01Synthetic",
                        "content": f"Empfänger: {NAME}, Konto {IBAN}",
                    },
                    {"type": "text", "text": "Weiter bitte."},
                ],
            },
        ],
        "metadata": {"user_id": USER_ID},
        "model": "claude-x",
        "output_config": {"effort": "high"},
        "stream": stream,
        "system": [
            {"type": "text", "text": BILLING},
            {"type": "text", "text": system_text, "cache_control": {"type": "ephemeral"}},
        ],
        "thinking": {"type": "enabled", "budget_tokens": 4000},
        "tools": [
            {
                "name": "Read",
                "description": "Reads one file. Paths are absolute.",
                "input_schema": {
                    "type": "object",
                    "properties": {"file_path": {"type": "string", "description": "A path."}},
                    "required": ["file_path"],
                },
            },
            {
                "name": "Review",
                "description": "Write `@name` for a person and `@reviewer` for a role in "
                "backticks. Help lives on claude.ai.",
                "input_schema": {"type": "object", "properties": {}},
            },
        ],
    }


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


SSE = (
    b'event: message_start\ndata: {"type":"message_start","message":{"id":"m","type":"message",'
    b'"role":"assistant","content":[],"model":"claude-x","usage":{"input_tokens":1}}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


async def _send(
    gateway: Gateway, tmp_path: Path, body: dict, **overrides: Any
) -> tuple[int, bytes, list[bytes], list[dict]]:
    seen: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if json.loads(request.content).get("stream") is True:
            return httpx.Response(200, content=SSE, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    audit = tmp_path / "audit"
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit, **overrides)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = server.create_app(settings, gateway, client=client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as proxy:
        response = await proxy.post("/v1/messages", content=json.dumps(body).encode())
    entries = [
        json.loads(line)
        for path in audit.glob("audit-*.jsonl")
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    return response.status_code, response.content, [r.content for r in seen], entries


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_a_representative_request_passes_with_a_transformed_system(
    gateway: Gateway, tmp_path: Path, stream: bool
) -> None:
    body = claude_code_body("Working directory: /home/testuser/projekt", stream=stream)

    status, data, sent, entries = await _send(gateway, tmp_path, body)

    assert status == 200, data
    assert len(sent) == 1
    upstream = sent[0].decode("utf-8")
    for value in VALUES:
        assert value not in upstream
        assert json.dumps(value)[1:-1] not in upstream
    assert "testuser" not in upstream
    assert "<IBAN_" in upstream and "<EMAIL_" in upstream
    forwarded = json.loads(sent[0])
    assert forwarded["tools"] == body["tools"]
    assert forwarded["messages"][1]["content"][0] == body["messages"][1]["content"][0]
    assert forwarded["metadata"] == body["metadata"]
    (entry,) = entries
    assert entry["verdict"] == "ok_with_unchecked_findings"
    assert entry["streaming"] is stream


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_an_untransformed_system_with_a_home_path_is_blocked(
    gateway: Gateway, tmp_path: Path, stream: bool
) -> None:
    body = claude_code_body("Working directory: /home/testuser/projekt", stream=stream)

    status, data, sent, entries = await _send(gateway, tmp_path, body, transform_system=False)

    assert status == 422
    assert json.loads(data)["error"]["type"] == "privacy_gateway_leak"
    assert sent == []
    (entry,) = entries
    assert entry["verdict"] == "blocked"
    findings = entry["outgoing"]["rescan"]["findings"]
    assert {(item["path"], item["cls"]) for item in findings} >= {
        ("system[1].text", "PERSON_USERNAME")
    }
    message = json.loads(data)["error"]["message"]
    assert "PERSON_USERNAME" in message
    assert "CUSTOM_HEADER" not in message
    assert "testuser" not in json.dumps(entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_an_untransformed_system_passes_with_the_opt_out(
    gateway: Gateway, tmp_path: Path, stream: bool
) -> None:
    body = claude_code_body("Working directory: /home/testuser/projekt", stream=stream)

    status, data, sent, entries = await _send(
        gateway, tmp_path, body, transform_system=False, unchecked_fields="allow"
    )

    assert status == 200, data
    assert len(sent) == 1
    forwarded = json.loads(sent[0])
    assert forwarded["system"] == body["system"]
    assert IBAN not in sent[0].decode("utf-8")
    (entry,) = entries
    assert entry["verdict"] == "ok_with_unchecked_findings"


@pytest.mark.asyncio
async def test_an_untransformed_system_without_findings_passes_by_default(
    gateway: Gateway, tmp_path: Path
) -> None:
    body = claude_code_body("Working directory: /srv/projekt", stream=True)

    status, data, sent, entries = await _send(gateway, tmp_path, body, transform_system=False)

    assert status == 200, data
    assert json.loads(sent[0])["system"] == body["system"]
    assert entries[0]["verdict"] == "ok_with_unchecked_findings"


@pytest.mark.asyncio
async def test_the_billing_line_reaches_the_upstream_unchanged_with_a_transformed_system(
    gateway: Gateway, tmp_path: Path
) -> None:
    # A replaced billing line made the upstream answer 429 for subscription sign-ins.
    body = claude_code_body("Working directory: /home/testuser/projekt", stream=False)

    status, data, sent, _ = await _send(gateway, tmp_path, body)

    assert status == 200, data
    forwarded = json.loads(sent[0])
    assert forwarded["system"][0] == {"type": "text", "text": BILLING}
    assert "testuser" not in sent[0].decode("utf-8")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "line",
    [
        BILLING + " erika.beispiel@firma-test.de",
        "x-anthropic-billing-header: cc_version=2.1.332; cc_entrypoint=erika.beispiel@firma-test.de;",
        "x-anthropic-billing-header: cc_version=2.1.332; cc_entrypoint=cli; note=Mueller;",
    ],
)
async def test_anything_but_the_exact_billing_line_is_still_transformed(
    gateway: Gateway, tmp_path: Path, line: str
) -> None:
    body = claude_code_body("Working directory: /home/testuser/projekt", stream=False)
    body["system"][0]["text"] = line

    status, data, sent, _ = await _send(gateway, tmp_path, body)

    assert status == 200, data
    assert json.loads(sent[0])["system"][0]["text"] != line
