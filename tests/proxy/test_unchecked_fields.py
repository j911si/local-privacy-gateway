"""Findings in fields the proxy does not transform block the request unless allowed."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.model import ConfigError
from privacy_gateway_proxy import audit_trail, cli, server
from privacy_gateway_proxy.settings import ProxySettings, load_settings

UPSTREAM = "https://upstream.test"
MAIL = "erika.beispiel@firma-test.de"
IBAN = "DE89370400440532013000"
VALUES = (MAIL, IBAN)
CONVERSATION = "0b1c2d3e-5f6a-4b7c-8d9e-0a1b2c3d4e5f"
BASE: dict[str, Any] = {
    "model": "claude-x",
    "max_tokens": 16,
    "metadata": {"user_id": f"user_a_account_b_session_{CONVERSATION}"},
    "messages": [{"role": "user", "content": [{"type": "text", "text": "hallo"}]}],
}


def _with_thinking(thinking: str) -> dict[str, Any]:
    return {
        **BASE,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "hallo"}]},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": thinking, "signature": "c2ln"},
                    {"type": "text", "text": "ok"},
                ],
            },
            {"role": "user", "content": [{"type": "text", "text": "weiter"}]},
        ],
    }


CASES: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {
    "tools_description": (
        {**BASE, "tools": [{"name": "T", "description": f"Mail an {MAIL}", "input_schema": {}}]},
        {},
        "tools[0].description",
    ),
    "tools_input_schema": (
        {
            **BASE,
            "tools": [
                {
                    "name": "T",
                    "description": "Ein Werkzeug.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"to": {"type": "string", "description": f"z. B. {MAIL}"}},
                    },
                }
            ],
        },
        {},
        "tools[0].input_schema",
    ),
    "system_untransformed": (
        {**BASE, "system": f"Kontakt {MAIL}, IBAN {IBAN}"},
        {"transform_system": False},
        "system",
    ),
    "system_blocks_untransformed": (
        {**BASE, "system": [{"type": "text", "text": f"IBAN {IBAN}"}]},
        {"transform_system": False},
        "system[0]",
    ),
    "thinking_block": (_with_thinking(f"IBAN {IBAN}"), {}, "messages[1].content[0]"),
    "unknown_field": ({**BASE, "x_extra": {"note": f"IBAN {IBAN}"}}, {}, "x_extra"),
}


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


class Run:
    """The outcome of one request through the proxy."""

    def __init__(self, status: int, body: bytes, sent: list[bytes], entries: list[dict]) -> None:
        self.status = status
        self.body = body
        self.sent = sent
        self.entries = entries


async def _send(gateway: Gateway, tmp_path: Path, body: dict, **overrides: Any) -> Run:
    seen: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if json.loads(request.content).get("stream") is True:
            return httpx.Response(
                200, content=b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                headers={"content-type": "text/event-stream"},
            )
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
    return Run(response.status_code, response.content, [r.content for r in seen], entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("case", sorted(CASES))
async def test_a_finding_in_an_unchecked_field_blocks_before_the_upstream(
    gateway: Gateway, tmp_path: Path, case: str, streaming: bool
) -> None:
    body, overrides, field = CASES[case]
    body = {**body, "stream": True} if streaming else body

    run = await _send(gateway, tmp_path, body, **overrides)

    assert run.sent == []
    assert run.status == 422
    error = json.loads(run.body)["error"]
    assert error["type"] == "privacy_gateway_leak"
    assert all(value not in run.body.decode() for value in VALUES)
    (entry,) = run.entries
    assert entry["verdict"] == "blocked"
    assert entry["streaming"] is streaming
    findings = entry["outgoing"]["rescan"]["findings"]
    assert findings
    assert all(item["path"].startswith(field) for item in findings)
    assert all(set(item) == {"path", "cls", "start", "end"} for item in findings)
    assert all(isinstance(item["start"], int) and item["end"] > item["start"] for item in findings)
    log = json.dumps(run.entries)
    assert all(value not in log for value in VALUES)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(CASES))
async def test_the_opt_out_forwards_unchecked_findings_as_before(
    gateway: Gateway, tmp_path: Path, case: str
) -> None:
    body, overrides, _ = CASES[case]

    run = await _send(gateway, tmp_path, body, unchecked_fields="allow", **overrides)

    assert run.status == 200
    assert len(run.sent) == 1
    assert json.loads(run.sent[0]) == {
        **json.loads(json.dumps(body)), **_checked_part(json.loads(run.sent[0]))
    }
    (entry,) = run.entries
    assert entry["verdict"] == "ok_with_unchecked_findings"


def _checked_part(sent: dict) -> dict:
    return {"messages": sent["messages"]}


@pytest.mark.asyncio
async def test_a_request_without_unchecked_findings_is_forwarded(
    gateway: Gateway, tmp_path: Path
) -> None:
    body = {
        **BASE,
        "tools": [{"name": "Read", "description": "Reads a file.", "input_schema": {}}],
        "messages": [{"role": "user", "content": f"Bitte IBAN {IBAN} pruefen."}],
    }

    run = await _send(gateway, tmp_path, body)

    assert run.status == 200
    assert len(run.sent) == 1
    assert IBAN not in run.sent[0].decode()
    assert run.entries[0]["verdict"] == "ok"


@pytest.mark.asyncio
async def test_placeholders_and_public_example_values_never_block(
    gateway: Gateway, tmp_path: Path
) -> None:
    first = await _send(
        gateway, tmp_path, {**BASE, "messages": [{"role": "user", "content": f"IBAN {IBAN}"}]}
    )
    token = re.search(r"<IBAN_\d+>", first.sent[0].decode()).group(0)
    body = {
        **_with_thinking(f"Die Nutzerin nannte {token}; Beispiel <EMAIL_007>."),
        "tools": [
            {
                "name": "Mail",
                "description": "Send mail, e.g. to someone@example.com or ops@mail.example.org.",
                "input_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema"},
            }
        ],
    }

    run = await _send(gateway, tmp_path, body)

    assert run.status == 200, run.body
    assert len(run.sent) == 1
    sent = json.loads(run.sent[0])
    assert sent["messages"][1]["content"][0] == body["messages"][1]["content"][0]


@pytest.mark.asyncio
async def test_the_signed_thinking_block_is_never_changed(
    gateway: Gateway, tmp_path: Path
) -> None:
    body = _with_thinking(f"IBAN {IBAN}")

    allowed = await _send(gateway, tmp_path / "a", body, unchecked_fields="allow")
    blocked = await _send(gateway, tmp_path / "b", body)

    assert json.loads(allowed.sent[0])["messages"][1]["content"][0] == {
        "type": "thinking", "thinking": f"IBAN {IBAN}", "signature": "c2ln"
    }
    assert blocked.sent == []


def test_the_mode_defaults_to_block() -> None:
    assert ProxySettings().unchecked_fields == "block"
    assert load_settings(env={}).unchecked_fields == "block"


@pytest.mark.parametrize("value", ["block", "allow"])
def test_the_mode_comes_from_env(value: str) -> None:
    assert load_settings(env={"PGW_PROXY_UNCHECKED_FIELDS": value}).unchecked_fields == value


@pytest.mark.parametrize("value", ["", "off", "warn", "ALLOW "])
def test_an_unknown_mode_stops_the_start(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env={"PGW_PROXY_UNCHECKED_FIELDS": value})


def test_the_opt_out_warns_at_startup(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        cli.log_startup(ProxySettings(unchecked_fields="allow"))

    assert "unchecked_fields=allow" in caplog.text
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("PGW_PROXY_UNCHECKED_FIELDS=allow" in text for text in warnings)


def test_the_default_mode_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        cli.log_startup(ProxySettings())

    assert "unchecked_fields=block" in caplog.text
    assert "PGW_PROXY_UNCHECKED_FIELDS" not in caplog.text


@pytest.mark.asyncio
async def test_a_subscription_style_system_prompt_with_a_home_path_is_blocked(
    gateway: Gateway, tmp_path: Path
) -> None:
    system = [
        {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
        {"type": "text", "text": "Working directory: /home/testuser/projekt"},
    ]
    body = {**BASE, "system": system}

    blocked = await _send(gateway, tmp_path / "a", body, transform_system=False)
    allowed = await _send(
        gateway, tmp_path / "b", body, transform_system=False, unchecked_fields="allow"
    )

    assert blocked.sent == []
    assert blocked.entries[0]["outgoing"]["rescan"]["findings"][0]["cls"] == "PERSON_USERNAME"
    assert json.loads(allowed.sent[0])["system"] == system


DEVICE = "a3" * 32
ACCOUNT = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
SESSION = "0b1c2d3e-5f6a-4b7c-8d9e-0a1b2c3d4e5f"
CREDIT_CARD_LIKE = "0b1c2d3e-1111-2222-3333-444444444444"
JSON_USER_ID = (
    f'{{"device_id":"{DEVICE}","account_uuid":"{ACCOUNT}","session_id":"{CREDIT_CARD_LIKE}"}}'
)
LEGACY_USER_ID = f"user_{DEVICE}_account_{ACCOUNT}_session_{CREDIT_CARD_LIKE}"
BILLING = "x-anthropic-billing-header: cc_version=2.1.332.18b; cc_entrypoint=cli;"


def test_the_synthetic_session_id_really_is_a_credit_card_finding(gateway: Gateway) -> None:
    hits = gateway.session("probe").rescan(f"user_a_account_b_session_{CREDIT_CARD_LIKE}")

    assert [hit.data_class for hit in hits] == ["CREDIT_CARD"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_id",
    [
        JSON_USER_ID,
        JSON_USER_ID.replace(ACCOUNT, ""),
        LEGACY_USER_ID,
        LEGACY_USER_ID.replace(ACCOUNT, ""),
    ],
)
async def test_the_exact_claude_code_user_id_formats_pass(
    gateway: Gateway, tmp_path: Path, user_id: str
) -> None:
    run = await _send(gateway, tmp_path, {**BASE, "metadata": {"user_id": user_id}})

    assert run.status == 200, run.body
    assert len(run.sent) == 1
    assert json.loads(run.sent[0])["metadata"] == {"user_id": user_id}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_id",
    [
        f"user_a_account_b_session_{CREDIT_CARD_LIKE}",
        JSON_USER_ID.replace(DEVICE, MAIL),
        JSON_USER_ID[:-1] + f',"note":"{MAIL}"}}',
        JSON_USER_ID[:-1] + f',"device_id":"{IBAN}"}}',
        JSON_USER_ID.replace('","account_uuid"', ' ","account_uuid"'),
        JSON_USER_ID.replace(DEVICE, DEVICE.upper()),
        LEGACY_USER_ID + f" {MAIL}",
        f"user_{DEVICE}_account_{MAIL}_session_{SESSION}",
    ],
)
async def test_any_other_user_id_is_checked_and_blocks_on_a_finding(
    gateway: Gateway, tmp_path: Path, user_id: str
) -> None:
    run = await _send(gateway, tmp_path, {**BASE, "metadata": {"user_id": user_id}})

    assert run.status == 422
    assert run.sent == []
    paths = [item["path"] for item in run.entries[0]["outgoing"]["rescan"]["findings"]]
    assert paths and all(path == "metadata.user_id" for path in paths)


@pytest.mark.asyncio
async def test_another_metadata_field_with_a_mail_blocks(gateway: Gateway, tmp_path: Path) -> None:
    body = {**BASE, "metadata": {"user_id": JSON_USER_ID, "contact": MAIL}}

    run = await _send(gateway, tmp_path, body)

    assert run.status == 422
    assert run.sent == []
    paths = [item["path"] for item in run.entries[0]["outgoing"]["rescan"]["findings"]]
    assert "metadata.contact" in paths


def _system(*blocks: dict[str, Any]) -> dict[str, Any]:
    return {**BASE, "system": [*blocks, {"type": "text", "text": "You are a helpful CLI."}]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "line",
    [BILLING, BILLING.replace("2.1.332.18b", "2.1.40").replace("=cli;", "=sdk-ts;")],
)
async def test_the_exact_billing_line_in_an_unchecked_system_passes(
    gateway: Gateway, tmp_path: Path, line: str
) -> None:
    body = _system({"type": "text", "text": line})

    run = await _send(gateway, tmp_path, body, transform_system=False)

    assert run.status == 200, run.body
    assert json.loads(run.sent[0])["system"] == body["system"]
    assert run.entries[0]["verdict"] == "ok_with_unchecked_findings"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("blocks", "position"),
    [
        ([{"type": "text", "text": BILLING + " x-api-key: sk-test-0123456789abcdef"}], 0),
        ([{"type": "text", "text": BILLING + " cc_extra=1;"}], 0),
        ([{"type": "text", "text": BILLING + f" {MAIL}"}], 0),
        ([{"type": "text", "text": BILLING + "\nx-api-key: sk-test-0123456789abcdef"}], 0),
        ([{"type": "text", "text": "x-api-key: sk-test-0123456789abcdef"}], 0),
        ([{"type": "text", "text": BILLING, "cache_control": {"type": "ephemeral"}}], 0),
        ([{"type": "text", "text": "Hi."}, {"type": "text", "text": BILLING}], 1),
    ],
)
async def test_anything_but_the_exact_billing_block_blocks(
    gateway: Gateway, tmp_path: Path, blocks: list[dict[str, Any]], position: int
) -> None:
    run = await _send(gateway, tmp_path, _system(*blocks), transform_system=False)

    assert run.status == 422
    assert run.sent == []
    paths = [item["path"] for item in run.entries[0]["outgoing"]["rescan"]["findings"]]
    assert any(path.startswith(f"system[{position}]") for path in paths)


@pytest.mark.asyncio
async def test_non_sensitive_classes_are_only_reported(gateway: Gateway, tmp_path: Path) -> None:
    tools = [
        {
            "name": "Review",
            "description": "Mention `@name` or `@reviewer`; docs on claude.ai and "
            "https://docs.claude.ai/guide.",
            "input_schema": {},
        }
    ]

    run = await _send(gateway, tmp_path, {**BASE, "tools": tools})

    assert run.status == 200, run.body
    assert json.loads(run.sent[0])["tools"] == tools
    (entry,) = run.entries
    assert entry["verdict"] == "ok_with_unchecked_findings"
    classes = {item["cls"] for item in entry["outgoing"]["rescan"]["findings"]}
    assert classes and not classes & audit_trail.UNCHECKED_BLOCKING_CLASSES


def _marking_scan(cls: str):
    def scan(session: Any, leaves: list, deadline: float | None = None) -> list:
        return [
            audit_trail.Hit(leaf.path, cls, 0, 4) for leaf in leaves if "MARK" in leaf.text
        ]

    return scan


TOOLS_WITH_MARK = [{"name": "T", "description": "MARK here", "input_schema": {}}]


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", sorted(audit_trail.UNCHECKED_BLOCKING_CLASSES))
async def test_every_blocking_class_blocks_in_an_unchecked_field(
    gateway: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cls: str
) -> None:
    monkeypatch.setattr(audit_trail, "scan", _marking_scan(cls))

    run = await _send(gateway, tmp_path, {**BASE, "tools": TOOLS_WITH_MARK})

    assert run.status == 422
    assert run.sent == []
    assert run.entries[0]["outgoing"]["rescan"]["findings"] == [
        {"path": "tools[0].description", "cls": cls, "start": 0, "end": 4}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls", ["FQDN", "URL", "SOCIAL_MEDIA_HANDLE", "ORGANIZATION_NAME", "PERSON_INITIALS", "CITY"]
)
async def test_other_classes_do_not_block_in_an_unchecked_field(
    gateway: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cls: str
) -> None:
    monkeypatch.setattr(audit_trail, "scan", _marking_scan(cls))

    run = await _send(gateway, tmp_path, {**BASE, "tools": TOOLS_WITH_MARK})

    assert run.status == 200
    assert len(run.sent) == 1
    assert run.entries[0]["verdict"] == "ok_with_unchecked_findings"


def test_every_redact_class_of_the_default_config_blocks(gateway: Gateway) -> None:
    redact = {
        item.name for item in gateway.config.registry if item.policy.name == "REDACT"
    }

    assert redact
    assert redact <= audit_trail.UNCHECKED_BLOCKING_CLASSES
    assert audit_trail.UNCHECKED_BLOCKING_CLASSES <= {
        item.name for item in gateway.config.registry
    }


IDENTITY_SAMPLES = {
    "DATE_OF_BIRTH": "Geburtsdatum: 12.03.1980",
    "BANK_ACCOUNT": "Kontonummer 1234567890",
    "PASSPORT_ID": "Reisepass C01X00T47",
    "NATIONAL_ID": "Personalausweis L01X00T47",
    "SOCIAL_SECURITY_ID": "SSN 078-05-1120",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", sorted(IDENTITY_SAMPLES))
async def test_a_detected_identity_value_in_a_tool_description_blocks(
    gateway: Gateway, tmp_path: Path, cls: str
) -> None:
    tools = [{"name": "T", "description": IDENTITY_SAMPLES[cls], "input_schema": {}}]

    run = await _send(gateway, tmp_path, {**BASE, "tools": tools})

    assert run.status == 422
    assert run.sent == []
    assert cls in {item["cls"] for item in run.entries[0]["outgoing"]["rescan"]["findings"]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "Version 2.1.332.18b, Stand 26.11.2026",
        "Termin am 01.02.2026",
        "since 2024-06-01, v1.2.3-beta",
    ],
)
async def test_versions_and_plain_dates_do_not_block(
    gateway: Gateway, tmp_path: Path, text: str
) -> None:
    tools = [{"name": "T", "description": text, "input_schema": {}}]

    run = await _send(gateway, tmp_path, {**BASE, "tools": tools})

    assert run.status == 200, run.body
    assert len(run.sent) == 1
