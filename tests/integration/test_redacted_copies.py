"""Every copy of a redacted value is redacted; the value stays in memory only."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway, LeakageError
from privacy_gateway.leakage import check_leakage
from privacy_gateway.model import DetectionReport
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

PIN = "482913"
PASSWORD = "Kx7#mQ2vRt9z"
PIN_TEXT = f"Zugangs-PIN: {PIN}. Bitte merken: {PIN}"
PIN_OUTPUT = "Zugangs-PIN: <PIN_REDACTED>. Bitte merken: <PIN_REDACTED>"
CONVERSATION = "user_a_account_b_session_0b1c2d3e-1a2b-4c3d-8e4f-5a6b7c8d9e0f"


def _empty(_text: str) -> DetectionReport:
    return DetectionReport(findings=[], entities={}, stage_stats={})


def test_a_document_redacts_the_unlabelled_copy_of_a_pin(gateway: Gateway) -> None:
    assert gateway.pseudonymize(PIN_TEXT).text == PIN_OUTPUT


def test_a_session_redacts_the_copy_in_the_same_and_in_a_later_turn(gateway: Gateway) -> None:
    session = gateway.session("redacted-copies")
    assert session.pseudonymize(PIN_TEXT) == PIN_OUTPUT
    assert session.pseudonymize(f"Nochmal: {PIN}") == "Nochmal: <PIN_REDACTED>"
    assert session.rescan(f"Antwort mit {PIN}") != []


def test_the_second_copy_of_a_labelled_password_is_redacted(gateway: Gateway) -> None:
    session = gateway.session("redacted-password")
    output = session.pseudonymize(f"Passwort: {PASSWORD}\nDann: login admin {PASSWORD}")
    assert PASSWORD not in output
    assert output.count("<PASSWORD_REDACTED>") == 2


def test_a_short_pin_is_not_replaced_inside_longer_numbers(gateway: Gateway) -> None:
    text = "PIN: 1234. Bestellung 12345, Kunde 51234, Code 1234."
    assert gateway.pseudonymize(text).text == (
        "PIN: <PIN_REDACTED>. Bestellung 12345, Kunde 51234, Code <PIN_REDACTED>."
    )


def test_the_leak_check_blocks_a_remaining_copy_of_a_redacted_value(gateway: Gateway) -> None:
    registry = gateway.config.registry
    with pytest.raises(LeakageError) as error:
        check_leakage(
            "Zugangs-PIN: <PIN_REDACTED>. Bitte merken: 482913",
            {},
            _empty,
            registry,
            redacted={PIN: "PIN"},
        )
    assert [(leak.kind, leak.data_class) for leak in error.value.leaks] == [
        ("original_value", "PIN")
    ]
    assert PIN not in str(error.value)
    check_leakage("Zugangs-PIN: <PIN_REDACTED>.", {}, _empty, registry, redacted={PIN: "PIN"})


def test_a_redacted_value_never_reaches_vault_or_audit(
    gateway: Gateway, gateway_env: dict[str, str]
) -> None:
    session = gateway.session("redacted-storage")
    session.pseudonymize(PIN_TEXT)
    session.pseudonymize(f"Nochmal: {PIN}")
    assert all(PIN not in entry.value for entry in session.entries().values())
    gateway.close()
    vault = Path(gateway_env["PGW_VAULT_DB"]).parent
    raw = b"".join(path.read_bytes() for path in sorted(vault.glob("vault.db*")))
    assert raw and PIN.encode() not in raw
    assert PIN not in Path(gateway_env["PGW_AUDIT_LOG"]).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_the_proxy_does_not_send_the_second_pin_copy(gateway: Gateway) -> None:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content.decode("utf-8"))
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = server.create_app(
        ProxySettings(upstream_base_url="https://upstream.test"), gateway, client=upstream
    )

    def body(text: str) -> dict:
        return {
            "model": "claude-x",
            "max_tokens": 16,
            "metadata": {"user_id": CONVERSATION},
            "messages": [{"role": "user", "content": text}],
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        first = await client.post("/v1/messages", json=body(PIN_TEXT))
        later = await client.post("/v1/messages", json=body(f"Nochmal: {PIN}"))
    assert first.status_code == 200
    assert later.status_code == 200
    assert PIN not in sent[0] and PIN not in sent[1]
    assert json.loads(sent[0])["messages"][0]["content"][-1]["text"] == PIN_OUTPUT
