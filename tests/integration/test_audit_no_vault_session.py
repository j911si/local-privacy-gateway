"""No audit file carries the vault session id, which is a handle for `pgw restore`.

Library, CLI and proxy run against one vault; afterwards every file the run wrote (the old
log, the daily v2 files, `tool-restore-*.jsonl`, debug dumps) is searched raw for each vault
session id, its hyphenated and hyphenless form and its 8-character prefix.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings
from tests.integration.test_cli import run

TEXT = "Sehr geehrte Frau Müller, bitte überweisen Sie auf DE89 3704 0044 0532 0130 00.\n"
UPSTREAM = "https://upstream.test"
AUDIT_ID = re.compile(r"^[0-9a-f]{12}$")
VAULT_EVENTS = {"pseudonymize", "session_pseudonymize", "restore"}


def _forms(session_id: str) -> set[str]:
    hyphenated = str(uuid.UUID(session_id))
    forms = {session_id, hyphenated, session_id.replace("-", ""), hyphenated.replace("-", "")}
    return {form.lower() for form in forms} | {form.lower()[:8] for form in forms}


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def _proxy_round(gateway: Gateway, audit_dir: Path, dumps: Path) -> httpx.Response:
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir, debug_dir=dumps)

    def reply(request: httpx.Request) -> httpx.Response:
        tokens = sorted(set(re.findall(r"<[A-Z_]+_\d{3}>", request.content.decode())))
        block = {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"cmd": " ".join(tokens)}}
        return httpx.Response(200, json={"content": [block]})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(reply))
    app = server.create_app(settings, gateway, client=upstream)
    body = {
        "model": "claude-x",
        "max_tokens": 64,
        "metadata": {"user_id": "user_abc_account_def_session_7d4e2c1a-1111-2222-3333-444455556666"},
        "messages": [{"role": "user", "content": [{"type": "text", "text": TEXT}]}],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        return await client.post("/v1/messages", json=body)


@pytest.mark.asyncio
async def test_no_audit_file_carries_the_vault_session_id(
    gateway: Gateway, gateway_env: dict[str, str], tmp_path: Path
) -> None:
    old_log = Path(gateway_env["PGW_AUDIT_LOG"])
    single = gateway.pseudonymize(TEXT)
    gateway.restore(single.text, single.session_id)
    session = gateway.session()
    pseudonymized = session.pseudonymize(TEXT)
    session.pseudonymize(TEXT)
    session.restore(pseudonymized)
    library_events = _events(old_log)

    source = tmp_path / "in.txt"
    source.write_text(TEXT, encoding="utf-8")
    session_file = tmp_path / "session.txt"
    cli = run(gateway_env, "pseudonymize", str(source), "--session-file", str(session_file))
    assert cli.returncode == 0, cli.stderr
    restored = run(
        gateway_env, "restore", "--session", session_file.read_text(encoding="utf-8"),
        stdin=cli.stdout,
    )
    assert restored.returncode == 0, restored.stderr
    assert restored.stdout == TEXT
    keyed = run(gateway_env, "pseudonymize", str(source), "--session-key", "kunde-42")
    assert keyed.returncode == 0, keyed.stderr

    state = tmp_path / "state"
    response = await _proxy_round(gateway, state / "audit", tmp_path / "dumps")
    assert response.status_code == 200

    session_ids = {single.session_id, session.session_id, session_file.read_text()}
    session_ids |= {info.id for info in gateway.vault.list_sessions()}
    assert len(session_ids) >= 4
    files = [path for path in tmp_path.rglob("*") if path.is_file()]
    files = [path for path in files if "vault" not in path.parts and path != session_file]
    assert old_log in files
    assert list((state / "audit").glob("audit-*.jsonl"))
    assert list((state / "audit").glob("tool-restore-*.jsonl"))
    assert list((tmp_path / "dumps").iterdir())
    haystacks = [path.read_text(encoding="utf-8").lower() for path in files if path != source]
    haystacks += [path.name.lower() for path in files]
    for session_id in session_ids:
        for form in _forms(session_id):
            assert all(form not in text for text in haystacks), form

    events = [event for event in _events(old_log) if event["event"] in VAULT_EVENTS]
    assert events
    for event in events:
        assert "session_id" not in event
        assert AUDIT_ID.fullmatch(event["audit_id"])
    first, first_restore, *session_events = [event["audit_id"] for event in library_events]
    assert first == first_restore
    assert len(session_events) == 3 and len(set(session_events)) == 1
    assert first != session_events[0]
    cli_pseudonymize, cli_restore = (event["audit_id"] for event in events[5:7])
    assert cli_pseudonymize != cli_restore
