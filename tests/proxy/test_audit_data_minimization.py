"""Data minimization of the `proxy_request` v2 log: no value, no value hash, no salt file.

The session key (here the conversation UUID from `metadata.user_id`) is a credential: whoever
presents it to the proxy gets the session's tokens restored. No log and no debug file name may
carry it, neither plain nor shortened nor hashed.

Every key of every record is checked against an explicit allowlist, so a new field breaks
this test and has to be reviewed for what it reveals.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.audit import AuditLog
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

UPSTREAM = "https://upstream.test"
CONVERSATION = "7d4e2c1a-5555-6666-7777-888899990000"
NAME = "Müller"
IBAN = "DE89 3704 0044 0532 0130 00"
PHONE = "+49 211 5559021"
CVV = "847"
BIRTH_DATE = "04.07.1979"
EMAIL = "erika.beispiel@kunde-beispiel.example"
KEY_PREFIX = "sk" + "-ant-"
API_KEY = KEY_PREFIX + "api03" + "-ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zyxw"
PASSWORD = "Tr0ub4dor&3"
HEALTH = "Typ-2-Diabetes"
VALUES = (NAME, IBAN, PHONE, CVV, BIRTH_DATE, EMAIL, API_KEY, PASSWORD, HEALTH)
TEXT = (
    f"Sehr geehrte Frau {NAME}, bitte überweisen Sie auf {IBAN}. "
    f"Tel. {PHONE}, Mail {EMAIL}. Kreditkarte CVV {CVV}. "
    f"Geboren am {BIRTH_DATE}. Diagnose: {HEALTH} seit 2019. "
    f"Key {API_KEY}\nPasswort: {PASSWORD} (bitte nicht weitergeben)"
)
EXPECTED_CLASSES = {
    "IBAN", "PHONE", "CVV", "DATE_OF_BIRTH", "EMAIL", "ANTHROPIC_API_KEY", "PASSWORD",
}

TOP_KEYS = {
    "v", "event", "ts", "request_id", "session", "path", "streaming", "duration_ms",
    "verdict", "coverage", "fields", "outgoing",
}
COVERAGE_KEYS = {"checked_fields", "checked_keys", "unchecked_fields"}
CHECKED_KEYS = {"path", "status", "chars", "findings", "leaks"}
UNCHECKED_KEYS = {"path", "status", "reason", "chars", "observed"}
FINDING_KEYS = {"cls", "start", "end", "token", "policy", "confidence", "stage"}
LEAK_KEYS = {"kind", "cls", "start", "end"}
OBSERVED_KEYS = {"cls", "count"}
OUTGOING_KEYS = {"sha256", "bytes", "leakage", "upstream_status", "rescan"}
RESCAN_KEYS = {"status", "reason", "findings"}
RESCAN_FINDING_KEYS = {"path", "cls", "start", "end"}
HEX_FIELDS = {("request_id",), ("session",), ("outgoing", "sha256")}
LONG_HEX = re.compile(r"[0-9a-fA-F]{12,}")


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault" / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault" / "vault.key"))
    monkeypatch.delenv("PGW_AUDIT_LOG", raising=False)
    with Gateway() as instance:
        yield instance


def _body() -> dict:
    return {
        "model": "claude-x",
        "max_tokens": 128,
        "metadata": {"user_id": f"user_abc_account_def_session_{CONVERSATION}"},
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": TEXT}]},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "Send",
                        "input": {"empfaenger": EMAIL, IBAN: "Konto"},
                    }
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"}],
            },
        ],
    }


def _normalized(value: str) -> set[str]:
    forms = {value, value.lower(), re.sub(r"\s", "", value), re.sub(r"\s", "", value).lower()}
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 6:
        forms.add(digits)
    return {form for form in forms if form}


def _strings(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str]]:
    """Every string in a record, keys included, with its key path (list indexes dropped)."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield (*path, "<key>"), key
            yield from _strings(item, (*path, key))
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, path)
    elif isinstance(value, str):
        yield path, value


def _numbers(value: Any) -> Iterator[int | float]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _numbers(item)
    elif isinstance(value, list):
        for item in value:
            yield from _numbers(item)
    elif isinstance(value, int | float) and not isinstance(value, bool):
        yield value


def _check_keys(record: dict) -> None:
    assert set(record) == TOP_KEYS
    assert set(record["coverage"]) == COVERAGE_KEYS
    for item in record["fields"]:
        allowed = CHECKED_KEYS if item["status"] == "checked" else UNCHECKED_KEYS
        assert set(item) <= allowed
        for finding in item.get("findings", []):
            assert set(finding) <= FINDING_KEYS
        for leak in item.get("leaks", []):
            assert set(leak) <= LEAK_KEYS
        for observed in item.get("observed", []):
            assert set(observed) <= OBSERVED_KEYS
    assert set(record["outgoing"]) == OUTGOING_KEYS
    rescan = record["outgoing"]["rescan"]
    assert set(rescan) <= RESCAN_KEYS
    for hit in rescan["findings"]:
        assert set(hit) <= RESCAN_FINDING_KEYS


def _derived(key: str) -> set[str]:
    """The key in plain forms plus 8-character prefixes of common hex digests of them."""
    forms = {key, key.lower(), key.replace("-", ""), key.lower().replace("-", "")}
    derived = set(forms)
    for form in forms:
        for name in ("sha256", "sha1", "md5", "sha512", "blake2b", "sha3_256"):
            derived.add(hashlib.new(name, form.encode("utf-8")).hexdigest()[:8])
    return derived


async def _send(gateway: Gateway, audit_dir: Path, **overrides: Any) -> httpx.Response:
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir, **overrides)
    upstream = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})
        )
    )
    app = server.create_app(settings, gateway, client=upstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        return await client.post("/v1/messages", json=_body())


@pytest.mark.asyncio
async def test_the_audit_directory_holds_no_value_no_hash_and_no_salt(
    gateway: Gateway, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    audit_dir = state / "audit"
    response = await _send(gateway, audit_dir)

    assert response.status_code == 200
    assert sorted(path.name for path in state.iterdir()) == ["audit"]
    assert not list(tmp_path.rglob("*.salt"))
    files = sorted(audit_dir.rglob("*"))
    assert [path.name for path in files] == [f"audit-{files[0].name[6:16]}.jsonl"]
    raw = files[0].read_text(encoding="utf-8")
    (record,) = [json.loads(line) for line in raw.splitlines()]

    _check_keys(record)
    found = {f["cls"] for item in record["fields"] for f in item.get("findings", [])}
    assert EXPECTED_CLASSES <= found
    assert any(cls.startswith("PERSON") for cls in found)
    assert any(cls.startswith("HEALTH") for cls in found)

    secrets = [*VALUES, *_derived(CONVERSATION)]
    strings = list(_strings(record))
    random_paths = HEX_FIELDS | {("ts",)}
    scrubbed = raw
    for path, text in strings:
        if path in random_paths:
            scrubbed = scrubbed.replace(text, "")
    for value in secrets:
        for form in _normalized(value):
            assert form not in scrubbed
            assert json.dumps(form)[1:-1] not in scrubbed
            assert all(form not in text.lower() for p, text in strings if p not in random_paths)
    assert int(CVV) not in set(_numbers(record))

    for path, text in strings:
        if path not in HEX_FIELDS:
            assert not LONG_HEX.search(text), path
    remainder = raw
    for path, text in strings:
        if path in HEX_FIELDS:
            remainder = remainder.replace(text, "")
    assert not LONG_HEX.search(remainder)
    assert re.fullmatch(r"[0-9a-f]{12}", record["session"])
    assert re.fullmatch(r"[0-9a-f]{64}", record["outgoing"]["sha256"])
    assert re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", record["request_id"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+\+00:00", record["ts"])


@pytest.mark.asyncio
async def test_no_log_and_no_debug_file_name_carries_the_session_key(
    gateway: Gateway, tmp_path: Path
) -> None:
    old = tmp_path / "old" / "audit.jsonl"
    gateway.audit = AuditLog(old)
    audit_dir = tmp_path / "state" / "audit"
    dumps = tmp_path / "dumps"
    response = await _send(gateway, audit_dir, debug_dir=dumps)

    assert response.status_code == 200
    (dump,) = sorted(dumps.iterdir())
    (record,) = [json.loads(line) for line in next(audit_dir.glob("audit-*.jsonl")).open()]
    events = [json.loads(line) for line in old.read_text(encoding="utf-8").splitlines()]
    (event,) = [item for item in events if item["event"] == "proxy_request"]
    assert "session_key" not in event
    assert re.fullmatch(r"\d{8}T\d{6}\.\d{6}-[0-9a-f]{12}\.json", dump.name)
    assert dump.name[23:35] == record["session"]
    texts = [old.read_text(encoding="utf-8"), *(p.read_text() for p in audit_dir.iterdir())]
    texts += [dump.name]
    for form in _derived(CONVERSATION):
        assert all(form not in text.lower() for text in texts), form


TOOL_RECORD_KEYS = {"v", "event", "ts", "request_id", "streaming", "on_deny", "entries"}
TOOL_ENTRY_KEYS = {"tool", "path", "cls", "decision"}
"""The `tool_restore` record names the tool, the position, the class and the decision.

The tool name is the model's choice, escaped and cut to 64 characters; `path` is positional
like the v2 fields, so no key text is rendered; no value, no token and no hash of either.
"""


@pytest.mark.asyncio
async def test_the_tool_restore_record_holds_no_value(gateway: Gateway, tmp_path: Path) -> None:
    audit_dir = tmp_path / "state" / "audit"
    settings = ProxySettings(upstream_base_url=UPSTREAM, audit_dir=audit_dir)

    def reply(request: httpx.Request) -> httpx.Response:
        tokens = sorted(set(re.findall(r"<[A-Z_]+_\d{3}>", request.content.decode())))
        payload = {"command": " ".join(tokens), tokens[0]: [t.lower() for t in tokens]}
        block = {"type": "tool_use", "id": "t9", "name": "Bash\u200b", "input": payload}
        return httpx.Response(200, json={"content": [block]})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(reply))
    app = server.create_app(settings, gateway, client=upstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787"
    ) as client:
        response = await client.post("/v1/messages", json=_body())

    assert response.status_code == 200
    (path,) = audit_dir.glob("tool-restore-*.jsonl")
    raw = path.read_text(encoding="utf-8")
    (record,) = [json.loads(line) for line in raw.splitlines()]
    assert set(record) == TOOL_RECORD_KEYS
    assert record["event"] == "tool_restore"
    assert record["entries"]
    for item in record["entries"]:
        assert set(item) == TOOL_ENTRY_KEYS
        assert item["decision"] == "kept"
    remainder = raw.replace(record["request_id"], "").replace(record["ts"], "")
    for value in [*VALUES, CONVERSATION, CONVERSATION.replace("-", "")]:
        for form in _normalized(value):
            for text in (remainder, response.text):
                assert form not in text
                assert json.dumps(form)[1:-1] not in text
    assert not re.search(r"<[A-Z_]+_\d{3}>", raw)
    strings = list(_strings(record))
    for key_path, text in strings:
        if key_path != ("request_id",):
            assert not LONG_HEX.search(text), key_path
