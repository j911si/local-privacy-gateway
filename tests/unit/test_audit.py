"""Tests for the JSON Lines audit log."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.audit import AuditLog, RequestAuditLog, load_salt, rotate

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _read(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_pseudonymize_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).pseudonymize("s1", {"IBAN": 1}, 3, "ok", 42)
    (event,) = _read(path)
    assert event["event"] == "pseudonymize"
    assert event["session_id"] == "s1"
    assert "doc_sha256" not in event
    assert event["counts"] == {"IBAN": 1}
    assert event["token_count"] == 3
    assert event["leakage"] == "ok"
    assert event["duration_ms"] == 42
    assert datetime.fromisoformat(str(event["ts"])).tzinfo is not None


def test_session_pseudonymize_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).session_pseudonymize("s1", 2, 3, "ok", 17)
    (event,) = _read(path)
    assert event["event"] == "session_pseudonymize"
    assert event["session_id"] == "s1"
    assert event["new_tokens"] == 2
    assert event["reused_tokens"] == 3
    assert event["leakage"] == "ok"
    assert event["duration_ms"] == 17
    assert datetime.fromisoformat(str(event["ts"])).tzinfo is not None


def test_proxy_request_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).proxy_request(
        session_key="conv-1",
        path="/v1/messages",
        fields=4,
        tokens=2,
        leakage="ok",
        streaming=True,
        duration_ms=31,
        system_transformed=False,
    )
    AuditLog(path).proxy_request(
        session_key="conv-2",
        path="/v1/messages",
        fields=4,
        tokens=2,
        leakage="ok",
        streaming=True,
        duration_ms=31,
    )
    event, default_event = _read(path)
    assert event["event"] == "proxy_request"
    assert event["session_key"] == "conv-1"
    assert event["path"] == "/v1/messages"
    assert event["fields"] == 4
    assert event["tokens"] == 2
    assert event["leakage"] == "ok"
    assert event["streaming"] is True
    assert event["duration_ms"] == 31
    assert event["system_transformed"] is False
    assert default_event["system_transformed"] is True
    assert datetime.fromisoformat(str(event["ts"])).tzinfo is not None


def test_restore_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).restore("s1", 4, 1, "lenient")
    (event,) = _read(path)
    assert event["event"] == "restore"
    assert event["session_id"] == "s1"
    assert event["restored_count"] == 4
    assert event["unknown_token_count"] == 1
    assert event["mode"] == "lenient"


def test_vault_purge_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).vault_purge(2)
    (event,) = _read(path)
    assert event["event"] == "vault_purge"
    assert event["sessions"] == 2


def test_error_event_has_expected_keys(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).error(exc_type="RuntimeError", stage="pattern")
    (event,) = _read(path)
    assert event["event"] == "error"
    assert event["exc_type"] == "RuntimeError"
    assert event["stage"] == "pattern"


def test_events_are_appended(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.vault_purge(1)
    log.error(exc_type="VaultError", stage="vault")
    log.restore("s1", 1, 0, "strict")
    assert [event["event"] for event in _read(path)] == ["vault_purge", "error", "restore"]


def test_file_and_parent_directory_permissions(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    AuditLog(path).vault_purge(1)
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700


def test_existing_file_and_directory_permissions_are_corrected(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir()
    os.chmod(path.parent, 0o755)
    path.touch()
    os.chmod(path, 0o644)

    AuditLog(path).vault_purge(1)

    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700


def test_disabled_log_writes_nothing(tmp_path: Path) -> None:
    log = AuditLog(None)
    log.pseudonymize("s1", {"IBAN": 1}, 3, "ok", 42)
    log.session_pseudonymize("s1", 1, 0, "ok", 1)
    log.proxy_request("conv-1", "/v1/messages", 1, 1, "ok", False, 1)
    log.restore("s1", 1, 0, "strict")
    log.vault_purge(1)
    log.error(exc_type="RuntimeError", stage="pattern")
    assert list(tmp_path.iterdir()) == []


def test_no_stored_value_appears_in_the_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(path))
    text = (FIXTURES_DIR / "customer_letter_de.txt").read_text(encoding="utf-8")

    with Gateway() as gateway:
        result = gateway.pseudonymize(text)
        entries = gateway.vault.load(result.session_id)

    # ponytail: timestamps are random digits and would collide with short numeric values
    content = "\n".join(
        json.dumps({k: v for k, v in event.items() if k != "ts"}, ensure_ascii=False)
        for event in _read(path)
    )
    assert entries
    for entry in entries.values():
        for value in [entry.value, *entry.surface_forms]:
            assert value not in content, value


NOW = datetime(2026, 11, 9, 7, 0, tzinfo=UTC)


def _daily(directory: Path, day: str) -> Path:
    path = directory / f"audit-{day}.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    return path


def test_request_log_writes_a_v2_line_into_the_utc_day_file(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    log = RequestAuditLog(directory, clock=lambda: NOW)
    path = log.write("proxy_request", {"verdict": "ok"})
    assert path == directory / "audit-2026-11-09.jsonl"
    (record,) = _read(path)
    assert list(record)[:3] == ["v", "event", "ts"]
    assert record["v"] == 2
    assert record["event"] == "proxy_request"
    assert record["ts"] == "2026-11-09T07:00:00+00:00"
    assert record["verdict"] == "ok"
    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_request_log_appends(tmp_path: Path) -> None:
    log = RequestAuditLog(tmp_path / "audit", clock=lambda: NOW)
    log.write("proxy_request", {"n": 1})
    path = log.write("proxy_request", {"n": 2})
    assert [record["n"] for record in _read(path)] == [1, 2]


def test_salt_is_created_once_beside_the_directory(tmp_path: Path) -> None:
    first = RequestAuditLog(tmp_path / "audit").value_hmac("DE89370400440532013000")
    salt_path = tmp_path / "audit.salt"
    assert len(salt_path.read_bytes()) == 32
    assert stat.S_IMODE(os.stat(salt_path).st_mode) == 0o600
    second = RequestAuditLog(tmp_path / "audit").value_hmac("DE89370400440532013000")
    assert first == second
    assert re.fullmatch(r"[0-9a-f]{16}", first)
    assert first != RequestAuditLog(tmp_path / "audit").value_hmac("DE00000000000000000000")


def test_a_damaged_salt_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "audit.salt").write_bytes(b"short")
    with pytest.raises(ValueError, match="unexpected size"):
        load_salt(tmp_path / "audit.salt")


def test_hmac_differs_between_installations(tmp_path: Path) -> None:
    one = RequestAuditLog(tmp_path / "a" / "audit").value_hmac("Müller")
    two = RequestAuditLog(tmp_path / "b" / "audit").value_hmac("Müller")
    assert one != two


def test_rotation_deletes_180_days_and_keeps_179_and_foreign_files(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    directory.mkdir()
    today = NOW.date()
    old = _daily(directory, (today - timedelta(days=180)).isoformat())
    older = _daily(directory, (today - timedelta(days=400)).isoformat())
    kept = _daily(directory, (today - timedelta(days=179)).isoformat())
    foreign = directory / "notes.jsonl"
    foreign.write_text("x", encoding="utf-8")
    lookalike = directory / "audit-2020-01-01.jsonl.bak"
    lookalike.write_text("x", encoding="utf-8")
    RequestAuditLog(directory, clock=lambda: NOW).write("proxy_request", {})
    assert not old.exists()
    assert not older.exists()
    assert kept.exists()
    assert foreign.exists()
    assert lookalike.exists()
    assert (directory / "audit-2026-11-09.jsonl").exists()


def test_rotation_runs_once_per_day_and_process(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    clock = [NOW]
    log = RequestAuditLog(directory, clock=lambda: clock[0])
    log.write("proxy_request", {})
    stale = _daily(directory, (NOW.date() - timedelta(days=200)).isoformat())
    log.write("proxy_request", {})
    assert stale.exists()
    clock[0] = NOW + timedelta(days=1)
    log.write("proxy_request", {})
    assert not stale.exists()


def test_rotate_returns_what_it_removed(tmp_path: Path) -> None:
    old = _daily(tmp_path, "2026-01-01")
    _daily(tmp_path, "2026-11-01")
    assert rotate(tmp_path, date(2026, 11, 9)) == [old]
