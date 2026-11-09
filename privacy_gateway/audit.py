"""Value-free JSON Lines audit log."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

DAILY_FILE = re.compile(r"^audit-(\d{4}-\d{2}-\d{2})\.jsonl$")
RETENTION_DAYS = 180
SALT_BYTES = 32
SALT_NAME = "audit.salt"
HMAC_HEX_CHARS = 16
NO_HMAC_CLASSES = frozenset({"PIN", "PASSWORD"})
RECORD_VERSION = 2
APPEND_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW


class AuditLog:
    """Appends one JSON object per event; disabled when path is None."""

    def __init__(self, path: Path | None) -> None:
        self._path = Path(path) if path is not None else None

    def pseudonymize(
        self,
        session_id: str,
        counts: dict[str, int],
        token_count: int,
        leakage: str,
        duration_ms: int,
    ) -> None:
        self._write(
            "pseudonymize",
            session_id=session_id,
            counts=counts,
            token_count=token_count,
            leakage=leakage,
            duration_ms=duration_ms,
        )

    def session_pseudonymize(
        self,
        session_id: str,
        new_tokens: int,
        reused_tokens: int,
        leakage: str,
        duration_ms: int,
    ) -> None:
        self._write(
            "session_pseudonymize",
            session_id=session_id,
            new_tokens=new_tokens,
            reused_tokens=reused_tokens,
            leakage=leakage,
            duration_ms=duration_ms,
        )

    def proxy_request(
        self,
        session_key: str,
        path: str,
        fields: int,
        tokens: int,
        leakage: str,
        streaming: bool,
        duration_ms: int,
        *,
        system_transformed: bool = True,
    ) -> None:
        self._write(
            "proxy_request",
            session_key=session_key,
            path=path,
            fields=fields,
            tokens=tokens,
            leakage=leakage,
            streaming=streaming,
            duration_ms=duration_ms,
            system_transformed=system_transformed,
        )

    def restore(
        self, session_id: str, restored_count: int, unknown_token_count: int, mode: str
    ) -> None:
        self._write(
            "restore",
            session_id=session_id,
            restored_count=restored_count,
            unknown_token_count=unknown_token_count,
            mode=mode,
        )

    def vault_purge(self, sessions: int) -> None:
        self._write("vault_purge", sessions=sessions)

    def error(self, exc_type: str, stage: str) -> None:
        self._write("error", exc_type=exc_type, stage=stage)

    def _write(self, event: str, **fields: object) -> None:
        if self._path is None:
            return
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        record = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
        descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


class RequestAuditLog:
    """Daily `audit-YYYY-MM-DD.jsonl` files (UTC) for v2 entries, with a salted value HMAC."""

    def __init__(
        self, directory: Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.directory = Path(directory).expanduser()
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._salt: bytes | None = None
        self._rotated_on: date | None = None

    def value_hmac(self, value: str) -> str:
        """First 16 hex chars of HMAC-SHA256(installation salt, value)."""
        if self._salt is None:
            self._salt = load_salt(self.directory.parent / SALT_NAME)
        digest = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:HMAC_HEX_CHARS]

    def write(self, event: str, fields: dict[str, object]) -> Path:
        """Append one entry to today's file, rotating old files once per day and process."""
        now = self._clock().astimezone(UTC)
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        today = now.date()
        if self._rotated_on != today:
            rotate(self.directory, today)
            self._rotated_on = today
        path = self.directory / f"audit-{today.isoformat()}.jsonl"
        record = {"v": RECORD_VERSION, "event": event, "ts": now.isoformat(), **fields}
        descriptor = os.open(path, APPEND_FLAGS, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path


def rotate(directory: Path, today: date, keep_days: int = RETENTION_DAYS) -> list[Path]:
    """Delete daily files dated `keep_days` or more days before `today`; others stay."""
    removed: list[Path] = []
    for path in Path(directory).iterdir():
        match = DAILY_FILE.match(path.name)
        if match is None or not path.is_file() or path.is_symlink():
            continue
        try:
            day = date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if (today - day).days >= keep_days:
            path.unlink()
            removed.append(path)
    return removed


def load_salt(path: Path) -> bytes:
    """Read the installation salt, creating it exclusively with mode 0600 on first use."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        salt = path.read_bytes()
        if len(salt) != SALT_BYTES:
            raise ValueError("audit salt has an unexpected size") from None
        return salt
    salt = secrets.token_bytes(SALT_BYTES)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(salt)
    return salt
