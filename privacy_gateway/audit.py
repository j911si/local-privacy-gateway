"""Value-free JSON Lines audit log."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path


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
