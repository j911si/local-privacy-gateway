"""AES-GCM encrypted SQLite vault for token mappings."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import NamedTuple, Self
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .model import SessionInfo, VaultEntry, VaultError
from .tokens import NUMBERED_TOKEN

KEY_SIZE = 32
NONCE_SIZE = 12
GENDER_LABEL_SUFFIXES = ("_FEMALE", "_MALE")
BUSY_TIMEOUT_MS = 10_000


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    doc_sha256 TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    external_key TEXT
);
CREATE TABLE IF NOT EXISTS mappings (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    data_class TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    attributes_json TEXT NOT NULL,
    PRIMARY KEY (session_id, token)
);
CREATE TABLE IF NOT EXISTS surface_forms (
    session_id TEXT NOT NULL,
    token TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (session_id, token, ordinal)
);
CREATE TABLE IF NOT EXISTS pending_mappings (
    session_id TEXT NOT NULL,
    token TEXT NOT NULL,
    owner TEXT NOT NULL,
    PRIMARY KEY (session_id, token)
);
CREATE TABLE IF NOT EXISTS session_revisions (
    session_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL
);
"""

_EXTERNAL_KEY_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS sessions_external_key ON sessions (external_key)"
)


class Write(NamedTuple):
    """Outcome of a vault write: whether a mapping changed, and the session revision around it."""

    changed: bool
    before: int
    after: int


def _base_label(label: str) -> str:
    for suffix in GENDER_LABEL_SUFFIXES:
        if label.endswith(suffix):
            return label[: -len(suffix)]
    return label


def _ensure_private_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o700)


def _restrict(db_path: Path) -> None:
    """Keep the database and its WAL side files readable by the owner only."""
    for suffix in ("", "-wal", "-shm"):
        side = Path(f"{db_path}{suffix}")
        if side.exists():
            os.chmod(side, 0o600)


def load_or_create_key(path: Path) -> bytes:
    """Return the vault key, creating a new 0600 key file when absent."""
    path = Path(path)
    if path.exists():
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if os.fstat(descriptor).st_mode & 0o077:
                raise VaultError(f"key file permissions are too permissive: {path}")
            key = os.read(descriptor, KEY_SIZE + 1)
        finally:
            os.close(descriptor)
        if len(key) != KEY_SIZE:
            raise VaultError(f"key file must contain exactly {KEY_SIZE} bytes: {path}")
        return key
    _ensure_private_parent(path)
    key = secrets.token_bytes(KEY_SIZE)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, key)
    finally:
        os.close(descriptor)
    print(f"privacy-gateway: new vault key created at {path}", file=sys.stderr)
    return key


class Vault:
    """Stores token mappings encrypted per session."""

    def __init__(self, db_path: Path, key_file: Path) -> None:
        self._aesgcm = AESGCM(load_or_create_key(Path(key_file)))
        db_path = Path(db_path)
        _ensure_private_parent(db_path)
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # ponytail: WAL with NORMAL fsyncs at checkpoints, not per commit; purge checkpoints.
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA secure_delete=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.execute(_EXTERNAL_KEY_INDEX)
        self._conn.commit()
        _restrict(db_path)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def create_session(self, doc_sha256: str, config_hash: str) -> str:
        session_id = uuid4().hex
        self._conn.execute(
            "INSERT INTO sessions (id, created_at, doc_sha256, config_hash) VALUES (?, ?, ?, ?)",
            (session_id, datetime.now(UTC).isoformat(), doc_sha256, config_hash),
        )
        self._conn.commit()
        return session_id

    def find_session(self, external_key: str) -> str | None:
        """Return the session stored under an external key, if any."""
        row = self._conn.execute(
            "SELECT id FROM sessions WHERE external_key = ?", (external_key,)
        ).fetchone()
        return row[0] if row is not None else None

    def get_or_create_session(self, external_key: str, config_hash: str) -> str:
        """Return the session for an external key, creating it on first use."""
        with self._write_transaction():
            row = self._conn.execute(
                "SELECT id, config_hash FROM sessions WHERE external_key = ?", (external_key,)
            ).fetchone()
            if row is None:
                session_id = uuid4().hex
                self._conn.execute(
                    "INSERT INTO sessions (id, created_at, doc_sha256, config_hash, external_key) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (session_id, datetime.now(UTC).isoformat(), "", config_hash, external_key),
                )
                return session_id
        if row[1] != config_hash:
            print(
                "privacy-gateway: a session was created with a different configuration",
                file=sys.stderr,
            )
        return row[0]

    def max_counters(self, session_id: str) -> dict[str, int]:
        """Return the highest token number per base label stored for a session."""
        counters: dict[str, int] = {}
        rows = self._conn.execute(
            "SELECT token FROM mappings WHERE session_id = ?", (session_id,)
        ).fetchall()
        for (token,) in rows:
            match = NUMBERED_TOKEN.fullmatch(token)
            if match is None:
                continue
            label = _base_label(match.group("label"))
            counters[label] = max(counters.get(label, 0), int(match.group("number")))
        return counters

    def revision(self, session_id: str) -> int:
        """A number that grows whenever a mapping of the session is written or removed."""
        row = self._conn.execute(
            "SELECT revision FROM session_revisions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return 0 if row is None else row[0]

    def delete_tokens(
        self, session_id: str, tokens: Iterable[str], owner: str | None = None
    ) -> Write:
        """Remove the given token mappings and their surface forms.

        With `owner` only mappings this owner inserted and nobody confirmed yet go, so a rollback
        never removes a mapping that another call already handed out.
        """
        tokens = list(tokens)
        if not tokens:
            revision = self.revision(session_id)
            return Write(False, revision, revision)
        with self._write_transaction():
            before = self.revision(session_id)
            changed = False
            for token in tokens:
                if owner is not None and not self._release(session_id, token, owner):
                    continue
                self._conn.execute(
                    "DELETE FROM surface_forms WHERE session_id = ? AND token = ?",
                    (session_id, token),
                )
                deleted = self._conn.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND token = ?", (session_id, token)
                ).rowcount
                changed = changed or bool(deleted)
            after = self._bump(session_id, before) if changed else before
        return Write(changed, before, after)

    def append_surface_forms(self, session_id: str, token: str, forms: list[str]) -> None:
        """Append further surface forms to an existing token mapping."""
        row = self._conn.execute(
            "SELECT max(ordinal) FROM surface_forms WHERE session_id = ? AND token = ?",
            (session_id, token),
        ).fetchone()
        next_ordinal = 0 if row[0] is None else row[0] + 1
        for offset, form in enumerate(forms):
            ordinal = next_ordinal + offset
            nonce, ciphertext = self._encrypt(form, f"{session_id}|{token}|{ordinal}")
            self._conn.execute(
                "INSERT INTO surface_forms (session_id, token, ordinal, nonce, ciphertext) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, token, ordinal, nonce, ciphertext),
            )
        self._conn.commit()

    def store(
        self,
        session_id: str,
        token: str,
        data_class: str,
        value: str,
        surface_forms: list[str],
        attributes: dict[str, str],
        owner: str | None = None,
    ) -> Write:
        """Encrypt and store one token mapping; a token already taken by another value fails.

        `changed` says whether the mapping is new. With `owner` a new mapping stays pending until
        `confirm_tokens`, and only `delete_tokens` with the same owner removes it again.
        """
        try:
            with self._write_transaction():
                if not self._session_exists(session_id):
                    raise VaultError(f"unknown session: {session_id}")
                if self._conflicts(session_id, token, value):
                    raise VaultError(f"token already assigned: {token}")
                before = self.revision(session_id)
                inserted = self._insert(
                    session_id, token, data_class, value, surface_forms, attributes
                )
                if inserted and owner is not None:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO pending_mappings (session_id, token, owner) "
                        "VALUES (?, ?, ?)",
                        (session_id, token, owner),
                    )
                after = self._bump(session_id, before)
        except sqlite3.Error as exc:
            raise VaultError(f"vault write failed: {type(exc).__name__}") from exc
        _restrict(self._db_path)
        return Write(inserted, before, after)

    def confirm_tokens(self, session_id: str, entries: Mapping[str, VaultEntry]) -> Write:
        """Make the mappings a call hands out permanent, storing any that went missing meanwhile.

        A confirmed mapping is no longer pending, so no rollback removes it. A token that now
        holds a different value fails.
        """
        try:
            with self._write_transaction():
                if not self._session_exists(session_id):
                    raise VaultError(f"unknown session: {session_id}")
                before = self.revision(session_id)
                changed = False
                for token, entry in entries.items():
                    self._conn.execute(
                        "DELETE FROM pending_mappings WHERE session_id = ? AND token = ?",
                        (session_id, token),
                    )
                    if self._conflicts(session_id, token, entry.value):
                        raise VaultError(f"token already assigned: {token}")
                    changed |= self._insert(
                        session_id,
                        token,
                        entry.data_class,
                        entry.value,
                        [entry.value],
                        entry.attributes,
                        keep=True,
                    )
                after = self._bump(session_id, before) if changed else before
        except sqlite3.Error as exc:
            raise VaultError(f"vault write failed: {type(exc).__name__}") from exc
        _restrict(self._db_path)
        return Write(changed, before, after)

    def _insert(
        self,
        session_id: str,
        token: str,
        data_class: str,
        value: str,
        surface_forms: list[str],
        attributes: dict[str, str],
        *,
        keep: bool = False,
    ) -> bool:
        """Write one mapping inside the caller's transaction; true when it was new.

        With `keep` an existing mapping stays as it is.
        """
        if keep and self._exists(session_id, token):
            return False
        nonce, ciphertext = self._encrypt(value, f"{session_id}|{token}")
        row = (data_class, nonce, ciphertext, json.dumps(attributes), session_id, token)
        updated = self._conn.execute(
            "UPDATE mappings SET data_class = ?, nonce = ?, ciphertext = ?, "
            "attributes_json = ? WHERE session_id = ? AND token = ?",
            row,
        ).rowcount
        if not updated:
            self._conn.execute(
                "INSERT INTO mappings "
                "(data_class, nonce, ciphertext, attributes_json, session_id, token) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                row,
            )
        self._conn.execute(
            "DELETE FROM surface_forms WHERE session_id = ? AND token = ?",
            (session_id, token),
        )
        for ordinal, form in enumerate(surface_forms):
            form_nonce, form_ciphertext = self._encrypt(form, f"{session_id}|{token}|{ordinal}")
            self._conn.execute(
                "INSERT INTO surface_forms (session_id, token, ordinal, nonce, ciphertext) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, token, ordinal, form_nonce, form_ciphertext),
            )
        return not updated

    def load(self, session_id: str) -> dict[str, VaultEntry]:
        """Return all decrypted mappings of a session."""
        if not self._session_exists(session_id):
            raise VaultError(f"unknown session: {session_id}")
        forms: dict[str, list[str]] = {}
        rows = self._conn.execute(
            "SELECT token, ordinal, nonce, ciphertext FROM surface_forms "
            "WHERE session_id = ? ORDER BY token, ordinal",
            (session_id,),
        ).fetchall()
        for token, ordinal, nonce, ciphertext in rows:
            plain = self._decrypt(nonce, ciphertext, f"{session_id}|{token}|{ordinal}")
            forms.setdefault(token, []).append(plain)
        entries: dict[str, VaultEntry] = {}
        mappings = self._conn.execute(
            "SELECT token, data_class, nonce, ciphertext, attributes_json FROM mappings "
            "WHERE session_id = ? ORDER BY token",
            (session_id,),
        ).fetchall()
        for token, data_class, nonce, ciphertext, attributes_json in mappings:
            entries[token] = VaultEntry(
                value=self._decrypt(nonce, ciphertext, f"{session_id}|{token}"),
                data_class=data_class,
                surface_forms=forms.get(token, []),
                attributes=json.loads(attributes_json),
            )
        return entries

    def purge(self, session_id: str) -> None:
        """Remove a session with all its mappings and surface forms."""
        # ponytail: the deletion gets its own fsync; NORMAL would leave it to a checkpoint that
        # a reader on another connection can block.
        # A session without mappings and name (a request-only scan session) frees no secret, so it
        # skips the VACUUM that would otherwise block for the size of the whole vault.
        self._conn.execute("PRAGMA synchronous=FULL")
        try:
            named = self._conn.execute(
                "SELECT 1 FROM sessions WHERE id = ? AND external_key IS NOT NULL", (session_id,)
            ).fetchone()
            freed = int(named is not None)
            freed += self._conn.execute(
                "DELETE FROM surface_forms WHERE session_id = ?", (session_id,)
            ).rowcount
            freed += self._conn.execute(
                "DELETE FROM mappings WHERE session_id = ?", (session_id,)
            ).rowcount
            self._conn.execute(
                "DELETE FROM pending_mappings WHERE session_id = ?", (session_id,)
            )
            self._conn.execute(
                "DELETE FROM session_revisions WHERE session_id = ?", (session_id,)
            )
            self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        finally:
            self._conn.execute("PRAGMA synchronous=NORMAL")
        if freed:
            self._reclaim()

    def purge_older_than(self, days: int) -> int:
        """Remove every session older than the given number of days."""
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        rows = self._conn.execute(
            "SELECT id FROM sessions WHERE created_at < ?", (cutoff,)
        ).fetchall()
        for (session_id,) in rows:
            self.purge(session_id)
        return len(rows)

    def _reclaim(self) -> None:
        """Drop the freed pages from the database file and the write-ahead log."""
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self._conn.execute("VACUUM")
        self._conn.commit()
        _restrict(self._db_path)

    def list_sessions(self) -> list[SessionInfo]:
        rows = self._conn.execute(
            "SELECT s.id, s.created_at, (SELECT count(*) FROM mappings m WHERE m.session_id = s.id) "
            "FROM sessions s ORDER BY s.created_at, s.id"
        ).fetchall()
        return [SessionInfo(id=row[0], created_at=row[1], token_count=row[2]) for row in rows]

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        """Hold the database write lock from the first read to the commit."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    def _migrate(self) -> None:
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "external_key" not in columns:
            self._conn.execute("ALTER TABLE sessions ADD COLUMN external_key TEXT")

    def _conflicts(self, session_id: str, token: str, value: str) -> bool:
        """Whether this token is already taken by a different value."""
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM mappings WHERE session_id = ? AND token = ?",
            (session_id, token),
        ).fetchone()
        if row is None:
            return False
        return self._decrypt(row[0], row[1], f"{session_id}|{token}") != value

    def _exists(self, session_id: str, token: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM mappings WHERE session_id = ? AND token = ?", (session_id, token)
        ).fetchone()
        return row is not None

    def _release(self, session_id: str, token: str, owner: str) -> bool:
        """Drop the pending mark of `owner` on a token; false when it holds none."""
        deleted = self._conn.execute(
            "DELETE FROM pending_mappings WHERE session_id = ? AND token = ? AND owner = ?",
            (session_id, token, owner),
        ).rowcount
        return bool(deleted)

    def _bump(self, session_id: str, before: int) -> int:
        self._conn.execute(
            "INSERT OR REPLACE INTO session_revisions (session_id, revision) VALUES (?, ?)",
            (session_id, before + 1),
        )
        return before + 1

    def _session_exists(self, session_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return row is not None

    def _encrypt(self, plaintext: str, aad: str) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
        return nonce, ciphertext

    def _decrypt(self, nonce: bytes, ciphertext: bytes, aad: str) -> str:
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad.encode("utf-8"))
        except InvalidTag as exc:
            raise VaultError("decryption failed") from exc
        return plaintext.decode("utf-8")
