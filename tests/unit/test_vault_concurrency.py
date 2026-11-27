"""Two vault connections on one database never give one token two values."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.model import VaultError
from privacy_gateway.vault import Vault

TOKEN = "<PERSON_FEMALE_001>"
KEY = "shared-conversation"
SHORT_WAIT = "PRAGMA busy_timeout=50"


def _interleave(monkeypatch: pytest.MonkeyPatch, late: Vault, early_write: Callable[[], None]) -> None:
    """After `late` checks for a conflict, `early_write` stores through another connection."""
    original = late._conflicts

    def checked_then_raced(session_id: str, token: str, value: str) -> bool:
        result = original(session_id, token, value)
        early_write()
        return result

    monkeypatch.setattr(late, "_conflicts", checked_then_raced)


@pytest.fixture
def gateway_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))


def test_interleaved_store_never_overwrites_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    a, b = Vault(db, key), Vault(db, key)
    a._conn.execute(SHORT_WAIT)
    session = a.get_or_create_session(KEY, "cfg")
    stored: list[str] = []

    def a_writes() -> None:
        try:
            a.store(session, TOKEN, "PERSON", "Anna Beispiel", [], {})
        except VaultError:
            return
        stored.append("Anna Beispiel")

    _interleave(monkeypatch, b, a_writes)
    try:
        b.store(session, TOKEN, "PERSON", "Berta Muster", [], {})
    except VaultError:
        pass
    else:
        stored.append("Berta Muster")

    with Vault(db, key) as fresh:
        value = fresh.load(session)[TOKEN].value
    assert stored == [value], f"successful stores {stored} but the vault holds {value!r}"
    a.close()
    b.close()


def test_two_gateways_on_one_named_session_never_restore_the_wrong_name(
    gateway_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    letter_a = "Sehr geehrte Frau Müller, danke."
    letter_b = "Sehr geehrte Frau Schneider, danke."
    with Gateway() as first, Gateway() as second:
        session_a = first.session(KEY)
        session_b = second.session(KEY)
        first.vault._conn.execute(SHORT_WAIT)
        holder: dict[str, str] = {}

        def a_writes() -> None:
            if "a" in holder:
                return
            holder["a"] = ""
            try:
                holder["a"] = session_a.pseudonymize(letter_a)
            except VaultError:
                pass

        _interleave(monkeypatch, second.vault, a_writes)
        try:
            out_b = session_b.pseudonymize(letter_b)
        except VaultError:
            out_b = ""

    outputs = [(out, letter) for out, letter in ((holder["a"], letter_a), (out_b, letter_b)) if out]
    assert outputs, "both requests failed"
    with Gateway() as fresh:
        for out, letter in outputs:
            assert fresh.restore(out, session_a.session_id).text == letter


def test_session_reloads_the_vault_after_a_token_conflict(gateway_env: None) -> None:
    letter_a = "Sehr geehrte Frau Müller, danke."
    letter_b = "Sehr geehrte Frau Schneider, danke."
    with Gateway() as first, Gateway() as second:
        session_a = first.session(KEY)
        session_b = second.session(KEY)
        out_a = session_a.pseudonymize(letter_a)
        session_b._refresh = lambda: None  # A wrote after B looked at the vault revision

        with pytest.raises(VaultError) as excinfo:
            session_b.pseudonymize(letter_b)
        del session_b._refresh
        assert "Schneider" not in str(excinfo.value)
        assert "Müller" not in str(excinfo.value)

        out_b = session_b.pseudonymize(letter_b)
        assert session_b.restore_text(out_a) == letter_a

    assert out_a != out_b
    with Gateway() as fresh:
        assert fresh.restore(out_a, session_a.session_id).text == letter_a
        assert fresh.restore(out_b, session_a.session_id).text == letter_b


def test_storing_the_same_value_under_the_same_token_twice_is_no_conflict(
    tmp_path: Path,
) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    with Vault(db, key) as a, Vault(db, key) as b:
        session = a.get_or_create_session(KEY, "cfg")
        a.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {})
        b.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {})
        assert b.load(session)[TOKEN].value == "Anna Beispiel"


def test_connections_wait_for_a_busy_database(tmp_path: Path) -> None:
    from privacy_gateway.vault import BUSY_TIMEOUT_MS

    with Vault(tmp_path / "vault.db", tmp_path / "vault.key") as vault:
        assert vault._conn.execute("PRAGMA busy_timeout").fetchone()[0] == BUSY_TIMEOUT_MS


def test_rollback_of_a_second_session_keeps_the_mapping_the_first_one_issued(
    gateway_env: None,
) -> None:
    letter_a = "Sehr geehrte Frau Müller, IBAN DE89370400440532013000, danke."
    letter_b = "Sehr geehrte Frau Müller, IBAN DE02120300000000202051, danke."
    letter_c = "Sehr geehrte Frau Schneider, danke."
    with Gateway() as gateway:
        session_a = gateway.session(KEY)
        session_b = gateway.session(KEY)
        out_a = session_a.pseudonymize(letter_a)
        session_b._refresh = lambda: None  # A wrote after B looked at the vault revision
        with pytest.raises(VaultError):
            session_b.pseudonymize(letter_b)
        del session_b._refresh
        out_c = session_b.pseudonymize(letter_c)
    with Gateway() as fresh:
        assert fresh.restore(out_a, session_a.session_id, mode="lenient").text == letter_a
        assert fresh.restore(out_c, session_a.session_id).text == letter_c


def test_a_rollback_only_removes_mappings_its_own_call_inserted(tmp_path: Path) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    with Vault(db, key) as a, Vault(db, key) as b:
        session = a.get_or_create_session(KEY, "cfg")
        a.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="a")
        assert not b.store(
            session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="b"
        ).changed
        assert not b.delete_tokens(session, [TOKEN], owner="b").changed
        assert a.load(session)[TOKEN].value == "Anna Beispiel"


def test_a_confirmed_mapping_survives_the_rollback_of_the_call_that_inserted_it(
    tmp_path: Path,
) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    with Vault(db, key) as a, Vault(db, key) as b:
        session = a.get_or_create_session(KEY, "cfg")
        b.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="b")
        a.confirm_tokens(session, a.load(session))
        assert not b.delete_tokens(session, [TOKEN], owner="b").changed
        assert a.load(session)[TOKEN].value == "Anna Beispiel"


def test_confirm_stores_a_mapping_again_that_a_rollback_removed_meanwhile(
    tmp_path: Path,
) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    with Vault(db, key) as a, Vault(db, key) as b:
        session = a.get_or_create_session(KEY, "cfg")
        b.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="b")
        relied_on = a.load(session)
        assert b.delete_tokens(session, [TOKEN], owner="b").changed
        assert a.confirm_tokens(session, relied_on).changed
        assert b.load(session)[TOKEN].value == "Anna Beispiel"
        b.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="b")
        assert not b.delete_tokens(session, [TOKEN], owner="b").changed


def test_confirm_fails_when_the_token_now_holds_another_value(tmp_path: Path) -> None:
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    with Vault(db, key) as a, Vault(db, key) as b:
        session = a.get_or_create_session(KEY, "cfg")
        b.store(session, TOKEN, "PERSON", "Anna Beispiel", ["Anna Beispiel"], {}, owner="b")
        relied_on = a.load(session)
        b.delete_tokens(session, [TOKEN], owner="b")
        b.store(session, TOKEN, "PERSON", "Berta Muster", ["Berta Muster"], {}, owner="c")
        with pytest.raises(VaultError) as excinfo:
            a.confirm_tokens(session, relied_on)
        assert "Anna" not in str(excinfo.value) and "Berta" not in str(excinfo.value)
