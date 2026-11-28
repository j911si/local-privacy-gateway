"""Real processes pseudonymize into one named session on one vault database at the same time."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.vault import Vault

PROCESSES = 8
LETTERS_PER_PROCESS = 20
SESSION_KEY = "parallel-conversation"
TOKEN_RE = re.compile(r"<[A-Z_]+_\d{3}>")

CHILD = r"""
import json, sys, time
from pathlib import Path
from privacy_gateway import Gateway

ready, go, worker, count = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
ready.touch()
while not go.exists():
    time.sleep(0.001)
results = []
with Gateway() as gateway:
    session = None
    for index in range(count):
        name = "Muster" + chr(97 + worker) + chr(97 + index // 26) + chr(97 + index % 26)
        letter = f"Sehr geehrte Frau {name}, danke."
        try:
            if session is None:
                session = gateway.session(sys.argv[5])
            results.append({"letter": letter, "output": session.pseudonymize(letter),
                            "session": session.session_id})
        except Exception as exc:
            results.append({"letter": letter, "error": type(exc).__name__})
print(json.dumps(results))
"""


def _child_env(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    env = {key: value for key, value in os.environ.items() if not key.startswith("PGW_")}
    env.update(
        {
            "PGW_SKIP_USER_CONFIG": "1",
            "PGW_VAULT_DB": str(tmp_path / "vault" / "vault.db"),
            "PGW_VAULT_KEY_FILE": str(tmp_path / "vault" / "vault.key"),
            "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
            "PGW_AUDIT_LOG_DIR": str(tmp_path / "audit"),
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "XDG_CACHE_HOME": str(home / ".cache"),
        }
    )
    return env


def test_parallel_processes_never_restore_a_foreign_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _child_env(tmp_path)
    for name in ("PGW_VAULT_DB", "PGW_VAULT_KEY_FILE"):
        monkeypatch.setenv(name, env[name])
    Vault(Path(env["PGW_VAULT_DB"]), Path(env["PGW_VAULT_KEY_FILE"])).close()
    go = tmp_path / "go"
    readies = [tmp_path / f"ready-{worker}" for worker in range(PROCESSES)]
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                CHILD,
                str(ready),
                str(go),
                str(worker),
                str(LETTERS_PER_PROCESS),
                SESSION_KEY,
            ],
            env=env,
            cwd=tmp_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for worker, ready in enumerate(readies)
    ]
    deadline = time.monotonic() + 60
    while not all(ready.exists() for ready in readies) and time.monotonic() < deadline:
        time.sleep(0.01)
    go.touch()
    results = []
    for child in children:
        stdout, stderr = child.communicate(timeout=180)
        assert child.returncode == 0, stderr
        results.extend(json.loads(stdout))

    succeeded = [result for result in results if "output" in result]
    errors = sorted({result["error"] for result in results if "error" in result})
    print(f"parallel: {len(succeeded)} ok, {len(results) - len(succeeded)} failed {errors}")
    assert succeeded, errors
    assert len({result["session"] for result in succeeded}) == 1

    owner: dict[str, str] = {}
    for result in succeeded:
        tokens = TOKEN_RE.findall(result["output"])
        assert len(tokens) == 1, result["output"]
        assert owner.setdefault(tokens[0], result["letter"]) == result["letter"], tokens[0]

    with Gateway() as fresh:
        session_id = succeeded[0]["session"]
        values = [entry.value for entry in fresh.vault.load(session_id).values()]
        assert len(values) == len(set(values))
        for result in succeeded:
            assert fresh.restore(result["output"], session_id).text == result["letter"]
    assert set(errors) <= {"VaultError"}, errors


STALE_CHILD = r"""
import json, sys, time
from pathlib import Path
from privacy_gateway import Gateway

ready, go = Path(sys.argv[1]), Path(sys.argv[2])
with Gateway() as gateway:
    session = gateway.session(sys.argv[3])
    session._refresh = lambda: None  # the other process writes after this one looked
    ready.touch()
    while not go.exists():
        time.sleep(0.001)
    results = {}
    try:
        results["b"] = session.pseudonymize(sys.argv[4])
    except Exception as exc:
        results["b_error"] = type(exc).__name__
    del session._refresh
    results["c"] = session.pseudonymize(sys.argv[5])
print(json.dumps(results))
"""


def test_a_failed_call_in_another_process_keeps_the_mapping_this_process_issued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    letter_a = "Sehr geehrte Frau Müller, IBAN DE89370400440532013000, danke."
    letter_b = "Sehr geehrte Frau Müller, IBAN DE02120300000000202051, danke."
    letter_c = "Sehr geehrte Frau Schneider, danke."
    env = _child_env(tmp_path)
    for name in ("PGW_VAULT_DB", "PGW_VAULT_KEY_FILE", "PGW_AUDIT_LOG", "PGW_SKIP_USER_CONFIG"):
        monkeypatch.setenv(name, env[name])
    Vault(Path(env["PGW_VAULT_DB"]), Path(env["PGW_VAULT_KEY_FILE"])).close()
    ready, go = tmp_path / "ready", tmp_path / "go"
    child = subprocess.Popen(
        [sys.executable, "-c", STALE_CHILD, str(ready), str(go), SESSION_KEY, letter_b, letter_c],
        env=env,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 60
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    with Gateway() as gateway:
        session = gateway.session(SESSION_KEY)
        out_a = session.pseudonymize(letter_a)
    go.touch()
    stdout, stderr = child.communicate(timeout=120)
    assert child.returncode == 0, stderr
    results = json.loads(stdout)
    assert results.get("b_error") == "VaultError", results

    with Gateway() as fresh:
        assert fresh.restore(out_a, session.session_id, mode="lenient").text == letter_a
        assert fresh.restore(results["c"], session.session_id).text == letter_c
