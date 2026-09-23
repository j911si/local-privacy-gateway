from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

CLASS_COUNT = 140
FIXTURE = "customer_letter_de"
IBAN = "DE89370400440532013000"
REPO_ROOT = Path(__file__).resolve().parents[2]


INHERITED_ENV = ("PATH", "HOME")


def run(
    env: dict[str, str], *args: str, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    inherited = {name: os.environ[name] for name in INHERITED_ENV if name in os.environ}
    return subprocess.run(
        [sys.executable, "-m", "privacy_gateway.cli", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**inherited, **env},
        check=False,
    )


def test_pseudonymize_then_restore_round_trip(
    gateway_env: dict[str, str], fixtures_dir: Path, tmp_path: Path
) -> None:
    source = fixtures_dir / f"{FIXTURE}.txt"
    session_file = tmp_path / "session.txt"
    pseudonymized = run(
        gateway_env, "pseudonymize", str(source), "--session-file", str(session_file)
    )
    assert pseudonymized.returncode == 0
    assert IBAN not in pseudonymized.stdout
    assert "session: " in pseudonymized.stderr
    session_id = session_file.read_text(encoding="utf-8")

    restored = run(gateway_env, "restore", "--session", session_id, stdin=pseudonymized.stdout)
    assert restored.returncode == 0
    assert restored.stdout == source.read_text(encoding="utf-8")


def test_output_files_are_private(
    gateway_env: dict[str, str], fixtures_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out.txt"
    session_file = tmp_path / "session.txt"

    result = run(
        gateway_env,
        "pseudonymize",
        str(fixtures_dir / f"{FIXTURE}.txt"),
        "--out",
        str(out),
        "--session-file",
        str(session_file),
    )

    assert result.returncode == 0
    assert os.stat(out).st_mode & 0o777 == 0o600
    assert os.stat(session_file).st_mode & 0o777 == 0o600


def test_session_key_reuses_the_token_across_two_calls(gateway_env: dict[str, str]) -> None:
    first = run(
        gateway_env,
        "pseudonymize",
        "-",
        "--session-key",
        "conversation-1",
        stdin=f"Sehr geehrte Frau Müller, Ihre IBAN {IBAN} ist vorgemerkt.",
    )
    assert first.returncode == 0
    assert "<PERSON_FEMALE_001>" in first.stdout

    second = run(
        gateway_env,
        "pseudonymize",
        "-",
        "--session-key",
        "conversation-1",
        stdin="Müller ruft morgen an.",
    )
    assert second.returncode == 0
    assert second.stdout == "<PERSON_FEMALE_001> ruft morgen an."
    sessions = [line for line in first.stderr.splitlines() if line.startswith("session: ")]
    assert second.stderr.splitlines() == sessions


def test_validate_exits_two_when_something_is_found(
    gateway_env: dict[str, str], fixtures_dir: Path
) -> None:
    result = run(gateway_env, "validate", str(fixtures_dir / f"{FIXTURE}.txt"))
    assert result.returncode == 2
    assert "IBAN: 1" in result.stdout


def test_validate_exits_zero_for_harmless_text(gateway_env: dict[str, str]) -> None:
    result = run(gateway_env, "validate", "-", stdin="Hello world.")
    assert result.returncode == 0


def test_classes_lists_every_registered_class(gateway_env: dict[str, str]) -> None:
    result = run(gateway_env, "classes")
    assert result.returncode == 0
    assert len(result.stdout.splitlines()) == CLASS_COUNT


def test_vault_list_and_purge(
    gateway_env: dict[str, str], fixtures_dir: Path, tmp_path: Path
) -> None:
    session_file = tmp_path / "session.txt"
    pseudonymized = run(
        gateway_env,
        "pseudonymize",
        str(fixtures_dir / f"{FIXTURE}.txt"),
        "--session-file",
        str(session_file),
    )
    session_id = session_file.read_text(encoding="utf-8")

    listed = run(gateway_env, "vault", "list")
    assert listed.returncode == 0
    assert session_id in listed.stdout

    purged = run(gateway_env, "vault", "purge", "--session", session_id)
    assert purged.returncode == 0

    restored = run(
        gateway_env, "restore", "--session", session_id, stdin=pseudonymized.stdout
    )
    assert restored.returncode == 1
    assert restored.stderr.startswith("error: ")
