from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_gateway import Gateway, LeakageError
from privacy_gateway.cli import EXIT_FAIL_CLOSED, main
from privacy_gateway.config import Config
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.model import DetectionReport, Finding
from privacy_gateway.pseudonymize import PseudonymizedText

FIXTURE = "customer_letter_de"
IBAN = "DE89370400440532013000"
SECRETS = (
    "9f2c4b7a1d6e8035ab19cd47ef2200aa",
    "8f14e45fceea167a",
    "2c1743a391305fbf",
    "H1nterland-42",
    "pk_live_8Xq2Rm4Tn7Vz1Cb5",
    "buchhaltung@fabrikam-nord.example",
)


def unchanged(text: str, report: DetectionReport, config: Config) -> PseudonymizedText:
    return PseudonymizedText(text=text, assignments=[])


def exploding(
    self: PatternStage, text: str, config: Config, findings: list[Finding]
) -> list[Finding]:
    raise RuntimeError("stage failure")


def audit_events(tmp_path: Path) -> list[dict[str, object]]:
    path = tmp_path / "audit" / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_unchanged_output_is_rejected_and_the_session_is_purged(
    gateway: Gateway, fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", unchanged)
    text = (fixtures_dir / f"{FIXTURE}.txt").read_text(encoding="utf-8")
    with pytest.raises(LeakageError) as error:
        gateway.pseudonymize(text)
    assert error.value.leaks
    assert gateway.vault.list_sessions() == []
    events = audit_events(tmp_path)
    assert [event["leakage"] for event in events if event["event"] == "pseudonymize"] == [
        "failed"
    ]


def test_a_failing_stage_aborts_without_output(
    gateway: Gateway, fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(PatternStage, "run", exploding)
    text = (fixtures_dir / f"{FIXTURE}.txt").read_text(encoding="utf-8")
    with pytest.raises(RuntimeError):
        gateway.pseudonymize(text)
    assert gateway.vault.list_sessions() == []
    assert [event["exc_type"] for event in audit_events(tmp_path) if event["event"] == "error"] == [
        "RuntimeError"
    ]


def test_cli_reports_fail_closed(
    gateway_env: dict[str, str],
    fixtures_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", unchanged)
    out = tmp_path / "out.txt"
    argv = ["pseudonymize", str(fixtures_dir / f"{FIXTURE}.txt"), "--out", str(out)]

    assert main(argv) == EXIT_FAIL_CLOSED

    captured = capsys.readouterr()
    assert not out.exists()
    assert captured.out == ""
    assert "fail-closed" in captured.err
    assert IBAN not in captured.err


def test_redacted_secrets_never_reach_the_vault_file(
    gateway: Gateway, fixtures_dir: Path, tmp_path: Path
) -> None:
    text = (fixtures_dir / "http_request_dump.txt").read_text(encoding="utf-8")

    gateway.pseudonymize(text)
    gateway.close()

    raw = b"".join(path.read_bytes() for path in sorted(tmp_path.glob("vault/vault.db*")))
    assert raw
    for secret in SECRETS:
        assert secret.encode("utf-8") not in raw, secret


def test_ignored_class_is_left_in_place(
    gateway_env: dict[str, str], fixtures_dir: Path, tmp_path: Path
) -> None:
    config_path = tmp_path / "ignore_iban.yaml"
    config_path.write_text("classes:\n  IBAN:\n    policy: ignore\n", encoding="utf-8")
    text = (fixtures_dir / f"{FIXTURE}.txt").read_text(encoding="utf-8")
    with Gateway(config_path) as gateway:
        result = gateway.pseudonymize(text)
    assert IBAN in result.text
