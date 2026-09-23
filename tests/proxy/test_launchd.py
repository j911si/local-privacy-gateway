import logging
import os
import plistlib
import subprocess
from pathlib import Path

import pytest

from privacy_gateway_proxy import cli, launchd
from privacy_gateway_proxy.settings import ProxySettings

LABEL = "com.example.privacy-gateway-test"
ARGS = ["/opt/bin/uv", "run", "--project", "/repo", "pgw-proxy", "serve"]
ENV = {"PGW_PROXY_TRANSFORM_SYSTEM": "0", "PATH": "/opt/bin:/usr/bin"}


class Recorder:
    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self.returncode, "", "")


def test_render_plist_structure(tmp_path: Path) -> None:
    rendered = launchd.render_plist(LABEL, ARGS, tmp_path / "logs", ENV)
    parsed = plistlib.loads(rendered.encode("utf-8"))

    assert rendered.startswith("<?xml")
    assert parsed["Label"] == LABEL
    assert parsed["ProgramArguments"] == ARGS
    assert parsed["RunAtLoad"] is True
    assert parsed["KeepAlive"] is True
    assert parsed["StandardOutPath"] == str(tmp_path / "logs" / f"{LABEL}.out.log")
    assert parsed["StandardErrorPath"] == str(tmp_path / "logs" / f"{LABEL}.err.log")
    assert parsed["EnvironmentVariables"] == ENV


def test_render_plist_carries_the_given_environment(tmp_path: Path) -> None:
    env = {
        "PGW_PROXY_TRANSFORM_SYSTEM": "0",
        "PGW_VAULT_DB": "/home/me/vault.db",
        "PATH": "/opt/bin",
    }

    rendered = launchd.render_plist(LABEL, ARGS, tmp_path, env)

    assert plistlib.loads(rendered.encode("utf-8"))["EnvironmentVariables"] == env


def test_launchd_env_copies_pgw_variables_and_path() -> None:
    env = cli.launchd_env(
        {
            "PGW_PROXY_TRANSFORM_SYSTEM": "0",
            "PGW_VAULT_DB": "/home/me/vault.db",
            "HOME": "/home/me",
            "PATH": "/opt/bin",
        }
    )

    assert env == {
        "PGW_PROXY_TRANSFORM_SYSTEM": "0",
        "PGW_VAULT_DB": "/home/me/vault.db",
        "PATH": "/opt/bin",
    }


def test_launchd_env_without_path_in_the_environment() -> None:
    assert cli.launchd_env({"PGW_CONFIG": "/c.yaml"}) == {"PGW_CONFIG": "/c.yaml"}


def test_plist_path_is_in_launch_agents() -> None:
    path = launchd.plist_path(LABEL)

    assert path == Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def test_install_writes_plist_and_bootstraps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "agents" / f"{LABEL}.plist"
    logs = tmp_path / "logs"
    monkeypatch.setattr(launchd, "plist_path", lambda label: target)
    recorder = Recorder()
    monkeypatch.setattr(launchd, "_run", recorder)

    written = launchd.install(LABEL, ARGS, logs, ENV)

    assert written == target
    parsed = plistlib.loads(target.read_bytes())
    assert parsed["ProgramArguments"] == ARGS
    assert parsed["EnvironmentVariables"] == ENV
    assert logs.is_dir()
    assert recorder.calls == [["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)]]


def test_uninstall_boots_out_and_removes_plist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / f"{LABEL}.plist"
    target.write_text("x", encoding="utf-8")
    monkeypatch.setattr(launchd, "plist_path", lambda label: target)
    recorder = Recorder()
    monkeypatch.setattr(launchd, "_run", recorder)

    launchd.uninstall(LABEL)

    assert not target.exists()
    assert recorder.calls == [["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"]]


def test_uninstall_tolerates_missing_plist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launchd, "plist_path", lambda label: tmp_path / "missing.plist")
    monkeypatch.setattr(launchd, "_run", Recorder(returncode=3))

    launchd.uninstall(LABEL)


def test_install_raises_when_launchctl_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launchd, "plist_path", lambda label: tmp_path / f"{LABEL}.plist")
    monkeypatch.setattr(launchd, "_run", Recorder(returncode=5))

    with pytest.raises(launchd.LaunchdError):
        launchd.install(LABEL, ARGS, tmp_path / "logs", ENV)


def test_status_reports_loaded_and_listening(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder()
    monkeypatch.setattr(launchd, "_run", recorder)
    monkeypatch.setattr(launchd, "_port_open", lambda host, port: True)

    result = launchd.status(LABEL, "127.0.0.1", 8787)

    assert result.loaded is True
    assert result.listening is True
    assert recorder.calls == [["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"]]


def test_status_reports_not_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launchd, "_run", Recorder(returncode=113))
    monkeypatch.setattr(launchd, "_port_open", lambda host, port: False)

    result = launchd.status(LABEL, "127.0.0.1", 8787)

    assert result.loaded is False
    assert result.listening is False
    assert result.plist == launchd.plist_path(LABEL)


def test_program_args_point_at_the_repo_root(tmp_path: Path) -> None:
    args = cli.program_args(tmp_path)

    assert args[1:] == ["run", "--project", str(tmp_path), "pgw-proxy", "serve"]
    assert args[0].endswith("uv")
    assert cli.REPO_ROOT == Path(launchd.__file__).resolve().parent.parent


def test_cli_status_reports_state(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PGW_PROXY_LISTEN", "127.0.0.1:9999")
    probed: list[tuple[str, str, int]] = []

    def fake_status(label: str, host: str, port: int) -> launchd.ProxyStatus:
        probed.append((label, host, port))
        return launchd.ProxyStatus(label, loaded=True, listening=True, plist=Path("/p.plist"))

    monkeypatch.setattr(cli.launchd, "status", fake_status)

    assert cli.main(["status", "--label", LABEL]) == 0
    assert probed == [(LABEL, "127.0.0.1", 9999)]
    assert "loaded: yes" in capsys.readouterr().out


def test_cli_status_exits_nonzero_when_port_is_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("PGW_PROXY_LISTEN", raising=False)
    monkeypatch.setattr(
        cli.launchd,
        "status",
        lambda label, host, port: launchd.ProxyStatus(
            label, loaded=False, listening=False, plist=Path("/p.plist")
        ),
    )

    assert cli.main(["status"]) == 1
    assert "listening on 127.0.0.1:8787: no" in capsys.readouterr().out


def test_cli_install_launchd_uses_uv_run_program_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("PGW_PROXY_LISTEN", raising=False)
    monkeypatch.setenv("PGW_PROXY_TRANSFORM_SYSTEM", "0")
    recorded: list[tuple[str, list[str], Path, dict[str, str]]] = []

    def fake_install(label: str, args: list[str], log_dir: Path, env: dict[str, str]) -> Path:
        recorded.append((label, args, log_dir, env))
        return tmp_path / f"{label}.plist"

    monkeypatch.setattr(cli.launchd, "install", fake_install)

    assert cli.main(["install-launchd", "--label", LABEL, "--log-dir", str(tmp_path)]) == 0
    assert recorded[0][0] == LABEL
    assert recorded[0][1] == cli.program_args()
    assert recorded[0][2] == tmp_path
    assert recorded[0][3]["PGW_PROXY_TRANSFORM_SYSTEM"] == "0"
    assert "PATH" in recorded[0][3]
    out = capsys.readouterr().out
    assert "export ANTHROPIC_BASE_URL=http://127.0.0.1:8787" in out
    assert "PGW_PROXY_TRANSFORM_SYSTEM=0" in out


def test_cli_uninstall_launchd(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    removed: list[str] = []
    monkeypatch.setattr(
        cli.launchd, "uninstall", lambda label: removed.append(label) or Path("/p.plist")
    )

    assert cli.main(["uninstall-launchd", "--label", LABEL]) == 0
    assert removed == [LABEL]
    assert "removed /p.plist" in capsys.readouterr().out


def test_log_startup_reports_the_effective_settings(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = ProxySettings(
        upstream_base_url="https://u.test", debug_dir=Path("/tmp/d"), transform_system=False
    )

    with caplog.at_level(logging.INFO):
        cli.log_startup(settings)

    assert "listen=127.0.0.1:8787" in caplog.text
    assert "upstream=https://u.test" in caplog.text
    assert "transform_system=False" in caplog.text
    assert "placeholder_notice=True" in caplog.text
    assert "debug_dir=/tmp/d" in caplog.text
    assert "debug_originals=False" in caplog.text
    assert "non-loopback" not in caplog.text


def test_log_startup_warns_about_a_non_loopback_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        cli.log_startup(ProxySettings(listen_host="0.0.0.0"))

    assert "non-loopback" in caplog.text
