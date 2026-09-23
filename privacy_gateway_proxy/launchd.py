"""macOS launchd agent for the proxy: plist rendering, install, uninstall, status."""

from __future__ import annotations

import os
import plistlib
import socket
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from privacy_gateway.model import PrivacyGatewayError

DEFAULT_LABEL = "com.privacy-gateway.proxy"
DEFAULT_LOG_DIR = Path.home() / "Library" / "Logs" / "privacy-gateway"


class LaunchdError(PrivacyGatewayError):
    """Raised when a launchctl call fails."""


@dataclass(frozen=True)
class ProxyStatus:
    """Whether the launchd job is loaded and the port answers."""

    label: str
    loaded: bool
    listening: bool
    plist: Path


def plist_path(label: str) -> Path:
    """Location of the user LaunchAgent plist."""
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def render_plist(
    label: str, program_args: list[str], log_dir: Path, env: Mapping[str, str]
) -> str:
    """Render the LaunchAgent plist as XML."""
    document = {
        "Label": label,
        "ProgramArguments": list(program_args),
        "EnvironmentVariables": dict(env),
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(Path(log_dir) / f"{label}.out.log"),
        "StandardErrorPath": str(Path(log_dir) / f"{label}.err.log"),
    }
    return plistlib.dumps(document).decode("utf-8")


def install(
    label: str, program_args: list[str], log_dir: Path, env: Mapping[str, str]
) -> Path:
    """Write the plist, create the log directory and bootstrap the job."""
    target = plist_path(label)
    target.parent.mkdir(parents=True, exist_ok=True)
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    target.write_text(render_plist(label, program_args, log_dir, env), encoding="utf-8")
    result = _run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)])
    if result.returncode != 0:
        raise LaunchdError(f"launchctl bootstrap failed with code {result.returncode}")
    return target


def uninstall(label: str) -> Path:
    """Boot the job out and remove its plist."""
    target = plist_path(label)
    _run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"])
    target.unlink(missing_ok=True)
    return target


def status(label: str, host: str, port: int) -> ProxyStatus:
    """Report whether the job is loaded and whether the port accepts connections."""
    loaded = _run(["launchctl", "print", f"gui/{os.getuid()}/{label}"]).returncode == 0
    return ProxyStatus(
        label=label,
        loaded=loaded,
        listening=_port_open(host, port),
        plist=plist_path(label),
    )


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False
