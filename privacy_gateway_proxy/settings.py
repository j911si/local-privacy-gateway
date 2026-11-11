"""Runtime settings of the proxy, loaded from environment and explicit overrides."""

from __future__ import annotations

import math
import os
import secrets
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path

from privacy_gateway.model import ConfigError

SESSION_STRATEGIES = ("metadata", "header", "single")
FALSY_VALUES = ("0", "false", "no", "off")
TRUTHY_VALUES = ("1", "true", "yes", "on")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")
LOCAL_UPSTREAM_PREFIXES = ("http://127.0.0.1", "http://localhost")
PROCESS_SESSION_KEY = secrets.token_hex(8)
AUDIT_DIR_ENV = "PGW_AUDIT_LOG_DIR"
DEFAULT_AUDIT_DIR = Path("~/.local/state/privacy-gateway/audit")


@dataclass
class ProxySettings:
    """Everything the proxy needs to listen, forward and pick a session."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8787
    upstream_base_url: str = "https://api.anthropic.com"
    session_strategy: str = "metadata"
    default_session_key: str = PROCESS_SESSION_KEY
    header_name: str = "x-pgw-session"
    config_path: Path | None = None
    debug_dir: Path | None = None
    transform_system: bool = True
    placeholder_notice: bool = True
    debug_originals: bool = False
    audit_dir: Path | None = None
    rescan_budget_s: float = 10.0
    passthrough_paths: tuple[str, ...] = ()
    auth_token: str = field(default="", repr=False)


def audit_dir_for(settings: ProxySettings, env: Mapping[str, str] | None = None) -> Path:
    """The daily audit directory: setting, then `PGW_AUDIT_LOG_DIR`, then the default."""
    if settings.audit_dir is not None:
        return Path(settings.audit_dir).expanduser()
    value = (os.environ if env is None else env).get(AUDIT_DIR_ENV)
    return Path(value).expanduser() if value else DEFAULT_AUDIT_DIR.expanduser()


def is_loopback(host: str) -> bool:
    """True when the host part addresses this machine only."""
    return host.strip().lower() in LOOPBACK_HOSTS


def _upstream_allowed(url: str) -> bool:
    if url.startswith("https://"):
        return True
    for prefix in LOCAL_UPSTREAM_PREFIXES:
        rest = url[len(prefix) :]
        if url.startswith(prefix) and (not rest or rest[0] in ":/"):
            return True
    return False


def is_normal_path(path: str) -> bool:
    """True for an absolute path with no encoded characters, empty or dot segments."""
    if not path.startswith("/") or "%" in path or "\\" in path:
        return False
    if path == "/":
        return True
    segments = path.removesuffix("/").split("/")[1:]
    return all(segment not in ("", ".", "..") for segment in segments)


def _read_token_file(path: Path) -> str:
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigError(f"auth token file must not be accessible to group or others: {path}")
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"auth token file is not readable: {type(exc).__name__}") from None
    if not token:
        raise ConfigError(f"auth token file is empty: {path}")
    return token


def parse_listen(value: str) -> tuple[str, int]:
    """Split a `host:port` string; raises ConfigError when it is not usable."""
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise ConfigError(f"invalid listen address: {value!r}")
    number = int(port)
    if not 1 <= number <= 65535:
        raise ConfigError(f"invalid listen port: {value!r}")
    return host, number


def load_settings(env: Mapping[str, str] | None = None, **overrides: object) -> ProxySettings:
    """Build settings from defaults, then environment, then explicit overrides."""
    environment = os.environ if env is None else env
    values: dict[str, object] = {}
    listen = environment.get("PGW_PROXY_LISTEN")
    if listen is not None:
        values["listen_host"], values["listen_port"] = parse_listen(listen)
    upstream = environment.get("PGW_PROXY_UPSTREAM")
    if upstream is not None:
        values["upstream_base_url"] = upstream.rstrip("/")
    strategy = environment.get("PGW_PROXY_SESSION_STRATEGY")
    if strategy is not None:
        values["session_strategy"] = strategy
    config_path = environment.get("PGW_CONFIG")
    if config_path is not None:
        values["config_path"] = Path(config_path)
    debug_dir = environment.get("PGW_PROXY_DEBUG_DIR")
    if debug_dir is not None:
        values["debug_dir"] = Path(debug_dir)
    transform_system = environment.get("PGW_PROXY_TRANSFORM_SYSTEM")
    if transform_system is not None:
        values["transform_system"] = transform_system.strip().lower() not in FALSY_VALUES
    placeholder_notice = environment.get("PGW_PROXY_PLACEHOLDER_NOTICE")
    if placeholder_notice is not None:
        values["placeholder_notice"] = placeholder_notice.strip().lower() not in FALSY_VALUES
    debug_originals = environment.get("PGW_PROXY_DEBUG_ORIGINALS")
    if debug_originals is not None:
        values["debug_originals"] = debug_originals.strip().lower() in TRUTHY_VALUES
    rescan_budget = environment.get("PGW_PROXY_RESCAN_BUDGET")
    if rescan_budget is not None:
        try:
            values["rescan_budget_s"] = float(rescan_budget)
        except ValueError:
            raise ConfigError(f"invalid rescan budget: {rescan_budget!r}") from None
    passthrough = environment.get("PGW_PROXY_PASSTHROUGH_PATHS")
    if passthrough is not None:
        values["passthrough_paths"] = tuple(
            item.strip() for item in passthrough.split(",") if item.strip()
        )
    auth_token = environment.get("PGW_PROXY_AUTH_TOKEN")
    token_file = environment.get("PGW_PROXY_AUTH_TOKEN_FILE")
    if auth_token and token_file:
        raise ConfigError("set only one of PGW_PROXY_AUTH_TOKEN and PGW_PROXY_AUTH_TOKEN_FILE")
    if auth_token:
        values["auth_token"] = auth_token
    if token_file:
        values["auth_token"] = _read_token_file(Path(token_file))
    audit_dir = environment.get(AUDIT_DIR_ENV)
    if audit_dir:
        values["audit_dir"] = Path(audit_dir)

    known = {item.name for item in fields(ProxySettings)}
    for name, value in overrides.items():
        if name not in known:
            raise ConfigError(f"unknown proxy setting: {name!r}")
        if value is not None:
            values[name] = value

    if "upstream_base_url" in values:
        values["upstream_base_url"] = str(values["upstream_base_url"]).rstrip("/")
    settings = ProxySettings(**values)  # type: ignore[arg-type]
    if not math.isfinite(settings.rescan_budget_s) or settings.rescan_budget_s <= 0:
        raise ConfigError("rescan budget must be a finite number of seconds above zero")
    for path in settings.passthrough_paths:
        if not is_normal_path(path):
            raise ConfigError(f"passthrough path is not a normal absolute path: {path!r}")
    if settings.session_strategy not in SESSION_STRATEGIES:
        raise ConfigError(f"unknown session strategy: {settings.session_strategy!r}")
    if not _upstream_allowed(settings.upstream_base_url):
        raise ConfigError(f"upstream must be https or loopback: {settings.upstream_base_url!r}")
    return settings
