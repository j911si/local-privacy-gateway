"""Runtime settings of the proxy, loaded from environment and explicit overrides."""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path

from privacy_gateway.model import ConfigError

SESSION_STRATEGIES = ("metadata", "header", "single")
FALSY_VALUES = ("0", "false", "no", "off")
TRUTHY_VALUES = ("1", "true", "yes", "on")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")
LOCAL_UPSTREAM_PREFIXES = ("http://127.0.0.1", "http://localhost")
PROCESS_SESSION_KEY = secrets.token_hex(8)


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

    known = {item.name for item in fields(ProxySettings)}
    for name, value in overrides.items():
        if name not in known:
            raise ConfigError(f"unknown proxy setting: {name!r}")
        if value is not None:
            values[name] = value

    if "upstream_base_url" in values:
        values["upstream_base_url"] = str(values["upstream_base_url"]).rstrip("/")
    settings = ProxySettings(**values)  # type: ignore[arg-type]
    if settings.session_strategy not in SESSION_STRATEGIES:
        raise ConfigError(f"unknown session strategy: {settings.session_strategy!r}")
    if not _upstream_allowed(settings.upstream_base_url):
        raise ConfigError(f"upstream must be https or loopback: {settings.upstream_base_url!r}")
    return settings
