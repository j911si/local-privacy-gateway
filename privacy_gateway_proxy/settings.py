"""Runtime settings of the proxy, loaded from environment and explicit overrides."""

from __future__ import annotations

import ipaddress
import math
import os
import secrets
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path

from privacy_gateway.model import ConfigError
from privacy_gateway_proxy.tool_policy import KEEP_TOKEN, ToolRule, check_settings, load_policy

SESSION_STRATEGIES = ("metadata", "header", "single")
FALSY_VALUES = ("0", "false", "no", "off")
TRUTHY_VALUES = ("1", "true", "yes", "on")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")
LOCAL_UPSTREAM_PREFIXES = ("http://127.0.0.1", "http://localhost")
PROCESS_SESSION_KEY = secrets.token_hex(8)
AUDIT_DIR_ENV = "PGW_AUDIT_LOG_DIR"
DEFAULT_AUDIT_DIR = Path("~/.local/state/privacy-gateway/audit")
ALLOW_UNAUTHENTICATED_ENV = "PGW_PROXY_ALLOW_UNAUTHENTICATED"
ALLOW_PUBLIC_BIND_ENV = "PGW_PROXY_ALLOW_PUBLIC_BIND"
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
UNCHECKED_FIELDS_ENV = "PGW_PROXY_UNCHECKED_FIELDS"
UNCHECKED_BLOCK = "block"
UNCHECKED_ALLOW = "allow"
UNCHECKED_MODES = (UNCHECKED_BLOCK, UNCHECKED_ALLOW)


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
    tool_restore_rules: tuple[ToolRule, ...] = ()
    tool_restore_on_deny: str = KEEP_TOKEN
    allow_unauthenticated: bool = False
    allow_public_bind: bool = False
    unchecked_fields: str = UNCHECKED_BLOCK


def audit_dir_for(settings: ProxySettings, env: Mapping[str, str] | None = None) -> Path:
    """The daily audit directory: setting, then `PGW_AUDIT_LOG_DIR`, then the default."""
    if settings.audit_dir is not None:
        return Path(settings.audit_dir).expanduser()
    value = (os.environ if env is None else env).get(AUDIT_DIR_ENV)
    return Path(value).expanduser() if value else DEFAULT_AUDIT_DIR.expanduser()


def is_loopback(host: str) -> bool:
    """True when the host part addresses this machine only."""
    return host.strip().lower() in LOOPBACK_HOSTS


def is_private_address(host: str) -> bool:
    """True for an explicit IP address in RFC 1918, 100.64.0.0/10 (Tailscale) or fc00::/7."""
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def check_bind(settings: ProxySettings) -> None:
    """Refuse a non-loopback bind without an auth token, and any bind that is neither
    loopback nor an explicit private address, unless the matching opt-out is set."""
    if is_loopback(settings.listen_host):
        return
    if not settings.auth_token and not settings.allow_unauthenticated:
        raise ConfigError(
            f"refusing to listen on the non-loopback address {settings.listen_host} without an "
            "auth token: anyone who reaches the port could restore pseudonymized values. Put a "
            "token in a 0600 file and set PGW_PROXY_AUTH_TOKEN_FILE (clients send it as "
            f"x-pgw-auth), or set {ALLOW_UNAUTHENTICATED_ENV}=1 to accept the risk"
        )
    if not is_private_address(settings.listen_host) and not settings.allow_public_bind:
        raise ConfigError(
            f"refusing to listen on {settings.listen_host}: only loopback and explicit private "
            "addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7) are "
            "allowed, because the proxy speaks plain HTTP without TLS and token, requests and "
            f"restored answers would cross the network in clear. Set {ALLOW_PUBLIC_BIND_ENV}=1 "
            "to accept the risk"
        )


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
    tool_policy = environment.get("PGW_PROXY_TOOL_RESTORE_POLICY")
    if tool_policy:
        values["tool_restore_rules"] = load_policy(Path(tool_policy).expanduser())
    on_deny = environment.get("PGW_PROXY_TOOL_RESTORE_ON_DENY")
    if on_deny is not None:
        values["tool_restore_on_deny"] = on_deny
    allow_unauthenticated = environment.get(ALLOW_UNAUTHENTICATED_ENV)
    if allow_unauthenticated is not None:
        values["allow_unauthenticated"] = allow_unauthenticated.strip().lower() in TRUTHY_VALUES
    allow_public_bind = environment.get(ALLOW_PUBLIC_BIND_ENV)
    if allow_public_bind is not None:
        values["allow_public_bind"] = allow_public_bind.strip().lower() in TRUTHY_VALUES
    unchecked_fields = environment.get(UNCHECKED_FIELDS_ENV)
    if unchecked_fields is not None:
        values["unchecked_fields"] = unchecked_fields
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
    check_settings((), settings.tool_restore_on_deny, None)
    if settings.unchecked_fields not in UNCHECKED_MODES:
        raise ConfigError(f"{UNCHECKED_FIELDS_ENV} must be one of {', '.join(UNCHECKED_MODES)}")
    if settings.session_strategy not in SESSION_STRATEGIES:
        raise ConfigError(f"unknown session strategy: {settings.session_strategy!r}")
    if not _upstream_allowed(settings.upstream_base_url):
        raise ConfigError(f"upstream must be https or loopback: {settings.upstream_base_url!r}")
    check_bind(settings)
    return settings
