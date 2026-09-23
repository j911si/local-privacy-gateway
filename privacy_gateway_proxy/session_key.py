"""Derive the vault session key of one request."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from privacy_gateway_proxy.settings import ProxySettings

SESSION_PATTERN = re.compile(r"session_([0-9a-f-]{36})")
KEY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def is_valid_key(key: str) -> bool:
    """True when the key is safe to use as a vault session id and a file name."""
    return KEY_PATTERN.match(key) is not None


def session_key_for(
    headers: Mapping[str, str], body: dict | None, settings: ProxySettings
) -> str:
    """Pick the session key according to the configured strategy."""
    if settings.session_strategy == "single":
        return settings.default_session_key
    if settings.session_strategy == "metadata":
        key = _from_metadata(body)
        if key is not None:
            return key
    header = _header(headers, settings.header_name)
    if header is not None:
        return header
    return settings.default_session_key


def _from_metadata(body: dict | None) -> str | None:
    if not isinstance(body, dict):
        return None
    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        return None
    user_id = metadata.get("user_id")
    if not isinstance(user_id, str):
        return None
    from_json = _from_json_user_id(user_id)
    if from_json is not None:
        return from_json
    match = SESSION_PATTERN.search(user_id)
    return match.group(1) if match else None


def _from_json_user_id(user_id: str) -> str | None:
    try:
        parsed = json.loads(user_id)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    session_id = parsed.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return None
    return session_id.strip()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower() and value.strip():
            return value.strip()
    return None
