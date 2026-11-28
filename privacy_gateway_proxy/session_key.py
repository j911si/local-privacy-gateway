"""Derive the vault session key of one request."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from privacy_gateway_proxy.settings import ProxySettings

SESSION_PATTERN = re.compile(r"session_([0-9a-f-]{36})")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
CLAUDE_CODE_USER_IDS = (
    re.compile(
        rf'\{{"device_id":"[0-9a-f]{{64}}","account_uuid":"(?:{_UUID})?",'
        rf'"session_id":"{_UUID}"\}}'
    ),
    re.compile(rf"user_[0-9a-f]{{64}}_account_(?:{_UUID})?_session_{_UUID}"),
)
KEY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def is_valid_key(key: str) -> bool:
    """True when the key is safe to use as a vault session id and a file name."""
    return KEY_PATTERN.match(key) is not None


def is_claude_code_user_id(value: object) -> bool:
    """True only for a `metadata.user_id` in one of the exact Claude Code formats."""
    return isinstance(value, str) and any(
        pattern.fullmatch(value) is not None for pattern in CLAUDE_CODE_USER_IDS
    )


def session_key_for(
    headers: Mapping[str, str], body: dict | None, settings: ProxySettings
) -> str | None:
    """Pick the session key according to the configured strategy.

    None means the request names no session: it then gets a session of its own that ends
    with the request, so it never shares tokens with another client.
    """
    if settings.session_strategy == "single":
        return settings.default_session_key
    if settings.session_strategy == "metadata":
        key = _from_metadata(body)
        if key is not None:
            return key
    return _header(headers, settings.header_name)


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
