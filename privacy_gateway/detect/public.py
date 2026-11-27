"""Values that are public by definition: reserved example domains and schema namespaces."""

from __future__ import annotations

import re

PUBLIC_DOMAINS = frozenset(
    {"example.com", "example.org", "example.net", "json-schema.org", "w3.org"}
)
_HOST = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^/@\s]*@)?([^/:?#\s]+)", re.IGNORECASE)


def is_public_reference(value: str) -> bool:
    """True when the URL, address or domain sits under a public or reserved domain."""
    candidate = value.strip()
    host = candidate.rsplit("@", 1)[1] if "@" in candidate.split("/", 3)[0] else candidate
    match = _HOST.match(host)
    if match is None:
        return False
    name = match.group(1).lower().rstrip(".")
    return any(name == domain or name.endswith("." + domain) for domain in PUBLIC_DOMAINS)
