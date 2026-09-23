"""Maps tokens in an LLM answer back to the original values."""

from __future__ import annotations

import re
from collections.abc import Mapping

from privacy_gateway.model import RestoreError, RestoreResult, VaultEntry

STRICT = "strict"
LENIENT = "lenient"

_STRICT_TOKEN = re.compile(r"<(?P<name>[A-Z][A-Z_]*?_\d{3,})>")
_LENIENT_TOKEN = re.compile(
    r"(?<![\w>])(?=[`\"'<])(?P<quote>[`\"'])?(?P<bracket><)?"
    r"(?P<name>[A-Za-z][A-Za-z_]*?_\d{3,})(?(bracket)>)"
    r"(?(quote)(?P=quote))(?!\w)"
)


def restore_text(
    text: str, entries: Mapping[str, VaultEntry], mode: str = STRICT
) -> RestoreResult:
    """Replace tokens with their recorded surface forms."""
    if mode not in (STRICT, LENIENT):
        raise RestoreError(f"unknown restore mode: {mode}")
    pattern = _STRICT_TOKEN if mode == STRICT else _LENIENT_TOKEN
    occurrences: dict[str, int] = {}
    unknown: list[str] = []
    restored = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal restored
        token = f"<{match.group('name').upper()}>"
        entry = entries.get(token)
        if entry is None:
            if mode == STRICT:
                raise RestoreError(f"unknown token: {token}")
            if token not in unknown:
                unknown.append(token)
            return match.group(0)
        index = occurrences.get(token, 0)
        occurrences[token] = index + 1
        restored += 1
        if index < len(entry.surface_forms):
            return entry.surface_forms[index]
        return entry.value

    return RestoreResult(
        text=pattern.sub(replace, text),
        restored_count=restored,
        unknown_tokens=unknown,
    )
