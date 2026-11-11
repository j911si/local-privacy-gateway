"""Maps tokens in an LLM answer back to the original values."""

from __future__ import annotations

import re
from collections.abc import Mapping

from privacy_gateway.model import RestoreError, RestoreResult, VaultEntry
from privacy_gateway.tokens import NUMBERED_TOKEN

STRICT = "strict"
LENIENT = "lenient"

_LABEL = r"[A-Za-z][A-Za-z0-9_]*?_\d{3,}"
# A bracketed token is unambiguous wherever it stands; a bracketless one needs its own quotes.
_LENIENT_TOKEN = re.compile(
    rf"<(?P<bracketed>{_LABEL})>"
    rf"|(?<![\w>])(?P<quote>[`\"'])(?P<bare>{_LABEL})(?P=quote)(?!\w)"
)


def restore_text(
    text: str, entries: Mapping[str, VaultEntry], mode: str = STRICT
) -> RestoreResult:
    """Replace tokens; the text around a token is never touched.

    Strict mode is for the unchanged pseudonymized text and hands back the recorded surface forms
    in occurrence order. Lenient mode is for a model's answer, where tokens come in any number
    and order (and in pieces, when streamed), so it always restores the canonical value.
    """
    if mode not in (STRICT, LENIENT):
        raise RestoreError(f"unknown restore mode: {mode}")
    pattern = NUMBERED_TOKEN if mode == STRICT else _LENIENT_TOKEN
    occurrences: dict[str, int] = {}
    unknown: list[str] = []
    restored = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal restored
        if mode == STRICT:
            name, quote = match.group("name"), ""
        else:
            name = match.group("bracketed") or match.group("bare")
            quote = match.group("quote") or ""
        token = f"<{name.upper()}>"
        entry = entries.get(token)
        if entry is None:
            if mode == STRICT:
                raise RestoreError(f"unknown token: {token}")
            if token not in unknown:
                unknown.append(token)
            return match.group(0)
        restored += 1
        if mode == STRICT:
            index = occurrences.get(token, 0)
            occurrences[token] = index + 1
            if index < len(entry.surface_forms):
                return entry.surface_forms[index]
        return f"{quote}{entry.value}{quote}"

    return RestoreResult(
        text=pattern.sub(replace, text),
        restored_count=restored,
        unknown_tokens=unknown,
    )
