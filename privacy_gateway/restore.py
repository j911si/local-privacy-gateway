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

    A token stands for exactly one value, so the result does not depend on how often or in which
    order tokens occur. Strict mode raises on an unknown token and takes only bracketed tokens;
    lenient mode is for a model's answer and also takes a token in its own quotes.
    """
    if mode not in (STRICT, LENIENT):
        raise RestoreError(f"unknown restore mode: {mode}")
    pattern = NUMBERED_TOKEN if mode == STRICT else _LENIENT_TOKEN
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
        return f"{quote}{entry.value}{quote}"

    return RestoreResult(
        text=pattern.sub(replace, text),
        restored_count=restored,
        unknown_tokens=unknown,
    )
