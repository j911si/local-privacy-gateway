"""Linear-time `finditer` for patterns whose first token consumes a whole character run.

`ADDRESS_RE`, `ORGANIZATION_RE` and `EMAIL_RE` start with a greedy character class that must be
followed by a character outside that class (whitespace or `@`). A match starting anywhere in a run
of class characters therefore always extends to the end of that run, and the rest of the match does
not depend on where in the run it started. So the first eligible start of a run decides for the
whole run: if it fails, every later start in that run fails too. Plain `finditer` tries every
start and rescans the run each time, which is quadratic on long runs such as base64.
"""

from __future__ import annotations

import re
from collections.abc import Iterator


def run_finditer(
    pattern: re.Pattern[str],
    text: str,
    run: re.Pattern[str],
    first: re.Pattern[str] | None = None,
) -> Iterator[re.Match[str]]:
    """Yield exactly what `pattern.finditer(text)` yields, trying one start per `run` match."""
    position = 0
    for segment in run.finditer(text):
        start, end = segment.span()
        if end <= position:
            continue
        start = max(start, position)
        if first is not None:
            eligible = first.search(text, start, end)
            if eligible is None:
                continue
            start = eligible.start()
        match = pattern.match(text, start)
        if match is not None:
            yield match
            position = match.end()
