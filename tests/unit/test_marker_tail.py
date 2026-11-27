"""The marker rule stays linear behind a marker word and matches exactly as before (R2-02#1)."""

from __future__ import annotations

import random
import re
import signal
import time
from collections.abc import Callable, Iterator

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import context

OLD_MARKER_TAIL = (
    r"\s*((?:[:#=]|-?\s*nr\.?|no\.?|number|nummer)?\s*[:#=]?)\s*"
    r"([A-Za-z0-9][A-Za-z0-9_\-./]{2,})"
)
PIECES = (
    " ",
    "  ",
    "\t",
    "\n",
    " ",
    "-",
    ":",
    "#",
    "=",
    ".",
    "/",
    "_",
    "nr",
    "Nr.",
    "no",
    "no.",
    "number",
    "nummer",
    "id",
    "ab1",
    "X9",
    "abc",
    "123",
    "a",
    "Kundennummer",
    "kunden-nummer",
    "server",
    "Host",
    "Ticket",
    "ID",
)
HARD_TIMEOUT_S = 60


def old_marker_re(word: str) -> re.Pattern[str]:
    body = r"[-\s]?".join(re.escape(part) for part in word.split("-"))
    boundary = context.MARKER_SUFFIX if word[-1:].isalnum() else r"\b"
    return re.compile(r"(?i)" + context.IDENTIFIER_PREFIX + body + boundary + OLD_MARKER_TAIL)


def matches(pattern: re.Pattern[str], text: str) -> list[tuple[tuple[int, int], ...]]:
    return [(m.span(), m.span(1), m.span(2)) for m in pattern.finditer(text)]


def marker_words(config: Config) -> list[str]:
    return sorted(
        {
            word.lower()
            for data_class in config.registry.enabled()
            if not data_class.patterns
            for word in data_class.context_words
        }
    )


def test_marker_rule_matches_exactly_as_before(default_config: Config) -> None:
    rng = random.Random(2002)
    words = marker_words(default_config)
    assert len(words) > 50
    for word in words:
        new, old = context._marker_re(word), old_marker_re(word)
        for _ in range(150):
            text = "".join(
                rng.choice((*PIECES, word, word.upper())) for _ in range(rng.randint(1, 14))
            )
            assert matches(new, text) == matches(old, text), (word, text)


@pytest.fixture
def hard_timeout() -> Iterator[None]:
    def _expired(signum: int, frame: object) -> None:
        raise TimeoutError(f"marker scan exceeded {HARD_TIMEOUT_S}s")

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def best_of_three(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(3):
        started = time.process_time()
        scan()
        timings.append(time.process_time() - started)
    return min(timings)


@pytest.mark.usefixtures("hard_timeout")
def test_all_marker_words_before_long_whitespace_scale_linearly(default_config: Config) -> None:
    patterns = [context._marker_re(word) for word in marker_words(default_config)]

    def scan(text: str) -> None:
        for pattern in patterns:
            list(pattern.finditer(text))

    def payload(n: int) -> str:
        return "Kundennummer" + " " * n + "!\nserver" + "\t" * n + "!\nhost -" + " " * n + "!"

    small, large = (
        best_of_three(lambda: scan(payload(5_000))),
        best_of_three(lambda: scan(payload(20_000))),
    )
    assert large < 2.0, f"{large:.2f}s"
    assert large < 0.05 or large / small < 8.0, f"factor {large / small:.2f}"
