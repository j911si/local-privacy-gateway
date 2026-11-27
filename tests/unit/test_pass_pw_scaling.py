"""The pass/pw finder stays linear inside one value and matches exactly as before (R2-01#1)."""

from __future__ import annotations

import random
import re
import signal
import time
from collections.abc import Callable

import pytest

from privacy_gateway.detect.runs import PASS_PW_PATTERN, pass_pw_finditer

HARD_TIMEOUT_S = 60
ALPHABET = (
    "pw",
    "pass",
    "PW",
    ":",
    " ",
    "\t",
    "\n",
    "a",
    "1",
    "ab12cd",
    "x9",
    ".",
    "..",
    ",",
    ";",
    ")",
    "]",
    "(",
    '"',
    "$",
    "=",
    "-",
    "_",
    "ä",
    " ",
)


def spans(matches: object) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    return [(m.span(), m.span(1)) for m in matches]  # type: ignore[attr-defined]


@pytest.mark.parametrize("flags", [0, re.MULTILINE])
def test_pass_pw_finder_equals_finditer_on_punctuation_runs(flags: int) -> None:
    pattern = re.compile(PASS_PW_PATTERN, flags)
    rng = random.Random(128 + flags)
    matched = 0
    for _ in range(30_000):
        text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 24)))
        expected = spans(pattern.finditer(text))
        assert spans(pass_pw_finditer(pattern, text)) == expected, text
        matched += len(expected)
    assert matched > 100


def _expired(signum: int, frame: object) -> None:
    raise TimeoutError(f"pass/pw scan exceeded {HARD_TIMEOUT_S}s")


def best_of_three(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        scan()
        timings.append(time.perf_counter() - started)
    return min(timings)


@pytest.mark.parametrize("tail", ["x", "x" * 3, ".x" * 4])
def test_a_value_with_a_long_dot_run_scales_linearly(tail: str) -> None:
    pattern = re.compile(PASS_PW_PATTERN)

    def scan(n: int) -> Callable[[], object]:
        text = "pw: abc123" + "." * n + tail
        return lambda: list(pass_pw_finditer(pattern, text))

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    try:
        small, large = best_of_three(scan(32_000)), best_of_three(scan(128_000))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert large < 1.0, f"{large:.2f}s for 128k characters"
    assert large < 0.02 or large / small < 8.0, f"factor {large / small:.2f}"
