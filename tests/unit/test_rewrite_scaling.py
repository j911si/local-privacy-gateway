"""Rewriting a text with many replacements is linear and equal to the old loop."""

from __future__ import annotations

import random
import signal
import time

import pytest

from privacy_gateway.model import Span
from privacy_gateway.pseudonymize import rewrite


def reference(text: str, replacements: list[tuple[Span, str]]) -> str:
    """The loop of 888981f: one new string per replacement, last start first."""
    rewritten = text
    for span, replacement in sorted(replacements, key=lambda item: item[0].start, reverse=True):
        rewritten = rewritten[: span.start] + replacement + rewritten[span.end :]
    return rewritten


def random_case(rng: random.Random, overlapping: bool) -> tuple[str, list[tuple[Span, str]]]:
    text = "".join(rng.choice("ab <>_") for _ in range(rng.randint(0, 40)))
    replacements = []
    position = 0
    for index in range(rng.randint(0, 8)):
        if overlapping:
            start = rng.randint(0, len(text))
            end = rng.randint(start, len(text))
        else:
            start = rng.randint(position, len(text))
            end = rng.randint(start, len(text))
            position = end
        replacements.append((Span(start, end), f"<T_{index:03d}>"))
    rng.shuffle(replacements)
    return text, replacements


@pytest.mark.parametrize("overlapping", [False, True])
def test_rewrite_equals_the_old_loop(overlapping: bool) -> None:
    rng = random.Random(41 if overlapping else 7)
    for _ in range(20_000):
        text, replacements = random_case(rng, overlapping)
        assert rewrite(text, replacements) == reference(text, replacements)


def _alarm(signum: int, frame: object) -> None:
    raise TimeoutError("rewrite did not finish in time")


def timed(text: str, replacements: list[tuple[Span, str]]) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        rewrite(text, replacements)
        best = min(best, time.process_time() - started)
    return best


def test_many_replacements_in_a_large_text_scale_linearly() -> None:
    def make(n: int) -> tuple[str, list[tuple[Span, str]]]:
        text = "x" * (n * 40)
        return text, [(Span(i * 40, i * 40 + 10), "<PASSWORD_REDACTED>") for i in range(n)]

    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(60)
    try:
        small, large = make(25_000), make(100_000)
        small_time, large_time = timed(*small), timed(*large)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert large_time < 1.0, f"{large_time:.2f}s for 100k replacements in 4 MB"
    assert large_time < 0.05 or large_time / small_time < 8.0, large_time / small_time
