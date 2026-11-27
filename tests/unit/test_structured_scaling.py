"""The containment check of the structured stage is linearithmic and equal to the old loop."""

from __future__ import annotations

import gc
import random
import signal
import time
from collections.abc import Callable

from privacy_gateway.config import Config
from privacy_gateway.detect.structured import StructuredStage, uncontained
from privacy_gateway.model import Finding, Span

HARD_TIMEOUT_S = 60


def reference(candidates: list[Finding]) -> list[Finding]:
    """The loop of 85dc859: compare every candidate with every kept one."""
    new: list[Finding] = []
    for candidate in candidates:
        if not any(kept.span.contains(candidate.span) for kept in new):
            new.append(candidate)
    return new


def test_uncontained_equals_the_old_loop() -> None:
    rng = random.Random(501)
    for _ in range(20_000):
        size = rng.randint(1, 30)
        candidates = []
        for _ in range(rng.randint(0, 12)):
            start = rng.randint(0, size)
            candidates.append(Finding(Span(start, rng.randint(start, size)), "URL", "s", 1.0))
        assert [id(f) for f in uncontained(candidates)] == [id(f) for f in reference(candidates)]


def _expired(signum: int, frame: object) -> None:
    raise TimeoutError(f"structured stage exceeded {HARD_TIMEOUT_S}s")


def best_of_three(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        scan()
        timings.append(time.perf_counter() - started)
    return min(timings)


def test_a_long_contact_list_scales_linearly(default_config: Config) -> None:
    """Measured without the cyclic GC, whose passes over 20k live findings add noise."""
    stage = StructuredStage()

    def contacts(count: int) -> str:
        return "".join(f"kontakt{i:07d}@beispiel-firma.invalid\n" for i in range(count))

    small_text, large_text = contacts(5_000), contacts(20_000)
    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    gc.collect()
    gc.disable()
    try:
        small = best_of_three(lambda: stage.run(small_text, default_config, []))
        large = best_of_three(lambda: stage.run(large_text, default_config, []))
    finally:
        gc.enable()
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert len(stage.run(large_text, default_config, [])) == 20_000
    assert large < 3.0, f"{large:.2f}s for 20k addresses"
    assert large / small < 8.0, f"factor {large / small:.2f}"
