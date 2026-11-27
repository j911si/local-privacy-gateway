"""Health findings use one boundary and date index per text, equal to the old scans."""

from __future__ import annotations

import random
import signal
import time
from collections.abc import Callable

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline, context
from privacy_gateway.model import Span

HARD_TIMEOUT_S = 120
PIECES = (
    "Diagnose: ",
    "Befund ",
    "Diabetes",
    "Asthma",
    "Hypertonie",
    ", ",
    ". ",
    "\n",
    " ",
    "geb. 01.02.1980 ",
    "12.03.1975 geboren ",
    "Version 1.2.3 ",
    "am 3.4. ",
    "x",
    "Patient ",
)


def old_sentence_fragment(text: str, start: int, end: int) -> Span:
    """The scan of 85dc859."""
    left = start
    while left > 0 and not context._is_boundary(text, left - 1):
        left -= 1
    right = end
    while right < len(text) and not context._is_boundary(text, right):
        right += 1
    return context._trimmed_span(text, left, right)


def old_health(self, text, config, findings, out):  # type: ignore[no-untyped-def]
    for finding in findings:
        if finding.data_class != "MEDICAL_INFORMATION":
            continue
        if finding.attributes.get("bundled") != "true":
            continue
        start = max(0, finding.span.start - context.HEALTH_MARKER_WINDOW)
        window = text[start : finding.span.start]
        if not any(marker in window.lower() for marker in context.HEALTH_MARKERS):
            continue
        span = old_sentence_fragment(text, finding.span.start, finding.span.end)
        dates = [
            f.span.end
            for f in (*findings, *out)
            if f.data_class == "DATE_OF_BIRTH"
            and span.contains(f.span)
            and f.span.end <= finding.span.start
        ]
        if dates:
            span = context._trimmed_span(text, max(dates), span.end)
        self._emit(config, out, span, "HEALTH_INFORMATION", 0.95)


def test_sentence_fragment_equals_the_old_scan() -> None:
    rng = random.Random(555)
    for _ in range(3_000):
        text = "".join(rng.choice("ab .\n1.2 ") for _ in range(rng.randint(1, 30)))
        sentences = context._Sentences(text)
        for _ in range(5):
            start = rng.randint(0, len(text))
            end = rng.randint(start, len(text))
            assert sentences.fragment(start, end) == old_sentence_fragment(text, start, end)


def findings_of(pipeline: Pipeline, text: str) -> list[tuple[Span, str]]:
    return [(f.span, f.data_class) for f in pipeline.run(text, {}).findings]


def test_health_findings_equal_the_old_rule(
    default_config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    rng = random.Random(556)
    pipeline = Pipeline(default_config)
    texts = ["".join(rng.choice(PIECES) for _ in range(rng.randint(1, 20))) for _ in range(800)]
    new = [findings_of(pipeline, text) for text in texts]
    monkeypatch.setattr(context.ContextStage, "_health", old_health)
    old = [findings_of(pipeline, text) for text in texts]
    assert new == old
    assert sum(cls == "HEALTH_INFORMATION" for found in new for _, cls in found) > 100
    classes = [{cls for _, cls in found} for found in new]
    assert sum({"HEALTH_INFORMATION", "DATE_OF_BIRTH"} <= found for found in classes) > 20


def _expired(signum: int, frame: object) -> None:
    raise TimeoutError(f"health rule exceeded {HARD_TIMEOUT_S}s")


def best_of_two(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(2):
        started = time.process_time()
        scan()
        timings.append(time.process_time() - started)
    return min(timings)


@pytest.mark.parametrize(
    "unit", ["Diagnose: Diabetes, Hypertonie, Asthma.\n", "Diagnose: Asthma, "]
)
def test_many_health_findings_scale_linearly(default_config: Config, unit: str) -> None:
    pipeline = Pipeline(default_config)
    small_text, large_text = unit * 2_000, unit * 8_000
    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    try:
        small = best_of_two(lambda: pipeline.run(small_text, {}))
        large = best_of_two(lambda: pipeline.run(large_text, {}))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert large < 6.0, f"{large:.2f}s"
    assert large / small < 6.0, f"factor {large / small:.2f}"
