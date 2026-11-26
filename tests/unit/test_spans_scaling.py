"""`resolve_overlaps` equals the original quadratic algorithm and scales with many findings."""

from __future__ import annotations

import random
import signal
import time
from collections.abc import Iterator

import pytest

from privacy_gateway.classes import ClassRegistry
from privacy_gateway.config import Config
from privacy_gateway.detect.spans import _loses, _order, _remainders, resolve_overlaps
from privacy_gateway.model import Finding, Span

STAGES = ("session", "structured", "pattern", "dictionary", "context", "correlation", "other")


@pytest.fixture(autouse=True)
def _hard_timeout() -> Iterator[None]:
    def _expired(signum: int, frame: object) -> None:
        raise TimeoutError("resolve_overlaps exceeded 60s")

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(60)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def reference(findings: list[Finding], registry: ClassRegistry) -> list[Finding]:
    """The original list-based algorithm (888981f), kept as the specification."""
    kept: list[Finding] = []
    pending = sorted(findings, key=_order)
    while pending:
        finding = pending.pop(0)
        for existing in kept:
            if not existing.span.overlaps(finding.span):
                continue
            if _loses(finding, existing, registry):
                pending.extend(_remainders(finding, existing.span))
            else:
                kept.remove(existing)
                pending.extend(_remainders(existing, finding.span))
                pending.append(finding)
            pending.sort(key=_order)
            break
        else:
            kept.append(finding)
    return sorted(kept, key=lambda f: f.span.start)


def random_findings(
    rng: random.Random, classes: list[str], count: int, width: int
) -> list[Finding]:
    findings = []
    for _ in range(count):
        start = rng.randint(0, width)
        end = start + rng.choice([0, 1, 1, 2, 3, 5, 8, 13, rng.randint(1, width)])
        attributes = {"token": f"<X_{rng.randint(1, 3):03d}>"} if rng.random() < 0.2 else {}
        findings.append(
            Finding(
                span=Span(start, end),
                data_class=rng.choice(classes),
                stage=rng.choice(STAGES),
                confidence=rng.choice([0.5, 0.9, 0.95]),
                attributes=attributes,
            )
        )
    return findings


def snapshot(findings: list[Finding]) -> list[tuple[object, ...]]:
    return [
        (f.span, f.data_class, f.stage, f.confidence, f.entity_id, sorted(f.attributes.items()))
        for f in findings
    ]


def test_equals_the_reference_on_random_finding_sets(default_config: Config) -> None:
    registry = default_config.registry
    every = [c.name for c in registry]
    rng = random.Random(5150)
    for round_ in range(6000):
        classes = rng.sample(every, rng.choice([1, 2, 3, 6, 20]))
        findings = random_findings(rng, classes, rng.randint(0, 24), rng.choice([5, 20, 80]))
        expected = snapshot(reference(list(findings), registry))
        assert snapshot(resolve_overlaps(list(findings), registry)) == expected, round_


def test_equal_findings_and_empty_spans(default_config: Config) -> None:
    registry = default_config.registry
    same = [Finding(Span(3, 3), "IBAN", "pattern", 0.9) for _ in range(3)]
    same += [
        Finding(Span(1, 5), "PHONE", "pattern", 0.9),
        Finding(Span(3, 9), "IBAN", "pattern", 0.9),
    ]
    assert snapshot(resolve_overlaps(list(same), registry)) == snapshot(reference(same, registry))


def best(findings: list[Finding], registry: ClassRegistry) -> float:
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        resolve_overlaps(list(findings), registry)
        timings.append(time.perf_counter() - started)
    return min(timings)


@pytest.mark.parametrize("overlapping", [False, True])
def test_many_findings_scale_n_log_n(default_config: Config, overlapping: bool) -> None:
    registry = default_config.registry
    rng = random.Random(9)

    def make(n: int) -> list[Finding]:
        out = []
        for index in range(n):
            start = index * 10 + (rng.randint(0, 9) if overlapping else 0)
            length = rng.randint(3, 15) if overlapping else 5
            data_class = rng.choice(["IBAN", "PHONE", "EMAIL", "PASSWORD"])
            out.append(Finding(Span(start, start + length), data_class, "pattern", 0.9))
        return out

    small, large = make(20_000), make(40_000)
    small_time, large_time = best(small, registry), best(large, registry)
    assert large_time < 2.0, f"{large_time:.2f}s for 40k findings"
    assert large_time < 0.05 or large_time / small_time < 3.0, large_time / small_time
