"""Person and generic-id correlation use lookups, equal to the old pairwise loops."""

from __future__ import annotations

import copy
import random
import signal
import string
import time
from collections.abc import Callable

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline, correlation
from privacy_gateway.model import Finding, Span

HARD_TIMEOUT_S = 120
CLASSES = (
    "PERSON_FULL_NAME",
    "PERSON_LAST_NAME",
    "PERSON_FIRST_NAME",
    "PERSON_INITIALS",
    "GENERIC_ID",
    "EMAIL",
    "CUSTOMER_ID",
    "PHONE",
)
WORDS = ("anna", "Anna", "Berg", "berg", "A. B.", "AB", "A.B.", "Max", "Ab", "Ott", "max", "x1")


def old_join_target(group, people, names):  # type: ignore[no-untyped-def]
    candidates = [g for g in people if g is not group and not g.merged]
    if group.data_class == correlation.PERSON_LAST_NAME:
        matches = [g for g in candidates if names[id(g)][1] == group.key]
    elif group.data_class == correlation.PERSON_FIRST_NAME:
        matches = [g for g in candidates if names[id(g)][0] == group.key]
    elif group.data_class == correlation.PERSON_INITIALS:
        wanted = correlation._letters(group.key)
        matches = [
            g for g in candidates if wanted and correlation._initials(names[id(g)]) == wanted
        ]
    else:
        return None
    return matches[0] if len(matches) == 1 else None


def old_resolve_persons(groups):  # type: ignore[no-untyped-def]
    people = [
        g
        for g in groups
        if g.data_class in correlation.PERSON_CLASSES
        and g.confidence >= correlation.ENTITY_CONFIDENCE
    ]
    names = {id(g): correlation._name_parts(g) for g in people}
    for group in list(groups):
        if group.merged:
            continue
        target = old_join_target(group, people, names)
        if target is None:
            continue
        if (
            group.key in correlation._common_name_words()
            and group.confidence < correlation.PROMOTED_CONFIDENCE
        ):
            continue
        for finding in group.findings:
            finding.confidence = max(finding.confidence, correlation.PROMOTED_CONFIDENCE)
        target.findings.extend(group.findings)
        group.merged = True
        groups.remove(group)


def old_resolve_generic_ids(groups):  # type: ignore[no-untyped-def]
    for group in [g for g in groups if g.data_class == correlation.GENERIC_ID]:
        matches = [g for g in groups if g is not group and g.key == group.key and not g.merged]
        if len(matches) != 1:
            continue
        matches[0].findings.extend(group.findings)
        group.merged = True
        groups.remove(group)


def random_case(rng: random.Random) -> tuple[str, list[Finding]]:
    parts: list[str] = []
    findings: list[Finding] = []
    position = 0
    for _ in range(rng.randint(1, 14)):
        word = rng.choice(WORDS)
        if rng.random() < 0.4:
            word = f"{word} {rng.choice(WORDS)}"
        findings.append(
            Finding(
                Span(position, position + len(word)),
                rng.choice(CLASSES),
                "pattern",
                rng.choice((0.3, 0.5, 0.85, 0.95)),
            )
        )
        parts.append(word + " ")
        position += len(word) + 1
    return "".join(parts), findings


def outcome(findings: list[Finding], entities: dict) -> tuple:  # type: ignore[type-arg]
    return (
        [(f.span, f.data_class, f.confidence, f.entity_id) for f in findings],
        {key: (e.data_class, e.canonical_norm, e.spans) for key, e in entities.items()},
    )


def test_correlation_equals_the_old_loops(
    default_config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    rng = random.Random(188)
    merged = 0
    for _ in range(4_000):
        text, findings = random_case(rng)
        twin = copy.deepcopy(findings)
        new = outcome(*correlation.correlate(text, findings, default_config))
        with monkeypatch.context() as patch:
            patch.setattr(correlation, "_resolve_persons", old_resolve_persons)
            patch.setattr(correlation, "_resolve_generic_ids", old_resolve_generic_ids)
            old = outcome(*correlation.correlate(text, twin, default_config))
        assert new == old, text
        merged += len({f.entity_id for f in findings}) < len(findings)
    assert merged > 500


def _words(count: int) -> list[str]:
    rng = random.Random(7)
    return [
        rng.choice(string.ascii_uppercase)
        + "".join(rng.choice("aeiou" if i % 2 else "bdfgklmnprstvz") for i in range(7))
        for _ in range(count)
    ]


def _expired(signum: int, frame: object) -> None:
    raise TimeoutError(f"correlation exceeded {HARD_TIMEOUT_S}s")


def best_of_two(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(2):
        started = time.process_time()
        scan()
        timings.append(time.process_time() - started)
    return min(timings)


def generic_ids(k: int) -> str:
    return "".join(f"Ref ABC-{i:07d} und XYZ-{i:07d}\n" for i in range(k))


def label_names(k: int) -> str:
    names = _words(2 * k)
    return "".join(f"Kontoinhaber: {names[2 * i]} {names[2 * i + 1]}\n" for i in range(k))


@pytest.mark.parametrize("payload", [generic_ids, label_names])
def test_many_groups_scale_linearly(default_config: Config, payload: Callable[[int], str]) -> None:
    pipeline = Pipeline(default_config)
    small_text, large_text = payload(2_000), payload(8_000)
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
