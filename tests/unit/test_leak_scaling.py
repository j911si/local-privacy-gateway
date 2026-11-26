"""The leak check equals the original token-by-token search and scales with many tokens."""

from __future__ import annotations

import random
import signal
import time
from collections.abc import Callable, Iterator, Mapping

import pytest

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.config import Config
from privacy_gateway.detect.session import Hit, SubstringSweep, known_occurrences
from privacy_gateway.leakage import (
    MIN_LENGTH_FOR_FUZZY_SEARCH,
    _deduplicate,
    _policy,
    check_leakage,
    issued_token_spans,
    redacted_token,
)
from privacy_gateway.model import DetectionReport, Finding, Leak, LeakageError, Span, VaultEntry
from privacy_gateway.tokens import ANY_TOKEN, NUMBERED_TOKEN

CLASSES = ["PASSWORD", "SOCIAL_MEDIA_HANDLE", "SALUTATION", "IBAN", "PERSON_LAST_NAME"]


@pytest.fixture(autouse=True)
def _hard_timeout() -> Iterator[None]:
    def _expired(signum: int, frame: object) -> None:
        raise TimeoutError("leak check exceeded 60s")

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(60)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def ref_glued_to_token(finding: Finding, tokens: list[Span]) -> bool:
    return finding.data_class == "SOCIAL_MEDIA_HANDLE" and any(
        token.end == finding.span.start for token in tokens
    )


def ref_short_touching_token(start: int, end: int, tokens: list[Span]) -> bool:
    return end - start < MIN_LENGTH_FOR_FUZZY_SEARCH and any(
        token.end == start or token.start == end for token in tokens
    )


def ref_short_fragment_next_to_token(text: str, start: int, end: int, tokens: list[Span]) -> bool:
    if end - start >= MIN_LENGTH_FOR_FUZZY_SEARCH:
        return False
    after = end < len(text) and text[end].isalnum() and any(t.end == start for t in tokens)
    before = start > 0 and text[start - 1].isalnum() and any(t.start == end for t in tokens)
    return after or before


def ref_only_tokens(text: str, span: Span, tokens: list[Span]) -> bool:
    rest = list(text[span.start : span.end])
    for token in tokens:
        for index in range(max(token.start, span.start), min(token.end, span.end)):
            rest[index - span.start] = " "
    return not any(char.isalnum() for char in rest)


def ref_exempt_from_residual(finding: Finding, tokens: list[Span], text: str) -> bool:
    return (
        any(token.contains(finding.span) for token in tokens)
        or ref_only_tokens(text, finding.span, tokens)
        or ref_glued_to_token(finding, tokens)
        or ref_short_touching_token(finding.span.start, finding.span.end, tokens)
    )


def ref_sweep_find(sweep: SubstringSweep, text: str) -> list[Hit]:
    """`SubstringSweep.find` of 45548ad, which tests every hit against every token."""
    from privacy_gateway.detect.normalize import offset_map
    from privacy_gateway.detect.session import _lower

    mapping = offset_map(text)
    work = text if mapping is None else mapping.text
    lowered = _lower(work)
    tokens = [Span(match.start(), match.end()) for match in ANY_TOKEN.finditer(work)]
    raw: list[tuple[int, int, tuple[str, str]]] = []
    for key, value in sweep._values.items():
        if " " in key:
            continue
        start = lowered.find(key)
        while start != -1:
            raw.append((start, start + len(key), value))
            start = lowered.find(key, start + 1)
    for pattern, value in sweep._spaced:
        raw.extend((m.start(), m.end(), value) for m in pattern.finditer(work))
    raw = [
        hit for hit in raw if not any(token.overlaps(Span(hit[0], hit[1])) for token in tokens)
    ]
    raw.sort(key=lambda hit: (hit[0] - hit[1], hit[0]))
    chosen: list[tuple[int, int, tuple[str, str]]] = []
    starts: set[int] = set()
    ends: set[int] = set()
    while raw:
        covered = bytearray(len(work))
        for start, end, _ in chosen:
            covered[start:end] = b"\x01" * (end - start)
        taken: list[tuple[int, int, tuple[str, str]]] = []
        for start, end, value in raw:
            if covered.find(1, start, end) == -1:
                covered[start:end] = b"\x01" * (end - start)
                taken.append((start, end, value))
        for start, end, _ in taken:
            if lowered[start:end] not in sweep._glued_only:
                starts.add(start)
                ends.add(end)
        rejected = False
        for start, end, value in taken:
            if sweep._valid(work, lowered[start:end], start, end, starts, ends):
                chosen.append((start, end, value))
            else:
                rejected = True
        if not rejected:
            break
        removed = set(taken)
        raw = [hit for hit in raw if hit not in removed]
    hits: list[Hit] = []
    for start, end, value in sorted(chosen):
        span = Span(start, end)
        hits.append((span if mapping is None else mapping.original(span), value))
    return hits


def ref_check_leakage(
    text: str,
    entries: Mapping[str, VaultEntry],
    scan: Callable[[str], DetectionReport],
    registry: ClassRegistry,
    literal_tokens: frozenset[str] = frozenset(),
    *,
    sweep: bool = True,
    redacted: Mapping[str, str] | None = None,
) -> None:
    """`check_leakage` of 45548ad, kept as the specification."""
    leaks: list[Leak] = []
    token_spans = issued_token_spans(text, entries)

    report = scan(text)
    for finding in report.findings:
        if _policy(registry, finding.data_class) is Policy.IGNORE:
            continue
        if ref_exempt_from_residual(finding, token_spans, text):
            continue
        leaks.append(
            Leak("residual_finding", finding.data_class, finding.span.start, finding.span.end)
        )

    known: dict[str, tuple[str, str]] = {}
    for token, entry in entries.items():
        for form in [entry.value, *entry.surface_forms]:
            if form:
                known.setdefault(form, (entry.data_class, token))
    for value, data_class in (redacted or {}).items():
        known.setdefault(value, (data_class, redacted_token(data_class)))
    for span, (data_class, _) in known_occurrences(text, known, registry):
        if any(token.contains(span) for token in token_spans):
            continue
        if ref_short_fragment_next_to_token(text, span.start, span.end, token_spans):
            continue
        if data_class == "SOCIAL_MEDIA_HANDLE" and any(t.end == span.start for t in token_spans):
            continue
        leaks.append(Leak("original_value", data_class, span.start, span.end))

    if sweep:
        ignored = [
            finding.span
            for finding in report.findings
            if _policy(registry, finding.data_class) is Policy.IGNORE
        ]
        for span, (data_class, _) in ref_sweep_find(SubstringSweep(known), text):
            if any(token.contains(span) for token in token_spans):
                continue
            if any(span.overlaps(other) for other in ignored):
                continue
            if data_class == "SOCIAL_MEDIA_HANDLE" and any(
                t.end == span.start for t in token_spans
            ):
                continue
            leaks.append(Leak("original_value", data_class, span.start, span.end))

    for match in NUMBERED_TOKEN.finditer(text):
        if match.group(0) not in entries and match.group(0) not in literal_tokens:
            leaks.append(Leak("unknown_token", "", match.start(), match.end()))

    if leaks:
        raise LeakageError(_deduplicate(leaks))


def random_spans(rng: random.Random, count: int, width: int) -> list[Span]:
    spans = []
    for _ in range(count):
        start = rng.randint(0, width)
        end = min(width, start + rng.choice([0, 1, 2, 3, 4, 5, 8, rng.randint(0, width)]))
        spans.append(Span(start, end))
    if spans and rng.random() < 0.3:
        spans.append(rng.choice(spans))
    if spans and rng.random() < 0.3:
        outer = rng.choice(spans)
        spans.append(Span(outer.start + (len(outer) > 1), max(outer.start, outer.end - 1)))
    return spans


def random_text(rng: random.Random, width: int) -> str:
    return "".join(rng.choice("ab1 .-@<>_") for _ in range(width))


def test_span_index_answers_like_a_search_over_every_span() -> None:
    from privacy_gateway.detect.spans import SpanIndex

    rng = random.Random(4711)
    for round_ in range(4000):
        width = rng.choice([3, 10, 40])
        tokens = random_spans(rng, rng.randint(0, 12), width)
        index = SpanIndex(tokens)
        for query in random_spans(rng, 8, width):
            assert index.contains(query) == any(t.contains(query) for t in tokens), round_
            assert index.overlaps(query) == any(t.overlaps(query) for t in tokens), round_
            assert index.ends_at(query.start) == any(t.end == query.start for t in tokens)
            assert index.starts_at(query.end) == any(t.start == query.end for t in tokens)


def test_exemptions_equal_the_reference_on_random_spans() -> None:
    from privacy_gateway.detect.spans import SpanIndex
    from privacy_gateway.leakage import (
        _only_tokens,
        _short_fragment_next_to_token,
        exempt_from_residual,
    )

    rng = random.Random(1312)
    for round_ in range(6000):
        width = rng.choice([4, 12, 40])
        text = random_text(rng, width)
        tokens = random_spans(rng, rng.randint(0, 10), width)
        index = SpanIndex(tokens)
        for span in random_spans(rng, 6, width):
            finding = Finding(span, rng.choice(CLASSES), "pattern", 0.9)
            assert exempt_from_residual(finding, index, text) == ref_exempt_from_residual(
                finding, tokens, text
            ), round_
            assert _only_tokens(text, span, index) == ref_only_tokens(text, span, tokens)
            assert _short_fragment_next_to_token(
                text, span.start, span.end, index
            ) == ref_short_fragment_next_to_token(text, span.start, span.end, tokens)


def _leaks(check: Callable[..., None], *args: object, **kwargs: object) -> list[Leak] | None:
    try:
        check(*args, **kwargs)
    except LeakageError as exc:
        return exc.leaks
    return None


VALUES = ["Sommer2024", "kx9", "ab", "Hans", "@hansi", "B2C4", "123456", "Wendland", "x."]


def _random_case(
    rng: random.Random,
) -> tuple[str, dict[str, VaultEntry], list[Finding], dict[str, str]]:
    entries: dict[str, VaultEntry] = {}
    for number, value in enumerate(rng.sample(VALUES, rng.randint(0, len(VALUES))), 1):
        data_class = rng.choice(CLASSES)
        token = f"<{data_class}_{number:03d}>"
        entries[token] = VaultEntry(value, data_class, [value], {})
    pieces = [
        *entries,
        *VALUES,
        "<PASSWORD_REDACTED>",
        "<UNKNOWN_042>",
        " ",
        " ",
        "und",
        "-",
        ".",
        "@",
        "1",
        "z",
    ]
    text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
    findings = [
        Finding(span, rng.choice(CLASSES), "pattern", 0.9)
        for span in random_spans(rng, rng.randint(0, 6), len(text))
    ]
    redacted = {"Geheim1": "PASSWORD"} if rng.random() < 0.3 else {}
    if redacted and rng.random() < 0.5:
        text += " Geheim1"
    return text, entries, findings, redacted


def test_check_leakage_equals_the_reference_on_random_texts(default_config: Config) -> None:
    registry = default_config.registry
    rng = random.Random(2026)
    for round_ in range(3000):
        text, entries, findings, redacted = _random_case(rng)

        def scan(_: str, findings: list[Finding] = findings) -> DetectionReport:
            return DetectionReport(findings=list(findings), entities={}, stage_stats={})

        for sweep in (True, False):
            expected = _leaks(
                ref_check_leakage, text, entries, scan, registry, sweep=sweep, redacted=redacted
            )
            actual = _leaks(
                check_leakage, text, entries, scan, registry, sweep=sweep, redacted=redacted
            )
            assert actual == expected, round_


def test_sweep_find_equals_the_reference_on_random_texts() -> None:
    rng = random.Random(77)
    for round_ in range(3000):
        known = {
            value: ("PASSWORD", f"<PASSWORD_{n:03d}>")
            for n, value in enumerate(rng.sample(VALUES, rng.randint(1, 5)), 1)
        }
        pieces = [*VALUES, "<PASSWORD_001>", "<X_REDACTED>", " ", "a", "1", "-", "Sommer 2024"]
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
        sweep = SubstringSweep(known)
        assert sweep.find(text) == ref_sweep_find(sweep, text), round_


def _many_tokens(n: int) -> tuple[str, dict[str, VaultEntry], DetectionReport]:
    """`n` issued tokens and `n` plain copies of a few known values, each also a finding."""
    entries: dict[str, VaultEntry] = {}
    parts: list[str] = []
    findings: list[Finding] = []
    position = 0
    for index in range(n):
        value = f"Kennwort{index % 7}q"
        token = f"<PASSWORD_{index + 1:05d}>"
        entries[token] = VaultEntry(value, "PASSWORD", [value], {})
        piece = f"{token} {value} "
        start = position + len(token) + 1
        findings.append(Finding(Span(start, start + len(value)), "PASSWORD", "pattern", 0.9))
        parts.append(piece)
        position += len(piece)
    report = DetectionReport(findings=findings, entities={}, stage_stats={})
    return "".join(parts), entries, report


def _check_time(n: int, registry: ClassRegistry) -> float:
    text, entries, report = _many_tokens(n)
    started = time.perf_counter()
    with pytest.raises(LeakageError) as caught:
        check_leakage(text, entries, lambda _: report, registry)
    elapsed = time.perf_counter() - started
    assert len(caught.value.leaks) == 2 * n
    return elapsed


def test_check_leakage_scales_with_many_tokens_and_findings(default_config: Config) -> None:
    registry = default_config.registry
    small = min(_check_time(10_000, registry) for _ in range(2))
    large = min(_check_time(20_000, registry) for _ in range(2))
    assert large < 5.0, f"{large:.2f}s for 20k tokens"
    assert large < 0.2 or large / small < 3.0, large / small
