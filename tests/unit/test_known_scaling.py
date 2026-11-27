"""Known numbers and values with digits are searched by their digits, equal to the old scans."""

from __future__ import annotations

import random
import re
import signal
import time
from collections.abc import Callable

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import session
from privacy_gateway.detect.normalize import offset_map
from privacy_gateway.detect.session import KnownMatcher, _value_span, compact_digit_run
from privacy_gateway.model import Span

HARD_TIMEOUT_S = 120
TEXT_PIECES = (
    "1",
    "2",
    "12",
    "123",
    "0",
    "00",
    "+",
    "-",
    "/",
    " ",
    "  ",
    "\t",
    "\n",
    "a",
    "B",
    "x",
    "K",
    "K",
    "ſ",
    "s",
    "S",
    "ä",
    "Ä",
    "²",
    "@",
    ".",
    "_",
    "\u200b",
    "<",
    ">",
    "4711",
)
CLASSES = ("CUSTOMER_ID", "PERSON_LAST_NAME", "PHONE", "IBAN")
FORM_PIECES = (
    "1",
    "2",
    "12",
    "123",
    "0",
    "+",
    "-",
    " ",
    "a",
    "b",
    "x",
    "k",
    "s",
    "K",
    "ä",
    "²",
    "@",
    ".",
    "4711",
    "ab",
)


class OldMatcher(KnownMatcher):
    """`find` and `_digit_hits` of 85dc859."""

    def find(self, text: str) -> list[session.Hit]:
        mapping = offset_map(text)
        work = text if mapping is None else mapping.text
        covered = bytearray(len(work))
        hits: list[session.Hit] = []

        def add(start: int, end: int, value: session.Known) -> None:
            if covered.find(1, start, end) != -1:
                return
            covered[start:end] = b"\x01" * (end - start)
            span = Span(start, end)
            hits.append((span if mapping is None else mapping.original(span), value))

        candidates: list[tuple[int, int, session.Known]] = []
        if self._trie is not None:
            for span, folded in self._trie.find(work):
                candidates.append((span.start, span.end, self._values[folded]))
        for pattern, value, *_ in self._spaced:
            candidates.extend((m.start(), m.end(), value) for m in pattern.finditer(work))
        candidates.extend((s.start, s.end, v) for s, v in self._old_digit_hits(work))
        for substring in self._substrings:
            for match in substring.pattern.finditer(work):
                if not self._inside_longer_number(work, match.start(), match.end(), substring):
                    candidates.append((match.start(), match.end(), substring.value))
        candidates.sort(key=lambda candidate: candidate[0] - candidate[1])
        for start, end, value in candidates:
            add(start, end, value)
        return hits

    def _old_digit_hits(self, text: str) -> list[session.Hit]:
        if not self._by_digits:
            return []
        offsets = [index for index, char in enumerate(text) if char.isdigit()]
        projection = "".join(text[index] for index in offsets)
        result: list[session.Hit] = []
        for digits, value in self._by_digits.items():
            for match in re.finditer(re.escape(digits), projection):
                first, last = offsets[match.start()], offsets[match.end() - 1] + 1
                if not compact_digit_run(text, first, last):
                    continue
                lead = first
                while lead and text[lead - 1].isdigit():
                    lead -= 1
                international = digits in self._signed_digits and text[lead:first] == "00"
                if lead < first and not international:
                    continue
                span = _value_span(
                    text, first, last, len(digits) >= session.MIN_DIGITS_FOR_DIGIT_SEARCH
                )
                if span is None:
                    continue
                if international:
                    span = Span(lead, span.end)
                if digits in self._signed_digits and text[span.start - 1 : span.start] == "+":
                    span = Span(span.start - 1, span.end)
                result.append((span, value))
        return result


def random_form(rng: random.Random) -> str:
    form = "".join(rng.choice(FORM_PIECES) for _ in range(rng.randint(2, 7)))
    return form if any(char.isdigit() for char in form) else form + "7"


@pytest.mark.parametrize("known_count", [3, 40])
def test_known_matcher_equals_the_old_scans(default_config: Config, known_count: int) -> None:
    rng = random.Random(4000 + known_count)
    hits = 0
    for _ in range(1_500):
        known = {
            random_form(rng): (rng.choice(CLASSES), f"<X_{i:03d}>")
            for i in range(rng.randint(1, known_count))
        }
        new = KnownMatcher(known, default_config.registry)
        old = OldMatcher(known, default_config.registry)
        forms = list(known)
        for _ in range(4):
            parts = [rng.choice(TEXT_PIECES) for _ in range(rng.randint(0, 30))]
            for _ in range(rng.randint(0, 3)):
                form = rng.choice(forms)
                if rng.random() < 0.5:
                    form = form.upper().replace(" ", rng.choice(("  ", "\t", "\n ")))
                parts.insert(rng.randint(0, len(parts)), form)
            text = "".join(parts)
            expected = old.find(text)
            assert new.find(text) == expected, (known, text)
            hits += len(expected)
    assert hits > 3_000


def _expired(signum: int, frame: object) -> None:
    raise TimeoutError(f"known matcher exceeded {HARD_TIMEOUT_S}s")


def best_of_two(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(2):
        started = time.perf_counter()
        scan()
        timings.append(time.perf_counter() - started)
    return min(timings)


def emails(k: int) -> tuple[dict[str, session.Known], str]:
    known = {
        f"kontakt{i:07d}@beispiel-firma.invalid": ("EMAIL", f"<EMAIL_{i:03d}>") for i in range(k)
    }
    text = "".join(f"<EMAIL_{i:03d}> kontakt{i:07d}@beispiel-firma.invalid\n" for i in range(k))
    return known, text


def phones(k: int) -> tuple[dict[str, session.Known], str]:
    known = {f"+49 151 {i:08d}": ("PHONE", f"<PHONE_{i:03d}>") for i in range(k)}
    text = "".join(f"Tel 0151 {i:08d} oder +49151{i:08d}\n" for i in range(k))
    return known, text


@pytest.mark.parametrize("case", [emails, phones])
def test_many_known_values_scale_linearly(
    default_config: Config, case: Callable[[int], tuple[dict[str, session.Known], str]]
) -> None:
    small_known, small_text = case(2_000)
    large_known, large_text = case(8_000)
    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    try:
        small_matcher = KnownMatcher(small_known, default_config.registry)
        large_matcher = KnownMatcher(large_known, default_config.registry)
        small = best_of_two(lambda: small_matcher.find(small_text))
        large = best_of_two(lambda: large_matcher.find(large_text))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert len(large_matcher.find(large_text)) >= 8_000
    assert large < 3.0, f"{large:.2f}s"
    assert large / small < 8.0, f"factor {large / small:.2f}"
