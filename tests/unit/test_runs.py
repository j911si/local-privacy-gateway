"""`run_finditer` yields exactly what `finditer` yields, in linear time."""

from __future__ import annotations

import base64
import random
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline, structured
from privacy_gateway.detect import context as ctx
from privacy_gateway.detect.runs import run_finditer

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CASES = [
    (ctx.ADDRESS_RE, ctx.ADDRESS_RUN_RE, ctx.UPPER_START_RE),
    (ctx.ORGANIZATION_RE, ctx.ORGANIZATION_RUN_RE, ctx.UPPER_START_RE),
    (structured.EMAIL_RE, structured.EMAIL_RUN_RE, None),
]
WORDS = (
    "Acme GmbH", "Frau Müller", "Hauptstraße 12, 80331 München", "anna@example.org",
    "x.y+z@mail.example.co.uk", "Beta AG", "Gamma Holding SE", "Rosenweg 3a 1010 Wien",
    "Kontakt", "und", "die", "Firma", "Muster Software Ltd.", "PLZ 12345", "a@b",
    "Main Street 5 12345 Springfield", "foo.Bar GmbH", "xAcme GmbH", "Acme GmbH.Foo Bar AG",
    "a@b.cc+d@e.ff", "Q@x.de", "ÄÖÜ Werke KG", "Am Ring 7 10115 Berlin", "x-Y.Z AG",
)


def _corpus() -> list[str]:
    texts = [path.read_text(encoding="utf-8") for path in sorted(FIXTURES.glob("*.txt"))]
    rng = random.Random(4711)
    for _ in range(150):
        texts.append(base64.b64encode(rng.randbytes(rng.randint(1, 1500))).decode())
        texts.append(rng.randbytes(rng.randint(1, 800)).hex())
        texts.append(" ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 60))))
        parts = [rng.choice(WORDS) for _ in range(20)]
        parts.append(base64.b64encode(rng.randbytes(60)).decode())
        rng.shuffle(parts)
        texts.append(rng.choice(["", " ", "\n", "."]).join(parts))
    return texts


def _spans(matches: Iterator[re.Match[str]], groups: int) -> list[list[tuple[int, int]]]:
    return [[match.span(index) for index in range(groups + 1)] for match in matches]


@pytest.mark.parametrize(("pattern", "run", "first"), CASES)
def test_run_finditer_equals_finditer(
    pattern: re.Pattern[str], run: re.Pattern[str], first: re.Pattern[str] | None
) -> None:
    matched = 0
    for text in _corpus():
        expected = _spans(pattern.finditer(text), pattern.groups)
        assert _spans(run_finditer(pattern, text, run, first), pattern.groups) == expected
        matched += len(expected)
    assert matched > 0


def test_base64_like_text_is_scanned_in_linear_time(default_config: Config) -> None:
    text = "iVBORw0KGgo" * 10_000
    started = time.perf_counter()
    Pipeline(default_config).run(text)
    assert time.perf_counter() - started < 5
