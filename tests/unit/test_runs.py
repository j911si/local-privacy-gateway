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
from privacy_gateway.detect.runs import FQDN_PATTERN, fqdn_finditer, run_finditer

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


DOTTED = (
    "example.com", "a.b.de", "foo-bar.example.org", "x" * 62 + ".de", "x" * 63 + ".de",
    "x" * 64 + ".de", "-a.de", "a-.de", "A.", "de", "com1", "co.ukä", "_a.de", "a.de_",
    "sub.domain.co.uk.", "1.2.3.4", "a..b.de", "www.Example.COM", "x.y", "ä.de", "a.dä",
)


def _dotted_corpus() -> list[str]:
    texts = _corpus()
    rng = random.Random(815)
    alphabet = "aAzZ09-._äé/@ \n:abcdefghij"
    for _ in range(300):
        texts.append("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 300))))
        separator = rng.choice(["", " ", ".", "-", "/"])
        texts.append(separator.join(rng.choice(DOTTED) for _ in range(rng.randint(1, 40))))
        labels = [
            "".join(rng.choice("abAB09-") for _ in range(rng.randint(1, 66)))
            for _ in range(rng.randint(1, 12))
        ]
        texts.append(".".join(labels) + rng.choice(["", ".", " ", "-", "ä", "1"]))
    texts.extend(["A." * 3000, "a.de." + "A." * 2000, "a-" * 2000 + ".de"])
    return texts


def test_fqdn_finditer_equals_finditer() -> None:
    pattern = re.compile(FQDN_PATTERN, re.MULTILINE)
    matched = 0
    for text in _dotted_corpus():
        expected = [match.span() for match in pattern.finditer(text)]
        assert [match.span() for match in fqdn_finditer(pattern, text)] == expected
        matched += len(expected)
    assert matched > 0


def test_the_default_fqdn_pattern_takes_the_linear_path(default_config: Config) -> None:
    assert default_config.registry.get("FQDN").patterns == (FQDN_PATTERN,)


def test_dotted_text_is_scanned_in_linear_time(default_config: Config) -> None:
    started = time.perf_counter()
    Pipeline(default_config).run("A." * 55_000)
    assert time.perf_counter() - started < 5
