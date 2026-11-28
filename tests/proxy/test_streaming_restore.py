"""Streaming restore equals the one-shot restore, wherever the text is cut into deltas."""

from __future__ import annotations

import json
import random
from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st

from privacy_gateway.model import VaultEntry
from privacy_gateway.restore import LENIENT, restore_text
from privacy_gateway_proxy.streaming import StreamRestorer, parse_sse

ENTRIES = {
    "<PERSON_001>": VaultEntry("annika", "PERSON", ["annika", "Annika"], {}),
    "<EMAIL_001>": VaultEntry("x@y.de", "EMAIL", ["x@y.de"], {}),
    "<IPV4_012>": VaultEntry("10.0.0.1", "IP", ["10.0.0.1"], {}),
}


def restore(text: str) -> str:
    return restore_text(text, ENTRIES, LENIENT).text


def _event(name: str, payload: dict) -> bytes:
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()


def stream(deltas: list[str]) -> str:
    restorer = StreamRestorer(restore)
    out = b""
    for text in deltas:
        payload = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }
        out += restorer.feed(_event("content_block_delta", payload))
    out += restorer.feed(_event("content_block_stop", {"type": "content_block_stop", "index": 0}))
    out += restorer.finish()
    events, rest = parse_sse(out)
    assert rest == b""
    return "".join(
        json.loads(e.data)["delta"]["text"] for e in events if e.event == "content_block_delta"
    )


TEXTS = [
    "backup_<PERSON_001>.tar",
    "<PERSON_001>2024 und x<IPV4_012>y",
    '{"owner": "<EMAIL_001>", "ip": "<IPV4_012>"}',
    "owner = '<PERSON_001>'",
    "Der Benutzer `<PERSON_001>` ist da",
    "say \"PERSON_001\" and 'email_001' and `ipv4_012`",
    "/home/<PERSON_001>/<PERSON_001>_notes.md",
    "<PERSON_001><PERSON_001>",
    "<PERSON_001>`PERSON_001`",
    "<PERSON_001>\"PERSON_001\"",
]


@pytest.mark.parametrize("text", TEXTS)
def test_every_two_part_split_gives_the_one_shot_result(text: str) -> None:
    expected = restore(text)

    for offset in range(len(text) + 1):
        assert stream([text[:offset], text[offset:]]) == expected, offset


@pytest.mark.parametrize("text", TEXTS)
def test_character_by_character_gives_the_one_shot_result(text: str) -> None:
    assert stream(list(text)) == restore(text)


@given(
    pieces=st.lists(
        st.one_of(
            st.text(alphabet="abc _-./\"'`<>\\\n", max_size=6),
            st.sampled_from(sorted(ENTRIES)),
            st.sampled_from(["PERSON_001", "email_001", "ipv4_012"]),
        ),
        max_size=8,
    ),
    cuts=st.lists(st.integers(min_value=0, max_value=200), max_size=6),
)
def test_arbitrary_chunking_gives_the_one_shot_result(pieces: list[str], cuts: list[int]) -> None:
    text = "".join(pieces)
    points = sorted({min(c, len(text)) for c in cuts} | {0, len(text)})
    deltas = [text[a:b] for a, b in pairwise(points) if text[a:b]]

    assert stream(deltas) == restore(text)


# A closing quote directly before `<` ends a bracketless token; it must not be held back with
# the `<`, or the token in front of it is cut off from its quote and never restored.
QUOTE_THEN_LT = [
    "Name: `PERSON_001`<",
    'Name: "PERSON_001"<',
    "Name: 'PERSON_001'<",
    "Name: `<PERSON_001>`<",
    "`PERSON_001`<EMAIL_001> und 'ipv4_012'<",
    "\"PERSON_001\"<<IPV4_012>'email_001'<b>",
    "'PERSON_001'<'email_001'<`ipv4_012`<",
]
VALUES = sorted({entry.value for entry in ENTRIES.values()})


def _assert_never_more_than_one_shot(streamed: str, text: str) -> None:
    expected = restore(text)
    for value in VALUES:
        assert streamed.count(value) <= expected.count(value), value


@pytest.mark.parametrize("quote", ["`", '"', "'"])
def test_closing_quote_before_angle_bracket_in_one_delta(quote: str) -> None:
    text = f"Name: {quote}PERSON_001{quote}<"

    assert stream([text]) == f"Name: {quote}annika{quote}<"


@pytest.mark.parametrize("text", QUOTE_THEN_LT)
def test_quote_before_angle_bracket_in_one_delta(text: str) -> None:
    assert stream([text]) == restore(text)


@pytest.mark.parametrize("text", QUOTE_THEN_LT + TEXTS)
def test_every_one_and_two_cut_split_gives_the_one_shot_result(text: str) -> None:
    expected = restore(text)
    for first in range(len(text) + 1):
        streamed = stream([text[:first], text[first:]])
        assert streamed == expected, first
        _assert_never_more_than_one_shot(streamed, text)
        for second in range(first, len(text) + 1):
            parts = [text[:first], text[first:second], text[second:]]
            streamed = stream(parts)
            assert streamed == expected, (first, second)
            _assert_never_more_than_one_shot(streamed, text)


FUZZ_PIECES = [
    "<PERSON_001>",
    "`PERSON_001`",
    "'email_001'",
    '"PERSON_001"',
    "<IPV4_012>",
    "x",
    " ",
    "'",
    "`",
    '"',
    "<",
    ">",
    "A",
    "_",
    "1",
    "ab",
    "\n",
    "PERSON_001",
    "Z<",
    "PERSON_001'",
]


def test_seeded_fuzz_gives_the_one_shot_result() -> None:
    rnd = random.Random(20261126)
    mismatches = []
    for _ in range(3000):
        text = "".join(rnd.choice(FUZZ_PIECES) for _ in range(rnd.randint(1, 12)))
        count = rnd.randint(0, min(5, len(text) - 1))
        cuts = sorted(rnd.sample(range(1, len(text)), k=count))
        points = [0, *cuts, len(text)]
        streamed = stream([text[a:b] for a, b in pairwise(points)])
        _assert_never_more_than_one_shot(streamed, text)
        if streamed != restore(text):
            mismatches.append(text)
    assert mismatches == []
