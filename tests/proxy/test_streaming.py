"""Tests for the SSE parser and the streaming token restorer."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from privacy_gateway_proxy.streaming import StreamRestorer, parse_sse

FIXTURE = Path(__file__).parent / "fixtures" / "stream_text_and_tool.sse"

INVERSE = {
    "<PERSON_FEMALE_001>": "Frau Müller",
    "<CUSTOMER_NAME_001>": "Alpenbank AG",
    "PERSON_FEMALE_001": "Frau Müller",
    "CUSTOMER_NAME_001": "Alpenbank AG",
}

STREAM_TEXT = "Hallo <PERSON_FEMALE_001>, die <CUSTOMER_NAME_001> hat zwei Konten …"
TOOL_INPUT = {"file_path": "/tmp/x", "content": "Kontakt <PERSON_FEMALE_001>"}
UNTERMINATED = re.compile(r"<[^>\s]*$")


def restore(text: str) -> str:
    for token, value in INVERSE.items():
        text = text.replace(token, value)
    return text


class RecordingRestore:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, text: str) -> str:
        self.calls.append(text)
        return restore(text)


def sse(name: str, payload: dict) -> bytes:
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()


def text_delta(index: int, text: str) -> bytes:
    payload = {
        "type": "content_block_delta",
        "index": index,
        "delta": {"type": "text_delta", "text": text},
    }
    return sse("content_block_delta", payload)


def block_stop(index: int) -> bytes:
    return sse("content_block_stop", {"type": "content_block_stop", "index": index})


def collect(output: bytes) -> tuple[str, str]:
    events, remainder = parse_sse(output)
    assert remainder == b""
    text = ""
    partial = ""
    for event in events:
        payload = json.loads(event.data)
        if payload.get("type") != "content_block_delta":
            continue
        delta = payload["delta"]
        if delta["type"] == "text_delta":
            text += delta["text"]
        elif delta["type"] == "input_json_delta":
            partial += delta["partial_json"]
    return text, partial


def run(chunks: list[bytes], restorer: StreamRestorer | None = None) -> bytes:
    restorer = restorer or StreamRestorer(restore)
    return b"".join(restorer.feed(chunk) for chunk in chunks) + restorer.finish()


@pytest.fixture(scope="module")
def raw() -> bytes:
    return FIXTURE.read_bytes()


def test_parse_sse_returns_complete_events_and_remainder() -> None:
    events, remainder = parse_sse(b"event: ping\ndata: {}\n\nevent: message_stop\ndata: {")
    assert len(events) == 1
    assert events[0].event == "ping"
    assert events[0].data == "{}"
    assert events[0].raw == b"event: ping\ndata: {}\n\n"
    assert remainder == b"event: message_stop\ndata: {"


def test_parse_sse_accepts_crlf_and_joins_data_lines() -> None:
    events, remainder = parse_sse(b"event: x\r\ndata: a\r\ndata: b\r\n\r\n")
    assert remainder == b""
    assert events[0].data == "a\nb"


def test_parse_sse_ignores_comment_lines() -> None:
    events, _ = parse_sse(b": keep-alive\nevent: ping\ndata: {}\n\n")
    assert len(events) == 1
    assert events[0].event == "ping"


def test_whole_stream_restores_text_and_tool_input(raw: bytes) -> None:
    text, partial = collect(run([raw]))
    assert text == restore(STREAM_TEXT)
    assert json.loads(partial) == {
        "file_path": "/tmp/x",
        "content": restore("Kontakt <PERSON_FEMALE_001>"),
    }


def test_no_token_survives_in_the_output(raw: bytes) -> None:
    output = run([raw]).decode("utf-8")
    assert "<PERSON_FEMALE_001>" not in collect(run([raw]))[0]
    assert "Frau Müller" in output
    assert "Alpenbank AG" in output


@pytest.mark.parametrize("offset", range(FIXTURE.stat().st_size + 1))
def test_every_split_offset_gives_identical_output(raw: bytes, offset: int) -> None:
    assert run([raw[:offset], raw[offset:]]) == run([raw])


def test_token_split_across_two_text_deltas() -> None:
    output = run([text_delta(1, "Hallo <PERSON"), text_delta(1, "_FEMALE_001>!"), block_stop(1)])
    assert collect(output)[0] == "Hallo Frau Müller!"


def test_bracketless_token_split_across_two_text_deltas() -> None:
    output = run([text_delta(1, "Kunde CUSTOMER_NA"), text_delta(1, "ME_001 ok"), block_stop(1)])
    assert collect(output)[0] == "Kunde Alpenbank AG ok"


def test_passthrough_events_are_byte_identical(raw: bytes) -> None:
    output = run([raw])
    events, _ = parse_sse(raw)
    names = {
        "message_start",
        "ping",
        "content_block_start",
        "content_block_stop",
        "message_delta",
        "message_stop",
    }
    passthrough = [
        event
        for event in events
        if event.event in names
        or "thinking_delta" in event.data
        or "signature_delta" in event.data
    ]
    assert len(passthrough) == 12
    for event in passthrough:
        assert event.raw in output


def test_holdback_is_not_emitted_before_the_closing_bracket() -> None:
    restorer = StreamRestorer(restore)
    first = restorer.feed(text_delta(1, "Hallo <PERSON"))
    assert b"<PERSON" not in first
    assert collect(first)[0] == "Hallo "
    second = restorer.feed(text_delta(1, "_FEMALE_001>."))
    assert collect(second)[0] == "Frau Müller."


def test_holdback_flushes_at_content_block_stop() -> None:
    restorer = StreamRestorer(restore)
    assert collect(restorer.feed(text_delta(1, "Ende ABC")))[0] == "Ende "
    output = restorer.feed(block_stop(1))
    assert collect(output)[0] == "ABC"
    assert output.index(b"text_delta") < output.index(b"content_block_stop")


def test_holdback_flushes_at_finish() -> None:
    restorer = StreamRestorer(restore)
    restorer.feed(text_delta(1, "Ende <PERSON"))
    assert collect(restorer.finish())[0] == "<PERSON"


def test_input_json_is_emitted_once_at_content_block_stop() -> None:
    chunks = [
        sse(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 2,
                "delta": {"type": "input_json_delta", "partial_json": piece},
            },
        )
        for piece in ('{"a":"<PERSON', '_FEMALE_001>"}')
    ]
    restorer = StreamRestorer(restore)
    assert restorer.feed(b"".join(chunks)) == b""
    output = restorer.feed(block_stop(2))
    events, _ = parse_sse(output)
    assert len(events) == 2
    assert json.loads(json.loads(events[0].data)["delta"]["partial_json"]) == {"a": "Frau Müller"}
    assert events[1].event == "content_block_stop"


def test_unparsable_input_json_is_restored_as_plain_text() -> None:
    payload = {
        "type": "content_block_delta",
        "index": 2,
        "delta": {"type": "input_json_delta", "partial_json": '{"a":"<PERSON_FEMALE_001>"'},
    }
    restorer = StreamRestorer(restore)
    restorer.feed(sse("content_block_delta", payload))
    events, _ = parse_sse(restorer.feed(block_stop(2)))
    assert json.loads(events[0].data)["delta"]["partial_json"] == '{"a":"Frau Müller"'


def test_restore_never_sees_an_unterminated_token_fragment(raw: bytes) -> None:
    recorder = RecordingRestore()
    run([raw], StreamRestorer(recorder))
    assert recorder.calls
    for call in recorder.calls:
        assert not UNTERMINATED.search(call)


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_CONNECTION_STRING_EXTRA_LONG_NAME_001",
        "DATABASE_CONNECTION_STRING_WITH_AN_EXTRA_LONG_CLASS_NAME_001",
    ],
)
def test_long_class_name_token_survives_every_delta_split(name: str) -> None:
    token = f"<{name}>"
    secret = "postgres://user:pw@db/app"
    text = f"Der Wert {token} ist gesetzt."
    expected = text.replace(token, secret)

    def restore_long(chunk: str) -> str:
        return chunk.replace(token, secret)

    for cut in range(len(text) + 1):
        chunks = [text_delta(1, text[:cut]), text_delta(1, text[cut:]), block_stop(1)]
        assert collect(run(chunks, StreamRestorer(restore_long)))[0] == expected, cut


def test_finish_forwards_an_incomplete_trailing_event() -> None:
    restorer = StreamRestorer(restore)
    assert restorer.feed(b"event: ping\ndata: {}") == b""
    assert restorer.finish() == b"event: ping\ndata: {}"
