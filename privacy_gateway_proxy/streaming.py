"""Restores tokens inside an Anthropic Messages SSE stream without splitting them."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from privacy_gateway_proxy.transform import restore_json as _restore_json

_SEPARATOR = re.compile(rb"\r?\n\r?\n")
_HOLDBACK = re.compile(r"(?:<[^>\s]{0,80}|[A-Z][A-Z_]{0,72}(?:_\d{0,2})?)$")


@dataclass
class SSEEvent:
    """One complete server-sent event plus the exact bytes it was parsed from."""

    event: str | None
    data: str
    raw: bytes


def parse_sse(buffer: bytes) -> tuple[list[SSEEvent], bytes]:
    """Splits off every complete event and returns the unconsumed remainder."""
    events: list[SSEEvent] = []
    position = 0
    for match in _SEPARATOR.finditer(buffer):
        block = buffer[position : match.start()]
        raw = buffer[position : match.end()]
        position = match.end()
        if block.strip():
            events.append(_parse_block(block, raw))
    return events, buffer[position:]


def _parse_block(block: bytes, raw: bytes) -> SSEEvent:
    event: str | None = None
    data_lines: list[str] = []
    for line in block.decode("utf-8", "replace").split("\n"):
        field = line.rstrip("\r")
        if field.startswith("event:"):
            event = field[len("event:") :].strip()
        elif field.startswith("data:"):
            data_lines.append(field[len("data:") :].removeprefix(" "))
    return SSEEvent(event=event, data="\n".join(data_lines), raw=raw)


class StreamRestorer:
    """Rewrites text and tool-input deltas, forwarding every other event unchanged."""

    def __init__(self, restore: Callable[[str], str]) -> None:
        self._restore = restore
        self._buffer = b""
        self._held: dict[int, str] = {}
        self._partial: dict[int, str] = {}

    def feed(self, chunk: bytes) -> bytes:
        self._buffer += chunk
        events, self._buffer = parse_sse(self._buffer)
        return b"".join(self._handle(event) for event in events)

    def finish(self) -> bytes:
        parts = [self._flush_text(index) for index in sorted(self._held)]
        parts += [self._flush_partial(index) for index in sorted(self._partial)]
        parts.append(self._buffer)
        self._buffer = b""
        return b"".join(parts)

    def _handle(self, event: SSEEvent) -> bytes:
        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError:
            return event.raw
        if not isinstance(payload, dict):
            return event.raw
        name = event.event or payload.get("type")
        index = payload.get("index")
        if not isinstance(index, int):
            return event.raw
        if name == "content_block_stop":
            return self._flush_text(index) + self._flush_partial(index) + event.raw
        if name == "content_block_delta":
            return self._delta(payload, index, event.raw)
        return event.raw

    def _delta(self, payload: dict[str, Any], index: int, raw: bytes) -> bytes:
        delta = payload.get("delta")
        if not isinstance(delta, dict):
            return raw
        kind = delta.get("type")
        if kind == "text_delta" and isinstance(delta.get("text"), str):
            return self._text_delta(index, delta["text"])
        if kind == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            self._partial[index] = self._partial.get(index, "") + delta["partial_json"]
            return b""
        return raw

    def _text_delta(self, index: int, text: str) -> bytes:
        buffered = self._held.pop(index, "") + text
        match = _HOLDBACK.search(buffered)
        split = match.start() if match else len(buffered)
        if split < len(buffered):
            self._held[index] = buffered[split:]
        safe = buffered[:split]
        return _text_event(index, self._restore(safe)) if safe else b""

    def _flush_text(self, index: int) -> bytes:
        held = self._held.pop(index, "")
        return _text_event(index, self._restore(held)) if held else b""

    def _flush_partial(self, index: int) -> bytes:
        accumulated = self._partial.pop(index, "")
        if not accumulated:
            return b""
        try:
            parsed = json.loads(accumulated)
        except json.JSONDecodeError:
            restored = self._restore(accumulated)
        else:
            restored = json.dumps(
                _restore_json(parsed, self._restore), separators=(",", ":"), ensure_ascii=False
            )
        return _event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": restored},
            },
        )


def _event(name: str, payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"event: {name}\ndata: {body}\n\n".encode()


def _text_event(index: int, text: str) -> bytes:
    return _event(
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "text_delta", "text": text},
        },
    )
