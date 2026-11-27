"""Only a real base64 attachment source skips the rescan of its `data` (R2-06#1)."""

from __future__ import annotations

import signal
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from privacy_gateway import Gateway
from privacy_gateway_proxy import audit_trail

from ._send import BASE, MAIL, send

DECOY = {"type": "base64", "data": f"Antwort an {MAIL}"}
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="


def _image(source: dict[str, Any]) -> dict[str, Any]:
    return {"type": "image", "source": source}


def _with_blocks(*blocks: dict[str, Any]) -> dict[str, Any]:
    content = [{"type": "text", "text": "hallo"}, *blocks]
    return {**BASE, "messages": [{"role": "user", "content": content}]}


BLOCKED = {
    "tool_schema_default": {
        **BASE,
        "tools": [
            {
                "name": "T",
                "description": "Ein Werkzeug.",
                "input_schema": {
                    "type": "object",
                    "properties": {"att": {"type": "object", "default": DECOY}},
                },
            }
        ],
    },
    "unknown_top_level_field": {**BASE, "x_extra": DECOY},
    "metadata_field": {**BASE, "metadata": {**BASE["metadata"], "extra": DECOY}},
    "image_without_media_type": _with_blocks(_image(DECOY)),
    "image_with_wrong_media_type": _with_blocks(_image({**DECOY, "media_type": "text/plain"})),
    "image_with_plain_text_data": _with_blocks(_image({**DECOY, "media_type": "image/png"})),
    "document_with_plain_text_data": _with_blocks(
        {"type": "document", "source": {**DECOY, "media_type": "application/pdf"}}
    ),
    "unknown_block_type": _with_blocks(
        {"type": "x_attachment", "source": {**DECOY, "media_type": "image/png"}}
    ),
    "image_nested_too_deep": _with_blocks(
        {"type": "text", "text": "x", "x": [_image({**DECOY, "media_type": "image/png"})]}
    ),
}


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(BLOCKED))
async def test_plain_text_in_a_base64_data_field_blocks(
    gateway: Gateway, tmp_path: Path, case: str
) -> None:
    run = await send(gateway, tmp_path, BLOCKED[case])

    assert run.status == 422
    assert run.sent == []
    assert run.entries[-1]["verdict"] == "blocked"


@pytest.mark.asyncio
@pytest.mark.parametrize("media_type", ["image/png", "image/jpeg", "image/gif", "image/webp"])
async def test_a_real_image_in_a_message_still_goes_through(
    gateway: Gateway, tmp_path: Path, media_type: str
) -> None:
    image = _image({"type": "base64", "media_type": media_type, "data": PNG})
    run = await send(gateway, tmp_path, _with_blocks(image))

    assert run.status == 200
    assert len(run.sent) == 1


@pytest.mark.asyncio
async def test_a_real_image_in_a_tool_result_and_a_pdf_still_go_through(
    gateway: Gateway, tmp_path: Path
) -> None:
    image = _image({"type": "base64", "media_type": "image/png", "data": PNG})
    result = {"type": "tool_result", "tool_use_id": "t1", "content": [image]}
    pdf = {
        "type": "document",
        "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0xLjQK"},
    }
    run = await send(gateway, tmp_path, _with_blocks(result, pdf))

    assert run.status == 200
    assert len(run.sent) == 1


def test_only_the_data_of_a_valid_source_is_left_out() -> None:
    image = _image({"type": "base64", "media_type": "image/png", "data": PNG})
    paths = {leaf.path for leaf in audit_trail.scannable_strings(_with_blocks(image))}

    assert ("messages", 0, "content", 1, "source", "data") not in paths
    assert ("messages", 0, "content", 1, "source", "media_type") in paths


@pytest.mark.parametrize(
    "data", ["QUJD", "QUI=", "", "a+b/" * 3, "QUJ", "QU=D", "QUJD\n", "Q UJD", "QUJD===", "QU@D"]
)
def test_base64_validation(data: str) -> None:
    image = _image({"type": "base64", "media_type": "image/png", "data": data})
    expected = data in ("QUJD", "QUI=", "", "a+b/" * 3)

    assert audit_trail._attachment_source(image, ("messages", 0, "content", 0)) is expected


def _alarm(signum: int, frame: object) -> None:
    raise TimeoutError("base64 check did not finish in time")


def _timed(data: str) -> float:
    image = _image({"type": "base64", "media_type": "image/png", "data": data})
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        assert not audit_trail._attachment_source(image, ("messages", 0, "content", 0))
        best = min(best, time.perf_counter() - started)
    return best


def test_the_base64_check_is_linear_on_a_near_miss() -> None:
    n = 2_000_000
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(20)
    try:
        small = _timed("A" * (n - 4) + "==@=")
        large = _timed("A" * (4 * n - 4) + "==@=")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    print(f"base64 check n={n}: {small:.4f}s, 4n: {large:.4f}s, factor {large / small:.2f}")
    assert large < 2.0
    assert large / small < 8
